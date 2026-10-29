import duckdb
import math
from collections import Counter
from config import Thresholds

# Anchor windows at the first packet, so short reference captures do not
# straddle a wall-clock boundary just because of their start timestamp.
WINDOW_BUCKET = """CAST(FLOOR((COALESCE(timestamp, 0) -
    COALESCE((SELECT MIN(timestamp) FROM connections), 0)) / ?) AS BIGINT)"""
WINDOW_CTE = f"WITH stamped AS (SELECT *, {WINDOW_BUCKET} AS window_bucket FROM connections)"


def detect_port_scan_and_syn_flood(con, window_seconds=None):
    """Count SYNs per window and match same-flow client ACKs for completion.

    An ACK from the original source on the same four-tuple indicates that
    the handshake progressed. Missing captures can make a flow look incomplete.
    """
    window_seconds = window_seconds or Thresholds.from_env().window_seconds
    return con.execute(f"""{WINDOW_CTE}
        , acks AS (
            SELECT DISTINCT ipsrc, ipdst, tcpsrc, tcpdst, window_bucket
            FROM stamped
            WHERE CAST(tcpflags AS VARCHAR) LIKE '%A%'
              AND CAST(tcpflags AS VARCHAR) NOT LIKE '%S%'
        )
        SELECT s.ipsrc,
               s.window_bucket,
               COUNT(*) AS total_syns,
               COUNT(DISTINCT s.tcpdst) AS unique_ports,
               SUM(CASE WHEN a.ipsrc IS NULL THEN 1 ELSE 0 END) AS incomplete_syns,
               SUM(CASE WHEN a.ipsrc IS NOT NULL THEN 1 ELSE 0 END)
                   / CAST(COUNT(*) AS DOUBLE) AS completion_rate
        FROM stamped s
        LEFT JOIN acks a
          ON s.ipsrc = a.ipsrc
         AND s.ipdst IS NOT DISTINCT FROM a.ipdst
         AND s.tcpsrc IS NOT DISTINCT FROM a.tcpsrc
         AND s.tcpdst IS NOT DISTINCT FROM a.tcpdst
         AND s.window_bucket = a.window_bucket
        WHERE CAST(s.tcpflags AS VARCHAR) = 'S'
        GROUP BY s.ipsrc, s.window_bucket
        HAVING total_syns > 5
        ORDER BY total_syns DESC
    """, [int(window_seconds)]).df()


def detect_icmp_flood(con, threshold=None, window_seconds=None):
    """Same skeleton as SYN flood: count ICMP echo requests (type 8) per source."""
    cfg = Thresholds.from_env()
    threshold = cfg.icmp_min if threshold is None else int(threshold)
    window_seconds = cfg.window_seconds if window_seconds is None else int(window_seconds)
    return con.execute(f"""{WINDOW_CTE}
        SELECT ipsrc,
               window_bucket,
               COUNT(*) AS icmp_count
        FROM stamped
        WHERE icmp_type = 8
        GROUP BY ipsrc, window_bucket
        HAVING icmp_count > ?
        ORDER BY icmp_count DESC
    """, [window_seconds, threshold]).df()


def detect_arp_spoofing(con, window_seconds=None):
    """If one IP (arp_psrc) is claimed by more than one MAC (arp_hwsrc),
       that's a spoofed/conflicting ARP mapping."""
    cfg = Thresholds.from_env()
    window_seconds = cfg.window_seconds if window_seconds is None else int(window_seconds)
    return con.execute(f"""{WINDOW_CTE}
        SELECT arp_psrc,
               window_bucket,
               COUNT(DISTINCT arp_hwsrc) AS mac_count,
               STRING_AGG(DISTINCT arp_hwsrc, ', ' ORDER BY arp_hwsrc) AS mac_addresses
        FROM stamped
        WHERE arp_psrc IS NOT NULL AND arp_psrc <> '0.0.0.0'
        GROUP BY arp_psrc, window_bucket
        HAVING mac_count >= ?
        ORDER BY mac_count DESC
    """, [window_seconds, cfg.arp_min_macs]).df()


def _dns_entropy(label):
    """Measure Shannon entropy of the first DNS label without dependencies."""
    if not label:
        return 0.0
    counts = Counter(label)
    return -sum((n / len(label)) * math.log2(n / len(label)) for n in counts.values())


def detect_dns_tunneling(con, size_threshold=None):
    """Require large DNS packets plus a long, varied, or high-entropy subdomain.

    Two-label base domains are an approximation; unusual legitimate DNS can
    still alert, while tunneling with small or repetitive names may be missed.
    """
    cfg = Thresholds.from_env()
    size_threshold = cfg.dns_min_size if size_threshold is None else int(size_threshold)
    candidates = con.execute(f"""{WINDOW_CTE}
        SELECT ipsrc,
               udpdst,
               packet_length,
               dns_qname,
               window_bucket
        FROM stamped
        WHERE udpdst = 53
          AND packet_length > ?
          AND dns_qname IS NOT NULL
        ORDER BY packet_length DESC
    """, [cfg.window_seconds, size_threshold]).df()
    if candidates.empty:
        return candidates
    candidates = candidates.copy()
    candidates["first_label"] = candidates["dns_qname"].str.split(".").str[0]
    candidates["base_domain"] = candidates["dns_qname"].map(
        lambda name: ".".join(name.split(".")[-2:])
    )
    candidates = candidates[~candidates["dns_qname"].map(
        lambda name: any(name == domain or name.endswith("." + domain)
                         for domain in cfg.dns_allowlist)
    )].copy()
    if candidates.empty:
        return candidates
    candidates["entropy"] = candidates["first_label"].map(_dns_entropy)
    candidates["distinct_subdomains"] = candidates.groupby(
        ["ipsrc", "window_bucket", "base_domain"]
    )["first_label"].transform("nunique")
    return candidates[
        (candidates["first_label"].str.len() >= cfg.dns_label_min)
        | (candidates["entropy"] >= cfg.dns_entropy_min)
        | (candidates["distinct_subdomains"] >= cfg.dns_distinct_subdomains)
    ].copy()


def detect_malformed_flags(con):
    """SYN + FIN set on the same packet is never valid TCP behavior -
       LIKE catches it even if other flags (like ACK) are also present."""
    return con.execute("""
        SELECT ipsrc, ipdst, tcpflags, timestamp
        FROM connections
        WHERE CAST(tcpflags AS VARCHAR) LIKE '%S%'
          AND CAST(tcpflags AS VARCHAR) LIKE '%F%'
    """).df()


def run_all_detectors(db_path="test.duckdb"):
    con = duckdb.connect(db_path)

    print("\n--- Port Scan / SYN Flood ---")
    print(detect_port_scan_and_syn_flood(con))

    print("\n--- ICMP Flood ---")
    print(detect_icmp_flood(con))

    print("\n--- ARP Spoofing ---")
    print(detect_arp_spoofing(con))

    print("\n--- DNS Tunneling ---")
    print(detect_dns_tunneling(con))

    print("\n--- Malformed Flags (SYN+FIN) ---")
    print(detect_malformed_flags(con))

    con.close()


if __name__ == "__main__":
    run_all_detectors()
