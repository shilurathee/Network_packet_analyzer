import duckdb
from config import Thresholds

# Anchor windows at the first packet, so short reference captures do not
# straddle a wall-clock boundary just because of their start timestamp.
WINDOW_BUCKET = """CAST(FLOOR((COALESCE(timestamp, 0) -
    COALESCE((SELECT MIN(timestamp) FROM connections), 0)) / ?) AS BIGINT)"""
WINDOW_CTE = f"WITH stamped AS (SELECT *, {WINDOW_BUCKET} AS window_bucket FROM connections)"


def detect_port_scan_and_syn_flood(con, window_seconds=None):
    """unique_ports == 1  -> SYN flood
       unique_ports > 1   -> Port scan
    """
    window_seconds = window_seconds or Thresholds.from_env().window_seconds
    return con.execute(f"""{WINDOW_CTE}
        SELECT ipsrc,
               window_bucket,
               COUNT(*) AS total_syns,
               COUNT(DISTINCT tcpdst) AS unique_ports
        FROM stamped
        WHERE CAST(tcpflags AS VARCHAR) = 'S'
        GROUP BY ipsrc, window_bucket
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
               COUNT(DISTINCT arp_hwsrc) AS mac_count
        FROM stamped
        WHERE arp_psrc IS NOT NULL
        GROUP BY arp_psrc, window_bucket
        HAVING mac_count >= ?
        ORDER BY mac_count DESC
    """, [window_seconds, cfg.arp_min_macs]).df()


def detect_dns_tunneling(con, size_threshold=None):
    """DNS traffic (udp port 53) with abnormally large packet size -
       normal lookups are small; tunneled data inflates packet length."""
    size_threshold = (Thresholds.from_env().dns_min_size
                      if size_threshold is None else int(size_threshold))
    return con.execute("""
        SELECT ipsrc,
               udpdst,
               packet_length
        FROM connections
        WHERE udpdst = 53
          AND packet_length > ?
        ORDER BY packet_length DESC
    """, [size_threshold]).df()


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
