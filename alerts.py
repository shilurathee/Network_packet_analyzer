import duckdb
import pandas as pd

from detector import (
    detect_port_scan_and_syn_flood,
    detect_icmp_flood,
    detect_arp_spoofing,
    detect_dns_tunneling,
    detect_malformed_flags,
)
from mitre_mapping import MITRE_MAP
from enrichment import enrich_alerts, persist_ip_reputation
from config import Thresholds

COLUMNS = ["ipsrc", "detection_type", "mitre_technique", "details"]

# Tunable thresholds: a few SYNs to 1-2 ports is normal browsing, not an attack
SCAN_MIN_PORTS = Thresholds().scan_min_ports
FLOOD_MIN_SYNS = Thresholds().flood_min_syns


def _finish(df, detection_type):
    """Stamp the detection name + MITRE ID, keep only the common columns."""
    df = df.copy()
    df["detection_type"] = detection_type
    df["mitre_technique"] = MITRE_MAP[detection_type]
    return df[COLUMNS]


def build_alerts(con, enrich: bool = True, include_virustotal: bool = False):
    cfg = Thresholds.from_env()
    parts = []

    #  Port scan vs SYN flood (classified by unique_ports) 
    syn = detect_port_scan_and_syn_flood(con)
    if not syn.empty:
        syn["details"] = (
            syn["total_syns"].astype(str) + " SYNs to "
            + syn["unique_ports"].astype(str) + " port(s)"
        )
        flood = syn[(syn["unique_ports"] == 1)
                    & (syn["incomplete_syns"] > cfg.flood_min_syns)
                    & (syn["completion_rate"] < cfg.syn_max_completion_rate)]
        scan = syn[syn["unique_ports"] >= cfg.scan_min_ports]
        flood = flood.sort_values("total_syns", ascending=False).drop_duplicates("ipsrc")
        scan = scan.sort_values("unique_ports", ascending=False).drop_duplicates("ipsrc")
        parts.append(_finish(flood, "syn_flood"))
        parts.append(_finish(scan, "port_scan"))

    # --- ICMP flood ---
    icmp = detect_icmp_flood(con)
    if not icmp.empty:
        icmp = icmp.sort_values("icmp_count", ascending=False).drop_duplicates("ipsrc")
        icmp["details"] = icmp["icmp_count"].astype(str) + " ICMP echo requests"
        parts.append(_finish(icmp, "icmp_flood"))

    # --- ARP spoofing (the IP being faked is the "source" here) ---
    arp = detect_arp_spoofing(con).rename(columns={"arp_psrc": "ipsrc"})
    if not arp.empty:
        arp = arp.sort_values("mac_count", ascending=False).drop_duplicates("ipsrc")
        arp["details"] = "IP claimed by " + arp["mac_count"].astype(str) + " different MACs"
        parts.append(_finish(arp, "arp_spoofing"))

    # --- DNS tunneling (one row per packet -> group into one alert per IP) ---
    dns = detect_dns_tunneling(con)
    if not dns.empty:
        dns = dns.groupby("ipsrc").agg(
            n=("packet_length", "size"),
            biggest=("packet_length", "max"),
        ).reset_index()
        dns["details"] = (
            dns["n"].astype(str) + " oversized DNS packets (max "
            + dns["biggest"].astype(str) + " bytes)"
        )
        parts.append(_finish(dns, "dns_tunneling"))

    # --- Malformed flags (also one row per packet -> one alert per IP) ---
    bad = detect_malformed_flags(con)
    if not bad.empty:
        bad = bad.groupby("ipsrc").size().reset_index(name="n")
        bad["details"] = bad["n"].astype(str) + " packets with SYN+FIN set"
        parts.append(_finish(bad, "malformed_flags"))

    parts = [p for p in parts if not p.empty]
    if not parts:
        return pd.DataFrame(columns=COLUMNS)
    alerts_df = pd.concat(parts, ignore_index=True)
    if enrich:
        alerts_df = enrich_alerts(alerts_df, include_virustotal=include_virustotal)
        persist_ip_reputation(con, alerts_df)  # store lat/lon/abuse in ip_reputation table
    return alerts_df


def save_alerts(con, alerts_df):
    con.register("alerts_temp", alerts_df)
    con.execute("CREATE OR REPLACE TABLE alerts AS SELECT * FROM alerts_temp")
    con.unregister("alerts_temp")


if __name__ == "__main__":
    con = duckdb.connect("test.duckdb")
    alerts_df = build_alerts(con)
    save_alerts(con, alerts_df)
    print(alerts_df.to_string())
    con.close()
