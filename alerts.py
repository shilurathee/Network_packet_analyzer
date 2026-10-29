import duckdb
import pandas as pd
import hashlib

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
DETAIL_COLUMNS = ["alert_id", "ipdst", "first_seen", "last_seen", "count", "window_start", "severity"]

# Tunable thresholds: a few SYNs to 1-2 ports is normal browsing, not an attack
SCAN_MIN_PORTS = Thresholds().scan_min_ports
FLOOD_MIN_SYNS = Thresholds().flood_min_syns


def _finish(df, detection_type):
    """Stamp the detection name + MITRE ID, keep only the common columns."""
    df = df.copy()
    df["detection_type"] = detection_type
    df["mitre_technique"] = MITRE_MAP[detection_type]
    if "window_bucket" not in df:
        df["window_bucket"] = None
    return df[COLUMNS + ["window_bucket", "rule_count", "severity_ratio"]]


def _severity(ratio):
    """Use distance above the rule cutoff as a simple triage priority."""
    return "high" if ratio > 5 else "medium" if ratio >= 2 else "low"


def _add_alert_metadata(con, alerts_df, cfg):
    """Add victim, observed times, stable ID and severity to a few alert rows."""
    origin = con.execute("SELECT MIN(timestamp) FROM connections").fetchone()[0]
    records = []
    for _, row in alerts_df.iterrows():
        kind = row["detection_type"]
        arp = kind == "arp_spoofing"
        source, target = ("arp_psrc", "arp_pdst") if arp else ("ipsrc", "ipdst")
        sql = f"SELECT MIN(timestamp), MAX(timestamp), ANY_VALUE({target}) FROM connections WHERE {source} = ?"
        params = [row["ipsrc"]]
        if kind in ("syn_flood", "port_scan"):
            sql += " AND tcpflags = 'S'"
        elif kind == "icmp_flood":
            sql += " AND icmp_type = 8"
        elif kind == "dns_tunneling":
            sql += " AND udpdst = 53 AND packet_length > ?"
            params.append(cfg.dns_min_size)
        elif kind == "malformed_flags":
            sql += " AND tcpflags LIKE '%S%' AND tcpflags LIKE '%F%'"
        bucket = row["window_bucket"]
        window_start = None
        if pd.notna(bucket) and origin is not None:
            window_start = float(origin) + int(bucket) * cfg.window_seconds
            sql += " AND timestamp >= ? AND timestamp < ?"
            params.extend([window_start, window_start + cfg.window_seconds])
        first, last, victim = con.execute(sql, params).fetchone()
        if window_start is None:
            window_start = first
        identity = f"{kind}|{row['ipsrc']}|{victim}|{window_start}"
        records.append({"alert_id": hashlib.sha1(identity.encode()).hexdigest()[:12],
                        "ipdst": victim, "first_seen": first, "last_seen": last,
                        "count": int(row["rule_count"]), "window_start": window_start,
                        "severity": _severity(float(row["severity_ratio"]))})
    return pd.concat([alerts_df[COLUMNS].reset_index(drop=True), pd.DataFrame(records)], axis=1)


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
        flood["rule_count"] = flood["incomplete_syns"]
        flood["severity_ratio"] = flood["incomplete_syns"] / cfg.flood_min_syns
        scan["rule_count"] = scan["unique_ports"]
        scan["severity_ratio"] = scan["unique_ports"] / cfg.scan_min_ports
        parts.append(_finish(flood, "syn_flood"))
        parts.append(_finish(scan, "port_scan"))

    # --- ICMP flood ---
    icmp = detect_icmp_flood(con)
    if not icmp.empty:
        icmp = icmp.sort_values("icmp_count", ascending=False).drop_duplicates("ipsrc")
        icmp["rule_count"] = icmp["icmp_count"]
        icmp["severity_ratio"] = icmp["icmp_count"] / cfg.icmp_min
        icmp["details"] = icmp["icmp_count"].astype(str) + " ICMP echo requests"
        parts.append(_finish(icmp, "icmp_flood"))

    # --- ARP spoofing (the IP being faked is the "source" here) ---
    arp = detect_arp_spoofing(con).rename(columns={"arp_psrc": "ipsrc"})
    if not arp.empty:
        arp = arp.sort_values("mac_count", ascending=False).drop_duplicates("ipsrc")
        arp["rule_count"] = arp["mac_count"]
        arp["severity_ratio"] = arp["mac_count"] / cfg.arp_min_macs
        arp["details"] = "IP claimed by " + arp["mac_count"].astype(str) + " different MACs"
        parts.append(_finish(arp, "arp_spoofing"))

    # --- DNS tunneling (one row per packet -> group into one alert per IP) ---
    dns = detect_dns_tunneling(con)
    if not dns.empty:
        dns = dns.groupby("ipsrc").agg(
            n=("packet_length", "size"),
            biggest=("packet_length", "max"),
        ).reset_index()
        dns["rule_count"] = dns["n"]
        dns["severity_ratio"] = dns["biggest"] / cfg.dns_min_size
        dns["details"] = (
            dns["n"].astype(str) + " oversized DNS packets (max "
            + dns["biggest"].astype(str) + " bytes)"
        )
        parts.append(_finish(dns, "dns_tunneling"))

    # --- Malformed flags (also one row per packet -> one alert per IP) ---
    bad = detect_malformed_flags(con)
    if not bad.empty:
        bad = bad.groupby("ipsrc").size().reset_index(name="n")
        bad["rule_count"] = bad["n"]
        bad["severity_ratio"] = 1.0
        bad["details"] = bad["n"].astype(str) + " packets with SYN+FIN set"
        parts.append(_finish(bad, "malformed_flags"))

    parts = [p for p in parts if not p.empty]
    if not parts:
        return pd.DataFrame(columns=COLUMNS + DETAIL_COLUMNS)
    alerts_df = pd.concat(parts, ignore_index=True)
    alerts_df = _add_alert_metadata(con, alerts_df, cfg)
    if enrich:
        alerts_df = enrich_alerts(alerts_df, include_virustotal=include_virustotal)
        persist_ip_reputation(con, alerts_df)  # store lat/lon/abuse in ip_reputation table
    return alerts_df


def save_alerts(con, alerts_df):
    """Migrate older alert tables and replace current-run rows by column name."""
    con.register("alerts_temp", alerts_df)
    con.execute("CREATE TABLE IF NOT EXISTS alerts AS SELECT * FROM alerts_temp WHERE 1 = 0")
    existing = {row[1] for row in con.execute("PRAGMA table_info('alerts')").fetchall()}
    for column in alerts_df.columns:
        if column not in existing:
            dtype = alerts_df[column].dtype
            sql_type = ("BIGINT" if pd.api.types.is_integer_dtype(dtype) else
                        "DOUBLE" if pd.api.types.is_float_dtype(dtype) else "VARCHAR")
            con.execute(f'ALTER TABLE alerts ADD COLUMN IF NOT EXISTS "{column}" {sql_type}')
    con.execute("DELETE FROM alerts")
    con.execute("INSERT INTO alerts BY NAME SELECT * FROM alerts_temp")
    con.execute("CREATE TABLE IF NOT EXISTS meta (schema_version INTEGER)")
    con.execute("DELETE FROM meta")
    con.execute("INSERT INTO meta VALUES (2)")
    con.unregister("alerts_temp")


if __name__ == "__main__":
    con = duckdb.connect("test.duckdb")
    alerts_df = build_alerts(con)
    save_alerts(con, alerts_df)
    print(alerts_df.to_string())
    con.close()
