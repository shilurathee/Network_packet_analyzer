"""Measure the real parser, 100,000-row DuckDB stages and dashboard load.

Inputs: --pcap reference capture, --packets >= 100000, --runs (default 5).
Output: JSON medians and machine specs on stdout for owner verification;
docs/benchmarks.md remains a placeholder until real output is supplied.
"""

import argparse
import json
import os
import platform
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

import duckdb
import pandas as pd
from streamlit.testing.v1 import AppTest

from alerts import build_alerts, save_alerts
from detector import (
    detect_arp_spoofing,
    detect_dns_tunneling,
    detect_icmp_flood,
    detect_malformed_flags,
    detect_port_scan_and_syn_flood,
)
from scapy_scan import process_pcap

DETECTORS = {
    "syn_and_scan": detect_port_scan_and_syn_flood,
    "icmp": detect_icmp_flood,
    "arp": detect_arp_spoofing,
    "dns": detect_dns_tunneling,
    "flags": detect_malformed_flags,
}


def synthetic_rows(count):
    """Build a representative 15-column table without slow Scapy generation."""
    i = pd.Series(range(count))
    df = pd.DataFrame({
        "timestamp": 1_700_000_000.0 + i * 0.01,
        "protocol": "TCP",
        "packet_length": 60,
        "ipsrc": "10.0.0.10",
        "ipdst": "10.0.0.20",
        "tcpsrc": 40000,
        "tcpdst": 443,
        "tcpflags": "A",
        "udpsrc": pd.Series([None] * count, dtype="Int64"),
        "udpdst": pd.Series([None] * count, dtype="Int64"),
        "icmp_type": pd.Series([None] * count, dtype="Int64"),
        "arp_hwsrc": pd.Series([None] * count, dtype="string"),
        "arp_psrc": pd.Series([None] * count, dtype="string"),
        "arp_hwdst": pd.Series([None] * count, dtype="string"),
        "arp_pdst": pd.Series([None] * count, dtype="string"),
    })
    # A tiny flagged tail makes AppTest exercise the full dashboard, not st.stop().
    df.loc[df.index[-51:], ["ipsrc", "tcpflags", "tcpdst"]] = ["10.0.0.66", "S", 80]
    return df


def measure_parser(pcap):
    """Return wall time, parsed rows and peak traced Python allocation."""
    tracemalloc.start()
    start = time.perf_counter()
    df = process_pcap(str(pcap))
    seconds = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return seconds, len(df), peak / (1024 * 1024)


def measure_db(df, db_path):
    """Measure load, each rule, alert build and dashboard SQL queries."""
    con = duckdb.connect(str(db_path))
    times = {}
    try:
        start = time.perf_counter()
        con.register("batch", df)
        con.execute("CREATE OR REPLACE TABLE connections AS SELECT * FROM batch")
        times["duckdb_load_s"] = time.perf_counter() - start
        for name, rule in DETECTORS.items():
            start = time.perf_counter()
            rule(con)
            times[f"detector_{name}_s"] = time.perf_counter() - start
        start = time.perf_counter()
        alerts = build_alerts(con, enrich=False)
        save_alerts(con, alerts)
        times["alert_build_s"] = time.perf_counter() - start
        start = time.perf_counter()
        for sql in ("SELECT COUNT(*) AS n FROM connections",
                    "SELECT * FROM alerts",
                    "SELECT protocol, COUNT(*) AS packets FROM connections GROUP BY protocol"):
            con.execute(sql).fetchall()
        times["dashboard_queries_s"] = time.perf_counter() - start
    finally:
        con.close()
    return times


def measure_app(db_path):
    """Time Streamlit AppTest against the closed database file."""
    old = os.environ.get("IDS_DB_PATH")
    os.environ["IDS_DB_PATH"] = str(db_path)
    try:
        start = time.perf_counter()
        app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "dashboard.py"))
        app.run(timeout=60)
        if app.exception:
            raise RuntimeError(f"Dashboard AppTest exceptions: {app.exception}")
        return time.perf_counter() - start
    finally:
        if old is None:
            os.environ.pop("IDS_DB_PATH", None)
        else:
            os.environ["IDS_DB_PATH"] = old


def benchmark(pcap, count, runs):
    """Return medians from five independent passes and the measured host specs."""
    if count < 100_000 or runs < 1:
        raise ValueError("--packets must be >= 100000 and --runs must be >= 1")
    df = synthetic_rows(count)
    results = []
    for _ in range(runs):
        parsed_s, parsed_count, peak_mb = measure_parser(pcap)
        with tempfile.TemporaryDirectory() as folder:
            db_path = Path(folder) / "benchmark.duckdb"
            stages = measure_db(df, db_path)
            stages["dashboard_apptest_s"] = measure_app(db_path)
        stages.update(parser_s=parsed_s, parser_rows=parsed_count, parser_peak_python_mb=peak_mb)
        results.append(stages)
    return {
        "machine": {"system": platform.platform(), "python": platform.python_version(),
                    "processor": platform.processor(), "logical_cpus": os.cpu_count()},
        "packets": count, "runs": runs,
        "median": {key: statistics.median(row[key] for row in results)
                   for key in results[0]},
        "dashboard_under_3s": statistics.median(row["dashboard_apptest_s"] for row in results) < 3,
    }


def main():
    """Print JSON for the owner to paste back; do not edit the report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, default=Path("test_traffic.pcap"))
    parser.add_argument("--packets", type=int, default=100_000)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.pcap, args.packets, args.runs), indent=2))


if __name__ == "__main__":
    main()
