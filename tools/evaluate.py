"""Compare detected (IP, type) pairs with generator ground truth.

Inputs: --pcap and --truth; output is JSON metrics on stdout, never a
fabricated docs/results.md. Uses an in-memory DuckDB table, no API calls.
"""

import argparse
import json
from pathlib import Path

import duckdb

from alerts import build_alerts
from scapy_scan import process_pcap

DETECTORS = ("port_scan", "syn_flood", "icmp_flood", "arp_spoofing",
             "dns_tunneling", "malformed_flags")


def evaluate(pcap, truth_path):
    """Return per-detector TP, FP, FN and derived IP-level scores."""
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    expected = {(row["ip"], row["attack_type"]) for row in truth["attackers"]}
    df = process_pcap(str(pcap))
    con = duckdb.connect(":memory:")
    try:
        con.register("packets", df)
        con.execute("CREATE TABLE connections AS SELECT * FROM packets")
        alerts = build_alerts(con, enrich=False)
    finally:
        con.close()
    found = set(zip(alerts["ipsrc"], alerts["detection_type"]))
    metrics = {}
    for kind in DETECTORS:
        actual = {ip for ip, typ in found if typ == kind}
        labelled = {ip for ip, typ in expected if typ == kind}
        tp, fp, fn = len(actual & labelled), len(actual - labelled), len(labelled - actual)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        metrics[kind] = {"TP": tp, "FP": fp, "FN": fn, "precision": precision,
                         "recall": recall, "F1": 2 * precision * recall / (precision + recall)
                         if precision + recall else 0.0}
    return {"packets": len(df), "noisy_normal": truth.get("noisy_normal", False),
            "per_detector": metrics}


def main():
    """Print measured metrics for the owner to review before documenting."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.pcap, args.truth), indent=2))


if __name__ == "__main__":
    main()
