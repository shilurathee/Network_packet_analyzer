"""Compare rules, ML and combined detection on a labelled, separate PCAP.

Run with --pcap, --truth and --model. Reports source-IP level metrics and
ROC-AUC only when both normal and attacker sources are present. No API calls.
"""

import argparse
import json
from pathlib import Path

import duckdb

from alerts import build_alerts
from ml.detect import capture_hash, score
from ml.integrate import merge_alerts
from scapy_scan import process_pcap


def _metrics(positives, predicted, universe, scores):
    from sklearn.metrics import roc_auc_score
    tp = len(positives & predicted)
    fp = len(predicted - positives)
    fn = len(positives - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    negatives = universe - positives
    auc = roc_auc_score([int(ip in positives) for ip in sorted(universe)],
                        [scores.get(ip, 0.0) for ip in sorted(universe)]) if positives and negatives else None
    return {"TP": tp, "FP": fp, "FN": fn, "precision": precision,
            "recall": recall, "F1": f1, "ROC_AUC": auc}


def _diagnostics(scored, truth, metadata):
    """Expose score/cutoff comparisons without changing prediction behavior."""
    best = scored.sort_values("raw_anomaly_score", ascending=False).drop_duplicates("ipsrc")
    rows = best.set_index("ipsrc")
    labelled = []
    for item in truth["attackers"]:
        ip = item["ip"]
        if ip not in rows.index:
            labelled.append({"ip": ip, "attack_type": item["attack_type"], "missing_score": True})
            continue
        row = rows.loc[ip]
        labelled.append({"ip": ip, "attack_type": item["attack_type"],
                         "score": float(row["anomaly_score"]),
                         "raw_score": float(row["raw_anomaly_score"]),
                         "flagged": bool(row["ml_flag"])})
    attackers = {item["ip"] for item in truth["attackers"]}
    false_positives = [
        {"ip": row["ipsrc"], "score": float(row["anomaly_score"]),
         "raw_score": float(row["raw_anomaly_score"]), "explanation": row["explanation"]}
        for _, row in best.iterrows()
        if bool(row["ml_flag"]) and row["ipsrc"] not in attackers
    ]
    return {"display_threshold": metadata["threshold"],
            "raw_threshold": metadata["raw_threshold"],
            "labelled_sources": labelled, "false_positive_sources": false_positives}


def evaluate(pcap, truth_path, model_path, details=False):
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    positives = {item["ip"] for item in truth["attackers"]}
    packets = process_pcap(str(pcap))
    con = duckdb.connect(":memory:")
    try:
        con.register("input_packets", packets)
        con.execute("CREATE TABLE connections AS SELECT * FROM input_packets")
        rules = build_alerts(con, enrich=False)
    finally:
        con.close()
    ml = score(packets, model_path, capture_sha256=capture_hash(pcap))
    metadata = json.loads(Path(model_path).with_suffix(".json").read_text(encoding="utf-8"))
    merged = merge_alerts(rules, ml, metadata["window_seconds"],
                          float(packets["timestamp"].min()))
    universe = set(packets["ipsrc"].dropna().astype(str)) | set(packets["arp_psrc"].dropna().astype(str))
    universe.discard("0.0.0.0")
    rule_ips = set(rules["ipsrc"].dropna())
    ml_ips = set(ml.loc[ml["ml_flag"], "ipsrc"])
    combined_ips = set(merged["ipsrc"].dropna())
    ml_scores = ml.groupby("ipsrc")["anomaly_score"].max().to_dict()
    result = {
        "packets": len(packets), "labelled_attackers": len(positives),
        "normal_sources": len(universe - positives),
        "rules_only": _metrics(positives, rule_ips, universe,
                               {ip: float(ip in rule_ips) for ip in universe}),
        "ml_only": _metrics(positives, ml_ips, universe, ml_scores),
        "combined": _metrics(positives, combined_ips, universe,
                             {ip: max(float(ip in rule_ips), ml_scores.get(ip, 0.0)) for ip in universe}),
        "novel_attacks": [item["attack_type"] for item in truth["attackers"]
                          if item["attack_type"] in {"slow_scan", "udp_flood", "host_sweep", "multi_host_syn_scan"}],
    }
    if details:
        result["score_diagnostics"] = _diagnostics(ml, truth, metadata)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--model", type=Path, default=Path("models/isolation_forest.joblib"))
    parser.add_argument("--details", action="store_true", help="Show labelled and false-positive source scores versus the cutoff")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.pcap, args.truth, args.model, details=args.details), indent=2))


if __name__ == "__main__":
    main()
