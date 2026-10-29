"""Merge model flags with rule alerts for the same source and time window."""

import hashlib

import pandas as pd


def merge_alerts(alerts, scored, window_seconds, capture_start):
    """Keep one anomaly row per unmatched source/window; annotate rule matches."""
    result = alerts.copy()
    result["source"] = "rule"
    result["anomaly_score"] = pd.NA
    if scored.empty:
        return result
    for _, flag in scored[scored["ml_flag"]].iterrows():
        bucket = round((float(flag["window_start"]) - capture_start) / window_seconds)
        if result.empty:
            matching = []
        else:
            matching = result.index[(result["ipsrc"] == flag["ipsrc"])
                & (result["window_start"].notna())
                & (((result["window_start"].astype(float) - capture_start) / window_seconds)
                   .apply(lambda x: pd.notna(x) and int(x) == bucket))].tolist()
        if matching:
            result.loc[matching, "source"] = "rule+ml"
            result.loc[matching, "anomaly_score"] = float(flag["anomaly_score"])
            continue
        identity = f"ml|{flag['ipsrc']}|{flag['window_start']}"
        row = {column: None for column in result.columns}
        row.update({
            "ipsrc": flag["ipsrc"], "detection_type": "anomaly",
            "mitre_technique": "Unmapped (anomaly)",
            "details": f"Unknown pattern, investigate: {flag['explanation']}",
            "alert_id": hashlib.sha1(identity.encode()).hexdigest()[:12],
            "first_seen": flag["window_start"],
            "last_seen": flag["window_start"] + window_seconds,
            "count": int(flag["packets"]), "window_start": flag["window_start"],
            "severity": "medium", "source": "ml",
            "anomaly_score": float(flag["anomaly_score"]),
        })
        result = pd.concat([result, pd.DataFrame([row])], ignore_index=True)
    return result
