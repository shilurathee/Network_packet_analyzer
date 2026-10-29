"""Small, offline feature/model and alert merge checks."""

import json

import pandas as pd
import pytest

from ml.features import FEATURES, extract_features, model_matrix
from ml.integrate import merge_alerts
from ml.train import train
from ml.detect import score
from tools.generate_traffic import generate
from tools.evaluate_ml import _diagnostics


def _row(ip, timestamp, protocol="TCP", flags="S", dst="10.2.0.1", port=443):
    return {"timestamp": timestamp, "ipsrc": ip, "arp_psrc": None,
            "ipdst": dst, "protocol": protocol, "packet_length": 60,
            "tcpdst": port if protocol == "TCP" else None,
            "udpdst": port if protocol == "UDP" else None,
            "tcpflags": flags if protocol == "TCP" else None,
            "icmp_type": 8 if protocol == "ICMP" else None}


def test_features_are_capture_relative_and_numeric():
    rows = [_row("10.0.0.1", 100.0), _row("10.0.0.1", 100.5, port=80),
            _row("10.0.0.1", 165.0), _row("10.0.0.2", 101.0, "ICMP")]
    features = extract_features(pd.DataFrame(rows), 60)
    assert list(features.columns) == ["ipsrc", "window_start", "response_only", *FEATURES]
    host = features[features["ipsrc"] == "10.0.0.1"].sort_values("window_start")
    assert host["packets"].tolist() == [2, 1]
    assert host["window_start"].tolist() == [100.0, 160.0]
    assert host.iloc[0]["unique_ports"] == 2
    assert host.iloc[0]["syn_only_ratio"] == 1
    assert model_matrix(features).notna().all().all()


def test_response_only_server_is_outside_client_model_scope(tmp_path):
    rows = [_row(f"10.1.0.{i}", 1000 + i + j * 0.01, port=1000 + j)
            for i in range(1, 41) for j in range(1 + i % 7)]
    rows += [_row("10.2.0.1", 1010 + j * 0.01, flags="SA", port=2000 + j)
             for j in range(50)]
    packets = pd.DataFrame(rows)
    model = tmp_path / "client.joblib"
    metadata = train(packets, model, "normal-capture")
    assert metadata["response_only_excluded"] == 1
    assert metadata["normal_examples"] == 40
    assert "10.2.0.1" not in set(score(packets, model, capture_sha256="separate-capture")["ipsrc"])


def test_training_and_scoring_reject_same_capture_and_bad_features(tmp_path):
    rows = [_row(f"10.1.0.{i}", 1000 + i + j * 0.01, port=1000 + j)
            for i in range(1, 41) for j in range(1 + i % 7)]
    packets = pd.DataFrame(rows)
    model = tmp_path / "model.joblib"
    metadata = train(packets, model, "training-hash")
    assert metadata["features"] == list(FEATURES)
    with pytest.raises(ValueError, match="training capture"):
        score(packets, model, capture_sha256="training-hash")
    scored = score(packets, model, capture_sha256="different-hash")
    assert scored["anomaly_score"].between(0, 1).all()
    data = json.loads(model.with_suffix(".json").read_text())
    data["features"] = ["wrong"]
    model.with_suffix(".json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="features"):
        score(packets, model)


def test_merging_rule_and_ml_flag_by_source_window():
    rules = pd.DataFrame([{"ipsrc": "10.0.0.1", "window_start": 100.0,
                           "detection_type": "port_scan", "alert_id": "rule1"}])
    scored = pd.DataFrame([
        {"ipsrc": "10.0.0.1", "window_start": 100.0, "ml_flag": True,
         "anomaly_score": 0.95, "explanation": "many ports", "packets": 20},
        {"ipsrc": "10.0.0.2", "window_start": 100.0, "ml_flag": True,
         "anomaly_score": 0.99, "explanation": "many destinations", "packets": 40},
    ])
    merged = merge_alerts(rules, scored, 60, 100.0)
    assert merged["source"].tolist() == ["rule+ml", "ml"]
    assert merged.iloc[0]["alert_id"] == "rule1"
    assert merged.iloc[1]["mitre_technique"] == "Unmapped (anomaly)"


def test_normal_training_capture_and_novel_labels_are_disjoint():
    normal, labels = generate(99, 150, 10, False, normal_only=True)
    assert len(normal) == 150 and labels["attackers"] == []
    _, novel = generate(42, 150, 10, False, novel_attacks=True)
    assert {item["attack_type"] for item in novel["attackers"]} >= {
        "slow_scan", "udp_flood", "host_sweep", "multi_host_syn_scan"}


def test_score_diagnostics_show_missed_attack_and_normal_false_positive():
    scored = pd.DataFrame([
        {"ipsrc": "10.0.0.1", "anomaly_score": 0.4, "raw_anomaly_score": 0.5,
         "ml_flag": False, "explanation": "normal"},
        {"ipsrc": "10.0.0.2", "anomaly_score": 0.9, "raw_anomaly_score": 0.8,
         "ml_flag": True, "explanation": "many ports"},
    ])
    result = _diagnostics(scored, {"attackers": [{"ip": "10.0.0.1", "attack_type": "novel"}]},
                          {"threshold": 0.7, "raw_threshold": 0.7})
    assert result["labelled_sources"][0]["flagged"] is False
    assert result["false_positive_sources"][0]["ip"] == "10.0.0.2"
    assert result["raw_threshold"] == 0.7
