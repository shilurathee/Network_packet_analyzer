"""Train only from a separate normal PCAP: python -m ml.train --pcap PATH."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from ml.features import FEATURES, extract_features, model_matrix


def train(packets, model_path, capture_sha256, percentile=99.0, window_seconds=60):
    """Fit a deterministic Isolation Forest and save its training distribution."""
    try:
        import joblib
        from sklearn.ensemble import IsolationForest
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import RobustScaler
    except ImportError as exc:
        raise RuntimeError("ML requires scikit-learn and joblib: python -m pip install -r requirements.txt") from exc
    if not 0 < percentile < 100:
        raise ValueError("percentile must be between 0 and 100")
    features = extract_features(packets, window_seconds)
    matrix = model_matrix(features)
    if len(matrix) < 30:
        raise ValueError("Need at least 30 normal source/window examples for training")
    pipeline = Pipeline([
        ("scaler", RobustScaler()),
        ("forest", IsolationForest(n_estimators=200, random_state=42, n_jobs=-1)),
    ])
    pipeline.fit(matrix)
    raw_scores = -pipeline.score_samples(matrix)
    low, high = float(raw_scores.min()), float(raw_scores.max())
    if high <= low:
        raise ValueError("Normal training examples have no score variation")
    raw_threshold = float(np.percentile(raw_scores, percentile))
    threshold = (raw_threshold - low) / (high - low)
    median = matrix.median()
    mad = (matrix - median).abs().median()
    path = Path(model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "features": list(FEATURES), "training_date": datetime.now(timezone.utc).isoformat(),
        "capture_sha256": capture_sha256, "normal_examples": len(matrix),
        "window_seconds": window_seconds, "percentile": percentile,
        "score_min": low, "score_max": high, "threshold": threshold,
        "raw_threshold": raw_threshold,
        "median": median.to_dict(), "mad": mad.to_dict(),
    }
    joblib.dump(pipeline, path)
    path.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True, help="A separate, normal-only capture")
    parser.add_argument("--model", type=Path, default=Path("models/isolation_forest.joblib"))
    parser.add_argument("--percentile", type=float, default=99.0)
    args = parser.parse_args()
    truth_path = args.pcap.with_name("ground_truth.json")
    if truth_path.exists():
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        if truth.get("attackers") or truth.get("noisy_normal"):
            parser.error("Training capture must be normal-only; ground truth contains attacks/noisy traffic")
    from scapy_scan import process_pcap
    packets = process_pcap(str(args.pcap))
    sha = hashlib.sha256(args.pcap.read_bytes()).hexdigest()
    result = train(packets, args.model, sha, percentile=args.percentile)
    print(json.dumps({k: result[k] for k in ("normal_examples", "percentile", "threshold")}, indent=2))


if __name__ == "__main__":
    main()
