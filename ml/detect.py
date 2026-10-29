"""Score capture windows with a model trained on distinct normal traffic."""

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from ml.features import FEATURES, extract_features, model_matrix


def score(packets, model_path="models/isolation_forest.joblib", capture_sha256=None):
    """Return scored source/windows; larger 0..1 scores indicate anomalies."""
    try:
        import joblib
    except ImportError as exc:
        raise RuntimeError("ML requires scikit-learn and joblib: python -m pip install -r requirements.txt") from exc
    path = Path(model_path)
    if not path.is_file() or not path.with_suffix(".json").is_file():
        raise FileNotFoundError(f"ML model missing at {path}; train with python -m ml.train --pcap NORMAL.pcap")
    metadata = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    if metadata["features"] != list(FEATURES):
        raise ValueError("ML model features do not match this version of the parser")
    if capture_sha256 and capture_sha256 == metadata["capture_sha256"]:
        raise ValueError("Refusing to score the training capture; use a separate test PCAP")
    features = extract_features(packets, metadata["window_seconds"])
    matrix = model_matrix(features)
    if matrix.empty:
        return features.assign(anomaly_score=pd.Series(dtype=float),
                               raw_anomaly_score=pd.Series(dtype=float),
                               ml_flag=pd.Series(dtype=bool),
                               explanation=pd.Series(dtype=str))
    # Only load models created locally; joblib deserialization executes pickle.
    pipeline = joblib.load(path)
    if list(getattr(pipeline, "feature_names_in_", [])) != list(FEATURES):
        raise ValueError("Stored ML model feature order differs from metadata")
    raw = -pipeline.score_samples(matrix)
    low, high = metadata["score_min"], metadata["score_max"]
    scores = np.clip((raw - low) / (high - low), 0, 1)
    median, mad = pd.Series(metadata["median"]), pd.Series(metadata["mad"])
    # A constant training column has zero MAD; use a unit floor so a novel
    # value still yields a useful, finite explanation rather than disappearing.
    scale = (1.4826 * mad).where(mad > 0, 1.0)
    robust_z = ((matrix - median).abs() / scale).fillna(0)
    explanations = []
    for _, row in robust_z.iterrows():
        top = row.nlargest(2)
        explanations.append(", ".join(f"{name} differs by {value:.1f} robust units from normal"
                                      for name, value in top.items() if value >= 2)
                            or "unusual combination of traffic features")
    # Compare unbounded scores: clipping the display score to 1 must not
    # suppress outliers when the normal 99th percentile is itself the max.
    return features.assign(anomaly_score=scores, raw_anomaly_score=raw,
                           ml_flag=raw > metadata["raw_threshold"],
                           explanation=explanations)


def capture_hash(path):
    """Hash the input only when it is a PCAP available on disk."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
