# Phase 4 owner-run ML results — PENDING

Training: a separate `--normal-only` capture with a different seed. Evaluation: labelled baseline, noisy-normal and novel-attack captures. Metrics count **source IPs**, not packets; ROC-AUC requires both positive and negative sources. Model scores are normalised against training-score min/max, and the 99th percentile of training anomaly scores is the default flag threshold.

| Capture | Method | TP | FP | FN | Precision | Recall | F1 | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Clean | Rules | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Clean | ML | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Clean | Combined | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Baseline | Rules / ML / Combined | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Noisy | Rules / ML / Combined | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Novel | Rules / ML / Combined | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

100,000-packet scoring median, excluding parser: **PENDING** seconds across **PENDING** runs on **PENDING** machine. Do not infer that ML improves on the rules until owner-run measurements support it. A trained model should be loaded only from a trusted local path because joblib uses pickle serialization.
