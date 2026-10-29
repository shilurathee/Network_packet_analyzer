# Phase 4 owner-run ML results — partial

Training: a separate `--normal-only` capture with a different seed. Evaluation: labelled baseline, noisy-normal and novel-attack captures. Metrics count **source IPs**, not packets; ROC-AUC requires both positive and negative sources. Model scores are normalised against training-score min/max, and the 99th percentile of training anomaly scores is the default flag threshold.

| Capture | Method | TP | FP | FN | Precision | Recall | F1 | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Clean | Rules | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Clean | ML | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Clean | Combined | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Baseline | Rules / ML / Combined | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Noisy | Rules / ML / Combined | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Novel (1,270 packets) | Rules | 6 | 0 | 4 | 1.0 | 0.6 | 0.7499999999999999 | 0.8 |
| Novel (1,270 packets) | ML | 0 | 1 | 10 | 0.0 | 0.0 | 0.0 | 0.9418326693227091 |
| Novel (1,270 packets) | Combined | 6 | 1 | 4 | 0.8571428571428571 | 0.6 | 0.7058823529411764 | 0.9908366533864542 |

The owner's normal-only training run produced **251** normal source/windows and a displayed 99th-percentile score cutoff of **0.6305873403583346**. The novel set had **10** labelled attacker IPs and **251** normal source IPs. The only model alert was for **10.2.0.1**, an unlabelled normal server. The model found **zero** of the four novel attack types at the default cutoff; adding it reduced combined precision and F1 relative to the six rules. The higher ROC-AUC describes ranking across cutoffs and does **not** imply successful alerting at the configured cutoff. Keep the 99th percentile unchanged until source scores and false-positive trade-offs have been reviewed.

The diagnostic rerun used raw cutoff **0.7295976443219502**. All four novel attackers scored below it:

| Novel type | Source IP | Raw score | Flagged |
|---|---|---:|---|
| UDP flood | 10.0.0.210 | 0.6332584844513518 | No |
| Host sweep | 10.0.0.211 | 0.6464891465439164 | No |
| SYN scan across hosts | 10.0.0.212 | 0.681255323774754 | No |
| Slow scan | 10.0.0.213 | 0.5454399001802798 | No |

The unlabelled normal server **10.2.0.1** scored **0.8933762216288652** and was flagged. Thus lowering a single global cutoff enough to catch even the highest-scoring novel attacker would still flag that server. This is a limitation of the present model/training distribution; the only verified result is the owner's synthetic run. The diagnostic test rerun passed **63** tests with **8** dashboard asyncio deprecation warnings. No threshold or model weights were changed in response to these results.

100,000-packet scoring median, excluding parser: **PENDING** seconds across **PENDING** runs on **PENDING** machine. Do not infer that ML improves on the rules until owner-run measurements support it. A trained model should be loaded only from a trusted local path because joblib uses pickle serialization.
