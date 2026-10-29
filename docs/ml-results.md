# Phase 4 owner-run ML results — first model (historical)

Training: a separate `--normal-only` capture with a different seed. Evaluation: labelled baseline, noisy-normal and novel-attack captures. Metrics count **source IPs**, not packets; ROC-AUC requires both positive and negative sources. Model scores are normalised against training-score min/max, and the 99th percentile of training anomaly scores is the default flag threshold.

| Capture | Method | TP | FP | FN | Precision | Recall | F1 | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Clean (1,000 packets) | Rules | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | null |
| Clean (1,000 packets) | ML | 0 | 1 | 0 | 0.0 | 0.0 | 0.0 | null |
| Clean (1,000 packets) | Combined | 0 | 1 | 0 | 0.0 | 0.0 | 0.0 | null |
| Baseline (1,088 packets) | Rules | 6 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Baseline (1,088 packets) | ML | 0 | 1 | 6 | 0.0 | 0.0 | 0.0 | 0.9163346613545816 |
| Baseline (1,088 packets) | Combined | 6 | 1 | 0 | 0.8571428571428571 | 1.0 | 0.923076923076923 | 0.99800796812749 |
| Noisy (1,128 packets) | Rules | 6 | 2 | 0 | 0.75 | 1.0 | 0.8571428571428571 | 0.9960629921259843 |
| Noisy (1,128 packets) | ML | 0 | 1 | 6 | 0.0 | 0.0 | 0.0 | 0.9094488188976378 |
| Noisy (1,128 packets) | Combined | 6 | 3 | 0 | 0.6666666666666666 | 1.0 | 0.8 | 0.9940944881889764 |
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

On the clean set there are **zero labelled positives**, so precision/recall/F1 display as `0.0` by the evaluator's convention and ROC-AUC is undefined (`null`); they do not measure attack detection there. On the baseline and noisy captures, ML again found zero attackers and contributed one false positive each. The combined result is worse than rules alone across all three labelled test sets.

The owner measured a **5.940199600001506-second** median over **5** scoring runs on **100,088** parsed packet rows and **3,457** source/windows, excluding PCAP parsing. Machine: Windows-11-10.0.26200-SP0, Python **3.14.7**, Intel64 Family 6 Model 189 Stepping 1 GenuineIntel. This meets the 10-second scoring target for this machine and dataset. Do not infer that ML improves on the rules from the timing result. A trained model should be loaded only from a trusted local path because joblib uses pickle serialization.

## Initiating-source model rerun — owner-validated

This model excludes response-only SYN+ACK source/windows from both training and inference because the first training capture contained just one such normal server. The owner's retraining used **250** eligible normal source/windows. Its displayed 99th-percentile cutoff was **1.0** (raw cutoff **0.7662642240839863**). The table below describes this scoped model; the previous table remains the first model's historical result.

| Capture | Method | TP | FP | FN | Precision | Recall | F1 | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Clean (1,000 packets) | Rules | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | null |
| Clean (1,000 packets) | ML | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | null |
| Clean (1,000 packets) | Combined | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | null |
| Baseline (1,088 packets) | Rules | 6 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Baseline (1,088 packets) | ML | 0 | 0 | 6 | 0.0 | 0.0 | 0.0 | 0.7928286852589641 |
| Baseline (1,088 packets) | Combined | 6 | 0 | 0 | 1.0 | 1.0 | 1.0 | 0.9920318725099602 |
| Noisy (1,128 packets) | Rules | 6 | 2 | 0 | 0.75 | 1.0 | 0.8571428571428571 | 0.9960629921259843 |
| Noisy (1,128 packets) | ML | 0 | 0 | 6 | 0.0 | 0.0 | 0.0 | 0.7887139107611549 |
| Noisy (1,128 packets) | Combined | 6 | 2 | 0 | 0.75 | 1.0 | 0.8571428571428571 | 0.9881889763779528 |
| Novel (1,270 packets) | Rules | 6 | 0 | 4 | 1.0 | 0.6 | 0.7499999999999999 | 0.8 |
| Novel (1,270 packets) | ML | 0 | 0 | 10 | 0.0 | 0.0 | 0.0 | 0.8127490039840638 |
| Novel (1,270 packets) | Combined | 6 | 0 | 4 | 1.0 | 0.6 | 0.7499999999999999 | 0.9322709163346614 |

The owner rerun passed **64** tests with **8** dashboard asyncio deprecation warnings. On the novel capture, all ten labelled sources were unflagged; the highest raw attack score was **0.5501453240323717**, below the raw cutoff. There were no model false positives, but the model caught **none** of the four novel attack types, so adding it did not improve alert-level performance over the rules. The 1.0 displayed cutoff comes from normalization against the training-score maximum; the flag decision uses the raw cutoff. These scores are not evidence that the model detects unseen attacks. Response-only source/windows are outside this model's coverage.

The owner's five-run median was **6.392216899999767 seconds** for **100,088** parsed packet rows and **3,456** eligible windows, excluding parsing. Machine: Windows-11-10.0.26200-SP0, Python **3.14.7**, Intel64 Family 6 Model 189 Stepping 1 GenuineIntel. This meets the Phase 4 scoring-time target on this dataset, while detection utility remains unproven.
