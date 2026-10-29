# Optional anomaly detector (Phase 4)

The six signature rules remain active without a model. With `--ml`, the pipeline scores each source IP in each capture-relative 60-second window. It records packet counts and bytes, length statistics, distinct destination ports and IPs, SYN/ICMP/DNS activity, protocol fractions, flag variety and inter-arrival times. Heavy counts use `log1p`. Training fits `RobustScaler` followed by `IsolationForest(n_estimators=200, random_state=42)`. Model files are ignored by Git; **load only models trained locally**, because joblib deserialization uses pickle.

The model must learn from normal-only traffic. Generate a **separate** training capture with a different seed and an empty attacker list; the CLI rejects a sidecar with labelled attacks or noisy traffic. The model JSON records the feature names/order, training date, training capture SHA-256, window size, normal-score range and 99th-percentile threshold. Inference refuses to score the exact training PCAP. Real normal traffic can be used when the owner can confirm it contains no attacks; a different filename alone does not prevent leakage.

After the first owner-run evaluation, the single normal server that sends only SYN+ACK responses was found to dominate the global cutoff. The current model explicitly covers **traffic-initiating sources**: source/windows with at least five packets that are *all* SYN+ACK responses are excluded from both training and scoring. It does not detect attacks launched by such response-only servers. The 99th-percentile cutoff is unchanged; retrain the model after pulling this change, since old model metadata is rejected. New detection and false-positive measurements are needed before treating this scoped model as useful.

PowerShell in an Administrator terminal (for the existing Npcap setup):

```powershell
python -m pip install -r requirements.txt
$runDir = Join-Path $env:TEMP 'ids-phase4'
python -m tools.generate_traffic --seed 99 --packets 1000 --normal-handshakes 50 --normal-only --output "$runDir\train\traffic.pcap"
python -m ml.train --pcap "$runDir\train\traffic.pcap"
python -m tools.generate_traffic --seed 42 --packets 1000 --normal-handshakes 50 --normal-only --output "$runDir\clean\traffic.pcap"
python -m tools.generate_traffic --seed 42 --packets 1000 --normal-handshakes 50 --output "$runDir\baseline\traffic.pcap"
python -m tools.generate_traffic --seed 42 --packets 1000 --normal-handshakes 50 --noisy-normal --output "$runDir\noisy\traffic.pcap"
python -m tools.generate_traffic --seed 42 --packets 1000 --normal-handshakes 50 --novel-attacks --output "$runDir\novel\traffic.pcap"
python -m tools.evaluate_ml --pcap "$runDir\clean\traffic.pcap" --truth "$runDir\clean\ground_truth.json"
python -m tools.evaluate_ml --pcap "$runDir\baseline\traffic.pcap" --truth "$runDir\baseline\ground_truth.json"
python -m tools.evaluate_ml --pcap "$runDir\noisy\traffic.pcap" --truth "$runDir\noisy\ground_truth.json"
python -m tools.evaluate_ml --pcap "$runDir\novel\traffic.pcap" --truth "$runDir\novel\ground_truth.json"
python -m tools.evaluate_ml --pcap "$runDir\novel\traffic.pcap" --truth "$runDir\novel\ground_truth.json" --details
python main.py --pcap test_traffic.pcap --no-enrich --no-dashboard
python main.py --pcap "$runDir\novel\traffic.pcap" --no-enrich --no-dashboard --ml
python -m tools.generate_traffic --seed 42 --packets 100000 --normal-handshakes 50 --output "$runDir\large\traffic.pcap"
python -m tools.benchmark_ml --pcap "$runDir\large\traffic.pcap" --runs 5
python -m pytest -q
```

The evaluator counts labelled attacker IPs and normal source IPs. Rules-only ROC-AUC uses a binary rule indicator; ML-only uses the maximum anomaly score per IP; combined uses the greater of the rule indicator and ML score. AUC is `null` for clean-only data because it contains no positive class. The scoring benchmark excludes parsing and model training, but includes loading the model and extracting features on each run. Record measurements in [ml-results.md](ml-results.md) only after running these commands on the owner's machine.

The novel set contains a UDP flood, a host sweep, SYNs across many hosts, and a slow scan with packets 65 seconds apart. Its labels are generator truth, not independent real-world annotation. The model may miss attacks or flag legitimate bursts. An anomaly score is a ranking against this training distribution, not a probability of compromise. `rule+ml` appears when a flagged IP/window already has a rule alert; otherwise an ML-only row is labelled **Unmapped (anomaly)** and **unknown pattern, investigate**.
