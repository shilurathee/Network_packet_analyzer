# Detection evaluation — owner-run measurements

Measured on the owner's Windows terminal with the seeded generator (`--seed 42`, `--normal-handshakes 50`). `--packets 1000` requests **1,000 normal packets**; six labelled attacks add 88 packets, giving **1,088 total**. Noisy-normal mode adds 40 more normal packets, giving **1,128 total**. The evaluator compares `(source IP, detection_type)` pairs. No true-negative rate is claimed.

| Dataset | Detector | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| Baseline (1,088) | port_scan | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Baseline (1,088) | syn_flood | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Baseline (1,088) | icmp_flood | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Baseline (1,088) | arp_spoofing | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Baseline (1,088) | dns_tunneling | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Baseline (1,088) | malformed_flags | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Noisy normal (1,128) | port_scan | 1 | 1 | 0 | 0.5 | 1.0 | 0.6667 |
| Noisy normal (1,128) | syn_flood | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Noisy normal (1,128) | icmp_flood | 1 | 1 | 0 | 0.5 | 1.0 | 0.6667 |
| Noisy normal (1,128) | arp_spoofing | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| Noisy normal (1,128) | dns_tunneling | 1 | 1 | 0 | 0.5 | 1.0 | 0.6667 |
| Noisy normal (1,128) | malformed_flags | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |

Each attack type has **one labelled attacker (TP 1)**. These scores demonstrate the pipeline on controlled examples; they are not statistical estimates of real-world detection accuracy.

## Noisy-normal false positives (hypotheses from generator and rules)

- **10.0.0.202, port_scan:** a busy legitimate client sends 12 SYN-only packets to 12 destination ports. The rule counts distinct ports and cannot tell this activity from a scan. The inferred alert detail is 12 SYNs to 12 ports; confirm against the actual alert output.
- **10.0.0.201, icmp_flood:** a monitoring host sends 25 echo requests to different destinations. The rule groups by source and cannot distinguish monitoring from a flood. The inferred detail is 25 ICMP echo requests; confirm against the actual alert output.
- **10.0.0.203, dns_tunneling:** three legitimate large DNS queries carry a 90-byte payload each. The size-only rule flags UDP destination port 53 packets above its existing size threshold, regardless of intent. The inferred detail is three oversized DNS packets; the exact maximum packet length requires the actual alert output.

These are explanations of synthetic scenarios, **not confirmed causes from packet investigation**. Do not tune thresholds from one attacker per type. The false positives motivate time-window and richer-rule evaluation in Phase 3.
