# Changelog

## Phase 0 — audit and stabilisation

- Golden path validated on the project owner's terminal: 1,001 packets and exactly six expected alerts.
- See [AUDIT.md](AUDIT.md) for the audit, hygiene changes and remaining risks.

## Phase 1 — enrichment UI (validation pending)

- Added the GeoIP map and a dedicated, cached, on-demand VirusTotal button.
- GeoIP's ip-api.com HTTP fallback is now opt-in (`GEOIP_HTTP_FALLBACK=1`), restricted to public IPs, timed out and cached in memory. It logs a one-time warning about unencrypted transmission.
- Explicit `--pcap` and `--live` skip the interactive menu. Removed the automatic VirusTotal CLI option.
- GeoIP tests: five passed on the project owner's terminal (reported 2026-10-28).
- **Map validation: PENDING.** The GeoLite2 database has not been added yet. A map screenshot and on-demand VirusTotal UI validation are still needed; no demo database was used.

## Phase 2B — measured evaluation and benchmark

- Owner terminal: 39 tests passed with 8 warnings in 33.50 seconds; seeded baseline 1,088 packets and noisy-normal 1,128. See [results.md](results.md) for per-detector scores and hypotheses for the three false positives.
- The five-run benchmark medians are in [benchmarks.md](benchmarks.md). The initial parser timing included `tracemalloc` overhead; the owner's rerun measured parser time separately from peak memory allocation.

## Phase 7 cleanup list

- Address the `asyncio` deprecation in `dashboard.py` around line 27.
- Avoid the GeoLite2 warning during `tools/*` commands; the tools should not import enrichment at module import time.
- Investigate AppTest's "missing ScriptRunContext" log noise without hiding real errors.
- Local validation uses Python 3.14.7; verify supported versions and deprecations during packaging.

## Phase 3.1 — threshold configuration and time windows (validated)

- Added immutable threshold settings with environment overrides; defaults preserve the existing cutoffs.
- SYN, ICMP and ARP aggregation now uses capture-relative 60-second windows; each source keeps its strongest qualifying window. DNS size and malformed-flag rules retain their per-packet behavior.
- Added tests contrasting a short SYN burst with the same SYN count spread across ten minutes. Owner terminal: 42 tests passed (8 dashboard deprecation warnings) and the golden capture retained six alerts from 1,001 packets.

## Phase 3.2 — SYN completion check (awaiting validation)

- The SYN detector now compares each SYN to an ACK from the same source and TCP flow inside its capture window. A flood requires more than 50 incomplete SYNs to one port and a completion rate below 10%; the other rule thresholds stay the same.
- Added tests for no ACKs, matching ACKs, the completion-rate boundary and an unrelated ACK. Missing packets or asymmetric captures can still make a legitimate flow appear incomplete.

## Phase 3.3–3.4 — severity and richer alerts (validated)

- Added severity from distance above each rule's existing cutoff and colour-coded it in the dashboard.
- Added stable alert ID, victim IP, first/last observed times, count and window start while retaining the original four alert fields.
- Existing alerts tables gain missing columns before current-run rows are replaced. Tests cover the new fields and an older four-column table.
- Owner terminal: 49 tests passed (8 dashboard deprecation warnings); the golden capture retained six alerts from 1,001 packets.

## Phase 3.5 — ARP context (validated)

- The parser now records `arp_op` as an additional column. ARP probes with source protocol address `0.0.0.0` are excluded.
- Conflicting MACs and the claimed victim IP appear in alert details, and the claimed IP populates the alert victim field. Conflicts must occur within one capture-relative window.
- Owner terminal: 52 tests passed (8 dashboard deprecation warnings), and the golden capture retained six alerts from 1,001 packets with the expected expanded ARP details.

## Phase 3.6 — DNS signals (validated)

- Parser adds `dns_qname` and `dns_qtype`. Large DNS packets now need a long first label, high label entropy, or several distinct subdomains to the same approximate base domain within a window. Optional `DNS_ALLOWLIST` excludes known noisy domains.
- Added tests for size boundaries, repeated large legitimate queries, distinct subdomains and allowlisting. Owner terminal: 56 passed, 211 warnings (8 dashboard, 203 Scapy DNS deprecations), six golden alerts from 1,001 packets. Both evaluation sets retained TP 1 and FN 0 for all six detectors; noisy DNS FP fell from 1 to 0, while port scan and ICMP remained FP 1 each. See [results.md](results.md).
- The two-label base-domain approximation can misgroup public suffixes, and small or repetitive tunnels can be missed; no real-world DNS accuracy claim is made.

## Phase 3.7 — ATT&CK mapping v2 (validated)

- Verified technique IDs, official names and tactics against ATT&CK Enterprise v20.0; see [mitre-mapping.md](mitre-mapping.md) for links and the evidence limits of each mapping.
- Switched to structured mapping metadata and explicitly labelled approximate display mappings. TCP SYN+FIN flags are unmapped because they do not demonstrate firewall tampering. The original four alert columns remain unchanged.
- Updated DNS question access for Scapy's list field to avoid the new deprecation warnings seen in the owner's Phase 3.6 test run. Dashboard asyncio warnings remain on the Phase 7 cleanup list.
- Owner terminal: 58 tests passed with 8 dashboard asyncio deprecation warnings. The golden capture retained six alerts from 1,001 packets, with the updated ATT&CK labels and an explicitly unmapped SYN+FIN alert.

## Phase 4 — optional anomaly detection (ML evaluation pending)

- Added seeded normal-only and four novel-attack scenarios, per-source/window features, deterministic Isolation Forest training, stored feature metadata, scored explanations, and `--ml` integration. Missing models or dependencies leave signature rules available.
- Added source and anomaly score fields to alerts, plus dashboard filter and chart. Matching rule/ML windows appear as `rule+ml`; otherwise anomaly alerts are explicitly unmapped.
- Added source-IP-level comparison for rules, ML and combined with ROC-AUC when defined, and a separate 100,000-packet scoring timer. Owner measurements are PENDING in [ml-results.md](ml-results.md).
- Owner terminal: dependencies installed on Python 3.14.7; 62 tests passed with 8 known dashboard asyncio deprecation warnings. The rule-only golden capture retained six alerts from 1,001 packets.
- Owner trained on a separate 1,000-packet normal capture (251 source/windows) and ran the 1,270-packet novel set. ML flagged only unlabelled 10.2.0.1, missing all ten labelled attackers; combined F1 dropped from 0.7499999999999999 for rules alone to 0.7058823529411764. Added optional source-score diagnostics for investigation; baseline/noisy evaluations and scoring benchmark remain pending in [ml-results.md](ml-results.md).
- Owner diagnostic rerun: 63 tests passed with 8 dashboard warnings; the highest-scoring novel attacker was below the raw 99th-percentile cutoff while the normal server exceeded it. This limits the current ML model's usefulness at the default cutoff; no rule or ML threshold was changed.
