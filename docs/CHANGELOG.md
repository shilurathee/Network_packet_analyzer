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

## Phase 3.1 — threshold configuration and time windows (awaiting validation)

- Added immutable threshold settings with environment overrides; defaults preserve the existing cutoffs.
- SYN, ICMP and ARP aggregation now uses capture-relative 60-second windows; each source keeps its strongest qualifying window. DNS size and malformed-flag rules retain their per-packet behavior.
- Added tests contrasting a short SYN burst with the same SYN count spread across ten minutes. The six-alert golden test and the evaluation tool still need to be run by the project owner before continuing Phase 3.
