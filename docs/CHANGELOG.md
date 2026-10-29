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
- The five-run benchmark medians are in [benchmarks.md](benchmarks.md). Parser time was collected while `tracemalloc` was active, so a clean timing rerun is required after separating timing and memory passes.

## Phase 7 cleanup list

- Address the `asyncio` deprecation in `dashboard.py` around line 27.
- Avoid the GeoLite2 warning during `tools/*` commands; the tools should not import enrichment at module import time.
- Investigate AppTest's "missing ScriptRunContext" log noise without hiding real errors.
- Local validation uses Python 3.14.7; verify supported versions and deprecations during packaging.
