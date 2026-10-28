# Phase 0 Audit Report

**Date:** 2026-10-28
**Python:** 3.14.7 (.venv) | **Scapy:** 2.8.0 | **DuckDB:** 1.5.6 | **Streamlit:** 1.65.0
**Status:** COMPLETE - golden path passes, no secrets found, hygiene fixed.

---

## 1. File Inventory

| Path | Status |
|---|---|
| main.py | OK. Flags: --pcap, --mode, --live, --db, --no-enrich, --no-dashboard. DB closed before dashboard. |
| scapy_scan.py | OK. 15-column output. Side-effect: writes data.csv on every parse (see Risk 2). |
| detector.py | OK. Named detector.py not detectors.py (README mismatch). |
| alerts.py | OK. SCAN_MIN_PORTS=10, FLOOD_MIN_SYNS=50. One alert per IP per type. |
| mitre_mapping.py | OK. IDs not yet verified against live ATT&CK (Phase 3.7 task). |
| enrichment/ | OK. load_dotenv() at import. Caches, skips private IPs, handles 429. |
| dashboard.py | OK. Passes AppTest smoke test. See section 5. |
| .env | OK. Exists locally. Never committed (git log confirms). |
| .env.example | UPDATED this phase - now has all 11 required variables with empty values. |
| .gitignore | UPDATED this phase - full hygiene rules. |
| requirements.txt | OK. All packages present. |
| requirements-dev.txt | CREATED this phase. pytest, pytest-cov, ruff. |
| README.md | OUTDATED - mentions analyze.py, detectors/ dir. Fix in Phase 7. |
| data.csv | Was tracked - UNTRACKED this phase. Now git-ignored. |
| live_capture.pcap | Was tracked - UNTRACKED this phase. Now git-ignored. |
| test.duckdb | Was tracked - UNTRACKED this phase. Now git-ignored. |
| sample_pcap.pcap | Still tracked. 1,974 bytes. Decision needed (see section 10). |
| test_traffic.pcap | OK. Tracked. Synthetic, safe. 72 KB. |
| help.txt | Early-stage dev notes. Not code. Delete before submission. |

---

## 2. Git Safety

git log --all --full-history -- .env
(no output - .env was NEVER committed)

Secret scan of 17 tracked text files: 0 matches for API key patterns.
No key rotation needed.

---

## 3. Golden Path Result

Command: python main.py --mode pcap --pcap test_traffic.pcap --no-enrich --no-dashboard
Packets parsed: 1,001

Exactly 6 alerts - ALL match section 2.3:

  10.0.0.66 | syn_flood       | 150 SYNs to 1 port(s)
  10.0.0.99 | port_scan       | 60 SYNs to 60 port(s)
  10.0.0.77 | icmp_flood      | 50 ICMP echo requests
  10.0.0.1  | arp_spoofing    | IP claimed by 2 different MACs
  10.0.0.88 | dns_tunneling   | 20 oversized DNS packets (max 141 bytes)
  10.0.0.55 | malformed_flags | 10 packets with SYN+FIN set

GOLDEN TEST PASSES.

---

## 4. README vs Code Mismatches

| README says | Reality | Severity |
|---|---|---|
| python analyze.py --input path/capture.pcap | python main.py --pcap ... | HIGH |
| Lists analyze.py, detectors/, db/ as files | None exist; real files: main.py, detector.py, enrichment/ | HIGH |
| sudo python analyze.py --live --interface eth0 | python main.py --live --interface <name> (Windows: no sudo) | HIGH |
| streamlit run dashboard.py | python -m streamlit run dashboard.py | MEDIUM |
| VirusTotal listed as not done | Dashboard already has a manual VT button (one-button style, not dedicated per-IP) | MEDIUM |

Fix: Phase 7 rewrites README. Do not touch before then.

---

## 5. Dashboard State (AppTest Smoke Test)

  Packets analyzed: 1,001 - SHOWN
  Alerts raised: 6 - SHOWN
  Unique attacker IPs: 6 - SHOWN
  Filterable alerts table - SHOWN
  Alerts by attack type bar chart - SHOWN
  Traffic by protocol bar chart - SHOWN
  "Query Threat Intel" button - SHOWN (queries GeoIP + AbuseIPDB + VT together)
  GeoIP map - NOT SHOWN (all test IPs are 10.x private; no lat/lon returned)
  Dedicated per-IP VirusTotal button with caching - NOT DONE (Phase 1 task)
  PCAP file selector + upload in sidebar - SHOWN
  Live capture controls in sidebar - SHOWN

Deprecation warnings (Python 3.14):
  asyncio.WindowsSelectorEventLoopPolicy and set_event_loop_policy deprecated.
  Removed in Python 3.16. Fix in Phase 7 (remove dashboard.py lines 5-6).

---

## 6. Hygiene Changes Made This Phase

.gitignore updated - added:
  *.pyc, *.duckdb.wal, cache.duckdb, *.pcap, *.pcapng,
  live_capture.pcap, data.csv, models/, .vscode/
  Exception added: !tests/data/*.pcap for synthetic test captures.

Files removed from git index (still on disk, just no longer tracked):
  data.csv - generated output, not source code
  live_capture.pcap - contains private traffic
  test.duckdb - binary, regenerated on each run

.env.example updated:
  Now has all 11 required variables: ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY,
  GEOIP_DB_PATH, IDS_DB_PATH, SLACK_WEBHOOK_URL, SMTP_HOST, SMTP_PORT,
  SMTP_USER, SMTP_PASSWORD, ALERT_FROM, ALERT_TO.

requirements-dev.txt created:
  pytest>=8.0.0, pytest-cov>=4.1.0, ruff>=0.17.0

---

## 7. Critical Bug: scapy.all Import Hangs (Non-Admin)

Root cause: Npcap is installed with AdminOnly=1 (registry key confirmed).
When scapy imports scapy.all, it calls pcap_findalldevs() which blocks
indefinitely because the non-admin process cannot open the Npcap driver.

Evidence: faulthandler traceback showed process stuck at:
  scapy/arch/libpcap.py, line 207 in load_winpcapy -> pcap_findalldevs

Impact: python main.py hangs unless run as Administrator.

Options (decision needed):
  1. Run terminal as Administrator - simplest, restores live capture too.
  2. Set env var SCAPY_USE_LIBPCAP=no - disables pcap, breaks live capture.
  3. Patch scapy_scan.py to use specific imports (scapy.utils, scapy.layers.inet)
     instead of "from scapy.all import ...". Confirmed fast (0.23s, no hang).
     Live capture still needs admin.

---

## 8. Static Analysis (ruff check .)

62 issues found. All code quality, no logic errors. Do not auto-fix yet (Phase 7).

  UP006/UP035/UP045: Dict->dict, List->list, Optional->X|None (10 issues)
  I001: Unsorted import blocks in main.py, scapy_scan.py (2 issues)
  BLE001: Bare except Exception (3 issues)
  F401: ThreatEnricher imported but unused in main.py (1 issue)
  F541: f-string with no placeholders in main.py (1 issue)
  PLW1510: subprocess.run() without check= argument (1 issue)
  RUF013: Implicit Optional in type annotation (1 issue)

---

## 9. Risks, Ordered by Importance

  1. scapy.all import hangs non-admin [HIGH] - fix before Phase 1
  2. data.csv auto-written on every parse (scapy_scan.py line 95) [HIGH] - remove this line
  3. README commands are wrong [HIGH] - fix in Phase 7
  4. sample_pcap.pcap still git-tracked [MEDIUM] - move to tests/data/ or untrack
  5. No tests/ directory [MEDIUM] - create in Phase 2
  6. asyncio deprecation warnings in Python 3.14 [LOW] - fix in Phase 7
  7. No config.py - thresholds split across files [LOW] - fix in Phase 3
  8. MITRE IDs not verified against current ATT&CK [LOW] - fix in Phase 3.7
  9. GeoLite2 mmdb missing - GeoIP map will never render on test data [INFO]
  10. ThreatEnricher imported but unused in main.py [INFO] - remove in Phase 7

---

## 10. Decisions (recorded 2026-10-28)

  1. Npcap AdminOnly: **A — always run the terminal as Administrator.**
     `scapy_scan.py` keeps `from scapy.all import ...`. Live capture still
     needs admin; offline parse also hangs without it on this machine.
  2. sample_pcap.pcap: **moved to `tests/data/`** (git-ignored `*.pcap` with
     `!tests/data/*.pcap` and `!test_traffic.pcap` exceptions).
  3. data.csv auto-write: **removed** from `process_pcap` (no leftover CSV).
  4. Phase 1: **go.** GeoIP map + dedicated per-IP VirusTotal button.

---

## 11. Explain It Simply (Viva Notes)

Phase 0 is like a pre-flight checklist before a plane takes off. Before writing
any new code, we read every file, ran every command, and wrote down exactly what
works and what does not.

What we found: the engine works (6 alerts, correct IPs, correct types), the fuel
is clean (no secrets ever leaked to GitHub), but the manual is wrong (README
describes a different, older version of the project).

We also found a quirk: Scapy on this machine freezes unless run as Administrator,
because the network driver requires admin permission to list network cards - even
when we only want to read a saved capture file, not sniff live traffic.

The fixes in this phase were housekeeping only. No detection logic was changed.

---

## 12. Suggested Commit Message

audit: Phase 0 - hygiene fixes and audit report

- Remove data.csv, live_capture.pcap, test.duckdb from git tracking
- Update .gitignore: full hygiene rules (*.pcap, *.duckdb, models/, .vscode/)
- Update .env.example: all 11 required variables with empty values
- Add requirements-dev.txt: pytest, pytest-cov, ruff
- Add docs/AUDIT.md: full Phase 0 audit report

Golden path: 1,001 packets -> exactly 6 alerts (matches section 2.3).
No secrets found in any tracked file. .env never committed.

Known issue: scapy.all hangs non-admin (Npcap AdminOnly=1). Decision needed.
