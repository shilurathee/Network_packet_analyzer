# AGENTS.md: Instruction Brief for the AI Coding Assistant

Project: **Network Traffic Intrusion Detection Pipeline** (Python, Scapy, DuckDB, Streamlit)
Owner: a 6th-semester cybersecurity student. This is a graded academic and portfolio project that will be published on GitHub and defended in a viva.

---

## 0. How the human should use this file

1. Save it in the project root as `AGENTS.md` (rename to `CLAUDE.md` or `.github/copilot-instructions.md` if your tool expects that), or paste it as the first message of a chat.
2. Then send: **"Read AGENTS.md fully. Do Phase 0 only, then stop and report."**
3. Work **one phase at a time**. Review the result, commit, then say "Do Phase N".
4. Priorities: **MUST** phases make the project complete and publishable. **SHOULD** phases make it impressive. **COULD** phases are extras. If time runs short, stop after the MUST and SHOULD phases.

---

## 1. Your role and ground rules (AI assistant: read this carefully)

You are a careful senior engineer pairing with a student. The student must be able to **explain every line in a viva**, so clarity beats cleverness.

**Always:**
- Read the existing code before changing it. Extend what exists; do not rewrite working code wholesale.
- Work in small steps. After each step run the code or tests and show real output.
- Keep the project simple and explainable: plain Python, pandas and SQL. No heavy frameworks (no Django, FastAPI, Kafka, Celery).
- Add a short module docstring to every new file saying what it does, why it exists, its inputs and outputs.
- Preserve existing table and column names. Add columns instead of renaming (see schema rules in section 6).
- Keep commands **Windows-first** (PowerShell, `python -m ...`, `pathlib` paths). Add Linux notes where they differ.
- Be honest in results. If a detector has false positives or a metric is poor, report it. Never invent numbers or hide failures.

**Never:**
- Never commit or print secrets (API keys, webhook URLs, passwords). Keys live only in `.env`.
- Never delete, rename or move user files without asking. Propose it in your report first.
- Never touch `.venv/`, `__pycache__/`, or the report document (`Network_Traffic_ID...`, treat it as read-only).
- Never run network scans or attacks against any real host. The synthetic generator only writes files.
- Never call real external APIs from automated tests.
- Never silently change detection thresholds or semantics. Any change must be stated, justified, and covered by tests.
- Never add more than the dependencies named in the phase without asking.

---

## 2. What the project is

A pipeline that turns a packet capture into a short, explained, prioritised list of suspected attacks:

```
pcap or live capture -> parser (Scapy) -> connections table (DuckDB)
 -> 6 rule-based detectors -> unified alerts table + MITRE ATT&CK tag
 -> enrichment (AbuseIPDB score, GeoIP, VirusTotal on demand)
 -> Streamlit dashboard -> human review
```

`main.py` is the single entry point: `python main.py --pcap <file> [--db name.duckdb] [--no-enrich] [--no-dashboard]`. It must close the DuckDB connection before launching the dashboard (file lock).

### 2.1 Data contracts (do not break)

**`connections`** (one row per packet, 15 columns): `timestamp, protocol, packet_length, ipsrc, ipdst, tcpsrc, tcpdst, tcpflags, udpsrc, udpdst, icmp_type, arp_hwsrc, arp_psrc, arp_hwdst, arp_pdst`.
`protocol` is one of TCP, UDP, ICMP, ARP, OTHER. `tcpflags` is a string such as `S`, `SA`, `FS`. Missing values are NULL.

**`alerts`**: `ipsrc, detection_type, mitre_technique, details`.

**`ip_reputation`** (persistent cache, primary key `ip`): `ip, abuse_score, total_reports, country, isp, status` where status is `checked` or `internal`.

### 2.2 The six detectors and current thresholds

| detection_type | Logic | Current threshold | MITRE tag used so far |
|---|---|---|---|
| port_scan | SYN-only packets per source, count distinct destination ports | 10 or more ports | T1046 |
| syn_flood | SYN-only packets per source, all to one port | exactly 1 port and more than 50 SYNs | T1499 |
| icmp_flood | ICMP echo requests (type 8) per source | more than 20 | T1499 |
| arp_spoofing | one IP claimed by more than one MAC | more than 1 MAC | T1557 |
| dns_tunneling | UDP to port 53 with large packets | longer than 100 bytes | T1071.004 |
| malformed_flags | TCP flags contain both S and F | any | T1562.004 (approximate) |

### 2.3 Reference test data and the expected golden result

`test_traffic.pcap` has 1,001 packets: about 700 normal packets plus six attackers. The pipeline must output **exactly 6 alerts**:

| Source IP | Expected detection_type | Details |
|---|---|---|
| 10.0.0.66 | syn_flood | 150 SYNs to 1 port |
| 10.0.0.99 | port_scan | 60 SYNs to 60 ports |
| 10.0.0.77 | icmp_flood | 50 ICMP echo requests |
| 10.0.0.1 | arp_spoofing | IP claimed by 2 MACs |
| 10.0.0.88 | dns_tunneling | 20 oversized DNS packets |
| 10.0.0.55 | malformed_flags | 10 packets with SYN+FIN |

This is the regression test for everything you do. Run it after every change.

---

## 3. Current state (inferred from the folder listing; the human says all of this is done)

**Verify each item. Do not trust, check.**

| Path | Appears to be | What to verify |
|---|---|---|
| `main.py` | pipeline entry point | runs end to end; closes DB before launching dashboard; which flags exist |
| `scapy_scan.py` | probably the pcap parser (earlier named `parser.py`, function `process_pcap`) | name used by imports; 15-column output; handles missing layers with NULLs |
| `detector.py` | the six detectors (older docs call it `detectors.py`) | the name mismatch with README/report |
| `alerts.py` | unifies detector output and tags MITRE | thresholds as constants; one alert per IP per type |
| `mitre_mapping.py` | detection to technique map | IDs and names accurate (see Phase 3.7) |
| `enrichment/` (`abuseipdb.py`, `geoip.py`, `virustotal.py`, `enricher.py`, `__init__.py`) | enrichment package, replaces the old single `enrichment.py` | who calls what; caching; private-IP skip; whether GeoIP database file actually exists |
| `dashboard.py` | Streamlit UI | does it show the GeoIP map and a VirusTotal button yet, or only the table and charts |
| `.env`, `.env.example`, `.gitignore` | secrets, template, ignore rules | `.env` is ignored and was never committed (check git history) |
| `requirements.txt` | dependencies | complete (scapy, pandas, duckdb, streamlit, requests, python-dotenv, geoip2 ...) |
| `README.md` | GitHub readme | out of date? It may still mention `analyze.py` and `detectors.py` |
| `data.csv`, `help.txt` | unknown leftovers | purpose; probably obsolete early-stage files |
| `live_capture.pcap` | output of a live capture test | do not commit; may contain private traffic |
| `sample_pcap.pcap`, `test_traffic.pcap` | input captures | size; whether safe to commit (test_traffic.pcap is synthetic and safe) |
| `test.duckdb` | database file | must not be committed |
| `Network_Traffic_ID...` | the project report | read-only reference |

**Missing, to be created:** `tests/`, `docs/`, `LICENSE`, `tools/` (traffic generator, evaluation, benchmark), `ml/`, `notifier.py`, CI workflow, Dockerfile.

---

## 4. Facts and gotchas learned (so you do not relearn them)

- **DuckDB concurrency:** a database file can be open read-write by one process, or read-only by several, but not both at once. The analysis process must close its connection before the dashboard opens the file. Two connections with different modes (read-only and read-write) to the same file in one process also conflict. Live mode must respect this (Phase 6).
- **Scapy truncates DNS labels to 63 characters.** Crafted tunneling packets with long names end up about 141 bytes, normal lookups are 70 to 73 bytes. The DNS threshold of 100 sits between them.
- **Scapy timestamps** (`packet.time`) can be a special decimal type. Cast to `float` explicitly.
- **Pandas turns int columns with None into floats** (NaN). Cast when comparing ports.
- **`ipaddress.ip_address(x).is_global`** is the correct "is this a public IP" test. Private ranges such as 10.x have no reputation, so they are labelled `internal` and never sent to an API.
- **Rule overlap:** port scan and SYN flood both send lone SYNs. They are told apart by the number of distinct destination ports.
- **A few SYNs to one or two ports is normal browsing.** That is why the scan and flood thresholds exist as named constants.
- **API limits:** AbuseIPDB free tier is 1,000 checks per day (HTTP 429 when exceeded). VirusTotal's free public API is roughly 4 requests per minute with a daily cap (check current terms). Always cache.
- **Windows:** a security policy ("Application Control") once blocked DuckDB's compiled library, and a stale venv launcher once failed. Always use `python -m pip`, `python -m streamlit`, `python -m pytest`. If an import fails with a policy error, **stop and report**; do not try workarounds.
- **The synthetic test pcaps span only about 10 seconds** (packets are 0.01 s apart). Any time-window feature must still pass the golden test (see Phase 3.1).
- **GeoLite2 needs a free MaxMind account and license key to download**, and the database file must not be committed.

---

## 5. Phases

Suggested order: 0, 1, 2, 3, 4, then 5 and 6 as time allows, 7, 8, and finish with 9. Rough effort for a student pace: Phase 0 half a day, 1 about a day, 2 one to two days, 3 about two days, 4 two to three days, 5 half a day, 6 one to two days, 7 about a day, 8 two or more days, 9 about a day.

### Phase 0: Audit and stabilise (MUST)

Goal: know exactly what works before changing anything.

1. Read every `.py` file, `requirements.txt`, `.env.example`, `.gitignore`, `README.md`, `help.txt`. Do not open `.env`; only confirm it exists and is git-ignored.
2. Git safety: run `git status`, `git ls-files`, and `git log --all --full-history -- .env`. If `.env` was ever committed, **stop immediately** and tell the human to rotate the AbuseIPDB and VirusTotal keys and decide how to purge history.
3. Environment: activate `.venv`, run `python --version`, `python -m pip install -r requirements.txt`, `python -m pip check`, and confirm `import duckdb, scapy, streamlit, pandas, requests` works.
4. Run the golden path: `python main.py --pcap test_traffic.pcap --no-enrich --no-dashboard`. Record packet count and alerts. Compare with section 2.3.
5. If API keys are in `.env`, run the pipeline with enrichment once and record what gets cached. If not, test with `--no-enrich`.
6. Smoke-test the dashboard: `python -m streamlit run dashboard.py` (or through `main.py`). Record what is shown: metric cards, table, charts, map, VirusTotal button.
7. List mismatches between code and docs: file names (`detector.py` vs `detectors.py`, `scapy_scan.py` vs `parser.py`), commands in README, function names, table columns.
8. Hygiene checks:
   - `.gitignore` must cover: `.env`, `.venv/`, `__pycache__/`, `*.pyc`, `*.duckdb`, `*.duckdb.wal`, `*.pcap` and `*.pcapng` (with an exception for small synthetic files in `tests/data/`), `data.csv`, `live_capture.pcap`, `models/`, `*.mmdb`, `.vscode/` (or keep only shared settings), `cache.duckdb`.
   - `.env.example` lists every variable with empty values: `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `GEOIP_DB_PATH`, `IDS_DB_PATH`, `SLACK_WEBHOOK_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_FROM`, `ALERT_TO`.
   - Check that no key-like strings exist in tracked files.
9. Static checks: `python -m compileall .` and `ruff check .` (add ruff to a dev requirements file). Only report findings; do not reformat the codebase in this phase.
10. Write `docs/AUDIT.md`: what works, what is broken, mismatches, risks, recommended fixes ordered by importance. **Stop and report.**

Acceptance: golden path gives 6 alerts; AUDIT.md exists; no files changed except `docs/AUDIT.md` and optional `.gitignore` and `.env.example` fixes (list them).

### Phase 1: Enrichment UI: GeoIP map and VirusTotal button (MUST)

Goal: finish the planned dashboard features.

**1.1 GeoIP (`enrichment/geoip.py`)**
- Use the `geoip2` library: `geoip2.database.Reader(path).city(ip)` gives latitude, longitude, country ISO code and city. Catch `geoip2.errors.AddressNotFoundError`.
- Database path from `GEOIP_DB_PATH`, default `data/GeoLite2-City.mmdb`. If the file is missing, log one warning and continue with no geo data. The app must never crash because of it.
- Skip private IPs (they stay `internal`).
- Store the result by adding columns to `ip_reputation`: `latitude DOUBLE, longitude DOUBLE, city VARCHAR`. Use a small migration helper with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so old databases keep working.
- Document in README how to download GeoLite2 (free MaxMind account and license key), and that the file is not committed because of the license.

**1.2 Map in the dashboard**
- New section "Where the attacks come from" using `st.pydeck_chart` (ScatterplotLayer) or `st.map`. Point size by number of alerts from that IP, colour by abuse score (green to red). Tooltip: IP, country, city, abuse score, alert types.
- Exclude internal IPs. If there are no coordinates, show `st.info` and fall back to a bar chart of alerts per country.

**1.3 VirusTotal on-demand lookup (`enrichment/virustotal.py` plus dashboard)**
- Endpoint: `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` with header `x-apikey`. Read `data.attributes.last_analysis_stats` (malicious, suspicious, harmless, undetected), `reputation`, `as_owner`, `country`, `last_analysis_date`.
- **Never auto-query.** Only when the user selects a flagged public IP and clicks **"Check on VirusTotal"**.
- Validate the IP with `ipaddress.ip_address()` before building the URL.
- Client-side rate limiter: at least 15 seconds between calls. On HTTP 429 show a friendly message, not a traceback.
- Cache in a **separate small file `cache.duckdb`** (table `virustotal_cache`: `ip` primary key, `malicious, suspicious, harmless, undetected, reputation, as_owner, checked_at`). Reuse results younger than 24 hours (configurable). Reason: the dashboard keeps the main database read-only, and writing there would hit the lock rules in section 4.
- Show results as metric cards and a link to `https://www.virustotal.com/gui/ip-address/<ip>`. Use `st.spinner` and `st.session_state`.

**1.4 Config loading:** call `load_dotenv()` once at the entry points (`main.py`, `dashboard.py`). Do not read keys at import time in a way that breaks tests.

Acceptance:
- With keys and the mmdb present: lat/lon stored and shown on the map; VirusTotal button returns results and a second click uses the cache.
- With no keys or no mmdb: app runs, and each missing feature shows a clear notice.
- Tests mock all network calls.

### Phase 2: Tests, ground truth and benchmarks (MUST)

Goal: prove it works and measure it. This also closes the report's Objective 3.

**2.1 Test setup:** `tests/conftest.py` with a fixture that builds an in-memory DuckDB `connections` table (the 15 columns) from a list of dicts. Add `pytest`, `pytest-cov` and `ruff` to `requirements-dev.txt`. Configure pytest so tests marked `network` are skipped by default.

**2.2 Parser tests:** craft packets with Scapy in memory, write a temp pcap, parse it, and assert that all columns have equal length, protocol labels are right, flags are strings such as `S` and `FS`, ARP fields are filled only for ARP, and missing layers give NULL.

**2.3 Detector tests:** for every detector write a positive case, a negative case and a **boundary case** (for example 10 ports triggers a scan, 9 does not; exactly 50 SYNs is not a flood, 51 is). Import thresholds from one place so tests follow config changes.

**2.4 Golden test:** `test_traffic.pcap` must give exactly the six (IP, type) pairs in section 2.3. Also a clean-traffic test that gives zero alerts. Store small synthetic pcaps in `tests/data/`.

**2.5 Traffic generator with ground truth (`tools/generate_traffic.py`):** refactor the earlier Scapy generator into a seeded CLI (`--seed`, `--normal-handshakes`, `--packets`). It writes a pcap and a `ground_truth.json` listing every attacker: IP, attack type, start, end, packet count. Add a **noisy normal traffic** mode with things that look suspicious but are legitimate: a monitoring host pinging many machines, a busy client opening many connections, big DNS replies. These measure false positives honestly.

**2.6 Evaluation (`tools/evaluate.py`):** run the pipeline on generated data and compare alerts to ground truth at IP level. Output per detector: TP, FP, FN, precision, recall, F1. Write `docs/results.md`. Report honestly, including false positives, and note which thresholds you would tune and why.

**2.7 Benchmark (`tools/benchmark.py`):** build a table of 100,000 or more packets (synthesise the DataFrame directly, since Scapy generation is slow). Measure with `time.perf_counter()`: parse speed on a real pcap, DuckDB load, each detector query, alert building, and dashboard queries (also via `AppTest`). Run 5 times, report the median and machine specs. Target for Objective 3: **dashboard data load on 100,000 rows under 3 seconds**. Write `docs/benchmarks.md`. Also measure peak memory of parsing a large pcap (`tracemalloc`).

**2.8 Parser memory fix (only if the benchmark shows a problem):** `rdpcap` loads the whole file into memory. Switch to `scapy.utils.PcapReader` (iterator) and insert in chunks (for example 50,000 rows). The output must stay identical to the old parser, proven by a test comparing both on `test_traffic.pcap`.

**2.9 Dashboard smoke tests** with `streamlit.testing.v1.AppTest`: normal database; before enrichment (table missing); zero alerts; missing database file (friendly message, not a traceback).

Acceptance: `python -m pytest -q` passes on Windows with no network access; `docs/results.md` and `docs/benchmarks.md` contain real measured numbers.

### Phase 3: Detection upgrades (SHOULD)

Goal: fix the known limitations of the rules.

**3.1 Central config and time windows**
- Create `config.py` with a `Thresholds` dataclass holding: `scan_min_ports=10`, `flood_min_syns=50`, `icmp_min=20`, `dns_min_size=100`, `arp_min_macs=2`, `window_seconds`. Allow overrides through environment variables. Defaults must reproduce current behaviour.
- Add time-window detection. Start with tumbling windows: bucket = `floor(timestamp / window_seconds)`, group by `(ipsrc, bucket)`, take the worst window per source, and record `window_start`. Optionally move to sliding windows later.
- Important: the synthetic captures last about 10 seconds. Choose the default window so the golden test still passes, and add two new tests: (a) the same number of attack packets spread over 10 minutes is **not** flagged, (b) a burst in a few seconds **is** flagged. These demonstrate why windows matter.
- Cast timestamps to `float`.

**3.2 Better SYN flood:** count SYNs that never completed a handshake (no matching ACK from the same source for that flow) and compute a completion rate. Flag when SYN count is above the threshold and the completion rate is low (for example under 10%, configurable). Keep it simple and explain the trade-off in the docstring.

**3.3 Severity:** add `severity` (`low`, `medium`, `high`) from how far the value is above its threshold (for example under 2x, 2x to 5x, over 5x). Colour-code it in the dashboard. The notifier (Phase 5) uses it.

**3.4 Richer alerts:** add columns `alert_id` (first 12 hex characters of a SHA-1 of `type|ipsrc|ipdst|window_start`), `ipdst` (victim), `first_seen`, `last_seen`, `count`, `window_start`, `severity`. Keep the original four columns unchanged so the dashboard keeps working. Migrate with `ADD COLUMN IF NOT EXISTS`.

**3.5 ARP improvements:** add `arp_op` to the parser. Ignore ARP probes where `arp_psrc = '0.0.0.0'`. Report the competing MAC addresses and the victim in `details`. Require the conflict to happen inside the window, so a legitimate IP change (DHCP, failover) does not alert forever.

**3.6 DNS tunneling improvements:** extend the parser with `dns_qname` and `dns_qtype`. If a name cannot be decoded, store NULL. Add features: query-name length, Shannon entropy of the subdomain part, and the number of **distinct subdomains per base domain per window** (the strongest tunneling signal). Combine them with the size rule. Add an optional allowlist in config for noisy legitimate domains. Calibrate on the noisy-normal data from Phase 2 and report the result.

**3.7 MITRE mapping v2:** turn `MITRE_MAP` into a dictionary of `{technique_id, name, tactic, url, confidence}` where `confidence` is `exact` or `approximate`. **Verify every ID and name on attack.mitre.org against the current ATT&CK version before changing anything.** Candidates to evaluate (do not assume they are right):
- SYN flood: T1499.001 (OS Exhaustion Flood) versus T1498 (Network Denial of Service).
- ICMP flood: T1498.001 (Direct Network Flood).
- ARP spoofing: T1557.002 (ARP Cache Poisoning).
- Port scan: T1046 (internal, post-compromise discovery) versus T1595 (Active Scanning, external reconnaissance); choose per scenario and document.
- DNS tunneling: T1071.004, and consider T1572 (Protocol Tunneling) or T1048 (Exfiltration Over Alternative Protocol).
- Malformed flags: ATT&CK has no exact technique; keep T1562.004 as `approximate` or mark `unmapped`, with a note.
Record the ATT&CK version used in `docs/`.

Acceptance: the golden test still passes (updated for new columns), new window tests pass, `tools/evaluate.py` shows no recall regression, and false positives on the noisy-normal data are lower than before or documented.

### Phase 4: ML anomaly detection (SHOULD)

Goal: catch what fixed rules cannot, while staying explainable and optional.

**4.1 Layout:** `ml/features.py`, `ml/train.py`, `ml/detect.py`. Models are saved to `models/` (git-ignored). Add `scikit-learn` and `joblib`. Import them lazily so the pipeline still runs without them and prints a friendly message.

**4.2 Features** per `(ipsrc, window)`: packets, bytes, mean and std of packet length, unique destination ports, unique destination IPs, SYN count, SYN-only ratio, ICMP count, DNS count and mean DNS size, fractions of TCP/UDP/ICMP/ARP, number of distinct flag combinations, inter-arrival mean and std. Apply `log1p` to heavy-tailed counts.

**4.3 Model:** a `sklearn.pipeline.Pipeline` of `RobustScaler` and `IsolationForest(n_estimators=200, random_state=42)`. Fit **only on normal traffic**. Save with `joblib` plus a JSON file with the feature list and training date. At inference, verify that the feature columns match.

**4.4 Training data and leakage:** use a separate normal capture for training (the student's own normal traffic, or a differently seeded synthetic normal set). Never train and test on the same capture. Document how the training set was made.

**4.5 Scoring and explanation:** use `score_samples` (lower means more anomalous), convert to a 0 to 1 anomaly score, and flag scores above the 99th percentile of the training scores (configurable). For each flag add a plain explanation using robust z-scores (for example "unique_ports is 14 standard deviations above normal"). Do not add SHAP.

**4.6 Integration:** `--ml` flag in `main.py`. Add a `source` column to `alerts` (`rule`, `ml`, `rule+ml`). If a rule and the model flag the same IP and window, merge them into one `rule+ml` row. ML-only rows get the tag "Unmapped (anomaly)" and are highlighted as "unknown pattern, investigate". Dashboard: anomaly-score column, filter by `source`, small chart.

**4.7 Evaluation:** extend the generator with **novel attacks the rules do not cover**: a slow-and-low scan spread across many windows, a UDP flood, a host sweep (one source touching many destination IPs), and a SYN scan across many hosts. Report precision, recall, F1 and ROC-AUC for rules only, ML only, and combined, plus false positives on clean baseline traffic. State plainly where ML helps and where it does not. Do not claim ML beats the rules unless the numbers show it.

Acceptance: pipeline works with and without `--ml`; fixed seeds make results reproducible; 100,000 packets score in about 10 seconds or less (report the real number); unit tests use tiny feature tables.

### Phase 5: Alerting (COULD)

**5.1 `notifier.py`** with three backends:
- Slack: POST JSON `{"text": "..."}` to the incoming-webhook URL from `SLACK_WEBHOOK_URL`.
- Email: `smtplib` with STARTTLS using `SMTP_*`, `ALERT_FROM`, `ALERT_TO`.
- Console: default dry-run that only prints.

**5.2 Behaviour:**
- Notify only when severity is at or above a configurable level (default `high`).
- Send **one summary message per run** (counts by type, top 5 IPs, hint to open the dashboard), never one message per alert.
- De-duplicate with a `notifications` table (`alert_id` primary key, `channel`, `sent_at`, `status`), so re-running does not re-send.
- 10-second timeouts, 3 retries with backoff, and failures logged without crashing the pipeline.

**5.3 CLI:** `--notify slack|email|console`, `--notify-min-severity`, `--dry-run`.

**5.4 Security:** secrets from environment only, masked in logs, HTTPS webhooks only, no packet payloads in messages.

**5.5 Tests:** mock `requests.post` and `smtplib.SMTP`; include a de-duplication test (second run sends nothing).

### Phase 6: Live capture hardening (COULD)

Inspect what already exists first (`scapy_scan.py`, `live_capture.pcap`, any `--live` flag in `main.py`).

1. **CLI:** `python main.py --live --iface <name> --duration 60` (or `--count N`), plus `--list-ifaces`, and an optional `--bpf "<filter>"`. On Windows map interface GUIDs to friendly names through `scapy.all.conf.ifaces`.
2. **Prerequisites:** Windows needs **Npcap** and an Administrator terminal; Linux and macOS need root or the `cap_net_raw` capability. Detect a missing capture library and print a clear message.
3. **Design:** `sniff(store=False, prn=..., timeout=...)` writing rolling pcap files through `PcapWriter`. Each rolled file goes through the same parser (use `PcapReader`), gets appended to `connections` with `INSERT`, and detectors run over a recent window (for example the last 60 to 120 seconds). Alerts are upserted by `alert_id`.
4. **Concurrency (critical):** because of the DuckDB rules in section 4, the writer must not hold the file open while the dashboard reads. Choose and document one approach: (a) the writer opens, writes and closes in short bursts and the dashboard retries on a lock error, or (b) the writer publishes results to Parquet files (atomic rename) and the dashboard reads them with `read_parquet`. Prefer (b) if (a) proves flaky.
5. **Dashboard refresh:** use `st.fragment(run_every=...)` (check the installed Streamlit version) or `streamlit-autorefresh`.
6. **Safety and privacy:** capture only on the student's own network. Warn that captures can contain sensitive data. Keep `live_capture.pcap` and all captures git-ignored. Optionally store headers only.
7. **Tests:** feed a pcap through the same ingest path. Do not sniff in tests or CI.

### Phase 7: Packaging, README, CI, Docker (MUST for 7.1 to 7.5; COULD for the rest)

**7.1 Dependencies:** run `pip freeze` to learn the working versions, then pin with compatible-release specifiers (`~=`) in `requirements.txt`. Put test and lint tools in `requirements-dev.txt`.

**7.2 `.gitignore`:** as listed in Phase 0, step 8.

**7.3 README.md** (rewrite so it matches the real code). Sections: title and status badges; screenshots (dashboard overview, map, VirusTotal result); features; architecture diagram (Mermaid); quick start for Windows PowerShell and Linux; environment-variable table; CLI flags; how each detector works (table of logic, thresholds, MITRE ID); project structure; testing; **results** copied from `docs/results.md` with real numbers; limitations; accurate roadmap checkboxes; references (Denning 1987; Garcia-Teodoro et al. 2009; Roesch 1999; Liu, Ting and Zhou 2008; Strom et al. 2018; Sharafaldin et al. 2018); ethics disclaimer; license; author placeholders. Do not mention commands or files that do not exist.

**7.4 LICENSE:** MIT with `[Your Name]` as a placeholder for the human to fill.

**7.5 Logging:** replace stray `print` calls with the `logging` module (`LOG_LEVEL` env or `--verbose`). Keep the user-facing progress lines in `main.py`.

**7.6 CI (COULD):** `.github/workflows/ci.yml` on push and pull request, matrix of ubuntu-latest and windows-latest with Python 3.11 and 3.12; steps: checkout, setup-python with pip cache, install requirements and dev requirements, `ruff check .`, `python -m pytest -q`. No network access in tests.

**7.7 Docker (COULD):** `python:3.12-slim` image, install requirements, `EXPOSE 8501`, run Streamlit; `docker-compose.yml` with a data volume and `env_file: .env`. State clearly that live capture inside Docker needs `--cap-add=NET_RAW` and host networking on Linux, and is not supported on Docker Desktop for Windows or macOS.

**7.8 Pre-commit (COULD):** ruff and a secret scanner such as detect-secrets.

Acceptance: a fresh clone can follow the README on a clean Windows machine and reach the dashboard with `test_traffic.pcap`.

### Phase 8: Validation on CICIDS2017 (COULD, time-boxed)

1. Download from the official UNB CIC dataset page. Never commit the data.
2. The pcaps are very large. Slice small windows around labelled attack periods (Scapy or `editcap`) and process them with `PcapReader` in chunks.
3. Map labels to detectors **honestly**: PortScan maps to `port_scan`; DDoS may map to the flood detectors; application-layer DoS (slow HTTP attacks) and web attacks will not match, so report them as out of scope instead of forcing a match.
4. Label CSV timestamps may use a different timezone or format from the pcap. Verify alignment against known flows before computing metrics.
5. Report precision and recall for the mappable classes only, with discussion, in `docs/cicids2017.md`. If it is too heavy for the machine, stop, document why, and move on.

### Phase 9: Sync the report and prepare the viva (MUST, last)

1. **Do not overwrite the report file.** Write `docs/report_updates.md` containing replacement text for the sections that changed: objectives status table, implementation (new modules), testing and results (real numbers from `docs/results.md` and `docs/benchmarks.md`), limitations (remove what was fixed, keep what remains), and future work. List the figures and screenshots the human must capture, with suggested file names.
2. `docs/architecture.md` with Mermaid diagrams: pipeline, database schema (ER), and the sequence of a VirusTotal button click.
3. `docs/VIVA_NOTES.md`: for every module, a three-line plain-language explanation with an everyday analogy, plus likely examiner questions with short answers. Include at least: why DuckDB over SQLite; why rules and ML together; what a false positive is and how thresholds were chosen; how a port scan differs from a SYN flood; how new attacks would be detected; why private IPs are skipped; why API results are cached; the limitations.
4. `docs/CHANGELOG.md` summarising each phase.

---

## 6. Cross-cutting requirements

**Code quality:** type hints and docstrings on public functions; docstrings explain **why**, not only what; functions under about 40 lines; no wildcard imports; no global mutable state; no bare `except`; constants live in `config.py`.

**SQL safety:** any value coming from the UI or a CLI argument goes through parameters (`con.execute(sql, [value])`). Thresholds interpolated into SQL must be cast to `int` or `float` first. Never put user text into an f-string query.

**Schema changes:** add columns only, using `ADD COLUMN IF NOT EXISTS`. Keep a `meta` table with `schema_version`. Old database files must keep working.

**Errors and CLI:** specific exceptions, readable messages, non-zero exit code on fatal errors, `--help` text for every flag.

**Network calls:** always a timeout (10 seconds), limited retries, rate limiting and caching. Never in default tests.

**Performance:** keep aggregation in DuckDB SQL; avoid `SELECT *` on large tables in the dashboard; limit displayed rows (for example 1,000) with a note; do not loop over 100,000+ rows in Python where a query will do.

**Privacy:** pcaps can contain sensitive data. Do not commit real captures. Keep only small synthetic files in `tests/data/`.

**Windows:** use `pathlib`, no shell-only scripts, and always `python -m` for pip, streamlit and pytest.

---

## 7. How to report after each phase

End every phase with this structure:
1. **What changed:** files created and modified.
2. **Commands run:** with real, trimmed output (never fabricated).
3. **Tests:** what passed and failed.
4. **Not verified:** anything you could not test and why.
5. **Decisions needed from the human.**
6. **Explain it simply:** six to eight lines with an everyday analogy, written so the student can repeat it in the viva.
7. **Suggested commit message(s)** in Conventional Commits style. Stage changes if the tool allows, but **do not push**.

---

## 8. Stop and ask the human when

- A secret may have been committed or exposed.
- An import fails because of an operating-system policy (for example Application Control).
- You are unsure what a file is for, or you want to delete, rename or move anything.
- A change would alter the golden result or any detection threshold.
- You want to add a dependency that the phase does not mention.
- A step would use API quota in bulk, need Administrator rights, or download licensed or very large data (GeoLite2, CICIDS2017).

---

## 9. Final definition of done

- [ ] `python main.py --pcap test_traffic.pcap` runs from a clean clone and opens the dashboard.
- [ ] `python -m pytest -q` passes offline on Windows; golden test gives exactly 6 alerts.
- [ ] Dashboard shows alerts, severity, MITRE tags, abuse scores, the GeoIP map and the VirusTotal on-demand button, and degrades gracefully when keys or the GeoIP file are missing.
- [ ] `docs/results.md` and `docs/benchmarks.md` hold real measured numbers, including false positives and the 100,000-packet timing.
- [ ] README matches the code; `.env`, databases, captures and the GeoLite2 file are not tracked; LICENSE present.
- [ ] MITRE mapping verified against the current ATT&CK version, with approximate mappings labelled.
- [ ] If Phases 4 to 6 were done: ML evaluation, alerting dedup, and live-mode concurrency approach documented.
- [ ] `docs/report_updates.md`, `docs/architecture.md` and `docs/VIVA_NOTES.md` exist.
