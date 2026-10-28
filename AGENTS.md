# AGENTS.md: Instruction Brief for the AI Coding Assistant

Project: **Network Traffic Intrusion Detection Pipeline** (Python, Scapy, DuckDB, Streamlit)
Owner: a 6th-semester cybersecurity student. This is a graded academic and portfolio project that will be published on GitHub and defended in a viva.

Work **one phase at a time**. Review the result, then say "Do Phase N".

Priorities: **MUST** phases (0, 1, 2, 7.1–7.5, 9) make the project complete. **SHOULD** phases (3, 4) make it impressive. **COULD** phases are extras.

Full phase text lives in the chat that created this file (Phase 0–9). Ground rules:

- Extend existing code; do not rewrite working code wholesale.
- Windows-first commands (`python -m ...`).
- Never commit secrets. Never call real APIs from default tests.
- Never silently change detection thresholds.
- Golden path: `python main.py --pcap test_traffic.pcap --no-enrich --no-dashboard` must yield exactly 6 alerts (section 2.3).
- Stop after each phase and report: what changed, commands run, tests, not verified, decisions needed, viva analogy, suggested commit message. Do not push.

## Recorded Phase 0 decisions (2026-10-28)

1. Npcap AdminOnly: always run the terminal as Administrator (keep `from scapy.all import ...`).
2. Remove leftover `data.csv` write from the parser.
3. Move `sample_pcap.pcap` to `tests/data/`.
4. Continue with Phase 1 (GeoIP map + dedicated VirusTotal button).
