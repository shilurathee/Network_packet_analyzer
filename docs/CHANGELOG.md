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
