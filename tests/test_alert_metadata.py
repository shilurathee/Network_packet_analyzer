"""Check richer alert fields, severity and migration of an old alerts table.

Inputs are synthetic connections in memory; outputs are alert rows and a
DuckDB table. No enrichment or external API is used.
"""

from alerts import COLUMNS, DETAIL_COLUMNS, build_alerts, save_alerts


def test_flood_metadata_and_severity(connections_db):
    """A 150-SYN burst retains old fields and adds stable triage context."""
    rows = [{"timestamp": 1000 + i * 0.01, "ipsrc": "10.0.0.66",
             "ipdst": "10.0.0.20", "protocol": "TCP", "tcpflags": "S",
             "tcpdst": 80, "tcpsrc": 30000 + i} for i in range(150)]
    con = connections_db(rows)
    alerts = build_alerts(con, enrich=False)
    assert list(alerts.columns) == COLUMNS + DETAIL_COLUMNS
    assert len(alerts) == 1
    row = alerts.iloc[0]
    assert row["detection_type"] == "syn_flood"
    assert row["ipdst"] == "10.0.0.20"
    assert row["count"] == 150
    assert row["severity"] == "medium"
    assert row["source"] == "rule"
    assert len(row["alert_id"]) == 12
    assert row["first_seen"] <= row["last_seen"]
    assert row["alert_id"] == build_alerts(con, enrich=False).iloc[0]["alert_id"]


def test_old_four_column_table_migrates(connections_db):
    """Existing database schema gains columns without renaming the old four."""
    con = connections_db([])
    con.execute("""CREATE TABLE alerts (
        ipsrc VARCHAR, detection_type VARCHAR, mitre_technique VARCHAR, details VARCHAR
    )""")
    alerts = build_alerts(con, enrich=False)
    save_alerts(con, alerts)
    columns = {row[1] for row in con.execute("PRAGMA table_info('alerts')").fetchall()}
    assert set(COLUMNS + DETAIL_COLUMNS).issubset(columns)
