"""Smoke-test dashboard states using temporary databases and Streamlit AppTest.

Inputs are small local tables; no UI button is clicked, so the tests never
capture traffic or contact threat-intelligence services.
"""

from pathlib import Path

import duckdb
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard.py"


def make_db(path, *, alerts, packet_count=1, reputation=False):
    """Create and close the minimal tables needed by dashboard read queries."""
    con = duckdb.connect(str(path))
    try:
        con.execute("CREATE TABLE connections (protocol VARCHAR)")
        for _ in range(packet_count):
            con.execute("INSERT INTO connections VALUES ('TCP')")
        con.execute("""CREATE TABLE alerts (
            ipsrc VARCHAR, detection_type VARCHAR, mitre_technique VARCHAR, details VARCHAR
        )""")
        if alerts:
            con.execute("INSERT INTO alerts VALUES ('10.0.0.66', 'syn_flood', 'T1499', 'demo')")
        if reputation:
            con.execute("""CREATE TABLE ip_reputation (
                ip VARCHAR, latitude DOUBLE, longitude DOUBLE, country VARCHAR,
                city VARCHAR, abuse_score INTEGER, status VARCHAR
            )""")
            con.execute("""INSERT INTO ip_reputation
                VALUES ('10.0.0.66', NULL, NULL, 'Private Network', 'Internal', 0, 'internal')""")
    finally:
        con.close()


@pytest.fixture
def app_for_db(monkeypatch):
    """Point an isolated AppTest run at a closed temporary database."""
    def run(path):
        monkeypatch.setenv("IDS_DB_PATH", str(path))
        st.cache_data.clear()
        app = AppTest.from_file(str(DASHBOARD)).run(timeout=30)
        assert not app.exception
        return app
    return run


def test_dashboard_normal_database(tmp_path, app_for_db):
    """A populated, enriched database renders alerts and a no-coordinates notice."""
    path = tmp_path / "normal.duckdb"
    make_db(path, alerts=True, reputation=True)
    app = app_for_db(path)
    assert any(metric.label == "Alerts raised" and metric.value == "1" for metric in app.metric)
    assert any("No public IPs with geo-coordinates" in info.value for info in app.info)
    assert any(button.label == "Check on VirusTotal" for button in app.button)


def test_dashboard_before_enrichment(tmp_path, app_for_db):
    """Missing ip_reputation cannot turn the map into a traceback or empty map."""
    path = tmp_path / "unenriched.duckdb"
    make_db(path, alerts=True)
    app = app_for_db(path)
    assert any("No public IPs with geo-coordinates" in info.value for info in app.info)


def test_dashboard_zero_alerts(tmp_path, app_for_db):
    """An empty alerts table shows the guidance message."""
    path = tmp_path / "empty.duckdb"
    make_db(path, alerts=False)
    app = app_for_db(path)
    assert any("No alerts found" in info.value for info in app.info)


def test_dashboard_missing_database(tmp_path, app_for_db):
    """No DB file produces a friendly empty-state notice, not a traceback."""
    app = app_for_db(tmp_path / "missing.duckdb")
    assert any("No alerts found" in info.value for info in app.info)
