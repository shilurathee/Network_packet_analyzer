"""Tests that ip_reputation stores GeoIP columns without calling APIs."""
from __future__ import annotations

import duckdb
import pandas as pd

from enrichment.enricher import persist_ip_reputation


def test_persist_adds_lat_lon_city_and_marks_private_internal():
    con = duckdb.connect(":memory:")
    alerts = pd.DataFrame(
        [
            {
                "ipsrc": "10.0.0.99",
                "detection_type": "port_scan",
                "abuse_score": 0,
                "country": "Private Network",
                "city": "Internal",
                "isp": "Private/Local Network",
                "latitude": None,
                "longitude": None,
            },
            {
                "ipsrc": "8.8.8.8",
                "detection_type": "syn_flood",
                "abuse_score": 12,
                "country": "United States",
                "city": "Mountain View",
                "isp": "Google",
                "latitude": 37.386,
                "longitude": -122.0838,
            },
        ]
    )
    persist_ip_reputation(con, alerts)
    rows = con.execute(
        "SELECT ip, status, latitude, longitude, city, country FROM ip_reputation ORDER BY ip"
    ).df()
    con.close()

    assert list(rows["ip"]) == ["10.0.0.99", "8.8.8.8"]
    private = rows[rows["ip"] == "10.0.0.99"].iloc[0]
    public = rows[rows["ip"] == "8.8.8.8"].iloc[0]
    assert private["status"] == "internal"
    assert public["status"] == "checked"
    assert public["latitude"] == 37.386
    assert public["city"] == "Mountain View"
