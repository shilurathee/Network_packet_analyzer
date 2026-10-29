"""Check burst-versus-spread behavior of capture-relative detector windows.

Inputs are synthetic connection rows; outputs are alert types from the
existing in-memory DuckDB fixture. No traffic is sent or captured.
"""

from alerts import build_alerts
from config import Thresholds


def syns(timestamps):
    """Make incomplete SYNs to one destination from one source."""
    return [{"timestamp": ts, "ipsrc": "10.0.0.66", "ipdst": "10.0.0.20",
             "protocol": "TCP", "tcpflags": "S", "tcpdst": 80}
            for ts in timestamps]


def test_syns_spread_over_ten_minutes_do_not_flood(connections_db):
    """A total above the threshold is harmless when no window exceeds it."""
    con = connections_db(syns([1_700_000_000 + i * 12 for i in range(51)]))
    assert "syn_flood" not in set(build_alerts(con, enrich=False)["detection_type"])


def test_syn_burst_in_few_seconds_is_flood(connections_db):
    """The same SYN count in one window still triggers the golden rule."""
    con = connections_db(syns([1_700_000_000 + i * 0.1 for i in range(51)]))
    alerts = build_alerts(con, enrich=False)
    assert list(alerts["detection_type"]) == ["syn_flood"]


def test_window_override_is_positive(monkeypatch):
    """An invalid window cannot silently turn grouping into division by zero."""
    monkeypatch.setenv("WINDOW_SECONDS", "0")
    try:
        Thresholds.from_env()
    except ValueError as exc:
        assert "WINDOW_SECONDS" in str(exc)
    else:
        raise AssertionError("zero-length window was accepted")
