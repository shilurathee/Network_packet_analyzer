"""Unit tests for GeoIPLookup. All network calls are mocked."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from enrichment.geoip import GeoIPLookup


def test_private_ip_is_internal_and_has_no_coordinates():
    geo = GeoIPLookup(mmdb_path="data/does-not-exist.mmdb")
    result = geo.lookup("10.0.0.99", allow_http_fallback=False)
    assert result["status"] == "private_ip"
    assert result["latitude"] is None
    assert result["longitude"] is None
    assert result["provider"] == "local"


def test_missing_mmdb_without_http_returns_not_found():
    geo = GeoIPLookup(mmdb_path="data/does-not-exist.mmdb")
    result = geo.lookup("8.8.8.8", allow_http_fallback=False)
    assert result["status"] == "not_found"
    assert result["latitude"] is None
    assert result["longitude"] is None


def test_http_fallback_is_off_by_default_and_opt_in_is_cached(monkeypatch, caplog):
    monkeypatch.delenv("GEOIP_HTTP_FALLBACK", raising=False)
    geo = GeoIPLookup(mmdb_path="data/does-not-exist.mmdb")
    with patch("enrichment.geoip.requests.get") as mocked:
        assert geo.lookup("8.8.8.8")["status"] == "not_found"
    mocked.assert_not_called()

    monkeypatch.setenv("GEOIP_HTTP_FALLBACK", "1")
    monkeypatch.setattr("enrichment.geoip._HTTP_FALLBACK_WARNED", False)
    geo = GeoIPLookup(mmdb_path="data/does-not-exist.mmdb")
    fake = MagicMock()
    fake.status_code = 200
    fake.json.return_value = {"status": "success", "country": "United States"}
    with patch("enrichment.geoip.requests.get", return_value=fake) as mocked:
        assert geo.lookup("8.8.8.8")["status"] == "success"
        assert geo.lookup("8.8.8.8")["status"] == "success"
        assert geo.lookup("10.0.0.1")["status"] == "private_ip"
    mocked.assert_called_once()
    assert mocked.call_args.kwargs["timeout"] == 10
    assert caplog.text.count("sent unencrypted over HTTP to ip-api.com") == 1


def test_http_fallback_is_mocked():
    geo = GeoIPLookup(mmdb_path="data/does-not-exist.mmdb")
    fake = MagicMock()
    fake.status_code = 200
    fake.json.return_value = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "city": "Mountain View",
        "lat": 37.386,
        "lon": -122.0838,
        "timezone": "America/Los_Angeles",
    }

    with patch("enrichment.geoip.requests.get", return_value=fake) as mocked:
        result = geo.lookup("8.8.8.8", allow_http_fallback=True)

    mocked.assert_called_once()
    assert mocked.call_args.kwargs.get("timeout") == 10
    assert result["status"] == "success"
    assert result["provider"] == "ip-api"
    assert result["latitude"] == 37.386
    assert result["country_code"] == "US"


def test_maxmind_reader_success():
    geo = GeoIPLookup(mmdb_path="data/does-not-exist.mmdb")
    city = MagicMock()
    city.country.name = "Germany"
    city.country.iso_code = "DE"
    city.city.name = "Frankfurt"
    city.location.latitude = 50.11
    city.location.longitude = 8.68
    city.location.time_zone = "Europe/Berlin"
    geo._reader = MagicMock()
    geo._reader.city.return_value = city

    result = geo.lookup("1.1.1.1", allow_http_fallback=False)

    assert result["status"] == "success"
    assert result["provider"] == "maxmind"
    assert result["city"] == "Frankfurt"
    assert result["latitude"] == 50.11
    geo._reader.city.assert_called_once_with("1.1.1.1")
