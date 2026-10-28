"""Unit tests for VirusTotal lookups. All HTTP calls are mocked."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from enrichment.virustotal import VTDuckDBCache, VirusTotalClient


def test_private_ip_never_calls_api(tmp_path):
    client = VirusTotalClient(api_key="fake-key", cache_db_path=str(tmp_path / "cache.duckdb"))
    with patch("enrichment.virustotal.requests.get") as mocked:
        result = client.lookup_ip("10.0.0.66")
    mocked.assert_not_called()
    assert result["status"] == "private_ip"


def test_missing_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    client = VirusTotalClient(api_key=None, cache_db_path=str(tmp_path / "cache.duckdb"))
    result = client.lookup_ip("8.8.8.8")
    assert result["status"] == "no_api_key"


def test_success_is_cached_for_second_lookup(tmp_path):
    cache_path = str(tmp_path / "cache.duckdb")
    client = VirusTotalClient(api_key="fake-key", cache_db_path=cache_path)

    fake = MagicMock()
    fake.status_code = 200
    fake.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 70,
                    "undetected": 10,
                },
                "reputation": -12,
                "as_owner": "Example ASN",
                "country": "US",
                "last_analysis_date": 1700000000,
                "tags": [],
            }
        }
    }

    with patch("enrichment.virustotal.requests.get", return_value=fake) as mocked:
        first = client.lookup_ip("1.2.3.4")
        second = client.lookup_ip("1.2.3.4")

    mocked.assert_called_once()
    assert first["status"] == "success"
    assert first["malicious_count"] == 2
    assert first["last_analysis_date"] == 1700000000
    assert second["from_cache"] is True or second["malicious_count"] == 2

    other = VirusTotalClient(api_key="fake-key", cache_db_path=cache_path)
    with patch("enrichment.virustotal.requests.get") as mocked_again:
        cached = other.lookup_ip("1.2.3.4")
    mocked_again.assert_not_called()
    assert cached["from_cache"] is True
    assert cached["malicious_count"] == 2


def test_http_429_is_rate_limited(tmp_path):
    client = VirusTotalClient(api_key="fake-key", cache_db_path=str(tmp_path / "cache.duckdb"))
    fake = MagicMock()
    fake.status_code = 429
    fake.text = "Too Many Requests"
    with patch("enrichment.virustotal.requests.get", return_value=fake):
        result = client.lookup_ip("9.9.9.9")
    assert result["status"] == "rate_limited"


def test_invalid_ip_rejected(tmp_path):
    client = VirusTotalClient(api_key="fake-key", cache_db_path=str(tmp_path / "cache.duckdb"))
    result = client.lookup_ip("not-an-ip")
    assert result["status"] == "invalid_input"


def test_cache_put_get_roundtrip(tmp_path):
    cache = VTDuckDBCache(str(tmp_path / "cache.duckdb"))
    cache.put(
        "8.8.4.4",
        {
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 80,
            "undetected_count": 5,
            "reputation": 10,
            "as_owner": "Google",
            "last_analysis_date": 1700000001,
        },
    )
    got = cache.get("8.8.4.4")
    assert got is not None
    assert got["from_cache"] is True
    assert got["harmless_count"] == 80
    assert got["last_analysis_date"] == "1700000001" or got["last_analysis_date"] == 1700000001
