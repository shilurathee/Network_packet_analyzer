"""
enrichment/geoip.py — IP geolocation via local MaxMind GeoLite2.

What it does:
  Maps a public IP to country, city, latitude and longitude so the dashboard
  can plot attackers. Private IPs are labelled internal and never looked up.

Why it exists:
  Abuse scores alone do not show *where* traffic came from. A local MMDB
  file avoids a paid GeoIP API for every alert.

Inputs:  IP string; optional path from GEOIP_DB_PATH (default
         data/GeoLite2-City.mmdb).
Outputs: dict with country_name, country_code, city, latitude, longitude,
         time_zone, provider, status.

The GeoLite2 file is licensed by MaxMind and must not be committed.
If it is missing, one warning is logged and lookups continue without
coordinates. Set GEOIP_HTTP_FALLBACK=1 to opt into ip-api.com lookups.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_MMDB_PATH = os.path.join("data", "GeoLite2-City.mmdb")
_MISSING_MMDB_WARNED = False
_HTTP_FALLBACK_WARNED = False


class GeoIPLookup:
    """GeoIP resolver supporting local MaxMind GeoLite2 databases with HTTP fallback."""

    def __init__(self, mmdb_path: Optional[str] = None):
        self.mmdb_path = mmdb_path or os.getenv("GEOIP_DB_PATH", DEFAULT_MMDB_PATH)
        self._reader = None
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._init_reader()

    def _init_reader(self) -> None:
        """Load the MaxMind reader if the database and geoip2 package exist."""
        global _MISSING_MMDB_WARNED
        if not os.path.exists(self.mmdb_path):
            if not _MISSING_MMDB_WARNED:
                logger.warning(
                    "GeoLite2 database not found at %s. "
                    "Map points will be empty unless GEOIP_HTTP_FALLBACK=1. "
                    "See README for MaxMind download steps.",
                    self.mmdb_path,
                )
                _MISSING_MMDB_WARNED = True
            self._reader = None
            return
        try:
            import importlib

            geoip2_db = importlib.import_module("geoip2.database")
            self._reader = geoip2_db.Reader(self.mmdb_path)
        except (ImportError, ModuleNotFoundError):
            logger.warning("geoip2 is not installed; GeoIP lookups will skip the local database.")
            self._reader = None
        except Exception:
            logger.warning("Failed to open GeoLite2 database at %s.", self.mmdb_path, exc_info=True)
            self._reader = None

    def is_valid_public_ip(self, ip: str) -> bool:
        """Return True if the IP is globally routable."""
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            return ip_obj.is_global
        except (ValueError, AttributeError):
            return False

    def lookup(self, ip: str, allow_http_fallback: Optional[bool] = None) -> Dict[str, Any]:
        """
        Resolve IP to geographic location.

        Returns:
            country_name, country_code, city, latitude, longitude, time_zone,
            provider ('maxmind', 'ip-api', 'local', or 'unknown'),
            status ('success', 'private_ip', or 'not_found').
        """
        if not ip or not isinstance(ip, str):
            return {"status": "invalid_input", "country_name": "Unknown"}

        ip = ip.strip()

        if allow_http_fallback is None:
            allow_http_fallback = os.getenv("GEOIP_HTTP_FALLBACK") == "1"
            if allow_http_fallback:
                global _HTTP_FALLBACK_WARNED
                if not _HTTP_FALLBACK_WARNED:
                    logger.warning(
                        "GEOIP_HTTP_FALLBACK is enabled: public IP addresses may be "
                        "sent unencrypted over HTTP to ip-api.com."
                    )
                    _HTTP_FALLBACK_WARNED = True

        if ip in self._cache:
            return self._cache[ip]

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "invalid_input", "country_name": "Unknown"}

        if not ip_obj.is_global:
            result = {
                "ip": ip,
                "country_name": "Private Network",
                "country_code": "LOCAL",
                "city": "Internal",
                "latitude": None,
                "longitude": None,
                "time_zone": None,
                "provider": "local",
                "status": "private_ip",
            }
            self._cache[ip] = result
            return result

        if self._reader:
            try:
                resp = self._reader.city(ip)
                result = {
                    "ip": ip,
                    "country_name": resp.country.name or "Unknown",
                    "country_code": resp.country.iso_code or "??",
                    "city": resp.city.name or "Unknown",
                    "latitude": resp.location.latitude,
                    "longitude": resp.location.longitude,
                    "time_zone": resp.location.time_zone,
                    "provider": "maxmind",
                    "status": "success",
                }
                self._cache[ip] = result
                return result
            except Exception as exc:
                address_not_found = False
                try:
                    from geoip2.errors import AddressNotFoundError

                    address_not_found = isinstance(exc, AddressNotFoundError)
                except ImportError:
                    address_not_found = False
                if not address_not_found:
                    logger.debug("MaxMind lookup failed for %s: %s", ip, exc)

        # The public-IP-only check above runs before any network request.
        if allow_http_fallback:
            try:
                res = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,timezone",
                    timeout=10,
                )
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        result = {
                            "ip": ip,
                            "country_name": data.get("country", "Unknown"),
                            "country_code": data.get("countryCode", "??"),
                            "city": data.get("city", "Unknown"),
                            "latitude": data.get("lat"),
                            "longitude": data.get("lon"),
                            "time_zone": data.get("timezone"),
                            "provider": "ip-api",
                            "status": "success",
                        }
                        self._cache[ip] = result
                        return result
            except requests.exceptions.RequestException:
                pass

        result = {
            "ip": ip,
            "country_name": "Unknown",
            "country_code": "??",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "time_zone": None,
            "provider": "unknown",
            "status": "not_found",
        }
        self._cache[ip] = result
        return result

    def close(self) -> None:
        """Close the MaxMind database reader."""
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass


_geo_client = GeoIPLookup()


def get_ip_location(ip: str) -> Dict[str, Any]:
    """Convenience function to get geolocation for an IP."""
    return _geo_client.lookup(ip)
