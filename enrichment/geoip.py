import os
import ipaddress
import requests
from typing import Dict, Any, Optional

DEFAULT_MMDB_PATH = os.path.join("data", "GeoLite2-City.mmdb")


class GeoIPLookup:
    """GeoIP resolver supporting local MaxMind GeoLite2 databases with HTTP fallback."""

    def __init__(self, mmdb_path: Optional[str] = None):
        self.mmdb_path = mmdb_path or os.getenv("GEOIP_DB_PATH", DEFAULT_MMDB_PATH)
        self._reader = None
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._init_reader()

    def _init_reader(self):
        """Attempt to load the MaxMind geoip2 reader if the database and package exist."""
        if os.path.exists(self.mmdb_path):
            try:
                import importlib
                geoip2_db = importlib.import_module("geoip2.database")
                self._reader = geoip2_db.Reader(self.mmdb_path)
            except (ImportError, ModuleNotFoundError):
                self._reader = None
            except Exception:
                self._reader = None
        else:
            self._reader = None

    def is_valid_public_ip(self, ip: str) -> bool:
        """Check if an IP string is a valid public IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            return not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
                or ip_obj.is_link_local
            )
        except (ValueError, AttributeError):
            return False

    def lookup(self, ip: str, allow_http_fallback: bool = True) -> Dict[str, Any]:
        """
        Resolve IP to geographic location.

        Returns:
            - country_name: e.g. 'United States'
            - country_code: e.g. 'US'
            - city: e.g. 'San Francisco'
            - latitude: float or None
            - longitude: float or None
            - time_zone: e.g. 'America/Los_Angeles'
            - provider: 'maxmind', 'ip-api', 'local', or 'unknown'
            - status: 'success', 'private_ip', or 'not_found'
        """
        if not ip or not isinstance(ip, str):
            return {"status": "invalid_input", "country_name": "Unknown"}

        ip = ip.strip()

        if ip in self._cache:
            return self._cache[ip]

        # Handle private / local addresses
        if not self.is_valid_public_ip(ip):
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

        # 1. Try MaxMind Local Database (fastest, offline)
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
            except Exception:
                pass

        # 2. Fallback to free HTTP API (ip-api.com) for development/demonstration
        if allow_http_fallback:
            try:
                res = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,timezone",
                    timeout=5,
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
            except Exception:
                pass

        # If all lookups fail
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

    def close(self):
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
