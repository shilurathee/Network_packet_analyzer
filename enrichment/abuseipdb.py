import os
import ipaddress
import requests
from typing import Dict, Any, Optional

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBClient:
    """Client for interacting with the AbuseIPDB API v2 with built-in caching."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self._cache: Dict[str, Dict[str, Any]] = {}

    def is_valid_public_ip(self, ip: str) -> bool:
        """Check if an IP string is a valid, publicly routable IPv4/IPv6 address."""
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

    def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check the reputation of an IP address.

        Returns a dictionary with:
            - abuse_score: Abuse Confidence Score (0-100)
            - total_reports: Total number of reports
            - country_code: 2-letter country code
            - isp: ISP name
            - domain: Associated domain name
            - is_whitelisted: Whether the IP is whitelisted
            - is_public: Whether the IP is public
            - status: 'success', 'private_ip', 'no_api_key', or 'error'
        """
        if not ip or not isinstance(ip, str):
            return {"status": "invalid_input", "abuse_score": 0, "total_reports": 0}

        ip = ip.strip()

        # Check cache
        if ip in self._cache:
            return self._cache[ip]

        # Check for private or non-routable IP
        if not self.is_valid_public_ip(ip):
            result = {
                "ip": ip,
                "abuse_score": 0,
                "total_reports": 0,
                "country_code": "LOCAL",
                "isp": "Private/Local Network",
                "domain": "local",
                "is_whitelisted": True,
                "is_public": False,
                "status": "private_ip",
            }
            self._cache[ip] = result
            return result

        if not self.api_key:
            self.api_key = os.getenv("ABUSEIPDB_API_KEY")

        if not self.api_key:
            return {
                "ip": ip,
                "abuse_score": 0,
                "total_reports": 0,
                "country_code": None,
                "isp": None,
                "domain": None,
                "is_whitelisted": None,
                "is_public": True,
                "status": "no_api_key",
                "error": "ABUSEIPDB_API_KEY environment variable not set",
            }

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": True,
        }

        try:
            response = requests.get(
                ABUSEIPDB_CHECK_URL,
                headers=headers,
                params=params,
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                result = {
                    "ip": ip,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "is_public": data.get("isPublic", True),
                    "last_reported_at": data.get("lastReportedAt"),
                    "status": "success",
                }
                self._cache[ip] = result
                return result
            elif response.status_code == 429:
                return {
                    "ip": ip,
                    "abuse_score": 0,
                    "status": "rate_limited",
                    "error": "AbuseIPDB daily limit reached (HTTP 429)",
                }
            else:
                return {
                    "ip": ip,
                    "abuse_score": 0,
                    "status": "error",
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except requests.exceptions.RequestException as e:
            return {
                "ip": ip,
                "abuse_score": 0,
                "status": "error",
                "error": str(e),
            }


_client = AbuseIPDBClient()


def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """Convenience function to check IP reputation using the global client."""
    return _client.check_ip(ip)
