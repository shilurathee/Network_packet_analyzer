import os
import ipaddress
import requests
from typing import Dict, Any, Optional

VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


class VirusTotalClient:
    """Client for VirusTotal API v3 IP lookups with rate-limit friendly caching."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self._cache: Dict[str, Dict[str, Any]] = {}

    def is_valid_public_ip(self, ip: str) -> bool:
        """Check if an IP string is a valid, publicly routable address."""
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

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Query VirusTotal for analysis statistics and reputation of an IP.

        Returns:
            - malicious_count: Number of engines flagging the IP as malicious
            - suspicious_count: Number of engines flagging as suspicious
            - harmless_count: Number of engines flagging as harmless
            - undetected_count: Undetected count
            - reputation: VT reputation score
            - as_owner: Autonomous System Owner
            - country: Associated country code
            - status: 'success', 'private_ip', 'no_api_key', 'not_found', or 'error'
        """
        if not ip or not isinstance(ip, str):
            return {"status": "invalid_input", "malicious_count": 0}

        ip = ip.strip()

        # Check in-memory cache first to conserve rate limit (4 req/min free tier)
        if ip in self._cache:
            return self._cache[ip]

        # Skip private / local addresses
        if not self.is_valid_public_ip(ip):
            result = {
                "ip": ip,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "reputation": 0,
                "as_owner": "Private Network",
                "country": "LOCAL",
                "status": "private_ip",
            }
            self._cache[ip] = result
            return result

        if not self.api_key:
            self.api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if not self.api_key:
            return {
                "ip": ip,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "reputation": 0,
                "as_owner": None,
                "country": None,
                "status": "no_api_key",
                "error": "VIRUSTOTAL_API_KEY environment variable not set",
            }

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            response = requests.get(
                VIRUSTOTAL_IP_URL.format(ip=ip),
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                result = {
                    "ip": ip,
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "as_owner": attrs.get("as_owner"),
                    "country": attrs.get("country"),
                    "tags": attrs.get("tags", []),
                    "status": "success",
                }
                self._cache[ip] = result
                return result
            elif response.status_code == 404:
                result = {
                    "ip": ip,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "harmless_count": 0,
                    "undetected_count": 0,
                    "reputation": 0,
                    "as_owner": None,
                    "country": None,
                    "status": "not_found",
                    "error": "IP not observed in VirusTotal database",
                }
                self._cache[ip] = result
                return result
            elif response.status_code == 429:
                return {
                    "ip": ip,
                    "malicious_count": 0,
                    "status": "rate_limited",
                    "error": "VirusTotal request rate limit exceeded (HTTP 429)",
                }
            else:
                return {
                    "ip": ip,
                    "malicious_count": 0,
                    "status": "error",
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except requests.exceptions.RequestException as e:
            return {
                "ip": ip,
                "malicious_count": 0,
                "status": "error",
                "error": str(e),
            }


_client = VirusTotalClient()


def check_virustotal_ip(ip: str) -> Dict[str, Any]:
    """Convenience function to perform on-demand VirusTotal IP analysis."""
    return _client.lookup_ip(ip)
