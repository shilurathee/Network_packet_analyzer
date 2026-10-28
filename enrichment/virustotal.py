"""
enrichment/virustotal.py — On-demand VirusTotal IP lookup.

What it does:
  Queries VirusTotal API v3 for a single public IP when the user clicks
  "Check on VirusTotal". Results live in cache.duckdb for 24 hours so the
  dashboard never writes to the main IDS database (DuckDB lock rules).

Why it exists:
  Automatic VT queries would burn the free-tier quota. Caching and a
  15-second client-side gap keep the button usable in a viva demo.

Inputs:  public IP string; VIRUSTOTAL_API_KEY from the environment.
Outputs: dict with last_analysis_stats counts, reputation, as_owner,
         country, last_analysis_date, status.
"""
import os
import ipaddress
import requests
from typing import Dict, Any, Optional

try:
    import duckdb as _duckdb
    _DUCKDB_AVAILABLE = True
except ImportError:
    _DUCKDB_AVAILABLE = False

VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_DEFAULT_CACHE_DB = "cache.duckdb"
_DEFAULT_CACHE_HOURS = 24


class VTDuckDBCache:
    """
    Persistent VirusTotal result cache stored in a separate DuckDB file (cache.duckdb).
    Kept separate from the main database to avoid the DuckDB read-write lock conflict
    when the dashboard opens the main DB read-only while the pipeline writes to it.

    Input:  ip (str), result dict from VirusTotal API.
    Output: cached result dict, or None if not found / expired.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or os.getenv("CACHE_DB_PATH", _DEFAULT_CACHE_DB)
        self._max_age_hours = int(os.getenv("VT_CACHE_MAX_AGE_HOURS", str(_DEFAULT_CACHE_HOURS)))
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create the virustotal_cache table if it does not already exist."""
        if not _DUCKDB_AVAILABLE:
            return
        try:
            con = _duckdb.connect(self.db_path)
            con.execute("""
                CREATE TABLE IF NOT EXISTS virustotal_cache (
                    ip           VARCHAR PRIMARY KEY,
                    malicious    INTEGER DEFAULT 0,
                    suspicious   INTEGER DEFAULT 0,
                    harmless     INTEGER DEFAULT 0,
                    undetected   INTEGER DEFAULT 0,
                    reputation   INTEGER DEFAULT 0,
                    as_owner     VARCHAR,
                    checked_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            try:
                con.execute(
                    "ALTER TABLE virustotal_cache "
                    "ADD COLUMN IF NOT EXISTS last_analysis_date VARCHAR"
                )
            except Exception:
                pass
            con.close()
        except Exception:
            pass

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Return a cached result if younger than VT_CACHE_MAX_AGE_HOURS, else None."""
        if not _DUCKDB_AVAILABLE:
            return None
        try:
            hours = int(self._max_age_hours)
            con = _duckdb.connect(self.db_path, read_only=True)
            row = con.execute(
                f"""
                SELECT malicious, suspicious, harmless, undetected,
                       reputation, as_owner, checked_at, last_analysis_date
                FROM   virustotal_cache
                WHERE  ip = ?
                  AND  checked_at > CURRENT_TIMESTAMP
                               - INTERVAL '{hours} hours'
                """,
                [ip],
            ).fetchone()
            con.close()
            if row:
                return {
                    "malicious_count": row[0],
                    "suspicious_count": row[1],
                    "harmless_count":   row[2],
                    "undetected_count": row[3],
                    "reputation":       row[4],
                    "as_owner":         row[5],
                    "cached_at":        str(row[6]),
                    "last_analysis_date": row[7],
                    "status":           "success",
                    "from_cache":       True,
                }
        except Exception:
            pass
        return None

    def put(self, ip: str, result: Dict[str, Any]) -> None:
        """Upsert a VirusTotal result into the persistent cache."""
        if not _DUCKDB_AVAILABLE:
            return
        try:
            con = _duckdb.connect(self.db_path)
            con.execute("DELETE FROM virustotal_cache WHERE ip = ?", [ip])
            con.execute(
                """
                INSERT INTO virustotal_cache
                    (ip, malicious, suspicious, harmless, undetected,
                     reputation, as_owner, last_analysis_date, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                [
                    ip,
                    result.get("malicious_count", 0),
                    result.get("suspicious_count", 0),
                    result.get("harmless_count",   0),
                    result.get("undetected_count", 0),
                    result.get("reputation",       0),
                    result.get("as_owner",         ""),
                    result.get("last_analysis_date"),
                ],
            )
            con.close()
        except Exception:
            pass



class VirusTotalClient:
    """Client for VirusTotal API v3 IP lookups with session and persistent caching."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_db_path: Optional[str] = None,
    ) -> None:
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._db_cache = VTDuckDBCache(cache_db_path)

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

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "invalid_input", "malicious_count": 0}

        # 1. Check in-memory session cache
        if ip in self._cache:
            return self._cache[ip]

        # 2. Check persistent DuckDB cache (survives dashboard restarts)
        db_cached = self._db_cache.get(ip)
        if db_cached:
            self._cache[ip] = db_cached
            return db_cached

        # 3. Skip private / local addresses
        if not ip_obj.is_global:
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
                    "ip":               ip,
                    "malicious_count":  stats.get("malicious",  0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count":   stats.get("harmless",   0),
                    "undetected_count": stats.get("undetected", 0),
                    "reputation":       attrs.get("reputation", 0),
                    "as_owner":         attrs.get("as_owner"),
                    "country":          attrs.get("country"),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                    "tags":             attrs.get("tags", []),
                    "status":           "success",
                    "from_cache":       False,
                }
                self._cache[ip] = result
                self._db_cache.put(ip, result)  # persist across sessions
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
