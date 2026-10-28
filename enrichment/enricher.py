import ipaddress
import pandas as pd
import duckdb
from typing import Dict, Any, Optional
from enrichment.abuseipdb import AbuseIPDBClient
from enrichment.virustotal import VirusTotalClient
from enrichment.geoip import GeoIPLookup


def _is_private_ip(ip: str) -> bool:
    """Return True if ip is a non-routable (private/loopback/link-local) address."""
    try:
        return not ipaddress.ip_address(ip.strip()).is_global
    except ValueError:
        return True


def _ensure_ip_reputation_table(con: duckdb.DuckDBPyConnection) -> None:
    """
    Create the ip_reputation table if it does not exist, and run column migrations
    so that existing databases (created before lat/lon/city were added) keep working.
    """
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip           VARCHAR PRIMARY KEY,
            abuse_score  INTEGER DEFAULT 0,
            total_reports INTEGER DEFAULT 0,
            country      VARCHAR,
            city         VARCHAR,
            isp          VARCHAR,
            latitude     DOUBLE,
            longitude    DOUBLE,
            status       VARCHAR DEFAULT 'checked'
        )
    """)
    for col, dtype in [("latitude", "DOUBLE"), ("longitude", "DOUBLE"), ("city", "VARCHAR")]:
        try:
            con.execute(f"ALTER TABLE ip_reputation ADD COLUMN IF NOT EXISTS {col} {dtype}")
        except Exception:
            pass


def persist_ip_reputation(con: duckdb.DuckDBPyConnection, alerts_df: pd.DataFrame) -> None:
    """
    Upsert geo + abuse enrichment for each unique alert IP into the ip_reputation table.
    Private IPs are stored with status='internal' and will not be sent to external APIs.

    Inputs:  DuckDB connection (read-write), enriched alerts DataFrame.
    Outputs: Rows inserted/updated in ip_reputation table (no return value).
    """
    if alerts_df.empty or "ipsrc" not in alerts_df.columns:
        return
    _ensure_ip_reputation_table(con)

    seen: set = set()
    for _, row in alerts_df.iterrows():
        ip = str(row.get("ipsrc", "") or "")
        if not ip or ip in seen:
            continue
        seen.add(ip)

        status       = "internal" if _is_private_ip(ip) else "checked"
        abuse_score  = int(row.get("abuse_score", 0) or 0)
        country      = str(row.get("country",     "") or "")
        city         = str(row.get("city",        "") or "")
        isp          = str(row.get("isp",         "") or "")
        latitude     = row.get("latitude")  if pd.notna(row.get("latitude"))  else None
        longitude    = row.get("longitude") if pd.notna(row.get("longitude")) else None

        try:
            con.execute("DELETE FROM ip_reputation WHERE ip = ?", [ip])
            con.execute(
                """
                INSERT INTO ip_reputation
                    (ip, abuse_score, total_reports, country, city, isp,
                     latitude, longitude, status)
                VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?)
                """,
                [ip, abuse_score, country, city, isp, latitude, longitude, status],
            )
        except Exception:
            pass



class ThreatEnricher:
    """Unified threat intelligence and geolocation enrichment orchestrator."""

    def __init__(
        self,
        abuseipdb_client: Optional[AbuseIPDBClient] = None,
        virustotal_client: Optional[VirusTotalClient] = None,
        geoip_lookup: Optional[GeoIPLookup] = None,
    ):
        self.abuse = abuseipdb_client or AbuseIPDBClient()
        self.vt = virustotal_client or VirusTotalClient()
        self.geo = geoip_lookup or GeoIPLookup()

    def enrich_single_ip(self, ip: str, include_virustotal: bool = False) -> Dict[str, Any]:
        """Enrich a single IP address with GeoIP, AbuseIPDB, and optionally VirusTotal."""
        geo_data = self.geo.lookup(ip)
        abuse_data = self.abuse.check_ip(ip)

        vt_data = {}
        if include_virustotal:
            vt_data = self.vt.lookup_ip(ip)

        return {
            "ip": ip,
            # GeoIP info
            "country": geo_data.get("country_name", "Unknown"),
            "country_code": geo_data.get("country_code", "??"),
            "city": geo_data.get("city", "Unknown"),
            "latitude": geo_data.get("latitude"),
            "longitude": geo_data.get("longitude"),
            # AbuseIPDB info
            "abuse_score": abuse_data.get("abuse_score", 0),
            "total_reports": abuse_data.get("total_reports", 0),
            "isp": abuse_data.get("isp", "N/A"),
            "abuse_status": abuse_data.get("status"),
            # VirusTotal info (if requested)
            "vt_malicious": vt_data.get("malicious_count", 0) if include_virustotal else None,
            "vt_suspicious": vt_data.get("suspicious_count", 0) if include_virustotal else None,
            "vt_reputation": vt_data.get("reputation", 0) if include_virustotal else None,
        }

    def enrich_dataframe(
        self,
        df: pd.DataFrame,
        ip_column: str = "ipsrc",
        include_virustotal: bool = False,
    ) -> pd.DataFrame:
        """
        Enrich an alerts DataFrame with threat intelligence and GeoIP data.
        Performs unique IP deduplication to minimize network calls and preserve rate limits.
        """
        if df.empty or ip_column not in df.columns:
            return df.copy()

        df = df.copy()
        unique_ips = [ip for ip in df[ip_column].dropna().unique() if str(ip).strip()]

        cache = {}
        for ip in unique_ips:
            cache[ip] = self.enrich_single_ip(ip, include_virustotal=include_virustotal)

        # Map enrichment columns onto DataFrame
        df["country"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("country", "Unknown"))
        df["city"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("city", "Unknown"))
        df["latitude"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("latitude"))
        df["longitude"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("longitude"))
        df["abuse_score"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("abuse_score", 0))
        df["isp"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("isp", "N/A"))

        if include_virustotal:
            df["vt_malicious"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("vt_malicious", 0))
            df["vt_reputation"] = df[ip_column].map(lambda ip: cache.get(ip, {}).get("vt_reputation", 0))

        return df


_default_enricher = ThreatEnricher()


def enrich_alerts(df: pd.DataFrame, include_virustotal: bool = False) -> pd.DataFrame:
    """Convenience helper to enrich alerts DataFrame."""
    return _default_enricher.enrich_dataframe(df, include_virustotal=include_virustotal)
