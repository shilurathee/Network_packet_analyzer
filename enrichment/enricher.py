import pandas as pd
from typing import Dict, Any, Optional
from enrichment.abuseipdb import AbuseIPDBClient
from enrichment.virustotal import VirusTotalClient
from enrichment.geoip import GeoIPLookup


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
