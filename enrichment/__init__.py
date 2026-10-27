import os

def _init_env():
    try:
        from dotenv import load_dotenv
        load_dotenv()
        return
    except ImportError:
        pass

    # Built-in fallback loader
    env_paths = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(__file__), "..", ".env"),
    ]
    for env_path in env_paths:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip('"').strip("'")
                            if k and k not in os.environ:
                                os.environ[k] = v
                break
            except Exception:
                pass

_init_env()

from enrichment.abuseipdb import AbuseIPDBClient, check_ip_reputation
from enrichment.virustotal import VirusTotalClient, check_virustotal_ip
from enrichment.geoip import GeoIPLookup, get_ip_location
from enrichment.enricher import ThreatEnricher, enrich_alerts

__all__ = [
    "AbuseIPDBClient",
    "check_ip_reputation",
    "VirusTotalClient",
    "check_virustotal_ip",
    "GeoIPLookup",
    "get_ip_location",
    "ThreatEnricher",
    "enrich_alerts",
]
