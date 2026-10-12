MITRE_MAP = {
    "port_scan": "T1046 - Network Service Discovery",
    "syn_flood": "T1499 - Endpoint Denial of Service",
    "icmp_flood": "T1499 - Endpoint Denial of Service",
    "arp_spoofing": "T1557 - Adversary-in-the-Middle",
    "dns_tunneling": "T1071.004 - Application Layer Protocol: DNS",
    "malformed_flags": "T1562.004 - Impair Defenses: Disable/Modify Firewall",
}


def tag_with_mitre(df, detection_name):
    """Stamps every row of a detector's result with its MITRE technique ID."""
    df = df.copy()
    df["mitre_technique"] = MITRE_MAP[detection_name]
    df["detection_type"] = detection_name
    return df