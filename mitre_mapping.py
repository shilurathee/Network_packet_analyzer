"""ATT&CK Enterprise v20.0 labels for network observations.

An alert describes packet behavior; it does not establish adversary intent.
The confidence field describes the strength of the behavioral mapping only.
"""

MITRE_MAP = {
    "port_scan": {
        "technique_id": "T1046", "name": "Network Service Discovery",
        "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1046/",
        "confidence": "approximate",
    },
    "syn_flood": {
        "technique_id": "T1499.001", "name": "Endpoint Denial of Service: OS Exhaustion Flood",
        "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1499/001/",
        "confidence": "exact",
    },
    "icmp_flood": {
        "technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1498/001/",
        "confidence": "approximate",
    },
    "arp_spoofing": {
        "technique_id": "T1557.002", "name": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "tactic": "Credential Access, Collection",
        "url": "https://attack.mitre.org/techniques/T1557/002/",
        "confidence": "approximate",
    },
    "dns_tunneling": {
        "technique_id": "T1071.004", "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
        "confidence": "approximate",
    },
    "malformed_flags": {
        "technique_id": None, "name": "Unmapped TCP SYN+FIN observation",
        "tactic": None, "url": None, "confidence": "approximate",
    },
}


def mitre_label(detection_name):
    """Render the legacy display column, marking uncertainty explicitly."""
    mapping = MITRE_MAP[detection_name]
    if mapping["technique_id"] is None:
        return "Unmapped (no ATT&CK technique for SYN+FIN flags)"
    label = f"{mapping['technique_id']} - {mapping['name']}"
    if mapping["confidence"] == "approximate":
        label += " (approximate)"
    return label


def tag_with_mitre(df, detection_name):
    """Stamp detector output with its display label and detection type."""
    df = df.copy()
    df["mitre_technique"] = mitre_label(detection_name)
    df["detection_type"] = detection_name
    return df
