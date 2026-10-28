"""Check the six-alert reference capture and a clean synthetic capture.

Both follow the real parser into an isolated DuckDB connections table and
build alerts without enrichment, so no API key or network access is needed.
"""

from pathlib import Path

import pandas as pd
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, wrpcap

from alerts import build_alerts
from scapy_scan import process_pcap

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    ("10.0.0.66", "syn_flood"),
    ("10.0.0.99", "port_scan"),
    ("10.0.0.77", "icmp_flood"),
    ("10.0.0.1", "arp_spoofing"),
    ("10.0.0.88", "dns_tunneling"),
    ("10.0.0.55", "malformed_flags"),
}


def packet_rows(df):
    """Convert pandas missing values to SQL NULLs for the fixture table."""
    return df.astype(object).where(pd.notna(df), None).to_dict("records")


def test_golden_capture(connections_db):
    """The reference capture must produce exactly the six documented pairs."""
    df = process_pcap(str(ROOT / "test_traffic.pcap"))
    assert len(df) == 1001
    con = connections_db(packet_rows(df))
    alerts = build_alerts(con, enrich=False)
    actual = set(zip(alerts["ipsrc"], alerts["detection_type"]))
    assert len(alerts) == 6
    assert actual == EXPECTED


def test_clean_capture_has_no_alerts(tmp_path, connections_db):
    """Small ordinary traffic must not trigger any detection rule."""
    packets = [
        Ether() / IP(src="10.0.0.10", dst="10.0.0.20") / TCP(dport=443, flags="S")
        for _ in range(5)
    ]
    packets += [Ether() / IP(src="10.0.0.11", dst="10.0.0.20") / ICMP(type=8)
                for _ in range(3)]
    packets += [Ether() / IP(src="10.0.0.12", dst="10.0.0.20") / UDP(dport=53)]
    packets += [Ether() / ARP(psrc="10.0.0.13", hwsrc="02:00:00:00:00:13")]
    path = tmp_path / "clean.pcap"
    wrpcap(str(path), packets)

    df = process_pcap(str(path))
    con = connections_db(packet_rows(df))
    assert len(df) == len(packets)
    assert build_alerts(con, enrich=False).empty
