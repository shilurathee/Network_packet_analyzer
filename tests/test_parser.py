"""Verify the Scapy parser's 15-column packet contract using temporary pcaps.

The tests write only synthetic packets and check layer-specific fields and
missing values before any detector or external service sees the data.
"""

import pandas as pd
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

from scapy_scan import process_pcap
from tests.conftest import CONNECTION_COLUMNS


def test_parser_packet_layers_and_nulls(tmp_path):
    """Each protocol fills its own fields and leaves unrelated fields null."""
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(flags="FS"),
        Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=4000, dport=53),
        Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / ICMP(type=8),
        Ether() / ARP(psrc="10.0.0.7", hwsrc="02:00:00:00:00:07", pdst="10.0.0.8"),
        Ether() / Raw(load=b"other"),
    ]
    path = tmp_path / "layers.pcap"
    wrpcap(str(path), packets)

    df = process_pcap(str(path))
    assert tuple(df.columns) == CONNECTION_COLUMNS
    assert all(len(df[column]) == len(packets) for column in CONNECTION_COLUMNS)
    assert df["protocol"].tolist() == ["TCP", "TCP", "UDP", "ICMP", "ARP", "OTHER"]
    assert df.loc[0, "tcpflags"] == "S"
    assert df.loc[1, "tcpflags"] == "FS"
    assert df.loc[2, "udpdst"] == 53
    assert df.loc[3, "icmp_type"] == 8
    assert df.loc[4, "arp_psrc"] == "10.0.0.7"
    assert df.loc[4, "arp_hwsrc"] == "02:00:00:00:00:07"
    assert pd.isna(df.loc[4, "ipsrc"])
    assert pd.isna(df.loc[0, "arp_psrc"])
    assert pd.isna(df.loc[5, "tcpflags"])
    assert df["timestamp"].notna().all()
