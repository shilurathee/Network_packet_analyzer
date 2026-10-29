"""Verify the Scapy parser's 18-column packet contract using temporary pcaps.

The tests write only synthetic packets and check layer-specific fields and
missing values before any detector or external service sees the data.
"""

import pandas as pd
import warnings
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

from scapy_scan import extract_packet_data, process_pcap
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
        Ether() / IP(src="10.0.0.9", dst="10.0.0.10") / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname="long.example.test", qtype=16)),
    ]
    path = tmp_path / "layers.pcap"
    wrpcap(str(path), packets)

    df = process_pcap(str(path))
    assert tuple(df.columns) == CONNECTION_COLUMNS
    assert all(len(df[column]) == len(packets) for column in CONNECTION_COLUMNS)
    assert df["protocol"].tolist() == ["TCP", "TCP", "UDP", "ICMP", "ARP", "OTHER", "UDP"]
    assert df.loc[0, "tcpflags"] == "S"
    assert df.loc[1, "tcpflags"] == "FS"
    assert df.loc[2, "udpdst"] == 53
    assert df.loc[3, "icmp_type"] == 8
    assert df.loc[4, "arp_psrc"] == "10.0.0.7"
    assert df.loc[4, "arp_hwsrc"] == "02:00:00:00:00:07"
    assert df.loc[4, "arp_op"] == 1
    assert pd.isna(df.loc[4, "ipsrc"])
    assert pd.isna(df.loc[0, "arp_psrc"])
    assert pd.isna(df.loc[0, "arp_op"])
    assert df.loc[6, "dns_qname"] == "long.example.test"
    assert df.loc[6, "dns_qtype"] == 16
    assert pd.isna(df.loc[0, "dns_qname"])
    assert pd.isna(df.loc[5, "tcpflags"])
    assert df["timestamp"].notna().all()


def test_invalid_dns_name_becomes_null():
    """An undecodable query name must not break the packet table."""
    packet = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
              / UDP(dport=53) / DNS(qd=DNSQR(qname=b"\xff.example.test")))
    df = extract_packet_data([packet])
    assert pd.isna(df.loc[0, "dns_qname"])
    assert pd.isna(df.loc[0, "dns_qtype"])


def test_dns_question_access_has_no_scapy_deprecation():
    packet = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
              / UDP(dport=53) / DNS(qd=DNSQR(qname="valid.example.test")))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        df = extract_packet_data([packet])
    assert df.loc[0, "dns_qname"] == "valid.example.test"
    assert not [warning for warning in caught if issubclass(warning.category, DeprecationWarning)
                and "DNS fields" in str(warning.message)]
