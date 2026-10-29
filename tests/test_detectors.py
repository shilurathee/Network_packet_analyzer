"""Exercise all six rules at positive, negative and threshold boundaries.

Rows use the real connections schema. Tests call detector.py and alerts.py
without changing production thresholds or making network requests.
"""

import pytest

from alerts import FLOOD_MIN_SYNS, SCAN_MIN_PORTS, build_alerts
from config import Thresholds
from detector import (
    detect_arp_spoofing,
    detect_dns_tunneling,
    detect_icmp_flood,
    detect_malformed_flags,
    detect_port_scan_and_syn_flood,
)

ICMP_MIN = Thresholds().icmp_min
DNS_MIN_SIZE = Thresholds().dns_min_size


def syn_rows(count, ports):
    """Make SYN-only rows from one source across the requested port count."""
    return [
        {"ipsrc": "10.0.0.1", "ipdst": "10.0.0.2", "protocol": "TCP",
         "tcpflags": "S", "tcpdst": 1000 + i % ports, "packet_length": 60}
        for i in range(count)
    ]


@pytest.mark.parametrize("ports,expected", [
    (SCAN_MIN_PORTS - 1, False),
    (SCAN_MIN_PORTS, True),
    (SCAN_MIN_PORTS + 1, True),
])
def test_port_scan_boundary(connections_db, ports, expected):
    """The raw SYN detector counts ports; the alert rule applies the scan limit."""
    con = connections_db(syn_rows(ports, ports))
    assert int(detect_port_scan_and_syn_flood(con).iloc[0]["unique_ports"]) == ports
    assert ("port_scan" in set(build_alerts(con, enrich=False)["detection_type"])) is expected


@pytest.mark.parametrize("count,expected", [
    (FLOOD_MIN_SYNS - 1, False),
    (FLOOD_MIN_SYNS, False),
    (FLOOD_MIN_SYNS + 1, True),
])
def test_syn_flood_boundary(connections_db, count, expected):
    """Exactly 50 lone SYNs are below the flood rule; 51 cross it."""
    con = connections_db(syn_rows(count, 1))
    assert ("syn_flood" in set(build_alerts(con, enrich=False)["detection_type"])) is expected


@pytest.mark.parametrize("completed_flows,expected", [
    (0, True), (5, True), (6, False), (60, False),
])
def test_syn_completion_rate(connections_db, completed_flows, expected):
    """ACKs on matching client flows lower the incomplete SYN fraction."""
    rows = [
        {"timestamp": 1_700_000_000 + i * 0.01,
         "ipsrc": "10.0.0.1", "ipdst": "10.0.0.2", "protocol": "TCP",
         "tcpsrc": 40000 + i, "tcpdst": 80, "tcpflags": "S"}
        for i in range(60)
    ]
    rows += [dict(rows[i], tcpflags="A") for i in range(completed_flows)]
    con = connections_db(rows)
    syn = detect_port_scan_and_syn_flood(con).iloc[0]
    assert syn["total_syns"] == 60
    assert syn["incomplete_syns"] == 60 - completed_flows
    assert ("syn_flood" in set(build_alerts(con, enrich=False)["detection_type"])) is expected


def test_unrelated_ack_does_not_complete_syn(connections_db):
    """An ACK on a different source port cannot mask incomplete SYNs."""
    rows = syn_rows(51, 1)
    rows.append({"ipsrc": "10.0.0.1", "ipdst": "10.0.0.2", "protocol": "TCP",
                 "tcpsrc": 9999, "tcpdst": 1000, "tcpflags": "A"})
    con = connections_db(rows)
    assert "syn_flood" in set(build_alerts(con, enrich=False)["detection_type"])


@pytest.mark.parametrize("count,expected", [
    (ICMP_MIN - 1, False), (ICMP_MIN, False), (ICMP_MIN + 1, True),
])
def test_icmp_flood_boundary(connections_db, count, expected):
    """Only echo requests above the current detector threshold are flagged."""
    rows = [{"ipsrc": "10.0.0.3", "protocol": "ICMP", "icmp_type": 8} for _ in range(count)]
    rows.append({"ipsrc": "10.0.0.3", "protocol": "ICMP", "icmp_type": 0})
    con = connections_db(rows)
    assert (not detect_icmp_flood(con).empty) is expected
    assert ("icmp_flood" in set(build_alerts(con, enrich=False)["detection_type"])) is expected


@pytest.mark.parametrize("macs,expected", [(0, False), (1, False), (2, True)])
def test_arp_conflict_boundary(connections_db, macs, expected):
    """One claimed IP is suspicious only when different MACs claim it."""
    rows = [{"protocol": "ARP", "arp_psrc": "10.0.0.4",
             "arp_hwsrc": f"02:00:00:00:00:{i:02x}"} for i in range(macs)]
    con = connections_db(rows)
    assert (not detect_arp_spoofing(con).empty) is expected
    assert ("arp_spoofing" in set(build_alerts(con, enrich=False)["detection_type"])) is expected


def test_arp_probe_is_ignored(connections_db):
    """A host probing with 0.0.0.0 is not an ownership conflict."""
    rows = [{"protocol": "ARP", "arp_psrc": "0.0.0.0", "arp_op": 1,
             "arp_hwsrc": f"02:00:00:00:00:{i:02x}"} for i in (1, 2)]
    con = connections_db(rows)
    assert detect_arp_spoofing(con).empty


def test_arp_conflict_details_and_victim(connections_db):
    """A same-window conflict names both MACs and the claimed IP."""
    macs = ("02:00:00:00:00:01", "02:00:00:00:00:02")
    rows = [{"timestamp": 1000 + i, "protocol": "ARP", "arp_op": 2,
             "arp_psrc": "10.0.0.4", "arp_hwsrc": mac}
            for i, mac in enumerate(macs)]
    con = connections_db(rows)
    alert = build_alerts(con, enrich=False).iloc[0]
    assert alert["ipdst"] == "10.0.0.4"
    assert "10.0.0.4" in alert["details"]
    assert all(mac in alert["details"] for mac in macs)


def test_arp_mac_change_in_different_windows_is_not_conflict(connections_db):
    """A later address change must not combine MACs across windows."""
    rows = [{"timestamp": 1000 + i * 120, "protocol": "ARP", "arp_op": 2,
             "arp_psrc": "10.0.0.4", "arp_hwsrc": f"02:00:00:00:00:{i:02x}"}
            for i in (1, 2)]
    con = connections_db(rows)
    assert detect_arp_spoofing(con).empty


@pytest.mark.parametrize("size,expected", [
    (DNS_MIN_SIZE - 1, False), (DNS_MIN_SIZE, False), (DNS_MIN_SIZE + 1, True),
])
def test_dns_size_boundary(connections_db, size, expected):
    """Large packets with a long label cross the size cutoff at 101."""
    con = connections_db([
        {"ipsrc": "10.0.0.5", "protocol": "UDP", "udpdst": 53,
         "dns_qname": "x" * 45 + ".example.test", "packet_length": size},
        {"ipsrc": "10.0.0.5", "protocol": "UDP", "udpdst": 123, "packet_length": 200},
    ])
    assert (not detect_dns_tunneling(con).empty) is expected
    assert ("dns_tunneling" in set(build_alerts(con, enrich=False)["detection_type"])) is expected


def test_large_repeated_legitimate_dns_is_not_flagged(connections_db):
    """Size alone no longer flags the noisy-normal DNS scenario."""
    rows = [{"timestamp": 1000 + i, "ipsrc": "10.0.0.203", "protocol": "UDP",
             "udpdst": 53, "packet_length": 150,
             "dns_qname": "large-legitimate.example.test"} for i in range(3)]
    con = connections_db(rows)
    assert detect_dns_tunneling(con).empty


def test_distinct_subdomains_can_flag_large_dns(connections_db):
    """Several short unique labels to one base domain count within a window."""
    rows = [{"timestamp": 1000 + i, "ipsrc": "10.0.0.88", "protocol": "UDP",
             "udpdst": 53, "packet_length": 150,
             "dns_qname": f"sub{i}.example.test"} for i in range(5)]
    con = connections_db(rows)
    assert len(detect_dns_tunneling(con)) == 5


def test_dns_allowlist_overrides_suspicious_name(connections_db, monkeypatch):
    """Optional allowlist suppresses a known noisy base domain."""
    monkeypatch.setenv("DNS_ALLOWLIST", "example.test")
    con = connections_db([{"ipsrc": "10.0.0.88", "protocol": "UDP", "udpdst": 53,
                           "packet_length": 150,
                           "dns_qname": "x" * 45 + ".example.test"}])
    assert detect_dns_tunneling(con).empty


@pytest.mark.parametrize("flags,expected", [("S", False), ("F", False), ("FS", True)])
def test_malformed_flags(connections_db, flags, expected):
    """Both SYN and FIN bits must occur in the same TCP packet."""
    con = connections_db([{"ipsrc": "10.0.0.6", "protocol": "TCP", "tcpflags": flags}])
    assert (not detect_malformed_flags(con).empty) is expected
    assert ("malformed_flags" in set(build_alerts(con, enrich=False)["detection_type"])) is expected
