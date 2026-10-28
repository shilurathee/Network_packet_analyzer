"""Exercise all six rules at positive, negative and threshold boundaries.

Rows use the real connections schema. Tests call detector.py and alerts.py
without changing production thresholds or making network requests.
"""

from inspect import signature

import pytest

from alerts import FLOOD_MIN_SYNS, SCAN_MIN_PORTS, build_alerts
from detector import (
    detect_arp_spoofing,
    detect_dns_tunneling,
    detect_icmp_flood,
    detect_malformed_flags,
    detect_port_scan_and_syn_flood,
)

ICMP_MIN = signature(detect_icmp_flood).parameters["threshold"].default
DNS_MIN_SIZE = signature(detect_dns_tunneling).parameters["size_threshold"].default


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


@pytest.mark.parametrize("size,expected", [
    (DNS_MIN_SIZE - 1, False), (DNS_MIN_SIZE, False), (DNS_MIN_SIZE + 1, True),
])
def test_dns_size_boundary(connections_db, size, expected):
    """Only UDP destination 53 packets over 100 bytes qualify."""
    con = connections_db([
        {"ipsrc": "10.0.0.5", "protocol": "UDP", "udpdst": 53, "packet_length": size},
        {"ipsrc": "10.0.0.5", "protocol": "UDP", "udpdst": 123, "packet_length": 200},
    ])
    assert (not detect_dns_tunneling(con).empty) is expected
    assert ("dns_tunneling" in set(build_alerts(con, enrich=False)["detection_type"])) is expected


@pytest.mark.parametrize("flags,expected", [("S", False), ("F", False), ("FS", True)])
def test_malformed_flags(connections_db, flags, expected):
    """Both SYN and FIN bits must occur in the same TCP packet."""
    con = connections_db([{"ipsrc": "10.0.0.6", "protocol": "TCP", "tcpflags": flags}])
    assert (not detect_malformed_flags(con).empty) is expected
    assert ("malformed_flags" in set(build_alerts(con, enrich=False)["detection_type"])) is expected
