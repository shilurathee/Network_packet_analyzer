"""Guard deterministic offline PCAP generation against host MAC lookups.

Inputs are seeded synthetic packets; outputs are explicit Ethernet fields
and identical PCAP bytes across runs, without external network calls.
"""

from scapy.all import ARP, IP, Ether, wrpcap

from tools.generate_traffic import _mac_for_ip, generate


def test_every_packet_has_explicit_ethernet_addresses():
    """An unset dst would make Scapy try ARP resolution when writing."""
    packets, _ = generate(seed=42, normal_packets=100, handshakes=5, noisy=True)
    for packet in packets:
        assert packet.haslayer(Ether)
        assert packet[Ether].getfieldval("src") is not None
        assert packet[Ether].getfieldval("dst") is not None
        assert packet[Ether].getfieldval("dst") != "ff:ff:ff:ff:ff:ff"
        destination = packet[IP].dst if packet.haslayer(IP) else packet[ARP].pdst
        assert packet[Ether].getfieldval("dst") == _mac_for_ip(42, destination)
        if packet.haslayer(IP):
            assert packet[Ether].getfieldval("src") == _mac_for_ip(42, packet[IP].src)
        else:
            assert packet[Ether].getfieldval("src") == packet[ARP].hwsrc


def test_same_seed_writes_identical_pcap_bytes(tmp_path):
    """Stable fields and timestamps give byte-for-byte reproducibility."""
    first, truth_a = generate(seed=17, normal_packets=100, handshakes=5, noisy=True)
    second, truth_b = generate(seed=17, normal_packets=100, handshakes=5, noisy=True)
    path_a, path_b = tmp_path / "first.pcap", tmp_path / "second.pcap"
    wrpcap(str(path_a), first)
    wrpcap(str(path_b), second)
    assert path_a.read_bytes() == path_b.read_bytes()
    assert truth_a == truth_b
