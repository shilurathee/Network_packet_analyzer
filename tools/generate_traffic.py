"""Generate a seeded synthetic PCAP and IP-level ground truth for evaluation.

Inputs: --seed, --packets (normal packet count), --normal-handshakes,
--noisy-normal, --output. Outputs: a PCAP and adjacent ground_truth.json.
No packets are transmitted or captured from a network.
"""

import argparse
import hashlib
import json
import random
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap


def _mac_for_ip(seed, ip, variant=0):
    """Map a seeded IP and variant to a fixed, locally administered MAC."""
    digest = hashlib.sha256(f"{seed}:{ip}:{variant}".encode("ascii")).digest()
    return "02:" + ":".join(f"{octet:02x}" for octet in digest[:5])


def generate(seed, normal_packets, handshakes, noisy):
    """Return packets and labels; fixed IPs keep evaluation easy to explain."""
    rng = random.Random(seed)
    packets = []
    labels = []

    def add(packet):
        # Set both Ethernet addresses before serialization: Scapy must never
        # ask the host to resolve a destination MAC, even for ARP frames.
        if packet.haslayer(IP):
            source, destination = packet[IP].src, packet[IP].dst
            packet[Ether].src = _mac_for_ip(seed, source)
        else:
            source, destination = packet[ARP].psrc, packet[ARP].pdst
            packet[Ether].src = packet[ARP].hwsrc
        packet[Ether].dst = _mac_for_ip(seed, destination)
        packet.time = 1_700_000_000 + len(packets) * 0.01
        packets.append(packet)

    if normal_packets < 3 * handshakes:
        raise ValueError("--packets must be at least 3 * --normal-handshakes")
    for i in range(handshakes):
        port = rng.randrange(2000, 65000)
        src = f"10.1.{i % 200}.10"
        dst = "10.2.0.1"
        add(Ether() / IP(src=src, dst=dst) / TCP(sport=port, dport=443, flags="S"))
        add(Ether() / IP(src=dst, dst=src) / TCP(sport=443, dport=port, flags="SA"))
        add(Ether() / IP(src=src, dst=dst) / TCP(sport=port, dport=443, flags="A"))
    while len(packets) < normal_packets:
        i = len(packets)
        add(Ether() / IP(src=f"10.3.{i % 200}.20", dst="10.2.0.1")
            / UDP(sport=2000 + i % 1000, dport=123) / Raw(load=b"normal"))

    def attack(ip, kind, items):
        start = len(packets)
        for packet in items:
            add(packet)
        labels.append({"ip": ip, "attack_type": kind, "start": float(packets[start].time),
                       "end": float(packets[-1].time), "packet_count": len(packets) - start})

    attack("10.0.0.66", "syn_flood", [Ether() / IP(src="10.0.0.66", dst="10.2.0.1")
           / TCP(dport=80, flags="S") for _ in range(51)])
    attack("10.0.0.99", "port_scan", [Ether() / IP(src="10.0.0.99", dst="10.2.0.1")
           / TCP(dport=1000 + i, flags="S") for i in range(10)])
    attack("10.0.0.77", "icmp_flood", [Ether() / IP(src="10.0.0.77", dst="10.2.0.1")
           / ICMP(type=8) for _ in range(21)])
    attack("10.0.0.1", "arp_spoofing", [Ether() / ARP(psrc="10.0.0.1",
           pdst="10.2.0.1", hwsrc=_mac_for_ip(seed, "10.0.0.1", i)) for i in (1, 2)])
    attack("10.0.0.88", "dns_tunneling", [Ether() / IP(src="10.0.0.88", dst="10.2.0.1")
           / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=("x" * 50 + ".example.test")))
           / Raw(load=b"x" * 90) for _ in range(3)])
    attack("10.0.0.55", "malformed_flags", [Ether() / IP(src="10.0.0.55", dst="10.2.0.1")
           / TCP(dport=80, flags="FS")])

    if noisy:
        # Legitimate but suspicious-looking: any resulting alerts are false positives.
        for i in range(25):
            add(Ether() / IP(src="10.0.0.201", dst=f"10.2.0.{i + 1}") / ICMP(type=8))
        for i in range(12):
            add(Ether() / IP(src="10.0.0.202", dst="10.2.0.1")
                / TCP(sport=30000 + i, dport=2000 + i, flags="S"))
        for _ in range(3):
            add(Ether() / IP(src="10.0.0.203", dst="10.2.0.1") / UDP(dport=53)
                / DNS(rd=1, qd=DNSQR(qname="large-legitimate.example.test"))
                / Raw(load=b"z" * 90))
    return packets, {"seed": seed, "normal_packets": normal_packets,
                     "noisy_normal": noisy, "attackers": labels}


def main():
    """Write the PCAP and JSON sidecar without contacting any host."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--packets", type=int, default=1000, help="Normal packet count")
    parser.add_argument("--normal-handshakes", type=int, default=50)
    parser.add_argument("--noisy-normal", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("generated_traffic.pcap"))
    args = parser.parse_args()
    packets, truth = generate(args.seed, args.packets, args.normal_handshakes, args.noisy_normal)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.output), packets)
    sidecar = args.output.with_name("ground_truth.json")
    sidecar.write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(packets)} packets to {args.output}; labels to {sidecar}")


if __name__ == "__main__":
    main()
