"""
scapy_scan.py — Packet capture and header extraction.

What it does:
  Reads a .pcap (or sniffs live traffic) with Scapy and returns a 16-column
  pandas DataFrame matching the `connections` table contract.

Why it exists:
  Detectors query structured columns, not raw packets. This module is the
  only place that talks to Scapy.

Inputs:  path to a .pcap, or live sniff arguments.
Outputs: DataFrame with timestamp, protocol, packet_length, ipsrc, ipdst,
         tcpsrc, tcpdst, tcpflags, udpsrc, udpdst, icmp_type,
         arp_hwsrc, arp_psrc, arp_hwdst, arp_pdst, arp_op.

Windows: Npcap with AdminOnly=1 requires an Administrator terminal for
`from scapy.all import ...` (even for offline files) and for live sniff.
"""
import time
import pandas as pd
from typing import Optional, List
from scapy.all import rdpcap, sniff, wrpcap, IP, TCP, UDP, ARP, ICMP


def extract_packet_data(packets) -> pd.DataFrame:
    """Extract structured feature vectors from a collection of Scapy packets."""
    ipsrc, ipdst = [], []
    tcpsrc, tcpdst, tcpflags = [], [], []
    udpsrc, udpdst = [], []
    icmp_type = []
    arp_hwsrc, arp_psrc, arp_hwdst, arp_pdst = [], [], [], []
    arp_op = []
    timestamp = []
    packet_length = []
    protocol = []

    for packet in packets:
        packet_length.append(len(packet))
        timestamp.append(float(packet.time) if hasattr(packet, "time") else time.time())

        if packet.haslayer(IP):
            ipsrc.append(packet[IP].src)
            ipdst.append(packet[IP].dst)
        else:
            ipsrc.append(None)
            ipdst.append(None)

        if packet.haslayer(TCP):
            tcpsrc.append(packet[TCP].sport)
            tcpdst.append(packet[TCP].dport)
            tcpflags.append(str(packet[TCP].flags))
        else:
            tcpsrc.append(None)
            tcpdst.append(None)
            tcpflags.append(None)

        if packet.haslayer(UDP):
            udpsrc.append(packet[UDP].sport)
            udpdst.append(packet[UDP].dport)
        else:
            udpsrc.append(None)
            udpdst.append(None)

        if packet.haslayer(ICMP):
            icmp_type.append(packet[ICMP].type)
        else:
            icmp_type.append(None)

        if packet.haslayer(ARP):
            arp_op.append(int(packet[ARP].op))
            arp_hwsrc.append(packet[ARP].hwsrc)
            arp_psrc.append(packet[ARP].psrc)
            arp_hwdst.append(packet[ARP].hwdst)
            arp_pdst.append(packet[ARP].pdst)
        else:
            arp_op.append(None)
            arp_hwsrc.append(None)
            arp_psrc.append(None)
            arp_hwdst.append(None)
            arp_pdst.append(None)

        if packet.haslayer(TCP):
            protocol.append("TCP")
        elif packet.haslayer(UDP):
            protocol.append("UDP")
        elif packet.haslayer(ICMP):
            protocol.append("ICMP")
        elif packet.haslayer(ARP):
            protocol.append("ARP")
        else:
            protocol.append("OTHER")

    dictionary = {
        "timestamp": timestamp,
        "protocol": protocol,
        "packet_length": packet_length,
        "ipsrc": ipsrc,
        "ipdst": ipdst,
        "tcpsrc": tcpsrc,
        "tcpdst": tcpdst,
        "tcpflags": tcpflags,
        "udpsrc": udpsrc,
        "udpdst": udpdst,
        "icmp_type": icmp_type,
        "arp_hwsrc": arp_hwsrc,
        "arp_psrc": arp_psrc,
        "arp_hwdst": arp_hwdst,
        "arp_pdst": arp_pdst,
        "arp_op": arp_op,
    }

    dataframe = pd.DataFrame(dictionary)
    # Explicitly enforce string dtypes so DuckDB never infers INT32 for empty/NULL columns
    for col in ["protocol", "ipsrc", "ipdst", "tcpflags", "arp_hwsrc", "arp_psrc", "arp_hwdst", "arp_pdst"]:
        dataframe[col] = dataframe[col].astype("string")

    return dataframe


def process_pcap(filename: str) -> pd.DataFrame:
    """Read packets from an offline .pcap file and extract feature vectors."""
    print(f"[*] Reading packets from file: '{filename}'...")
    packets = rdpcap(filename)
    return extract_packet_data(packets)


def capture_live_traffic(
    count: int = 100,
    timeout: int = 30,
    iface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    save_pcap_path: Optional[str] = "live_capture.pcap",
) -> pd.DataFrame:
    """
    Capture live network traffic from an interface and extract feature vectors.

    Args:
        count: Number of packets to capture (0 for unlimited until timeout).
        timeout: Stop sniffing after this many seconds.
        iface: Network interface name (optional, Scapy defaults to default interface).
        bpf_filter: Berkeley Packet Filter string (e.g. 'ip or arp').
        save_pcap_path: Optional path to save the captured packets as a .pcap file.
    """
    print(
        f"[*] Starting live traffic capture (count={count}, timeout={timeout}s, iface={iface or 'default'})..."
    )

    sniff_kwargs = {}
    if count and count > 0:
        sniff_kwargs["count"] = count
    if timeout and timeout > 0:
        sniff_kwargs["timeout"] = timeout
    if iface:
        sniff_kwargs["iface"] = iface
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    packets = sniff(**sniff_kwargs)
    print(f"[+] Captured {len(packets)} live packets.")

    if save_pcap_path and len(packets) > 0:
        try:
            wrpcap(save_pcap_path, packets)
            print(f"[+] Saved raw capture to '{save_pcap_path}'.")
        except Exception as e:
            print(f"[!] Could not save pcap to '{save_pcap_path}': {e}")

    return extract_packet_data(packets)


def get_network_interfaces() -> List[str]:
    """Retrieve available network interface names on the host."""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception:
        return []


if __name__ == "__main__":
    df = process_pcap("test_traffic.pcap")
    print(df.describe())
