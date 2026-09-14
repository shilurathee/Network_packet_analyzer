from scapy.all import rdpcap, IP, TCP, UDP, ARP, ICMP
import pandas as pd

def process_pcap(filename):
    packets = rdpcap(filename)

    ipsrc, ipdst = [], []
    tcpsrc, tcpdst, tcpflags = [], [], []
    udpsrc, udpdst = [], []
    icmp_type = []
    arp_hwsrc, arp_psrc, arp_hwdst, arp_pdst = [], [], [], []
    timestamp = []
    packet_length = []
    protocol = []

    for packet in packets:
        packet_length.append(len(packet))
        timestamp.append(packet.time)

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
            arp_hwsrc.append(packet[ARP].hwsrc)
            arp_psrc.append(packet[ARP].psrc)
            arp_hwdst.append(packet[ARP].hwdst)
            arp_pdst.append(packet[ARP].pdst)
        else:
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
    }

    dataframe = pd.DataFrame(dictionary)
    dataframe.to_csv("data.csv",index=False)
    return dataframe


if __name__ == "__main__":
    df = process_pcap("sample_pcap.pcap")
    #print(df)