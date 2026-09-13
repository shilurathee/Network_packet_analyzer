
print("i am scapy processor")
def process_pcap(filename):
    from scapy.all import rdpcap,IP,TCP,UDP,sniff
    import pandas as pd

    packets=rdpcap(filename)
    #packets.summary()

    ipsrc=[]
    ipdst=[]
    tcpsrc=[]
    tcpdst=[]
    udpsrc=[]
    udpdst=[]
    timestamp=[]
   
    for packet in packets:
        if packet.haslayer(IP):
            ipsrc.append(packet[IP].src)
            ipdst.append(packet[IP].dst)
        else : 
            ipsrc.append(None)
            ipdst.append(None)
    
        if packet.haslayer(TCP):
            tcpsrc.append(packet[TCP].sport)
            tcpdst.append(packet[TCP].dport)
        else : 
            tcpsrc.append(None)
            tcpdst.append(None)
        if packet.haslayer(UDP):
            udpsrc.append(packet[UDP].sport)
            udpdst.append(packet[UDP].dport)
        else:
            udpsrc.append(None)
            udpdst.append(None)
        timestamp.append(packet.time)

    dictionary={
        "ipsrc": ipsrc,
        "ipdst": ipdst,
        "tcpsrc": tcpsrc,
        "tcpdst": tcpdst,
        "udpsrc": udpsrc,
        "udpdst": udpdst,
        "timestamp": timestamp  
        }

    #print(dictionary)
    dataframe=pd.DataFrame(dictionary)
    dataframe.to_csv("dic.csv",index=False)
    #print(type(dic.csv))
    return "dic.csv"