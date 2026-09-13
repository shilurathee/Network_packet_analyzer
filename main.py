print("i am main")

def scan_scapy(filename):
    from scapy_scan import process_pcap
    return_file=process_pcap(filename)
    with open(return_file,"r") as f:
        data=f.read()
    print(data) #works fine till here



def show():
    from stream import stream_function
    stream_function()
    
def main():
    scan_scapy("sample_pcap.pcap")







if __name__=="__main__":
    main()



    