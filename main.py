print("i am main")

class Solution:
    def __init__(self):
        pass
    def scan_scapy(self,filename):
        from scapy_scan import process_pcap
        return_file=process_pcap(filename)
        with open(return_file,"r") as f:
            data=f.read()
        print(data)

if __name__=="__main__":
    a=Solution()
    a.scan_scapy("sample_pcap.pcap")

    