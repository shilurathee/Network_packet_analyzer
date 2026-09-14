print("i am main")

def scan_scapy(filename):
    from scapy_scan import process_pcap
    return_file=process_pcap(filename)
    print(return_file)
    #print(type(return_file))
    return return_file


def database(dataframe):
    from database import resolve
    resolve(dataframe)


    
def main():
    dataframe=scan_scapy("sample_pcap.pcap")
    database(dataframe)







if __name__=="__main__":
    main()



    