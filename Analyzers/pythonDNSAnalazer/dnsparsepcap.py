from scapy.all import *
dnsmas=[]

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    
    for packet in packets:
        if DNS in packet:
            dns_packet = packet[DNS]
            try: 
                if dns_packet.qd.qname is not None:
                    dnsmas.append(dns_packet.qd.qname.decode())
            except:
                 continue


def add_domains_to_hosts(domains, ip_address):
    with open('hosts', 'a') as hosts_file:
        for domain in domains:
            if domain == "github.githubassets.com.":
                continue
            else:
                hosts_file.write(f"{ip_address}\t{domain[:-1]}\n")


def main():
    pcap_file = "test.pcapng"
    analyze_pcap(pcap_file)
    dnsNamesUnic= set(dnsmas)
    print(dnsNamesUnic)
    add_domains_to_hosts(dnsNamesUnic, "10.10.0.105")


if __name__=="__main__":
    main()
