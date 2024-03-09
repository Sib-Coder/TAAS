from scapy.all import *

dnsmas=[] #пулл dns имён
witedns=["github.githubassets.com.","github.com"]


# Функция-обработчик, которая будет вызываться для каждого захваченного пакета
def packet_handler(packet):
    if packet.haslayer(DNS):
        # Вывод информации о пакете DNS
        print("DNS Request:")        
        for qname in packet[DNS].qd:
            print( qname.qname.decode()[:-1])
            dnsmas.append(qname.qname.decode()[:-1])
            add_domains_to_hosts(dnsmas,"10.10.0.105") #!!!!!!!!!!Напиши НУЖНЫЙ IP
        print("_____________________________________")
    

def add_domains_to_hosts(domains, ip_address):
    with open('//etc/hosts', 'a') as hosts_file:
        for domain in domains:
            if domain in witedns:
                continue
            else:
                hosts_file.write(f"{ip_address}\t{domain}\n")


def main():
    # Захват пакетов с интерфейса 'eth0' и передача их на обработку функции packet_handler
    sniff(iface='wlp2s0', filter="udp port 53", prn=packet_handler)
    #add_domains_to_hosts(dnsmas, "127.0.0.1")

if __name__=="__main__":
    main()
   
