#!/usr/bin/env python

import pyfiglet
import scapy.all as scapy
import optparse




def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help ="Target IP or the IP range")   
    options, argument = parser.parse_args()
    return options

def get_banner():
    banner = pyfiglet.figlet_format("Net scan")
    return banner

def scan(ip):
    arp_request = scapy.ARP(pdst= ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff" )
    arp_request_broadcast = broadcast/arp_request
    answered_list , _ = scapy.srp(arp_request_broadcast, timeout=1)
    return [{"ip":element[1].psrc , "mac": element[1].hwsrc} for element in answered_list]

def print_results(result_list):
    print(f"IP \t\t\t MAC Address\n{ '-' * 42}")
    for element in result_list :
        print(f"{element['ip']} \t\t {element['mac']}")   

       
options = get_argument()

print(get_banner())

clients = scan(options.target)

print_results(clients)

