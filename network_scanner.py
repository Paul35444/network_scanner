#!/bin/usr/env python3

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)                    #store IP in arp_request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    #store Ether in broadcast
    arp_request_broadcast = broadcast/arp_request       #combine both

    #.srp (send and recv) sends packets with cust Ether
    #[0] to only give us the first list which is answered packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #verbose=False hides everything but results

    for element in answered_list:
        print(element[1].psrc)  #psrc: source IP who sent packet
        print(element[1].hwsrc) #hwsrc: MAC add of client who sent packet
        print("--------------------------------------------------------------------------------------------------------")

#scan modem ip
scan("192.168.1.1/24")
