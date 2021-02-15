#!/bin/usr/env python3

import scapy.all as scapy

#func to scan ip
def scan(ip):
    #store IP in arp_request
    arp_request = scapy.ARP(pdst=ip)
    #store Ether in broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #combine both
    arp_request_broadcast = broadcast/arp_request

    #.srp sends packets with cust Ether
    answered, unanswered = scapy.srp(arp_request_broadcast)

#scan modem ip
scan("192.168.1.1/24")
