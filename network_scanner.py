#!/bin/usr/env python3

import scapy.all as scapy

#func to scan ip
def scan(ip):
    arp_request = scapy.ARP()
    print(arp_request.summary())
    scapy.ls(scapy.ARP())

#scan modem ip
scan("192.168.1.1/24")
