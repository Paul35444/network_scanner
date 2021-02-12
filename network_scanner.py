#!/bin/usr/env python3

import scapy.all as scapy

#func to scan ip
def scan(ip):
    scapy.arping(ip)

