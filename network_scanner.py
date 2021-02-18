#!/bin/usr/env python3

import scapy.all as scapy

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP/IP range.")
    (options, arguments) = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)                    #store IP in arp_request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    #store Ether in broadcast
    arp_request_broadcast = broadcast/arp_request       #combine both

    #.srp (send and recv) sends packets with cust Ether
    #[0] to only give us the first list which is answered packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #verbose=False hides everything but results
 
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc} 
        clients_list.append(client_dict)
    return(clients_list)

def print_results(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


#scan modem ip
scan_result = scan("192.168.1.1/24")
print_results(scan_result)
