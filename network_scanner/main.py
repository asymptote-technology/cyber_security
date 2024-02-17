#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import argparse


def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("--------------------------------------------")
    print("IP\t\t\tMAC Address\n--------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range")
    _options = parser.parse_args()
    if not _options.target:
        parser.error("[-] Please specify an IP Address. Use --help for more info.")
    return _options


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

# --target 192.168.42.2/24

