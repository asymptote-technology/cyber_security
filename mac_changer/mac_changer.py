#!/usr/bin/env python

import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change this mac address")
    parser.add_option("-m", "--mac", dest="new_mac", help="Newly provided mac address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface. Use --help for more info.")
    if not options.new_mac:
        parser.error("[-] Please specify a new MAC address. Use --help for more info.")
    return options


def change_mac(_interface, _new_mac):
    print("[+] Changing MAC Address for " + _interface + " to " + _new_mac)
    subprocess.call(["ifconfig", _interface, "down"])
    subprocess.call(["ifconfig", _interface, "hw", "ether", _new_mac])
    subprocess.call(["ifconfig", _interface, "up"])


def get_current_mac(_interface):
    ifconfig_result = subprocess.check_output(["ifconfig", _interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC address")


options = get_arguments()

current_mac = get_current_mac(options.interface)
print("CURRENT MAC = " + str(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] The MAC address was successfully changed")
else:
    print("[-] The MAC address was not changed")




