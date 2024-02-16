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
