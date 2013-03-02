#!/usr/bin/python
#
# P2P group formation test
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import sys
import time
import subprocess
import logging

import hwsim_utils
from wpasupplicant import WpaSupplicant


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '-d':
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig()

    dev0 = WpaSupplicant('wlan0')
    dev1 = WpaSupplicant('wlan1')
    dev0.request("hello")
    dev0.ping()
    if not dev0.ping() or not dev1.ping():
        print "No response from wpa_supplicant"
        return
    addr0 = dev0.p2p_dev_addr()
    addr1 = dev1.p2p_dev_addr()
    print "dev0 P2P Device Address: " + addr0
    print "dev1 P2P Device Address: " + addr1
    dev0.reset()
    dev1.reset()

    dev0.p2p_listen()
    dev1.p2p_listen()
    pin = dev0.wps_read_pin()
    dev0.p2p_go_neg_auth(addr1, pin, "display")
    print "Start GO negotiation"
    dev1.p2p_go_neg_init(addr0, pin, "enter", timeout=15)
    dev0.dump_monitor()
    dev1.dump_monitor()
    print "Group formed"

    hwsim_utils.test_connectivity('wlan0', 'wlan1')

    dev0.remove_group('wlan0')
    try:
        dev1.remove_group('wlan1')
    except:
        pass

    print "Test passed"

if __name__ == "__main__":
    main()
