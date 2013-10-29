#!/usr/bin/python
#
# Test cases for AP VLAN
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger(__name__)

import hwsim_utils
import hostapd

def test_ap_vlan_open(dev, apdev):
    """AP VLAN with open network"""
    params = { "ssid": "test-vlan-open",
               "dynamic_vlan": "1",
               "accept_mac_file": "hostapd.accept" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[1].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[2].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, "brvlan1")
    hwsim_utils.test_connectivity(dev[1].ifname, "brvlan2")
    hwsim_utils.test_connectivity(dev[2].ifname, apdev[0]['ifname'])

def test_ap_vlan_wpa2(dev, apdev):
    """AP VLAN with WPA2-PSK"""
    params = hostapd.wpa2_params(ssid="test-vlan",
                                 passphrase="12345678")
    params['dynamic_vlan'] = "1";
    params['accept_mac_file'] = "hostapd.accept";
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan", psk="12345678", scan_freq="2412")
    dev[1].connect("test-vlan", psk="12345678", scan_freq="2412")
    dev[2].connect("test-vlan", psk="12345678", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, "brvlan1")
    hwsim_utils.test_connectivity(dev[1].ifname, "brvlan2")
    hwsim_utils.test_connectivity(dev[2].ifname, apdev[0]['ifname'])
