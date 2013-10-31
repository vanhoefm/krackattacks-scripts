#!/usr/bin/python
#
# Roaming tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd

def test_ap_roam_open(dev, apdev):
    """Roam between two open APs"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    hostapd.add_ap(apdev[1]['ifname'], { "ssid": "test-open" })
    dev[0].scan(type="ONLY")
    dev[0].roam(apdev[1]['bssid'])
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[1]['ifname'])
    dev[0].roam(apdev[0]['bssid'])
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_roam_wpa2_psk(dev, apdev):
    """Roam between two WPA2-PSK APs"""
    params = hostapd.wpa2_params(ssid="test-wpa2-psk", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-psk", psk="12345678")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    hostapd.add_ap(apdev[1]['ifname'], params)
    dev[0].scan(type="ONLY")
    dev[0].roam(apdev[1]['bssid'])
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[1]['ifname'])
    dev[0].roam(apdev[0]['bssid'])
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
