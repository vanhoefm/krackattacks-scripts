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
logger = logging.getLogger(__name__)

import hwsim_utils
import hostapd

ap_ifname = 'wlan2'
bssid = "02:00:00:00:02:00"
ap2_ifname = 'wlan3'
bssid2 = "02:00:00:00:03:00"

def test_ap_roam_open(dev):
    """Roam between two open APs"""
    hostapd.add_ap(ap_ifname, { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE")
    hwsim_utils.test_connectivity(dev[0].ifname, ap_ifname)
    hostapd.add_ap(ap2_ifname, { "ssid": "test-open" })
    dev[0].scan(type="ONLY")
    dev[0].roam(bssid2)
    hwsim_utils.test_connectivity(dev[0].ifname, ap2_ifname)
    dev[0].roam(bssid)
    hwsim_utils.test_connectivity(dev[0].ifname, ap_ifname)

def test_ap_roam_wpa2_psk(dev):
    """Roam between two WPA2-PSK APs"""
    params = hostapd.wpa2_params(ssid="test-wpa2-psk", passphrase="12345678")
    hostapd.add_ap(ap_ifname, params)
    dev[0].connect("test-wpa2-psk", psk="12345678")
    hwsim_utils.test_connectivity(dev[0].ifname, ap_ifname)
    hostapd.add_ap(ap2_ifname, params)
    dev[0].scan(type="ONLY")
    dev[0].roam(bssid2)
    hwsim_utils.test_connectivity(dev[0].ifname, ap2_ifname)
    dev[0].roam(bssid)
    hwsim_utils.test_connectivity(dev[0].ifname, ap_ifname)
