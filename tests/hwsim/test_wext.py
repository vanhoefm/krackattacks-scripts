#!/usr/bin/python
#
# Deprecated WEXT driver interface in wpa_supplicant
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os

import hostapd
import hwsim_utils
from wpasupplicant import WpaSupplicant

# It did not look like open mode association completed with WEXT.. Commenting
# this test case out for now. If you care about WEXT, feel free to fix it and
# submit a patch to remove the "REMOVED_" prefix here..
def REMOVED_test_wext_open(dev, apdev):
    """WEXT driver interface with open network"""
    if not os.path.exists("/proc/net/wireless"):
        logger.info("WEXT support not included in the kernel")
        return "skip"

    params = { "ssid": "wext-open" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    try:
        wpas.interface_add("wlan5", driver="wext")
    except Exception, e:
        logger.info("WEXT driver support not included in wpa_supplicant")
        return "skip"

    wpas.connect("wext-open", key_mgmt="NONE")
    hwsim_utils.test_connectivity(wpas.ifname, apdev[0]['ifname'])

def test_wext_wpa2_psk(dev, apdev):
    """WEXT driver interface with WPA2-PSK"""
    if not os.path.exists("/proc/net/wireless"):
        logger.info("WEXT support not included in the kernel")
        return "skip"

    params = hostapd.wpa2_params(ssid="wext-wpa2-psk", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    try:
        wpas.interface_add("wlan5", driver="wext")
    except Exception, e:
        logger.info("WEXT driver support not included in wpa_supplicant")
        return "skip"

    wpas.connect("wext-wpa2-psk", psk="12345678")
    hwsim_utils.test_connectivity(wpas.ifname, apdev[0]['ifname'])
