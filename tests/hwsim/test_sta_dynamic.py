#!/usr/bin/python
#
# Dynamic wpa_supplicant interface
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant

def test_sta_dynamic(dev, apdev):
    """Dynamically added wpa_supplicant interface"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)

    logger.info("Create a dynamic wpa_supplicant interface and connect")
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")

    wpas.connect("sta-dynamic", psk="12345678", scan_freq="2412")
