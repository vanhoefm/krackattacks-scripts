#!/usr/bin/python
#
# cfg80211 connect command (SME in the driver/firmware)
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

def test_connect_cmd_open(dev, apdev):
    """Open connection using cfg80211 connect command"""
    params = { "ssid": "sta-connect" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", key_mgmt="NONE", scan_freq="2412")
    wpas.request("DISCONNECT")

def test_connect_cmd_wpa2_psk(dev, apdev):
    """WPA2-PSK connection using cfg80211 connect command"""
    params = hostapd.wpa2_params(ssid="sta-connect", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", psk="12345678", scan_freq="2412")
    wpas.request("DISCONNECT")
