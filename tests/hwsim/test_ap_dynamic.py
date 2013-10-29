#!/usr/bin/python
#
# Test cases for dynamic BSS changes with hostapd
# Copyright (c) 2013, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger(__name__)

import hwsim_utils
import hostapd

def test_ap_change_ssid(dev, apdev):
    """Dynamic SSID change with hostapd and WPA2-PSK"""
    params = hostapd.wpa2_params(ssid="test-wpa2-psk-start",
                                 passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)
    id = dev[0].connect("test-wpa2-psk-start", psk="12345678")
    dev[0].request("DISCONNECT")

    logger.info("Change SSID dynamically")
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    res = hapd.request("SET ssid test-wpa2-psk-new")
    if "OK" not in res:
        raise Exception("SET command failed")
    res = hapd.request("RELOAD")
    if "OK" not in res:
        raise Exception("RELOAD command failed")

    dev[0].set_network_quoted(id, "ssid", "test-wpa2-psk-new")
    dev[0].connect_network(id)
