#!/usr/bin/python
#
# WEP tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
import hwsim_utils

def test_wep_open_auth(dev, apdev):
    """WEP Open System authentication"""
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": "wep-open",
                     "wep_key0": '"hello"' })
    dev[0].connect("wep-open", key_mgmt="NONE", wep_key0='"hello"',
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_wep_shared_key_auth(dev, apdev):
    """WEP Shared Key authentication"""
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": "wep-shared-key",
                     "wep_key0": '"hello12345678"',
                     "auth_algs": "2" })
    dev[0].connect("wep-shared-key", key_mgmt="NONE", auth_alg="SHARED",
                   wep_key0='"hello12345678"',
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    dev[1].connect("wep-shared-key", key_mgmt="NONE", auth_alg="OPEN SHARED",
                   wep_key0='"hello12345678"',
                   scan_freq="2412")

def test_wep_shared_key_auth_not_allowed(dev, apdev):
    """WEP Shared Key authentication not allowed"""
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": "wep-shared-key",
                     "wep_key0": '"hello12345678"',
                     "auth_algs": "1" })
    dev[0].connect("wep-shared-key", key_mgmt="NONE", auth_alg="SHARED",
                   wep_key0='"hello12345678"',
                   scan_freq="2412", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected association")
