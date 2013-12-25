#!/usr/bin/python
#
# Cipher suite tests
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

def check_cipher(dev, ap, cipher):
    if cipher not in dev.get_capability("pairwise"):
        return "skip"
    params = { "ssid": "test-wpa2-psk",
               "wpa_passphrase": "12345678",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": cipher }
    hostapd.add_ap(ap['ifname'], params)
    dev.connect("test-wpa2-psk", psk="12345678",
                pairwise=cipher, group=cipher)
    hwsim_utils.test_connectivity(dev.ifname, ap['ifname'])

def test_ap_cipher_tkip(dev, apdev):
    """WPA2-PSK/TKIP connection"""
    check_cipher(dev[0], apdev[0], "TKIP")

def test_ap_cipher_ccmp(dev, apdev):
    """WPA2-PSK/CCMP connection"""
    check_cipher(dev[0], apdev[0], "CCMP")

def test_ap_cipher_gcmp(dev, apdev):
    """WPA2-PSK/GCMP connection"""
    check_cipher(dev[0], apdev[0], "GCMP")

def test_ap_cipher_ccmp_256(dev, apdev):
    """WPA2-PSK/CCMP-256 connection"""
    check_cipher(dev[0], apdev[0], "CCMP-256")

def test_ap_cipher_gcmp_256(dev, apdev):
    """WPA2-PSK/GCMP-256 connection"""
    check_cipher(dev[0], apdev[0], "GCMP-256")
