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
                pairwise=cipher, group=cipher, scan_freq="2412")
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

def test_ap_cipher_mixed_wpa_wpa2(dev, apdev):
    """WPA2-PSK/CCMP/ and WPA-PSK/TKIP mixed configuration"""
    ssid = "test-wpa-wpa2-psk"
    passphrase = "12345678"
    params = { "ssid": ssid,
               "wpa_passphrase": passphrase,
               "wpa": "3",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": "CCMP",
               "wpa_pairwise": "TKIP" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, proto="WPA2",
                   pairwise="CCMP", group="TKIP", scan_freq="2412")
    status = dev[0].get_status()
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Incorrect key_mgmt reported")
    if status['pairwise_cipher'] != 'CCMP':
        raise Exception("Incorrect pairwise_cipher reported")
    if status['group_cipher'] != 'TKIP':
        raise Exception("Incorrect group_cipher reported")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if bss['ssid'] != ssid:
        raise Exception("Unexpected SSID in the BSS entry")
    if "[WPA-PSK-TKIP]" not in bss['flags']:
        raise Exception("Missing BSS flag WPA-PSK-TKIP")
    if "[WPA2-PSK-CCMP]" not in bss['flags']:
        raise Exception("Missing BSS flag WPA2-PSK-CCMP")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

    dev[1].connect(ssid, psk=passphrase, proto="WPA",
                   pairwise="TKIP", group="TKIP", scan_freq="2412")
    status = dev[1].get_status()
    if status['key_mgmt'] != 'WPA-PSK':
        raise Exception("Incorrect key_mgmt reported")
    if status['pairwise_cipher'] != 'TKIP':
        raise Exception("Incorrect pairwise_cipher reported")
    if status['group_cipher'] != 'TKIP':
        raise Exception("Incorrect group_cipher reported")
    hwsim_utils.test_connectivity(dev[1].ifname, apdev[0]['ifname'])
    hwsim_utils.test_connectivity(dev[0].ifname, dev[1].ifname)
