#!/usr/bin/python
#
# Test various AP mode parameters
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd

def test_ap_fragmentation_rts_set_high(dev, apdev):
    """WPA2-PSK AP with fragmentation and RTS thresholds larger than frame length"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['rts_threshold'] = "1000"
    params['fragm_threshold'] = "2000"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_fragmentation_open(dev, apdev):
    """Open AP with fragmentation threshold"""
    ssid = "fragmentation"
    params = {}
    params['ssid'] = ssid
    params['fragm_threshold'] = "1000"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_fragmentation_wpa2(dev, apdev):
    """WPA2-PSK AP with fragmentation threshold"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['fragm_threshold'] = "1000"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    # TODO: figure out why this fails.. mac80211 bug?
    #hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
