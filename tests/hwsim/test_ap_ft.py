#!/usr/bin/python
#
# Fast BSS Transition tests
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
from wlantest import Wlantest

def ft_base_rsn():
    params = { "wpa": "2",
               "wpa_key_mgmt": "FT-PSK",
               "rsn_pairwise": "CCMP" }
    return params

def ft_base_mixed():
    params = { "wpa": "3",
               "wpa_key_mgmt": "WPA-PSK FT-PSK",
               "wpa_pairwise": "TKIP",
               "rsn_pairwise": "CCMP" }
    return params

def ft_params(rsn=True, ssid=None, passphrase=None):
    if rsn:
        params = ft_base_rsn()
    else:
        params = ft_base_mixed()
    if ssid:
        params["ssid"] = ssid
    if passphrase:
        params["wpa_passphrase"] = passphrase

    params["mobility_domain"] = "a1b2"
    params["r0_key_lifetime"] = "10000"
    params["pmk_r1_push"] = "1"
    params["reassociation_deadline"] = "1000"
    return params

def ft_params1(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas1.w1.fi"
    params['r1_key_holder'] = "000102030405"
    params['r0kh'] = [ "02:00:00:00:03:00 nas1.w1.fi 100102030405060708090a0b0c0d0e0f",
                       "02:00:00:00:04:00 nas2.w1.fi 300102030405060708090a0b0c0d0e0f" ]
    params['r1kh'] = "02:00:00:00:04:00 00:01:02:03:04:06 200102030405060708090a0b0c0d0e0f"
    return params

def ft_params2(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas2.w1.fi"
    params['r1_key_holder'] = "000102030406"
    params['r0kh'] = [ "02:00:00:00:03:00 nas1.w1.fi 200102030405060708090a0b0c0d0e0f",
                       "02:00:00:00:04:00 nas2.w1.fi 000102030405060708090a0b0c0d0e0f" ]
    params['r1kh'] = "02:00:00:00:03:00 00:01:02:03:04:05 300102030405060708090a0b0c0d0e0f"
    return params

def run_roams(dev, apdev, ssid, passphrase):
    logger.info("Connect to first AP")
    dev.connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                ieee80211w="1")
    if dev.get_status_field('bssid') == apdev[0]['bssid']:
        ap1 = apdev[0]
        ap2 = apdev[1]
    else:
        ap1 = apdev[1]
        ap2 = apdev[0]
    hwsim_utils.test_connectivity(dev.ifname, ap1['ifname'])

    logger.info("Roam to the second AP")
    dev.roam(ap2['bssid'])
    if dev.get_status_field('bssid') != ap2['bssid']:
        raise Exception("Did not connect to correct AP")
    hwsim_utils.test_connectivity(dev.ifname, ap2['ifname'])

    logger.info("Roam back to the first AP")
    dev.roam(ap1['bssid'])
    if dev.get_status_field('bssid') != ap1['bssid']:
        raise Exception("Did not connect to correct AP")
    hwsim_utils.test_connectivity(dev.ifname, ap1['ifname'])

def test_ap_ft(dev, apdev):
    """WPA2-PSK-FT AP"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, ssid, passphrase)

def test_ap_ft_mixed(dev, apdev):
    """WPA2-PSK-FT mixed-mode AP"""
    ssid = "test-ft-mixed"
    passphrase="12345678"

    params = ft_params1(rsn=False, ssid=ssid, passphrase=passphrase)
    hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(rsn=False, ssid=ssid, passphrase=passphrase)
    hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, ssid, passphrase)

def test_ap_ft_pmf(dev, apdev):
    """WPA2-PSK-FT AP with PMF"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, ssid, passphrase)
