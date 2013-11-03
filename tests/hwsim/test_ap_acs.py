#!/usr/bin/python
#
# Test cases for automatic channel selection with hostapd
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd

def wait_acs(hapd):
    ev = hapd.wait_event(["ACS-STARTED", "ACS-COMPLETED", "ACS-FAILED",
                          "AP-ENABLED"], timeout=5)
    if not ev:
        raise Exception("ACS start timed out")
    if "ACS-STARTED" not in ev:
        raise Exception("Unexpected ACS event")

    state = hapd.get_status_field("state")
    if state != "ACS":
        raise Exception("Unexpected interface state")

    ev = hapd.wait_event(["ACS-COMPLETED", "ACS-FAILED", "AP-ENABLED"],
                         timeout=20)
    if not ev:
        raise Exception("ACS timed out")
    if "ACS-COMPLETED" not in ev:
        raise Exception("Unexpected ACS event")

    ev = hapd.wait_event(["AP-ENABLED"], timeout=5)
    if not ev:
        raise Exception("AP setup timed out")

    state = hapd.get_status_field("state")
    if state != "ENABLED":
        raise Exception("Unexpected interface state")

def test_ap_acs(dev, apdev):
    """Automatic channel selection"""
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

def test_ap_multi_bss_acs(dev, apdev):
    """hostapd start with a multi-BSS configuration file using ACS"""
    ifname = apdev[0]['ifname']
    hostapd.add_iface(ifname, 'multi-bss-acs.conf')
    hapd = hostapd.Hostapd(ifname)
    hapd.enable()
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    dev[0].connect("bss-1", key_mgmt="NONE", scan_freq=freq)
    dev[1].connect("bss-2", psk="12345678", scan_freq=freq)
    dev[2].connect("bss-3", psk="qwertyuiop", scan_freq=freq)
