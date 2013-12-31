#!/usr/bin/python
#
# RADIUS tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

import hostapd

def connect(dev, ssid, wait_connect=True):
    dev.connect(ssid, key_mgmt="WPA-EAP", scan_freq="2412",
                eap="PSK", identity="psk.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef",
                wait_connect=wait_connect)

def test_radius_auth_unreachable(dev, apdev):
    """RADIUS Authentication server unreachable"""
    params = hostapd.wpa2_eap_params(ssid="radius-auth")
    params['auth_server_port'] = "18139"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    connect(dev[0], "radius-auth", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"])
    if ev is None:
        raise Exception("Timeout on EAP start")
    logger.info("Checking for RADIUS retries")
    time.sleep(4)
    mib = hapd.get_mib()
    if "radiusAuthClientAccessRequests" not in mib:
        raise Exception("Missing MIB fields")
    if int(mib["radiusAuthClientAccessRetransmissions"]) < 1:
        raise Exception("Missing RADIUS Authentication retransmission")
    if int(mib["radiusAuthClientPendingRequests"]) < 1:
        raise Exception("Missing pending RADIUS Authentication request")

def test_radius_acct_unreachable(dev, apdev):
    """RADIUS Accounting server unreachable"""
    params = hostapd.wpa2_eap_params(ssid="radius-acct")
    params['acct_server_addr'] = "127.0.0.1"
    params['acct_server_port'] = "18139"
    params['acct_server_shared_secret'] = "radius"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    connect(dev[0], "radius-acct")
    logger.info("Checking for RADIUS retries")
    time.sleep(4)
    mib = hapd.get_mib()
    if "radiusAccClientRetransmissions" not in mib:
        raise Exception("Missing MIB fields")
    if int(mib["radiusAccClientRetransmissions"]) < 2:
        raise Exception("Missing RADIUS Accounting retransmissions")
    if int(mib["radiusAccClientPendingRequests"]) < 2:
        raise Exception("Missing pending RADIUS Accounting requests")
