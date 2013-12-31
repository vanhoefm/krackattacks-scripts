#!/usr/bin/python
#
# IEEE 802.1X tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
import time

import hostapd
import hwsim_utils

logger = logging.getLogger()

def test_ieee8021x_wep104(dev, apdev):
    """IEEE 802.1X connection using dynamic WEP104"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-wep"
    params["ieee8021x"] = "1"
    params["wep_key_len_broadcast"] = "13"
    params["wep_key_len_unicast"] = "13"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("ieee8021x-wep", key_mgmt="IEEE8021X", eap="PSK",
                   identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ieee8021x_wep40(dev, apdev):
    """IEEE 802.1X connection using dynamic WEP40"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-wep"
    params["ieee8021x"] = "1"
    params["wep_key_len_broadcast"] = "5"
    params["wep_key_len_unicast"] = "5"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("ieee8021x-wep", key_mgmt="IEEE8021X", eap="PSK",
                   identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ieee8021x_open(dev, apdev):
    """IEEE 802.1X connection using open network"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-open"
    params["ieee8021x"] = "1"
    hostapd.add_ap(apdev[0]['ifname'], params)

    id = dev[0].connect("ieee8021x-open", key_mgmt="IEEE8021X", eapol_flags="0",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

    logger.info("Test EAPOL-Logoff")
    dev[0].request("LOGOFF")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Did not get disconnected")
    if "reason=23" not in ev:
        raise Exception("Unexpected disconnection reason")

    dev[0].request("LOGON")
    dev[0].connect_network(id)
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
