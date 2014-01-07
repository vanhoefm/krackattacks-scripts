#!/usr/bin/python
#
# External password storage
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd
from test_ap_hs20 import hs20_ap_params
from test_ap_hs20 import interworking_select
from test_ap_hs20 import interworking_connect

def test_ext_password_psk(dev, apdev):
    """External password storage for PSK"""
    params = hostapd.wpa2_params(ssid="ext-pw-psk", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].request("SET ext_password_backend test:psk1=12345678")
    dev[0].connect("ext-pw-psk", raw_psk="ext:psk1", scan_freq="2412")

def test_ext_password_eap(dev, apdev):
    """External password storage for EAP password"""
    params = hostapd.wpa2_eap_params(ssid="ext-pw-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].request("SET ext_password_backend test:pw0=hello|pw1=password|pw2=secret")
    dev[0].connect("ext-pw-eap", key_mgmt="WPA-EAP", eap="PEAP",
                   identity="user", password_hex="ext:pw1",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                   scan_freq="2412")

def test_ext_password_interworking(dev, apdev):
    """External password storage for Interworking network selection"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].request("SET ext_password_backend test:pw1=password")
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test" })
    dev[0].set_cred(id, "password", "ext:pw1")
    interworking_select(dev[0], bssid, freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
