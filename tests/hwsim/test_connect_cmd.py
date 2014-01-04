#!/usr/bin/python
#
# cfg80211 connect command (SME in the driver/firmware)
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from test_p2p_grpform import go_neg_pin_authorized
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group

def test_connect_cmd_open(dev, apdev):
    """Open connection using cfg80211 connect command"""
    params = { "ssid": "sta-connect" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", key_mgmt="NONE", scan_freq="2412")
    wpas.request("DISCONNECT")

def test_connect_cmd_wpa2_psk(dev, apdev):
    """WPA2-PSK connection using cfg80211 connect command"""
    params = hostapd.wpa2_params(ssid="sta-connect", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", psk="12345678", scan_freq="2412")
    wpas.request("DISCONNECT")

def test_connect_cmd_concurrent_grpform_while_connecting(dev, apdev):
    """Concurrent P2P group formation while connecting to an AP using cfg80211 connect command"""
    logger.info("Start connection to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("test-open", key_mgmt="NONE", wait_connect=False)

    logger.info("Form a P2P group while connecting to an AP")
    wpas.request("SET p2p_no_group_iface 0")

    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_freq=2412,
                                           r_dev=wpas, r_freq=2412)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], wpas)

    logger.info("Confirm AP connection after P2P group removal")
    hwsim_utils.test_connectivity(wpas.ifname, apdev[0]['ifname'])
