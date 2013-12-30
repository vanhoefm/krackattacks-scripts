#!/usr/bin/python
#
# AP mode using the older monitor interface design
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

def test_monitor_iface_open(dev, apdev):
    """Open connection using cfg80211 monitor interface on AP"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="use_monitor=1")
    id = wpas.add_network()
    wpas.set_network(id, "mode", "2")
    wpas.set_network_quoted(id, "ssid", "monitor-iface")
    wpas.set_network(id, "key_mgmt", "NONE")
    wpas.set_network(id, "frequency", "2412")
    wpas.connect_network(id)

    dev[0].connect("monitor-iface", key_mgmt="NONE", scan_freq="2412")

def test_monitor_iface_wpa2_psk(dev, apdev):
    """WPA2-PSK connection using cfg80211 monitor interface on AP"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="use_monitor=1")
    id = wpas.add_network()
    wpas.set_network(id, "mode", "2")
    wpas.set_network_quoted(id, "ssid", "monitor-iface-wpa2")
    wpas.set_network(id, "proto", "WPA2")
    wpas.set_network(id, "key_mgmt", "WPA-PSK")
    wpas.set_network_quoted(id, "psk", "12345678")
    wpas.set_network(id, "pairwise", "CCMP")
    wpas.set_network(id, "group", "CCMP")
    wpas.set_network(id, "frequency", "2412")
    wpas.connect_network(id)

    dev[0].connect("monitor-iface-wpa2", psk="12345678", scan_freq="2412")
