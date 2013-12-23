#!/usr/bin/python
#
# QoS Mapping tests
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

def test_ap_qosmap(dev, apdev):
    """QoS mapping"""
    drv_flags = dev[0].get_driver_status_field("capa.flags")
    if int(drv_flags, 0) & 0x40000000 == 0:
        return "skip"
    ssid = "test-qosmap"
    params = { "ssid": ssid }
    params['qos_map_set'] = '53,2,22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,255,255'
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("SET_QOS_MAP_SET 22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,255,255")
    hapd.request("SEND_QOS_MAP_CONF " + dev[0].get_status_field("address"))
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
