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
from wlantest import Wlantest

def check_qos_map(ap, dev, dscp, tid):
    bssid = ap['bssid']
    sta = dev.p2p_interface_addr()
    wt = Wlantest()
    wt.clear_sta_counters(bssid, sta)
    hwsim_utils.test_connectivity(dev.ifname, ap['ifname'], dscp=dscp)
    [ tx, rx ] = wt.get_tid_counters(bssid, sta)
    if tx[tid] == 0:
        logger.info("Expected TX DSCP " + str(dscp) + " with TID " + str(tid) + " but counters: " + str(tx))
        raise Exception("No STA->AP data frame using the expected TID")
    if rx[tid] == 0:
        logger.info("Expected RX DSCP " + str(dscp) + " with TID " + str(tid) + " but counters: " + str(rx))
        raise Exception("No AP->STA data frame using the expected TID")

def test_ap_qosmap(dev, apdev):
    """QoS mapping"""
    drv_flags = dev[0].get_driver_status_field("capa.flags")
    if int(drv_flags, 0) & 0x40000000 == 0:
        return "skip"
    ssid = "test-qosmap"
    params = { "ssid": ssid }
    params['qos_map_set'] = '53,2,22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,48,55'
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    check_qos_map(apdev[0], dev[0], 53, 2)
    check_qos_map(apdev[0], dev[0], 22, 6)
    check_qos_map(apdev[0], dev[0], 8, 0)
    check_qos_map(apdev[0], dev[0], 15, 0)
    check_qos_map(apdev[0], dev[0], 0, 1)
    check_qos_map(apdev[0], dev[0], 7, 1)
    check_qos_map(apdev[0], dev[0], 16, 3)
    check_qos_map(apdev[0], dev[0], 31, 3)
    check_qos_map(apdev[0], dev[0], 32, 4)
    check_qos_map(apdev[0], dev[0], 39, 4)
    check_qos_map(apdev[0], dev[0], 40, 6)
    check_qos_map(apdev[0], dev[0], 47, 6)
    check_qos_map(apdev[0], dev[0], 48, 7)
    check_qos_map(apdev[0], dev[0], 55, 7)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("SET_QOS_MAP_SET 22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,48,55")
    hapd.request("SEND_QOS_MAP_CONF " + dev[0].get_status_field("address"))
    check_qos_map(apdev[0], dev[0], 53, 7)
    check_qos_map(apdev[0], dev[0], 22, 6)
    check_qos_map(apdev[0], dev[0], 48, 7)
    check_qos_map(apdev[0], dev[0], 55, 7)
    check_qos_map(apdev[0], dev[0], 56, 56 >> 3)
    check_qos_map(apdev[0], dev[0], 63, 63 >> 3)

def test_ap_qosmap_default(dev, apdev):
    """QoS mapping with default values"""
    ssid = "test-qosmap-default"
    params = { "ssid": ssid }
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    for dscp in [ 0, 7, 8, 15, 16, 23, 24, 31, 32, 39, 40, 47, 48, 55, 56, 63]:
        check_qos_map(apdev[0], dev[0], dscp, dscp >> 3)
