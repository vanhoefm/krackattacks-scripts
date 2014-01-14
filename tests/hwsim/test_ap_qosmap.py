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

def check_qos_map(ap, dev, dscp, tid, ap_tid=None):
    if not ap_tid:
        ap_tid = tid
    bssid = ap['bssid']
    sta = dev.p2p_interface_addr()
    wt = Wlantest()
    wt.clear_sta_counters(bssid, sta)
    hwsim_utils.test_connectivity(dev.ifname, ap['ifname'], dscp=dscp)
    time.sleep(0.02)
    [ tx, rx ] = wt.get_tid_counters(bssid, sta)
    if tx[tid] == 0:
        logger.info("Expected TX DSCP " + str(dscp) + " with TID " + str(tid) + " but counters: " + str(tx))
        raise Exception("No STA->AP data frame using the expected TID")
    if rx[ap_tid] == 0:
        logger.info("Expected RX DSCP " + str(dscp) + " with TID " + str(ap_tid) + " but counters: " + str(rx))
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
    time.sleep(0.1)
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

def test_ap_qosmap_default_acm(dev, apdev):
    """QoS mapping with default values and ACM=1 for VO/VI"""
    ssid = "test-qosmap-default"
    params = { "ssid": ssid,
               "wmm_ac_bk_aifs": "7",
               "wmm_ac_bk_cwmin": "4",
               "wmm_ac_bk_cwmax": "10",
               "wmm_ac_bk_txop_limit": "0",
               "wmm_ac_bk_acm": "0",
               "wmm_ac_be_aifs": "3",
               "wmm_ac_be_cwmin": "4",
               "wmm_ac_be_cwmax": "10",
               "wmm_ac_be_txop_limit": "0",
               "wmm_ac_be_acm": "0",
               "wmm_ac_vi_aifs": "2",
               "wmm_ac_vi_cwmin": "3",
               "wmm_ac_vi_cwmax": "4",
               "wmm_ac_vi_txop_limit": "94",
               "wmm_ac_vi_acm": "1",
               "wmm_ac_vo_aifs": "2",
               "wmm_ac_vo_cwmin": "2",
               "wmm_ac_vo_cwmax": "2",
               "wmm_ac_vo_txop_limit": "47",
               "wmm_ac_vo_acm": "1"  }
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    for dscp in [ 0, 7, 8, 15, 16, 23, 24, 31, 32, 39, 40, 47, 48, 55, 56, 63]:
        ap_tid = dscp >> 3
        tid = ap_tid
        # downgrade VI/VO to BE
        if tid in [ 4, 5, 6, 7 ]:
            tid = 3
        check_qos_map(apdev[0], dev[0], dscp, tid, ap_tid)
