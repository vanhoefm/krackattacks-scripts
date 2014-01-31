#!/usr/bin/python
#
# Test cases for HT operations with hostapd
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()
import struct

import hostapd

def test_ap_ht40_scan(dev, apdev):
    """HT40 co-ex scan"""
    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-]"}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    state = hapd.get_status_field("state")
    if state != "HT_SCAN":
        time.sleep(0.1)
        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            raise Exception("Unexpected interface state - expected HT_SCAN")

    ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
    if not ev:
        raise Exception("AP setup timed out")

    state = hapd.get_status_field("state")
    if state != "ENABLED":
        raise Exception("Unexpected interface state - expected ENABLED")

    freq = hapd.get_status_field("freq")
    if freq != "2432":
        raise Exception("Unexpected frequency")
    pri = hapd.get_status_field("channel")
    if pri != "5":
        raise Exception("Unexpected primary channel")
    sec = hapd.get_status_field("secondary_channel")
    if sec != "-1":
        raise Exception("Unexpected secondary channel")

    dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)

def test_obss_scan(dev, apdev):
    """Overlapping BSS scan request"""
    params = { "ssid": "obss-scan",
               "channel": "6",
               "ht_capab": "[HT40-]",
               "obss_interval": "10" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("obss-scan", key_mgmt="NONE", scan_freq="2437")
    hapd.set("ext_mgmt_frame_handling", "1")
    logger.info("Waiting for OBSS scan to occur")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=15)
    if ev is None:
        raise Exception("Timed out while waiting for OBSS scan to start")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=10)
    if ev is None:
        raise Exception("Timed out while waiting for OBSS scan results")
    received = False
    for i in range(0, 4):
        frame = hapd.mgmt_rx(timeout=5)
        if frame is None:
            raise Exception("MGMT RX wait timed out")
        if frame['subtype'] != 13:
            continue
        payload = frame['payload']
        if len(payload) < 3:
            continue
        (category, action, ie) = struct.unpack('BBB', payload[0:3])
        if category != 4:
            continue
        if action != 0:
            continue
        if ie == 72:
            logger.info("20/40 BSS Coexistence report received")
            received = True
            break
    if not received:
        raise Exception("20/40 BSS Coexistence report not seen")

def test_olbc(dev, apdev):
    """OLBC detection"""
    params = { "ssid": "test-olbc",
               "channel": "6",
               "ht_capab": "[HT40-]" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    status = hapd.get_status()
    if status['olbc'] != '0' or status['olbc_ht'] != '0':
        raise Exception("Unexpected OLBC information")

    params = { "ssid": "olbc-ap",
               "hw_mode": "b",
               "channel": "6",
               "wmm_enabled": "0" }
    hostapd.add_ap(apdev[1]['ifname'], params)
    time.sleep(0.5)
    status = hapd.get_status()
    if status['olbc'] != '1' or status['olbc_ht'] != '1':
        raise Exception("Missing OLBC information")

def test_ap_require_ht(dev, apdev):
    """Require HT"""
    params = { "ssid": "require-ht",
               "require_ht": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    dev[0].connect("require-ht", key_mgmt="NONE", scan_freq="2412")
