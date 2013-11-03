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

import hostapd

def test_ap_ht40_scan(dev, apdev):
    """HT40 co-ex scan"""
    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-]"}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    state = hapd.get_status_field("state")
    if state != "HT_SCAN":
        time.wait(0.1)
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
