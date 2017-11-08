# bgscan tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()
import os

import hostapd

def test_bgscan_simple(dev, apdev):
    """bgscan_simple"""
    hostapd.add_ap(apdev[0], { "ssid": "bgscan" })
    hostapd.add_ap(apdev[1], { "ssid": "bgscan" })

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-20:2")
    dev[1].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-45:2")

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-45")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:0:0")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    ev = dev[0].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
    if ev is None:
        raise Exception("dev0 did not indicate signal change event")
    if "above=0" not in ev:
        raise Exception("Unexpected signal change event contents from dev0: " + ev)

    ev = dev[1].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
    if ev is None:
        raise Exception("dev1 did not indicate signal change event")
    if "above=1" not in ev:
        raise Exception("Unexpected signal change event contents from dev1: " + ev)

    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
    if ev is None:
        raise Exception("dev0 did not start a scan")

    ev = dev[1].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
    if ev is None:
        raise Exception("dev1 did not start a scan")

    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
    if ev is None:
        raise Exception("dev0 did not complete a scan")
    ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
    if ev is None:
        raise Exception("dev1 did not complete a scan")

def test_bgscan_learn(dev, apdev):
    """bgscan_learn"""
    hostapd.add_ap(apdev[0], { "ssid": "bgscan" })
    hostapd.add_ap(apdev[1], { "ssid": "bgscan" })

    try:
        os.remove("/tmp/test_bgscan_learn.bgscan")
    except:
        pass

    try:
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1:-20:2")
        id = dev[1].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                            bgscan="learn:1:-45:2:/tmp/test_bgscan_learn.bgscan")

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1:-45")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:0:0")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        ev = dev[0].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
        if ev is None:
            raise Exception("dev0 did not indicate signal change event")
        if "above=0" not in ev:
            raise Exception("Unexpected signal change event contents from dev0: " + ev)

        ev = dev[1].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
        if ev is None:
            raise Exception("dev1 did not indicate signal change event")
        if "above=1" not in ev:
            raise Exception("Unexpected signal change event contents from dev1: " + ev)

        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
        if ev is None:
            raise Exception("dev0 did not start a scan")

        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
        if ev is None:
            raise Exception("dev1 did not start a scan")

        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        if ev is None:
            raise Exception("dev0 did not complete a scan")
        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        if ev is None:
            raise Exception("dev1 did not complete a scan")

        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        dev[0].request("REMOVE_NETWORK all")

        with open("/tmp/test_bgscan_learn.bgscan", "r") as f:
            lines = f.read().splitlines()
        if lines[0] != "wpa_supplicant-bgscan-learn":
            raise Exception("Unexpected bgscan header line")
        if 'BSS 02:00:00:00:03:00 2412' not in lines:
            raise Exception("Missing BSS1")
        if 'BSS 02:00:00:00:04:00 2412' not in lines:
            raise Exception("Missing BSS2")
        if 'NEIGHBOR 02:00:00:00:03:00 02:00:00:00:04:00' not in lines:
            raise Exception("Missing BSS1->BSS2 neighbor entry")
        if 'NEIGHBOR 02:00:00:00:04:00 02:00:00:00:03:00' not in lines:
            raise Exception("Missing BSS2->BSS1 neighbor entry")

        dev[1].set_network(id, "scan_freq", "")
        dev[1].connect_network(id)

        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=10)
        if ev is None:
            raise Exception("dev1 did not start a scan")

        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
        if ev is None:
            raise Exception("dev1 did not complete a scan")

        dev[1].request("REMOVE_NETWORK all")
    finally:
        try:
            os.remove("/tmp/test_bgscan_learn.bgscan")
        except:
            pass
