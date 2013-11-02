#!/usr/bin/python
#
# Test cases for dynamic BSS changes with hostapd
# Copyright (c) 2013, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd

def test_ap_change_ssid(dev, apdev):
    """Dynamic SSID change with hostapd and WPA2-PSK"""
    params = hostapd.wpa2_params(ssid="test-wpa2-psk-start",
                                 passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)
    id = dev[0].connect("test-wpa2-psk-start", psk="12345678",
                        scan_freq="2412")
    dev[0].request("DISCONNECT")

    logger.info("Change SSID dynamically")
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    res = hapd.request("SET ssid test-wpa2-psk-new")
    if "OK" not in res:
        raise Exception("SET command failed")
    res = hapd.request("RELOAD")
    if "OK" not in res:
        raise Exception("RELOAD command failed")

    dev[0].set_network_quoted(id, "ssid", "test-wpa2-psk-new")
    dev[0].connect_network(id)

def multi_check(dev, check0, check1, check2):
    for d in dev:
        d.request("BSS_FLUSH 0")
        d.dump_monitor()

    id0 = dev[0].connect("bss-1", key_mgmt="NONE", scan_freq="2412",
                         wait_connect=check0)
    id1 = dev[1].connect("bss-2", key_mgmt="NONE", scan_freq="2412",
                         wait_connect=check1)
    id2 = dev[2].connect("bss-3", key_mgmt="NONE", scan_freq="2412",
                         wait_connect=check2)
    if not check0:
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.2)
        if ev:
            raise Exception("Unexpected connection")
    if not check1:
        ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.2)
        if ev:
            raise Exception("Unexpected connection")
    if not check2:
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.2)
        if ev:
            raise Exception("Unexpected connection")

    dev[0].remove_network(id0)
    dev[1].remove_network(id1)
    dev[2].remove_network(id2)

    time.sleep(0.3)

    res0 = dev[0].request("BSS RANGE=ALL MASK=0x2")
    res1 = dev[1].request("BSS RANGE=ALL MASK=0x2")
    res2 = dev[2].request("BSS RANGE=ALL MASK=0x2")

    if not check0:
        if ('02:00:00:00:03:00' in res0 or
            '02:00:00:00:03:00' in res1 or
            '02:00:00:00:03:00' in res2):
            raise Exception("Unexpected BSS0 in scan results")

    if not check1:
        if ('02:00:00:00:03:01' in res0 or
            '02:00:00:00:03:01' in res1 or
            '02:00:00:00:03:01' in res2):
            raise Exception("Unexpected BSS1 in scan results")

    if not check2:
        if ('02:00:00:00:03:02' in res0 or
            '02:00:00:00:03:02' in res1 or
            '02:00:00:00:03:02' in res2):
            raise Exception("Unexpected BSS2 in scan results")

def test_ap_bss_add_remove(dev, apdev):
    """Dynamic BSS add/remove operations with hostapd"""
    for d in dev:
        d.request("SET ignore_old_scan_res 1")
    ifname1 = apdev[0]['ifname']
    ifname2 = apdev[0]['ifname'] + '-2'
    ifname3 = apdev[0]['ifname'] + '-3'
    logger.info("Set up three BSSes one by one")
    hostapd.add_bss('phy3', ifname1, 'bss-1.conf')
    multi_check(dev, True, False, False)
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, True, True, False)
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, True, True, True)

    logger.info("Remove the last BSS and re-add it")
    hostapd.remove_bss(ifname3)
    multi_check(dev, True, True, False)
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, True, True, True)

    logger.info("Remove the middle BSS and re-add it")
    hostapd.remove_bss(ifname2)
    multi_check(dev, True, False, True)
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, True, True, True)

    logger.info("Remove the first BSS and re-add it")
    hostapd.remove_bss(ifname1)
    multi_check(dev, False, True, True)
    hostapd.add_bss('phy3', ifname1, 'bss-1.conf')
    multi_check(dev, True, True, True)

    logger.info("Remove two BSSes and re-add them")
    hostapd.remove_bss(ifname2)
    multi_check(dev, True, False, True)
    hostapd.remove_bss(ifname3)
    multi_check(dev, True, False, False)
    dev[0].request("NOTE failure-done")
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, True, True, False)
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, True, True, True)

    logger.info("Remove three BSSes and re-add them")
    hostapd.remove_bss(ifname1)
    multi_check(dev, False, True, True)
    hostapd.remove_bss(ifname2)
    multi_check(dev, False, False, True)
    hostapd.remove_bss(ifname3)
    multi_check(dev, False, False, False)
    hostapd.add_bss('phy3', ifname1, 'bss-1.conf')
    multi_check(dev, True, False, False)
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, True, True, False)
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, True, True, True)

    logger.info("Remove three BSSes in reverse order and re-add them")
    hostapd.remove_bss(ifname3)
    multi_check(dev, True, True, False)
    hostapd.remove_bss(ifname2)
    multi_check(dev, True, False, False)
    hostapd.remove_bss(ifname1)
    hostapd.add_bss('phy3', ifname1, 'bss-1.conf')
    multi_check(dev, True, False, False)
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, True, True, False)
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, True, True, True)

    logger.info("Test error handling if a duplicate ifname is tried")
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf', ignore_error=True)
    multi_check(dev, True, True, True)
