#!/usr/bin/python
#
# WNM tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hostapd

def test_wnm_bss_transition_mgmt(dev, apdev):
    """WNM BSS Transition Management"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("WNM_BSS_QUERY 0")

def test_wnm_disassoc_imminent(dev, apdev):
    """WNM Disassociation Imminent"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].p2p_interface_addr()
    hapd.request("DISASSOC_IMMINENT " + addr + " 10")
    ev = dev[0].wait_event(["WNM: Disassociation Imminent"])
    if ev is None:
        raise Exception("Timeout while waiting for disassociation imminent")
    if "Disassociation Timer 10" not in ev:
        raise Exception("Unexpected disassociation imminent contents")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection scan")

def test_wnm_ess_disassoc_imminent(dev, apdev):
    """WNM ESS Disassociation Imminent"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].p2p_interface_addr()
    hapd.request("ESS_DISASSOC " + addr + " 10 http://example.com/session-info")
    ev = dev[0].wait_event(["ESS-DISASSOC-IMMINENT"])
    if ev is None:
        raise Exception("Timeout while waiting for ESS disassociation imminent")
    if "0 1024 http://example.com/session-info" not in ev:
        raise Exception("Unexpected ESS disassociation imminent message contents")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection scan")

def test_wnm_ess_disassoc_imminent_pmf(dev, apdev):
    """WNM ESS Disassociation Imminent"""
    params = hostapd.wpa2_params("test-wnm-rsn", "12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256";
    params["ieee80211w"] = "2";
    params["bss_transition"] = "1"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    dev[0].connect("test-wnm-rsn", psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK-SHA256", proto="WPA2", scan_freq="2412")
    addr = dev[0].p2p_interface_addr()
    hapd.request("ESS_DISASSOC " + addr + " 10 http://example.com/session-info")
    ev = dev[0].wait_event(["ESS-DISASSOC-IMMINENT"])
    if ev is None:
        raise Exception("Timeout while waiting for ESS disassociation imminent")
    if "1 1024 http://example.com/session-info" not in ev:
        raise Exception("Unexpected ESS disassociation imminent message contents")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection scan")

def check_wnm_sleep_mode_enter_exit(hapd, dev):
    addr = dev.p2p_interface_addr()
    sta = hapd.get_sta(addr)
    if "[WNM_SLEEP_MODE]" in sta['flags']:
        raise Exception("Station unexpectedly in WNM-Sleep Mode")
    logger.info("Going to WNM Sleep Mode")
    dev.request("WNM_SLEEP enter")
    time.sleep(0.5)
    sta = hapd.get_sta(addr)
    if "[WNM_SLEEP_MODE]" not in sta['flags']:
        raise Exception("Station failed to enter WNM-Sleep Mode")
    logger.info("Waking up from WNM Sleep Mode")
    dev.request("WNM_SLEEP exit")
    time.sleep(0.5)
    sta = hapd.get_sta(addr)
    if "[WNM_SLEEP_MODE]" in sta['flags']:
        raise Exception("Station failed to exit WNM-Sleep Mode")

def test_wnm_sleep_mode_open(dev, apdev):
    """WNM Sleep Mode - open"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    check_wnm_sleep_mode_enter_exit(hapd, dev[0])

def test_wnm_sleep_mode_rsn(dev, apdev):
    """WNM Sleep Mode - RSN"""
    params = hostapd.wpa2_params("test-wnm-rsn", "12345678")
    params["time_advertisement"] = "2"
    params["time_zone"] = "EST5"
    params["wnm_sleep_mode"] = "1"
    params["bss_transition"] = "1"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    dev[0].connect("test-wnm-rsn", psk="12345678", scan_freq="2412")
    check_wnm_sleep_mode_enter_exit(hapd, dev[0])

def test_wnm_sleep_mode_rsn_pmf(dev, apdev):
    """WNM Sleep Mode - RSN with PMF"""
    params = hostapd.wpa2_params("test-wnm-rsn", "12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256";
    params["ieee80211w"] = "2";
    params["time_advertisement"] = "2"
    params["time_zone"] = "EST5"
    params["wnm_sleep_mode"] = "1"
    params["bss_transition"] = "1"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    dev[0].connect("test-wnm-rsn", psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK-SHA256", proto="WPA2", scan_freq="2412")
    check_wnm_sleep_mode_enter_exit(hapd, dev[0])
