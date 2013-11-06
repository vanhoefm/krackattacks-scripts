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

def multi_check(dev, check):
    id = []
    num_bss = len(check)
    for i in range(0, num_bss):
        dev[i].request("BSS_FLUSH 0")
        dev[i].dump_monitor()
        id.append(dev[i].connect("bss-" + str(i + 1), key_mgmt="NONE",
                                 scan_freq="2412", wait_connect=check[i]))
    for i in range(0, num_bss):
        if not check[i]:
            ev = dev[i].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.2)
            if ev:
                raise Exception("Unexpected connection")

    for i in range(0, num_bss):
        dev[i].remove_network(id[i])

    time.sleep(0.3)

    res = ''
    for i in range(0, num_bss):
        res = res + dev[i].request("BSS RANGE=ALL MASK=0x2")

    for i in range(0, num_bss):
        if not check[i]:
            bssid = '02:00:00:00:03:0' + str(i)
            if bssid in res:
                raise Exception("Unexpected BSS" + str(i) + " in scan results")

def test_ap_bss_add_remove(dev, apdev):
    """Dynamic BSS add/remove operations with hostapd"""
    for d in dev:
        d.request("SET ignore_old_scan_res 1")
    ifname1 = apdev[0]['ifname']
    ifname2 = apdev[0]['ifname'] + '-2'
    ifname3 = apdev[0]['ifname'] + '-3'
    logger.info("Set up three BSSes one by one")
    hostapd.add_bss('phy3', ifname1, 'bss-1.conf')
    multi_check(dev, [ True, False, False ])
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, [ True, True, False ])
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, [ True, True, True ])

    logger.info("Remove the last BSS and re-add it")
    hostapd.remove_bss(ifname3)
    multi_check(dev, [ True, True, False ])
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, [ True, True, True ])

    logger.info("Remove the middle BSS and re-add it")
    hostapd.remove_bss(ifname2)
    multi_check(dev, [ True, False, True ])
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, [ True, True, True ])

    logger.info("Remove the first BSS and re-add it and other BSSs")
    hostapd.remove_bss(ifname1)
    multi_check(dev, [ False, False, False ])
    hostapd.add_bss('phy3', ifname1, 'bss-1.conf')
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, [ True, True, True ])

    logger.info("Remove two BSSes and re-add them")
    hostapd.remove_bss(ifname2)
    multi_check(dev, [ True, False, True ])
    hostapd.remove_bss(ifname3)
    multi_check(dev, [ True, False, False ])
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, [ True, True, False ])
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, [ True, True, True ])

    logger.info("Remove three BSSes in and re-add them")
    hostapd.remove_bss(ifname3)
    multi_check(dev, [ True, True, False ])
    hostapd.remove_bss(ifname2)
    multi_check(dev, [ True, False, False ])
    hostapd.remove_bss(ifname1)
    multi_check(dev, [ False, False, False ])
    hostapd.add_bss('phy3', ifname1, 'bss-1.conf')
    multi_check(dev, [ True, False, False ])
    hostapd.add_bss('phy3', ifname2, 'bss-2.conf')
    multi_check(dev, [ True, True, False ])
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf')
    multi_check(dev, [ True, True, True ])

    logger.info("Test error handling if a duplicate ifname is tried")
    hostapd.add_bss('phy3', ifname3, 'bss-3.conf', ignore_error=True)
    multi_check(dev, [ True, True, True ])

def test_ap_bss_add_remove_during_ht_scan(dev, apdev):
    """Dynamic BSS add during HT40 co-ex scan"""
    for d in dev:
        d.request("SET ignore_old_scan_res 1")
    ifname1 = apdev[0]['ifname']
    ifname2 = apdev[0]['ifname'] + '-2'
    hostapd.add_bss('phy3', ifname1, 'bss-ht40-1.conf')
    hostapd.add_bss('phy3', ifname2, 'bss-ht40-2.conf')
    multi_check(dev, [ True, True ])
    hostapd.remove_bss(ifname2)
    hostapd.remove_bss(ifname1)

    hostapd.add_bss('phy3', ifname1, 'bss-ht40-1.conf')
    hostapd.add_bss('phy3', ifname2, 'bss-ht40-2.conf')
    hostapd.remove_bss(ifname2)
    multi_check(dev, [ True, False ])
    hostapd.remove_bss(ifname1)

    hostapd.add_bss('phy3', ifname1, 'bss-ht40-1.conf')
    hostapd.add_bss('phy3', ifname2, 'bss-ht40-2.conf')
    hostapd.remove_bss(ifname1)
    multi_check(dev, [ False, False ])

def test_ap_multi_bss_config(dev, apdev):
    """hostapd start with a multi-BSS configuration file"""
    for d in dev:
        d.request("SET ignore_old_scan_res 1")
    ifname1 = apdev[0]['ifname']
    ifname2 = apdev[0]['ifname'] + '-2'
    ifname3 = apdev[0]['ifname'] + '-3'
    logger.info("Set up three BSSes with one configuration file")
    hostapd.add_iface(ifname1, 'multi-bss.conf')
    hapd = hostapd.Hostapd(ifname1)
    hapd.enable()
    multi_check(dev, [ True, True, True ])
    hostapd.remove_bss(ifname2)
    multi_check(dev, [ True, False, True ])
    hostapd.remove_bss(ifname3)
    multi_check(dev, [ True, False, False ])
    hostapd.remove_bss(ifname1)
    multi_check(dev, [ False, False, False ])

    hostapd.add_iface(ifname1, 'multi-bss.conf')
    hapd = hostapd.Hostapd(ifname1)
    hapd.enable()
    hostapd.remove_bss(ifname1)
    multi_check(dev, [ False, False, False ])

def invalid_ap(hapd_global, ifname):
    logger.info("Trying to start AP " + ifname + " with invalid configuration")
    hapd_global.remove(ifname)
    hapd_global.add(ifname)
    hapd = hostapd.Hostapd(ifname)
    if not hapd.ping():
        raise Exception("Could not ping hostapd")
    hapd.set_defaults()
    hapd.set("ssid", "invalid-config")
    hapd.set("channel", "12345")
    try:
        hapd.enable()
        started = True
    except Exception, e:
        started = False
    if started:
        raise Exception("ENABLE command succeeded unexpectedly")
    return hapd

def test_ap_invalid_config(dev, apdev):
    """Try to start AP with invalid configuration and fix configuration"""
    hapd_global = hostapd.HostapdGlobal()
    ifname = apdev[0]['ifname']
    hapd = invalid_ap(hapd_global, ifname)

    logger.info("Fix configuration and start AP again")
    hapd.set("channel", "1")
    hapd.enable()
    dev[0].connect("invalid-config", key_mgmt="NONE", scan_freq="2412")

def test_ap_invalid_config2(dev, apdev):
    """Try to start AP with invalid configuration and remove interface"""
    hapd_global = hostapd.HostapdGlobal()
    ifname = apdev[0]['ifname']
    hapd = invalid_ap(hapd_global, ifname)
    logger.info("Remove interface with failed configuration")
    hapd_global.remove(ifname)

def test_ap_remove_during_acs(dev, apdev):
    """Remove interface during ACS"""
    params = hostapd.wpa2_params(ssid="test-acs-remove", passphrase="12345678")
    params['channel'] = '0'
    ifname = apdev[0]['ifname']
    hapd = hostapd.HostapdGlobal()
    hostapd.add_ap(ifname, params)
    hapd.remove(ifname)

def test_ap_remove_during_acs2(dev, apdev):
    """Remove BSS during ACS in multi-BSS configuration"""
    ifname = apdev[0]['ifname']
    ifname2 = ifname + "-2"
    hapd_global = hostapd.HostapdGlobal()
    hapd_global.add(ifname)
    hapd = hostapd.Hostapd(ifname)
    hapd.set_defaults()
    hapd.set("ssid", "test-acs-remove")
    hapd.set("channel", "0")
    hapd.set("bss", ifname2)
    hapd.set("ssid", "test-acs-remove2")
    hapd.enable()
    hapd_global.remove(ifname)

def test_ap_remove_during_acs3(dev, apdev):
    """Remove second BSS during ACS in multi-BSS configuration"""
    ifname = apdev[0]['ifname']
    ifname2 = ifname + "-2"
    hapd_global = hostapd.HostapdGlobal()
    hapd_global.add(ifname)
    hapd = hostapd.Hostapd(ifname)
    hapd.set_defaults()
    hapd.set("ssid", "test-acs-remove")
    hapd.set("channel", "0")
    hapd.set("bss", ifname2)
    hapd.set("ssid", "test-acs-remove2")
    hapd.enable()
    hapd_global.remove(ifname2)

def test_ap_remove_during_ht_coex_scan(dev, apdev):
    """Remove interface during HT co-ex scan"""
    params = hostapd.wpa2_params(ssid="test-ht-remove", passphrase="12345678")
    params['channel'] = '1'
    params['ht_capab'] = "[HT40+]"
    ifname = apdev[0]['ifname']
    hapd = hostapd.HostapdGlobal()
    hostapd.add_ap(ifname, params)
    hapd.remove(ifname)

def test_ap_remove_during_ht_coex_scan2(dev, apdev):
    """Remove BSS during HT co-ex scan in multi-BSS configuration"""
    ifname = apdev[0]['ifname']
    ifname2 = ifname + "-2"
    hapd_global = hostapd.HostapdGlobal()
    hapd_global.add(ifname)
    hapd = hostapd.Hostapd(ifname)
    hapd.set_defaults()
    hapd.set("ssid", "test-ht-remove")
    hapd.set("channel", "1")
    hapd.set("ht_capab", "[HT40+]")
    hapd.set("bss", ifname2)
    hapd.set("ssid", "test-ht-remove2")
    hapd.enable()
    hapd_global.remove(ifname)

def test_ap_remove_during_ht_coex_scan3(dev, apdev):
    """Remove second BSS during HT co-ex scan in multi-BSS configuration"""
    ifname = apdev[0]['ifname']
    ifname2 = ifname + "-2"
    hapd_global = hostapd.HostapdGlobal()
    hapd_global.add(ifname)
    hapd = hostapd.Hostapd(ifname)
    hapd.set_defaults()
    hapd.set("ssid", "test-ht-remove")
    hapd.set("channel", "1")
    hapd.set("ht_capab", "[HT40+]")
    hapd.set("bss", ifname2)
    hapd.set("ssid", "test-ht-remove2")
    hapd.enable()
    hapd_global.remove(ifname2)
