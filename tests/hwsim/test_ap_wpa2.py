#!/usr/bin/python
#
# Tests with a WPA2-PSK AP
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger(__name__)

import hwsim_utils

def connect_sta(sta):
    logger.info("Connect STA " + sta.ifname + " to AP")
    id = sta.add_network()
    sta.set_network_quoted(id, "ssid", "test-wpa2-psk")
    sta.set_network_quoted(id, "psk", "12345678")
    sta.connect_network(id)

def connect_2sta(dev):
    connect_sta(dev[0])
    connect_sta(dev[1])
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])
    hwsim_utils.test_connectivity(dev[0].ifname, "wlan2")
    hwsim_utils.test_connectivity(dev[1].ifname, "wlan2")

def test_ap_wpa2_psk_2sta(dev):
    """WPA2-PSK AP and two stations"""
    connect_2sta(dev)

def wlantest_tdls(field, bssid, addr1, addr2):
    res = subprocess.check_output(["../../wlantest/wlantest_cli",
                                   "get_tdls_counter", field, bssid, addr1,
                                   addr2]);
    if "FAIL" in res:
        raise Exception("wlantest_cli command failed")
    return int(res)

def wlantest_tdls_clear(bssid, addr1, addr2):
    subprocess.call(["../../wlantest/wlantest_cli",
                     "clear_tdls_counters", bssid, addr1, addr2]);

def wlantest_setup():
    subprocess.call(["../../wlantest/wlantest_cli", "flush"]);
    subprocess.call(["../../wlantest/wlantest_cli", "add_passphrase",
                     "12345678"]);

def setup_tdls(sta0, sta1, bssid, reverse=False):
    logger.info("Setup TDLS")
    addr0 = sta0.p2p_interface_addr()
    addr1 = sta1.p2p_interface_addr()
    sta0.tdls_setup(addr1)
    time.sleep(1)
    if reverse:
        addr1 = sta0.p2p_interface_addr()
        addr0 = sta1.p2p_interface_addr()
    hwsim_utils.test_connectivity_sta(sta0, sta1)
    conf = wlantest_tdls("setup_conf_ok", bssid, addr0, addr1);
    if conf == 0:
        raise Exception("No TDLS Setup Confirm (success) seen")
    dl = wlantest_tdls("valid_direct_link", bssid, addr0, addr1);
    if dl == 0:
        raise Exception("No valid frames through direct link")
    wlantest_tdls_clear(bssid, addr0, addr1);

def teardown_tdls(sta0, sta1, bssid):
    logger.info("Teardown TDLS")
    addr0 = sta0.p2p_interface_addr()
    addr1 = sta1.p2p_interface_addr()
    sta0.tdls_teardown(addr1)
    time.sleep(1)
    teardown = wlantest_tdls("teardown", bssid, addr0, addr1);
    if teardown == 0:
        raise Exception("No TDLS Setup Teardown seen")
    wlantest_tdls_clear(bssid, addr0, addr1);
    hwsim_utils.test_connectivity_sta(sta0, sta1)
    ap_path = wlantest_tdls("valid_ap_path", bssid, addr0, addr1);
    if ap_path == 0:
        raise Exception("No valid frames via AP path")
    direct_link = wlantest_tdls("valid_direct_link", bssid, addr0, addr1);
    if direct_link > 0:
        raise Exception("Unexpected frames through direct link")
    idirect_link = wlantest_tdls("invalid_direct_link", bssid, addr0, addr1);
    if idirect_link > 0:
        raise Exception("Unexpected frames through direct link (invalid)")

def test_ap_wpa2_tdls(dev):
    """WPA2-PSK AP and two stations using TDLS"""
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta(dev)
    setup_tdls(dev[0], dev[1], bssid)
    teardown_tdls(dev[0], dev[1], bssid)
    setup_tdls(dev[1], dev[0], bssid)
    #teardown_tdls(dev[0], dev[1], bssid)

def test_ap_wpa2_tdls_concurrent_init(dev):
    """Concurrent TDLS setup initiation"""
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta(dev)
    dev[0].request("SET tdls_testing 0x80")
    setup_tdls(dev[1], dev[0], bssid, reverse=True)

def test_ap_wpa2_tdls_concurrent_init2(dev):
    """Concurrent TDLS setup initiation (reverse)"""
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta(dev)
    dev[1].request("SET tdls_testing 0x80")
    setup_tdls(dev[0], dev[1], bssid)

def add_tests(tests):
    tests.append(test_ap_wpa2_psk_2sta)
    tests.append(test_ap_wpa2_tdls)
    tests.append(test_ap_wpa2_tdls_concurrent_init)
    tests.append(test_ap_wpa2_tdls_concurrent_init2)
