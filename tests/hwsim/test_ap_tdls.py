#!/usr/bin/python
#
# TDLS tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hwsim_utils
from hostapd import HostapdGlobal
from hostapd import Hostapd
import hostapd
from wlantest import Wlantest

def start_ap_wpa2_psk(ifname):
    params = hostapd.wpa2_params(ssid="test-wpa2-psk", passphrase="12345678")
    hostapd.add_ap(ifname, params)

def connectivity(dev, ap_ifname):
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])
    hwsim_utils.test_connectivity(dev[0].ifname, ap_ifname)
    hwsim_utils.test_connectivity(dev[1].ifname, ap_ifname)

def connect_2sta(dev, ssid, ap_ifname):
    dev[0].connect(ssid, psk="12345678", scan_freq="2412")
    dev[1].connect(ssid, psk="12345678", scan_freq="2412")
    connectivity(dev, ap_ifname)

def connect_2sta_wpa2_psk(dev, ap_ifname):
    connect_2sta(dev, "test-wpa2-psk", ap_ifname)

def connect_2sta_wpa_psk(dev, ap_ifname):
    connect_2sta(dev, "test-wpa-psk", ap_ifname)

def connect_2sta_wpa_psk_mixed(dev, ap_ifname):
    dev[0].connect("test-wpa-mixed-psk", psk="12345678", proto="WPA",
                   scan_freq="2412")
    dev[1].connect("test-wpa-mixed-psk", psk="12345678", proto="WPA2",
                   scan_freq="2412")
    connectivity(dev, ap_ifname)

def connect_2sta_wep(dev, ap_ifname):
    dev[0].connect("test-wep", key_mgmt="NONE", wep_key0='"hello"',
                   scan_freq="2412")
    dev[1].connect("test-wep", key_mgmt="NONE", wep_key0='"hello"',
                   scan_freq="2412")
    connectivity(dev, ap_ifname)

def connect_2sta_open(dev, ap_ifname):
    dev[0].connect("test-open", key_mgmt="NONE", scan_freq="2412")
    dev[1].connect("test-open", key_mgmt="NONE", scan_freq="2412")
    connectivity(dev, ap_ifname)

def wlantest_setup():
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    wt.add_wepkey("68656c6c6f")

def wlantest_tdls_packet_counters(bssid, addr0, addr1):
    wt = Wlantest()
    dl = wt.get_tdls_counter("valid_direct_link", bssid, addr0, addr1)
    inv_dl = wt.get_tdls_counter("invalid_direct_link", bssid, addr0, addr1)
    ap = wt.get_tdls_counter("valid_ap_path", bssid, addr0, addr1)
    inv_ap = wt.get_tdls_counter("invalid_ap_path", bssid, addr0, addr1)
    return [dl,inv_dl,ap,inv_ap]

def tdls_check_dl(sta0, sta1, bssid, addr0, addr1):
    wt = Wlantest()
    wt.tdls_clear(bssid, addr0, addr1)
    hwsim_utils.test_connectivity_sta(sta0, sta1)
    [dl,inv_dl,ap,inv_ap] = wlantest_tdls_packet_counters(bssid, addr0, addr1)
    if dl == 0:
        raise Exception("No valid frames through direct link")
    if inv_dl > 0:
        raise Exception("Invalid frames through direct link")
    if ap > 0:
        raise Exception("Unexpected frames through AP path")
    if inv_ap > 0:
        raise Exception("Invalid frames through AP path")

def tdls_check_ap(sta0, sta1, bssid, addr0, addr1):
    wt = Wlantest()
    wt.tdls_clear(bssid, addr0, addr1);
    hwsim_utils.test_connectivity_sta(sta0, sta1)
    [dl,inv_dl,ap,inv_ap] = wlantest_tdls_packet_counters(bssid, addr0, addr1)
    if dl > 0:
        raise Exception("Unexpected frames through direct link")
    if inv_dl > 0:
        raise Exception("Invalid frames through direct link")
    if ap == 0:
        raise Exception("No valid frames through AP path")
    if inv_ap > 0:
        raise Exception("Invalid frames through AP path")

def check_connectivity(sta0, sta1, ap):
    hwsim_utils.test_connectivity_sta(sta0, sta1)
    hwsim_utils.test_connectivity(sta0.ifname, ap['ifname'])
    hwsim_utils.test_connectivity(sta1.ifname, ap['ifname'])

def setup_tdls(sta0, sta1, ap, reverse=False, expect_fail=False):
    logger.info("Setup TDLS")
    check_connectivity(sta0, sta1, ap)
    bssid = ap['bssid']
    addr0 = sta0.p2p_interface_addr()
    addr1 = sta1.p2p_interface_addr()
    wt = Wlantest()
    wt.tdls_clear(bssid, addr0, addr1);
    wt.tdls_clear(bssid, addr1, addr0);
    sta0.tdls_setup(addr1)
    time.sleep(1)
    if expect_fail:
        tdls_check_ap(sta0, sta1, bssid, addr0, addr1)
        return
    if reverse:
        addr1 = sta0.p2p_interface_addr()
        addr0 = sta1.p2p_interface_addr()
    conf = wt.get_tdls_counter("setup_conf_ok", bssid, addr0, addr1);
    if conf == 0:
        raise Exception("No TDLS Setup Confirm (success) seen")
    tdls_check_dl(sta0, sta1, bssid, addr0, addr1)
    check_connectivity(sta0, sta1, ap)

def teardown_tdls(sta0, sta1, ap):
    logger.info("Teardown TDLS")
    check_connectivity(sta0, sta1, ap)
    bssid = ap['bssid']
    addr0 = sta0.p2p_interface_addr()
    addr1 = sta1.p2p_interface_addr()
    sta0.tdls_teardown(addr1)
    time.sleep(1)
    wt = Wlantest()
    teardown = wt.get_tdls_counter("teardown", bssid, addr0, addr1);
    if teardown == 0:
        raise Exception("No TDLS Setup Teardown seen")
    tdls_check_ap(sta0, sta1, bssid, addr0, addr1)
    check_connectivity(sta0, sta1, ap)

def test_ap_wpa2_tdls(dev, apdev):
    """WPA2-PSK AP and two stations using TDLS"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    setup_tdls(dev[0], dev[1], apdev[0])
    teardown_tdls(dev[0], dev[1], apdev[0])
    setup_tdls(dev[1], dev[0], apdev[0])
    #teardown_tdls(dev[0], dev[1], apdev[0])

def test_ap_wpa2_tdls_concurrent_init(dev, apdev):
    """Concurrent TDLS setup initiation"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    dev[0].request("SET tdls_testing 0x80")
    setup_tdls(dev[1], dev[0], apdev[0], reverse=True)

def test_ap_wpa2_tdls_concurrent_init2(dev, apdev):
    """Concurrent TDLS setup initiation (reverse)"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    dev[1].request("SET tdls_testing 0x80")
    setup_tdls(dev[0], dev[1], apdev[0])

def test_ap_wpa2_tdls_decline_resp(dev, apdev):
    """Decline TDLS Setup Response"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    dev[1].request("SET tdls_testing 0x200")
    setup_tdls(dev[1], dev[0], apdev[0], expect_fail=True)

def test_ap_wpa2_tdls_long_lifetime(dev, apdev):
    """TDLS with long TPK lifetime"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    dev[1].request("SET tdls_testing 0x40")
    setup_tdls(dev[1], dev[0], apdev[0])

def test_ap_wpa2_tdls_long_frame(dev, apdev):
    """TDLS with long setup/teardown frames"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    dev[0].request("SET tdls_testing 0x1")
    dev[1].request("SET tdls_testing 0x1")
    setup_tdls(dev[1], dev[0], apdev[0])
    teardown_tdls(dev[1], dev[0], apdev[0])
    setup_tdls(dev[0], dev[1], apdev[0])

def test_ap_wpa2_tdls_reneg(dev, apdev):
    """Renegotiate TDLS link"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    setup_tdls(dev[1], dev[0], apdev[0])
    setup_tdls(dev[0], dev[1], apdev[0])

def test_ap_wpa2_tdls_wrong_lifetime_resp(dev, apdev):
    """Incorrect TPK lifetime in TDLS Setup Response"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    dev[1].request("SET tdls_testing 0x10")
    setup_tdls(dev[0], dev[1], apdev[0], expect_fail=True)

def test_ap_wpa2_tdls_diff_rsnie(dev, apdev):
    """TDLS with different RSN IEs"""
    start_ap_wpa2_psk(apdev[0]['ifname'])
    wlantest_setup()
    connect_2sta_wpa2_psk(dev, apdev[0]['ifname'])
    dev[1].request("SET tdls_testing 0x2")
    setup_tdls(dev[1], dev[0], apdev[0])
    teardown_tdls(dev[1], dev[0], apdev[0])

def test_ap_wpa_tdls(dev, apdev):
    """WPA-PSK AP and two stations using TDLS"""
    hostapd.add_ap(apdev[0]['ifname'],
                   hostapd.wpa_params(ssid="test-wpa-psk",
                                      passphrase="12345678"))
    wlantest_setup()
    connect_2sta_wpa_psk(dev, apdev[0]['ifname'])
    setup_tdls(dev[0], dev[1], apdev[0])
    teardown_tdls(dev[0], dev[1], apdev[0])
    setup_tdls(dev[1], dev[0], apdev[0])

def test_ap_wpa_mixed_tdls(dev, apdev):
    """WPA+WPA2-PSK AP and two stations using TDLS"""
    hostapd.add_ap(apdev[0]['ifname'],
                   hostapd.wpa_mixed_params(ssid="test-wpa-mixed-psk",
                                            passphrase="12345678"))
    wlantest_setup()
    connect_2sta_wpa_psk_mixed(dev, apdev[0]['ifname'])
    setup_tdls(dev[0], dev[1], apdev[0])
    teardown_tdls(dev[0], dev[1], apdev[0])
    setup_tdls(dev[1], dev[0], apdev[0])

def test_ap_wep_tdls(dev, apdev):
    """WEP AP and two stations using TDLS"""
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": "test-wep", "wep_key0": '"hello"' })
    wlantest_setup()
    connect_2sta_wep(dev, apdev[0]['ifname'])
    setup_tdls(dev[0], dev[1], apdev[0])
    teardown_tdls(dev[0], dev[1], apdev[0])
    setup_tdls(dev[1], dev[0], apdev[0])

def test_ap_open_tdls(dev, apdev):
    """Open AP and two stations using TDLS"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    wlantest_setup()
    connect_2sta_open(dev, apdev[0]['ifname'])
    setup_tdls(dev[0], dev[1], apdev[0])
    teardown_tdls(dev[0], dev[1], apdev[0])
    setup_tdls(dev[1], dev[0], apdev[0])
