#!/usr/bin/python
#
# TDLS tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger(__name__)

import hwsim_utils
from hostapd import HostapdGlobal
from hostapd import Hostapd
import hostapd

ap_ifname = 'wlan2'

def start_ap_wpa2_psk(ifname):
    params = hostapd.wpa2_params(ssid="test-wpa2-psk", passphrase="12345678")
    hostapd.add_ap(ifname, params)

def connectivity(dev, ap_ifname):
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])
    hwsim_utils.test_connectivity(dev[0].ifname, "wlan2")
    hwsim_utils.test_connectivity(dev[1].ifname, "wlan2")

def connect_2sta(dev, ssid):
    dev[0].connect(ssid, psk="12345678")
    dev[1].connect(ssid, psk="12345678")
    connectivity(dev, "wlan2")

def connect_2sta_wpa2_psk(dev):
    connect_2sta(dev, "test-wpa2-psk")

def connect_2sta_wpa_psk(dev):
    connect_2sta(dev, "test-wpa-psk")

def connect_2sta_wpa_psk_mixed(dev):
    dev[0].connect("test-wpa-mixed-psk", psk="12345678", proto="WPA")
    dev[1].connect("test-wpa-mixed-psk", psk="12345678", proto="WPA2")
    connectivity(dev, "wlan2")

def connect_2sta_wep(dev):
    dev[0].connect("test-wep", key_mgmt="NONE", wep_key0='"hello"')
    dev[1].connect("test-wep", key_mgmt="NONE", wep_key0='"hello"')
    connectivity(dev, "wlan2")

def connect_2sta_open(dev):
    dev[0].connect("test-open", key_mgmt="NONE")
    dev[1].connect("test-open", key_mgmt="NONE")
    connectivity(dev, "wlan2")

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
    subprocess.call(["../../wlantest/wlantest_cli", "add_wepkey",
                     "68656c6c6f"]);

def wlantest_tdls_packet_counters(bssid, addr0, addr1):
    dl = wlantest_tdls("valid_direct_link", bssid, addr0, addr1);
    inv_dl = wlantest_tdls("invalid_direct_link", bssid, addr0, addr1);
    ap = wlantest_tdls("valid_ap_path", bssid, addr0, addr1);
    inv_ap = wlantest_tdls("invalid_ap_path", bssid, addr0, addr1);
    return [dl,inv_dl,ap,inv_ap]

def tdls_check_dl(sta0, sta1, bssid, addr0, addr1):
    wlantest_tdls_clear(bssid, addr0, addr1);
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
    wlantest_tdls_clear(bssid, addr0, addr1);
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

def setup_tdls(sta0, sta1, bssid, reverse=False, expect_fail=False):
    logger.info("Setup TDLS")
    addr0 = sta0.p2p_interface_addr()
    addr1 = sta1.p2p_interface_addr()
    wlantest_tdls_clear(bssid, addr0, addr1);
    wlantest_tdls_clear(bssid, addr1, addr0);
    sta0.tdls_setup(addr1)
    time.sleep(1)
    if expect_fail:
        tdls_check_ap(sta0, sta1, bssid, addr0, addr1)
        return
    if reverse:
        addr1 = sta0.p2p_interface_addr()
        addr0 = sta1.p2p_interface_addr()
    conf = wlantest_tdls("setup_conf_ok", bssid, addr0, addr1);
    if conf == 0:
        raise Exception("No TDLS Setup Confirm (success) seen")
    tdls_check_dl(sta0, sta1, bssid, addr0, addr1)

def teardown_tdls(sta0, sta1, bssid):
    logger.info("Teardown TDLS")
    addr0 = sta0.p2p_interface_addr()
    addr1 = sta1.p2p_interface_addr()
    sta0.tdls_teardown(addr1)
    time.sleep(1)
    teardown = wlantest_tdls("teardown", bssid, addr0, addr1);
    if teardown == 0:
        raise Exception("No TDLS Setup Teardown seen")
    tdls_check_ap(sta0, sta1, bssid, addr0, addr1)

def test_ap_wpa2_tdls(dev):
    """WPA2-PSK AP and two stations using TDLS"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    setup_tdls(dev[0], dev[1], bssid)
    teardown_tdls(dev[0], dev[1], bssid)
    setup_tdls(dev[1], dev[0], bssid)
    #teardown_tdls(dev[0], dev[1], bssid)

def test_ap_wpa2_tdls_concurrent_init(dev):
    """Concurrent TDLS setup initiation"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    dev[0].request("SET tdls_testing 0x80")
    setup_tdls(dev[1], dev[0], bssid, reverse=True)

def test_ap_wpa2_tdls_concurrent_init2(dev):
    """Concurrent TDLS setup initiation (reverse)"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    dev[1].request("SET tdls_testing 0x80")
    setup_tdls(dev[0], dev[1], bssid)

def test_ap_wpa2_tdls_decline_resp(dev):
    """Decline TDLS Setup Response"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    dev[1].request("SET tdls_testing 0x200")
    setup_tdls(dev[1], dev[0], bssid, expect_fail=True)

def test_ap_wpa2_tdls_long_lifetime(dev):
    """TDLS with long TPK lifetime"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    dev[1].request("SET tdls_testing 0x40")
    setup_tdls(dev[1], dev[0], bssid)

def test_ap_wpa2_tdls_long_frame(dev):
    """TDLS with long setup/teardown frames"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    dev[0].request("SET tdls_testing 0x1")
    dev[1].request("SET tdls_testing 0x1")
    setup_tdls(dev[1], dev[0], bssid)
    teardown_tdls(dev[1], dev[0], bssid)
    setup_tdls(dev[0], dev[1], bssid)

def test_ap_wpa2_tdls_reneg(dev):
    """Renegotiate TDLS link"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    setup_tdls(dev[1], dev[0], bssid)
    setup_tdls(dev[0], dev[1], bssid)

def test_ap_wpa2_tdls_wrong_lifetime_resp(dev):
    """Incorrect TPK lifetime in TDLS Setup Response"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    dev[1].request("SET tdls_testing 0x10")
    setup_tdls(dev[0], dev[1], bssid, expect_fail=True)

def test_ap_wpa2_tdls_diff_rsnie(dev):
    """TDLS with different RSN IEs"""
    start_ap_wpa2_psk(ap_ifname)
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa2_psk(dev)
    dev[1].request("SET tdls_testing 0x2")
    setup_tdls(dev[1], dev[0], bssid)
    teardown_tdls(dev[1], dev[0], bssid)

def test_ap_wpa_tdls(dev):
    """WPA-PSK AP and two stations using TDLS"""
    hostapd.add_ap(ap_ifname, hostapd.wpa_params(ssid="test-wpa-psk", passphrase="12345678"))
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa_psk(dev)
    setup_tdls(dev[0], dev[1], bssid)
    teardown_tdls(dev[0], dev[1], bssid)
    setup_tdls(dev[1], dev[0], bssid)

def test_ap_wpa_mixed_tdls(dev):
    """WPA+WPA2-PSK AP and two stations using TDLS"""
    hostapd.add_ap(ap_ifname, hostapd.wpa_mixed_params(ssid="test-wpa-mixed-psk", passphrase="12345678"))
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wpa_psk_mixed(dev)
    setup_tdls(dev[0], dev[1], bssid)
    teardown_tdls(dev[0], dev[1], bssid)
    setup_tdls(dev[1], dev[0], bssid)

def test_ap_wep_tdls(dev):
    """WEP AP and two stations using TDLS"""
    hostapd.add_ap(ap_ifname, { "ssid": "test-wep", "wep_key0": '"hello"' })
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_wep(dev)
    setup_tdls(dev[0], dev[1], bssid)
    teardown_tdls(dev[0], dev[1], bssid)
    setup_tdls(dev[1], dev[0], bssid)

def test_ap_open_tdls(dev):
    """Open AP and two stations using TDLS"""
    hostapd.add_ap(ap_ifname, { "ssid": "test-open" })
    bssid = "02:00:00:00:02:00"
    wlantest_setup()
    connect_2sta_open(dev)
    setup_tdls(dev[0], dev[1], bssid)
    teardown_tdls(dev[0], dev[1], bssid)
    setup_tdls(dev[1], dev[0], bssid)
