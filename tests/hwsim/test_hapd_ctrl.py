# hostapd control interface
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

def test_hapd_ctrl_status(dev, apdev):
    """hostapd ctrl_iface STATUS commands"""
    ssid = "hapd-ctrl"
    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    status = hapd.get_status()
    driver = hapd.get_driver_status()

    if status['bss[0]'] != apdev[0]['ifname']:
        raise Exception("Unexpected bss[0]")
    if status['ssid[0]'] != ssid:
        raise Exception("Unexpected ssid[0]")
    if status['bssid[0]'] != bssid:
        raise Exception("Unexpected bssid[0]")
    if status['freq'] != "2412":
        raise Exception("Unexpected freq")

    if driver['beacon_set'] != "1":
        raise Exception("Unexpected beacon_set")
    if driver['addr'] != bssid:
        raise Exception("Unexpected addr")

def test_hapd_ctrl_p2p_manager(dev, apdev):
    """hostapd as P2P Device manager"""
    ssid = "hapd-p2p-mgr"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['manage_p2p'] = '1'
    params['allow_cross_connection'] = '0'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    addr = dev[0].p2p_dev_addr()
    if "OK" not in hapd.request("DEAUTHENTICATE " + addr + " p2p=2"):
        raise Exception("DEAUTHENTICATE command failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Disconnection event timed out")
