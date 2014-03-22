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
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Re-connection timed out")

    if "OK" not in hapd.request("DISASSOCIATE " + addr + " p2p=2"):
        raise Exception("DISASSOCIATE command failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Disconnection event timed out")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Re-connection timed out")

def test_hapd_ctrl_sta(dev, apdev):
    """hostapd and STA ctrl_iface commands"""
    ssid = "hapd-ctrl-sta"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    addr = dev[0].p2p_dev_addr()
    if "FAIL" in hapd.request("STA " + addr):
        raise Exception("Unexpected STA failure")
    if "FAIL" not in hapd.request("STA " + addr + " eapol"):
        raise Exception("Unexpected STA-eapol success")
    if "FAIL" not in hapd.request("STA 00:11:22:33:44"):
        raise Exception("Unexpected STA success")
    if "FAIL" not in hapd.request("STA 00:11:22:33:44:55"):
        raise Exception("Unexpected STA success")

    if len(hapd.request("STA-NEXT " + addr).splitlines()) > 0:
        raise Exception("Unexpected STA-NEXT result")
    if "FAIL" not in hapd.request("STA-NEXT 00:11:22:33:44"):
        raise Exception("Unexpected STA-NEXT success")

def test_hapd_ctrl_disconnect(dev, apdev):
    """hostapd and disconnection ctrl_iface commands"""
    ssid = "hapd-ctrl"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    addr = dev[0].p2p_dev_addr()

    if "FAIL" not in hapd.request("DEAUTHENTICATE 00:11:22:33:44"):
        raise Exception("Unexpected DEAUTHENTICATE success")

    if "OK" not in hapd.request("DEAUTHENTICATE ff:ff:ff:ff:ff:ff"):
        raise Exception("Unexpected DEAUTHENTICATE failure")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Disconnection event timed out")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Re-connection timed out")

    if "FAIL" not in hapd.request("DISASSOCIATE 00:11:22:33:44"):
        raise Exception("Unexpected DISASSOCIATE success")

    if "OK" not in hapd.request("DISASSOCIATE ff:ff:ff:ff:ff:ff"):
        raise Exception("Unexpected DISASSOCIATE failure")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Disconnection event timed out")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Re-connection timed out")

def test_hapd_ctrl_chan_switch(dev, apdev):
    """hostapd and CHAN_SWITCH ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("CHAN_SWITCH "):
        raise Exception("Unexpected CHAN_SWITCH success")
    if "FAIL" not in hapd.request("CHAN_SWITCH qwerty 2422"):
        raise Exception("Unexpected CHAN_SWITCH success")
    if "FAIL" not in hapd.request("CHAN_SWITCH 5 qwerty"):
        raise Exception("Unexpected CHAN_SWITCH success")
    if "FAIL" not in hapd.request("CHAN_SWITCH 0 2432 center_freq1=123 center_freq2=234 bandwidth=1000 sec_channel_offset=20 ht vht"):
        raise Exception("Unexpected CHAN_SWITCH success")

def test_hapd_ctrl_level(dev, apdev):
    """hostapd and LEVEL ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("LEVEL 0"):
        raise Exception("Unexpected LEVEL success on non-monitor interface")

def test_hapd_ctrl_new_sta(dev, apdev):
    """hostapd and NEW_STA ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("NEW_STA 00:11:22:33:44"):
        raise Exception("Unexpected NEW_STA success")
    if "OK" not in hapd.request("NEW_STA 00:11:22:33:44:55"):
        raise Exception("Unexpected NEW_STA failure")
    if "AUTHORIZED" not in hapd.request("STA 00:11:22:33:44:55"):
        raise Esception("Unexpected NEW_STA STA status")

def test_hapd_ctrl_get(dev, apdev):
    """hostapd and GET ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("GET foo"):
        raise Exception("Unexpected GET success")
    if "FAIL" in hapd.request("GET version"):
        raise Exception("Unexpected GET version failure")

def test_hapd_ctrl_unknown(dev, apdev):
    """hostapd and unknown ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "UNKNOWN COMMAND" not in hapd.request("FOO"):
        raise Exception("Unexpected response")
