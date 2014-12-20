# cfg80211 connect command (SME in the driver/firmware)
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from test_p2p_grpform import go_neg_pin_authorized
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group

def test_connect_cmd_open(dev, apdev):
    """Open connection using cfg80211 connect command"""
    params = { "ssid": "sta-connect",
               "manage_p2p": "1",
               "allow_cross_connection": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", key_mgmt="NONE", scan_freq="2412",
                 bg_scan_period="1")
    wpas.request("DISCONNECT")

def test_connect_cmd_wep(dev, apdev):
    """WEP Open System using cfg80211 connect command"""
    params = { "ssid": "sta-connect-wep", "wep_key0": '"hello"' }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect-wep", key_mgmt="NONE", scan_freq="2412",
                 wep_key0='"hello"')
    hwsim_utils.test_connectivity(wpas, hapd)
    wpas.request("DISCONNECT")

def test_connect_cmd_wep_shared(dev, apdev):
    """WEP Shared key using cfg80211 connect command"""
    params = { "ssid": "sta-connect-wep", "wep_key0": '"hello"',
               "auth_algs": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    id = wpas.connect("sta-connect-wep", key_mgmt="NONE", scan_freq="2412",
                      auth_alg="SHARED", wep_key0='"hello"')
    hwsim_utils.test_connectivity(wpas, hapd)
    wpas.request("DISCONNECT")
    wpas.remove_network(id)
    wpas.connect("sta-connect-wep", key_mgmt="NONE", scan_freq="2412",
                 auth_alg="OPEN SHARED", wep_key0='"hello"')
    hwsim_utils.test_connectivity(wpas, hapd)
    wpas.request("DISCONNECT")

def test_connect_cmd_p2p_management(dev, apdev):
    """Open connection using cfg80211 connect command and AP using P2P management"""
    params = { "ssid": "sta-connect",
               "manage_p2p": "1",
               "allow_cross_connection": "0" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", key_mgmt="NONE", scan_freq="2412")
    wpas.request("DISCONNECT")

def test_connect_cmd_wpa2_psk(dev, apdev):
    """WPA2-PSK connection using cfg80211 connect command"""
    params = hostapd.wpa2_params(ssid="sta-connect", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", psk="12345678", scan_freq="2412")
    wpas.request("DISCONNECT")

def test_connect_cmd_concurrent_grpform_while_connecting(dev, apdev):
    """Concurrent P2P group formation while connecting to an AP using cfg80211 connect command"""
    logger.info("Start connection to an infrastructure AP")
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("test-open", key_mgmt="NONE", wait_connect=False)

    logger.info("Form a P2P group while connecting to an AP")
    wpas.request("SET p2p_no_group_iface 0")

    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_freq=2412,
                                           r_dev=wpas, r_freq=2412)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], wpas)

    logger.info("Confirm AP connection after P2P group removal")
    hwsim_utils.test_connectivity(wpas, hapd)

def test_connect_cmd_reject_assoc(dev, apdev):
    """Connection using cfg80211 connect command getting rejected"""
    params = { "ssid": "sta-connect",
               "require_ht": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", key_mgmt="NONE", scan_freq="2412",
                 disable_ht="1", wait_connect=False)
    # Reject event gets reported twice since we force connect command to be used
    # with a driver that supports auth+assoc for testing purposes.
    for i in range(0, 2):
        ev = wpas.wait_event(["CTRL-EVENT-ASSOC-REJECT"], timeout=15)
        if ev is None:
            raise Exception("Association rejection timed out")
        if "status_code=27" not in ev:
            raise Exception("Unexpected rejection status code")

def test_connect_cmd_disconnect_event(dev, apdev):
    """Connection using cfg80211 connect command getting disconnected by the AP"""
    params = { "ssid": "sta-connect" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("sta-connect", key_mgmt="NONE", scan_freq="2412")

    if "OK" not in hapd.request("DEAUTHENTICATE " + wpas.p2p_interface_addr()):
        raise Exception("DEAUTHENTICATE command failed")
    ev = wpas.wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Disconnection event timed out")
    # This event was actually based on deauthenticate event since we force
    # connect command to be used with a driver that supports auth+assoc for
    # testing purposes. Anyway, wait some time to allow the debug log to capture
    # the following NL80211_CMD_DISCONNECT event.
    time.sleep(0.1)
