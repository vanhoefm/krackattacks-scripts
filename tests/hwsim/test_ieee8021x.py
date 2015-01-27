# IEEE 802.1X tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
import time

import hostapd
import hwsim_utils

logger = logging.getLogger()

def test_ieee8021x_wep104(dev, apdev):
    """IEEE 802.1X connection using dynamic WEP104"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-wep"
    params["ieee8021x"] = "1"
    params["wep_key_len_broadcast"] = "13"
    params["wep_key_len_unicast"] = "13"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("ieee8021x-wep", key_mgmt="IEEE8021X", eap="PSK",
                   identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_wep40(dev, apdev):
    """IEEE 802.1X connection using dynamic WEP40"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-wep"
    params["ieee8021x"] = "1"
    params["wep_key_len_broadcast"] = "5"
    params["wep_key_len_unicast"] = "5"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("ieee8021x-wep", key_mgmt="IEEE8021X", eap="PSK",
                   identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_open(dev, apdev):
    """IEEE 802.1X connection using open network"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-open"
    params["ieee8021x"] = "1"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    id = dev[0].connect("ieee8021x-open", key_mgmt="IEEE8021X", eapol_flags="0",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

    logger.info("Test EAPOL-Logoff")
    dev[0].request("LOGOFF")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Did not get disconnected")
    if "reason=23" not in ev:
        raise Exception("Unexpected disconnection reason")

    dev[0].request("LOGON")
    dev[0].connect_network(id)
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_static_wep40(dev, apdev):
    """IEEE 802.1X connection using static WEP40"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-wep"
    params["ieee8021x"] = "1"
    params["wep_key0"] = '"hello"'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("ieee8021x-wep", key_mgmt="IEEE8021X", eap="PSK",
                   identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   wep_key0='"hello"', eapol_flags="0",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_proto(dev, apdev):
    """IEEE 802.1X and EAPOL supplicant protocol testing"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-open"
    params["ieee8021x"] = "1"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    dev[1].request("SET ext_eapol_frame_io 1")
    dev[1].connect("ieee8021x-open", key_mgmt="IEEE8021X", eapol_flags="0",
                   eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412", wait_connect=False)
    id = dev[0].connect("ieee8021x-open", key_mgmt="IEEE8021X", eapol_flags="0",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        scan_freq="2412")
    ev = dev[1].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=5)

    start = dev[0].get_mib()

    tests = [ "11",
              "11223344",
              "020000050a93000501",
              "020300050a93000501",
              "0203002c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "0203002c0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "0203002c0100050000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "02aa00050a93000501" ]
    for frame in tests:
        res = dev[0].request("EAPOL_RX " + bssid + " " + frame)
        if "OK" not in res:
            raise Exception("EAPOL_RX to wpa_supplicant failed")
        dev[1].request("EAPOL_RX " + bssid + " " + frame)

    stop = dev[0].get_mib()

    logger.info("MIB before test frames: " + str(start))
    logger.info("MIB after test frames: " + str(stop))

    vals = [ 'dot1xSuppInvalidEapolFramesRx',
             'dot1xSuppEapLengthErrorFramesRx' ]
    for val in vals:
        if int(stop[val]) <= int(start[val]):
            raise Exception(val + " did not increase")
