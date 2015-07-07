# IEEE 802.1X tests
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import hmac
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

def test_ieee8021x_eapol_start(dev, apdev):
    """IEEE 802.1X and EAPOL-Start retransmissions"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-open"
    params["ieee8021x"] = "1"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    hapd.set("ext_eapol_frame_io", "1")
    try:
        dev[0].request("SET EAPOL::startPeriod 1")
        dev[0].request("SET EAPOL::maxStart 1")
        dev[0].connect("ieee8021x-open", key_mgmt="IEEE8021X", eapol_flags="0",
                       eap="PSK", identity="psk.user@example.com",
                       password_hex="0123456789abcdef0123456789abcdef",
                       scan_freq="2412", wait_connect=False)
        held = False
        for i in range(30):
            pae = dev[0].get_status_field('Supplicant PAE state')
            if pae == "HELD":
                held = True
                break
            time.sleep(0.25)
        if not held:
            raise Exception("PAE state HELD not reached")
        dev[0].wait_disconnected()
    finally:
        dev[0].request("SET EAPOL::startPeriod 30")
        dev[0].request("SET EAPOL::maxStart 3")

def test_ieee8021x_held(dev, apdev):
    """IEEE 802.1X and HELD state"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-open"
    params["ieee8021x"] = "1"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    hapd.set("ext_eapol_frame_io", "1")
    try:
        dev[0].request("SET EAPOL::startPeriod 1")
        dev[0].request("SET EAPOL::maxStart 0")
        dev[0].request("SET EAPOL::heldPeriod 1")
        dev[0].connect("ieee8021x-open", key_mgmt="IEEE8021X", eapol_flags="0",
                       eap="PSK", identity="psk.user@example.com",
                       password_hex="0123456789abcdef0123456789abcdef",
                       scan_freq="2412", wait_connect=False)
        held = False
        for i in range(30):
            pae = dev[0].get_status_field('Supplicant PAE state')
            if pae == "HELD":
                held = True
                break
            time.sleep(0.25)
        if not held:
            raise Exception("PAE state HELD not reached")

        hapd.set("ext_eapol_frame_io", "0")
        for i in range(30):
            pae = dev[0].get_status_field('Supplicant PAE state')
            if pae != "HELD":
                held = False
                break
            time.sleep(0.25)
        if held:
            raise Exception("PAE state HELD not left")
        ev = dev[0].wait_event([ "CTRL-EVENT-CONNECTED",
                                 "CTRL-EVENT-DISCONNECTED" ], timeout=10)
        if ev is None:
            raise Exception("Connection timed out")
        if "CTRL-EVENT-DISCONNECTED" in ev:
            raise Exception("Unexpected disconnection")
    finally:
        dev[0].request("SET EAPOL::startPeriod 30")
        dev[0].request("SET EAPOL::maxStart 3")
        dev[0].request("SET EAPOL::heldPeriod 60")

def send_eapol_key(dev, bssid, signkey, frame_start, frame_end):
    zero_sign = "00000000000000000000000000000000"
    frame = frame_start + zero_sign + frame_end
    hmac_obj = hmac.new(binascii.unhexlify(signkey))
    hmac_obj.update(binascii.unhexlify(frame))
    sign = hmac_obj.digest()
    frame = frame_start + binascii.hexlify(sign) + frame_end
    dev.request("EAPOL_RX " + bssid + " " + frame)

def test_ieee8021x_eapol_key(dev, apdev):
    """IEEE 802.1X connection and EAPOL-Key protocol tests"""
    params = hostapd.radius_params()
    params["ssid"] = "ieee8021x-wep"
    params["ieee8021x"] = "1"
    params["wep_key_len_broadcast"] = "5"
    params["wep_key_len_unicast"] = "5"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    dev[0].connect("ieee8021x-wep", key_mgmt="IEEE8021X", eap="VENDOR-TEST",
                   identity="vendor-test", scan_freq="2412")

    # Hardcoded MSK from VENDOR-TEST
    encrkey = "1111111111111111111111111111111111111111111111111111111111111111"
    signkey = "2222222222222222222222222222222222222222222222222222222222222222"

    # EAPOL-Key replay counter does not increase
    send_eapol_key(dev[0], bssid, signkey,
                   "02030031" + "010005" + "0000000000000000" + "056c22d109f29d4d9fb9b9ccbad33283" + "02",
                   "1c636a30a4")

    # EAPOL-Key too large Key Length field value
    send_eapol_key(dev[0], bssid, signkey,
                   "02030031" + "010021" + "ffffffffffffffff" + "056c22d109f29d4d9fb9b9ccbad33283" + "02",
                   "1c636a30a4")

    # EAPOL-Key too much key data
    send_eapol_key(dev[0], bssid, signkey,
                   "0203004d" + "010005" + "ffffffffffffffff" + "056c22d109f29d4d9fb9b9ccbad33283" + "02",
                   33*"ff")

    # EAPOL-Key too little key data
    send_eapol_key(dev[0], bssid, signkey,
                   "02030030" + "010005" + "ffffffffffffffff" + "056c22d109f29d4d9fb9b9ccbad33283" + "02",
                   "1c636a30")

    # EAPOL-Key with no key data and too long WEP key length
    send_eapol_key(dev[0], bssid, signkey,
                   "0203002c" + "010020" + "ffffffffffffffff" + "056c22d109f29d4d9fb9b9ccbad33283" + "02",
                   "")
