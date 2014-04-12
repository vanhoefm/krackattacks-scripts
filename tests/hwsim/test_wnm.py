# WNM tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import struct
import time
import logging
logger = logging.getLogger()

import hostapd
from wlantest import Wlantest

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

def check_wnm_sleep_mode_enter_exit(hapd, dev, interval=None, tfs_req=None):
    addr = dev.p2p_interface_addr()
    sta = hapd.get_sta(addr)
    if "[WNM_SLEEP_MODE]" in sta['flags']:
        raise Exception("Station unexpectedly in WNM-Sleep Mode")
    logger.info("Going to WNM Sleep Mode")
    extra = ""
    if interval is not None:
        extra += " interval=" + str(interval)
    if tfs_req:
        extra += " tfs_req=" + tfs_req
    if "OK" not in dev.request("WNM_SLEEP enter" + extra):
        raise Exception("WNM_SLEEP failed")
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
    check_wnm_sleep_mode_enter_exit(hapd, dev[0], interval=100)
    check_wnm_sleep_mode_enter_exit(hapd, dev[0], tfs_req="5b17010001130e110000071122334455661122334455661234")

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
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
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

MGMT_SUBTYPE_ACTION = 13
ACTION_CATEG_WNM = 10
WNM_ACT_BSS_TM_REQ = 7
WNM_ACT_BSS_TM_RESP = 8

def bss_tm_req(dst, src, dialog_token=1, req_mode=0, disassoc_timer=0,
               validity_interval=1):
    msg = {}
    msg['fc'] = MGMT_SUBTYPE_ACTION << 4
    msg['da'] = dst
    msg['sa'] = src
    msg['bssid'] = src
    msg['payload'] = struct.pack("<BBBBHB",
                                 ACTION_CATEG_WNM, WNM_ACT_BSS_TM_REQ,
                                 dialog_token, req_mode, disassoc_timer,
                                 validity_interval)
    return msg

def rx_bss_tm_resp(hapd, expect_dialog=None, expect_status=None):
    for i in range(0, 100):
        resp = hapd.mgmt_rx()
        if resp is None:
            raise Exception("No BSS TM Response received")
        if resp['subtype'] == MGMT_SUBTYPE_ACTION:
            break
    if i == 99:
        raise Exception("Not an Action frame")
    payload = resp['payload']
    if len(payload) < 2 + 3:
        raise Exception("Too short payload")
    (category, action) = struct.unpack('BB', payload[0:2])
    if category != ACTION_CATEG_WNM or action != WNM_ACT_BSS_TM_RESP:
        raise Exception("Not a BSS TM Response")
    pos = payload[2:]
    (dialog, status, bss_term_delay) = struct.unpack('BBB', pos[0:3])
    resp['dialog'] = dialog
    resp['status'] = status
    resp['bss_term_delay'] = bss_term_delay
    pos = pos[3:]
    if len(pos) >= 6 and status == 0:
        resp['target_bssid'] = binascii.hexlify(pos[0:6])
        pos = pos[6:]
    resp['candidates'] = pos
    if expect_dialog is not None and dialog != expect_dialog:
        raise Exception("Unexpected dialog token")
    if expect_status is not None and status != expect_status:
        raise Exception("Unexpected status code %d" % status)
    return resp

def except_ack(hapd):
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Missing TX status")
    if "ok=1" not in ev:
        raise Exception("Action frame not acknowledged")

def test_wnm_bss_tm_req(dev, apdev):
    """BSS Transition Management Request"""
    params = { "ssid": "test-wnm", "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)

    hapd.set("ext_mgmt_frame_handling", "1")

    # truncated BSS TM Request
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x08)
    req['payload'] = struct.pack("<BBBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_BSS_TM_REQ,
                                 1, 0, 0)
    hapd.mgmt_tx(req)
    except_ack(hapd)

    # no disassociation and no candidate list
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     dialog_token=2)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=2, expect_status=1)

    # truncated BSS Termination Duration
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x08)
    hapd.mgmt_tx(req)
    except_ack(hapd)

    # BSS Termination Duration with TSF=0 and Duration=10
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x08, dialog_token=3)
    req['payload'] += struct.pack("<BBQH", 4, 10, 0, 10)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=3, expect_status=1)

    # truncated Session Information URL
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x10)
    hapd.mgmt_tx(req)
    except_ack(hapd)
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x10)
    req['payload'] += struct.pack("<BBB", 3, 65, 66)
    hapd.mgmt_tx(req)
    except_ack(hapd)

    # Session Information URL
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x10, dialog_token=4)
    req['payload'] += struct.pack("<BBB", 2, 65, 66)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=4, expect_status=0)

    # Preferred Candidate List without any entries
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=5)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=5, expect_status=1)

    # Preferred Candidate List with a truncated entry
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01)
    req['payload'] += struct.pack("<BB", 52, 1)
    hapd.mgmt_tx(req)
    except_ack(hapd)

    # Preferred Candidate List with a too short entry
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=6)
    req['payload'] += struct.pack("<BB", 52, 0)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=6, expect_status=1)

    # Preferred Candidate List with a non-matching entry
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=6)
    req['payload'] += struct.pack("<BB6BLBBB", 52, 13,
                                  1, 2, 3, 4, 5, 6,
                                  0, 81, 1, 7)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=6, expect_status=1)

    # Preferred Candidate List with a truncated subelement
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=7)
    req['payload'] += struct.pack("<BB6BLBBBBB", 52, 13 + 2,
                                  1, 2, 3, 4, 5, 6,
                                  0, 81, 1, 7,
                                  1, 1)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=7, expect_status=1)

    # Preferred Candidate List with lots of invalid optional subelements
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=8)
    subelems = struct.pack("<BBHB", 1, 3, 0, 100)
    subelems += struct.pack("<BBB", 2, 1, 65)
    subelems += struct.pack("<BB", 3, 0)
    subelems += struct.pack("<BBQB", 4, 9, 0, 10)
    subelems += struct.pack("<BBHLB", 5, 7, 0, 0, 0)
    subelems += struct.pack("<BB", 66, 0)
    subelems += struct.pack("<BBBBBB", 70, 4, 0, 0, 0, 0)
    subelems += struct.pack("<BB", 71, 0)
    req['payload'] += struct.pack("<BB6BLBBB", 52, 13 + len(subelems),
                                  1, 2, 3, 4, 5, 6,
                                  0, 81, 1, 7) + subelems
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=8, expect_status=1)

    # Preferred Candidate List with lots of valid optional subelements (twice)
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=8)
    # TSF Information
    subelems = struct.pack("<BBHH", 1, 4, 0, 100)
    # Condensed Country String
    subelems += struct.pack("<BBBB", 2, 2, 65, 66)
    # BSS Transition Candidate Preference
    subelems += struct.pack("<BBB", 3, 1, 100)
    # BSS Termination Duration
    subelems += struct.pack("<BBQH", 4, 10, 0, 10)
    # Bearing
    subelems += struct.pack("<BBHLH", 5, 8, 0, 0, 0)
    # Measurement Pilot Transmission
    subelems += struct.pack("<BBBBB", 66, 3, 0, 0, 0)
    # RM Enabled Capabilities
    subelems += struct.pack("<BBBBBBB", 70, 5, 0, 0, 0, 0, 0)
    # Multiple BSSID
    subelems += struct.pack("<BBBB", 71, 2, 0, 0)
    req['payload'] += struct.pack("<BB6BLBBB", 52, 13 + len(subelems) * 2,
                                  1, 2, 3, 4, 5, 6,
                                  0, 81, 1, 7) + subelems + subelems
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=8, expect_status=1)

def test_wnm_bss_keep_alive(dev, apdev):
    """WNM keep-alive"""
    params = { "ssid": "test-wnm",
               "ap_max_inactivity": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    time.sleep(2)
