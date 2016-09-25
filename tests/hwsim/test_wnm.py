# WNM tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import binascii
import struct
import time
import logging
logger = logging.getLogger()
import subprocess

import hostapd
from wpasupplicant import WpaSupplicant
from utils import alloc_fail, wait_fail_trigger
from wlantest import Wlantest

@remote_compatible
def test_wnm_bss_transition_mgmt(dev, apdev):
    """WNM BSS Transition Management"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("WNM_BSS_QUERY 0")

@remote_compatible
def test_wnm_disassoc_imminent(dev, apdev):
    """WNM Disassociation Imminent"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

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

@remote_compatible
def test_wnm_ess_disassoc_imminent(dev, apdev):
    """WNM ESS Disassociation Imminent"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

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

def test_wnm_ess_disassoc_imminent_reject(dev, apdev):
    """WNM ESS Disassociation Imminent getting rejected"""
    params = { "ssid": "test-wnm",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()
    if "OK" not in dev[0].request("SET reject_btm_req_reason 123"):
        raise Exception("Failed to set reject_btm_req_reason")

    hapd.request("ESS_DISASSOC " + addr + " 1 http://example.com/session-info")
    ev = hapd.wait_event(["BSS-TM-RESP"], timeout=10)
    if ev is None:
        raise Exception("BSS-TM-RESP not seen")
    if "status_code=123" not in ev:
        raise Exception("Unexpected response status: " + ev)
    dev[0].wait_disconnected()
    dev[0].request("DISCONNECT")

@remote_compatible
def test_wnm_ess_disassoc_imminent_pmf(dev, apdev):
    """WNM ESS Disassociation Imminent"""
    params = hostapd.wpa2_params("test-wnm-rsn", "12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    params["bss_transition"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

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
    ok = False
    for i in range(20):
        time.sleep(0.1)
        sta = hapd.get_sta(addr)
        if "[WNM_SLEEP_MODE]" in sta['flags']:
            ok = True
            break
    if not ok:
        raise Exception("Station failed to enter WNM-Sleep Mode")

    logger.info("Waking up from WNM Sleep Mode")
    ok = False
    dev.request("WNM_SLEEP exit")
    for i in range(20):
        time.sleep(0.1)
        sta = hapd.get_sta(addr)
        if "[WNM_SLEEP_MODE]" not in sta['flags']:
            ok = True
            break
    if not ok:
        raise Exception("Station failed to exit WNM-Sleep Mode")

@remote_compatible
def test_wnm_sleep_mode_open(dev, apdev):
    """WNM Sleep Mode - open"""
    params = { "ssid": "test-wnm",
               "time_advertisement": "2",
               "time_zone": "EST5",
               "wnm_sleep_mode": "1",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    check_wnm_sleep_mode_enter_exit(hapd, dev[0])
    check_wnm_sleep_mode_enter_exit(hapd, dev[0], interval=100)
    check_wnm_sleep_mode_enter_exit(hapd, dev[0], tfs_req="5b17010001130e110000071122334455661122334455661234")

    cmds = [ "foo",
             "exit tfs_req=123 interval=10",
             "enter tfs_req=qq interval=10" ]
    for cmd in cmds:
        if "FAIL" not in dev[0].request("WNM_SLEEP " + cmd):
            raise Exception("Invalid WNM_SLEEP accepted")

@remote_compatible
def test_wnm_sleep_mode_rsn(dev, apdev):
    """WNM Sleep Mode - RSN"""
    params = hostapd.wpa2_params("test-wnm-rsn", "12345678")
    params["time_advertisement"] = "2"
    params["time_zone"] = "EST5"
    params["wnm_sleep_mode"] = "1"
    params["bss_transition"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-wnm-rsn", psk="12345678", scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    check_wnm_sleep_mode_enter_exit(hapd, dev[0])

@remote_compatible
def test_wnm_sleep_mode_ap_oom(dev, apdev):
    """WNM Sleep Mode - AP side OOM"""
    params = { "ssid": "test-wnm",
               "wnm_sleep_mode": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    with alloc_fail(hapd, 1, "ieee802_11_send_wnmsleep_resp"):
        dev[0].request("WNM_SLEEP enter")
        wait_fail_trigger(hapd, "GET_ALLOC_FAIL")
    with alloc_fail(hapd, 2, "ieee802_11_send_wnmsleep_resp"):
        dev[0].request("WNM_SLEEP exit")
        wait_fail_trigger(hapd, "GET_ALLOC_FAIL")

@remote_compatible
def test_wnm_sleep_mode_rsn_pmf(dev, apdev):
    """WNM Sleep Mode - RSN with PMF"""
    params = hostapd.wpa2_params("test-wnm-rsn", "12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    params["time_advertisement"] = "2"
    params["time_zone"] = "EST5"
    params["wnm_sleep_mode"] = "1"
    params["bss_transition"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    Wlantest.setup(hapd)
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")

    dev[0].connect("test-wnm-rsn", psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK-SHA256", proto="WPA2", scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    check_wnm_sleep_mode_enter_exit(hapd, dev[0])

MGMT_SUBTYPE_ACTION = 13
ACTION_CATEG_WNM = 10
WNM_ACT_BSS_TM_REQ = 7
WNM_ACT_BSS_TM_RESP = 8
WNM_ACT_SLEEP_MODE_REQ = 16
WNM_ACT_SLEEP_MODE_RESP = 17
WNM_ACT_NOTIFICATION_REQ = 26
WNM_ACT_NOTIFICATION_RESP = 27
WNM_NOTIF_TYPE_FW_UPGRADE = 0
WNM_NOTIF_TYPE_WFA = 1
WLAN_EID_TFS_RESP = 92
WLAN_EID_WNMSLEEP = 93
WNM_SLEEP_MODE_ENTER = 0
WNM_SLEEP_MODE_EXIT = 1
WNM_STATUS_SLEEP_ACCEPT = 0
WNM_STATUS_SLEEP_EXIT_ACCEPT_GTK_UPDATE = 1
WNM_STATUS_DENIED_ACTION = 2
WNM_STATUS_DENIED_TMP = 3
WNM_STATUS_DENIED_KEY = 4
WNM_STATUS_DENIED_OTHER_WNM_SERVICE = 5
WNM_SLEEP_SUBELEM_GTK = 0
WNM_SLEEP_SUBELEM_IGTK = 1

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

def expect_ack(hapd):
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Missing TX status")
    if "ok=1" not in ev:
        raise Exception("Action frame not acknowledged")

@remote_compatible
def test_wnm_bss_tm_req(dev, apdev):
    """BSS Transition Management Request"""
    params = { "ssid": "test-wnm", "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    hapd2 = hostapd.add_ap(apdev[1], params)

    hapd.set("ext_mgmt_frame_handling", "1")

    # truncated BSS TM Request
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x08)
    req['payload'] = struct.pack("<BBBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_BSS_TM_REQ,
                                 1, 0, 0)
    hapd.mgmt_tx(req)
    expect_ack(hapd)

    # no disassociation and no candidate list
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     dialog_token=2)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=2, expect_status=1)

    # truncated BSS Termination Duration
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x08)
    hapd.mgmt_tx(req)
    expect_ack(hapd)

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
    expect_ack(hapd)
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x10)
    req['payload'] += struct.pack("<BBB", 3, 65, 66)
    hapd.mgmt_tx(req)
    expect_ack(hapd)

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
    resp = rx_bss_tm_resp(hapd, expect_dialog=5, expect_status=7)

    # Preferred Candidate List with a truncated entry
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01)
    req['payload'] += struct.pack("<BB", 52, 1)
    hapd.mgmt_tx(req)
    expect_ack(hapd)

    # Preferred Candidate List with a too short entry
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=6)
    req['payload'] += struct.pack("<BB", 52, 0)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=6, expect_status=7)

    # Preferred Candidate List with a non-matching entry
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=6)
    req['payload'] += struct.pack("<BB6BLBBB", 52, 13,
                                  1, 2, 3, 4, 5, 6,
                                  0, 81, 1, 7)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=6, expect_status=7)

    # Preferred Candidate List with a truncated subelement
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=7)
    req['payload'] += struct.pack("<BB6BLBBBBB", 52, 13 + 2,
                                  1, 2, 3, 4, 5, 6,
                                  0, 81, 1, 7,
                                  1, 1)
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=7, expect_status=7)

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
    resp = rx_bss_tm_resp(hapd, expect_dialog=8, expect_status=7)

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
    resp = rx_bss_tm_resp(hapd, expect_dialog=8, expect_status=7)

    # Preferred Candidate List followed by vendor element
    req = bss_tm_req(dev[0].p2p_interface_addr(), apdev[0]['bssid'],
                     req_mode=0x01, dialog_token=8)
    subelems = ""
    req['payload'] += struct.pack("<BB6BLBBB", 52, 13 + len(subelems),
                                  1, 2, 3, 4, 5, 6,
                                  0, 81, 1, 7) + subelems
    req['payload'] += binascii.unhexlify("DD0411223344")
    hapd.mgmt_tx(req)
    resp = rx_bss_tm_resp(hapd, expect_dialog=8, expect_status=7)

@remote_compatible
def test_wnm_bss_keep_alive(dev, apdev):
    """WNM keep-alive"""
    params = { "ssid": "test-wnm",
               "ap_max_inactivity": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

    addr = dev[0].p2p_interface_addr()
    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    start = hapd.get_sta(addr)
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=2)
    if ev is not None:
        raise Exception("Unexpected disconnection")
    end = hapd.get_sta(addr)
    if int(end['rx_packets']) <= int(start['rx_packets']):
        raise Exception("No keep-alive packets received")
    try:
        # Disable client keep-alive so that hostapd will verify connection
        # with client poll
        dev[0].request("SET no_keep_alive 1")
        for i in range(60):
            sta = hapd.get_sta(addr)
            logger.info("timeout_next=%s rx_packets=%s tx_packets=%s" % (sta['timeout_next'], sta['rx_packets'], sta['tx_packets']))
            if i > 1 and sta['timeout_next'] != "NULLFUNC POLL" and int(sta['tx_packets']) > int(end['tx_packets']):
                break
            ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=0.5)
            if ev is not None:
                raise Exception("Unexpected disconnection (client poll expected)")
    finally:
        dev[0].request("SET no_keep_alive 0")
    if int(sta['tx_packets']) <= int(end['tx_packets']):
        raise Exception("No client poll packet seen")

def test_wnm_bss_tm(dev, apdev):
    """WNM BSS Transition Management"""
    try:
        hapd = None
        hapd2 = None
        params = { "ssid": "test-wnm",
                   "country_code": "FI",
                   "ieee80211d": "1",
                   "hw_mode": "g",
                   "channel": "1",
                   "bss_transition": "1" }
        hapd = hostapd.add_ap(apdev[0], params)

        id = dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
        dev[0].set_network(id, "scan_freq", "")

        params = { "ssid": "test-wnm",
                   "country_code": "FI",
                   "ieee80211d": "1",
                   "hw_mode": "a",
                   "channel": "36",
                   "bss_transition": "1" }
        hapd2 = hostapd.add_ap(apdev[1], params)

        addr = dev[0].p2p_interface_addr()
        dev[0].dump_monitor()

        logger.info("No neighbor list entries")
        if "OK" not in hapd.request("BSS_TM_REQ " + addr):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if addr not in ev:
            raise Exception("Unexpected BSS Transition Management Response address")
        if "status_code=0" in ev:
            raise Exception("BSS transition accepted unexpectedly")
        dev[0].dump_monitor()

        logger.info("Neighbor list entry, but not claimed as Preferred Candidate List")
        if "OK" not in hapd.request("BSS_TM_REQ " + addr + " neighbor=11:22:33:44:55:66,0x0000,81,3,7"):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if "status_code=0" in ev:
            raise Exception("BSS transition accepted unexpectedly")
        dev[0].dump_monitor()

        logger.info("Preferred Candidate List (no matching neighbor) without Disassociation Imminent")
        if "OK" not in hapd.request("BSS_TM_REQ " + addr + " pref=1 neighbor=11:22:33:44:55:66,0x0000,81,3,7,0301ff neighbor=22:33:44:55:66:77,0x0000,1,36,7 neighbor=00:11:22:33:44:55,0x0000,81,4,7,03010a"):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if "status_code=0" in ev:
            raise Exception("BSS transition accepted unexpectedly")
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=5)
        if ev is None:
            raise Exception("No scan started")
        dev[0].dump_monitor()

        logger.info("Preferred Candidate List (matching neighbor for another BSS) without Disassociation Imminent")
        if "OK" not in hapd.request("BSS_TM_REQ " + addr + " pref=1 abridged=1 valid_int=255 neighbor=" + apdev[1]['bssid'] + ",0x0000,115,36,7,0301ff"):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if "status_code=0" not in ev:
            raise Exception("BSS transition request was not accepted: " + ev)
        if "target_bssid=" + apdev[1]['bssid'] not in ev:
            raise Exception("Unexpected target BSS: " + ev)
        dev[0].wait_connected(timeout=15, error="No reassociation seen")
        if apdev[1]['bssid'] not in ev:
            raise Exception("Unexpected reassociation target: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected scan started")
        dev[0].dump_monitor()

        logger.info("Preferred Candidate List with two matches, no roam needed")
        if "OK" not in hapd2.request("BSS_TM_REQ " + addr + " pref=1 abridged=1 valid_int=255 neighbor=" + apdev[0]['bssid'] + ",0x0000,81,1,7,030101 neighbor=" + apdev[1]['bssid'] + ",0x0000,115,36,7,0301ff"):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd2.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if "status_code=0" not in ev:
            raise Exception("BSS transition request was not accepted: " + ev)
        if "target_bssid=" + apdev[1]['bssid'] not in ev:
            raise Exception("Unexpected target BSS: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected scan started")
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.5)
        if ev is not None:
            raise Exception("Unexpected reassociation")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_wnm_bss_tm_scan_not_needed(dev, apdev):
    """WNM BSS Transition Management and scan not needed"""
    run_wnm_bss_tm_scan_not_needed(dev, apdev)

def test_wnm_bss_tm_nei_vht(dev, apdev):
    """WNM BSS Transition Management and VHT neighbor"""
    run_wnm_bss_tm_scan_not_needed(dev, apdev, vht=True, nei_info="115,36,9")

def test_wnm_bss_tm_nei_11a(dev, apdev):
    """WNM BSS Transition Management and 11a neighbor"""
    run_wnm_bss_tm_scan_not_needed(dev, apdev, ht=False, nei_info="115,36,4")

def test_wnm_bss_tm_nei_11g(dev, apdev):
    """WNM BSS Transition Management and 11g neighbor"""
    run_wnm_bss_tm_scan_not_needed(dev, apdev, ht=False, hwmode='g',
                                   channel='2', freq=2417, nei_info="81,2,6")

def test_wnm_bss_tm_nei_11b(dev, apdev):
    """WNM BSS Transition Management and 11g neighbor"""
    run_wnm_bss_tm_scan_not_needed(dev, apdev, ht=False, hwmode='b',
                                   channel='3', freq=2422, nei_info="81,2,5")

def run_wnm_bss_tm_scan_not_needed(dev, apdev, ht=True, vht=False, hwmode='a',
                                   channel='36', freq=5180,
                                   nei_info="115,36,7,0301ff"):
    try:
        hapd = None
        hapd2 = None
        params = { "ssid": "test-wnm",
                   "country_code": "FI",
                   "ieee80211d": "1",
                   "hw_mode": "g",
                   "channel": "1",
                   "bss_transition": "1" }
        hapd = hostapd.add_ap(apdev[0], params)

        params = { "ssid": "test-wnm",
                   "country_code": "FI",
                   "ieee80211d": "1",
                   "hw_mode": hwmode,
                   "channel": channel,
                   "bss_transition": "1" }
        if not ht:
            params['ieee80211n'] = '0'
        if vht:
            params['ieee80211ac'] = "1"
            params["vht_oper_chwidth"] = "0"
            params["vht_oper_centr_freq_seg0_idx"] = "0"

        hapd2 = hostapd.add_ap(apdev[1], params)

        dev[0].scan_for_bss(apdev[1]['bssid'], freq)

        id = dev[0].connect("test-wnm", key_mgmt="NONE",
                            bssid=apdev[0]['bssid'], scan_freq="2412")
        dev[0].set_network(id, "scan_freq", "")
        dev[0].set_network(id, "bssid", "")

        addr = dev[0].own_addr()
        dev[0].dump_monitor()

        logger.info("Preferred Candidate List (matching neighbor for another BSS) without Disassociation Imminent")
        if "OK" not in hapd.request("BSS_TM_REQ " + addr + " pref=1 abridged=1 valid_int=255 neighbor=" + apdev[1]['bssid'] + ",0x0000," + nei_info):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if "status_code=0" not in ev:
            raise Exception("BSS transition request was not accepted: " + ev)
        if "target_bssid=" + apdev[1]['bssid'] not in ev:
            raise Exception("Unexpected target BSS: " + ev)
        dev[0].wait_connected(timeout=15, error="No reassociation seen")
        if apdev[1]['bssid'] not in ev:
            raise Exception("Unexpected reassociation target: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected scan started")
        dev[0].dump_monitor()
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_wnm_bss_tm_scan_needed(dev, apdev):
    """WNM BSS Transition Management and scan needed"""
    try:
        hapd = None
        hapd2 = None
        params = { "ssid": "test-wnm",
                   "country_code": "FI",
                   "ieee80211d": "1",
                   "hw_mode": "g",
                   "channel": "1",
                   "bss_transition": "1" }
        hapd = hostapd.add_ap(apdev[0], params)

        params = { "ssid": "test-wnm",
                   "country_code": "FI",
                   "ieee80211d": "1",
                   "hw_mode": "a",
                   "channel": "36",
                   "bss_transition": "1" }
        hapd2 = hostapd.add_ap(apdev[1], params)

        dev[0].scan_for_bss(apdev[1]['bssid'], 5180)

        id = dev[0].connect("test-wnm", key_mgmt="NONE",
                            bssid=apdev[0]['bssid'], scan_freq="2412")
        dev[0].set_network(id, "scan_freq", "")
        dev[0].set_network(id, "bssid", "")

        addr = dev[0].own_addr()
        dev[0].dump_monitor()

        logger.info("Wait 11 seconds for the last scan result to be too old, but still present in BSS table")
        time.sleep(11)
        logger.info("Preferred Candidate List (matching neighbor for another BSS) without Disassociation Imminent")
        if "OK" not in hapd.request("BSS_TM_REQ " + addr + " pref=1 abridged=1 valid_int=255 neighbor=" + apdev[1]['bssid'] + ",0x0000,115,36,7,0301ff"):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if "status_code=0" not in ev:
            raise Exception("BSS transition request was not accepted: " + ev)
        if "target_bssid=" + apdev[1]['bssid'] not in ev:
            raise Exception("Unexpected target BSS: " + ev)
        dev[0].wait_connected(timeout=15, error="No reassociation seen")
        if apdev[1]['bssid'] not in ev:
            raise Exception("Unexpected reassociation target: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected scan started")
        dev[0].dump_monitor()
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def start_wnm_tm(ap, country, dev):
    params = { "ssid": "test-wnm",
               "country_code": country,
               "ieee80211d": "1",
               "hw_mode": "g",
               "channel": "1",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(ap, params)
    id = dev.connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    dev.dump_monitor()
    dev.set_network(id, "scan_freq", "")
    return hapd, id

def stop_wnm_tm(hapd, dev):
    dev.request("DISCONNECT")
    try:
        dev.wait_disconnected()
    except:
        pass
    if hapd:
        hapd.request("DISABLE")
    subprocess.call(['iw', 'reg', 'set', '00'])
    dev.flush_scan_cache()

def wnm_bss_tm_check(hapd, dev, data):
    addr = dev.p2p_interface_addr()
    if "OK" not in hapd.request("BSS_TM_REQ " + addr + " " + data):
        raise Exception("BSS_TM_REQ command failed")
    ev = dev.wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=5)
    if ev is None:
        raise Exception("No scan started")
    ev = dev.wait_event(["CTRL-EVENT-SCAN-RESULTS"], 15)
    if ev is None:
        raise Exception("Scan did not complete")

    ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
    if ev is None:
        raise Exception("No BSS Transition Management Response")
    if "status_code=7" not in ev:
        raise Exception("Unexpected response: " + ev)

def test_wnm_bss_tm_country_us(dev, apdev):
    """WNM BSS Transition Management (US)"""
    try:
        hapd = None
        hapd, id = start_wnm_tm(apdev[0], "US", dev[0])

        logger.info("Preferred Candidate List (no matching neighbor, known channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,12,3,7,0301ff neighbor=00:11:22:33:44:55,0x0000,2,52,7,03010a neighbor=00:11:22:33:44:57,0x0000,4,100,7 neighbor=00:11:22:33:44:59,0x0000,3,149,7 neighbor=00:11:22:33:44:5b,0x0000,34,1,7 neighbor=00:11:22:33:44:5d,0x0000,5,149,7")

        # Make the test take less time by limiting full scans
        dev[0].set_network(id, "scan_freq", "2412")
        logger.info("Preferred Candidate List (no matching neighbor, unknown channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,12,0,7,0301ff neighbor=22:33:44:55:66:77,0x0000,12,12,7 neighbor=00:11:22:33:44:55,0x0000,2,35,7,03010a neighbor=00:11:22:33:44:56,0x0000,2,65,7 neighbor=00:11:22:33:44:57,0x0000,4,99,7 neighbor=00:11:22:33:44:58,0x0000,4,145,7")

        logger.info("Preferred Candidate List (no matching neighbor, unknown channels 2)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=00:11:22:33:44:59,0x0000,3,148,7 neighbor=00:11:22:33:44:5a,0x0000,3,162,7 neighbor=00:11:22:33:44:5b,0x0000,34,0,7 neighbor=00:11:22:33:44:5c,0x0000,34,4,7 neighbor=00:11:22:33:44:5d,0x0000,5,148,7 neighbor=00:11:22:33:44:5e,0x0000,5,166,7 neighbor=00:11:22:33:44:5f,0x0000,0,0,7")
    finally:
        stop_wnm_tm(hapd, dev[0])

def test_wnm_bss_tm_country_fi(dev, apdev):
    """WNM BSS Transition Management (FI)"""
    addr = dev[0].p2p_interface_addr()
    try:
        hapd = None
        hapd, id = start_wnm_tm(apdev[0], "FI", dev[0])

        logger.info("Preferred Candidate List (no matching neighbor, known channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,4,3,7,0301ff neighbor=00:11:22:33:44:55,0x0000,1,36,7,03010a neighbor=00:11:22:33:44:57,0x0000,3,100,7 neighbor=00:11:22:33:44:59,0x0000,17,149,7 neighbor=00:11:22:33:44:5c,0x0000,18,1,7")

        # Make the test take less time by limiting full scans
        dev[0].set_network(id, "scan_freq", "2412")
        logger.info("Preferred Candidate List (no matching neighbor, unknown channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=00:11:22:33:44:00,0x0000,4,0,7 neighbor=00:11:22:33:44:01,0x0000,4,14,7 neighbor=00:11:22:33:44:02,0x0000,1,35,7 neighbor=00:11:22:33:44:03,0x0000,1,65,7 neighbor=00:11:22:33:44:04,0x0000,3,99,7 neighbor=00:11:22:33:44:05,0x0000,3,141,7 neighbor=00:11:22:33:44:06,0x0000,17,148,7 neighbor=00:11:22:33:44:07,0x0000,17,170,7 neighbor=00:11:22:33:44:08,0x0000,18,0,7 neighbor=00:11:22:33:44:09,0x0000,18,5,7")

        logger.info("Preferred Candidate List (no matching neighbor, unknown channels 2)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=00:11:22:33:44:00,0x0000,0,0,7")
    finally:
        stop_wnm_tm(hapd, dev[0])

def test_wnm_bss_tm_country_jp(dev, apdev):
    """WNM BSS Transition Management (JP)"""
    addr = dev[0].p2p_interface_addr()
    try:
        hapd = None
        hapd, id = start_wnm_tm(apdev[0], "JP", dev[0])

        logger.info("Preferred Candidate List (no matching neighbor, known channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,30,3,7,0301ff neighbor=00:11:22:33:44:55,0x0000,31,14,7,03010a neighbor=00:11:22:33:44:57,0x0000,1,36,7 neighbor=00:11:22:33:44:59,0x0000,34,100,7 neighbor=00:11:22:33:44:5c,0x0000,59,1,7")

        # Make the test take less time by limiting full scans
        dev[0].set_network(id, "scan_freq", "2412")
        logger.info("Preferred Candidate List (no matching neighbor, unknown channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,30,0,7,0301ff neighbor=22:33:44:55:66:77,0x0000,30,14,7 neighbor=00:11:22:33:44:56,0x0000,31,13,7 neighbor=00:11:22:33:44:57,0x0000,1,33,7 neighbor=00:11:22:33:44:58,0x0000,1,65,7 neighbor=00:11:22:33:44:5a,0x0000,34,99,7 neighbor=00:11:22:33:44:5b,0x0000,34,141,7 neighbor=00:11:22:33:44:5d,0x0000,59,0,7 neighbor=00:11:22:33:44:5e,0x0000,59,4,7 neighbor=00:11:22:33:44:5f,0x0000,0,0,7")
    finally:
        stop_wnm_tm(hapd, dev[0])

def test_wnm_bss_tm_country_cn(dev, apdev):
    """WNM BSS Transition Management (CN)"""
    addr = dev[0].p2p_interface_addr()
    try:
        hapd = None
        hapd, id = start_wnm_tm(apdev[0], "CN", dev[0])

        logger.info("Preferred Candidate List (no matching neighbor, known channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,7,3,7,0301ff neighbor=00:11:22:33:44:55,0x0000,1,36,7,03010a neighbor=00:11:22:33:44:57,0x0000,3,149,7 neighbor=00:11:22:33:44:59,0x0000,6,149,7")

        # Make the test take less time by limiting full scans
        dev[0].set_network(id, "scan_freq", "2412")
        logger.info("Preferred Candidate List (no matching neighbor, unknown channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,7,0,7,0301ff neighbor=22:33:44:55:66:77,0x0000,7,14,7 neighbor=00:11:22:33:44:56,0x0000,1,35,7 neighbor=00:11:22:33:44:57,0x0000,1,65,7 neighbor=00:11:22:33:44:58,0x0000,3,148,7 neighbor=00:11:22:33:44:5a,0x0000,3,166,7 neighbor=00:11:22:33:44:5f,0x0000,0,0,7")
    finally:
        stop_wnm_tm(hapd, dev[0])

def test_wnm_bss_tm_global(dev, apdev):
    """WNM BSS Transition Management (global)"""
    addr = dev[0].p2p_interface_addr()
    try:
        hapd = None
        hapd, id = start_wnm_tm(apdev[0], "XX", dev[0])

        logger.info("Preferred Candidate List (no matching neighbor, known channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=11:22:33:44:55:66,0x0000,81,3,7,0301ff neighbor=00:11:22:33:44:55,0x0000,82,14,7,03010a neighbor=00:11:22:33:44:57,0x0000,83,1,7 neighbor=00:11:22:33:44:59,0x0000,115,36,7 neighbor=00:11:22:33:44:5a,0x0000,121,100,7 neighbor=00:11:22:33:44:5c,0x0000,124,149,7 neighbor=00:11:22:33:44:5d,0x0000,125,149,7 neighbor=00:11:22:33:44:5e,0x0000,128,42,7 neighbor=00:11:22:33:44:5f,0x0000,129,50,7 neighbor=00:11:22:33:44:60,0x0000,180,1,7")

        # Make the test take less time by limiting full scans
        dev[0].set_network(id, "scan_freq", "2412")
        logger.info("Preferred Candidate List (no matching neighbor, unknown channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=00:11:22:33:44:00,0x0000,81,0,7 neighbor=00:11:22:33:44:01,0x0000,81,14,7 neighbor=00:11:22:33:44:02,0x0000,82,13,7 neighbor=00:11:22:33:44:03,0x0000,83,0,7 neighbor=00:11:22:33:44:04,0x0000,83,14,7 neighbor=00:11:22:33:44:05,0x0000,115,35,7 neighbor=00:11:22:33:44:06,0x0000,115,65,7 neighbor=00:11:22:33:44:07,0x0000,121,99,7 neighbor=00:11:22:33:44:08,0x0000,121,141,7 neighbor=00:11:22:33:44:09,0x0000,124,148,7")

        logger.info("Preferred Candidate List (no matching neighbor, unknown channels 2)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=00:11:22:33:44:00,0x0000,124,162,7 neighbor=00:11:22:33:44:01,0x0000,125,148,7 neighbor=00:11:22:33:44:02,0x0000,125,170,7 neighbor=00:11:22:33:44:03,0x0000,128,35,7 neighbor=00:11:22:33:44:04,0x0000,128,162,7 neighbor=00:11:22:33:44:05,0x0000,129,49,7 neighbor=00:11:22:33:44:06,0x0000,129,115,7 neighbor=00:11:22:33:44:07,0x0000,180,0,7 neighbor=00:11:22:33:44:08,0x0000,180,5,7 neighbor=00:11:22:33:44:09,0x0000,0,0,7")
    finally:
        stop_wnm_tm(hapd, dev[0])

def test_wnm_bss_tm_op_class_0(dev, apdev):
    """WNM BSS Transition Management with invalid operating class"""
    try:
        hapd = None
        hapd, id = start_wnm_tm(apdev[0], "US", dev[0])

        logger.info("Preferred Candidate List (no matching neighbor, invalid op class specified for channels)")
        wnm_bss_tm_check(hapd, dev[0], "pref=1 neighbor=00:11:22:33:44:59,0x0000,0,149,7 neighbor=00:11:22:33:44:5b,0x0000,0,1,7")
    finally:
        stop_wnm_tm(hapd, dev[0])

def test_wnm_action_proto(dev, apdev):
    """WNM Action protocol testing"""
    params = { "ssid": "test-wnm" }
    params['wnm_sleep_mode'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']
    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("WNM_SLEEP enter")
    time.sleep(0.1)
    hapd.set("ext_mgmt_frame_handling", "1")

    msg = {}
    msg['fc'] = MGMT_SUBTYPE_ACTION << 4
    msg['da'] = dev[0].own_addr()
    msg['sa'] = bssid
    msg['bssid'] = bssid

    dialog_token = 1

    logger.debug("Unexpected WNM-Notification Response")
    # Note: This is actually not registered for user space processing in
    # driver_nl80211.c nl80211_mgmt_subscribe_non_ap() and as such, won't make
    # it to wpa_supplicant.
    msg['payload'] = struct.pack("<BBBB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_RESP,
                                 dialog_token, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("Truncated WNM-Notification Request (no Type field)")
    msg['payload'] = struct.pack("<BBB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with truncated IE (min)")
    msg['payload'] = struct.pack("<BBBBBB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0, 1)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with truncated IE (max)")
    msg['payload'] = struct.pack("<BBBBBB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0, 255)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with too short IE")
    msg['payload'] = struct.pack("<BBBBBB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with truncated Sub Rem URL")
    msg['payload'] = struct.pack(">BBBBBBLB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0xdd, 5,
                                 0x506f9a00, 1)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with truncated Sub Rem URL(2)")
    msg['payload'] = struct.pack(">BBBBBBLBB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0xdd, 6,
                                 0x506f9a00, 1, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with truncated Sub Rem URL(3)")
    msg['payload'] = struct.pack(">BBBBBBLB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0xdd, 5,
                                 0x506f9a00, 0xff)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with truncated Deauth Imminent URL(min)")
    msg['payload'] = struct.pack(">BBBBBBLBHB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0xdd, 8,
                                 0x506f9a01, 0, 0, 1)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with truncated Deauth Imminent URL(max)")
    msg['payload'] = struct.pack(">BBBBBBLBHB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0xdd, 8,
                                 0x506f9a01, 0, 0, 0xff)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WFA WNM-Notification Request with unsupported IE")
    msg['payload'] = struct.pack("<BBBBBBL",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_WFA, 0xdd, 4, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM-Notification Request with unknown WNM-Notification type 0")
    msg['payload'] = struct.pack("<BBBB",
                                 ACTION_CATEG_WNM, WNM_ACT_NOTIFICATION_REQ,
                                 dialog_token, WNM_NOTIF_TYPE_FW_UPGRADE)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("Truncated WNM Sleep Mode Response - no Dialog Token")
    msg['payload'] = struct.pack("<BB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("Truncated WNM Sleep Mode Response - no Key Data Length")
    msg['payload'] = struct.pack("<BBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("Truncated WNM Sleep Mode Response - truncated Key Data (min)")
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 1)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("Truncated WNM Sleep Mode Response - truncated Key Data (max)")
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0xffff)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - truncated IE header")
    msg['payload'] = struct.pack("<BBBHB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - truncated IE")
    msg['payload'] = struct.pack("<BBBHBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, 0, 1)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - Empty TFS Response")
    msg['payload'] = struct.pack("<BBBHBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - EID 0 not recognized")
    msg['payload'] = struct.pack("<BBBHBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, 0, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - Empty WNM Sleep Mode element and TFS Response element")
    msg['payload'] = struct.pack("<BBBHBBBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, WLAN_EID_WNMSLEEP, 0, WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - WNM Sleep Mode element and empty TFS Response element")
    msg['payload'] = struct.pack("<BBBHBBBBHBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_ENTER,
                                 WNM_STATUS_SLEEP_ACCEPT, 0,
                                 WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - WNM Sleep Mode element(exit, deny key) and empty TFS Response element")
    msg['payload'] = struct.pack("<BBBHBBBBHBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                 WNM_STATUS_DENIED_KEY, 0,
                                 WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - WNM Sleep Mode element(enter, deny key) and empty TFS Response element")
    msg['payload'] = struct.pack("<BBBHBBBBHBB",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 0, WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_ENTER,
                                 WNM_STATUS_DENIED_KEY, 0,
                                 WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

@remote_compatible
def test_wnm_action_proto_pmf(dev, apdev):
    """WNM Action protocol testing (PMF enabled)"""
    ssid = "test-wnm-pmf"
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    params['wnm_sleep_mode'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']
    dev[0].connect(ssid, psk="12345678", key_mgmt="WPA-PSK-SHA256",
                   proto="WPA2", ieee80211w="2", scan_freq="2412")
    dev[0].request("WNM_SLEEP enter")
    time.sleep(0.1)
    hapd.set("ext_mgmt_frame_handling", "1")

    msg = {}
    msg['fc'] = MGMT_SUBTYPE_ACTION << 4
    msg['da'] = dev[0].own_addr()
    msg['sa'] = bssid
    msg['bssid'] = bssid

    logger.debug("WNM Sleep Mode Response - Invalid Key Data element length")
    keydata = struct.pack("<BB", 0, 1)
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 len(keydata))
    msg['payload'] += keydata
    msg['payload'] += struct.pack("<BBBBHBB",
                                  WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                  WNM_STATUS_SLEEP_ACCEPT, 0,
                                  WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - Too short GTK subelem")
    keydata = struct.pack("<BB", WNM_SLEEP_SUBELEM_GTK, 0)
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 len(keydata))
    msg['payload'] += keydata
    msg['payload'] += struct.pack("<BBBBHBB",
                                  WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                  WNM_STATUS_SLEEP_ACCEPT, 0,
                                  WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - Invalid GTK subelem")
    keydata = struct.pack("<BBHB2L4L", WNM_SLEEP_SUBELEM_GTK, 11 + 16,
                          0, 17, 0, 0, 0, 0, 0, 0)
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 len(keydata))
    msg['payload'] += keydata
    msg['payload'] += struct.pack("<BBBBHBB",
                                  WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                  WNM_STATUS_SLEEP_ACCEPT, 0,
                                  WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - Invalid GTK subelem (2)")
    keydata = struct.pack("<BBHB2L4L", WNM_SLEEP_SUBELEM_GTK, 11 + 16,
                          0, 0, 0, 0, 0, 0, 0, 0)
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 len(keydata))
    msg['payload'] += keydata
    msg['payload'] += struct.pack("<BBBBHBB",
                                  WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                  WNM_STATUS_SLEEP_ACCEPT, 0,
                                  WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - GTK subelem and too short IGTK subelem")
    keydata = struct.pack("<BBHB", WNM_SLEEP_SUBELEM_GTK, 11 + 16, 0, 16)
    keydata += struct.pack(">2L4L", 0x01020304, 0x05060708,
                           0x11223344, 0x55667788, 0x9900aabb, 0xccddeeff)
    keydata += struct.pack("<BB", WNM_SLEEP_SUBELEM_IGTK, 0)
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 len(keydata))
    msg['payload'] += keydata
    msg['payload'] += struct.pack("<BBBBHBB",
                                  WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                  WNM_STATUS_SLEEP_ACCEPT, 0,
                                  WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    logger.debug("WNM Sleep Mode Response - Unknown subelem")
    keydata = struct.pack("<BB", 255, 0)
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 len(keydata))
    msg['payload'] += keydata
    msg['payload'] += struct.pack("<BBBBHBB",
                                  WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                  WNM_STATUS_SLEEP_ACCEPT, 0,
                                  WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

@remote_compatible
def test_wnm_action_proto_no_pmf(dev, apdev):
    """WNM Action protocol testing (PMF disabled)"""
    ssid = "test-wnm-no-pmf"
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params['wnm_sleep_mode'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']
    dev[0].connect(ssid, psk="12345678", key_mgmt="WPA-PSK",
                   proto="WPA2", ieee80211w="0", scan_freq="2412")
    dev[0].request("WNM_SLEEP enter")
    time.sleep(0.1)
    hapd.set("ext_mgmt_frame_handling", "1")

    msg = {}
    msg['fc'] = MGMT_SUBTYPE_ACTION << 4
    msg['da'] = dev[0].own_addr()
    msg['sa'] = bssid
    msg['bssid'] = bssid

    logger.debug("WNM Sleep Mode Response - GTK subelem and IGTK subelem")
    keydata = struct.pack("<BBHB", WNM_SLEEP_SUBELEM_GTK, 11 + 16, 0, 16)
    keydata += struct.pack(">2L4L", 0x01020304, 0x05060708,
                           0x11223344, 0x55667788, 0x9900aabb, 0xccddeeff)
    keydata += struct.pack("<BBHLH4L", WNM_SLEEP_SUBELEM_IGTK, 2 + 6 + 16, 0,
                           0x10203040, 0x5060,
                           0xf1f2f3f4, 0xf5f6f7f8, 0xf9f0fafb, 0xfcfdfeff)
    msg['payload'] = struct.pack("<BBBH",
                                 ACTION_CATEG_WNM, WNM_ACT_SLEEP_MODE_RESP, 0,
                                 len(keydata))
    msg['payload'] += keydata
    msg['payload'] += struct.pack("<BBBBHBB",
                                  WLAN_EID_WNMSLEEP, 4, WNM_SLEEP_MODE_EXIT,
                                  WNM_STATUS_SLEEP_ACCEPT, 0,
                                  WLAN_EID_TFS_RESP, 0)
    hapd.mgmt_tx(msg)
    expect_ack(hapd)

    ev = dev[0].wait_event(["WNM: Ignore Key Data"], timeout=5)
    if ev is None:
        raise Exception("Key Data not ignored")

def test_wnm_bss_tm_req_with_mbo_ie(dev, apdev):
    """WNM BSS transition request with MBO IE and reassociation delay attribute"""
    ssid = "test-wnm-mbo"
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']
    if "OK" not in dev[0].request("SET mbo_cell_capa 1"):
        raise Exception("Failed to set STA as cellular data capable")

    dev[0].connect(ssid, psk="12345678", key_mgmt="WPA-PSK",
                   proto="WPA2", ieee80211w="0", scan_freq="2412")

    logger.debug("BTM request with MBO reassociation delay when disassoc imminent is not set")
    if 'FAIL' not in hapd.request("BSS_TM_REQ " + dev[0].own_addr() + " mbo=3:2:1"):
        raise Exception("BSS transition management succeeded unexpectedly")

    logger.debug("BTM request with invalid MBO transition reason code")
    if 'FAIL' not in hapd.request("BSS_TM_REQ " + dev[0].own_addr() + " mbo=10:2:1"):
        raise Exception("BSS transition management succeeded unexpectedly")

    logger.debug("BTM request with MBO reassociation retry delay of 5 seconds")
    if 'OK' not in hapd.request("BSS_TM_REQ " + dev[0].own_addr() + " disassoc_imminent=1 disassoc_timer=3 mbo=3:5:1"):
        raise Exception("BSS transition management command failed")

    ev = dev[0].wait_event(['MBO-CELL-PREFERENCE'], 1)
    if ev is None or "preference=1" not in ev:
        raise Exception("Timeout waiting for MBO-CELL-PREFERENCE event")

    ev = dev[0].wait_event(['MBO-TRANSITION-REASON'], 1)
    if ev is None or "reason=3" not in ev:
        raise Exception("Timeout waiting for MBO-TRANSITION-REASON event")

    ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
    if ev is None:
        raise Exception("No BSS Transition Management Response")
    if dev[0].own_addr() not in ev:
        raise Exception("Unexpected BSS Transition Management Response address")

    ev = dev[0].wait_event(['CTRL-EVENT-DISCONNECTED'], 5)
    if ev is None:
        raise Exception("Station did not disconnect although disassoc imminent was set")

    # Set the scan interval to make dev[0] look for connections
    if 'OK' not in dev[0].request("SCAN_INTERVAL 1"):
        raise Exception("Failed to set scan interval")

    # Make sure no connection is made during the retry delay
    ev = dev[0].wait_event(['CTRL-EVENT-CONNECTED'], 5)
    if ev is not None:
        raise Exception("Station connected before assoc retry delay was over")

    # After the assoc retry delay is over, we can reconnect
    ev = dev[0].wait_event(['CTRL-EVENT-CONNECTED'], 5)
    if ev is None:
        raise Exception("Station did not connect after assoc retry delay is over")

    if "OK" not in dev[0].request("SET mbo_cell_capa 3"):
        raise Exception("Failed to set STA as cellular data not-capable")

@remote_compatible
def test_wnm_bss_transition_mgmt_query(dev, apdev):
    """WNM BSS Transition Management query"""
    params = { "ssid": "test-wnm",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)
    params = { "ssid": "another" }
    hapd2 = hostapd.add_ap(apdev[1], params)

    dev[0].scan_for_bss(apdev[1]['bssid'], 2412)
    dev[0].scan_for_bss(apdev[0]['bssid'], 2412)

    dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("WNM_BSS_QUERY 0 list")

    ev = dev[0].wait_event(["WNM: BSS Transition Management Request"],
                           timeout=5)
    if ev is None:
        raise Exception("No BSS Transition Management Request frame seen")

    ev = hapd.wait_event(["BSS-TM-RESP"], timeout=5)
    if ev is None:
        raise Exception("No BSS Transition Management Response frame seen")

@remote_compatible
def test_wnm_bss_tm_security_mismatch(dev, apdev):
    """WNM BSS Transition Management and security mismatch"""
    params = { "ssid": "test-wnm",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": "CCMP",
               "wpa_passphrase": "12345678",
               "hw_mode": "g",
               "channel": "1",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

    params = { "ssid": "test-wnm",
               "hw_mode": "g",
               "channel": "11",
               "bss_transition": "1" }
    hapd2 = hostapd.add_ap(apdev[1], params)

    dev[0].scan_for_bss(apdev[1]['bssid'], 2462)

    id = dev[0].connect("test-wnm", psk="12345678",
                        bssid=apdev[0]['bssid'], scan_freq="2412")
    dev[0].set_network(id, "scan_freq", "")
    dev[0].set_network(id, "bssid", "")

    addr = dev[0].own_addr()
    dev[0].dump_monitor()

    logger.info("Preferred Candidate List (matching neighbor for another BSS) without Disassociation Imminent")
    if "OK" not in hapd.request("BSS_TM_REQ " + addr + " pref=1 abridged=1 valid_int=255 neighbor=" + apdev[1]['bssid'] + ",0x0000,115,36,7,0301ff"):
        raise Exception("BSS_TM_REQ command failed")
    ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
    if ev is None:
        raise Exception("No BSS Transition Management Response")
    if "status_code=7" not in ev:
        raise Exception("Unexpected BSS transition request response: " + ev)

def test_wnm_bss_tm_connect_cmd(dev, apdev):
    """WNM BSS Transition Management and cfg80211 connect command"""
    params = { "ssid": "test-wnm",
               "hw_mode": "g",
               "channel": "1",
               "bss_transition": "1" }
    hapd = hostapd.add_ap(apdev[0], params)

    params = { "ssid": "test-wnm",
               "hw_mode": "g",
               "channel": "11",
               "bss_transition": "1" }
    hapd2 = hostapd.add_ap(apdev[1], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")

    wpas.scan_for_bss(apdev[1]['bssid'], 2462)

    id = wpas.connect("test-wnm", key_mgmt="NONE",
                      bssid=apdev[0]['bssid'], scan_freq="2412")
    wpas.set_network(id, "scan_freq", "")
    wpas.set_network(id, "bssid", "")

    addr = wpas.own_addr()
    wpas.dump_monitor()

    logger.info("Preferred Candidate List (matching neighbor for another BSS) without Disassociation Imminent")
    if "OK" not in hapd.request("BSS_TM_REQ " + addr + " pref=1 abridged=1 valid_int=255 neighbor=" + apdev[1]['bssid'] + ",0x0000,115,36,7,0301ff"):
        raise Exception("BSS_TM_REQ command failed")
    ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
    if ev is None:
        raise Exception("No BSS Transition Management Response")
    if "status_code=0" not in ev:
        raise Exception("BSS transition request was not accepted: " + ev)
    if "target_bssid=" + apdev[1]['bssid'] not in ev:
        raise Exception("Unexpected target BSS: " + ev)
    ev = wpas.wait_event(["CTRL-EVENT-CONNECTED",
                          "CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("No reassociation seen")
    if "CTRL-EVENT-DISCONNECTED" in ev:
        #TODO: Uncomment this once kernel side changes for Connect command
        #reassociation are in upstream.
        #raise Exception("Unexpected disconnection reported")
        logger.info("Unexpected disconnection reported")
        ev = wpas.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("No reassociation seen")
    if apdev[1]['bssid'] not in ev:
        raise Exception("Unexpected reassociation target: " + ev)

def test_wnm_bss_tm_reject(dev, apdev):
    """WNM BSS Transition Management request getting rejected"""
    try:
        hapd = None
        params = { "ssid": "test-wnm",
                   "country_code": "FI",
                   "ieee80211d": "1",
                   "hw_mode": "g",
                   "channel": "1",
                   "bss_transition": "1" }
        hapd = hostapd.add_ap(apdev[0], params)

        id = dev[0].connect("test-wnm", key_mgmt="NONE", scan_freq="2412")
        addr = dev[0].own_addr()
        dev[0].dump_monitor()

        if "OK" not in dev[0].request("SET reject_btm_req_reason 123"):
            raise Exception("Failed to set reject_btm_req_reason")

        if "OK" not in hapd.request("BSS_TM_REQ " + addr + " disassoc_timer=1"):
            raise Exception("BSS_TM_REQ command failed")
        ev = hapd.wait_event(['BSS-TM-RESP'], timeout=10)
        if ev is None:
            raise Exception("No BSS Transition Management Response")
        if addr not in ev:
            raise Exception("Unexpected BSS Transition Management Response address")
        if "status_code=123" not in ev:
            raise Exception("Unexpected BSS Transition Management Response status: " + ev)
        dev[0].wait_disconnected()
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
