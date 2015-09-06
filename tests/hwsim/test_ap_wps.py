# WPS tests
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import base64
import binascii
import os
import time
import stat
import subprocess
import logging
logger = logging.getLogger()
import re
import socket
import httplib
import urlparse
import urllib
import xml.etree.ElementTree as ET
import StringIO
import SocketServer

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from utils import HwsimSkip, alloc_fail, fail_test, skip_with_fips

def wps_start_ap(apdev, ssid="test-wps-conf"):
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" }
    return hostapd.add_ap(apdev['ifname'], params)

def test_ap_wps_init(dev, apdev):
    """Initial AP configuration with first WPS Enrollee"""
    ssid = "test-wps"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    if "PBC Status: Active" not in hapd.request("WPS_GET_STATUS"):
        raise Exception("PBC status not shown correctly")

    id = dev[0].add_network()
    dev[0].set_network_quoted(id, "ssid", "home")
    dev[0].set_network_quoted(id, "psk", "12345678")
    dev[0].request("ENABLE_NETWORK %s no-connect" % id)

    id = dev[0].add_network()
    dev[0].set_network_quoted(id, "ssid", "home2")
    dev[0].set_network(id, "bssid", "00:11:22:33:44:55")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].request("ENABLE_NETWORK %s no-connect" % id)

    dev[0].request("WPS_PBC")
    dev[0].wait_connected(timeout=30)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    status = hapd.request("WPS_GET_STATUS")
    if "PBC Status: Disabled" not in status:
        raise Exception("PBC status not shown correctly")
    if "Last WPS result: Success" not in status:
        raise Exception("Last WPS result not shown correctly")
    if "Peer Address: " + dev[0].p2p_interface_addr() not in status:
        raise Exception("Peer address not shown correctly")
    conf = hapd.request("GET_CONFIG")
    if "wps_state=configured" not in conf:
        raise Exception("AP not in WPS configured state")
    if "wpa=3" not in conf:
        raise Exception("AP not in WPA+WPA2 configuration")
    if "rsn_pairwise_cipher=CCMP TKIP" not in conf:
        raise Exception("Unexpected rsn_pairwise_cipher")
    if "wpa_pairwise_cipher=CCMP TKIP" not in conf:
        raise Exception("Unexpected wpa_pairwise_cipher")
    if "group_cipher=TKIP" not in conf:
        raise Exception("Unexpected group_cipher")

    if len(dev[0].list_networks()) != 3:
        raise Exception("Unexpected number of network blocks")

def test_ap_wps_init_2ap_pbc(dev, apdev):
    """Initial two-radio AP configuration with first WPS PBC Enrollee"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hostapd.add_ap(apdev[1]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" not in bss['flags']:
        raise Exception("WPS-PBC flag missing from AP1")
    bss = dev[0].get_bss(apdev[1]['bssid'])
    if "[WPS-PBC]" not in bss['flags']:
        raise Exception("WPS-PBC flag missing from AP2")
    dev[0].dump_monitor()
    dev[0].request("SET wps_cred_processing 2")
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["WPS-CRED-RECEIVED"], timeout=30)
    dev[0].request("SET wps_cred_processing 0")
    if ev is None:
        raise Exception("WPS cred event not seen")
    if "100e" not in ev:
        raise Exception("WPS attributes not included in the cred event")
    dev[0].wait_connected(timeout=30)

    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    dev[1].scan_for_bss(apdev[1]['bssid'], freq="2412")
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" in bss['flags']:
        raise Exception("WPS-PBC flag not cleared from AP1")
    bss = dev[1].get_bss(apdev[1]['bssid'])
    if "[WPS-PBC]" in bss['flags']:
        raise Exception("WPS-PBC flag not cleared from AP2")

def test_ap_wps_init_2ap_pin(dev, apdev):
    """Initial two-radio AP configuration with first WPS PIN Enrollee"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hostapd.add_ap(apdev[1]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    pin = dev[0].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" not in bss['flags']:
        raise Exception("WPS-AUTH flag missing from AP1")
    bss = dev[0].get_bss(apdev[1]['bssid'])
    if "[WPS-AUTH]" not in bss['flags']:
        raise Exception("WPS-AUTH flag missing from AP2")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN any " + pin)
    dev[0].wait_connected(timeout=30)

    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    dev[1].scan_for_bss(apdev[1]['bssid'], freq="2412")
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not cleared from AP1")
    bss = dev[1].get_bss(apdev[1]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not cleared from AP2")

def test_ap_wps_init_through_wps_config(dev, apdev):
    """Initial AP configuration using wps_config command"""
    ssid = "test-wps-init-config"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    if "FAIL" in hapd.request("WPS_CONFIG " + ssid.encode("hex") + " WPA2PSK CCMP " + "12345678".encode("hex")):
        raise Exception("WPS_CONFIG command failed")
    ev = hapd.wait_event(["WPS-NEW-AP-SETTINGS"], timeout=5)
    if ev is None:
        raise Exception("Timeout on WPS-NEW-AP-SETTINGS events")
    # It takes some time for the AP to update Beacon and Probe Response frames,
    # so wait here before requesting the scan to be started to avoid adding
    # extra five second wait to the test due to fetching obsolete scan results.
    hapd.ping()
    time.sleep(0.2)
    dev[0].connect(ssid, psk="12345678", scan_freq="2412", proto="WPA2",
                   pairwise="CCMP", group="CCMP")

def test_ap_wps_init_through_wps_config_2(dev, apdev):
    """AP configuration using wps_config and wps_cred_processing=2"""
    ssid = "test-wps-init-config"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1",
                     "wps_cred_processing": "2" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    if "FAIL" in hapd.request("WPS_CONFIG " + ssid.encode("hex") + " WPA2PSK CCMP " + "12345678".encode("hex")):
        raise Exception("WPS_CONFIG command failed")
    ev = hapd.wait_event(["WPS-NEW-AP-SETTINGS"], timeout=5)
    if ev is None:
        raise Exception("Timeout on WPS-NEW-AP-SETTINGS events")
    if "100e" not in ev:
        raise Exception("WPS-NEW-AP-SETTINGS did not include Credential")

def test_ap_wps_invalid_wps_config_passphrase(dev, apdev):
    """AP configuration using wps_config command with invalid passphrase"""
    ssid = "test-wps-init-config"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    if "FAIL" not in hapd.request("WPS_CONFIG " + ssid.encode("hex") + " WPA2PSK CCMP " + "1234567".encode("hex")):
        raise Exception("Invalid WPS_CONFIG command accepted")

def test_ap_wps_conf(dev, apdev):
    """WPS PBC provisioning with configured AP"""
    ssid = "test-wps-conf"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED':
        raise Exception("Not fully connected")
    if status['bssid'] != apdev[0]['bssid']:
        raise Exception("Unexpected BSSID")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    sta = hapd.get_sta(dev[0].p2p_interface_addr())
    if 'wpsDeviceName' not in sta or sta['wpsDeviceName'] != "Device A":
        raise Exception("Device name not available in STA command")

def test_ap_wps_conf_5ghz(dev, apdev):
    """WPS PBC provisioning with configured AP on 5 GHz band"""
    try:
        hapd = None
        ssid = "test-wps-conf"
        params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                   "wpa_passphrase": "12345678", "wpa": "2",
                   "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                   "country_code": "FI", "hw_mode": "a", "channel": "36" }
        hapd = hostapd.add_ap(apdev[0]['ifname'], params)
        logger.info("WPS provisioning step")
        hapd.request("WPS_PBC")
        dev[0].scan_for_bss(apdev[0]['bssid'], freq="5180")
        dev[0].request("WPS_PBC " + apdev[0]['bssid'])
        dev[0].wait_connected(timeout=30)

        sta = hapd.get_sta(dev[0].p2p_interface_addr())
        if 'wpsDeviceName' not in sta or sta['wpsDeviceName'] != "Device A":
            raise Exception("Device name not available in STA command")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_wps_conf_chan14(dev, apdev):
    """WPS PBC provisioning with configured AP on channel 14"""
    try:
        hapd = None
        ssid = "test-wps-conf"
        params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                   "wpa_passphrase": "12345678", "wpa": "2",
                   "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                   "country_code": "JP", "hw_mode": "b", "channel": "14" }
        hapd = hostapd.add_ap(apdev[0]['ifname'], params)
        logger.info("WPS provisioning step")
        hapd.request("WPS_PBC")
        dev[0].request("WPS_PBC")
        dev[0].wait_connected(timeout=30)

        sta = hapd.get_sta(dev[0].p2p_interface_addr())
        if 'wpsDeviceName' not in sta or sta['wpsDeviceName'] != "Device A":
            raise Exception("Device name not available in STA command")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_wps_twice(dev, apdev):
    """WPS provisioning with twice to change passphrase"""
    ssid = "test-wps-twice"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)
    dev[0].request("DISCONNECT")

    logger.info("Restart AP with different passphrase and re-run WPS")
    hapd_global = hostapd.HostapdGlobal()
    hapd_global.remove(apdev[0]['ifname'])
    params['wpa_passphrase'] = 'another passphrase'
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)
    networks = dev[0].list_networks()
    if len(networks) > 1:
        raise Exception("Unexpected duplicated network block present")

def test_ap_wps_incorrect_pin(dev, apdev):
    """WPS PIN provisioning with incorrect PIN"""
    ssid = "test-wps-incorrect-pin"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    logger.info("WPS provisioning attempt 1")
    hapd.request("WPS_PIN any 12345670")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN %s 55554444" % apdev[0]['bssid'])
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=30)
    if ev is None:
        raise Exception("WPS operation timed out")
    if "config_error=18" not in ev:
        raise Exception("Incorrect config_error reported")
    if "msg=8" not in ev:
        raise Exception("PIN error detected on incorrect message")
    dev[0].wait_disconnected(timeout=10)
    dev[0].request("WPS_CANCEL")
    # if a scan was in progress, wait for it to complete before trying WPS again
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)

    status = hapd.request("WPS_GET_STATUS")
    if "Last WPS result: Failed" not in status:
        raise Exception("WPS failure result not shown correctly")

    logger.info("WPS provisioning attempt 2")
    hapd.request("WPS_PIN any 12345670")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN %s 12344444" % apdev[0]['bssid'])
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=30)
    if ev is None:
        raise Exception("WPS operation timed out")
    if "config_error=18" not in ev:
        raise Exception("Incorrect config_error reported")
    if "msg=10" not in ev:
        raise Exception("PIN error detected on incorrect message")
    dev[0].wait_disconnected(timeout=10)

def test_ap_wps_conf_pin(dev, apdev):
    """WPS PIN provisioning with configured AP"""
    ssid = "test-wps-conf-pin"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    pin = dev[0].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    dev[0].wait_connected(timeout=30)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not cleared")
    logger.info("Try to connect from another station using the same PIN")
    pin = dev[1].request("WPS_PIN " + apdev[0]['bssid'])
    ev = dev[1].wait_event(["WPS-M2D","CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Operation timed out")
    if "WPS-M2D" not in ev:
        raise Exception("Unexpected WPS operation started")
    hapd.request("WPS_PIN any " + pin)
    dev[1].wait_connected(timeout=30)

def test_ap_wps_conf_pin_v1(dev, apdev):
    """WPS PIN provisioning with configured WPS v1.0 AP"""
    ssid = "test-wps-conf-pin-v1"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    pin = dev[0].wps_read_pin()
    hapd.request("SET wps_version_number 0x10")
    hapd.request("WPS_PIN any " + pin)
    found = False
    for i in range(0, 10):
        dev[0].scan(freq="2412")
        if "[WPS-PIN]" in dev[0].request("SCAN_RESULTS"):
            found = True
            break
    if not found:
        hapd.request("SET wps_version_number 0x20")
        raise Exception("WPS-PIN flag not seen in scan results")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    dev[0].wait_connected(timeout=30)
    hapd.request("SET wps_version_number 0x20")

def test_ap_wps_conf_pin_2sta(dev, apdev):
    """Two stations trying to use WPS PIN at the same time"""
    ssid = "test-wps-conf-pin2"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    pin = "12345670"
    pin2 = "55554444"
    hapd.request("WPS_PIN " + dev[0].get_status_field("uuid") + " " + pin)
    hapd.request("WPS_PIN " + dev[1].get_status_field("uuid") + " " + pin)
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    dev[1].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    dev[0].wait_connected(timeout=30)
    dev[1].wait_connected(timeout=30)

def test_ap_wps_conf_pin_timeout(dev, apdev):
    """WPS PIN provisioning with configured AP timing out PIN"""
    ssid = "test-wps-conf-pin"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    addr = dev[0].p2p_interface_addr()
    pin = dev[0].wps_read_pin()
    if "FAIL" not in hapd.request("WPS_PIN "):
        raise Exception("Unexpected success on invalid WPS_PIN")
    hapd.request("WPS_PIN any " + pin + " 1")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    time.sleep(1.1)
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = hapd.wait_event(["WPS-PIN-NEEDED"], timeout=20)
    if ev is None:
        raise Exception("WPS-PIN-NEEDED event timed out")
    ev = dev[0].wait_event(["WPS-M2D"])
    if ev is None:
        raise Exception("M2D not reported")
    dev[0].request("WPS_CANCEL")

    hapd.request("WPS_PIN any " + pin + " 20 " + addr)
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    dev[0].wait_connected(timeout=30)

def test_ap_wps_reg_connect(dev, apdev):
    """WPS registrar using AP PIN to connect"""
    ssid = "test-wps-reg-ap-pin"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "ap_pin": appin})
    logger.info("WPS provisioning step")
    dev[0].dump_monitor()
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].wps_reg(apdev[0]['bssid'], appin)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

def test_ap_wps_reg_connect_mixed_mode(dev, apdev):
    """WPS registrar using AP PIN to connect (WPA+WPA2)"""
    ssid = "test-wps-reg-ap-pin"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "3",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "wpa_pairwise": "TKIP", "ap_pin": appin})
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].wps_reg(apdev[0]['bssid'], appin)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'TKIP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

def check_wps_reg_failure(dev, ap, appin):
    dev.request("WPS_REG " + ap['bssid'] + " " + appin)
    ev = dev.wait_event(["WPS-SUCCESS", "WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS operation timed out")
    if "WPS-SUCCESS" in ev:
        raise Exception("WPS operation succeeded unexpectedly")
    if "config_error=15" not in ev:
        raise Exception("WPS setup locked state was not reported correctly")

def test_ap_wps_random_ap_pin(dev, apdev):
    """WPS registrar using random AP PIN"""
    ssid = "test-wps-reg-random-ap-pin"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     "config_methods": "label push_button",
                     "uuid": ap_uuid, "upnp_iface": "lo" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    appin = hapd.request("WPS_AP_PIN random")
    if "FAIL" in appin:
        raise Exception("Could not generate random AP PIN")
    if appin not in hapd.request("WPS_AP_PIN get"):
        raise Exception("Could not fetch current AP PIN")
    logger.info("WPS provisioning step")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].wps_reg(apdev[0]['bssid'], appin)

    hapd.request("WPS_AP_PIN disable")
    logger.info("WPS provisioning step with AP PIN disabled")
    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    check_wps_reg_failure(dev[1], apdev[0], appin)

    logger.info("WPS provisioning step with AP PIN reset")
    appin = "12345670"
    hapd.request("WPS_AP_PIN set " + appin)
    dev[1].wps_reg(apdev[0]['bssid'], appin)
    dev[0].request("REMOVE_NETWORK all")
    dev[1].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected(timeout=10)
    dev[1].wait_disconnected(timeout=10)

    logger.info("WPS provisioning step after AP PIN timeout")
    hapd.request("WPS_AP_PIN disable")
    appin = hapd.request("WPS_AP_PIN random 1")
    time.sleep(1.1)
    if "FAIL" not in hapd.request("WPS_AP_PIN get"):
        raise Exception("AP PIN unexpectedly still enabled")
    check_wps_reg_failure(dev[0], apdev[0], appin)

    logger.info("WPS provisioning step after AP PIN timeout(2)")
    hapd.request("WPS_AP_PIN disable")
    appin = "12345670"
    hapd.request("WPS_AP_PIN set " + appin + " 1")
    time.sleep(1.1)
    if "FAIL" not in hapd.request("WPS_AP_PIN get"):
        raise Exception("AP PIN unexpectedly still enabled")
    check_wps_reg_failure(dev[1], apdev[0], appin)

    with fail_test(hapd, 1, "os_get_random;wps_generate_pin"):
        if "FAIL" in hapd.request("WPS_AP_PIN random 1"):
            raise Exception("Failed to generate PIN during OOM")
        hapd.request("WPS_AP_PIN disable")

    with alloc_fail(hapd, 1, "upnp_wps_set_ap_pin"):
        hapd.request("WPS_AP_PIN set 12345670")
        hapd.request("WPS_AP_PIN disable")

def test_ap_wps_reg_config(dev, apdev):
    """WPS registrar configuring an AP using AP PIN"""
    ssid = "test-wps-init-ap-pin"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "ap_pin": appin})
    logger.info("WPS configuration step")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].dump_monitor()
    new_ssid = "wps-new-ssid"
    new_passphrase = "1234567890"
    dev[0].wps_reg(apdev[0]['bssid'], appin, new_ssid, "WPA2PSK", "CCMP",
                   new_passphrase)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != new_ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    logger.info("Re-configure back to open")
    dev[0].request("REMOVE_NETWORK all")
    dev[0].flush_scan_cache()
    dev[0].dump_monitor()
    dev[0].wps_reg(apdev[0]['bssid'], appin, "wps-open", "OPEN", "NONE", "")
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != "wps-open":
        raise Exception("Unexpected SSID")
    if status['key_mgmt'] != 'NONE':
        raise Exception("Unexpected key_mgmt")

def test_ap_wps_reg_config_ext_processing(dev, apdev):
    """WPS registrar configuring an AP with external config processing"""
    ssid = "test-wps-init-ap-pin"
    appin = "12345670"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wps_cred_processing": "1", "ap_pin": appin}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    new_ssid = "wps-new-ssid"
    new_passphrase = "1234567890"
    dev[0].wps_reg(apdev[0]['bssid'], appin, new_ssid, "WPA2PSK", "CCMP",
                   new_passphrase, no_wait=True)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS registrar operation timed out")
    ev = hapd.wait_event(["WPS-NEW-AP-SETTINGS"], timeout=15)
    if ev is None:
        raise Exception("WPS configuration timed out")
    if "1026" not in ev:
        raise Exception("AP Settings missing from event")
    hapd.request("SET wps_cred_processing 0")
    if "FAIL" in hapd.request("WPS_CONFIG " + new_ssid.encode("hex") + " WPA2PSK CCMP " + new_passphrase.encode("hex")):
        raise Exception("WPS_CONFIG command failed")
    dev[0].wait_connected(timeout=15)

def test_ap_wps_reg_config_tkip(dev, apdev):
    """WPS registrar configuring AP to use TKIP and AP upgrading to TKIP+CCMP"""
    skip_with_fips(dev[0])
    ssid = "test-wps-init-ap"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1",
                     "ap_pin": appin})
    logger.info("WPS configuration step")
    dev[0].request("SET wps_version_number 0x10")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].dump_monitor()
    new_ssid = "wps-new-ssid-with-tkip"
    new_passphrase = "1234567890"
    dev[0].wps_reg(apdev[0]['bssid'], appin, new_ssid, "WPAPSK", "TKIP",
                   new_passphrase)
    logger.info("Re-connect to verify WPA2 mixed mode")
    dev[0].request("DISCONNECT")
    id = 0
    dev[0].set_network(id, "pairwise", "CCMP")
    dev[0].set_network(id, "proto", "RSN")
    dev[0].connect_network(id)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected: wpa_state={} bssid={}".format(status['wpa_state'], status['bssid']))
    if status['ssid'] != new_ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'TKIP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

def test_ap_wps_setup_locked(dev, apdev):
    """WPS registrar locking up AP setup on AP PIN failures"""
    ssid = "test-wps-incorrect-ap-pin"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "ap_pin": appin})
    new_ssid = "wps-new-ssid-test"
    new_passphrase = "1234567890"

    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    ap_setup_locked=False
    for pin in ["55554444", "1234", "12345678", "00000000", "11111111"]:
        dev[0].dump_monitor()
        logger.info("Try incorrect AP PIN - attempt " + pin)
        dev[0].wps_reg(apdev[0]['bssid'], pin, new_ssid, "WPA2PSK",
                       "CCMP", new_passphrase, no_wait=True)
        ev = dev[0].wait_event(["WPS-FAIL", "CTRL-EVENT-CONNECTED"])
        if ev is None:
            raise Exception("Timeout on receiving WPS operation failure event")
        if "CTRL-EVENT-CONNECTED" in ev:
            raise Exception("Unexpected connection")
        if "config_error=15" in ev:
            logger.info("AP Setup Locked")
            ap_setup_locked=True
        elif "config_error=18" not in ev:
            raise Exception("config_error=18 not reported")
        dev[0].wait_disconnected(timeout=10)
        time.sleep(0.1)
    if not ap_setup_locked:
        raise Exception("AP setup was not locked")
    dev[0].request("WPS_CANCEL")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412, force_scan=True,
                        only_new=True)
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if 'wps_ap_setup_locked' not in bss or bss['wps_ap_setup_locked'] != '1':
        logger.info("BSS: " + str(bss))
        raise Exception("AP Setup Locked not indicated in scan results")

    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    status = hapd.request("WPS_GET_STATUS")
    if "Last WPS result: Failed" not in status:
        raise Exception("WPS failure result not shown correctly")
    if "Peer Address: " + dev[0].p2p_interface_addr() not in status:
        raise Exception("Peer address not shown correctly")

    time.sleep(0.5)
    dev[0].dump_monitor()
    logger.info("WPS provisioning step")
    pin = dev[0].wps_read_pin()
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("WPS_PIN any " + pin)
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=30)
    if ev is None:
        raise Exception("WPS success was not reported")
    dev[0].wait_connected(timeout=30)

    appin = hapd.request("WPS_AP_PIN random")
    if "FAIL" in appin:
        raise Exception("Could not generate random AP PIN")
    ev = hapd.wait_event(["WPS-AP-SETUP-UNLOCKED"], timeout=10)
    if ev is None:
        raise Exception("Failed to unlock AP PIN")

def test_ap_wps_setup_locked_timeout(dev, apdev):
    """WPS re-enabling AP PIN after timeout"""
    ssid = "test-wps-incorrect-ap-pin"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "ap_pin": appin})
    new_ssid = "wps-new-ssid-test"
    new_passphrase = "1234567890"

    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    ap_setup_locked=False
    for pin in ["55554444", "1234", "12345678", "00000000", "11111111"]:
        dev[0].dump_monitor()
        logger.info("Try incorrect AP PIN - attempt " + pin)
        dev[0].wps_reg(apdev[0]['bssid'], pin, new_ssid, "WPA2PSK",
                       "CCMP", new_passphrase, no_wait=True)
        ev = dev[0].wait_event(["WPS-FAIL", "CTRL-EVENT-CONNECTED"], timeout=15)
        if ev is None:
            raise Exception("Timeout on receiving WPS operation failure event")
        if "CTRL-EVENT-CONNECTED" in ev:
            raise Exception("Unexpected connection")
        if "config_error=15" in ev:
            logger.info("AP Setup Locked")
            ap_setup_locked=True
            break
        elif "config_error=18" not in ev:
            raise Exception("config_error=18 not reported")
        dev[0].wait_disconnected(timeout=10)
        time.sleep(0.1)
    if not ap_setup_locked:
        raise Exception("AP setup was not locked")
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    ev = hapd.wait_event(["WPS-AP-SETUP-UNLOCKED"], timeout=80)
    if ev is None:
        raise Exception("AP PIN did not get unlocked on 60 second timeout")

def test_ap_wps_pbc_overlap_2ap(dev, apdev):
    """WPS PBC session overlap with two active APs"""
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": "wps1", "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "wps_independent": "1"})
    hostapd.add_ap(apdev[1]['ifname'],
                   { "ssid": "wps2", "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "123456789", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "wps_independent": "1"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("WPS_PBC")
    hapd2 = hostapd.Hostapd(apdev[1]['ifname'])
    hapd2.request("WPS_PBC")
    logger.info("WPS provisioning step")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["WPS-OVERLAP-DETECTED"], timeout=15)
    if ev is None:
        raise Exception("PBC session overlap not detected")
    hapd.request("DISABLE")
    hapd2.request("DISABLE")
    dev[0].flush_scan_cache()

def test_ap_wps_pbc_overlap_2sta(dev, apdev):
    """WPS PBC session overlap with two active STAs"""
    ssid = "test-wps-pbc-overlap"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[1].dump_monitor()
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[1].request("WPS_PBC " + apdev[0]['bssid'])
    ev = dev[0].wait_event(["WPS-M2D"], timeout=15)
    if ev is None:
        raise Exception("PBC session overlap not detected (dev0)")
    if "config_error=12" not in ev:
        raise Exception("PBC session overlap not correctly reported (dev0)")
    dev[0].request("WPS_CANCEL")
    dev[0].request("DISCONNECT")
    ev = dev[1].wait_event(["WPS-M2D"], timeout=15)
    if ev is None:
        raise Exception("PBC session overlap not detected (dev1)")
    if "config_error=12" not in ev:
        raise Exception("PBC session overlap not correctly reported (dev1)")
    dev[1].request("WPS_CANCEL")
    dev[1].request("DISCONNECT")
    hapd.request("WPS_CANCEL")
    ret = hapd.request("WPS_PBC")
    if "FAIL" not in ret:
        raise Exception("PBC mode allowed to be started while PBC overlap still active")
    hapd.request("DISABLE")
    dev[0].flush_scan_cache()
    dev[1].flush_scan_cache()

def test_ap_wps_cancel(dev, apdev):
    """WPS AP cancelling enabled config method"""
    ssid = "test-wps-ap-cancel"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" })
    bssid = apdev[0]['bssid']
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    logger.info("Verify PBC enable/cancel")
    hapd.request("WPS_PBC")
    dev[0].scan(freq="2412")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" not in bss['flags']:
        raise Exception("WPS-PBC flag missing")
    if "FAIL" in hapd.request("WPS_CANCEL"):
        raise Exception("WPS_CANCEL failed")
    dev[0].scan(freq="2412")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" in bss['flags']:
        raise Exception("WPS-PBC flag not cleared")

    logger.info("Verify PIN enable/cancel")
    hapd.request("WPS_PIN any 12345670")
    dev[0].scan(freq="2412")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" not in bss['flags']:
        raise Exception("WPS-AUTH flag missing")
    if "FAIL" in hapd.request("WPS_CANCEL"):
        raise Exception("WPS_CANCEL failed")
    dev[0].scan(freq="2412")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not cleared")

def test_ap_wps_er_add_enrollee(dev, apdev):
    """WPS ER configuring AP and adding a new enrollee using PIN"""
    try:
        _test_ap_wps_er_add_enrollee(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_add_enrollee(dev, apdev):
    ssid = "wps-er-add-enrollee"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     'friendly_name': "WPS AP - <>&'\" - TEST",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})
    logger.info("WPS configuration step")
    new_passphrase = "1234567890"
    dev[0].dump_monitor()
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].wps_reg(apdev[0]['bssid'], ap_pin, ssid, "WPA2PSK", "CCMP",
                   new_passphrase)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    logger.info("Start ER")
    dev[0].request("WPS_ER_START ifname=lo")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found")
    if "|WPS AP - &lt;&gt;&amp;&apos;&quot; - TEST|Company|" not in ev:
        raise Exception("Expected friendly name not found")

    logger.info("Learn AP configuration through UPnP")
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_LEARN " + ap_uuid + " " + ap_pin)
    ev = dev[0].wait_event(["WPS-ER-AP-SETTINGS"], timeout=15)
    if ev is None:
        raise Exception("AP learn timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not in settings")
    if "ssid=" + ssid not in ev:
        raise Exception("Expected SSID not in settings")
    if "key=" + new_passphrase not in ev:
        raise Exception("Expected passphrase not in settings")
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS-FAIL after AP learn timed out")
    time.sleep(0.1)

    logger.info("Add Enrollee using ER")
    pin = dev[1].wps_read_pin()
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_PIN any " + pin + " " + dev[1].p2p_interface_addr())
    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[1].dump_monitor()
    dev[1].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[1].wait_event(["WPS-SUCCESS"], timeout=30)
    if ev is None:
        raise Exception("Enrollee did not report success")
    dev[1].wait_connected(timeout=15)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

    logger.info("Add a specific Enrollee using ER")
    pin = dev[2].wps_read_pin()
    addr2 = dev[2].p2p_interface_addr()
    dev[0].dump_monitor()
    dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[2].dump_monitor()
    dev[2].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=10)
    if ev is None:
        raise Exception("Enrollee not seen")
    if addr2 not in ev:
        raise Exception("Unexpected Enrollee MAC address")
    dev[0].request("WPS_ER_PIN " + addr2 + " " + pin + " " + addr2)
    dev[2].wait_connected(timeout=30)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")

    logger.info("Verify registrar selection behavior")
    dev[0].request("WPS_ER_PIN any " + pin + " " + dev[1].p2p_interface_addr())
    dev[1].request("DISCONNECT")
    dev[1].wait_disconnected(timeout=10)
    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[1].scan(freq="2412")
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" not in bss['flags']:
        # It is possible for scan to miss an update especially when running
        # tests under load with multiple VMs, so allow another attempt.
        dev[1].scan(freq="2412")
        bss = dev[1].get_bss(apdev[0]['bssid'])
        if "[WPS-AUTH]" not in bss['flags']:
            raise Exception("WPS-AUTH flag missing")

    logger.info("Stop ER")
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_STOP")
    ev = dev[0].wait_event(["WPS-ER-AP-REMOVE"])
    if ev is None:
        raise Exception("WPS ER unsubscription timed out")
    # It takes some time for the UPnP UNSUBSCRIBE command to go through, so wait
    # a bit before verifying that the scan results have changed.
    time.sleep(0.2)

    for i in range(0, 10):
        dev[1].request("BSS_FLUSH 0")
        dev[1].scan(freq="2412", only_new=True)
        bss = dev[1].get_bss(apdev[0]['bssid'])
        if bss and 'flags' in bss and "[WPS-AUTH]" not in bss['flags']:
            break
        logger.debug("WPS-AUTH flag was still in place - wait a bit longer")
        time.sleep(0.1)
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not removed")

def test_ap_wps_er_add_enrollee_uuid(dev, apdev):
    """WPS ER adding a new enrollee identified by UUID"""
    try:
        _test_ap_wps_er_add_enrollee_uuid(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_add_enrollee_uuid(dev, apdev):
    ssid = "wps-er-add-enrollee"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})
    logger.info("WPS configuration step")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].wps_reg(apdev[0]['bssid'], ap_pin)

    logger.info("Start ER")
    dev[0].request("WPS_ER_START ifname=lo")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found")

    logger.info("Learn AP configuration through UPnP")
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_LEARN " + ap_uuid + " " + ap_pin)
    ev = dev[0].wait_event(["WPS-ER-AP-SETTINGS"], timeout=15)
    if ev is None:
        raise Exception("AP learn timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not in settings")
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS-FAIL after AP learn timed out")
    time.sleep(0.1)

    logger.info("Add a specific Enrollee using ER (PBC/UUID)")
    addr1 = dev[1].p2p_interface_addr()
    dev[0].dump_monitor()
    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[1].dump_monitor()
    dev[1].request("WPS_PBC %s" % apdev[0]['bssid'])
    ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=10)
    if ev is None:
        raise Exception("Enrollee not seen")
    if addr1 not in ev:
        raise Exception("Unexpected Enrollee MAC address")
    uuid = ev.split(' ')[1]
    dev[0].request("WPS_ER_PBC " + uuid)
    dev[1].wait_connected(timeout=30)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")

    logger.info("Add a specific Enrollee using ER (PIN/UUID)")
    pin = dev[2].wps_read_pin()
    addr2 = dev[2].p2p_interface_addr()
    dev[0].dump_monitor()
    dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[2].dump_monitor()
    dev[2].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=10)
    if ev is None:
        raise Exception("Enrollee not seen")
    if addr2 not in ev:
        raise Exception("Unexpected Enrollee MAC address")
    uuid = ev.split(' ')[1]
    dev[0].request("WPS_ER_PIN " + uuid + " " + pin)
    dev[2].wait_connected(timeout=30)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")

    ev = dev[0].wait_event(["WPS-ER-ENROLLEE-REMOVE"], timeout=15)
    if ev is None:
        raise Exception("No Enrollee STA entry timeout seen")

    logger.info("Stop ER")
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_STOP")

def test_ap_wps_er_multi_add_enrollee(dev, apdev):
    """Multiple WPS ERs adding a new enrollee using PIN"""
    try:
        _test_ap_wps_er_multi_add_enrollee(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_multi_add_enrollee(dev, apdev):
    ssid = "wps-er-add-enrollee"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     'friendly_name': "WPS AP",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})

    for i in range(2):
        dev[i].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[i].wps_reg(apdev[0]['bssid'], ap_pin)
        dev[i].request("WPS_ER_START ifname=lo")
    for i in range(2):
        ev = dev[i].wait_event(["WPS-ER-AP-ADD"], timeout=15)
        if ev is None:
            raise Exception("AP discovery timed out")
        dev[i].dump_monitor()
        dev[i].request("WPS_ER_LEARN " + ap_uuid + " " + ap_pin)
        ev = dev[i].wait_event(["WPS-ER-AP-SETTINGS"], timeout=15)
        if ev is None:
            raise Exception("AP learn timed out")
        ev = dev[i].wait_event(["WPS-FAIL"], timeout=15)
        if ev is None:
            raise Exception("WPS-FAIL after AP learn timed out")

    time.sleep(0.1)

    pin = dev[2].wps_read_pin()
    addr = dev[2].own_addr()
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_PIN any " + pin + " " + addr)
    dev[1].dump_monitor()
    dev[1].request("WPS_ER_PIN any " + pin + " " + addr)

    dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[2].dump_monitor()
    dev[2].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[2].wait_event(["WPS-SUCCESS"], timeout=30)
    if ev is None:
        raise Exception("Enrollee did not report success")
    dev[2].wait_connected(timeout=15)

def test_ap_wps_er_add_enrollee_pbc(dev, apdev):
    """WPS ER connected to AP and adding a new enrollee using PBC"""
    try:
        _test_ap_wps_er_add_enrollee_pbc(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_add_enrollee_pbc(dev, apdev):
    ssid = "wps-er-add-enrollee-pbc"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})
    logger.info("Learn AP configuration")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].dump_monitor()
    dev[0].wps_reg(apdev[0]['bssid'], ap_pin)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")

    logger.info("Start ER")
    dev[0].request("WPS_ER_START ifname=lo")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found")

    enrollee = dev[1].p2p_interface_addr()

    if "FAIL-UNKNOWN-UUID" not in dev[0].request("WPS_ER_PBC " + enrollee):
        raise Exception("Unknown UUID not reported")

    logger.info("Add Enrollee using ER and PBC")
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    dev[1].request("WPS_PBC")

    for i in range(0, 2):
        ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=15)
        if ev is None:
            raise Exception("Enrollee discovery timed out")
        if enrollee in ev:
            break
        if i == 1:
            raise Exception("Expected Enrollee not found")
    if "FAIL-NO-AP-SETTINGS" not in dev[0].request("WPS_ER_PBC " + enrollee):
        raise Exception("Unknown UUID not reported")
    logger.info("Use learned network configuration on ER")
    dev[0].request("WPS_ER_SET_CONFIG " + ap_uuid + " 0")
    if "OK" not in dev[0].request("WPS_ER_PBC " + enrollee):
        raise Exception("WPS_ER_PBC failed")

    ev = dev[1].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("Enrollee did not report success")
    dev[1].wait_connected(timeout=15)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

def test_ap_wps_er_pbc_overlap(dev, apdev):
    """WPS ER connected to AP and PBC session overlap"""
    try:
        _test_ap_wps_er_pbc_overlap(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_pbc_overlap(dev, apdev):
    ssid = "wps-er-add-enrollee-pbc"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].dump_monitor()
    dev[0].wps_reg(apdev[0]['bssid'], ap_pin)

    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[2].scan_for_bss(apdev[0]['bssid'], freq="2412")
    # avoid leaving dev 1 or 2 as the last Probe Request to the AP
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412, force_scan=True)

    dev[0].dump_monitor()
    dev[0].request("WPS_ER_START ifname=lo")

    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found")

    # verify BSSID selection of the AP instead of UUID
    if "FAIL" in dev[0].request("WPS_ER_SET_CONFIG " + apdev[0]['bssid'] + " 0"):
        raise Exception("Could not select AP based on BSSID")

    dev[0].dump_monitor()
    dev[1].request("WPS_PBC " + apdev[0]['bssid'])
    dev[2].request("WPS_PBC " + apdev[0]['bssid'])
    ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=10)
    if ev is None:
        raise Exception("PBC scan failed")
    ev = dev[2].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=10)
    if ev is None:
        raise Exception("PBC scan failed")
    found1 = False
    found2 = False
    addr1 = dev[1].own_addr()
    addr2 = dev[2].own_addr()
    for i in range(3):
        ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=15)
        if ev is None:
            raise Exception("Enrollee discovery timed out")
        if addr1 in ev:
            found1 = True
            if found2:
                break
        if addr2 in ev:
            found2 = True
            if found1:
                break
    if dev[0].request("WPS_ER_PBC " + ap_uuid) != "FAIL-PBC-OVERLAP\n":
        raise Exception("PBC overlap not reported")
    dev[1].request("WPS_CANCEL")
    dev[2].request("WPS_CANCEL")
    if dev[0].request("WPS_ER_PBC foo") != "FAIL\n":
        raise Exception("Invalid WPS_ER_PBC accepted")

def test_ap_wps_er_v10_add_enrollee_pin(dev, apdev):
    """WPS v1.0 ER connected to AP and adding a new enrollee using PIN"""
    try:
        _test_ap_wps_er_v10_add_enrollee_pin(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_v10_add_enrollee_pin(dev, apdev):
    ssid = "wps-er-add-enrollee-pbc"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})
    logger.info("Learn AP configuration")
    dev[0].request("SET wps_version_number 0x10")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].dump_monitor()
    dev[0].wps_reg(apdev[0]['bssid'], ap_pin)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")

    logger.info("Start ER")
    dev[0].request("WPS_ER_START ifname=lo")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found")

    logger.info("Use learned network configuration on ER")
    dev[0].request("WPS_ER_SET_CONFIG " + ap_uuid + " 0")

    logger.info("Add Enrollee using ER and PIN")
    enrollee = dev[1].p2p_interface_addr()
    pin = dev[1].wps_read_pin()
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_PIN any " + pin + " " + enrollee)
    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[1].dump_monitor()
    dev[1].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    dev[1].wait_connected(timeout=30)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")

def test_ap_wps_er_config_ap(dev, apdev):
    """WPS ER configuring AP over UPnP"""
    try:
        _test_ap_wps_er_config_ap(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_config_ap(dev, apdev):
    ssid = "wps-er-ap-config"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})

    logger.info("Connect ER to the AP")
    dev[0].connect(ssid, psk="12345678", scan_freq="2412")

    logger.info("WPS configuration step")
    dev[0].request("WPS_ER_START ifname=lo")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found")
    new_passphrase = "1234567890"
    dev[0].request("WPS_ER_CONFIG " + apdev[0]['bssid'] + " " + ap_pin + " " +
                   ssid.encode("hex") + " WPA2PSK CCMP " +
                   new_passphrase.encode("hex"))
    ev = dev[0].wait_event(["WPS-SUCCESS"])
    if ev is None:
        raise Exception("WPS ER configuration operation timed out")
    dev[0].wait_disconnected(timeout=10)
    dev[0].connect(ssid, psk="1234567890", scan_freq="2412")

    logger.info("WPS ER restart")
    dev[0].request("WPS_ER_START")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out on ER restart")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found on ER restart")
    if "OK" not in dev[0].request("WPS_ER_STOP"):
        raise Exception("WPS_ER_STOP failed")
    if "OK" not in dev[0].request("WPS_ER_STOP"):
        raise Exception("WPS_ER_STOP failed")

def test_ap_wps_er_cache_ap_settings(dev, apdev):
    """WPS ER caching AP settings"""
    try:
        _test_ap_wps_er_cache_ap_settings(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_cache_ap_settings(dev, apdev):
    ssid = "wps-er-add-enrollee"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
               "device_name": "Wireless AP", "manufacturer": "Company",
               "model_name": "WAP", "model_number": "123",
               "serial_number": "12345", "device_type": "6-0050F204-1",
               "os_version": "01020300",
               "config_methods": "label push_button",
               "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].wps_reg(apdev[0]['bssid'], ap_pin)
    id = int(dev[0].list_networks()[0]['id'])
    dev[0].set_network(id, "scan_freq", "2412")

    dev[0].request("WPS_ER_START ifname=lo")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=15)
    if ev is None:
        raise Exception("AP discovery timed out")
    if ap_uuid not in ev:
        raise Exception("Expected AP UUID not found")

    dev[0].dump_monitor()
    dev[0].request("WPS_ER_LEARN " + ap_uuid + " " + ap_pin)
    ev = dev[0].wait_event(["WPS-ER-AP-SETTINGS"], timeout=15)
    if ev is None:
        raise Exception("AP learn timed out")
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS-FAIL after AP learn timed out")
    time.sleep(0.1)

    hapd.disable()

    for i in range(2):
        ev = dev[0].wait_event([ "WPS-ER-AP-REMOVE",
                                 "CTRL-EVENT-DISCONNECTED" ],
                               timeout=15)
        if ev is None:
            raise Exception("AP removal or disconnection timed out")

    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    for i in range(2):
        ev = dev[0].wait_event([ "WPS-ER-AP-ADD", "CTRL-EVENT-CONNECTED" ],
                               timeout=15)
        if ev is None:
            raise Exception("AP discovery or connection timed out")

    pin = dev[1].wps_read_pin()
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_PIN any " + pin + " " + dev[1].p2p_interface_addr())

    time.sleep(0.2)

    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[1].dump_monitor()
    dev[1].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[1].wait_event(["WPS-SUCCESS"], timeout=30)
    if ev is None:
        raise Exception("Enrollee did not report success")
    dev[1].wait_connected(timeout=15)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")

    dev[0].dump_monitor()
    dev[0].request("WPS_ER_STOP")

def test_ap_wps_fragmentation(dev, apdev):
    """WPS with fragmentation in EAP-WSC and mixed mode WPA+WPA2"""
    ssid = "test-wps-fragmentation"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "3",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "wpa_pairwise": "TKIP", "ap_pin": appin,
                     "fragment_size": "50" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step (PBC)")
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].dump_monitor()
    dev[0].request("SET wps_fragment_size 50")
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED':
        raise Exception("Not fully connected")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'TKIP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    logger.info("WPS provisioning step (PIN)")
    pin = dev[1].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[1].request("SET wps_fragment_size 50")
    dev[1].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    dev[1].wait_connected(timeout=30)
    status = dev[1].get_status()
    if status['wpa_state'] != 'COMPLETED':
        raise Exception("Not fully connected")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'TKIP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    logger.info("WPS connection as registrar")
    dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[2].request("SET wps_fragment_size 50")
    dev[2].wps_reg(apdev[0]['bssid'], appin)
    status = dev[2].get_status()
    if status['wpa_state'] != 'COMPLETED':
        raise Exception("Not fully connected")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'TKIP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

def test_ap_wps_new_version_sta(dev, apdev):
    """WPS compatibility with new version number on the station"""
    ssid = "test-wps-ver"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[0].request("SET wps_version_number 0x43")
    dev[0].request("SET wps_vendor_ext_m1 000137100100020001")
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)

def test_ap_wps_new_version_ap(dev, apdev):
    """WPS compatibility with new version number on the AP"""
    ssid = "test-wps-ver"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    if "FAIL" in hapd.request("SET wps_version_number 0x43"):
        raise Exception("Failed to enable test functionality")
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)
    hapd.request("SET wps_version_number 0x20")

def test_ap_wps_check_pin(dev, apdev):
    """Verify PIN checking through control interface"""
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": "wps", "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    for t in [ ("12345670", "12345670"),
               ("12345678", "FAIL-CHECKSUM"),
               ("12345", "FAIL"),
               ("123456789", "FAIL"),
               ("1234-5670", "12345670"),
               ("1234 5670", "12345670"),
               ("1-2.3:4 5670", "12345670") ]:
        res = hapd.request("WPS_CHECK_PIN " + t[0]).rstrip('\n')
        res2 = dev[0].request("WPS_CHECK_PIN " + t[0]).rstrip('\n')
        if res != res2:
            raise Exception("Unexpected difference in WPS_CHECK_PIN responses")
        if res != t[1]:
            raise Exception("Incorrect WPS_CHECK_PIN response {} (expected {})".format(res, t[1]))

    if "FAIL" not in hapd.request("WPS_CHECK_PIN 12345"):
        raise Exception("Unexpected WPS_CHECK_PIN success")
    if "FAIL" not in hapd.request("WPS_CHECK_PIN 123456789"):
        raise Exception("Unexpected WPS_CHECK_PIN success")

    for i in range(0, 10):
        pin = dev[0].request("WPS_PIN get")
        rpin = dev[0].request("WPS_CHECK_PIN " + pin).rstrip('\n')
        if pin != rpin:
            raise Exception("Random PIN validation failed for " + pin)

def test_ap_wps_wep_config(dev, apdev):
    """WPS 2.0 AP rejecting WEP configuration"""
    ssid = "test-wps-config"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "ap_pin": appin})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].wps_reg(apdev[0]['bssid'], appin, "wps-new-ssid-wep", "OPEN", "WEP",
                   "hello", no_wait=True)
    ev = hapd.wait_event(["WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS-FAIL timed out")
    if "reason=2" not in ev:
        raise Exception("Unexpected reason code in WPS-FAIL")
    status = hapd.request("WPS_GET_STATUS")
    if "Last WPS result: Failed" not in status:
        raise Exception("WPS failure result not shown correctly")
    if "Failure Reason: WEP Prohibited" not in status:
        raise Exception("Failure reason not reported correctly")
    if "Peer Address: " + dev[0].p2p_interface_addr() not in status:
        raise Exception("Peer address not shown correctly")

def test_ap_wps_wep_enroll(dev, apdev):
    """WPS 2.0 STA rejecting WEP configuration"""
    ssid = "test-wps-wep"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "skip_cred_build": "1", "extra_cred": "wps-wep-cred" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS-FAIL event timed out")
    if "msg=12" not in ev or "reason=2 (WEP Prohibited)" not in ev:
        raise Exception("Unexpected WPS-FAIL event: " + ev)

def test_ap_wps_ie_fragmentation(dev, apdev):
    """WPS AP using fragmented WPS IE"""
    ssid = "test-wps-ie-fragmentation"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
               "device_name": "1234567890abcdef1234567890abcdef",
               "manufacturer": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
               "model_name": "1234567890abcdef1234567890abcdef",
               "model_number": "1234567890abcdef1234567890abcdef",
               "serial_number": "1234567890abcdef1234567890abcdef" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "wps_device_name" not in bss or bss['wps_device_name'] != "1234567890abcdef1234567890abcdef":
        logger.info("Device Name not received correctly")
        logger.info(bss)
        # This can fail if Probe Response frame is missed and Beacon frame was
        # used to fill in the BSS entry. This can happen, e.g., during heavy
        # load every now and then and is not really an error, so try to
        # workaround by runnign another scan.
        dev[0].scan(freq="2412", only_new=True)
        bss = dev[0].get_bss(apdev[0]['bssid'])
        if not bss or "wps_device_name" not in bss or bss['wps_device_name'] != "1234567890abcdef1234567890abcdef":
            logger.info(bss)
            raise Exception("Device Name not received correctly")
    if len(re.findall("dd..0050f204", bss['ie'])) != 2:
        raise Exception("Unexpected number of WPS IEs")

def get_psk(pskfile):
    psks = {}
    with open(pskfile, "r") as f:
        lines = f.read().splitlines()
        for l in lines:
            if l == "# WPA PSKs":
                continue
            (addr,psk) = l.split(' ')
            psks[addr] = psk
    return psks

def test_ap_wps_per_station_psk(dev, apdev):
    """WPS PBC provisioning with per-station PSK"""
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    addr2 = dev[2].own_addr()
    ssid = "wps"
    appin = "12345670"
    pskfile = "/tmp/ap_wps_per_enrollee_psk.psk_file"
    try:
        os.remove(pskfile)
    except:
        pass

    try:
        with open(pskfile, "w") as f:
            f.write("# WPA PSKs\n")

        params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                   "wpa": "2", "wpa_key_mgmt": "WPA-PSK",
                   "rsn_pairwise": "CCMP", "ap_pin": appin,
                   "wpa_psk_file": pskfile }
        hapd = hostapd.add_ap(apdev[0]['ifname'], params)

        logger.info("First enrollee")
        hapd.request("WPS_PBC")
        dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[0].request("WPS_PBC " + apdev[0]['bssid'])
        dev[0].wait_connected(timeout=30)

        logger.info("Second enrollee")
        hapd.request("WPS_PBC")
        dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[1].request("WPS_PBC " + apdev[0]['bssid'])
        dev[1].wait_connected(timeout=30)

        logger.info("External registrar")
        dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[2].wps_reg(apdev[0]['bssid'], appin)

        logger.info("Verifying PSK results")
        psks = get_psk(pskfile)
        if addr0 not in psks:
            raise Exception("No PSK recorded for sta0")
        if addr1 not in psks:
            raise Exception("No PSK recorded for sta1")
        if addr2 not in psks:
            raise Exception("No PSK recorded for sta2")
        if psks[addr0] == psks[addr1]:
            raise Exception("Same PSK recorded for sta0 and sta1")
        if psks[addr0] == psks[addr2]:
            raise Exception("Same PSK recorded for sta0 and sta2")
        if psks[addr1] == psks[addr2]:
            raise Exception("Same PSK recorded for sta1 and sta2")

        dev[0].request("REMOVE_NETWORK all")
        logger.info("Second external registrar")
        dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[0].wps_reg(apdev[0]['bssid'], appin)
        psks2 = get_psk(pskfile)
        if addr0 not in psks2:
            raise Exception("No PSK recorded for sta0(reg)")
        if psks[addr0] == psks2[addr0]:
            raise Exception("Same PSK recorded for sta0(enrollee) and sta0(reg)")
    finally:
        os.remove(pskfile)

def test_ap_wps_per_station_psk_failure(dev, apdev):
    """WPS PBC provisioning with per-station PSK (file not writable)"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()
    ssid = "wps"
    appin = "12345670"
    pskfile = "/tmp/ap_wps_per_enrollee_psk.psk_file"
    try:
        os.remove(pskfile)
    except:
        pass

    try:
        with open(pskfile, "w") as f:
            f.write("# WPA PSKs\n")

        params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                   "wpa": "2", "wpa_key_mgmt": "WPA-PSK",
                   "rsn_pairwise": "CCMP", "ap_pin": appin,
                   "wpa_psk_file": pskfile }
        hapd = hostapd.add_ap(apdev[0]['ifname'], params)
        if "FAIL" in hapd.request("SET wpa_psk_file /tmp/does/not/exists/ap_wps_per_enrollee_psk_failure.psk_file"):
            raise Exception("Failed to set wpa_psk_file")

        logger.info("First enrollee")
        hapd.request("WPS_PBC")
        dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[0].request("WPS_PBC " + apdev[0]['bssid'])
        dev[0].wait_connected(timeout=30)

        logger.info("Second enrollee")
        hapd.request("WPS_PBC")
        dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[1].request("WPS_PBC " + apdev[0]['bssid'])
        dev[1].wait_connected(timeout=30)

        logger.info("External registrar")
        dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
        dev[2].wps_reg(apdev[0]['bssid'], appin)

        logger.info("Verifying PSK results")
        psks = get_psk(pskfile)
        if len(psks) > 0:
            raise Exception("PSK recorded unexpectedly")
    finally:
        os.remove(pskfile)

def test_ap_wps_pin_request_file(dev, apdev):
    """WPS PIN provisioning with configured AP"""
    ssid = "wps"
    pinfile = "/tmp/ap_wps_pin_request_file.log"
    if os.path.exists(pinfile):
        os.remove(pinfile)
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wps_pin_requests": pinfile,
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    uuid = dev[0].get_status_field("uuid")
    pin = dev[0].wps_read_pin()
    try:
        dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        ev = hapd.wait_event(["WPS-PIN-NEEDED"], timeout=15)
        if ev is None:
            raise Exception("PIN needed event not shown")
        if uuid not in ev:
            raise Exception("UUID mismatch")
        dev[0].request("WPS_CANCEL")
        success = False
        with open(pinfile, "r") as f:
            lines = f.readlines()
            for l in lines:
                if uuid in l:
                    success = True
                    break
        if not success:
            raise Exception("PIN request entry not in the log file")
    finally:
        try:
            os.remove(pinfile)
        except:
            pass

def test_ap_wps_auto_setup_with_config_file(dev, apdev):
    """WPS auto-setup with configuration file"""
    conffile = "/tmp/ap_wps_auto_setup_with_config_file.conf"
    ifname = apdev[0]['ifname']
    try:
        with open(conffile, "w") as f:
            f.write("driver=nl80211\n")
            f.write("hw_mode=g\n")
            f.write("channel=1\n")
            f.write("ieee80211n=1\n")
            f.write("interface=%s\n" % ifname)
            f.write("ctrl_interface=/var/run/hostapd\n")
            f.write("ssid=wps\n")
            f.write("eap_server=1\n")
            f.write("wps_state=1\n")
        hostapd.add_bss('phy3', ifname, conffile)
        hapd = hostapd.Hostapd(ifname)
        hapd.request("WPS_PBC")
        dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
        dev[0].request("WPS_PBC " + apdev[0]['bssid'])
        dev[0].wait_connected(timeout=30)
        with open(conffile, "r") as f:
            lines = f.read().splitlines()
            vals = dict()
            for l in lines:
                try:
                    [name,value] = l.split('=', 1)
                    vals[name] = value
                except ValueError, e:
                    if "# WPS configuration" in l:
                        pass
                    else:
                        raise Exception("Unexpected configuration line: " + l)
        if vals['ieee80211n'] != '1' or vals['wps_state'] != '2' or "WPA-PSK" not in vals['wpa_key_mgmt']:
            raise Exception("Incorrect configuration: " + str(vals))
    finally:
        try:
            os.remove(conffile)
        except:
            pass

def test_ap_wps_pbc_timeout(dev, apdev, params):
    """wpa_supplicant PBC walk time and WPS ER SelReg timeout [long]"""
    if not params['long']:
        raise HwsimSkip("Skip test case with long duration due to --long not specified")
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hapd = add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)
    urls = upnp_get_urls(location)
    eventurl = urlparse.urlparse(urls['event_sub_url'])
    ctrlurl = urlparse.urlparse(urls['control_url'])

    url = urlparse.urlparse(location)
    conn = httplib.HTTPConnection(url.netloc)

    class WPSERHTTPServer(SocketServer.StreamRequestHandler):
        def handle(self):
            data = self.rfile.readline().strip()
            logger.debug(data)
            self.wfile.write(gen_wps_event())

    server = MyTCPServer(("127.0.0.1", 12345), WPSERHTTPServer)
    server.timeout = 1

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)

    msg = '''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:SetSelectedRegistrar xmlns:u="urn:schemas-wifialliance-org:service:WFAWLANConfig:1">
<NewMessage>EEoAARAQQQABARASAAIAABBTAAIxSBBJAA4ANyoAASABBv///////xBIABA2LbR7pTpRkYj7
VFi5hrLk
</NewMessage>
</u:SetSelectedRegistrar>
</s:Body>
</s:Envelope>'''
    headers = { "Content-type": 'text/xml; charset="utf-8"' }
    headers["SOAPAction"] = '"urn:schemas-wifialliance-org:service:WFAWLANConfig:1#%s"' % "SetSelectedRegistrar"
    conn.request("POST", ctrlurl.path, msg, headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    server.handle_request()

    logger.info("Start WPS_PBC and wait for PBC walk time expiration")
    if "OK" not in dev[0].request("WPS_PBC"):
        raise Exception("WPS_PBC failed")

    start = os.times()[4]

    server.handle_request()
    dev[1].request("BSS_FLUSH 0")
    dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True,
                        only_new=True)
    bss = dev[1].get_bss(apdev[0]['bssid'])
    logger.debug("BSS: " + str(bss))
    if '[WPS-AUTH]' not in bss['flags']:
        raise Exception("WPS not indicated authorized")

    server.handle_request()

    wps_timeout_seen = False

    while True:
        hapd.dump_monitor()
        dev[1].dump_monitor()
        if not wps_timeout_seen:
            ev = dev[0].wait_event(["WPS-TIMEOUT"], timeout=0)
            if ev is not None:
                logger.info("PBC timeout seen")
                wps_timeout_seen = True
        else:
            dev[0].dump_monitor()
        now = os.times()[4]
        if now - start > 130:
            raise Exception("Selected registration information not removed")
        dev[1].request("BSS_FLUSH 0")
        dev[1].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True,
                            only_new=True)
        bss = dev[1].get_bss(apdev[0]['bssid'])
        logger.debug("BSS: " + str(bss))
        if '[WPS-AUTH]' not in bss['flags']:
            break
        server.handle_request()

    server.server_close()

    if wps_timeout_seen:
        return

    now = os.times()[4]
    if now < start + 150:
        dur = start + 150 - now
    else:
        dur = 1
    logger.info("Continue waiting for PBC timeout (%d sec)" % dur)
    ev = dev[0].wait_event(["WPS-TIMEOUT"], timeout=dur)
    if ev is None:
        raise Exception("WPS-TIMEOUT not reported")

def add_ssdp_ap(ifname, ap_uuid):
    ssid = "wps-ssdp"
    ap_pin = "12345670"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
               "device_name": "Wireless AP", "manufacturer": "Company",
               "model_name": "WAP", "model_number": "123",
               "serial_number": "12345", "device_type": "6-0050F204-1",
               "os_version": "01020300",
               "config_methods": "label push_button",
               "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo",
               "friendly_name": "WPS Access Point",
               "manufacturer_url": "http://www.example.com/",
               "model_description": "Wireless Access Point",
               "model_url": "http://www.example.com/model/",
               "upc": "123456789012" }
    return hostapd.add_ap(ifname, params)

def ssdp_send(msg, no_recv=False):
    socket.setdefaulttimeout(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.bind(("127.0.0.1", 0))
    sock.sendto(msg, ("239.255.255.250", 1900))
    if no_recv:
        return None
    return sock.recv(1000)

def ssdp_send_msearch(st, no_recv=False):
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MX: 1',
            'MAN: "ssdp:discover"',
            'ST: ' + st,
            '', ''])
    return ssdp_send(msg, no_recv=no_recv)

def test_ap_wps_ssdp_msearch(dev, apdev):
    """WPS AP and SSDP M-SEARCH messages"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'Host: 239.255.255.250:1900',
            'Mx: 1',
            'Man: "ssdp:discover"',
            'St: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    ssdp_send(msg)

    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'host:\t239.255.255.250:1900\t\t\t\t \t\t',
            'mx: \t1\t\t   ',
            'man: \t \t "ssdp:discover"   ',
            'st: urn:schemas-wifialliance-org:device:WFADevice:1\t\t',
            '', ''])
    ssdp_send(msg)

    ssdp_send_msearch("ssdp:all")
    ssdp_send_msearch("upnp:rootdevice")
    ssdp_send_msearch("uuid:" + ap_uuid)
    ssdp_send_msearch("urn:schemas-wifialliance-org:service:WFAWLANConfig:1")
    ssdp_send_msearch("urn:schemas-wifialliance-org:device:WFADevice:1");

    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST:\t239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 130',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    ssdp_send(msg, no_recv=True)

def test_ap_wps_ssdp_invalid_msearch(dev, apdev):
    """WPS AP and invalid SSDP M-SEARCH messages"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    socket.setdefaulttimeout(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.bind(("127.0.0.1", 0))

    logger.debug("Missing MX")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Negative MX")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MX: -1',
            'MAN: "ssdp:discover"',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Invalid MX")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MX; 1',
            'MAN: "ssdp:discover"',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Missing MAN")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MX: 1',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Invalid MAN")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MX: 1',
            'MAN: foo',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MX: 1',
            'MAN; "ssdp:discover"',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Missing HOST")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Missing ST")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Mismatching ST")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: uuid:16d5f8a9-4ee4-4f5e-81f9-cc6e2f47f42d',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: foo:bar',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: foobar',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Invalid ST")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST; urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Invalid M-SEARCH")
    msg = '\r\n'.join([
            'M+SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))
    msg = '\r\n'.join([
            'M-SEARCH-* HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    logger.debug("Invalid message format")
    sock.sendto("NOTIFY * HTTP/1.1", ("239.255.255.250", 1900))
    msg = '\r'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    try:
        r = sock.recv(1000)
        raise Exception("Unexpected M-SEARCH response: " + r)
    except socket.timeout:
        pass

    logger.debug("Valid M-SEARCH")
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    sock.sendto(msg, ("239.255.255.250", 1900))

    try:
        r = sock.recv(1000)
        pass
    except socket.timeout:
        raise Exception("No SSDP response")

def test_ap_wps_ssdp_burst(dev, apdev):
    """WPS AP and SSDP burst"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 1',
            'ST: urn:schemas-wifialliance-org:device:WFADevice:1',
            '', ''])
    socket.setdefaulttimeout(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.bind(("127.0.0.1", 0))
    for i in range(0, 25):
        sock.sendto(msg, ("239.255.255.250", 1900))
    resp = 0
    while True:
        try:
            r = sock.recv(1000)
            if not r.startswith("HTTP/1.1 200 OK\r\n"):
                raise Exception("Unexpected message: " + r)
            resp += 1
        except socket.timeout:
            break
    if resp < 20:
        raise Exception("Too few SSDP responses")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.bind(("127.0.0.1", 0))
    for i in range(0, 25):
        sock.sendto(msg, ("239.255.255.250", 1900))
    while True:
        try:
            r = sock.recv(1000)
            if ap_uuid in r:
                break
        except socket.timeout:
            raise Exception("No SSDP response")

def ssdp_get_location(uuid):
    res = ssdp_send_msearch("uuid:" + uuid)
    location = None
    for l in res.splitlines():
        if l.lower().startswith("location:"):
            location = l.split(':', 1)[1].strip()
            break
    if location is None:
        raise Exception("No UPnP location found")
    return location

def upnp_get_urls(location):
    conn = urllib.urlopen(location)
    tree = ET.parse(conn)
    root = tree.getroot()
    urn = '{urn:schemas-upnp-org:device-1-0}'
    service = root.find("./" + urn + "device/" + urn + "serviceList/" + urn + "service")
    res = {}
    res['scpd_url'] = urlparse.urljoin(location, service.find(urn + 'SCPDURL').text)
    res['control_url'] = urlparse.urljoin(location, service.find(urn + 'controlURL').text)
    res['event_sub_url'] = urlparse.urljoin(location, service.find(urn + 'eventSubURL').text)
    return res

def upnp_soap_action(conn, path, action, include_soap_action=True, soap_action_override=None):
    soapns = 'http://schemas.xmlsoap.org/soap/envelope/'
    wpsns = 'urn:schemas-wifialliance-org:service:WFAWLANConfig:1'
    ET.register_namespace('soapenv', soapns)
    ET.register_namespace('wfa', wpsns)
    attrib = {}
    attrib['{%s}encodingStyle' % soapns] = 'http://schemas.xmlsoap.org/soap/encoding/'
    root = ET.Element("{%s}Envelope" % soapns, attrib=attrib)
    body = ET.SubElement(root, "{%s}Body" % soapns)
    act = ET.SubElement(body, "{%s}%s" % (wpsns, action))
    tree = ET.ElementTree(root)
    soap = StringIO.StringIO()
    tree.write(soap, xml_declaration=True, encoding='utf-8')

    headers = { "Content-type": 'text/xml; charset="utf-8"' }
    if include_soap_action:
        headers["SOAPAction"] = '"urn:schemas-wifialliance-org:service:WFAWLANConfig:1#%s"' % action
    elif soap_action_override:
        headers["SOAPAction"] = soap_action_override
    conn.request("POST", path, soap.getvalue(), headers)
    return conn.getresponse()

def test_ap_wps_upnp(dev, apdev):
    """WPS AP and UPnP operations"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)
    urls = upnp_get_urls(location)

    conn = urllib.urlopen(urls['scpd_url'])
    scpd = conn.read()

    conn = urllib.urlopen(urlparse.urljoin(location, "unknown.html"))
    if conn.getcode() != 404:
        raise Exception("Unexpected HTTP response to GET unknown URL")

    url = urlparse.urlparse(location)
    conn = httplib.HTTPConnection(url.netloc)
    #conn.set_debuglevel(1)
    headers = { "Content-type": 'text/xml; charset="utf-8"',
                "SOAPAction": '"urn:schemas-wifialliance-org:service:WFAWLANConfig:1#GetDeviceInfo"' }
    conn.request("POST", "hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 404:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    conn.request("UNKNOWN", "hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 501:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    headers = { "Content-type": 'text/xml; charset="utf-8"',
                "SOAPAction": '"urn:some-unknown-action#GetDeviceInfo"' }
    ctrlurl = urlparse.urlparse(urls['control_url'])
    conn.request("POST", ctrlurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 401:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("GetDeviceInfo without SOAPAction header")
    resp = upnp_soap_action(conn, ctrlurl.path, "GetDeviceInfo",
                            include_soap_action=False)
    if resp.status != 401:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("GetDeviceInfo with invalid SOAPAction header")
    for act in [ "foo",
                 "urn:schemas-wifialliance-org:service:WFAWLANConfig:1#GetDeviceInfo",
                 '"urn:schemas-wifialliance-org:service:WFAWLANConfig:1"',
                 '"urn:schemas-wifialliance-org:service:WFAWLANConfig:123#GetDevice']:
        resp = upnp_soap_action(conn, ctrlurl.path, "GetDeviceInfo",
                                include_soap_action=False,
                                soap_action_override=act)
        if resp.status != 401:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    resp = upnp_soap_action(conn, ctrlurl.path, "GetDeviceInfo")
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    dev = resp.read()
    if "NewDeviceInfo" not in dev:
        raise Exception("Unexpected GetDeviceInfo response")

    logger.debug("PutMessage without required parameters")
    resp = upnp_soap_action(conn, ctrlurl.path, "PutMessage")
    if resp.status != 600:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("PutWLANResponse without required parameters")
    resp = upnp_soap_action(conn, ctrlurl.path, "PutWLANResponse")
    if resp.status != 600:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("SetSelectedRegistrar from unregistered ER")
    resp = upnp_soap_action(conn, ctrlurl.path, "SetSelectedRegistrar")
    if resp.status != 501:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Unknown action")
    resp = upnp_soap_action(conn, ctrlurl.path, "Unknown")
    if resp.status != 401:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

def test_ap_wps_upnp_subscribe(dev, apdev):
    """WPS AP and UPnP event subscription"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hapd = add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)
    urls = upnp_get_urls(location)
    eventurl = urlparse.urlparse(urls['event_sub_url'])

    url = urlparse.urlparse(location)
    conn = httplib.HTTPConnection(url.netloc)
    #conn.set_debuglevel(1)
    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", "hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    headers = { "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:foobar",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Valid subscription")
    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)

    logger.debug("Invalid re-subscription")
    headers = { "NT": "upnp:event",
                "sid": "123456734567854",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Invalid re-subscription")
    headers = { "NT": "upnp:event",
                "sid": "uuid:123456734567854",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Invalid re-subscription")
    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "sid": sid,
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("SID mismatch in re-subscription")
    headers = { "NT": "upnp:event",
                "sid": "uuid:4c2bca79-1ff4-4e43-85d4-952a2b8a51fb",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Valid re-subscription")
    headers = { "NT": "upnp:event",
                "sid": sid,
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    sid2 = resp.getheader("sid")
    logger.debug("Subscription SID " + sid2)

    if sid != sid2:
        raise Exception("Unexpected SID change")

    logger.debug("Valid re-subscription")
    headers = { "NT": "upnp:event",
                "sid": "uuid: \t \t" + sid.split(':')[1],
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", "/hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    headers = { "foo": "bar" }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Valid unsubscription")
    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Unsubscription for not existing SID")
    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "sid": " \t \tfoo" }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "sid": "uuid:\t \tfoo" }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "NT": "upnp:event",
                "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.debug("Valid subscription with multiple callbacks")
    headers = { "callback": '<http://127.0.0.1:12345/event> <http://127.0.0.1:12345/event>\t<http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)

    # Force subscription to be deleted due to errors
    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
    with alloc_fail(hapd, 1, "event_build_message"):
        for i in range(10):
            dev[1].dump_monitor()
            dev[2].dump_monitor()
            dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
            dev[2].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
            dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
            dev[1].request("WPS_CANCEL")
            dev[2].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
            dev[2].request("WPS_CANCEL")
            if i % 4 == 1:
                time.sleep(1)
            else:
                time.sleep(0.1)
    time.sleep(0.2)

    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "", headers)
    resp = conn.getresponse()
    if resp.status != 200 and resp.status != 412:
        raise Exception("Unexpected HTTP response for UNSUBSCRIBE: %d" % resp.status)

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    with alloc_fail(hapd, 1, "http_client_addr;event_send_start"):
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 200:
            raise Exception("Unexpected HTTP response for SUBSCRIBE: %d" % resp.status)
        sid = resp.getheader("sid")
        logger.debug("Subscription SID " + sid)

    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response for UNSUBSCRIBE: %d" % resp.status)

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)

    with alloc_fail(hapd, 1, "=event_add"):
        for i in range(2):
            dev[1].dump_monitor()
            dev[2].dump_monitor()
            dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
            dev[2].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
            dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
            dev[1].request("WPS_CANCEL")
            dev[2].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
            dev[2].request("WPS_CANCEL")
            if i == 0:
                time.sleep(1)
            else:
                time.sleep(0.1)

    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    with alloc_fail(hapd, 1, "wpabuf_dup;event_add"):
        dev[1].dump_monitor()
        dev[2].dump_monitor()
        dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
        dev[2].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
        dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        dev[1].request("WPS_CANCEL")
        dev[2].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        dev[2].request("WPS_CANCEL")
        time.sleep(0.1)

    with fail_test(hapd, 1, "os_get_random;uuid_make;subscription_start"):
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 500:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    with alloc_fail(hapd, 1, "=subscription_start"):
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 500:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    headers = { "callback": '',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 500:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    headers = { "callback": ' <',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 500:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    with alloc_fail(hapd, 1, "wpabuf_alloc;subscription_first_event"):
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 500:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    with alloc_fail(hapd, 1, "event_add;subscription_first_event"):
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 500:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    with alloc_fail(hapd, 1, "subscr_addr_add_url"):
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 500:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    with alloc_fail(hapd, 2, "subscr_addr_add_url"):
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 500:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    for i in range(6):
        headers = { "callback": '<http://127.0.0.1:%d/event>' % (12345 + i),
                    "NT": "upnp:event",
                    "timeout": "Second-1234" }
        conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
        resp = conn.getresponse()
        if resp.status != 200:
            raise Exception("Unexpected HTTP response: %d" % resp.status)

    with alloc_fail(hapd, 1, "=upnp_wps_device_send_wlan_event"):
        dev[1].dump_monitor()
        dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
        dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        dev[1].request("WPS_CANCEL")
        time.sleep(0.1)

    with alloc_fail(hapd, 1, "wpabuf_alloc;upnp_wps_device_send_event"):
        dev[1].dump_monitor()
        dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
        dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        dev[1].request("WPS_CANCEL")
        time.sleep(0.1)

    with alloc_fail(hapd, 1, "base64_encode;upnp_wps_device_send_wlan_event"):
        dev[1].dump_monitor()
        dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
        dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        dev[1].request("WPS_CANCEL")
        time.sleep(0.1)

    hapd.disable()
    with alloc_fail(hapd, 1, "get_netif_info"):
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("ENABLE succeeded during OOM")

def test_ap_wps_upnp_subscribe_events(dev, apdev):
    """WPS AP and UPnP event subscription and many events"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hapd = add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)
    urls = upnp_get_urls(location)
    eventurl = urlparse.urlparse(urls['event_sub_url'])

    class WPSERHTTPServer(SocketServer.StreamRequestHandler):
        def handle(self):
            data = self.rfile.readline().strip()
            logger.debug(data)
            self.wfile.write(gen_wps_event())

    server = MyTCPServer(("127.0.0.1", 12345), WPSERHTTPServer)
    server.timeout = 1

    url = urlparse.urlparse(location)
    conn = httplib.HTTPConnection(url.netloc)

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)

    # Fetch the first event message
    server.handle_request()

    # Force subscription event queue to reach the maximum length by generating
    # new proxied events without the ER fetching any of the pending events.
    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    dev[2].scan_for_bss(apdev[0]['bssid'], freq=2412)
    for i in range(16):
        dev[1].dump_monitor()
        dev[2].dump_monitor()
        dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
        dev[2].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
        dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        dev[1].request("WPS_CANCEL")
        dev[2].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        dev[2].request("WPS_CANCEL")
        if i % 4 == 1:
            time.sleep(1)
        else:
            time.sleep(0.1)

    hapd.request("WPS_PIN any 12345670")
    dev[1].dump_monitor()
    dev[1].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
    ev = dev[1].wait_event(["WPS-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("WPS success not reported")

    # Close the WPS ER HTTP server without fetching all the pending events.
    # This tests hostapd code path that clears subscription and the remaining
    # event queue when the interface is deinitialized.
    server.handle_request()
    server.server_close()

    dev[1].wait_connected()

def test_ap_wps_upnp_http_proto(dev, apdev):
    """WPS AP and UPnP/HTTP protocol testing"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)

    url = urlparse.urlparse(location)
    conn = httplib.HTTPConnection(url.netloc, timeout=0.2)
    #conn.set_debuglevel(1)

    conn.request("HEAD", "hello")
    resp = conn.getresponse()
    if resp.status != 501:
        raise Exception("Unexpected response to HEAD: " + str(resp.status))
    conn.close()

    for cmd in [ "PUT", "DELETE", "TRACE", "CONNECT", "M-SEARCH", "M-POST" ]:
        try:
            conn.request(cmd, "hello")
            resp = conn.getresponse()
        except Exception, e:
            pass
        conn.close()

    headers = { "Content-Length": 'abc' }
    conn.request("HEAD", "hello", "\r\n\r\n", headers)
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

    headers = { "Content-Length": '-10' }
    conn.request("HEAD", "hello", "\r\n\r\n", headers)
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

    headers = { "Content-Length": '10000000000000' }
    conn.request("HEAD", "hello", "\r\n\r\nhello", headers)
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

    headers = { "Transfer-Encoding": 'abc' }
    conn.request("HEAD", "hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 501:
        raise Exception("Unexpected response to HEAD: " + str(resp.status))
    conn.close()

    headers = { "Transfer-Encoding": 'chunked' }
    conn.request("HEAD", "hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 501:
        raise Exception("Unexpected response to HEAD: " + str(resp.status))
    conn.close()

    # Too long a header
    conn.request("HEAD", 5000 * 'A')
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

    # Long URL but within header length limits
    conn.request("HEAD", 3000 * 'A')
    resp = conn.getresponse()
    if resp.status != 501:
        raise Exception("Unexpected response to HEAD: " + str(resp.status))
    conn.close()

    headers = { "Content-Length": '20' }
    conn.request("POST", "hello", 10 * 'A' + "\r\n\r\n", headers)
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

    conn.request("POST", "hello", 5000 * 'A' + "\r\n\r\n")
    resp = conn.getresponse()
    if resp.status != 404:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    conn.close()

    conn.request("POST", "hello", 60000 * 'A' + "\r\n\r\n")
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

def test_ap_wps_upnp_http_proto_chunked(dev, apdev):
    """WPS AP and UPnP/HTTP protocol testing for chunked encoding"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)

    url = urlparse.urlparse(location)
    conn = httplib.HTTPConnection(url.netloc)
    #conn.set_debuglevel(1)

    headers = { "Transfer-Encoding": 'chunked' }
    conn.request("POST", "hello",
                 "a\r\nabcdefghij\r\n" + "2\r\nkl\r\n" + "0\r\n\r\n",
                 headers)
    resp = conn.getresponse()
    if resp.status != 404:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    conn.close()

    conn.putrequest("POST", "hello")
    conn.putheader('Transfer-Encoding', 'chunked')
    conn.endheaders()
    conn.send("a\r\nabcdefghij\r\n")
    time.sleep(0.1)
    conn.send("2\r\nkl\r\n")
    conn.send("0\r\n\r\n")
    resp = conn.getresponse()
    if resp.status != 404:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    conn.close()

    conn.putrequest("POST", "hello")
    conn.putheader('Transfer-Encoding', 'chunked')
    conn.endheaders()
    completed = False
    try:
        for i in range(20000):
            conn.send("1\r\nZ\r\n")
        conn.send("0\r\n\r\n")
        resp = conn.getresponse()
        completed = True
    except Exception, e:
        pass
    conn.close()
    if completed:
        raise Exception("Too long chunked request did not result in connection reset")

    headers = { "Transfer-Encoding": 'chunked' }
    conn.request("POST", "hello", "80000000\r\na", headers)
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

    conn.request("POST", "hello", "10000000\r\na", headers)
    try:
        resp = conn.getresponse()
    except Exception, e:
        pass
    conn.close()

def test_ap_wps_disabled(dev, apdev):
    """WPS operations while WPS is disabled"""
    ssid = "test-wps-disabled"
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": ssid })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    if "FAIL" not in hapd.request("WPS_PBC"):
        raise Exception("WPS_PBC succeeded unexpectedly")
    if "FAIL" not in hapd.request("WPS_CANCEL"):
        raise Exception("WPS_CANCEL succeeded unexpectedly")

def test_ap_wps_mixed_cred(dev, apdev):
    """WPS 2.0 STA merging mixed mode WPA/WPA2 credentials"""
    ssid = "test-wps-wep"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "skip_cred_build": "1", "extra_cred": "wps-mixed-cred" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=30)
    if ev is None:
        raise Exception("WPS-SUCCESS event timed out")
    nets = dev[0].list_networks()
    if len(nets) != 1:
        raise Exception("Unexpected number of network blocks")
    id = nets[0]['id']
    proto = dev[0].get_network(id, "proto")
    if proto != "WPA RSN":
        raise Exception("Unexpected merged proto field value: " + proto)
    pairwise = dev[0].get_network(id, "pairwise")
    if pairwise != "CCMP TKIP" and pairwise != "CCMP GCMP TKIP":
        raise Exception("Unexpected merged pairwise field value: " + pairwise)

def test_ap_wps_while_connected(dev, apdev):
    """WPS PBC provisioning while connected to another AP"""
    ssid = "test-wps-conf"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    hostapd.add_ap(apdev[1]['ifname'], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")

    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])
    dev[0].wait_connected(timeout=30)
    status = dev[0].get_status()
    if status['bssid'] != apdev[0]['bssid']:
        raise Exception("Unexpected BSSID")

def test_ap_wps_while_connected_no_autoconnect(dev, apdev):
    """WPS PBC provisioning while connected to another AP and STA_AUTOCONNECT disabled"""
    ssid = "test-wps-conf"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    hostapd.add_ap(apdev[1]['ifname'], { "ssid": "open" })

    try:
        dev[0].request("STA_AUTOCONNECT 0")
        dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")

        logger.info("WPS provisioning step")
        hapd.request("WPS_PBC")
        dev[0].dump_monitor()
        dev[0].request("WPS_PBC " + apdev[0]['bssid'])
        dev[0].wait_connected(timeout=30)
        status = dev[0].get_status()
        if status['bssid'] != apdev[0]['bssid']:
            raise Exception("Unexpected BSSID")
    finally:
        dev[0].request("STA_AUTOCONNECT 1")

def test_ap_wps_from_event(dev, apdev):
    """WPS PBC event on AP to enable PBC"""
    ssid = "test-wps-conf"
    hapd = hostapd.add_ap(apdev[0]['ifname'],
                          { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                            "wpa_passphrase": "12345678", "wpa": "2",
                            "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    hapd.dump_monitor()
    dev[0].request("WPS_PBC " + apdev[0]['bssid'])

    ev = hapd.wait_event(['WPS-ENROLLEE-SEEN'], timeout=15)
    if ev is None:
        raise Exception("No WPS-ENROLLEE-SEEN event on AP")
    vals = ev.split(' ')
    if vals[1] != dev[0].p2p_interface_addr():
        raise Exception("Unexpected enrollee address: " + vals[1])
    if vals[5] != '4':
        raise Exception("Unexpected Device Password Id: " + vals[5])
    hapd.request("WPS_PBC")
    dev[0].wait_connected(timeout=30)

def test_ap_wps_ap_scan_2(dev, apdev):
    """AP_SCAN 2 for WPS"""
    ssid = "test-wps-conf"
    hapd = hostapd.add_ap(apdev[0]['ifname'],
                          { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                            "wpa_passphrase": "12345678", "wpa": "2",
                            "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd.request("WPS_PBC")

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")

    if "OK" not in wpas.request("AP_SCAN 2"):
        raise Exception("Failed to set AP_SCAN 2")

    wpas.flush_scan_cache()
    wpas.scan_for_bss(apdev[0]['bssid'], freq="2412")
    wpas.request("WPS_PBC " + apdev[0]['bssid'])
    ev = wpas.wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS-SUCCESS event timed out")
    wpas.wait_connected(timeout=30)
    wpas.request("DISCONNECT")
    wpas.request("BSS_FLUSH 0")
    wpas.dump_monitor()
    wpas.request("REASSOCIATE")
    wpas.wait_connected(timeout=30)

def test_ap_wps_eapol_workaround(dev, apdev):
    """EAPOL workaround code path for 802.1X header length mismatch"""
    ssid = "test-wps"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    bssid = apdev[0]['bssid']
    hapd.request("SET ext_eapol_frame_io 1")
    dev[0].request("SET ext_eapol_frame_io 1")
    hapd.request("WPS_PBC")
    dev[0].request("WPS_PBC")

    ev = hapd.wait_event(["EAPOL-TX"], timeout=15)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX from hostapd")

    res = dev[0].request("EAPOL_RX " + bssid + " 020000040193000501FFFF")
    if "OK" not in res:
        raise Exception("EAPOL_RX to wpa_supplicant failed")

def test_ap_wps_iteration(dev, apdev):
    """WPS PIN and iterate through APs without selected registrar"""
    ssid = "test-wps-conf"
    hapd = hostapd.add_ap(apdev[0]['ifname'],
                          { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                            "wpa_passphrase": "12345678", "wpa": "2",
                            "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})

    ssid2 = "test-wps-conf2"
    hapd2 = hostapd.add_ap(apdev[1]['ifname'],
                           { "ssid": ssid2, "eap_server": "1", "wps_state": "2",
                             "wpa_passphrase": "12345678", "wpa": "2",
                             "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})

    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    dev[0].dump_monitor()
    pin = dev[0].request("WPS_PIN any")

    # Wait for iteration through all WPS APs to happen before enabling any
    # Registrar.
    for i in range(2):
        ev = dev[0].wait_event(["Associated with"], timeout=30)
        if ev is None:
            raise Exception("No association seen")
        ev = dev[0].wait_event(["WPS-M2D"], timeout=10)
        if ev is None:
            raise Exception("No M2D from AP")
        dev[0].wait_disconnected()

    # Verify that each AP requested PIN
    ev = hapd.wait_event(["WPS-PIN-NEEDED"], timeout=1)
    if ev is None:
        raise Exception("No WPS-PIN-NEEDED event from AP")
    ev = hapd2.wait_event(["WPS-PIN-NEEDED"], timeout=1)
    if ev is None:
        raise Exception("No WPS-PIN-NEEDED event from AP2")

    # Provide PIN to one of the APs and verify that connection gets formed
    hapd.request("WPS_PIN any " + pin)
    dev[0].wait_connected(timeout=30)

def test_ap_wps_iteration_error(dev, apdev):
    """WPS AP iteration on no Selected Registrar and error case with an AP"""
    ssid = "test-wps-conf-pin"
    hapd = hostapd.add_ap(apdev[0]['ifname'],
                          { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                            "wpa_passphrase": "12345678", "wpa": "2",
                            "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                            "wps_independent": "1" })
    hapd.request("SET ext_eapol_frame_io 1")
    bssid = apdev[0]['bssid']
    pin = dev[0].wps_read_pin()
    dev[0].request("WPS_PIN any " + pin)

    ev = hapd.wait_event(["EAPOL-TX"], timeout=15)
    if ev is None:
        raise Exception("No EAPOL-TX (EAP-Request/Identity) from hostapd")
    dev[0].request("EAPOL_RX " + bssid + " " + ev.split(' ')[2])

    ev = hapd.wait_event(["EAPOL-TX"], timeout=15)
    if ev is None:
        raise Exception("No EAPOL-TX (EAP-WSC/Start) from hostapd")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=5)
    if ev is None:
        raise Exception("No CTRL-EVENT-EAP-STARTED")

    # Do not forward any more EAPOL frames to test wpa_supplicant behavior for
    # a case with an incorrectly behaving WPS AP.

    # Start the real target AP and activate registrar on it.
    hapd2 = hostapd.add_ap(apdev[1]['ifname'],
                          { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                            "wpa_passphrase": "12345678", "wpa": "2",
                            "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                            "wps_independent": "1" })
    hapd2.request("WPS_PIN any " + pin)

    dev[0].wait_disconnected(timeout=15)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=15)
    if ev is None:
        raise Exception("No CTRL-EVENT-EAP-STARTED for the second AP")
    ev = dev[0].wait_event(["WPS-CRED-RECEIVED"], timeout=15)
    if ev is None:
        raise Exception("No WPS-CRED-RECEIVED for the second AP")
    dev[0].wait_connected(timeout=15)

def test_ap_wps_priority(dev, apdev):
    """WPS PIN provisioning with configured AP and wps_priority"""
    ssid = "test-wps-conf-pin"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    pin = dev[0].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    try:
        dev[0].request("SET wps_priority 6")
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        dev[0].wait_connected(timeout=30)
        netw = dev[0].list_networks()
        prio = dev[0].get_network(netw[0]['id'], 'priority')
        if prio != '6':
            raise Exception("Unexpected network priority: " + prio)
    finally:
        dev[0].request("SET wps_priority 0")

def test_ap_wps_and_non_wps(dev, apdev):
    """WPS and non-WPS AP in single hostapd process"""
    params = { "ssid": "wps", "eap_server": "1", "wps_state": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    params = { "ssid": "no wps" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)

    appin = hapd.request("WPS_AP_PIN random")
    if "FAIL" in appin:
        raise Exception("Could not generate random AP PIN")
    if appin not in hapd.request("WPS_AP_PIN get"):
        raise Exception("Could not fetch current AP PIN")

    if "FAIL" in hapd.request("WPS_PBC"):
        raise Exception("WPS_PBC failed")
    if "FAIL" in hapd.request("WPS_CANCEL"):
        raise Exception("WPS_CANCEL failed")

def test_ap_wps_init_oom(dev, apdev):
    """Initial AP configuration and OOM during PSK generation"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    with alloc_fail(hapd, 1, "base64_encode;wps_build_cred"):
        pin = dev[0].wps_read_pin()
        hapd.request("WPS_PIN any " + pin)
        dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        dev[0].wait_disconnected()

    hapd.request("WPS_PIN any " + pin)
    dev[0].wait_connected(timeout=30)

def test_ap_wps_er_oom(dev, apdev):
    """WPS ER OOM in XML processing"""
    try:
        _test_ap_wps_er_oom(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")
        dev[1].request("WPS_CANCEL")
        dev[0].request("DISCONNECT")

def _test_ap_wps_er_oom(dev, apdev):
    ssid = "wps-er-ap-config"
    ap_pin = "12345670"
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "device_name": "Wireless AP", "manufacturer": "Company",
                     "model_name": "WAP", "model_number": "123",
                     "serial_number": "12345", "device_type": "6-0050F204-1",
                     "os_version": "01020300",
                     "config_methods": "label push_button",
                     "ap_pin": ap_pin, "uuid": ap_uuid, "upnp_iface": "lo"})

    dev[0].connect(ssid, psk="12345678", scan_freq="2412")

    with alloc_fail(dev[0], 1, "base64_decode;xml_get_base64_item"):
        dev[0].request("WPS_ER_START ifname=lo")
        ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=3)
        if ev is not None:
            raise Exception("Unexpected AP discovery")

    dev[0].request("WPS_ER_STOP")
    dev[0].request("WPS_ER_START ifname=lo")
    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=10)
    if ev is None:
        raise Exception("AP discovery timed out")

    dev[1].scan_for_bss(apdev[0]['bssid'], freq=2412)
    with alloc_fail(dev[0], 1, "base64_decode;xml_get_base64_item"):
        dev[1].request("WPS_PBC " + apdev[0]['bssid'])
        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=10)
        if ev is None:
            raise Exception("PBC scan failed")
        ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=15)
        if ev is None:
            raise Exception("Enrollee discovery timed out")

def test_ap_wps_er_init_oom(dev, apdev):
    """WPS ER and OOM during init"""
    try:
        _test_ap_wps_er_init_oom(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_init_oom(dev, apdev):
    with alloc_fail(dev[0], 1, "wps_er_init"):
        if "FAIL" not in dev[0].request("WPS_ER_START ifname=lo"):
            raise Exception("WPS_ER_START succeeded during OOM")
    with alloc_fail(dev[0], 1, "http_server_init"):
        if "FAIL" not in dev[0].request("WPS_ER_START ifname=lo"):
            raise Exception("WPS_ER_START succeeded during OOM")
    with alloc_fail(dev[0], 2, "http_server_init"):
        if "FAIL" not in dev[0].request("WPS_ER_START ifname=lo"):
            raise Exception("WPS_ER_START succeeded during OOM")
    with alloc_fail(dev[0], 1, "eloop_register_sock;wps_er_ssdp_init"):
        if "FAIL" not in dev[0].request("WPS_ER_START ifname=lo"):
            raise Exception("WPS_ER_START succeeded during OOM")
    with fail_test(dev[0], 1, "os_get_random;wps_er_init"):
        if "FAIL" not in dev[0].request("WPS_ER_START ifname=lo"):
            raise Exception("WPS_ER_START succeeded during os_get_random failure")

def test_ap_wps_wpa_cli_action(dev, apdev, test_params):
    """WPS events and wpa_cli action script"""
    logdir = os.path.abspath(test_params['logdir'])
    pidfile = os.path.join(logdir, 'ap_wps_wpa_cli_action.wpa_cli.pid')
    logfile = os.path.join(logdir, 'ap_wps_wpa_cli_action.wpa_cli.res')
    actionfile = os.path.join(logdir, 'ap_wps_wpa_cli_action.wpa_cli.action.sh')

    with open(actionfile, 'w') as f:
        f.write('#!/bin/sh\n')
        f.write('echo $* >> %s\n' % logfile)
        # Kill the process and wait some time before returning to allow all the
        # pending events to be processed with some of this happening after the
        # eloop SIGALRM signal has been scheduled.
        f.write('if [ $2 = "WPS-SUCCESS" -a -r %s ]; then kill `cat %s`; sleep 1; fi\n' % (pidfile, pidfile))

    os.chmod(actionfile, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC |
             stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    ssid = "test-wps-conf"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    prg = os.path.join(test_params['logdir'],
                       'alt-wpa_supplicant/wpa_supplicant/wpa_cli')
    if not os.path.exists(prg):
        prg = '../../wpa_supplicant/wpa_cli'
    arg = [ prg, '-P', pidfile, '-B', '-i', dev[0].ifname, '-a', actionfile ]
    subprocess.call(arg)

    arg = [ 'ps', 'ax' ]
    cmd = subprocess.Popen(arg, stdout=subprocess.PIPE)
    out = cmd.communicate()[0]
    cmd.wait()
    logger.debug("Processes:\n" + out)
    if "wpa_cli -P %s -B -i %s" % (pidfile, dev[0].ifname) not in out:
        raise Exception("Did not see wpa_cli running")

    hapd.request("WPS_PIN any 12345670")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN " + apdev[0]['bssid'] + " 12345670")
    dev[0].wait_connected(timeout=30)

    for i in range(30):
        if not os.path.exists(pidfile):
            break
        time.sleep(0.1)

    if not os.path.exists(logfile):
        raise Exception("wpa_cli action results file not found")
    with open(logfile, 'r') as f:
        res = f.read()
    if "WPS-SUCCESS" not in res:
        raise Exception("WPS-SUCCESS event not seen in action file")

    arg = [ 'ps', 'ax' ]
    cmd = subprocess.Popen(arg, stdout=subprocess.PIPE)
    out = cmd.communicate()[0]
    cmd.wait()
    logger.debug("Remaining processes:\n" + out)
    if "wpa_cli -P %s -B -i %s" % (pidfile, dev[0].ifname) in out:
        raise Exception("wpa_cli still running")

    if os.path.exists(pidfile):
        raise Exception("PID file not removed")

def test_ap_wps_er_ssdp_proto(dev, apdev):
    """WPS ER SSDP protocol testing"""
    try:
        _test_ap_wps_er_ssdp_proto(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_ssdp_proto(dev, apdev):
    socket.setdefaulttimeout(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("239.255.255.250", 1900))
    if "FAIL" not in dev[0].request("WPS_ER_START ifname=lo foo"):
        raise Exception("Invalid filter accepted")
    if "OK" not in dev[0].request("WPS_ER_START ifname=lo 1.2.3.4"):
        raise Exception("WPS_ER_START with filter failed")
    (msg,addr) = sock.recvfrom(1000)
    logger.debug("Received SSDP message from %s: %s" % (str(addr), msg))
    if "M-SEARCH" not in msg:
        raise Exception("Not an M-SEARCH")
    sock.sendto("FOO", addr)
    time.sleep(0.1)
    dev[0].request("WPS_ER_STOP")

    dev[0].request("WPS_ER_START ifname=lo")
    (msg,addr) = sock.recvfrom(1000)
    logger.debug("Received SSDP message from %s: %s" % (str(addr), msg))
    if "M-SEARCH" not in msg:
        raise Exception("Not an M-SEARCH")
    sock.sendto("FOO", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nFOO\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nNTS:foo\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nNTS:ssdp:byebye\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\ncache-control:   foo=1\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\ncache-control:   max-age=1\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nusn:\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nusn:foo\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nusn:   uuid:\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nusn:   uuid:     \r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nusn:   uuid:     foo\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nNTS:ssdp:byebye\r\n\r\n", addr)
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:foo\r\n\r\n", addr)
    with alloc_fail(dev[0], 1, "wps_er_ap_add"):
        sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:foo\r\ncache-control:max-age=1\r\n\r\n", addr)
        time.sleep(0.1)
    with alloc_fail(dev[0], 2, "wps_er_ap_add"):
        sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:foo\r\ncache-control:max-age=1\r\n\r\n", addr)
        time.sleep(0.1)

    # Add an AP with bogus URL
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:foo\r\ncache-control:max-age=1\r\n\r\n", addr)
    # Update timeout on AP without updating URL
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:http://127.0.0.1:12345/foo.xml\r\ncache-control:max-age=1\r\n\r\n", addr)
    ev = dev[0].wait_event(["WPS-ER-AP-REMOVE"], timeout=5)
    if ev is None:
        raise Exception("No WPS-ER-AP-REMOVE event on max-age timeout")

    # Add an AP with a valid URL (but no server listing to it)
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:http://127.0.0.1:12345/foo.xml\r\ncache-control:max-age=1\r\n\r\n", addr)
    ev = dev[0].wait_event(["WPS-ER-AP-REMOVE"], timeout=5)
    if ev is None:
        raise Exception("No WPS-ER-AP-REMOVE event on max-age timeout")

    sock.close()

wps_event_url = None

def gen_upnp_info(eventSubURL='wps_event', controlURL='wps_control',
                  udn='uuid:27ea801a-9e5c-4e73-bd82-f89cbcd10d7e'):
    payload = '''<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion>
<major>1</major>
<minor>0</minor>
</specVersion>
<device>
<deviceType>urn:schemas-wifialliance-org:device:WFADevice:1</deviceType>
<friendlyName>WPS Access Point</friendlyName>
<manufacturer>Company</manufacturer>
<modelName>WAP</modelName>
<modelNumber>123</modelNumber>
<serialNumber>12345</serialNumber>
'''
    if udn:
        payload += '<UDN>' + udn + '</UDN>'
    payload += '''<serviceList>
<service>
<serviceType>urn:schemas-wifialliance-org:service:WFAWLANConfig:1</serviceType>
<serviceId>urn:wifialliance-org:serviceId:WFAWLANConfig1</serviceId>
<SCPDURL>wps_scpd.xml</SCPDURL>
'''
    if controlURL:
        payload += '<controlURL>' + controlURL + '</controlURL>\n'
    if eventSubURL:
        payload += '<eventSubURL>' + eventSubURL + '</eventSubURL>\n'
    payload += '''</service>
</serviceList>
</device>
</root>
'''
    hdr = 'HTTP/1.1 200 OK\r\n' + \
          'Content-Type: text/xml; charset="utf-8"\r\n' + \
          'Server: Unspecified, UPnP/1.0, Unspecified\r\n' + \
          'Connection: close\r\n' + \
          'Content-Length: ' + str(len(payload)) + '\r\n' + \
          'Date: Sat, 15 Aug 2015 18:55:08 GMT\r\n\r\n'
    return hdr + payload

def gen_wps_control(payload_override=None):
    payload = '''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetDeviceInfoResponse xmlns:u="urn:schemas-wifialliance-org:service:WFAWLANConfig:1">
<NewDeviceInfo>EEoAARAQIgABBBBHABAn6oAanlxOc72C+Jy80Q1+ECAABgIAAAADABAaABCJZ7DPtbU3Ust9
Z3wJF07WEDIAwH45D3i1OqB7eJGwTzqeapS71h3KyXncK2xJZ+xqScrlorNEg6LijBJzG2Ca
+FZli0iliDJd397yAx/jk4nFXco3q5ylBSvSw9dhJ5u1xBKSnTilKGlUHPhLP75PUqM3fot9
7zwtFZ4bx6x1sBA6oEe2d0aUJmLumQGCiKEIWlnxs44zego/2tAe81bDzdPBM7o5HH/FUhD+
KoGzFXp51atP+1n9Vta6AkI0Vye99JKLcC6Md9dMJltSVBgd4Xc4lRAEAAIAIxAQAAIADRAN
AAEBEAgAAgAEEEQAAQIQIQAHQ29tcGFueRAjAANXQVAQJAADMTIzEEIABTEyMzQ1EFQACAAG
AFDyBAABEBEAC1dpcmVsZXNzIEFQEDwAAQEQAgACAAAQEgACAAAQCQACAAAQLQAEgQIDABBJ
AAYANyoAASA=
</NewDeviceInfo>
</u:GetDeviceInfoResponse>
</s:Body>
</s:Envelope>
'''
    if payload_override:
        payload = payload_override
    hdr = 'HTTP/1.1 200 OK\r\n' + \
          'Content-Type: text/xml; charset="utf-8"\r\n' + \
          'Server: Unspecified, UPnP/1.0, Unspecified\r\n' + \
          'Connection: close\r\n' + \
          'Content-Length: ' + str(len(payload)) + '\r\n' + \
          'Date: Sat, 15 Aug 2015 18:55:08 GMT\r\n\r\n'
    return hdr + payload

def gen_wps_event(sid='uuid:7eb3342a-8a5f-47fe-a585-0785bfec6d8a'):
    payload = ""
    hdr = 'HTTP/1.1 200 OK\r\n' + \
          'Content-Type: text/xml; charset="utf-8"\r\n' + \
          'Server: Unspecified, UPnP/1.0, Unspecified\r\n' + \
          'Connection: close\r\n' + \
          'Content-Length: ' + str(len(payload)) + '\r\n'
    if sid:
        hdr += 'SID: ' + sid + '\r\n'
    hdr += 'Timeout: Second-1801\r\n' + \
          'Date: Sat, 15 Aug 2015 18:55:08 GMT\r\n\r\n'
    return hdr + payload

class WPSAPHTTPServer(SocketServer.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline().strip()
        logger.info("HTTP server received: " + data)
        while True:
            hdr = self.rfile.readline().strip()
            if len(hdr) == 0:
                break
            logger.info("HTTP header: " + hdr)
            if "CALLBACK:" in hdr:
                global wps_event_url
                wps_event_url = hdr.split(' ')[1].strip('<>')

        if "GET /foo.xml" in data:
            self.handle_upnp_info()
        elif "POST /wps_control" in data:
            self.handle_wps_control()
        elif "SUBSCRIBE /wps_event" in data:
            self.handle_wps_event()
        else:
            self.handle_others(data)

    def handle_upnp_info(self):
        self.wfile.write(gen_upnp_info())

    def handle_wps_control(self):
        self.wfile.write(gen_wps_control())

    def handle_wps_event(self):
        self.wfile.write(gen_wps_event())

    def handle_others(self, data):
        logger.info("Ignore HTTP request: " + data)

class MyTCPServer(SocketServer.TCPServer):
    def __init__(self, addr, handler):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, addr, handler)

def wps_er_start(dev, http_server, max_age=1, wait_m_search=False,
                 location_url=None):
    socket.setdefaulttimeout(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("239.255.255.250", 1900))
    dev.request("WPS_ER_START ifname=lo")
    for i in range(100):
        (msg,addr) = sock.recvfrom(1000)
        logger.debug("Received SSDP message from %s: %s" % (str(addr), msg))
        if "M-SEARCH" in msg:
            break
        if not wait_m_search:
            raise Exception("Not an M-SEARCH")
        if i == 99:
            raise Exception("No M-SEARCH seen")

    # Add an AP with a valid URL and server listing to it
    server = MyTCPServer(("127.0.0.1", 12345), http_server)
    if not location_url:
        location_url = 'http://127.0.0.1:12345/foo.xml'
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:%s\r\ncache-control:max-age=%d\r\n\r\n" % (location_url, max_age), addr)
    server.timeout = 1
    return server,sock

def wps_er_stop(dev, sock, server, on_alloc_fail=False):
    sock.close()
    server.server_close()

    if on_alloc_fail:
        done = False
        for i in range(50):
            res = dev.request("GET_ALLOC_FAIL")
            if res.startswith("0:"):
                done = True
                break
            time.sleep(0.1)
        if not done:
            raise Exception("No allocation failure reported")
    else:
        ev = dev.wait_event(["WPS-ER-AP-REMOVE"], timeout=5)
        if ev is None:
            raise Exception("No WPS-ER-AP-REMOVE event on max-age timeout")
    dev.request("WPS_ER_STOP")

def run_wps_er_proto_test(dev, handler, no_event_url=False, location_url=None):
    try:
        uuid = '27ea801a-9e5c-4e73-bd82-f89cbcd10d7e'
        server,sock = wps_er_start(dev, handler, location_url=location_url)
        global wps_event_url
        wps_event_url = None
        server.handle_request()
        server.handle_request()
        server.handle_request()
        server.server_close()
        if no_event_url:
            if wps_event_url:
                raise Exception("Received event URL unexpectedly")
            return
        if wps_event_url is None:
            raise Exception("Did not get event URL")
        logger.info("Event URL: " + wps_event_url)
    finally:
            dev.request("WPS_ER_STOP")

def send_wlanevent(url, uuid, data):
    conn = httplib.HTTPConnection(url.netloc)
    payload = '''<?xml version="1.0" encoding="utf-8"?>
<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
<e:property><STAStatus>1</STAStatus></e:property>
<e:property><APStatus>1</APStatus></e:property>
<e:property><WLANEvent>'''
    payload += base64.b64encode(data)
    payload += '</WLANEvent></e:property></e:propertyset>'
    headers = { "Content-type": 'text/xml; charset="utf-8"',
                "Server": "Unspecified, UPnP/1.0, Unspecified",
                "HOST": url.netloc,
                "NT": "upnp:event",
                "SID": "uuid:" + uuid,
                "SEQ": "0",
                "Content-Length": str(len(payload)) }
    conn.request("NOTIFY", url.path, payload, headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

def test_ap_wps_er_http_proto(dev, apdev):
    """WPS ER HTTP protocol testing"""
    try:
        _test_ap_wps_er_http_proto(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_http_proto(dev, apdev):
    uuid = '27ea801a-9e5c-4e73-bd82-f89cbcd10d7e'
    server,sock = wps_er_start(dev[0], WPSAPHTTPServer, max_age=15)
    global wps_event_url
    wps_event_url = None
    server.handle_request()
    server.handle_request()
    server.handle_request()
    server.server_close()
    if wps_event_url is None:
        raise Exception("Did not get event URL")
    logger.info("Event URL: " + wps_event_url)

    ev = dev[0].wait_event(["WPS-ER-AP-ADD"], timeout=10)
    if ev is None:
        raise Exception("No WPS-ER-AP-ADD event")
    if uuid not in ev:
        raise Exception("UUID mismatch")

    sock.close()

    logger.info("Valid Probe Request notification")
    url = urlparse.urlparse(wps_event_url)
    conn = httplib.HTTPConnection(url.netloc)
    payload = '''<?xml version="1.0" encoding="utf-8"?>
<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
<e:property><STAStatus>1</STAStatus></e:property>
<e:property><APStatus>1</APStatus></e:property>
<e:property><WLANEvent>ATAyOjAwOjAwOjAwOjAwOjAwEEoAARAQOgABAhAIAAIxSBBHABA2LbR7pTpRkYj7VFi5hrLk
EFQACAAAAAAAAAAAEDwAAQMQAgACAAAQCQACAAAQEgACAAAQIQABIBAjAAEgECQAASAQEQAI
RGV2aWNlIEEQSQAGADcqAAEg
</WLANEvent></e:property>
</e:propertyset>
'''
    headers = { "Content-type": 'text/xml; charset="utf-8"',
                "Server": "Unspecified, UPnP/1.0, Unspecified",
                "HOST": url.netloc,
                "NT": "upnp:event",
                "SID": "uuid:" + uuid,
                "SEQ": "0",
                "Content-Length": str(len(payload)) }
    conn.request("NOTIFY", url.path, payload, headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=5)
    if ev is None:
        raise Exception("No WPS-ER-ENROLLEE-ADD event")
    if "362db47b-a53a-5191-88fb-5458b986b2e4" not in ev:
        raise Exception("No Enrollee UUID match")

    logger.info("Incorrect event URL AP id")
    conn = httplib.HTTPConnection(url.netloc)
    conn.request("NOTIFY", url.path + '123', payload, headers)
    resp = conn.getresponse()
    if resp.status != 404:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.info("Missing AP id")
    conn = httplib.HTTPConnection(url.netloc)
    conn.request("NOTIFY", '/event/' + url.path.split('/')[2],
                 payload, headers)
    time.sleep(0.1)

    logger.info("Incorrect event URL event id")
    conn = httplib.HTTPConnection(url.netloc)
    conn.request("NOTIFY", '/event/123456789/123', payload, headers)
    time.sleep(0.1)

    logger.info("Incorrect event URL prefix")
    conn = httplib.HTTPConnection(url.netloc)
    conn.request("NOTIFY", '/foobar/123456789/123', payload, headers)
    resp = conn.getresponse()
    if resp.status != 404:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.info("Unsupported request")
    conn = httplib.HTTPConnection(url.netloc)
    conn.request("FOOBAR", '/foobar/123456789/123', payload, headers)
    resp = conn.getresponse()
    if resp.status != 501:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    logger.info("Unsupported request and OOM")
    with alloc_fail(dev[0], 1, "wps_er_http_req"):
        conn = httplib.HTTPConnection(url.netloc)
        conn.request("FOOBAR", '/foobar/123456789/123', payload, headers)
        time.sleep(0.5)

    logger.info("Too short WLANEvent")
    data = '\x00'
    send_wlanevent(url, uuid, data)

    logger.info("Invalid WLANEventMAC")
    data = '\x00qwertyuiopasdfghjklzxcvbnm'
    send_wlanevent(url, uuid, data)

    logger.info("Unknown WLANEventType")
    data = '\xff02:00:00:00:00:00'
    send_wlanevent(url, uuid, data)

    logger.info("Probe Request notification without any attributes")
    data = '\x0102:00:00:00:00:00'
    send_wlanevent(url, uuid, data)

    logger.info("Probe Request notification with invalid attribute")
    data = '\x0102:00:00:00:00:00\xff'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message without any attributes")
    data = '\x0202:00:00:00:00:00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message with invalid attribute")
    data = '\x0202:00:00:00:00:00\xff'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message from new STA and not M1")
    data = '\x0202:ff:ff:ff:ff:ff' + '\x10\x22\x00\x01\x05'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1")
    data = '\x0202:00:00:00:00:00'
    data += '\x10\x22\x00\x01\x04'
    data += '\x10\x47\x00\x10' + 16*'\x00'
    data += '\x10\x20\x00\x06\x02\x00\x00\x00\x00\x00'
    data += '\x10\x1a\x00\x10' + 16*'\x00'
    data += '\x10\x32\x00\xc0' + 192*'\x00'
    data += '\x10\x04\x00\x02\x00\x00'
    data += '\x10\x10\x00\x02\x00\x00'
    data += '\x10\x0d\x00\x01\x00'
    data += '\x10\x08\x00\x02\x00\x00'
    data += '\x10\x44\x00\x01\x00'
    data += '\x10\x21\x00\x00'
    data += '\x10\x23\x00\x00'
    data += '\x10\x24\x00\x00'
    data += '\x10\x42\x00\x00'
    data += '\x10\x54\x00\x08' + 8*'\x00'
    data += '\x10\x11\x00\x00'
    data += '\x10\x3c\x00\x01\x00'
    data += '\x10\x02\x00\x02\x00\x00'
    data += '\x10\x12\x00\x02\x00\x00'
    data += '\x10\x09\x00\x02\x00\x00'
    data += '\x10\x2d\x00\x04\x00\x00\x00\x00'
    m1 = data
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: WSC_ACK")
    data = '\x0202:00:00:00:00:00' + '\x10\x22\x00\x01\x0d'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1")
    send_wlanevent(url, uuid, m1)

    logger.info("EAP message: WSC_NACK")
    data = '\x0202:00:00:00:00:00' + '\x10\x22\x00\x01\x0e'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 - Too long attribute values")
    data = '\x0202:00:00:00:00:00'
    data += '\x10\x11\x00\x21' + 33*'\x00'
    data += '\x10\x45\x00\x21' + 33*'\x00'
    data += '\x10\x42\x00\x21' + 33*'\x00'
    data += '\x10\x24\x00\x21' + 33*'\x00'
    data += '\x10\x23\x00\x21' + 33*'\x00'
    data += '\x10\x21\x00\x41' + 65*'\x00'
    data += '\x10\x49\x00\x09\x00\x37\x2a\x05\x02\x00\x00\x05\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing UUID-E")
    data = '\x0202:00:00:00:00:00'
    data += '\x10\x22\x00\x01\x04'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing MAC Address")
    data += '\x10\x47\x00\x10' + 16*'\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Enrollee Nonce")
    data += '\x10\x20\x00\x06\x02\x00\x00\x00\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Public Key")
    data += '\x10\x1a\x00\x10' + 16*'\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Authentication Type flags")
    data += '\x10\x32\x00\xc0' + 192*'\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Encryption Type Flags")
    data += '\x10\x04\x00\x02\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Connection Type flags")
    data += '\x10\x10\x00\x02\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Config Methods")
    data += '\x10\x0d\x00\x01\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Wi-Fi Protected Setup State")
    data += '\x10\x08\x00\x02\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Manufacturer")
    data += '\x10\x44\x00\x01\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Model Name")
    data += '\x10\x21\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Model Number")
    data += '\x10\x23\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Serial Number")
    data += '\x10\x24\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Primary Device Type")
    data += '\x10\x42\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Device Name")
    data += '\x10\x54\x00\x08' + 8*'\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing RF Bands")
    data += '\x10\x11\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Association State")
    data += '\x10\x3c\x00\x01\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Device Password ID")
    data += '\x10\x02\x00\x02\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing Configuration Error")
    data += '\x10\x12\x00\x02\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("EAP message: M1 missing OS Version")
    data += '\x10\x09\x00\x02\x00\x00'
    send_wlanevent(url, uuid, data)

    logger.info("Check max concurrent requests")
    addr = (url.hostname, url.port)
    socks = {}
    for i in range(20):
        socks[i] = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                                 socket.IPPROTO_TCP)
        socks[i].connect(addr)
    for i in range(20):
        socks[i].send("GET / HTTP/1.1\r\n\r\n")
    count = 0
    for i in range(20):
        try:
            res = socks[i].recv(100)
            if "HTTP/1" in res:
                count += 1
        except:
            pass
        socks[i].close()
    logger.info("%d concurrent HTTP GET operations returned response" % count)
    if count < 10:
        raise Exception("Too few concurrent HTTP connections accepted")

    logger.info("OOM in HTTP server")
    for func in [ "http_request_init", "httpread_create",
                  "eloop_register_timeout;httpread_create",
                  "eloop_register_sock;httpread_create",
                  "httpread_hdr_analyze" ]:
        with alloc_fail(dev[0], 1, func):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                                 socket.IPPROTO_TCP)
            sock.connect(addr)
            sock.send("GET / HTTP/1.1\r\n\r\n")
            try:
                sock.recv(100)
            except:
                pass
            sock.close()

    logger.info("Invalid HTTP header")
    for req in [ " GET / HTTP/1.1\r\n\r\n",
                 "HTTP/1.1 200 OK\r\n\r\n",
                 "HTTP/\r\n\r\n",
                 "GET %%a%aa% HTTP/1.1\r\n\r\n",
                 "GET / HTTP/1.1\r\n FOO\r\n\r\n",
                 "NOTIFY / HTTP/1.1\r\n" + 4097*'a' + '\r\n\r\n',
                 "NOTIFY / HTTP/1.1\r\n\r\n" + 8193*'a',
                 "POST / HTTP/1.1\r\nTransfer-Encoding: CHUNKED\r\n\r\n foo\r\n",
                 "POST / HTTP/1.1\r\nTransfer-Encoding: CHUNKED\r\n\r\n1\r\nfoo\r\n",
                 "POST / HTTP/1.1\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\n",
                 "POST / HTTP/1.1\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\naa\ra\r\n\ra" ]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                             socket.IPPROTO_TCP)
        sock.settimeout(0.1)
        sock.connect(addr)
        sock.send(req)
        try:
            sock.recv(100)
        except:
            pass
        sock.close()

    with alloc_fail(dev[0], 2, "httpread_read_handler"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                             socket.IPPROTO_TCP)
        sock.connect(addr)
        sock.send("NOTIFY / HTTP/1.1\r\n\r\n" + 4500*'a')
        try:
            sock.recv(100)
        except:
            pass
        sock.close()

    conn = httplib.HTTPConnection(url.netloc)
    payload = '<foo'
    headers = { "Content-type": 'text/xml; charset="utf-8"',
                "Server": "Unspecified, UPnP/1.0, Unspecified",
                "HOST": url.netloc,
                "NT": "upnp:event",
                "SID": "uuid:" + uuid,
                "SEQ": "0",
                "Content-Length": str(len(payload)) }
    conn.request("NOTIFY", url.path, payload, headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    conn = httplib.HTTPConnection(url.netloc)
    payload = '<WLANEvent foo></WLANEvent>'
    headers = { "Content-type": 'text/xml; charset="utf-8"',
                "Server": "Unspecified, UPnP/1.0, Unspecified",
                "HOST": url.netloc,
                "NT": "upnp:event",
                "SID": "uuid:" + uuid,
                "SEQ": "0",
                "Content-Length": str(len(payload)) }
    conn.request("NOTIFY", url.path, payload, headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)

    with alloc_fail(dev[0], 1, "xml_get_first_item"):
        send_wlanevent(url, uuid, '')

    with alloc_fail(dev[0], 1, "wpabuf_alloc_ext_data;xml_get_base64_item"):
        send_wlanevent(url, uuid, 'foo')

    for func in [ "wps_init",
                  "wps_process_manufacturer",
                  "wps_process_model_name",
                  "wps_process_model_number",
                  "wps_process_serial_number",
                  "wps_process_dev_name" ]:
        with alloc_fail(dev[0], 1, func):
            send_wlanevent(url, uuid, m1)

def test_ap_wps_er_http_proto_no_event_sub_url(dev, apdev):
    """WPS ER HTTP protocol testing - no eventSubURL"""
    class WPSAPHTTPServer_no_event_sub_url(WPSAPHTTPServer):
        def handle_upnp_info(self):
            self.wfile.write(gen_upnp_info(eventSubURL=None))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_no_event_sub_url,
                          no_event_url=True)

def test_ap_wps_er_http_proto_event_sub_url_dns(dev, apdev):
    """WPS ER HTTP protocol testing - DNS name in eventSubURL"""
    class WPSAPHTTPServer_event_sub_url_dns(WPSAPHTTPServer):
        def handle_upnp_info(self):
            self.wfile.write(gen_upnp_info(eventSubURL='http://example.com/wps_event'))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_event_sub_url_dns,
                          no_event_url=True)

def test_ap_wps_er_http_proto_subscribe_oom(dev, apdev):
    """WPS ER HTTP protocol testing - subscribe OOM"""
    try:
        _test_ap_wps_er_http_proto_subscribe_oom(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_http_proto_subscribe_oom(dev, apdev):
    tests = [ (1, "http_client_url_parse"),
              (1, "wpabuf_alloc;wps_er_subscribe"),
              (1, "http_client_addr"),
              (1, "eloop_register_sock;http_client_addr"),
              (1, "eloop_register_timeout;http_client_addr") ]
    for count,func in tests:
        with alloc_fail(dev[0], count, func):
            server,sock = wps_er_start(dev[0], WPSAPHTTPServer)
            server.handle_request()
            server.handle_request()
            wps_er_stop(dev[0], sock, server, on_alloc_fail=True)

def test_ap_wps_er_http_proto_no_sid(dev, apdev):
    """WPS ER HTTP protocol testing - no SID"""
    class WPSAPHTTPServer_no_sid(WPSAPHTTPServer):
        def handle_wps_event(self):
            self.wfile.write(gen_wps_event(sid=None))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_no_sid)

def test_ap_wps_er_http_proto_invalid_sid_no_uuid(dev, apdev):
    """WPS ER HTTP protocol testing - invalid SID - no UUID"""
    class WPSAPHTTPServer_invalid_sid_no_uuid(WPSAPHTTPServer):
        def handle_wps_event(self):
            self.wfile.write(gen_wps_event(sid='FOO'))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_invalid_sid_no_uuid)

def test_ap_wps_er_http_proto_invalid_sid_uuid(dev, apdev):
    """WPS ER HTTP protocol testing - invalid SID UUID"""
    class WPSAPHTTPServer_invalid_sid_uuid(WPSAPHTTPServer):
        def handle_wps_event(self):
            self.wfile.write(gen_wps_event(sid='uuid:FOO'))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_invalid_sid_uuid)

def test_ap_wps_er_http_proto_subscribe_failing(dev, apdev):
    """WPS ER HTTP protocol testing - SUBSCRIBE failing"""
    class WPSAPHTTPServer_fail_subscribe(WPSAPHTTPServer):
        def handle_wps_event(self):
            payload = ""
            hdr = 'HTTP/1.1 404 Not Found\r\n' + \
                  'Content-Type: text/xml; charset="utf-8"\r\n' + \
                  'Server: Unspecified, UPnP/1.0, Unspecified\r\n' + \
                  'Connection: close\r\n' + \
                  'Content-Length: ' + str(len(payload)) + '\r\n' + \
                  'Timeout: Second-1801\r\n' + \
                  'Date: Sat, 15 Aug 2015 18:55:08 GMT\r\n\r\n'
            self.wfile.write(hdr + payload)
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_fail_subscribe)

def test_ap_wps_er_http_proto_subscribe_invalid_response(dev, apdev):
    """WPS ER HTTP protocol testing - SUBSCRIBE and invalid response"""
    class WPSAPHTTPServer_subscribe_invalid_response(WPSAPHTTPServer):
        def handle_wps_event(self):
            payload = ""
            hdr = 'HTTP/1.1 FOO\r\n' + \
                  'Content-Type: text/xml; charset="utf-8"\r\n' + \
                  'Server: Unspecified, UPnP/1.0, Unspecified\r\n' + \
                  'Connection: close\r\n' + \
                  'Content-Length: ' + str(len(payload)) + '\r\n' + \
                  'Timeout: Second-1801\r\n' + \
                  'Date: Sat, 15 Aug 2015 18:55:08 GMT\r\n\r\n'
            self.wfile.write(hdr + payload)
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_subscribe_invalid_response)

def test_ap_wps_er_http_proto_subscribe_invalid_response(dev, apdev):
    """WPS ER HTTP protocol testing - SUBSCRIBE and invalid response"""
    class WPSAPHTTPServer_invalid_m1(WPSAPHTTPServer):
        def handle_wps_control(self):
            payload = '''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetDeviceInfoResponse xmlns:u="urn:schemas-wifialliance-org:service:WFAWLANConfig:1">
<NewDeviceInfo>Rk9P</NewDeviceInfo>
</u:GetDeviceInfoResponse>
</s:Body>
</s:Envelope>
'''
            self.wfile.write(gen_wps_control(payload_override=payload))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_invalid_m1, no_event_url=True)

def test_ap_wps_er_http_proto_upnp_info_no_device(dev, apdev):
    """WPS ER HTTP protocol testing - No device in UPnP info"""
    class WPSAPHTTPServer_no_device(WPSAPHTTPServer):
        def handle_upnp_info(self):
            payload = '''<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion>
<major>1</major>
<minor>0</minor>
</specVersion>
</root>
'''
            hdr = 'HTTP/1.1 200 OK\r\n' + \
                  'Content-Type: text/xml; charset="utf-8"\r\n' + \
                  'Server: Unspecified, UPnP/1.0, Unspecified\r\n' + \
                  'Connection: close\r\n' + \
                  'Content-Length: ' + str(len(payload)) + '\r\n' + \
                  'Date: Sat, 15 Aug 2015 18:55:08 GMT\r\n\r\n'
            self.wfile.write(hdr + payload)
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_no_device, no_event_url=True)

def test_ap_wps_er_http_proto_upnp_info_no_device_type(dev, apdev):
    """WPS ER HTTP protocol testing - No deviceType in UPnP info"""
    class WPSAPHTTPServer_no_device(WPSAPHTTPServer):
        def handle_upnp_info(self):
            payload = '''<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion>
<major>1</major>
<minor>0</minor>
</specVersion>
<device>
</device>
</root>
'''
            hdr = 'HTTP/1.1 200 OK\r\n' + \
                  'Content-Type: text/xml; charset="utf-8"\r\n' + \
                  'Server: Unspecified, UPnP/1.0, Unspecified\r\n' + \
                  'Connection: close\r\n' + \
                  'Content-Length: ' + str(len(payload)) + '\r\n' + \
                  'Date: Sat, 15 Aug 2015 18:55:08 GMT\r\n\r\n'
            self.wfile.write(hdr + payload)
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_no_device, no_event_url=True)

def test_ap_wps_er_http_proto_upnp_info_invalid_udn_uuid(dev, apdev):
    """WPS ER HTTP protocol testing - Invalid UDN UUID"""
    class WPSAPHTTPServer_invalid_udn_uuid(WPSAPHTTPServer):
        def handle_upnp_info(self):
            self.wfile.write(gen_upnp_info(udn='uuid:foo'))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_invalid_udn_uuid)

def test_ap_wps_er_http_proto_no_control_url(dev, apdev):
    """WPS ER HTTP protocol testing - no controlURL"""
    class WPSAPHTTPServer_no_control_url(WPSAPHTTPServer):
        def handle_upnp_info(self):
            self.wfile.write(gen_upnp_info(controlURL=None))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_no_control_url,
                          no_event_url=True)

def test_ap_wps_er_http_proto_control_url_dns(dev, apdev):
    """WPS ER HTTP protocol testing - DNS name in controlURL"""
    class WPSAPHTTPServer_control_url_dns(WPSAPHTTPServer):
        def handle_upnp_info(self):
            self.wfile.write(gen_upnp_info(controlURL='http://example.com/wps_control'))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_control_url_dns,
                          no_event_url=True)

def test_ap_wps_http_timeout(dev, apdev):
    """WPS AP/ER and HTTP timeout"""
    try:
        _test_ap_wps_http_timeout(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_http_timeout(dev, apdev):
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)
    url = urlparse.urlparse(location)
    addr = (url.hostname, url.port)
    logger.debug("Open HTTP connection to hostapd, but do not complete request")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                         socket.IPPROTO_TCP)
    sock.connect(addr)
    sock.send("G")

    class DummyServer(SocketServer.StreamRequestHandler):
        def handle(self):
            logger.debug("DummyServer - start 31 sec wait")
            time.sleep(31)
            logger.debug("DummyServer - wait done")

    logger.debug("Start WPS ER")
    server,sock2 = wps_er_start(dev[0], DummyServer, max_age=40,
                                wait_m_search=True)

    logger.debug("Start server to accept, but not complete, HTTP connection from WPS ER")
    # This will wait for 31 seconds..
    server.handle_request()

    logger.debug("Complete HTTP connection with hostapd (that should have already closed the connection)")
    try:
        sock.send("ET / HTTP/1.1\r\n\r\n")
        res = sock.recv(100)
        sock.close()
    except:
        pass

def test_ap_wps_er_url_parse(dev, apdev):
    """WPS ER and URL parsing special cases"""
    try:
        _test_ap_wps_er_url_parse(dev, apdev)
    finally:
        dev[0].request("WPS_ER_STOP")

def _test_ap_wps_er_url_parse(dev, apdev):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("239.255.255.250", 1900))
    dev[0].request("WPS_ER_START ifname=lo")
    (msg,addr) = sock.recvfrom(1000)
    logger.debug("Received SSDP message from %s: %s" % (str(addr), msg))
    if "M-SEARCH" not in msg:
        raise Exception("Not an M-SEARCH")
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:http://127.0.0.1\r\ncache-control:max-age=1\r\n\r\n", addr)
    ev = dev[0].wait_event(["WPS-ER-AP-REMOVE"], timeout=2)
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:http://127.0.0.1/:foo\r\ncache-control:max-age=1\r\n\r\n", addr)
    ev = dev[0].wait_event(["WPS-ER-AP-REMOVE"], timeout=2)
    sock.sendto("HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\nlocation:http://255.255.255.255:0/foo.xml\r\ncache-control:max-age=1\r\n\r\n", addr)
    ev = dev[0].wait_event(["WPS-ER-AP-REMOVE"], timeout=2)

    sock.close()

def test_ap_wps_er_link_update(dev, apdev):
    """WPS ER and link update special cases"""
    class WPSAPHTTPServer_link_update(WPSAPHTTPServer):
        def handle_upnp_info(self):
            self.wfile.write(gen_upnp_info(controlURL='/wps_control'))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_link_update)

    class WPSAPHTTPServer_link_update2(WPSAPHTTPServer):
        def handle_others(self, data):
            if "GET / " in data:
                self.wfile.write(gen_upnp_info(controlURL='/wps_control'))
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_link_update2,
                          location_url='http://127.0.0.1:12345')

def test_ap_wps_er_http_client(dev, apdev):
    """WPS ER and HTTP client special cases"""
    with alloc_fail(dev[0], 1, "http_link_update"):
        run_wps_er_proto_test(dev[0], WPSAPHTTPServer)

    with alloc_fail(dev[0], 1, "wpabuf_alloc;http_client_url"):
        run_wps_er_proto_test(dev[0], WPSAPHTTPServer, no_event_url=True)

    with alloc_fail(dev[0], 1, "httpread_create;http_client_tx_ready"):
        run_wps_er_proto_test(dev[0], WPSAPHTTPServer, no_event_url=True)

    class WPSAPHTTPServer_req_as_resp(WPSAPHTTPServer):
        def handle_upnp_info(self):
            self.wfile.write("GET / HTTP/1.1\r\n\r\n")
    run_wps_er_proto_test(dev[0], WPSAPHTTPServer_req_as_resp,
                          no_event_url=True)

def test_ap_wps_init_oom(dev, apdev):
    """wps_init OOM cases"""
    ssid = "test-wps"
    appin = "12345670"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "ap_pin": appin }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    pin = dev[0].wps_read_pin()

    with alloc_fail(hapd, 1, "wps_init"):
        hapd.request("WPS_PIN any " + pin)
        dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        ev = hapd.wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
        if ev is None:
            raise Exception("No EAP failure reported")
        dev[0].request("WPS_CANCEL")

    with alloc_fail(dev[0], 2, "wps_init"):
        hapd.request("WPS_PIN any " + pin)
        dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        ev = hapd.wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
        if ev is None:
            raise Exception("No EAP failure reported")
        dev[0].request("WPS_CANCEL")

    with alloc_fail(dev[0], 2, "wps_init"):
        hapd.request("WPS_PBC")
        dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
        dev[0].request("WPS_PBC %s" % (apdev[0]['bssid']))
        ev = hapd.wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
        if ev is None:
            raise Exception("No EAP failure reported")
        dev[0].request("WPS_CANCEL")

    dev[0].dump_monitor()
    new_ssid = "wps-new-ssid"
    new_passphrase = "1234567890"
    with alloc_fail(dev[0], 3, "wps_init"):
        dev[0].wps_reg(apdev[0]['bssid'], appin, new_ssid, "WPA2PSK", "CCMP",
                       new_passphrase, no_wait=True)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
        if ev is None:
            raise Exception("No EAP failure reported")

    dev[0].flush_scan_cache()

def test_ap_wps_invalid_assoc_req_elem(dev, apdev):
    """WPS and invalid IE in Association Request frame"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    pin = "12345670"
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    try:
        dev[0].request("VENDOR_ELEM_ADD 13 dd050050f20410")
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        for i in range(5):
            ev = hapd.wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=10)
            if ev and "vendor=14122" in ev:
                break
        if ev is None or "vendor=14122" not in ev:
            raise Exception("EAP-WSC not started")
        dev[0].request("WPS_CANCEL")
    finally:
        dev[0].request("VENDOR_ELEM_REMOVE 13 *")

def test_ap_wps_pbc_pin_mismatch(dev, apdev):
    """WPS PBC/PIN mismatch"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    hapd.request("SET wps_version_number 0x10")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    hapd.request("WPS_PBC")
    pin = dev[0].wps_read_pin()
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Scan did not complete")
    dev[0].request("WPS_CANCEL")

    hapd.request("WPS_CANCEL")
    dev[0].flush_scan_cache()

def test_ap_wps_ie_invalid(dev, apdev):
    """WPS PIN attempt with AP that has invalid WSC IE"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "vendor_elements": "dd050050f20410" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    params = { 'ssid': "another", "vendor_elements": "dd050050f20410" }
    hostapd.add_ap(apdev[1]['ifname'], params)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    pin = dev[0].wps_read_pin()
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Scan did not complete")
    dev[0].request("WPS_CANCEL")

def test_ap_wps_scan_prio_order(dev, apdev):
    """WPS scan priority ordering"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    params = { 'ssid': "another", "vendor_elements": "dd050050f20410" }
    hostapd.add_ap(apdev[1]['ifname'], params)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    pin = dev[0].wps_read_pin()
    dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Scan did not complete")
    dev[0].request("WPS_CANCEL")

def test_ap_wps_probe_req_ie_oom(dev, apdev):
    """WPS ProbeReq IE OOM"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    pin = dev[0].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    with alloc_fail(dev[0], 1, "wps_build_probe_req_ie"):
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        ev = hapd.wait_event(["AP-STA-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Association not seen")
    dev[0].request("WPS_CANCEL")

    with alloc_fail(dev[0], 1, "wps_ie_encapsulate"):
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        ev = hapd.wait_event(["AP-STA-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Association not seen")
    dev[0].request("WPS_CANCEL")

def test_ap_wps_assoc_req_ie_oom(dev, apdev):
    """WPS AssocReq IE OOM"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    pin = dev[0].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    with alloc_fail(dev[0], 1, "wps_build_assoc_req_ie"):
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        ev = hapd.wait_event(["AP-STA-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Association not seen")
    dev[0].request("WPS_CANCEL")

def test_ap_wps_assoc_resp_ie_oom(dev, apdev):
    """WPS AssocResp IE OOM"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    pin = dev[0].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    with alloc_fail(hapd, 1, "wps_build_assoc_resp_ie"):
        dev[0].request("WPS_PIN %s %s" % (apdev[0]['bssid'], pin))
        ev = hapd.wait_event(["AP-STA-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Association not seen")
    dev[0].request("WPS_CANCEL")

def test_ap_wps_bss_info_errors(dev, apdev):
    """WPS BSS info errors"""
    params = { "ssid": "1",
               "vendor_elements": "dd0e0050f20410440001ff101100010a" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    params = { 'ssid': "2", "vendor_elements": "dd050050f20410" }
    hostapd.add_ap(apdev[1]['ifname'], params)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    logger.info("BSS: " + str(bss))
    if "wps_state" in bss:
        raise Exception("Unexpected wps_state in BSS info")
    if 'wps_device_name' not in bss:
        raise Exception("No wps_device_name in BSS info")
    if bss['wps_device_name'] != '_':
        raise Exception("Unexpected wps_device_name value")
    bss = dev[0].get_bss(apdev[1]['bssid'])
    logger.info("BSS: " + str(bss))

    with alloc_fail(dev[0], 1, "=wps_attr_text"):
        bss = dev[0].get_bss(apdev[0]['bssid'])
        logger.info("BSS(OOM): " + str(bss))

def wps_run_pbc_fail_ap(apdev, dev, hapd):
    hapd.request("WPS_PBC")
    dev.scan_for_bss(apdev['bssid'], freq="2412")
    dev.request("WPS_PBC " + apdev['bssid'])
    ev = dev.wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("No EAP failure reported")
    dev.request("WPS_CANCEL")
    dev.wait_disconnected()
    for i in range(5):
        try:
            dev.flush_scan_cache()
            break
        except Exception, e:
            if str(e).startswith("Failed to trigger scan"):
                # Try again
                time.sleep(1)
            else:
                raise

def wps_run_pbc_fail(apdev, dev):
    hapd = wps_start_ap(apdev)
    wps_run_pbc_fail_ap(apdev, dev, hapd)

def test_ap_wps_pk_oom(dev, apdev):
    """WPS and public key OOM"""
    with alloc_fail(dev[0], 1, "wps_build_public_key"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_pk_oom_ap(dev, apdev):
    """WPS and public key OOM on AP"""
    hapd = wps_start_ap(apdev[0])
    with alloc_fail(hapd, 1, "wps_build_public_key"):
        wps_run_pbc_fail_ap(apdev[0], dev[0], hapd)

def test_ap_wps_encr_oom_ap(dev, apdev):
    """WPS and encrypted settings decryption OOM on AP"""
    hapd = wps_start_ap(apdev[0])
    pin = dev[0].wps_read_pin()
    hapd.request("WPS_PIN any " + pin)
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    with alloc_fail(hapd, 1, "wps_decrypt_encr_settings"):
        dev[0].request("WPS_PIN " + apdev[0]['bssid'] + " " + pin)
        ev = hapd.wait_event(["WPS-FAIL"], timeout=10)
        if ev is None:
            raise Exception("No WPS-FAIL reported")
        dev[0].request("WPS_CANCEL")
    dev[0].wait_disconnected()

def test_ap_wps_encr_no_random_ap(dev, apdev):
    """WPS and no random data available for encryption on AP"""
    hapd = wps_start_ap(apdev[0])
    with fail_test(hapd, 1, "os_get_random;wps_build_encr_settings"):
        wps_run_pbc_fail_ap(apdev[0], dev[0], hapd)

def test_ap_wps_e_hash_no_random_sta(dev, apdev):
    """WPS and no random data available for e-hash on STA"""
    with fail_test(dev[0], 1, "os_get_random;wps_build_e_hash"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_m1_no_random(dev, apdev):
    """WPS and no random for M1 on STA"""
    with fail_test(dev[0], 1, "os_get_random;wps_build_m1"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_m1_oom(dev, apdev):
    """WPS and OOM for M1 on STA"""
    with alloc_fail(dev[0], 1, "wps_build_m1"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_m3_oom(dev, apdev):
    """WPS and OOM for M3 on STA"""
    with alloc_fail(dev[0], 1, "wps_build_m3"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_m5_oom(dev, apdev):
    """WPS and OOM for M5 on STA"""
    hapd = wps_start_ap(apdev[0])
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    for i in range(1, 3):
        with alloc_fail(dev[0], i, "wps_build_m5"):
            dev[0].request("WPS_PBC " + apdev[0]['bssid'])
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
            if ev is None:
                raise Exception("No EAP failure reported")
            dev[0].request("WPS_CANCEL")
            dev[0].wait_disconnected()
    dev[0].flush_scan_cache()

def test_ap_wps_m5_no_random(dev, apdev):
    """WPS and no random for M5 on STA"""
    with fail_test(dev[0], 1,
                   "os_get_random;wps_build_encr_settings;wps_build_m5"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_m7_oom(dev, apdev):
    """WPS and OOM for M7 on STA"""
    hapd = wps_start_ap(apdev[0])
    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    for i in range(1, 3):
        with alloc_fail(dev[0], i, "wps_build_m7"):
            dev[0].request("WPS_PBC " + apdev[0]['bssid'])
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
            if ev is None:
                raise Exception("No EAP failure reported")
            dev[0].request("WPS_CANCEL")
            dev[0].wait_disconnected()
    dev[0].flush_scan_cache()

def test_ap_wps_m7_no_random(dev, apdev):
    """WPS and no random for M7 on STA"""
    with fail_test(dev[0], 1,
                   "os_get_random;wps_build_encr_settings;wps_build_m7"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_wsc_done_oom(dev, apdev):
    """WPS and OOM for WSC_Done on STA"""
    with alloc_fail(dev[0], 1, "wps_build_wsc_done"):
        wps_run_pbc_fail(apdev[0], dev[0])

def test_ap_wps_random_psk_fail(dev, apdev):
    """WPS and no random for PSK on AP"""
    ssid = "test-wps"
    pskfile = "/tmp/ap_wps_per_enrollee_psk.psk_file"
    appin = "12345670"
    try:
        os.remove(pskfile)
    except:
        pass

    try:
        with open(pskfile, "w") as f:
            f.write("# WPA PSKs\n")

        params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                   "wpa": "2", "wpa_key_mgmt": "WPA-PSK",
                   "rsn_pairwise": "CCMP", "ap_pin": appin,
                   "wpa_psk_file": pskfile }
        hapd = hostapd.add_ap(apdev[0]['ifname'], params)

        dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
        with fail_test(hapd, 1, "os_get_random;wps_build_cred_network_key"):
            dev[0].request("WPS_REG " + apdev[0]['bssid'] + " " + appin)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
            if ev is None:
                raise Exception("No EAP failure reported")
            dev[0].request("WPS_CANCEL")
        dev[0].wait_disconnected()

        with fail_test(hapd, 1, "os_get_random;wps_build_cred"):
            wps_run_pbc_fail_ap(apdev[0], dev[0], hapd)

        with alloc_fail(hapd, 1, "wps_build_cred"):
            wps_run_pbc_fail_ap(apdev[0], dev[0], hapd)

        with alloc_fail(hapd, 2, "wps_build_cred"):
            wps_run_pbc_fail_ap(apdev[0], dev[0], hapd)
    finally:
        os.remove(pskfile)

def wps_ext_eap_identity_req(dev, hapd, bssid):
    logger.debug("EAP-Identity/Request")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX from hostapd")
    res = dev.request("EAPOL_RX " + bssid + " " + ev.split(' ')[2])
    if "OK" not in res:
        raise Exception("EAPOL_RX to wpa_supplicant failed")

def wps_ext_eap_identity_resp(hapd, dev, addr):
    ev = dev.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX from wpa_supplicant")
    res = hapd.request("EAPOL_RX " + addr + " " + ev.split(' ')[2])
    if "OK" not in res:
        raise Exception("EAPOL_RX to hostapd failed")

def wps_ext_eap_wsc(dst, src, src_addr, msg):
    logger.debug(msg)
    ev = src.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    res = dst.request("EAPOL_RX " + src_addr + " " + ev.split(' ')[2])
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")

def wps_start_ext(apdev, dev, pbc=False):
    addr = dev.own_addr()
    bssid = apdev['bssid']
    ssid = "test-wps-conf"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"}
    hapd = hostapd.add_ap(apdev['ifname'], params)

    if pbc:
        hapd.request("WPS_PBC")
    else:
        pin = dev.wps_read_pin()
        hapd.request("WPS_PIN any " + pin)
    dev.scan_for_bss(bssid, freq="2412")
    hapd.request("SET ext_eapol_frame_io 1")
    dev.request("SET ext_eapol_frame_io 1")

    if pbc:
        dev.request("WPS_PBC " + bssid)
    else:
        dev.request("WPS_PIN " + bssid + " " + pin)
    return addr,bssid,hapd

def wps_auth_corrupt(dst, src, addr):
    ev = src.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    src.request("SET ext_eapol_frame_io 0")
    dst.request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[-24:-16] != '10050008':
        raise Exception("Could not find Authenticator attribute")
    # Corrupt Authenticator value
    msg = msg[:-1] + '%x' % ((int(msg[-1], 16) + 1) % 16)
    res = dst.request("EAPOL_RX " + addr + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")

def wps_fail_finish(hapd, dev, fail_str):
    ev = hapd.wait_event(["WPS-FAIL"], timeout=5)
    if ev is None:
        raise Exception("WPS-FAIL not indicated")
    if fail_str not in ev:
        raise Exception("Unexpected WPS-FAIL value: " + ev)
    dev.request("WPS_CANCEL")
    dev.wait_disconnected()

def wps_auth_corrupt_from_ap(dev, hapd, bssid, fail_str):
    wps_auth_corrupt(dev, hapd, bssid)
    wps_fail_finish(hapd, dev, fail_str)

def wps_auth_corrupt_to_ap(dev, hapd, addr, fail_str):
    wps_auth_corrupt(hapd, dev, addr)
    wps_fail_finish(hapd, dev, fail_str)

def test_ap_wps_authenticator_mismatch_m2(dev, apdev):
    """WPS and Authenticator attribute mismatch in M2"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    wps_auth_corrupt_from_ap(dev[0], hapd, bssid, "msg=5")

def test_ap_wps_authenticator_mismatch_m3(dev, apdev):
    """WPS and Authenticator attribute mismatch in M3"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M2")
    logger.debug("M3")
    wps_auth_corrupt_to_ap(dev[0], hapd, addr, "msg=7")

def test_ap_wps_authenticator_mismatch_m4(dev, apdev):
    """WPS and Authenticator attribute mismatch in M4"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M2")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M3")
    logger.debug("M4")
    wps_auth_corrupt_from_ap(dev[0], hapd, bssid, "msg=8")

def test_ap_wps_authenticator_mismatch_m5(dev, apdev):
    """WPS and Authenticator attribute mismatch in M5"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M2")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M3")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M4")
    logger.debug("M5")
    wps_auth_corrupt_to_ap(dev[0], hapd, addr, "msg=9")

def test_ap_wps_authenticator_mismatch_m6(dev, apdev):
    """WPS and Authenticator attribute mismatch in M6"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M2")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M3")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M4")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M5")
    logger.debug("M6")
    wps_auth_corrupt_from_ap(dev[0], hapd, bssid, "msg=10")

def test_ap_wps_authenticator_mismatch_m7(dev, apdev):
    """WPS and Authenticator attribute mismatch in M7"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M2")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M3")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M4")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M5")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M6")
    logger.debug("M7")
    wps_auth_corrupt_to_ap(dev[0], hapd, addr, "msg=11")

def test_ap_wps_authenticator_mismatch_m8(dev, apdev):
    """WPS and Authenticator attribute mismatch in M8"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M2")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M3")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M4")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M5")
    wps_ext_eap_wsc(dev[0], hapd, bssid, "M6")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M7")
    logger.debug("M8")
    wps_auth_corrupt_from_ap(dev[0], hapd, bssid, "msg=12")

def test_ap_wps_authenticator_missing_m2(dev, apdev):
    """WPS and Authenticator attribute missing from M2"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[-24:-16] != '10050008':
        raise Exception("Could not find Authenticator attribute")
    # Remove Authenticator value
    msg = msg[:-24]
    mlen = "%04x" % (int(msg[4:8], 16) - 12)
    msg = msg[0:4] + mlen + msg[8:12] + mlen + msg[16:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    wps_fail_finish(hapd, dev[0], "msg=5")

def test_ap_wps_m2_dev_passwd_id_p2p(dev, apdev):
    """WPS and M2 with different Device Password ID (P2P)"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[722:730] != '10120002':
        raise Exception("Could not find Device Password ID attribute")
    # Replace Device Password ID value. This will fail Authenticator check, but
    # allows the code path in wps_process_dev_pw_id() to be checked from debug
    # log.
    msg = msg[0:730] + "0005" + msg[734:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    wps_fail_finish(hapd, dev[0], "msg=5")

def test_ap_wps_m2_dev_passwd_id_change_pin_to_pbc(dev, apdev):
    """WPS and M2 with different Device Password ID (PIN to PBC)"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[722:730] != '10120002':
        raise Exception("Could not find Device Password ID attribute")
    # Replace Device Password ID value (PIN --> PBC). This will be rejected.
    msg = msg[0:730] + "0004" + msg[734:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    wps_fail_finish(hapd, dev[0], "msg=5")

def test_ap_wps_m2_dev_passwd_id_change_pbc_to_pin(dev, apdev):
    """WPS and M2 with different Device Password ID (PBC to PIN)"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[722:730] != '10120002':
        raise Exception("Could not find Device Password ID attribute")
    # Replace Device Password ID value. This will fail Authenticator check, but
    # allows the code path in wps_process_dev_pw_id() to be checked from debug
    # log.
    msg = msg[0:730] + "0000" + msg[734:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    wps_fail_finish(hapd, dev[0], "msg=5")
    dev[0].flush_scan_cache()

def test_ap_wps_m2_missing_dev_passwd_id(dev, apdev):
    """WPS and M2 without Device Password ID"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0])
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[722:730] != '10120002':
        raise Exception("Could not find Device Password ID attribute")
    # Remove Device Password ID value. This will fail Authenticator check, but
    # allows the code path in wps_process_dev_pw_id() to be checked from debug
    # log.
    mlen = "%04x" % (int(msg[4:8], 16) - 6)
    msg = msg[0:4] + mlen + msg[8:12] + mlen + msg[16:722] + msg[734:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    wps_fail_finish(hapd, dev[0], "msg=5")

def test_ap_wps_m2_missing_registrar_nonce(dev, apdev):
    """WPS and M2 without Registrar Nonce"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[96:104] != '10390010':
        raise Exception("Could not find Registrar Nonce attribute")
    # Remove Registrar Nonce. This will fail Authenticator check, but
    # allows the code path in wps_process_registrar_nonce() to be checked from
    # the debug log.
    mlen = "%04x" % (int(msg[4:8], 16) - 20)
    msg = msg[0:4] + mlen + msg[8:12] + mlen + msg[16:96] + msg[136:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECT"], timeout=5)
    if ev is None:
        raise Exception("Disconnect event not seen")
    dev[0].request("WPS_CANCEL")
    dev[0].flush_scan_cache()

def test_ap_wps_m2_missing_enrollee_nonce(dev, apdev):
    """WPS and M2 without Enrollee Nonce"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[56:64] != '101a0010':
        raise Exception("Could not find enrollee Nonce attribute")
    # Remove Enrollee Nonce. This will fail Authenticator check, but
    # allows the code path in wps_process_enrollee_nonce() to be checked from
    # the debug log.
    mlen = "%04x" % (int(msg[4:8], 16) - 20)
    msg = msg[0:4] + mlen + msg[8:12] + mlen + msg[16:56] + msg[96:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECT"], timeout=5)
    if ev is None:
        raise Exception("Disconnect event not seen")
    dev[0].request("WPS_CANCEL")
    dev[0].flush_scan_cache()

def test_ap_wps_m2_missing_uuid_r(dev, apdev):
    """WPS and M2 without UUID-R"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[136:144] != '10480010':
        raise Exception("Could not find enrollee Nonce attribute")
    # Remove UUID-R. This will fail Authenticator check, but allows the code
    # path in wps_process_uuid_r() to be checked from the debug log.
    mlen = "%04x" % (int(msg[4:8], 16) - 20)
    msg = msg[0:4] + mlen + msg[8:12] + mlen + msg[16:136] + msg[176:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECT"], timeout=5)
    if ev is None:
        raise Exception("Disconnect event not seen")
    dev[0].request("WPS_CANCEL")
    dev[0].flush_scan_cache()

def test_ap_wps_m2_invalid(dev, apdev):
    """WPS and M2 parsing failure"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[136:144] != '10480010':
        raise Exception("Could not find enrollee Nonce attribute")
    # Remove UUID-R. This will fail Authenticator check, but allows the code
    # path in wps_process_uuid_r() to be checked from the debug log.
    mlen = "%04x" % (int(msg[4:8], 16) - 1)
    msg = msg[0:4] + mlen + msg[8:12] + mlen + msg[16:-2]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECT"], timeout=5)
    if ev is None:
        raise Exception("Disconnect event not seen")
    dev[0].request("WPS_CANCEL")
    dev[0].flush_scan_cache()

def test_ap_wps_m2_missing_msg_type(dev, apdev):
    """WPS and M2 without Message Type"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[46:54] != '10220001':
        raise Exception("Could not find Message Type attribute")
    # Remove Message Type. This will fail Authenticator check, but allows the
    # code path in wps_process_wsc_msg() to be checked from the debug log.
    mlen = "%04x" % (int(msg[4:8], 16) - 5)
    msg = msg[0:4] + mlen + msg[8:12] + mlen + msg[16:46] + msg[56:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECT"], timeout=5)
    if ev is None:
        raise Exception("Disconnect event not seen")
    dev[0].request("WPS_CANCEL")
    dev[0].flush_scan_cache()

def test_ap_wps_m2_unknown_msg_type(dev, apdev):
    """WPS and M2 but unknown Message Type"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[46:54] != '10220001':
        raise Exception("Could not find Message Type attribute")
    # Replace Message Type value. This will be rejected.
    msg = msg[0:54] + "00" + msg[56:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECT"], timeout=5)
    if ev is None:
        raise Exception("Disconnect event not seen")
    dev[0].request("WPS_CANCEL")
    dev[0].flush_scan_cache()

def test_ap_wps_m2_unknown_opcode(dev, apdev):
    """WPS and M2 but unknown opcode"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    # Replace opcode. This will be discarded in EAP-WSC processing.
    msg = msg[0:32] + "00" + msg[34:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    dev[0].request("WPS_CANCEL")
    dev[0].wait_disconnected()
    dev[0].flush_scan_cache()

def test_ap_wps_m2_unknown_opcode2(dev, apdev):
    """WPS and M2 but unknown opcode (WSC_Start)"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    # Replace opcode. This will be discarded in EAP-WSC processing.
    msg = msg[0:32] + "01" + msg[34:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    dev[0].request("WPS_CANCEL")
    dev[0].wait_disconnected()
    dev[0].flush_scan_cache()

def test_ap_wps_m2_unknown_opcode3(dev, apdev):
    """WPS and M2 but unknown opcode (WSC_Done)"""
    addr,bssid,hapd = wps_start_ext(apdev[0], dev[0], pbc=True)
    wps_ext_eap_identity_req(dev[0], hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev[0], addr)
    wps_ext_eap_wsc(dev[0], hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev[0], addr, "M1")
    logger.debug("M2")
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev[0].request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    # Replace opcode. This will be discarded in WPS Enrollee processing.
    msg = msg[0:32] + "05" + msg[34:]
    res = dev[0].request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    dev[0].request("WPS_CANCEL")
    dev[0].wait_disconnected()
    dev[0].flush_scan_cache()

def wps_m2_but_other(dev, apdev, title, msgtype):
    addr,bssid,hapd = wps_start_ext(apdev, dev)
    wps_ext_eap_identity_req(dev, hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev, addr)
    wps_ext_eap_wsc(dev, hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev, addr, "M1")
    logger.debug(title)
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev.request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[46:54] != '10220001':
        raise Exception("Could not find Message Type attribute")
    # Replace Message Type value. This will be rejected.
    msg = msg[0:54] + msgtype + msg[56:]
    res = dev.request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = dev.wait_event(["WPS-FAIL"], timeout=5)
    if ev is None:
        raise Exception("WPS-FAIL event not seen")
    dev.request("WPS_CANCEL")
    dev.wait_disconnected()

def wps_m4_but_other(dev, apdev, title, msgtype):
    addr,bssid,hapd = wps_start_ext(apdev, dev)
    wps_ext_eap_identity_req(dev, hapd, bssid)
    wps_ext_eap_identity_resp(hapd, dev, addr)
    wps_ext_eap_wsc(dev, hapd, bssid, "EAP-WSC/Start")
    wps_ext_eap_wsc(hapd, dev, addr, "M1")
    wps_ext_eap_wsc(dev, hapd, bssid, "M2")
    wps_ext_eap_wsc(hapd, dev, addr, "M3")
    logger.debug(title)
    ev = hapd.wait_event(["EAPOL-TX"], timeout=10)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX")
    hapd.request("SET ext_eapol_frame_io 0")
    dev.request("SET ext_eapol_frame_io 0")
    msg = ev.split(' ')[2]
    if msg[46:54] != '10220001':
        raise Exception("Could not find Message Type attribute")
    # Replace Message Type value. This will be rejected.
    msg = msg[0:54] + msgtype + msg[56:]
    res = dev.request("EAPOL_RX " + bssid + " " + msg)
    if "OK" not in res:
        raise Exception("EAPOL_RX failed")
    ev = hapd.wait_event(["WPS-FAIL"], timeout=5)
    if ev is None:
        raise Exception("WPS-FAIL event not seen")
    dev.request("WPS_CANCEL")
    dev.wait_disconnected()

def test_ap_wps_m2_msg_type_m4(dev, apdev):
    """WPS and M2 but Message Type M4"""
    wps_m2_but_other(dev[0], apdev[0], "M2/M4", "08")

def test_ap_wps_m2_msg_type_m6(dev, apdev):
    """WPS and M2 but Message Type M6"""
    wps_m2_but_other(dev[0], apdev[0], "M2/M6", "0a")

def test_ap_wps_m2_msg_type_m8(dev, apdev):
    """WPS and M2 but Message Type M8"""
    wps_m2_but_other(dev[0], apdev[0], "M2/M8", "0c")

def test_ap_wps_m4_msg_type_m2(dev, apdev):
    """WPS and M4 but Message Type M2"""
    wps_m4_but_other(dev[0], apdev[0], "M4/M2", "05")

def test_ap_wps_m4_msg_type_m2d(dev, apdev):
    """WPS and M4 but Message Type M2D"""
    wps_m4_but_other(dev[0], apdev[0], "M4/M2D", "06")

def test_ap_wps_config_methods(dev, apdev):
    """WPS configuration method parsing"""
    ssid = "test-wps-conf"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
               "config_methods": "ethernet display ext_nfc_token int_nfc_token physical_display physical_push_button" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "2",
               "wpa_passphrase": "12345678", "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
               "config_methods": "display push_button" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)

def test_ap_wps_set_selected_registrar_proto(dev, apdev):
    """WPS UPnP SetSelectedRegistrar protocol testing"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hapd = add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    location = ssdp_get_location(ap_uuid)
    urls = upnp_get_urls(location)
    eventurl = urlparse.urlparse(urls['event_sub_url'])
    ctrlurl = urlparse.urlparse(urls['control_url'])
    url = urlparse.urlparse(location)
    conn = httplib.HTTPConnection(url.netloc)

    class WPSERHTTPServer(SocketServer.StreamRequestHandler):
        def handle(self):
            data = self.rfile.readline().strip()
            logger.debug(data)
            self.wfile.write(gen_wps_event())

    server = MyTCPServer(("127.0.0.1", 12345), WPSERHTTPServer)
    server.timeout = 1

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %d" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)
    server.handle_request()

    tests = [ (500, "10"),
              (200, "104a000110" + "1041000101" + "101200020000" +
               "105300023148" +
               "1049002c00372a0001200124111111111111222222222222333333333333444444444444555555555555666666666666" +
               "10480010362db47ba53a519188fb5458b986b2e4"),
              (200, "104a000110" + "1041000100" + "101200020000" +
               "105300020000"),
              (200, "104a000110" + "1041000100"),
              (200, "104a000110") ]
    for status,test in tests:
        tlvs = binascii.unhexlify(test)
        newmsg = base64.b64encode(tlvs)
        msg = '<?xml version="1.0"?>\n'
        msg += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        msg += '<s:Body>'
        msg += '<u:SetSelectedRegistrar xmlns:u="urn:schemas-wifialliance-org:service:WFAWLANConfig:1">'
        msg += '<NewMessage>'
        msg += newmsg
        msg += "</NewMessage></u:SetSelectedRegistrar></s:Body></s:Envelope>"
        headers = { "Content-type": 'text/xml; charset="utf-8"' }
        headers["SOAPAction"] = '"urn:schemas-wifialliance-org:service:WFAWLANConfig:1#%s"' % "SetSelectedRegistrar"
        conn.request("POST", ctrlurl.path, msg, headers)
        resp = conn.getresponse()
        if resp.status != status:
            raise Exception("Unexpected HTTP response: %d (expected %d)" % (resp.status, status))

def test_ap_wps_adv_oom(dev, apdev):
    """WPS AP and advertisement OOM"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    hapd = add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

    with alloc_fail(hapd, 1, "=msearchreply_state_machine_start"):
        ssdp_send_msearch("urn:schemas-wifialliance-org:service:WFAWLANConfig:1",
                          no_recv=True)
        time.sleep(0.2)

    with alloc_fail(hapd, 1, "eloop_register_timeout;msearchreply_state_machine_start"):
        ssdp_send_msearch("urn:schemas-wifialliance-org:service:WFAWLANConfig:1",
                          no_recv=True)
        time.sleep(0.2)

    with alloc_fail(hapd, 1,
                    "next_advertisement;advertisement_state_machine_stop"):
        hapd.disable()

    with alloc_fail(hapd, 1, "ssdp_listener_start"):
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("ENABLE succeeded during OOM")

def test_wps_config_methods(dev):
    """WPS config method update"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    if "OK" not in wpas.request("SET config_methods display label"):
        raise Exception("Failed to set config_methods")
    if wpas.request("GET config_methods").strip() != "display label":
        raise Exception("config_methods were not updated")
    if "OK" not in wpas.request("SET config_methods "):
        raise Exception("Failed to clear config_methods")
    if wpas.request("GET config_methods").strip() != "":
        raise Exception("config_methods were not cleared")
