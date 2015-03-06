# WPS tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time
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

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from utils import HwsimSkip

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
    ev = dev[1].wait_event(["WPS-M2D"], timeout=15)
    if ev is None:
        raise Exception("PBC session overlap not detected (dev1)")
    if "config_error=12" not in ev:
        raise Exception("PBC session overlap not correctly reported (dev1)")
    hapd.request("WPS_CANCEL")
    ret = hapd.request("WPS_PBC")
    if "FAIL" not in ret:
        raise Exception("PBC mode allowed to be started while PBC overlap still active")

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
    """wpa_supplicant PBC walk time [long]"""
    if not params['long']:
        raise HwsimSkip("Skip test case with long duration due to --long not specified")
    ssid = "test-wps"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("Start WPS_PBC and wait for PBC walk time expiration")
    if "OK" not in dev[0].request("WPS_PBC"):
        raise Exception("WPS_PBC failed")
    ev = dev[0].wait_event(["WPS-TIMEOUT"], timeout=150)
    if ev is None:
        raise Exception("WPS-TIMEOUT not reported")

def add_ssdp_ap(ifname, ap_uuid):
    ssid = "wps-ssdp"
    ap_pin = "12345670"
    hostapd.add_ap(ifname,
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
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
                     "upc": "123456789012" })

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

def ssdp_send_msearch(st):
    msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MX: 1',
            'MAN: "ssdp:discover"',
            'ST: ' + st,
            '', ''])
    return ssdp_send(msg)

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
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    conn.request("UNKNOWN", "hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 501:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    headers = { "Content-type": 'text/xml; charset="utf-8"',
                "SOAPAction": '"urn:some-unknown-action#GetDeviceInfo"' }
    ctrlurl = urlparse.urlparse(urls['control_url'])
    conn.request("POST", ctrlurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 401:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("GetDeviceInfo without SOAPAction header")
    resp = upnp_soap_action(conn, ctrlurl.path, "GetDeviceInfo",
                            include_soap_action=False)
    if resp.status != 401:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("GetDeviceInfo with invalid SOAPAction header")
    for act in [ "foo",
                 "urn:schemas-wifialliance-org:service:WFAWLANConfig:1#GetDeviceInfo",
                 '"urn:schemas-wifialliance-org:service:WFAWLANConfig:1"',
                 '"urn:schemas-wifialliance-org:service:WFAWLANConfig:123#GetDevice']:
        resp = upnp_soap_action(conn, ctrlurl.path, "GetDeviceInfo",
                                include_soap_action=False,
                                soap_action_override=act)
        if resp.status != 401:
            raise Exception("Unexpected HTTP response: %s" % resp.status)

    resp = upnp_soap_action(conn, ctrlurl.path, "GetDeviceInfo")
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %s" % resp.status)
    dev = resp.read()
    if "NewDeviceInfo" not in dev:
        raise Exception("Unexpected GetDeviceInfo response")

    logger.debug("PutMessage without required parameters")
    resp = upnp_soap_action(conn, ctrlurl.path, "PutMessage")
    if resp.status != 600:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("PutWLANResponse without required parameters")
    resp = upnp_soap_action(conn, ctrlurl.path, "PutWLANResponse")
    if resp.status != 600:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("SetSelectedRegistrar from unregistered ER")
    resp = upnp_soap_action(conn, ctrlurl.path, "SetSelectedRegistrar")
    if resp.status != 501:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Unknown action")
    resp = upnp_soap_action(conn, ctrlurl.path, "Unknown")
    if resp.status != 401:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

def test_ap_wps_upnp_subscribe(dev, apdev):
    """WPS AP and UPnP event subscription"""
    ap_uuid = "27ea801a-9e5c-4e73-bd82-f89cbcd10d7e"
    add_ssdp_ap(apdev[0]['ifname'], ap_uuid)

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
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    headers = { "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:foobar",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Valid subscription")
    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %s" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)

    logger.debug("Invalid re-subscription")
    headers = { "NT": "upnp:event",
                "sid": "123456734567854",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Invalid re-subscription")
    headers = { "NT": "upnp:event",
                "sid": "uuid:123456734567854",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Invalid re-subscription")
    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "sid": sid,
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("SID mismatch in re-subscription")
    headers = { "NT": "upnp:event",
                "sid": "uuid:4c2bca79-1ff4-4e43-85d4-952a2b8a51fb",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Valid re-subscription")
    headers = { "NT": "upnp:event",
                "sid": sid,
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %s" % resp.status)
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
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", "/hello", "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %s" % resp.status)
    headers = { "foo": "bar" }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Valid unsubscription")
    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Unsubscription for not existing SID")
    headers = { "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 412:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "sid": " \t \tfoo" }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "sid": "uuid:\t \tfoo" }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Invalid unsubscription")
    headers = { "NT": "upnp:event",
                "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)
    headers = { "callback": '<http://127.0.0.1:12345/event>',
                "sid": sid }
    conn.request("UNSUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 400:
        raise Exception("Unexpected HTTP response: %s" % resp.status)

    logger.debug("Valid subscription with multiple callbacks")
    headers = { "callback": '<http://127.0.0.1:12345/event> <http://127.0.0.1:12345/event>\t<http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event><http://127.0.0.1:12345/event>',
                "NT": "upnp:event",
                "timeout": "Second-1234" }
    conn.request("SUBSCRIBE", eventurl.path, "\r\n\r\n", headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise Exception("Unexpected HTTP response: %s" % resp.status)
    sid = resp.getheader("sid")
    logger.debug("Subscription SID " + sid)

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
