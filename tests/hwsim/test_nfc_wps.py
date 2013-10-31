#!/usr/bin/python
#
# WPS+NFC tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd

def check_wpa2_connection(sta, ap, ssid, mixed=False):
    status = sta.get_status()
    if status['wpa_state'] != 'COMPLETED':
        raise Exception("Not fully connected")
    if status['bssid'] != ap['bssid']:
        raise Exception("Unexpected BSSID")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['group_cipher'] != 'CCMP' and not mixed:
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")
    hwsim_utils.test_connectivity(sta.ifname, ap['ifname'])

def ap_wps_params(ssid):
    return { "ssid": ssid, "eap_server": "1", "wps_state": "2",
             "wpa_passphrase": "12345678", "wpa": "2",
             "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP"}

def test_nfc_wps_password_token_sta(dev, apdev):
    """NFC tag with password token on the station/Enrollee"""
    dev[0].request("SET ignore_old_scan_res 1")
    ssid = "test-wps-nfc-pw-token-conf"
    params = ap_wps_params(ssid)
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step using password token from station")
    pw = dev[0].request("WPS_NFC_TOKEN NDEF").rstrip()
    if "FAIL" in pw:
        raise Exception("Failed to generate password token")
    res = hapd.request("WPS_NFC_TAG_READ " + pw)
    if "FAIL" in res:
        raise Exception("Failed to provide NFC tag contents to hostapd")
    dev[0].dump_monitor()
    res = dev[0].request("WPS_NFC")
    if "FAIL" in res:
        raise Exception("Failed to start Enrollee using NFC password token")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    check_wpa2_connection(dev[0], apdev[0], ssid)

def test_nfc_wps_config_token(dev, apdev):
    """NFC tag with configuration token from AP"""
    ssid = "test-wps-nfc-conf-token"
    params = ap_wps_params(ssid)
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("NFC configuration token from AP to station")
    conf = hapd.request("WPS_NFC_CONFIG_TOKEN NDEF").rstrip()
    if "FAIL" in conf:
        raise Exception("Failed to generate configuration token")
    dev[0].dump_monitor()
    res = dev[0].request("WPS_NFC_TAG_READ " + conf)
    if "FAIL" in res:
        raise Exception("Failed to provide NFC tag contents to wpa_supplicant")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Association with the AP timed out")
    check_wpa2_connection(dev[0], apdev[0], ssid)

def test_nfc_wps_config_token_init(dev, apdev):
    """NFC tag with configuration token from AP with auto configuration"""
    dev[0].request("SET ignore_old_scan_res 1")
    ssid = "test-wps-nfc-conf-token-init"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("NFC configuration token from AP to station")
    conf = hapd.request("WPS_NFC_CONFIG_TOKEN NDEF").rstrip()
    if "FAIL" in conf:
        raise Exception("Failed to generate configuration token")
    dev[0].dump_monitor()
    res = dev[0].request("WPS_NFC_TAG_READ " + conf)
    if "FAIL" in res:
        raise Exception("Failed to provide NFC tag contents to wpa_supplicant")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Association with the AP timed out")
    check_wpa2_connection(dev[0], apdev[0], ssid, mixed=True)

def test_nfc_wps_password_token_sta_init(dev, apdev):
    """Initial AP configuration with first WPS NFC Enrollee"""
    dev[0].request("SET ignore_old_scan_res 1")
    ssid = "test-wps-nfc-pw-token-init"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step using password token from station")
    pw = dev[0].request("WPS_NFC_TOKEN NDEF").rstrip()
    if "FAIL" in pw:
        raise Exception("Failed to generate password token")
    res = hapd.request("WPS_NFC_TAG_READ " + pw)
    if "FAIL" in res:
        raise Exception("Failed to provide NFC tag contents to hostapd")
    dev[0].dump_monitor()
    res = dev[0].request("WPS_NFC")
    if "FAIL" in res:
        raise Exception("Failed to start Enrollee using NFC password token")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    check_wpa2_connection(dev[0], apdev[0], ssid, mixed=True)

def test_nfc_wps_password_token_ap(dev, apdev):
    """WPS registrar configuring an AP using AP password token"""
    dev[0].request("SET ignore_old_scan_res 1")
    ssid = "test-wps-nfc-pw-token-init"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS configuration step")
    pw = hapd.request("WPS_NFC_TOKEN NDEF").rstrip()
    if "FAIL" in pw:
        raise Exception("Failed to generate password token")
    res = hapd.request("WPS_NFC_TOKEN enable")
    if "FAIL" in pw:
        raise Exception("Failed to enable AP password token")
    res = dev[0].request("WPS_NFC_TAG_READ " + pw)
    if "FAIL" in res:
        raise Exception("Failed to provide NFC tag contents to wpa_supplicant")
    dev[0].dump_monitor()
    new_ssid = "test-wps-nfc-pw-token-new-ssid"
    new_passphrase = "1234567890"
    res = dev[0].request("WPS_REG " + apdev[0]['bssid'] + " nfc-pw " + new_ssid.encode("hex") + " WPA2PSK CCMP " + new_passphrase.encode("hex"))
    if "FAIL" in res:
        raise Exception("Failed to start Registrar using NFC password token")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    check_wpa2_connection(dev[0], apdev[0], new_ssid, mixed=True)

def test_nfc_wps_handover(dev, apdev):
    """Connect to WPS AP with NFC connection handover"""
    ssid = "test-wps-nfc-handover"
    params = ap_wps_params(ssid)
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("NFC connection handover")
    req = dev[0].request("NFC_GET_HANDOVER_REQ NDEF WPS-CR").rstrip()
    if "FAIL" in req:
        raise Exception("Failed to generate NFC connection handover request")
    sel = hapd.request("NFC_GET_HANDOVER_SEL NDEF WPS-CR").rstrip()
    if "FAIL" in sel:
        raise Exception("Failed to generate NFC connection handover select")
    res = hapd.request("NFC_REPORT_HANDOVER RESP WPS " + req + " " + sel)
    if "FAIL" in res:
        raise Exception("Failed to report NFC connection handover to to hostapd")
    dev[0].dump_monitor()
    res = dev[0].request("NFC_REPORT_HANDOVER INIT WPS " + req + " " + sel)
    if "FAIL" in res:
        raise Exception("Failed to report NFC connection handover to to wpa_supplicant")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    check_wpa2_connection(dev[0], apdev[0], ssid)
