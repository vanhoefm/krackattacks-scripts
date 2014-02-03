#!/usr/bin/python
#
# WPS tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()
import re

import hwsim_utils
import hostapd

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
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
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

def test_ap_wps_init_2ap_pbc(dev, apdev):
    """Initial two-radio AP configuration with first WPS PBC Enrollee"""
    ssid = "test-wps"
    params = { "ssid": ssid, "eap_server": "1", "wps_state": "1" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    hostapd.add_ap(apdev[1]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" not in bss['flags']:
        raise Exception("WPS-PBC flag missing from AP1")
    bss = dev[0].get_bss(apdev[1]['bssid'])
    if "[WPS-PBC]" not in bss['flags']:
        raise Exception("WPS-PBC flag missing from AP2")
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")

    dev[1].scan(freq="2412")
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" in bss['flags']:
        raise Exception("WPS-PBC flag not cleared from AP1")
    bss = dev[1].get_bss(apdev[1]['bssid'])
    if "[WPS-PBC]" in bss['flags']:
        raise Exception("WPS-PBC flag bit ckeared from AP2")

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
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" not in bss['flags']:
        raise Exception("WPS-AUTH flag missing from AP1")
    bss = dev[0].get_bss(apdev[1]['bssid'])
    if "[WPS-AUTH]" not in bss['flags']:
        raise Exception("WPS-AUTH flag missing from AP2")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN any " + pin)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")

    dev[1].scan(freq="2412")
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not cleared from AP1")
    bss = dev[1].get_bss(apdev[1]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag bit ckeared from AP2")

def test_ap_wps_init_through_wps_config(dev, apdev):
    """Initial AP configuration using wps_config command"""
    ssid = "test-wps-init-config"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    if "FAIL" in hapd.request("WPS_CONFIG " + ssid.encode("hex") + " WPA2PSK CCMP " + "12345678".encode("hex")):
        raise Exception("WPS_CONFIG command failed")
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
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
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
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
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
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
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
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN any 55554444")
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=30)
    if ev is None:
        raise Exception("WPS operation timed out")
    if "config_error=18" not in ev:
        raise Exception("Incorrect config_error reported")
    if "msg=8" not in ev:
        raise Exception("PIN error detected on incorrect message")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout on disconnection event")
    dev[0].request("WPS_CANCEL")
    # if a scan was in progress, wait for it to complete before trying WPS again
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)

    status = hapd.request("WPS_GET_STATUS")
    if "Last WPS result: Failed" not in status:
        raise Exception("WPS failure result not shown correctly")

    logger.info("WPS provisioning attempt 2")
    hapd.request("WPS_PIN any 12345670")
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN any 12344444")
    ev = dev[0].wait_event(["WPS-FAIL"], timeout=30)
    if ev is None:
        raise Exception("WPS operation timed out")
    if "config_error=18" not in ev:
        raise Exception("Incorrect config_error reported")
    if "msg=10" not in ev:
        raise Exception("PIN error detected on incorrect message")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout on disconnection event")

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
    dev[0].dump_monitor()
    dev[0].request("WPS_PIN any " + pin)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    status = dev[0].get_status()
    if status['wpa_state'] != 'COMPLETED' or status['bssid'] != apdev[0]['bssid']:
        raise Exception("Not fully connected")
    if status['ssid'] != ssid:
        raise Exception("Unexpected SSID")
    if status['pairwise_cipher'] != 'CCMP' or status['group_cipher'] != 'CCMP':
        raise Exception("Unexpected encryption configuration")
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Unexpected key_mgmt")

    dev[1].scan(freq="2412")
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not cleared")
    logger.info("Try to connect from another station using the same PIN")
    dev[1].request("WPS_PIN any " + pin)
    ev = dev[1].wait_event(["WPS-M2D","CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Operation timed out")
    if "WPS-M2D" not in ev:
        raise Exception("Unexpected WPS operation started")

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
    dev[0].request("WPS_PIN any " + pin)
    dev[1].request("WPS_PIN any " + pin)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")

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
    dev[0].wps_reg(apdev[0]['bssid'], appin)

    hapd.request("WPS_AP_PIN disable")
    logger.info("WPS provisioning step with AP PIN disabled")
    check_wps_reg_failure(dev[1], apdev[0], appin)

    logger.info("WPS provisioning step with AP PIN reset")
    appin = "12345670"
    hapd.request("WPS_AP_PIN set " + appin)
    dev[1].wps_reg(apdev[0]['bssid'], appin)
    dev[0].request("REMOVE_NETWORK all")
    dev[1].request("REMOVE_NETWORK all")
    dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    dev[1].wait_event(["CTRL-EVENT-DISCONNECTED"])

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
    """WPS registrar configuring and AP using AP PIN"""
    ssid = "test-wps-init-ap-pin"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "ap_pin": appin})
    logger.info("WPS configuration step")
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

def test_ap_wps_reg_config_tkip(dev, apdev):
    """WPS registrar configuring AP to use TKIP and AP upgrading to TKIP+CCMP"""
    ssid = "test-wps-init-ap"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1",
                     "ap_pin": appin})
    logger.info("WPS configuration step")
    dev[0].request("SET wps_version_number 0x10")
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
        raise Exception("Not fully connected")
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
        ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
        if ev is None:
            raise Exception("Timeout on disconnection event")
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
    dev[0].request("WPS_PIN any " + pin)
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=30)
    if ev is None:
        raise Exception("WPS success was not reported")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")

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
    dev[0].dump_monitor()
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
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    dev[0].request("WPS_PBC")
    dev[1].request("WPS_PBC")
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
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" not in bss['flags']:
        raise Exception("WPS-PBC flag missing")
    if "FAIL" in hapd.request("WPS_CANCEL"):
        raise Exception("WPS_CANCEL failed")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-PBC]" in bss['flags']:
        raise Exception("WPS-PBC flag not cleared")

    logger.info("Verify PIN enable/cancel")
    hapd.request("WPS_PIN any 12345670")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" not in bss['flags']:
        raise Exception("WPS-AUTH flag missing")
    if "FAIL" in hapd.request("WPS_CANCEL"):
        raise Exception("WPS_CANCEL failed")
    dev[0].scan(freq="2412")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not cleared")

def test_ap_wps_er_add_enrollee(dev, apdev):
    """WPS ER configuring AP and adding a new enrollee using PIN"""
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

    logger.info("Add Enrollee using ER")
    pin = dev[1].wps_read_pin()
    dev[0].dump_monitor()
    dev[0].request("WPS_ER_PIN any " + pin + " " + dev[1].p2p_interface_addr())
    dev[1].dump_monitor()
    dev[1].request("WPS_PIN any " + pin)
    ev = dev[1].wait_event(["WPS-SUCCESS"], timeout=30)
    if ev is None:
        raise Exception("Enrollee did not report success")
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Association with the AP timed out")
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

    logger.info("Add a specific Enrollee using ER")
    pin = dev[2].wps_read_pin()
    addr2 = dev[2].p2p_interface_addr()
    dev[0].dump_monitor()
    dev[2].dump_monitor()
    dev[2].request("WPS_PIN any " + pin)
    ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=10)
    if ev is None:
        raise Exception("Enrollee not seen")
    if addr2 not in ev:
        raise Exception("Unexpected Enrollee MAC address")
    dev[0].request("WPS_ER_PIN " + addr2 + " " + pin + " " + addr2)
    ev = dev[2].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Association with the AP timed out")
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")

    logger.info("Verify registrar selection behavior")
    dev[0].request("WPS_ER_PIN any " + pin + " " + dev[1].p2p_interface_addr())
    dev[1].request("DISCONNECT")
    dev[1].wait_event(["CTRL-EVENT-DISCONNECTED"])
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
    # a bit before verifying that the scan results have change.
    time.sleep(0.2)

    dev[1].scan(freq="2412")
    bss = dev[1].get_bss(apdev[0]['bssid'])
    if "[WPS-AUTH]" in bss['flags']:
        raise Exception("WPS-AUTH flag not removed")

def test_ap_wps_er_add_enrollee_pbc(dev, apdev):
    """WPS ER connected to AP and adding a new enrollee using PBC"""
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

    logger.info("Add Enrollee using ER and PBC")
    dev[0].dump_monitor()
    enrollee = dev[1].p2p_interface_addr()
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
    dev[0].request("WPS_ER_PBC " + enrollee)

    ev = dev[1].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("Enrollee did not report success")
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Association with the AP timed out")
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

    # verify BSSID selection of the AP instead of UUID
    if "FAIL" in dev[0].request("WPS_ER_SET_CONFIG " + apdev[0]['bssid'] + " 0"):
        raise Exception("Could not select AP based on BSSID")

def test_ap_wps_er_v10_add_enrollee_pin(dev, apdev):
    """WPS v1.0 ER connected to AP and adding a new enrollee using PIN"""
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
    dev[1].dump_monitor()
    dev[1].request("WPS_PIN any " + pin)
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Association with the AP timed out")
    ev = dev[0].wait_event(["WPS-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("WPS ER did not report success")

def test_ap_wps_er_config_ap(dev, apdev):
    """WPS ER configuring AP over UPnP"""
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
    dev[1].wait_event(["CTRL-EVENT-DISCONNECTED"])
    dev[0].connect(ssid, psk="1234567890", scan_freq="2412")

def test_ap_wps_fragmentation(dev, apdev):
    """WPS with fragmentation in EAP-WSC and mixed mode WPA+WPA2"""
    ssid = "test-wps-fragmentation"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "3",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
                     "wpa_pairwise": "TKIP",
                     "fragment_size": "50" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].dump_monitor()
    dev[0].request("SET wps_fragment_size 50")
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    status = dev[0].get_status()
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
    dev[0].dump_monitor()
    dev[0].request("SET wps_version_number 0x43")
    dev[0].request("SET wps_vendor_ext_m1 000137100100020001")
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")

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
    dev[0].dump_monitor()
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    hapd.request("SET wps_version_number 0x20")
    if ev is None:
        raise Exception("Association with the AP timed out")

def test_ap_wps_check_pin(dev, apdev):
    """Verify PIN checking through control interface"""
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": "wps", "eap_server": "1", "wps_state": "2",
                     "wpa_passphrase": "12345678", "wpa": "2",
                     "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    for t in [ ("12345670", "12345670"),
               ("12345678", "FAIL-CHECKSUM"),
               ("1234-5670", "12345670"),
               ("1234 5670", "12345670"),
               ("1-2.3:4 5670", "12345670") ]:
        res = hapd.request("WPS_CHECK_PIN " + t[0]).rstrip('\n')
        res2 = dev[0].request("WPS_CHECK_PIN " + t[0]).rstrip('\n')
        if res != res2:
            raise Exception("Unexpected difference in WPS_CHECK_PIN responses")
        if res != t[1]:
            raise Exception("Incorrect WPS_CHECK_PIN response {} (expected {})".format(res, t[1]))

def test_ap_wps_wep_config(dev, apdev):
    """WPS 2.0 AP rejecting WEP configuration"""
    ssid = "test-wps-config"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "ap_pin": appin})
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
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
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "wps_device_name" not in bss or bss['wps_device_name'] != "1234567890abcdef1234567890abcdef":
        raise Exception("Device Name not received correctly")
    if len(re.findall("dd..0050f204", bss['ie'])) != 2:
        raise Exception("Unexpected number of WPS IEs")
