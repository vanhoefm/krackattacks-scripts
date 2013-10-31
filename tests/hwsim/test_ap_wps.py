#!/usr/bin/python
#
# WPS tests
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

def test_ap_wps_init(dev, apdev):
    """Initial AP configuration with first WPS Enrollee"""
    ssid = "test-wps"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "1" })
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    logger.info("WPS provisioning step")
    hapd.request("WPS_PBC")
    dev[0].request("SET ignore_old_scan_res 1")
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
    dev[0].request("SET ignore_old_scan_res 1")
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
    dev[0].request("SET ignore_old_scan_res 1")
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

def test_ap_wps_reg_config(dev, apdev):
    """WPS registrar configuring and AP using AP PIN"""
    ssid = "test-wps-init-ap-pin"
    appin = "12345670"
    hostapd.add_ap(apdev[0]['ifname'],
                   { "ssid": ssid, "eap_server": "1", "wps_state": "2",
                     "ap_pin": appin})
    logger.info("WPS configuration step")
    dev[0].request("SET ignore_old_scan_res 1")
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
    dev[0].request("SET ignore_old_scan_res 1")
    dev[1].request("SET ignore_old_scan_res 1")
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
    dev[0].request("SET ignore_old_scan_res 1")
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
    dev[1].request("SET ignore_old_scan_res 1")
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
    dev[0].request("SET ignore_old_scan_res 1")
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
    dev[1].request("SET ignore_old_scan_res 1")
    dev[1].dump_monitor()
    dev[1].request("WPS_PBC")

    ev = dev[0].wait_event(["WPS-ER-ENROLLEE-ADD"], timeout=15)
    if ev is None:
        raise Exception("Enrollee discovery timed out")
    if enrollee not in ev:
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
