#!/usr/bin/python
#
# wpa_supplicant AP mode tests
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hwsim_utils

def test_wpas_ap_open(dev):
    """wpa_supplicant AP mode - open network"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "2")
    dev[0].set_network_quoted(id, "ssid", "wpas-ap-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].set_network(id, "scan_freq", "2412")
    dev[0].select_network(id)

    dev[1].connect("wpas-ap-open", key_mgmt="NONE", scan_freq="2412")
    dev[2].connect("wpas-ap-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, dev[1].ifname)
    hwsim_utils.test_connectivity(dev[1].ifname, dev[2].ifname)

    addr1 = dev[1].p2p_interface_addr()
    addr2 = dev[2].p2p_interface_addr()
    addrs = [ addr1, addr2 ]
    sta = dev[0].get_sta(None)
    if sta['addr'] not in addrs:
        raise Exception("Unexpected STA address")
    sta1 = dev[0].get_sta(sta['addr'])
    if sta1['addr'] not in addrs:
        raise Exception("Unexpected STA address")
    sta2 = dev[0].get_sta(sta['addr'], next=True)
    if sta2['addr'] not in addrs:
        raise Exception("Unexpected STA2 address")
    sta3 = dev[0].get_sta(sta2['addr'], next=True)
    if len(sta3) != 0:
        raise Exception("Unexpected STA iteration result (did not stop)")

    status = dev[0].get_status()
    if status['mode'] != "AP":
        raise Exception("Unexpected status mode")

    dev[1].dump_monitor()
    dev[2].dump_monitor()
    dev[0].request("DEAUTHENTICATE " + addr1)
    dev[0].request("DISASSOCIATE " + addr2)
    ev = dev[1].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Disconnection timed out")
    ev = dev[2].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Disconnection timed out")
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Reconnection timed out")
    ev = dev[2].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Reconnection timed out")

def test_wpas_ap_wep(dev):
    """wpa_supplicant AP mode - WEP"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "2")
    dev[0].set_network_quoted(id, "ssid", "wpas-ap-wep")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].set_network(id, "scan_freq", "2412")
    dev[0].set_network_quoted(id, "wep_key0", "hello")
    dev[0].select_network(id)

    dev[1].connect("wpas-ap-wep", key_mgmt="NONE", wep_key0='"hello"',
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, dev[1].ifname)

def test_wpas_ap_no_ssid(dev):
    """wpa_supplicant AP mode - invalid network configuration"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "2")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].set_network(id, "scan_freq", "2412")
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected AP start")

def test_wpas_ap_default_frequency(dev):
    """wpa_supplicant AP mode - default frequency"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "2")
    dev[0].set_network_quoted(id, "ssid", "wpas-ap-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "scan_freq", "2412")
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("AP failed to start")
    dev[1].connect("wpas-ap-open", key_mgmt="NONE", scan_freq="2462")

def test_wpas_ap_invalid_frequency(dev):
    """wpa_supplicant AP mode - invalid frequency configuration"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "2")
    dev[0].set_network_quoted(id, "ssid", "wpas-ap-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2413")
    dev[0].set_network(id, "scan_freq", "2412")
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected AP start")

def test_wpas_ap_wps(dev):
    """wpa_supplicant AP mode - WPS operations"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "2")
    dev[0].set_network_quoted(id, "ssid", "wpas-ap-wps")
    dev[0].set_network_quoted(id, "psk", "1234567890")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].set_network(id, "scan_freq", "2412")
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("AP start timeout")
    bssid = dev[0].p2p_interface_addr()

    logger.info("Test PBC mode start/stop")
    if "FAIL" not in dev[0].request("WPS_CANCEL"):
        raise Exception("Unexpected WPS_CANCEL success")
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["WPS-PBC-ACTIVE"])
    if ev is None:
        raise Exception("PBC mode start timeout")
    if "OK" not in dev[0].request("WPS_CANCEL"):
        raise Exception("Unexpected WPS_CANCEL failure")
    ev = dev[0].wait_event(["WPS-TIMEOUT"])
    if ev is None:
        raise Exception("PBC mode disabling timeout")

    logger.info("Test PBC protocol run")
    dev[0].request("WPS_PBC")
    ev = dev[0].wait_event(["WPS-PBC-ACTIVE"])
    if ev is None:
        raise Exception("PBC mode start timeout")
    dev[1].request("WPS_PBC")
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("WPS PBC operation timed out")
    hwsim_utils.test_connectivity(dev[0].ifname, dev[1].ifname)

    logger.info("Test AP PIN to learn configuration")
    pin = dev[0].request("WPS_AP_PIN random")
    if "FAIL" in pin:
        raise Exception("Could not generate random AP PIN")
    if pin not in dev[0].request("WPS_AP_PIN get"):
        raise Exception("Could not fetch current AP PIN")
    dev[2].wps_reg(bssid, pin)
    hwsim_utils.test_connectivity(dev[1].ifname, dev[2].ifname)

    dev[1].request("REMOVE_NETWORK all")
    dev[2].request("REMOVE_NETWORK all")

    logger.info("Test AP PIN operations")
    dev[0].request("WPS_AP_PIN disable")
    dev[0].request("WPS_AP_PIN set " + pin + " 1")
    time.sleep(1.1)
    if "FAIL" not in dev[0].request("WPS_AP_PIN get"):
        raise Exception("AP PIN unexpectedly still enabled")

    pin = dev[1].wps_read_pin()
    dev[0].request("WPS_PIN any " + pin)
    dev[1].request("WPS_PIN any " + pin)
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the AP timed out")
    dev[1].request("REMOVE_NETWORK all")
    dev[1].dump_monitor()

    dev[0].request("WPS_AP_PIN set 12345670")
    dev[0].dump_monitor()

    runs = ("88887777", "12340000", "00000000", "12345670")
    for pin in runs:
        logger.info("Try AP PIN " + pin)
        dev[2].dump_monitor()
        dev[2].request("WPS_REG " + bssid + " " + pin)
        ev = dev[2].wait_event(["WPS-SUCCESS", "WPS-FAIL msg"], timeout=15)
        if ev is None:
            raise Exception("WPS operation timed out")
        if "WPS-SUCCESS" in ev:
            raise Exception("WPS operation succeeded unexpectedly")
        ev = dev[2].wait_event(["CTRL-EVENT-DISCONNECTED"])
        if ev is None:
            raise Exception("Timeout while waiting for disconnection")
        dev[2].request("WPS_CANCEL")
        dev[2].request("REMOVE_NETWORK all")
    ev = dev[0].wait_event(["WPS-AP-SETUP-LOCKED"])
    if ev is None:
        raise Exception("WPS AP PIN not locked")
