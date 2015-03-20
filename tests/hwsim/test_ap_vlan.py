#!/usr/bin/python
#
# Test cases for AP VLAN
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger(__name__)

import hwsim_utils
import hostapd

def test_ap_vlan_open(dev, apdev):
    """AP VLAN with open network"""
    params = { "ssid": "test-vlan-open",
               "dynamic_vlan": "1",
               "accept_mac_file": "hostapd.accept" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[1].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[2].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")
    hwsim_utils.test_connectivity_iface(dev[1], hapd, "brvlan2")
    hwsim_utils.test_connectivity(dev[2], hapd)

def test_ap_vlan_file_open(dev, apdev):
    """AP VLAN with open network and vlan_file mapping"""
    params = { "ssid": "test-vlan-open",
               "dynamic_vlan": "1",
               "vlan_file": "hostapd.vlan",
               "accept_mac_file": "hostapd.accept" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[1].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[2].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")
    hwsim_utils.test_connectivity_iface(dev[1], hapd, "brvlan2")
    hwsim_utils.test_connectivity(dev[2], hapd)

def test_ap_vlan_wpa2(dev, apdev):
    """AP VLAN with WPA2-PSK"""
    params = hostapd.wpa2_params(ssid="test-vlan",
                                 passphrase="12345678")
    params['dynamic_vlan'] = "1";
    params['accept_mac_file'] = "hostapd.accept";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan", psk="12345678", scan_freq="2412")
    dev[1].connect("test-vlan", psk="12345678", scan_freq="2412")
    dev[2].connect("test-vlan", psk="12345678", scan_freq="2412")
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")
    hwsim_utils.test_connectivity_iface(dev[1], hapd, "brvlan2")
    hwsim_utils.test_connectivity(dev[2], hapd)

def test_ap_vlan_wpa2_radius(dev, apdev):
    """AP VLAN with WPA2-Enterprise and RADIUS attributes"""
    params = hostapd.wpa2_eap_params(ssid="test-vlan")
    params['dynamic_vlan'] = "1";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan", key_mgmt="WPA-EAP", eap="PAX",
                   identity="vlan1",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")
    dev[1].connect("test-vlan", key_mgmt="WPA-EAP", eap="PAX",
                   identity="vlan2",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")
    dev[2].connect("test-vlan", key_mgmt="WPA-EAP", eap="PAX",
                   identity="pax.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")
    hwsim_utils.test_connectivity_iface(dev[1], hapd, "brvlan2")
    hwsim_utils.test_connectivity(dev[2], hapd)

def test_ap_vlan_wpa2_radius_id_change(dev, apdev):
    """AP VLAN with WPA2-Enterprise and RADIUS attributes changing VLANID"""
    as_params = { "ssid": "as",
                  "beacon_int": "2000",
                  "radius_server_clients": "auth_serv/radius_clients.conf",
                  "radius_server_auth_port": '18128',
                  "eap_server": "1",
                  "eap_user_file": "auth_serv/eap_user.conf",
                  "ca_cert": "auth_serv/ca.pem",
                  "server_cert": "auth_serv/server.pem",
                  "private_key": "auth_serv/server.key" }
    authserv = hostapd.add_ap(apdev[1]['ifname'], as_params)

    params = hostapd.wpa2_eap_params(ssid="test-vlan")
    params['dynamic_vlan'] = "1";
    params['auth_server_port'] = "18128"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan", key_mgmt="WPA-EAP", eap="PAX",
                   identity="vlan1",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")

    authserv.disable()
    authserv.set('eap_user_file', "auth_serv/eap_user_vlan.conf")
    authserv.enable()

    dev[0].dump_monitor()
    dev[0].request("REAUTHENTICATE")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("EAP reauthentication timed out")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"], timeout=5)
    if ev is None:
        raise Exception("4-way handshake after reauthentication timed out")
    state = dev[0].get_status_field('wpa_state')
    if state != "COMPLETED":
        raise Exception("Unexpected state after reauth: " + state)
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan2")

def test_ap_vlan_wpa2_radius_required(dev, apdev):
    """AP VLAN with WPA2-Enterprise and RADIUS attributes required"""
    params = hostapd.wpa2_eap_params(ssid="test-vlan")
    params['dynamic_vlan'] = "2";
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan", key_mgmt="WPA-EAP", eap="PAX",
                   identity="vlan1",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")
    dev[2].connect("test-vlan", key_mgmt="WPA-EAP", eap="PAX",
                   identity="pax.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412", wait_connect=False)
    ev = dev[2].wait_event(["CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-DISCONNECTED"], timeout=20)
    if ev is None:
        raise Exception("Timeout on connection attempt")
    if "CTRL-EVENT-CONNECTED" in ev:
        raise Exception("Unexpected success without tunnel parameters")

def test_ap_vlan_tagged(dev, apdev):
    """AP VLAN with tagged interface"""
    params = { "ssid": "test-vlan-open",
               "dynamic_vlan": "1",
               "vlan_tagged_interface": "lo",
               "accept_mac_file": "hostapd.accept" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[1].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    dev[2].connect("test-vlan-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brlo.1")
    hwsim_utils.test_connectivity_iface(dev[1], hapd, "brlo.2")
    hwsim_utils.test_connectivity(dev[2], hapd)
