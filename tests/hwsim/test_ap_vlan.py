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

try:
    import netifaces
    netifaces_imported = True
except ImportError:
    netifaces_imported = False

import hwsim_utils
import hostapd
from utils import iface_is_in_bridge, HwsimSkip

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

    logger.info("VLAN-ID -> 2")

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
    sta = hapd.get_sta(dev[0].own_addr())
    if 'vlan_id' not in sta:
        raise Exception("No VLAN ID in STA info")
    if sta['vlan_id'] != '2':
        raise Exception("Unexpected VLAN ID: " + sta['vlan_id'])
    hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan2")

    logger.info("VLAN-ID -> 1")
    time.sleep(1)

    authserv.disable()
    authserv.set('eap_user_file', "auth_serv/eap_user.conf")
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
    sta = hapd.get_sta(dev[0].own_addr())
    if 'vlan_id' not in sta:
        raise Exception("No VLAN ID in STA info")
    if sta['vlan_id'] != '1':
        raise Exception("Unexpected VLAN ID: " + sta['vlan_id'])
    time.sleep(0.2)
    try:
        hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")
    except Exception, e:
        # It is possible for new bridge setup to not be ready immediately, so
        # try again to avoid reporting issues related to that.
        logger.info("First VLAN-ID 1 data test failed - try again")
        hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")

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

def ap_vlan_iface_cleanup_multibss_cleanup():
    subprocess.call(['ifconfig', 'dummy0', 'down'],
                    stderr=open('/dev/null', 'w'))
    ifnames = [ 'wlan3.1', 'wlan3.2', 'wlan3-2.1', 'wlan3-2.2', 'dummy0.2',
                'dummy0.1', 'dummy0', 'brvlan1', 'brvlan2' ]
    for ifname in ifnames:
        subprocess.call(['ip', 'link', 'del', ifname],
                        stderr=open('/dev/null', 'w'))

def ap_vlan_iface_test_and_prepare_environ():
    ifaces = netifaces.interfaces()
    if "dummy0" in ifaces:
        raise Exception("dummy0 already exists before")
    ifaces = netifaces.interfaces()
    if "dummy0.1" in ifaces:
        raise Exception("dummy0.1 already exists before")

    subprocess.call(['ip', 'link', 'add', 'dummy0', 'type', 'dummy'])
    subprocess.call(['ifconfig', 'dummy0', 'up'])

    ifaces = netifaces.interfaces()
    if not("dummy0" in ifaces):
        raise HwsimSkip("failed to add dummy0 - missing kernel config DUMMY ?")

    subprocess.call(['ip', 'link', 'add', 'link', 'dummy0', 'name', 'dummy0.1',
                     'type', 'vlan', 'id', '1'])

    ifaces = netifaces.interfaces()
    if not("dummy0.1" in ifaces):
        raise HwsimSkip("failed to add dummy0.1 - missing kernel config VLAN_8021Q ?")

    subprocess.call(['ip', 'link', 'del', 'dummy0.1'])

    ifaces = netifaces.interfaces()
    if "dummy0.1" in ifaces:
        raise Exception("dummy0.1 was not removed before testing")

def test_ap_vlan_iface_cleanup_multibss(dev, apdev):
    """AP VLAN operation in multi-BSS multi-VLAN case"""

    # AP VLAN with WPA2-Enterprise and RADIUS attributes changing VLANID
    # check that multiple bss do not interfere with each other with respect
    # to deletion of bridge and tagged interface.

    if not netifaces_imported:
        raise HwsimSkip("python module netifaces not available")

    try:
        ap_vlan_iface_cleanup_multibss_cleanup()
        ap_vlan_iface_test_and_prepare_environ()

        as_params = { "ssid": "as",
                      "beacon_int": "2000",
                      "radius_server_clients": "auth_serv/radius_clients.conf",
                      "radius_server_auth_port": '18128',
                      "eap_server": "1",
                      "eap_user_file": "auth_serv/eap_user.conf",
                      "ca_cert": "auth_serv/ca.pem",
                      "server_cert": "auth_serv/server.pem",
                      "private_key": "auth_serv/server.key",
                      "vlan_naming": "1" }
        authserv = hostapd.add_ap(apdev[1]['ifname'], as_params)

        ifname = apdev[0]['ifname']

        # start the actual test
        hostapd.add_iface(ifname, 'multi-bss-iface.conf')
        hapd = hostapd.Hostapd(ifname)
        hapd1 = hostapd.Hostapd("wlan3-2", 1)
        hapd1.enable()

        ifaces = netifaces.interfaces()
        if "brvlan1" in ifaces:
            raise Exception("bridge brvlan1 already exists before")
        if "brvlan2" in ifaces:
            raise Exception("bridge brvlan2 already exists before")

        dev[0].connect("bss-1", key_mgmt="WPA-EAP", eap="PAX",
                       identity="vlan1",
                       password_hex="0123456789abcdef0123456789abcdef",
                       scan_freq="2412")

        ifaces = netifaces.interfaces()
        if not("brvlan1" in ifaces):
            raise Exception("bridge brvlan1 was not created")

        hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")
        if not iface_is_in_bridge("brvlan1", "dummy0.1"):
            raise Exception("dummy0.1 not in brvlan1")

        dev[1].connect("bss-2", key_mgmt="WPA-EAP", eap="PAX",
                       identity="vlan1",
                       password_hex="0123456789abcdef0123456789abcdef",
                       scan_freq="2412")

        hwsim_utils.test_connectivity_iface(dev[1], hapd1, "brvlan1")
        if not iface_is_in_bridge("brvlan1", "dummy0.1"):
            raise Exception("dummy0.1 not in brvlan1")

        authserv.disable()
        authserv.set('eap_user_file', "auth_serv/eap_user_vlan.conf")
        authserv.enable()

        logger.info("wlan0 -> VLAN 2")

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

        ifaces = netifaces.interfaces()
        if not ("brvlan1" in ifaces):
            raise Exception("bridge brvlan1 has been removed too early")

        hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan2",
                                            max_tries=5)

        if not iface_is_in_bridge("brvlan2", "dummy0.2"):
            raise Exception("dummy0.2 not in brvlan2")

        logger.info("test wlan1 == VLAN 1")
        hwsim_utils.test_connectivity_iface(dev[1], hapd1, "brvlan1")
        if not iface_is_in_bridge("brvlan1", "dummy0.1"):
            raise Exception("dummy0.1 not in brvlan1")

        logger.info("wlan1 -> VLAN 2")

        dev[1].dump_monitor()
        dev[1].request("REAUTHENTICATE")
        ev = dev[1].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
        if ev is None:
            raise Exception("EAP reauthentication timed out")
        ev = dev[1].wait_event(["WPA: Key negotiation completed"], timeout=5)
        if ev is None:
            raise Exception("4-way handshake after reauthentication timed out")
        state = dev[1].get_status_field('wpa_state')
        if state != "COMPLETED":
            raise Exception("Unexpected state after reauth: " + state)

        # it can take some time for data connectivity to be updated
        hwsim_utils.test_connectivity_iface(dev[1], hapd1, "brvlan2",
                                            max_tries=5)
        logger.info("test wlan0 == VLAN 2")
        hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan2")

        if not iface_is_in_bridge("brvlan2", "dummy0.2"):
            raise Exception("dummy0.2 not in brvlan2")

        ifaces = netifaces.interfaces()
        if "brvlan1" in ifaces:
            raise Exception("bridge brvlan1 has not been cleaned up")

        # disconnect dev0 first to test a corner case
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[1].request("DISCONNECT")
        dev[1].wait_disconnected()

        # station removal needs some time
        for i in range(5):
            time.sleep(1)
            ifaces = netifaces.interfaces()
            if "brvlan2" not in ifaces:
                break

        ifaces = netifaces.interfaces()
        if "brvlan2" in ifaces:
            raise Exception("bridge brvlan2 has not been cleaned up")

        hapd.request("DISABLE")
    finally:
        ap_vlan_iface_cleanup_multibss_cleanup()
