# Dynamic wpa_supplicant interface
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess
import time

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant

def test_sta_dynamic(dev, apdev):
    """Dynamically added wpa_supplicant interface"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)

    logger.info("Create a dynamic wpa_supplicant interface and connect")
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")

    wpas.connect("sta-dynamic", psk="12345678", scan_freq="2412")

def test_sta_ap_scan_0(dev, apdev):
    """Dynamically added wpa_supplicant interface with AP_SCAN 0 connection"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test" })
    bssid = apdev[0]['bssid']

    logger.info("Create a dynamic wpa_supplicant interface and connect")
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")

    if "OK" not in wpas.request("AP_SCAN 0"):
        raise Exception("Failed to set AP_SCAN 2")

    id = wpas.connect("", key_mgmt="NONE", bssid=bssid,
                      only_add_network=True)
    wpas.request("ENABLE_NETWORK " + str(id) + " no-connect")
    wpas.request("SCAN")
    time.sleep(0.5)
    subprocess.call(['sudo', 'iw', wpas.ifname, 'connect', 'test', '2412'])
    ev = wpas.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection not reported")
    wpas.request("SCAN")
    ev = wpas.wait_event(["CTRL-EVENT-CONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Connection not reported")

def test_sta_ap_scan_2(dev, apdev):
    """Dynamically added wpa_supplicant interface with AP_SCAN 2 connection"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test" })
    bssid = apdev[0]['bssid']

    logger.info("Create a dynamic wpa_supplicant interface and connect")
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")

    if "FAIL" not in wpas.request("AP_SCAN -1"):
        raise Exception("Invalid AP_SCAN -1 accepted")
    if "FAIL" not in wpas.request("AP_SCAN 3"):
        raise Exception("Invalid AP_SCAN 3 accepted")
    if "OK" not in wpas.request("AP_SCAN 2"):
        raise Exception("Failed to set AP_SCAN 2")

    id = wpas.connect("", key_mgmt="NONE", bssid=bssid,
                      only_add_network=True)
    wpas.request("ENABLE_NETWORK " + str(id) + " no-connect")
    subprocess.call(['sudo', 'iw', wpas.ifname, 'scan', 'trigger',
                     'freq', '2412'])
    time.sleep(1)
    subprocess.call(['sudo', 'iw', wpas.ifname, 'connect', 'test', '2412'])
    ev = wpas.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection not reported")

    wpas.request("SET disallow_aps bssid " + bssid)
    ev = wpas.wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Disconnection not reported")

    subprocess.call(['sudo', 'iw', wpas.ifname, 'connect', 'test', '2412'])
    ev = wpas.wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection reported")

def test_sta_dynamic_down_up(dev, apdev):
    """Dynamically added wpa_supplicant interface down/up"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hostapd.add_ap(apdev[0]['ifname'], params)

    logger.info("Create a dynamic wpa_supplicant interface and connect")
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    wpas.connect("sta-dynamic", psk="12345678", scan_freq="2412")
    hwsim_utils.test_connectivity(wpas.ifname, apdev[0]['ifname'])
    subprocess.call(['sudo', 'ifconfig', wpas.ifname, 'down'])
    ev = wpas.wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Disconnection not reported")
    if wpas.get_status_field("wpa_state") != "INTERFACE_DISABLED":
        raise Exception("Unexpected wpa_state")
    subprocess.call(['sudo', 'ifconfig', wpas.ifname, 'up'])
    ev = wpas.wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Reconnection not reported")
    hwsim_utils.test_connectivity(wpas.ifname, apdev[0]['ifname'])

def test_sta_dynamic_ext_mac_addr_change(dev, apdev):
    """Dynamically added wpa_supplicant interface with external MAC address change"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    logger.info("Create a dynamic wpa_supplicant interface and connect")
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    wpas.connect("sta-dynamic", psk="12345678", scan_freq="2412")
    hwsim_utils.test_connectivity(wpas.ifname, apdev[0]['ifname'])
    subprocess.call(['sudo', 'ifconfig', wpas.ifname, 'down'])
    ev = wpas.wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Disconnection not reported")
    if wpas.get_status_field("wpa_state") != "INTERFACE_DISABLED":
        raise Exception("Unexpected wpa_state")
    prev_addr = wpas.p2p_interface_addr()
    new_addr = '02:11:22:33:44:55'
    try:
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', wpas.ifname,
                         'address', new_addr])
        subprocess.call(['sudo', 'ifconfig', wpas.ifname, 'up'])
        ev = wpas.wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
        if ev is None:
            raise Exception("Reconnection not reported")
        if wpas.get_driver_status_field('addr') != new_addr:
            raise Exception("Address change not reported")
        hwsim_utils.test_connectivity(wpas.ifname, apdev[0]['ifname'])
        sta = hapd.get_sta(new_addr)
        if sta['addr'] != new_addr:
            raise Exception("STA association with new address not found")
    finally:
        subprocess.call(['sudo', 'ifconfig', wpas.ifname, 'down'])
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', wpas.ifname,
                         'address', prev_addr])
        subprocess.call(['sudo', 'ifconfig', wpas.ifname, 'up'])

def test_sta_dynamic_random_mac_addr(dev, apdev):
    """Dynamically added wpa_supplicant interface and random MAC address"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    addr0 = wpas.get_driver_status_field("addr")
    wpas.request("SET preassoc_mac_addr 1")
    wpas.request("SET rand_addr_lifetime 0")

    id = wpas.connect("sta-dynamic", psk="12345678", mac_addr="1",
                      scan_freq="2412")
    addr1 = wpas.get_driver_status_field("addr")

    if addr0 == addr1:
        raise Exception("Random MAC address not used")

    sta = hapd.get_sta(addr0)
    if sta['addr'] != "FAIL":
        raise Exception("Unexpected STA association with permanent address")
    sta = hapd.get_sta(addr1)
    if sta['addr'] != addr1:
        raise Exception("STA association with random address not found")

    wpas.request("DISCONNECT")
    wpas.connect_network(id)
    addr2 = wpas.get_driver_status_field("addr")
    if addr1 != addr2:
        raise Exception("Random MAC address changed unexpectedly")

    wpas.remove_network(id)
    id = wpas.connect("sta-dynamic", psk="12345678", mac_addr="1",
                      scan_freq="2412")
    addr2 = wpas.get_driver_status_field("addr")
    if addr1 == addr2:
        raise Exception("Random MAC address did not change")

def test_sta_dynamic_random_mac_addr_keep_oui(dev, apdev):
    """Dynamically added wpa_supplicant interface and random MAC address (keep OUI)"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    addr0 = wpas.get_driver_status_field("addr")
    wpas.request("SET preassoc_mac_addr 2")
    wpas.request("SET rand_addr_lifetime 0")

    id = wpas.connect("sta-dynamic", psk="12345678", mac_addr="2",
                      scan_freq="2412")
    addr1 = wpas.get_driver_status_field("addr")

    if addr0 == addr1:
        raise Exception("Random MAC address not used")
    if addr1[3:8] != addr0[3:8]:
        raise Exception("OUI was not kept")

    sta = hapd.get_sta(addr0)
    if sta['addr'] != "FAIL":
        raise Exception("Unexpected STA association with permanent address")
    sta = hapd.get_sta(addr1)
    if sta['addr'] != addr1:
        raise Exception("STA association with random address not found")

    wpas.request("DISCONNECT")
    wpas.connect_network(id)
    addr2 = wpas.get_driver_status_field("addr")
    if addr1 != addr2:
        raise Exception("Random MAC address changed unexpectedly")

    wpas.remove_network(id)
    id = wpas.connect("sta-dynamic", psk="12345678", mac_addr="2",
                      scan_freq="2412")
    addr2 = wpas.get_driver_status_field("addr")
    if addr1 == addr2:
        raise Exception("Random MAC address did not change")
    if addr2[3:8] != addr0[3:8]:
        raise Exception("OUI was not kept")

def test_sta_dynamic_random_mac_addr_scan(dev, apdev):
    """Dynamically added wpa_supplicant interface and random MAC address for scan"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    addr0 = wpas.get_driver_status_field("addr")
    wpas.request("SET preassoc_mac_addr 1")
    wpas.request("SET rand_addr_lifetime 0")

    id = wpas.connect("sta-dynamic", psk="12345678", scan_freq="2412")
    addr1 = wpas.get_driver_status_field("addr")

    if addr0 != addr1:
        raise Exception("Random MAC address used unexpectedly")

def test_sta_dynamic_random_mac_addr_scan_keep_oui(dev, apdev):
    """Dynamically added wpa_supplicant interface and random MAC address for scan (keep OUI)"""
    params = hostapd.wpa2_params(ssid="sta-dynamic", passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    addr0 = wpas.get_driver_status_field("addr")
    wpas.request("SET preassoc_mac_addr 2")
    wpas.request("SET rand_addr_lifetime 0")

    id = wpas.connect("sta-dynamic", psk="12345678", scan_freq="2412")
    addr1 = wpas.get_driver_status_field("addr")

    if addr0 != addr1:
        raise Exception("Random MAC address used unexpectedly")
