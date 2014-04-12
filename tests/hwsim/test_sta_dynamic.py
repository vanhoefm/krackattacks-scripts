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
