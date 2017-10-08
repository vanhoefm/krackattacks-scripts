# Test cases for Opportunistic Wireless Encryption (OWE)
# Copyright (c) 2017, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd
import hwsim_utils
from utils import HwsimSkip

def test_owe(dev, apdev):
    """Opportunistic Wireless Encryption"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    bss = dev[0].get_bss(bssid)
    if "[WPA2-OWE-CCMP]" not in bss['flags']:
        raise Exception("OWE AKM not recognized: " + bss['flags'])

    dev[0].connect("owe", key_mgmt="OWE")
    hwsim_utils.test_connectivity(dev[0], hapd)
    val = dev[0].get_status_field("key_mgmt")
    if val != "OWE":
        raise Exception("Unexpected key_mgmt: " + val)

def test_owe_and_psk(dev, apdev):
    """Opportunistic Wireless Encryption and WPA2-PSK enabled"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe+psk",
               "wpa": "2",
               "wpa_key_mgmt": "OWE WPA-PSK",
               "rsn_pairwise": "CCMP",
               "wpa_passphrase": "12345678" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].connect("owe+psk", psk="12345678")
    hwsim_utils.test_connectivity(dev[0], hapd)

    dev[1].scan_for_bss(bssid, freq="2412")
    dev[1].connect("owe+psk", key_mgmt="OWE")
    hwsim_utils.test_connectivity(dev[1], hapd)

def test_owe_transition_mode(dev, apdev):
    """Opportunistic Wireless Encryption transition mode"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe-random",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP",
               "owe_transition_bssid": apdev[1]['bssid'],
               "owe_transition_ssid": '"owe-test"',
               "ignore_broadcast_ssid": "1" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    params = { "ssid": "owe-test",
               "owe_transition_bssid": apdev[0]['bssid'],
               "owe_transition_ssid": '"owe-random"' }
    hapd2 = hostapd.add_ap(apdev[1], params)
    bssid2 = hapd2.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].scan_for_bss(bssid2, freq="2412")

    bss = dev[0].get_bss(bssid)
    if "[WPA2-OWE-CCMP]" not in bss['flags']:
        raise Exception("OWE AKM not recognized: " + bss['flags'])
    if "[OWE-TRANS]" not in bss['flags']:
        raise Exception("OWE transition not recognized: " + bss['flags'])

    bss = dev[0].get_bss(bssid2)
    if "[OWE-TRANS-OPEN]" not in bss['flags']:
        raise Exception("OWE transition (open) not recognized: " + bss['flags'])

    id = dev[0].connect("owe-test", key_mgmt="OWE")
    hwsim_utils.test_connectivity(dev[0], hapd)
    val = dev[0].get_status_field("key_mgmt")
    if val != "OWE":
        raise Exception("Unexpected key_mgmt: " + val)

    logger.info("Move to OWE only mode (disable transition mode)")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()

    hapd2.disable()
    hapd.disable()
    dev[0].flush_scan_cache()
    hapd.set("owe_transition_bssid", "00:00:00:00:00:00")
    hapd.set("ignore_broadcast_ssid", '0')
    hapd.set("ssid", 'owe-test')
    hapd.enable()

    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].select_network(id, 2412)
    dev[0].wait_connected()
    hwsim_utils.test_connectivity(dev[0], hapd)
