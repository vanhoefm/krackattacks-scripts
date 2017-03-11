# Test cases for Opportunistic Wireless Encryption (OWE)
# Copyright (c) 2017, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

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
