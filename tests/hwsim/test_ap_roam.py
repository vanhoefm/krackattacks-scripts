# Roaming tests
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

def test_ap_roam_open(dev, apdev):
    """Roam between two open APs"""
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE")
    hwsim_utils.test_connectivity(dev[0], hapd0)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], { "ssid": "test-open" })
    dev[0].scan(type="ONLY")
    dev[0].roam(apdev[1]['bssid'])
    hwsim_utils.test_connectivity(dev[0], hapd1)
    dev[0].roam(apdev[0]['bssid'])
    hwsim_utils.test_connectivity(dev[0], hapd0)

def test_ap_roam_wpa2_psk(dev, apdev):
    """Roam between two WPA2-PSK APs"""
    params = hostapd.wpa2_params(ssid="test-wpa2-psk", passphrase="12345678")
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-psk", psk="12345678")
    hwsim_utils.test_connectivity(dev[0], hapd0)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)
    dev[0].scan(type="ONLY")
    dev[0].roam(apdev[1]['bssid'])
    hwsim_utils.test_connectivity(dev[0], hapd1)
    dev[0].roam(apdev[0]['bssid'])
    hwsim_utils.test_connectivity(dev[0], hapd0)

def test_ap_reassociation_to_same_bss(dev, apdev):
    """Reassociate to the same BSS"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE")

    dev[0].request("REASSOCIATE")
    dev[0].wait_connected(timeout=10, error="Reassociation timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

    dev[0].request("REATTACH")
    dev[0].wait_connected(timeout=10, error="Reattach timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_roam_set_bssid(dev, apdev):
    """Roam control"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    hostapd.add_ap(apdev[1]['ifname'], { "ssid": "test-open" })
    id = dev[0].connect("test-open", key_mgmt="NONE", bssid=apdev[1]['bssid'],
                        scan_freq="2412")
    if dev[0].get_status_field('bssid') != apdev[1]['bssid']:
        raise Exception("Unexpected BSS")
    # for now, these are just verifying that the code path to indicate
    # within-ESS roaming changes can be executed; the actual results of those
    # operations are not currently verified (that would require a test driver
    # that does BSS selection)
    dev[0].set_network(id, "bssid", "")
    dev[0].set_network(id, "bssid", apdev[0]['bssid'])
    dev[0].set_network(id, "bssid", apdev[1]['bssid'])
