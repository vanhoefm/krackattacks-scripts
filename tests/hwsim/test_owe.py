# Test cases for Opportunistic Wireless Encryption (OWE)
# Copyright (c) 2017, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

import hostapd
from wpasupplicant import WpaSupplicant
import hwsim_utils
from utils import HwsimSkip

def test_owe(dev, apdev):
    """Opportunistic Wireless Encryption"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe",
               "wpa": "2",
               "ieee80211w": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    bss = dev[0].get_bss(bssid)
    if "[WPA2-OWE-CCMP]" not in bss['flags']:
        raise Exception("OWE AKM not recognized: " + bss['flags'])

    dev[0].connect("owe", key_mgmt="OWE", ieee80211w="2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)
    val = dev[0].get_status_field("key_mgmt")
    if val != "OWE":
        raise Exception("Unexpected key_mgmt: " + val)

def test_owe_groups(dev, apdev):
    """Opportunistic Wireless Encryption - DH groups"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    for group in [ 19, 20, 21 ]:
        dev[0].connect("owe", key_mgmt="OWE", owe_group=str(group))
        hwsim_utils.test_connectivity(dev[0], hapd)
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()
        dev[0].dump_monitor()

def test_owe_pmksa_caching(dev, apdev):
    """Opportunistic Wireless Encryption and PMKSA caching"""
    run_owe_pmksa_caching(dev, apdev)

def test_owe_pmksa_caching_connect_cmd(dev, apdev):
    """Opportunistic Wireless Encryption and PMKSA caching using cfg80211 connect command"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    run_owe_pmksa_caching([ wpas ], apdev)

def run_owe_pmksa_caching(dev, apdev):
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    id = dev[0].connect("owe", key_mgmt="OWE")
    hwsim_utils.test_connectivity(dev[0], hapd)
    pmksa = dev[0].get_pmksa(bssid)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()

    dev[0].select_network(id, 2412)
    dev[0].wait_connected()
    hwsim_utils.test_connectivity(dev[0], hapd)
    pmksa2 = dev[0].get_pmksa(bssid)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()

    if "OK" not in hapd.request("PMKSA_FLUSH"):
        raise Exception("PMKSA_FLUSH failed")

    dev[0].select_network(id, 2412)
    dev[0].wait_connected()
    hwsim_utils.test_connectivity(dev[0], hapd)
    pmksa3 = dev[0].get_pmksa(bssid)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()

    if pmksa is None or pmksa2 is None or pmksa3 is None:
        raise Exception("PMKSA entry missing")
    if pmksa['pmkid'] != pmksa2['pmkid']:
        raise Exception("Unexpected PMKID change when using PMKSA caching")
    if pmksa['pmkid'] == pmksa3['pmkid']:
        raise Exception("PMKID did not change after PMKSA cache flush")

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
    run_owe_transition_mode(dev, apdev)

def test_owe_transition_mode_connect_cmd(dev, apdev):
    """Opportunistic Wireless Encryption transition mode using cfg80211 connect command"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    run_owe_transition_mode([ wpas ], apdev)

def run_owe_transition_mode(dev, apdev):
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    dev[0].flush_scan_cache()
    params = { "ssid": "owe-random",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP",
               "ieee80211w": "2",
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

    id = dev[0].connect("owe-test", key_mgmt="OWE", ieee80211w="2",
                        scan_freq="2412")
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

def test_owe_transition_mode_open_only_ap(dev, apdev):
    """Opportunistic Wireless Encryption transition mode connect to open-only AP"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    dev[0].flush_scan_cache()
    params = { "ssid": "owe-test-open" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")

    bss = dev[0].get_bss(bssid)

    id = dev[0].connect("owe-test-open", key_mgmt="OWE", ieee80211w="2",
                        scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)
    val = dev[0].get_status_field("key_mgmt")
    if val != "NONE":
        raise Exception("Unexpected key_mgmt: " + val)

def test_owe_transition_mode_multi_bss(dev, apdev):
    """Opportunistic Wireless Encryption transition mode (multi BSS)"""
    try:
        run_owe_transition_mode_multi_bss(dev, apdev)
    finally:
        dev[0].request("SCAN_INTERVAL 5")

def run_owe_transition_mode_multi_bss(dev, apdev):
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    ifname1 = apdev[0]['ifname']
    ifname2 = apdev[0]['ifname'] + '-2'
    hapd1 = hostapd.add_bss(apdev[0], ifname1, 'owe-bss-1.conf')
    hapd2 = hostapd.add_bss(apdev[0], ifname2, 'owe-bss-2.conf')
    hapd2.bssidx = 1

    bssid = hapd1.own_addr()
    bssid2 = hapd2.own_addr()

    # Beaconing with the OWE Transition Mode element can start only once both
    # BSSs are enabled, so the very first Beacon frame may go out without this
    # element. Wait a bit to avoid getting incomplete scan results.
    time.sleep(0.1)

    dev[0].request("SCAN_INTERVAL 1")
    dev[0].scan_for_bss(bssid2, freq="2412")
    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].connect("transition-mode-open", key_mgmt="OWE")
    val = dev[0].get_status_field("bssid")
    if val != bssid2:
        raise Exception("Unexpected bssid: " + val)
    val = dev[0].get_status_field("key_mgmt")
    if val != "OWE":
        raise Exception("Unexpected key_mgmt: " + val)
    hwsim_utils.test_connectivity(dev[0], hapd2)

def test_owe_unsupported_group(dev, apdev):
    """Opportunistic Wireless Encryption and unsupported group"""
    try:
        run_owe_unsupported_group(dev, apdev)
    finally:
        dev[0].request("VENDOR_ELEM_REMOVE 13 *")

def test_owe_unsupported_group_connect_cmd(dev, apdev):
    """Opportunistic Wireless Encryption and unsupported group using cfg80211 connect command"""
    try:
        wpas = None
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
        run_owe_unsupported_group([ wpas ], apdev)
    finally:
        if wpas:
            wpas.request("VENDOR_ELEM_REMOVE 13 *")

def run_owe_unsupported_group(dev, apdev):
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    # Override OWE Dh Parameters element with a payload that uses invalid group
    # 0 (and actual group 19 data) to make the AP reject this with the specific
    # status code 77.
    dev[0].request("VENDOR_ELEM_ADD 13 ff23200000783590fb7440e03d5b3b33911f86affdcc6b4411b707846ac4ff08ddc8831ccd")

    params = { "ssid": "owe",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].connect("owe", key_mgmt="OWE", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-ASSOC-REJECT"], timeout=10)
    dev[0].request("DISCONNECT")
    if ev is None:
        raise Exception("Association not rejected")
    if "status_code=77" not in ev:
        raise Exception("Unexpected rejection reason: " + ev)

def test_owe_limited_group_set(dev, apdev):
    """Opportunistic Wireless Encryption and limited group set"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP",
               "owe_groups": "20 21" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].connect("owe", key_mgmt="OWE", owe_group="19", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-ASSOC-REJECT"], timeout=10)
    dev[0].request("DISCONNECT")
    if ev is None:
        raise Exception("Association not rejected")
    if "status_code=77" not in ev:
        raise Exception("Unexpected rejection reason: " + ev)
    dev[0].dump_monitor()

    for group in [ 20, 21 ]:
        dev[0].connect("owe", key_mgmt="OWE", owe_group=str(group))
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()
        dev[0].dump_monitor()

def test_owe_group_negotiation(dev, apdev):
    """Opportunistic Wireless Encryption and group negotiation"""
    run_owe_group_negotiation(dev[0], apdev)

def test_owe_group_negotiation_connect_cmd(dev, apdev):
    """Opportunistic Wireless Encryption and group negotiation (connect command)"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    run_owe_group_negotiation(wpas, apdev)

def run_owe_group_negotiation(dev, apdev):
    if "OWE" not in dev.get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    params = { "ssid": "owe",
               "wpa": "2",
               "wpa_key_mgmt": "OWE",
               "rsn_pairwise": "CCMP",
               "owe_groups": "21" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    dev.scan_for_bss(bssid, freq="2412")
    dev.connect("owe", key_mgmt="OWE")
