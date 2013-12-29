#!/usr/bin/python
#
# WPA2-Enterprise PMKSA caching tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd

def test_pmksa_cache_on_roam_back(dev, apdev):
    """PMKSA cache to skip EAP on reassociation back to same AP"""
    params = hostapd.wpa2_eap_params(ssid="test-pmksa-cache")
    hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    dev[0].connect("test-pmksa-cache", proto="RSN", key_mgmt="WPA-EAP",
                   eap="GPSK", identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")
    if pmksa['opportunistic'] != '0':
        raise Exception("Unexpected opportunistic PMKSA cache entry")

    hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].dump_monitor()
    logger.info("Roam to AP2")
    dev[0].scan(freq="2412")
    dev[0].request("ROAM " + bssid2)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("EAP success timed out")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    pmksa2 = dev[0].get_pmksa(bssid2)
    if pmksa2 is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa2['opportunistic'] != '0':
        raise Exception("Unexpected opportunistic PMKSA cache entry")

    dev[0].dump_monitor()
    logger.info("Roam back to AP1")
    dev[0].scan(freq="2412")
    dev[0].request("ROAM " + bssid)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    pmksa1b = dev[0].get_pmksa(bssid)
    if pmksa1b is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa['pmkid'] != pmksa1b['pmkid']:
        raise Exception("Unexpected PMKID change for AP1")

def test_pmksa_cache_opportunistic_only_on_sta(dev, apdev):
    """Opportunistic PMKSA caching enabled only on station"""
    params = hostapd.wpa2_eap_params(ssid="test-pmksa-cache")
    hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    dev[0].connect("test-pmksa-cache", proto="RSN", key_mgmt="WPA-EAP",
                   eap="GPSK", identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef", okc=True,
                   scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")
    if pmksa['opportunistic'] != '0':
        raise Exception("Unexpected opportunistic PMKSA cache entry")

    hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].dump_monitor()
    logger.info("Roam to AP2")
    dev[0].scan(freq="2412")
    dev[0].request("ROAM " + bssid2)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("EAP success timed out")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    pmksa2 = dev[0].get_pmksa(bssid2)
    if pmksa2 is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa2['opportunistic'] != '0':
        raise Exception("Unexpected opportunistic PMKSA cache entry")

    dev[0].dump_monitor()
    logger.info("Roam back to AP1")
    dev[0].scan(freq="2412")
    dev[0].request("ROAM " + bssid)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    pmksa1b = dev[0].get_pmksa(bssid)
    if pmksa1b is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa['pmkid'] != pmksa1b['pmkid']:
        raise Exception("Unexpected PMKID change for AP1")

def test_pmksa_cache_opportunistic(dev, apdev):
    """Opportunistic PMKSA caching"""
    params = hostapd.wpa2_eap_params(ssid="test-pmksa-cache")
    params['okc'] = "1"
    hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    dev[0].connect("test-pmksa-cache", proto="RSN", key_mgmt="WPA-EAP",
                   eap="GPSK", identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef", okc=True,
                   scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")
    if pmksa['opportunistic'] != '0':
        raise Exception("Unexpected opportunistic PMKSA cache entry")

    hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].dump_monitor()
    logger.info("Roam to AP2")
    dev[0].scan(freq="2412")
    dev[0].request("ROAM " + bssid2)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    pmksa2 = dev[0].get_pmksa(bssid2)
    if pmksa2 is None:
        raise Exception("No PMKSA cache entry created")

    dev[0].dump_monitor()
    logger.info("Roam back to AP1")
    dev[0].scan(freq="2412")
    dev[0].request("ROAM " + bssid)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")

    pmksa1b = dev[0].get_pmksa(bssid)
    if pmksa1b is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa['pmkid'] != pmksa1b['pmkid']:
        raise Exception("Unexpected PMKID change for AP1")

def test_pmksa_cache_expiration(dev, apdev):
    """PMKSA cache entry expiration"""
    params = hostapd.wpa2_eap_params(ssid="test-pmksa-cache")
    hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    dev[0].request("SET dot11RSNAConfigPMKLifetime 10")
    dev[0].connect("test-pmksa-cache", proto="RSN", key_mgmt="WPA-EAP",
                   eap="GPSK", identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")
    logger.info("Wait for PMKSA cache entry to expire")
    ev = dev[0].wait_event(["WPA: Key negotiation completed",
                            "CTRL-EVENT-DISCONNECTED"], timeout=15)
    if ev is None:
        raise Exception("No EAP reauthentication seen")
    if "CTRL-EVENT-DISCONNECTED" in ev:
        raise Exception("Unexpected disconnection")
    pmksa2 = dev[0].get_pmksa(bssid)
    if pmksa['pmkid'] == pmksa2['pmkid']:
        raise Exception("PMKID did not change")
