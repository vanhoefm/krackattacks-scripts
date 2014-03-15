# WPA2-Enterprise PMKSA caching tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess
import time

import hostapd
from test_ap_eap import eap_connect

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

def test_pmksa_cache_and_cui(dev, apdev):
    """PMKSA cache and Chargeable-User-Identity"""
    params = hostapd.wpa2_eap_params(ssid="cui")
    params['radius_request_cui'] = '1'
    params['acct_server_addr'] = "127.0.0.1"
    params['acct_server_port'] = "1813"
    params['acct_server_shared_secret'] = "radius"
    hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    dev[0].connect("cui", proto="RSN", key_mgmt="WPA-EAP",
                   eap="GPSK", identity="gpsk-cui",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")

    dev[0].dump_monitor()
    logger.info("Disconnect and reconnect to the same AP")
    dev[0].request("DISCONNECT")
    dev[0].request("RECONNECT")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Reconnect timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    pmksa1b = dev[0].get_pmksa(bssid)
    if pmksa1b is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa['pmkid'] != pmksa1b['pmkid']:
        raise Exception("Unexpected PMKID change for AP1")

    dev[0].request("REAUTHENTICATE")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("EAP success timed out")
    for i in range(0, 20):
        state = dev[0].get_status_field("wpa_state")
        if state == "COMPLETED":
            break
        time.sleep(0.1)
    if state != "COMPLETED":
        raise Exception("Reauthentication did not complete")

def test_pmksa_cache_preauth(dev, apdev):
    """RSN pre-authentication to generate PMKSA cache entry"""
    try:
        params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
        params['bridge'] = 'ap-br0'
        hostapd.add_ap(apdev[0]['ifname'], params)
        subprocess.call(['sudo', 'brctl', 'setfd', 'ap-br0', '0'])
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', 'ap-br0', 'up'])
        eap_connect(dev[0], apdev[0], "PAX", "pax.user@example.com",
                    password_hex="0123456789abcdef0123456789abcdef")

        params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
        params['bridge'] = 'ap-br0'
        params['rsn_preauth'] = '1'
        params['rsn_preauth_interfaces'] = 'ap-br0'
        hostapd.add_ap(apdev[1]['ifname'], params)
        bssid1 = apdev[1]['bssid']
        dev[0].scan(freq="2412")
        success = False
        for i in range(0, 50):
            time.sleep(0.1)
            pmksa = dev[0].get_pmksa(bssid1)
            if pmksa:
                success = True
                break
        if not success:
            raise Exception("No PMKSA cache entry created from pre-authentication")

        dev[0].scan(freq="2412")
        dev[0].request("ROAM " + bssid1)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                                "CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Roaming with the AP timed out")
        if "CTRL-EVENT-EAP-STARTED" in ev:
            raise Exception("Unexpected EAP exchange")
        pmksa2 = dev[0].get_pmksa(bssid1)
        if pmksa2 is None:
            raise Exception("No PMKSA cache entry")
        if pmksa['pmkid'] != pmksa2['pmkid']:
            raise Exception("Unexpected PMKID change")

    finally:
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', 'ap-br0', 'down'])
        subprocess.call(['sudo', 'brctl', 'delbr', 'ap-br0'])
