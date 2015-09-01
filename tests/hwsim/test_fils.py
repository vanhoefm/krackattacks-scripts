# Test cases for FILS
# Copyright (c) 2015-2016, Qualcomm Atheros, Inc.
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
from test_erp import check_erp_capa, start_erp_as

def check_fils_capa(dev):
    capa = dev.get_capability("fils")
    if capa is None or "FILS" not in capa:
        raise HwsimSkip("FILS not supported")

def test_fils_sk_full_auth(dev, apdev):
    """FILS SK full authentication"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    bss = dev[0].get_bss(bssid)
    logger.debug("BSS: " + str(bss))
    if "[FILS]" not in bss['flags']:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA256-CCMP]" not in bss['flags']:
        raise Exception("[WPA2-FILS-SHA256-CCMP] flag not indicated")

    res = dev[0].request("SCAN_RESULTS")
    logger.debug("SCAN_RESULTS: " + res)
    if "[FILS]" not in res:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA256-CCMP]" not in res:
        raise Exception("[WPA2-FILS-SHA256-CCMP] flag not indicated")

    dev[0].request("ERP_FLUSH")
    dev[0].connect("fils", key_mgmt="FILS-SHA256",
                   eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   erp="1", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_fils_sk_sha384_full_auth(dev, apdev):
    """FILS SK full authentication (SHA384)"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA384"
    params['auth_server_port'] = "18128"
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    bss = dev[0].get_bss(bssid)
    logger.debug("BSS: " + str(bss))
    if "[FILS]" not in bss['flags']:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA384-CCMP]" not in bss['flags']:
        raise Exception("[WPA2-FILS-SHA384-CCMP] flag not indicated")

    res = dev[0].request("SCAN_RESULTS")
    logger.debug("SCAN_RESULTS: " + res)
    if "[FILS]" not in res:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA384-CCMP]" not in res:
        raise Exception("[WPA2-FILS-SHA384-CCMP] flag not indicated")

    dev[0].request("ERP_FLUSH")
    dev[0].connect("fils", key_mgmt="FILS-SHA384",
                   eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   erp="1", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_fils_sk_pmksa_caching(dev, apdev):
    """FILS SK and PMKSA caching"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection using PMKSA caching timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    hwsim_utils.test_connectivity(dev[0], hapd)
    pmksa2 = dev[0].get_pmksa(bssid)
    if pmksa2 is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa['pmkid'] != pmksa2['pmkid']:
        raise Exception("Unexpected PMKID change")

    # Verify EAPOL reauthentication after FILS authentication
    hapd.request("EAPOL_REAUTH " + dev[0].own_addr())
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=5)
    if ev is None:
        raise Exception("EAP authentication did not start")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("EAP authentication did not succeed")
    time.sleep(0.1)
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_fils_sk_erp(dev, apdev):
    """FILS SK using ERP"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "EVENT-ASSOC-REJECT",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection using FILS/ERP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    if "EVENT-ASSOC-REJECT" in ev:
        raise Exception("Association failed")
    hwsim_utils.test_connectivity(dev[0], hapd)
