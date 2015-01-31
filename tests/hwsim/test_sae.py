# Test cases for SAE
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import os
import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd
from utils import HwsimSkip
from test_ap_psk import find_wpas_process, read_process_memory, verify_not_present, get_key_locations

def test_sae(dev, apdev):
    """SAE with default group"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "SAE":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)

    dev[0].request("SET sae_groups ")
    id = dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                        scan_freq="2412")
    if dev[0].get_status_field('sae_group') != '19':
            raise Exception("Expected default SAE group not used")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if 'flags' not in bss:
        raise Exception("Could not get BSS flags from BSS table")
    if "[WPA2-SAE-CCMP]" not in bss['flags']:
        raise Exception("Unexpected BSS flags: " + bss['flags'])

def test_sae_pmksa_caching(dev, apdev):
    """SAE and PMKSA caching"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                   scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].request("RECONNECT")
    dev[0].wait_connected(timeout=15, error="Reconnect timed out")
    if dev[0].get_status_field('sae_group') is not None:
            raise Exception("SAE group claimed to have been used")

def test_sae_pmksa_caching_disabled(dev, apdev):
    """SAE and PMKSA caching disabled"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                   scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].request("RECONNECT")
    dev[0].wait_connected(timeout=15, error="Reconnect timed out")
    if dev[0].get_status_field('sae_group') != '19':
            raise Exception("Expected default SAE group not used")

def test_sae_groups(dev, apdev):
    """SAE with all supported groups"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    # This would be the full list of supported groups, but groups 14-16
    # (2048-4096 bit MODP) are a bit too slow on some VMs and can result in
    # hitting mac80211 authentication timeout, so skip them for now.
    #sae_groups = [ 19, 25, 26, 20, 21, 2, 5, 14, 15, 16, 22, 23, 24 ]
    sae_groups = [ 19, 25, 26, 20, 21, 2, 5, 22, 23, 24 ]
    groups = [str(g) for g in sae_groups]
    params = hostapd.wpa2_params(ssid="test-sae-groups",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = ' '.join(groups)
    hostapd.add_ap(apdev[0]['ifname'], params)

    for g in groups:
        logger.info("Testing SAE group " + g)
        dev[0].request("SET sae_groups " + g)
        id = dev[0].connect("test-sae-groups", psk="12345678", key_mgmt="SAE",
                            scan_freq="2412")
        if dev[0].get_status_field('sae_group') != g:
            raise Exception("Expected SAE group not used")
        dev[0].remove_network(id)

def test_sae_group_nego(dev, apdev):
    """SAE group negotiation"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae-group-nego",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = '19'
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET sae_groups 25 26 20 19")
    dev[0].connect("test-sae-group-nego", psk="12345678", key_mgmt="SAE",
                   scan_freq="2412")
    if dev[0].get_status_field('sae_group') != '19':
        raise Exception("Expected SAE group not used")

def test_sae_anti_clogging(dev, apdev):
    """SAE anti clogging"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_anti_clogging_threshold'] = '1'
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET sae_groups ")
    dev[1].request("SET sae_groups ")
    id = {}
    for i in range(0, 2):
        dev[i].scan(freq="2412")
        id[i] = dev[i].connect("test-sae", psk="12345678", key_mgmt="SAE",
                               scan_freq="2412", only_add_network=True)
    for i in range(0, 2):
        dev[i].select_network(id[i])
    for i in range(0, 2):
        dev[i].wait_connected(timeout=10)

def test_sae_forced_anti_clogging(dev, apdev):
    """SAE anti clogging (forced)"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE WPA-PSK'
    params['sae_anti_clogging_threshold'] = '0'
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[2].connect("test-sae", psk="12345678", scan_freq="2412")
    for i in range(0, 2):
        dev[i].request("SET sae_groups ")
        dev[i].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")

def test_sae_mixed(dev, apdev):
    """Mixed SAE and non-SAE network"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE WPA-PSK'
    params['sae_anti_clogging_threshold'] = '0'
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[2].connect("test-sae", psk="12345678", scan_freq="2412")
    for i in range(0, 2):
        dev[i].request("SET sae_groups ")
        dev[i].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")

def test_sae_missing_password(dev, apdev):
    """SAE and missing password"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET sae_groups ")
    id = dev[0].connect("test-sae",
                        raw_psk="46b4a73b8a951ad53ebd2e0afdb9c5483257edd4c21d12b7710759da70945858",
                        key_mgmt="SAE", scan_freq="2412", wait_connect=False)
    ev = dev[0].wait_event(['CTRL-EVENT-SSID-TEMP-DISABLED'], timeout=10)
    if ev is None:
        raise Exception("Invalid network not temporarily disabled")


def test_sae_key_lifetime_in_memory(dev, apdev, params):
    """SAE and key lifetime in memory"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    password = "5ad144a7c1f5a5503baa6fa01dabc15b1843e8c01662d78d16b70b5cd23cf8b"
    p = hostapd.wpa2_params(ssid="test-sae", passphrase=password)
    p['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0]['ifname'], p)

    pid = find_wpas_process(dev[0])

    dev[0].request("SET sae_groups ")
    id = dev[0].connect("test-sae", psk=password, key_mgmt="SAE",
                        scan_freq="2412")

    time.sleep(1)
    buf = read_process_memory(pid, password)

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].relog()
    sae_k = None
    sae_keyseed = None
    sae_kck = None
    pmk = None
    ptk = None
    gtk = None
    with open(os.path.join(params['logdir'], 'log0'), 'r') as f:
        for l in f.readlines():
            if "SAE: k - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                sae_k = binascii.unhexlify(val)
            if "SAE: keyseed - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                sae_keyseed = binascii.unhexlify(val)
            if "SAE: KCK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                sae_kck = binascii.unhexlify(val)
            if "SAE: PMK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                pmk = binascii.unhexlify(val)
            if "WPA: PTK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                ptk = binascii.unhexlify(val)
            if "WPA: Group Key - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                gtk = binascii.unhexlify(val)
    if not sae_k or not sae_keyseed or not sae_kck or not pmk or not ptk or not gtk:
        raise Exception("Could not find keys from debug log")
    if len(gtk) != 16:
        raise Exception("Unexpected GTK length")

    kck = ptk[0:16]
    kek = ptk[16:32]
    tk = ptk[32:48]

    fname = os.path.join(params['logdir'],
                         'sae_key_lifetime_in_memory.memctx-')

    logger.info("Checking keys in memory while associated")
    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    if password not in buf:
        raise HwsimSkip("Password not found while associated")
    if pmk not in buf:
        raise HwsimSkip("PMK not found while associated")
    if kck not in buf:
        raise Exception("KCK not found while associated")
    if kek not in buf:
        raise Exception("KEK not found while associated")
    if tk in buf:
        raise Exception("TK found from memory")
    if gtk in buf:
        raise Exception("GTK found from memory")
    verify_not_present(buf, sae_k, fname, "SAE(k)")
    verify_not_present(buf, sae_keyseed, fname, "SAE(keyseed)")
    verify_not_present(buf, sae_kck, fname, "SAE(KCK)")

    logger.info("Checking keys in memory after disassociation")
    buf = read_process_memory(pid, password)

    # Note: Password is still present in network configuration
    # Note: PMK is in PMKSA cache

    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    verify_not_present(buf, kck, fname, "KCK")
    verify_not_present(buf, kek, fname, "KEK")
    verify_not_present(buf, tk, fname, "TK")
    verify_not_present(buf, gtk, fname, "GTK")
    verify_not_present(buf, sae_k, fname, "SAE(k)")
    verify_not_present(buf, sae_keyseed, fname, "SAE(keyseed)")
    verify_not_present(buf, sae_kck, fname, "SAE(KCK)")

    dev[0].request("PMKSA_FLUSH")
    logger.info("Checking keys in memory after PMKSA cache flush")
    buf = read_process_memory(pid, password)
    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    verify_not_present(buf, pmk, fname, "PMK")

    dev[0].request("REMOVE_NETWORK all")

    logger.info("Checking keys in memory after network profile removal")
    buf = read_process_memory(pid, password)

    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    verify_not_present(buf, password, fname, "password")
    verify_not_present(buf, pmk, fname, "PMK")
    verify_not_present(buf, kck, fname, "KCK")
    verify_not_present(buf, kek, fname, "KEK")
    verify_not_present(buf, tk, fname, "TK")
    verify_not_present(buf, gtk, fname, "GTK")
    verify_not_present(buf, sae_k, fname, "SAE(k)")
    verify_not_present(buf, sae_keyseed, fname, "SAE(keyseed)")
    verify_not_present(buf, sae_kck, fname, "SAE(KCK)")
