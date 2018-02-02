# Test cases for SAE
# Copyright (c) 2013-2016, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import binascii
import os
import time
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from utils import HwsimSkip, alloc_fail, fail_test, wait_fail_trigger
from test_ap_psk import find_wpas_process, read_process_memory, verify_not_present, get_key_locations

@remote_compatible
def test_sae(dev, apdev):
    """SAE with default group"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)
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

    res = hapd.request("STA-FIRST")
    if "sae_group=19" not in res.splitlines():
        raise Exception("hostapd STA output did not specify SAE group")

@remote_compatible
def test_sae_password_ecc(dev, apdev):
    """SAE with number of different passwords (ECC)"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups 19")

    for i in range(10):
        password = "12345678-" + str(i)
        hapd.set("wpa_passphrase", password)
        dev[0].connect("test-sae", psk=password, key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()

@remote_compatible
def test_sae_password_ffc(dev, apdev):
    """SAE with number of different passwords (FFC)"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = '22'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups 22")

    for i in range(10):
        password = "12345678-" + str(i)
        hapd.set("wpa_passphrase", password)
        dev[0].connect("test-sae", psk=password, key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()

@remote_compatible
def test_sae_pmksa_caching(dev, apdev):
    """SAE and PMKSA caching"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

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

@remote_compatible
def test_sae_pmksa_caching_disabled(dev, apdev):
    """SAE and PMKSA caching disabled"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)

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
    # This is the full list of supported groups, but groups 14-16 (2048-4096 bit
    # MODP) and group 21 (521-bit random ECP group) are a bit too slow on some
    # VMs and can result in hitting the mac80211 authentication timeout, so
    # allow them to fail and just report such failures in the debug log.
    sae_groups = [ 19, 25, 26, 20, 21, 2, 5, 14, 15, 16, 22, 23, 24 ]
    tls = dev[0].request("GET tls_library")
    if tls.startswith("OpenSSL") and "build=OpenSSL 1.0.2" in tls and "run=OpenSSL 1.0.2" in tls:
        logger.info("Add Brainpool EC groups since OpenSSL is new enough")
        sae_groups += [ 27, 28, 29, 30 ]
    heavy_groups = [ 14, 15, 16 ]
    groups = [str(g) for g in sae_groups]
    params = hostapd.wpa2_params(ssid="test-sae-groups",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = ' '.join(groups)
    hostapd.add_ap(apdev[0], params)

    for g in groups:
        logger.info("Testing SAE group " + g)
        dev[0].request("SET sae_groups " + g)
        id = dev[0].connect("test-sae-groups", psk="12345678", key_mgmt="SAE",
                            scan_freq="2412", wait_connect=False)
        if int(g) in heavy_groups:
            ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=5)
            if ev is None:
                logger.info("No connection with heavy SAE group %s did not connect - likely hitting timeout in mac80211" % g)
                dev[0].remove_network(id)
                time.sleep(0.1)
                dev[0].dump_monitor()
                continue
            logger.info("Connection with heavy SAE group " + g)
        else:
            ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
            if ev is None:
                if "BoringSSL" in tls and int(g) in [ 25 ]:
                    logger.info("Ignore connection failure with group " + g + " with BoringSSL")
                    dev[0].remove_network(id)
                    dev[0].dump_monitor()
                    continue
                raise Exception("Connection timed out with group " + g)
        if dev[0].get_status_field('sae_group') != g:
            raise Exception("Expected SAE group not used")
        dev[0].remove_network(id)
        dev[0].wait_disconnected()
        dev[0].dump_monitor()

@remote_compatible
def test_sae_group_nego(dev, apdev):
    """SAE group negotiation"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae-group-nego",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = '19'
    hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups 25 26 20 19")
    dev[0].connect("test-sae-group-nego", psk="12345678", key_mgmt="SAE",
                   scan_freq="2412")
    if dev[0].get_status_field('sae_group') != '19':
        raise Exception("Expected SAE group not used")

@remote_compatible
def test_sae_anti_clogging(dev, apdev):
    """SAE anti clogging"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_anti_clogging_threshold'] = '1'
    hostapd.add_ap(apdev[0], params)

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
    hostapd.add_ap(apdev[0], params)
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
    hostapd.add_ap(apdev[0], params)

    dev[2].connect("test-sae", psk="12345678", scan_freq="2412")
    for i in range(0, 2):
        dev[i].request("SET sae_groups ")
        dev[i].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")

def test_sae_mixed_mfp(dev, apdev):
    """Mixed SAE and non-SAE network and MFP required with SAE"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE WPA-PSK'
    params["ieee80211w"] = "1"
    params['sae_require_mfp'] = '1'
    hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE", ieee80211w="2",
                   scan_freq="2412")
    dev[0].dump_monitor()

    dev[1].request("SET sae_groups ")
    dev[1].connect("test-sae", psk="12345678", key_mgmt="SAE", ieee80211w="0",
                   scan_freq="2412", wait_connect=False)
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-ASSOC-REJECT"], timeout=10)
    if ev is None:
        raise Exception("No connection result reported")
    if "CTRL-EVENT-ASSOC-REJECT" not in ev:
        raise Exception("SAE connection without MFP was not rejected")
    if "status_code=31" not in ev:
        raise Exception("Unexpected status code in rejection: " + ev)
    dev[1].request("DISCONNECT")
    dev[1].dump_monitor()

    dev[2].connect("test-sae", psk="12345678", ieee80211w="0", scan_freq="2412")
    dev[2].dump_monitor()

@remote_compatible
def test_sae_missing_password(dev, apdev):
    """SAE and missing password"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

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
    hapd = hostapd.add_ap(apdev[0], p)

    pid = find_wpas_process(dev[0])

    dev[0].request("SET sae_groups ")
    id = dev[0].connect("test-sae", psk=password, key_mgmt="SAE",
                        scan_freq="2412")

    # The decrypted copy of GTK is freed only after the CTRL-EVENT-CONNECTED
    # event has been delivered, so verify that wpa_supplicant has returned to
    # eloop before reading process memory.
    time.sleep(1)
    dev[0].ping()
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
    #if tk in buf:
    #    raise Exception("TK found from memory")
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
    if gtk in buf:
        get_key_locations(buf, gtk, "GTK")
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

@remote_compatible
def test_sae_oom_wpas(dev, apdev):
    """SAE and OOM in wpa_supplicant"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups 25")
    tls = dev[0].request("GET tls_library")
    if "BoringSSL" in tls:
        dev[0].request("SET sae_groups 26")
    with alloc_fail(dev[0], 1, "sae_set_group"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")

    dev[0].request("SET sae_groups ")
    with alloc_fail(dev[0], 2, "sae_set_group"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(dev[0], 1, "wpabuf_alloc;sme_auth_build_sae_commit"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(dev[0], 1, "wpabuf_alloc;sme_auth_build_sae_confirm"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412", wait_connect=False)
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(dev[0], 1, "=sme_authenticate"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412", wait_connect=False)
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(dev[0], 1, "radio_add_work;sme_authenticate"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412", wait_connect=False)
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
        dev[0].request("REMOVE_NETWORK all")

@remote_compatible
def test_sae_proto_ecc(dev, apdev):
    """SAE protocol testing (ECC)"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']

    dev[0].request("SET sae_groups 19")

    tests = [ ("Confirm mismatch",
               "1300" + "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8",
               "0000800edebc3f260dc1fe7e0b20888af2b8a3316252ec37388a8504e25b73dc4240"),
              ("Commit without even full cyclic group field",
               "13",
               None),
              ("Too short commit",
               "1300" + "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02",
               None),
              ("Invalid commit scalar (0)",
               "1300" + "0000000000000000000000000000000000000000000000000000000000000000" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8",
               None),
              ("Invalid commit scalar (1)",
               "1300" + "0000000000000000000000000000000000000000000000000000000000000001" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8",
               None),
              ("Invalid commit scalar (> r)",
               "1300" + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8",
               None),
              ("Commit element not on curve",
               "1300" + "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728d0000000000000000000000000000000000000000000000000000000000000000",
               None),
              ("Invalid commit element (y coordinate > P)",
               "1300" + "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
               None),
              ("Invalid commit element (x coordinate > P)",
               "1300" + "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03" + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8",
               None),
              ("Different group in commit",
               "1400" + "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8",
               None),
              ("Too short confirm",
               "1300" + "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03" + "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728dd3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8",
               "0000800edebc3f260dc1fe7e0b20888af2b8a3316252ec37388a8504e25b73dc42")]
    for (note, commit, confirm) in tests:
        logger.info(note)
        dev[0].scan_for_bss(bssid, freq=2412)
        hapd.set("ext_mgmt_frame_handling", "1")
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412", wait_connect=False)

        logger.info("Commit")
        for i in range(0, 10):
            req = hapd.mgmt_rx()
            if req is None:
                raise Exception("MGMT RX wait timed out (commit)")
            if req['subtype'] == 11:
                break
            req = None
        if not req:
            raise Exception("Authentication frame (commit) not received")

        hapd.dump_monitor()
        resp = {}
        resp['fc'] = req['fc']
        resp['da'] = req['sa']
        resp['sa'] = req['da']
        resp['bssid'] = req['bssid']
        resp['payload'] = binascii.unhexlify("030001000000" + commit)
        hapd.mgmt_tx(resp)

        if confirm:
            logger.info("Confirm")
            for i in range(0, 10):
                req = hapd.mgmt_rx()
                if req is None:
                    raise Exception("MGMT RX wait timed out (confirm)")
                if req['subtype'] == 11:
                    break
                req = None
            if not req:
                raise Exception("Authentication frame (confirm) not received")

            hapd.dump_monitor()
            resp = {}
            resp['fc'] = req['fc']
            resp['da'] = req['sa']
            resp['sa'] = req['da']
            resp['bssid'] = req['bssid']
            resp['payload'] = binascii.unhexlify("030002000000" + confirm)
            hapd.mgmt_tx(resp)

        time.sleep(0.1)
        dev[0].request("REMOVE_NETWORK all")
        hapd.set("ext_mgmt_frame_handling", "0")
        hapd.dump_monitor()

@remote_compatible
def test_sae_proto_ffc(dev, apdev):
    """SAE protocol testing (FFC)"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']

    dev[0].request("SET sae_groups 2")

    tests = [ ("Confirm mismatch",
               "0200" + "0c70519d874e3e4930a917cc5e17ea7a26028211159f217bab28b8d6c56691805e49f03249b2c6e22c7c9f86b30e04ccad2deedd5e5108ae07b737c00001c59cd0eb08b1dfc7f1b06a1542e2b6601a963c066e0c65940983a03917ae57a101ce84b5cbbc76ff33ebb990aac2e54aa0f0ab6ec0a58113d927683502b2cb2347d2" + "a8c00117493cdffa5dd671e934bc9cb1a69f39e25e9dd9cd9afd3aea2441a0f5491211c7ba50a753563f9ce943b043557cb71193b28e86ed9544f4289c471bf91b70af5c018cf4663e004165b0fd0bc1d8f3f78adf42eee92bcbc55246fd3ee9f107ab965dc7d4986f23eb71d616ebfe6bfe0a6c1ac5dc1718acee17c9a17486",
               "0000f3116a9731f1259622e3eb55d4b3b50ba16f8c5f5565b28e609b180c51460251"),
              ("Too short commit",
               "0200" + "0c70519d874e3e4930a917cc5e17ea7a26028211159f217bab28b8d6c56691805e49f03249b2c6e22c7c9f86b30e04ccad2deedd5e5108ae07b737c00001c59cd0eb08b1dfc7f1b06a1542e2b6601a963c066e0c65940983a03917ae57a101ce84b5cbbc76ff33ebb990aac2e54aa0f0ab6ec0a58113d927683502b2cb2347d2" + "a8c00117493cdffa5dd671e934bc9cb1a69f39e25e9dd9cd9afd3aea2441a0f5491211c7ba50a753563f9ce943b043557cb71193b28e86ed9544f4289c471bf91b70af5c018cf4663e004165b0fd0bc1d8f3f78adf42eee92bcbc55246fd3ee9f107ab965dc7d4986f23eb71d616ebfe6bfe0a6c1ac5dc1718acee17c9a174",
               None),
              ("Invalid element (0) in commit",
               "0200" + "0c70519d874e3e4930a917cc5e17ea7a26028211159f217bab28b8d6c56691805e49f03249b2c6e22c7c9f86b30e04ccad2deedd5e5108ae07b737c00001c59cd0eb08b1dfc7f1b06a1542e2b6601a963c066e0c65940983a03917ae57a101ce84b5cbbc76ff33ebb990aac2e54aa0f0ab6ec0a58113d927683502b2cb2347d2" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
               None),
              ("Invalid element (1) in commit",
               "0200" + "0c70519d874e3e4930a917cc5e17ea7a26028211159f217bab28b8d6c56691805e49f03249b2c6e22c7c9f86b30e04ccad2deedd5e5108ae07b737c00001c59cd0eb08b1dfc7f1b06a1542e2b6601a963c066e0c65940983a03917ae57a101ce84b5cbbc76ff33ebb990aac2e54aa0f0ab6ec0a58113d927683502b2cb2347d2" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
               None),
              ("Invalid element (> P) in commit",
               "0200" + "0c70519d874e3e4930a917cc5e17ea7a26028211159f217bab28b8d6c56691805e49f03249b2c6e22c7c9f86b30e04ccad2deedd5e5108ae07b737c00001c59cd0eb08b1dfc7f1b06a1542e2b6601a963c066e0c65940983a03917ae57a101ce84b5cbbc76ff33ebb990aac2e54aa0f0ab6ec0a58113d927683502b2cb2347d2" + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
               None) ]
    for (note, commit, confirm) in tests:
        logger.info(note)
        dev[0].scan_for_bss(bssid, freq=2412)
        hapd.set("ext_mgmt_frame_handling", "1")
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412", wait_connect=False)

        logger.info("Commit")
        for i in range(0, 10):
            req = hapd.mgmt_rx()
            if req is None:
                raise Exception("MGMT RX wait timed out (commit)")
            if req['subtype'] == 11:
                break
            req = None
        if not req:
            raise Exception("Authentication frame (commit) not received")

        hapd.dump_monitor()
        resp = {}
        resp['fc'] = req['fc']
        resp['da'] = req['sa']
        resp['sa'] = req['da']
        resp['bssid'] = req['bssid']
        resp['payload'] = binascii.unhexlify("030001000000" + commit)
        hapd.mgmt_tx(resp)

        if confirm:
            logger.info("Confirm")
            for i in range(0, 10):
                req = hapd.mgmt_rx()
                if req is None:
                    raise Exception("MGMT RX wait timed out (confirm)")
                if req['subtype'] == 11:
                    break
                req = None
            if not req:
                raise Exception("Authentication frame (confirm) not received")

            hapd.dump_monitor()
            resp = {}
            resp['fc'] = req['fc']
            resp['da'] = req['sa']
            resp['sa'] = req['da']
            resp['bssid'] = req['bssid']
            resp['payload'] = binascii.unhexlify("030002000000" + confirm)
            hapd.mgmt_tx(resp)

        time.sleep(0.1)
        dev[0].request("REMOVE_NETWORK all")
        hapd.set("ext_mgmt_frame_handling", "0")
        hapd.dump_monitor()

def test_sae_proto_confirm_replay(dev, apdev):
    """SAE protocol testing - Confirm replay"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']

    dev[0].request("SET sae_groups 19")

    dev[0].scan_for_bss(bssid, freq=2412)
    hapd.set("ext_mgmt_frame_handling", "1")
    dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                   scan_freq="2412", wait_connect=False)

    logger.info("Commit")
    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out (commit)")
        if req['subtype'] == 11:
            break
        req = None
    if not req:
        raise Exception("Authentication frame (commit) not received")

    bssid = hapd.own_addr().replace(':', '')
    addr = dev[0].own_addr().replace(':', '')
    hdr = "b0003a01" + bssid + addr + bssid + "1000"

    hapd.dump_monitor()
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + req['frame'].encode('hex'))

    logger.info("Confirm")
    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out (confirm)")
        if req['subtype'] == 11:
            break
        req = None
    if not req:
        raise Exception("Authentication frame (confirm) not received")

    hapd.dump_monitor()
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + req['frame'].encode('hex'))

    logger.info("Replay Confirm")
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + req['frame'].encode('hex'))

    logger.info("Association Request")
    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out (AssocReq)")
        if req['subtype'] == 0:
            break
        req = None
    if not req:
        raise Exception("Association Request frame not received")

    hapd.dump_monitor()
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + req['frame'].encode('hex'))
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Management frame TX status not reported (1)")
    if "stype=1 ok=1" not in ev:
        raise Exception("Unexpected management frame TX status (1): " + ev)
    cmd = "MGMT_TX_STATUS_PROCESS %s" % (" ".join(ev.split(' ')[1:4]))
    if "OK" not in hapd.request(cmd):
        raise Exception("MGMT_TX_STATUS_PROCESS failed")

    hapd.set("ext_mgmt_frame_handling", "0")

    dev[0].wait_connected()

def test_sae_proto_hostapd(dev, apdev):
    """SAE protocol testing with hostapd"""
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = "19 65535"
    hapd = hostapd.add_ap(apdev[0], params)
    hapd.set("ext_mgmt_frame_handling", "1")
    bssid = hapd.own_addr().replace(':', '')
    addr = "020000000000"
    addr2 = "020000000001"
    hdr = "b0003a01" + bssid + addr + bssid + "1000"
    hdr2 = "b0003a01" + bssid + addr2 + bssid + "1000"
    group = "1300"
    scalar = "f7df19f4a7fef1d3b895ea1de150b7c5a7a705c8ebb31a52b623e0057908bd93"
    element_x = "21931572027f2e953e2a49fab3d992944102cc95aa19515fc068b394fb25ae3c"
    element_y = "cb4eeb94d7b0b789abfdb73a67ab9d6d5efa94dd553e0e724a6289821cbce530"
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + hdr + "030001000000" + group + scalar + element_x + element_y)
    # "SAE: Not enough data for scalar"
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + hdr + "030001000000" + group + scalar[:-2])
    # "SAE: Do not allow group to be changed"
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + hdr + "030001000000" + "ffff" + scalar[:-2])
    # "SAE: Unsupported Finite Cyclic Group 65535"
    hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + hdr2 + "030001000000" + "ffff" + scalar[:-2])

@remote_compatible
def test_sae_no_ffc_by_default(dev, apdev):
    """SAE and default groups rejecting FFC"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups 5")
    dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE", scan_freq="2412",
                   wait_connect=False)
    ev = dev[0].wait_event(["SME: Trying to authenticate"], timeout=3)
    if ev is None:
        raise Exception("Did not try to authenticate")
    ev = dev[0].wait_event(["SME: Trying to authenticate"], timeout=3)
    if ev is None:
        raise Exception("Did not try to authenticate (2)")
    dev[0].request("REMOVE_NETWORK all")

def sae_reflection_attack(apdev, dev, group):
    if "SAE" not in dev.get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="no-knowledge-of-passphrase")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev, params)
    bssid = apdev['bssid']

    dev.scan_for_bss(bssid, freq=2412)
    hapd.set("ext_mgmt_frame_handling", "1")

    dev.request("SET sae_groups %d" % group)
    dev.connect("test-sae", psk="reflection-attack", key_mgmt="SAE",
                scan_freq="2412", wait_connect=False)

    # Commit
    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out")
        if req['subtype'] == 11:
            break
        req = None
    if not req:
        raise Exception("Authentication frame not received")

    resp = {}
    resp['fc'] = req['fc']
    resp['da'] = req['sa']
    resp['sa'] = req['da']
    resp['bssid'] = req['bssid']
    resp['payload'] = req['payload']
    hapd.mgmt_tx(resp)

    # Confirm
    req = hapd.mgmt_rx(timeout=0.5)
    if req is not None:
        if req['subtype'] == 11:
            raise Exception("Unexpected Authentication frame seen")

@remote_compatible
def test_sae_reflection_attack_ecc(dev, apdev):
    """SAE reflection attack (ECC)"""
    sae_reflection_attack(apdev[0], dev[0], 19)

@remote_compatible
def test_sae_reflection_attack_ffc(dev, apdev):
    """SAE reflection attack (FFC)"""
    sae_reflection_attack(apdev[0], dev[0], 5)

def sae_reflection_attack_internal(apdev, dev, group):
    if "SAE" not in dev.get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="no-knowledge-of-passphrase")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_reflection_attack'] = '1'
    hapd = hostapd.add_ap(apdev, params)
    bssid = apdev['bssid']

    dev.scan_for_bss(bssid, freq=2412)
    dev.request("SET sae_groups %d" % group)
    dev.connect("test-sae", psk="reflection-attack", key_mgmt="SAE",
                scan_freq="2412", wait_connect=False)
    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection")

@remote_compatible
def test_sae_reflection_attack_ecc_internal(dev, apdev):
    """SAE reflection attack (ECC) - internal"""
    sae_reflection_attack_internal(apdev[0], dev[0], 19)

@remote_compatible
def test_sae_reflection_attack_ffc_internal(dev, apdev):
    """SAE reflection attack (FFC) - internal"""
    sae_reflection_attack_internal(apdev[0], dev[0], 5)

@remote_compatible
def test_sae_commit_override(dev, apdev):
    """SAE commit override (hostapd)"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_commit_override'] = '13ffbad00d215867a7c5ff37d87bb9bdb7cb116e520f71e8d7a794ca2606d537ddc6c099c40e7a25372b80a8fd443cd7dd222c8ea21b8ef372d4b3e316c26a73fd999cc79ad483eb826e7b3893ea332da68fa13224bcdeb4fb18b0584dd100a2c514'
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", psk="test-sae", key_mgmt="SAE",
                   scan_freq="2412", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection")

@remote_compatible
def test_sae_commit_override2(dev, apdev):
    """SAE commit override (wpa_supplicant)"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].request("SET sae_groups ")
    dev[0].set('sae_commit_override', '13ffbad00d215867a7c5ff37d87bb9bdb7cb116e520f71e8d7a794ca2606d537ddc6c099c40e7a25372b80a8fd443cd7dd222c8ea21b8ef372d4b3e316c26a73fd999cc79ad483eb826e7b3893ea332da68fa13224bcdeb4fb18b0584dd100a2c514')
    dev[0].connect("test-sae", psk="test-sae", key_mgmt="SAE",
                   scan_freq="2412", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection")

@remote_compatible
def test_sae_anti_clogging_proto(dev, apdev):
    """SAE anti clogging protocol testing"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="no-knowledge-of-passphrase")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq=2412)
    hapd.set("ext_mgmt_frame_handling", "1")

    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", psk="anti-cloggign", key_mgmt="SAE",
                   scan_freq="2412", wait_connect=False)

    # Commit
    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out")
        if req['subtype'] == 11:
            break
        req = None
    if not req:
        raise Exception("Authentication frame not received")

    resp = {}
    resp['fc'] = req['fc']
    resp['da'] = req['sa']
    resp['sa'] = req['da']
    resp['bssid'] = req['bssid']
    resp['payload'] = binascii.unhexlify("030001004c00" + "ffff00")
    hapd.mgmt_tx(resp)

    # Confirm (not received due to DH group being rejected)
    req = hapd.mgmt_rx(timeout=0.5)
    if req is not None:
        if req['subtype'] == 11:
            raise Exception("Unexpected Authentication frame seen")

@remote_compatible
def test_sae_no_random(dev, apdev):
    """SAE and no random numbers available"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups ")
    tests = [ (1, "os_get_random;sae_get_rand"),
              (1, "os_get_random;get_rand_1_to_p_1"),
              (1, "os_get_random;get_random_qr_qnr"),
              (1, "os_get_random;sae_derive_pwe_ecc") ]
    for count, func in tests:
        with fail_test(dev[0], count, func):
            dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                           scan_freq="2412")
            dev[0].request("REMOVE_NETWORK all")
            dev[0].wait_disconnected()

@remote_compatible
def test_sae_pwe_failure(dev, apdev):
    """SAE and pwe failure"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = '19 5'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups 19")
    with fail_test(dev[0], 1, "hmac_sha256_vector;sae_derive_pwe_ecc"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()
    with fail_test(dev[0], 1, "sae_test_pwd_seed_ecc"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()

    dev[0].request("SET sae_groups 5")
    with fail_test(dev[0], 1, "hmac_sha256_vector;sae_derive_pwe_ffc"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()

    dev[0].request("SET sae_groups 5")
    with fail_test(dev[0], 1, "sae_test_pwd_seed_ffc"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()
    with fail_test(dev[0], 2, "sae_test_pwd_seed_ffc"):
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()

@remote_compatible
def test_sae_bignum_failure(dev, apdev):
    """SAE and bignum failure"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_groups'] = '19 5 22'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups 19")
    tests = [ (1, "crypto_bignum_init_set;get_rand_1_to_p_1"),
              (1, "crypto_bignum_init;is_quadratic_residue_blind"),
              (1, "crypto_bignum_mulmod;is_quadratic_residue_blind"),
              (2, "crypto_bignum_mulmod;is_quadratic_residue_blind"),
              (3, "crypto_bignum_mulmod;is_quadratic_residue_blind"),
              (1, "crypto_bignum_legendre;is_quadratic_residue_blind"),
              (1, "crypto_bignum_init_set;sae_test_pwd_seed_ecc"),
              (1, "crypto_ec_point_compute_y_sqr;sae_test_pwd_seed_ecc"),
              (1, "crypto_bignum_init_set;get_random_qr_qnr"),
              (1, "crypto_bignum_to_bin;sae_derive_pwe_ecc"),
              (1, "crypto_ec_point_init;sae_derive_pwe_ecc"),
              (1, "crypto_ec_point_solve_y_coord;sae_derive_pwe_ecc"),
              (1, "crypto_ec_point_init;sae_derive_commit_element_ecc"),
              (1, "crypto_ec_point_mul;sae_derive_commit_element_ecc"),
              (1, "crypto_ec_point_invert;sae_derive_commit_element_ecc"),
              (1, "crypto_bignum_init;=sae_derive_commit"),
              (1, "crypto_ec_point_init;sae_derive_k_ecc"),
              (1, "crypto_ec_point_mul;sae_derive_k_ecc"),
              (1, "crypto_ec_point_add;sae_derive_k_ecc"),
              (2, "crypto_ec_point_mul;sae_derive_k_ecc"),
              (1, "crypto_ec_point_to_bin;sae_derive_k_ecc"),
              (1, "crypto_bignum_legendre;get_random_qr_qnr"),
              (1, "sha256_prf;sae_derive_keys"),
              (1, "crypto_bignum_init;sae_derive_keys"),
              (1, "crypto_bignum_init_set;sae_parse_commit_scalar"),
              (1, "crypto_bignum_to_bin;sae_parse_commit_element_ecc"),
              (1, "crypto_ec_point_from_bin;sae_parse_commit_element_ecc") ]
    for count, func in tests:
        with fail_test(dev[0], count, func):
            dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                           scan_freq="2412", wait_connect=False)
            wait_fail_trigger(dev[0], "GET_FAIL")
            dev[0].request("REMOVE_NETWORK all")

    dev[0].request("SET sae_groups 5")
    tests = [ (1, "crypto_bignum_init_set;sae_set_group"),
              (2, "crypto_bignum_init_set;sae_set_group"),
              (1, "crypto_bignum_init_set;sae_get_rand"),
              (1, "crypto_bignum_init_set;sae_test_pwd_seed_ffc"),
              (1, "crypto_bignum_exptmod;sae_test_pwd_seed_ffc"),
              (1, "crypto_bignum_init;sae_derive_pwe_ffc"),
              (1, "crypto_bignum_init;sae_derive_commit_element_ffc"),
              (1, "crypto_bignum_exptmod;sae_derive_commit_element_ffc"),
              (1, "crypto_bignum_inverse;sae_derive_commit_element_ffc"),
              (1, "crypto_bignum_init;sae_derive_k_ffc"),
              (1, "crypto_bignum_exptmod;sae_derive_k_ffc"),
              (1, "crypto_bignum_mulmod;sae_derive_k_ffc"),
              (2, "crypto_bignum_exptmod;sae_derive_k_ffc"),
              (1, "crypto_bignum_to_bin;sae_derive_k_ffc"),
              (1, "crypto_bignum_init_set;sae_parse_commit_element_ffc"),
              (1, "crypto_bignum_init;sae_parse_commit_element_ffc"),
              (2, "crypto_bignum_init_set;sae_parse_commit_element_ffc"),
              (1, "crypto_bignum_exptmod;sae_parse_commit_element_ffc") ]
    for count, func in tests:
        with fail_test(dev[0], count, func):
            dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                           scan_freq="2412", wait_connect=False)
            wait_fail_trigger(dev[0], "GET_FAIL")
            dev[0].request("REMOVE_NETWORK all")

    dev[0].request("SET sae_groups 22")
    tests = [ (1, "crypto_bignum_init_set;sae_test_pwd_seed_ffc"),
              (1, "crypto_bignum_sub;sae_test_pwd_seed_ffc"),
              (1, "crypto_bignum_div;sae_test_pwd_seed_ffc") ]
    for count, func in tests:
        with fail_test(dev[0], count, func):
            dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                           scan_freq="2412", wait_connect=False)
            wait_fail_trigger(dev[0], "GET_FAIL")
            dev[0].request("REMOVE_NETWORK all")

def test_sae_invalid_anti_clogging_token_req(dev, apdev):
    """SAE and invalid anti-clogging token request"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    # Beacon more frequently since Probe Request frames are practically ignored
    # in this test setup (ext_mgmt_frame_handled=1 on hostapd side) and
    # wpa_supplicant scans may end up getting ignored if no new results are
    # available due to the missing Probe Response frames.
    params['beacon_int'] = '20'
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']

    dev[0].request("SET sae_groups 19")
    dev[0].scan_for_bss(bssid, freq=2412)
    hapd.set("ext_mgmt_frame_handling", "1")
    dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                   scan_freq="2412", wait_connect=False)
    ev = dev[0].wait_event(["SME: Trying to authenticate"])
    if ev is None:
        raise Exception("No authentication attempt seen (1)")
    dev[0].dump_monitor()

    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out (commit)")
        if req['subtype'] == 11:
            break
        req = None
    if not req:
        raise Exception("Authentication frame (commit) not received")

    hapd.dump_monitor()
    resp = {}
    resp['fc'] = req['fc']
    resp['da'] = req['sa']
    resp['sa'] = req['da']
    resp['bssid'] = req['bssid']
    resp['payload'] = binascii.unhexlify("030001004c0013")
    hapd.mgmt_tx(resp)
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Management frame TX status not reported (1)")
    if "stype=11 ok=1" not in ev:
        raise Exception("Unexpected management frame TX status (1): " + ev)

    ev = dev[0].wait_event(["SME: Trying to authenticate"])
    if ev is None:
        raise Exception("No authentication attempt seen (2)")
    dev[0].dump_monitor()

    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out (commit) (2)")
        if req['subtype'] == 11:
            break
        req = None
    if not req:
        raise Exception("Authentication frame (commit) not received (2)")

    hapd.dump_monitor()
    resp = {}
    resp['fc'] = req['fc']
    resp['da'] = req['sa']
    resp['sa'] = req['da']
    resp['bssid'] = req['bssid']
    resp['payload'] = binascii.unhexlify("030001000100")
    hapd.mgmt_tx(resp)
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Management frame TX status not reported (1)")
    if "stype=11 ok=1" not in ev:
        raise Exception("Unexpected management frame TX status (1): " + ev)

    ev = dev[0].wait_event(["SME: Trying to authenticate"])
    if ev is None:
        raise Exception("No authentication attempt seen (3)")
    dev[0].dump_monitor()

    dev[0].request("DISCONNECT")

def test_sae_password(dev, apdev):
    """SAE and sae_password in hostapd configuration"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE WPA-PSK'
    params['sae_password'] = "sae-password"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", psk="sae-password", key_mgmt="SAE",
                   scan_freq="2412")
    dev[1].connect("test-sae", psk="12345678", scan_freq="2412")
    dev[2].request("SET sae_groups ")
    dev[2].connect("test-sae", sae_password="sae-password", key_mgmt="SAE",
                   scan_freq="2412")

def test_sae_password_short(dev, apdev):
    """SAE and short password"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_password'] = "secret"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", sae_password="secret", key_mgmt="SAE",
                   scan_freq="2412")

def test_sae_password_long(dev, apdev):
    """SAE and long password"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae")
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_password'] = 100*"A"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].request("SET sae_groups ")
    dev[0].connect("test-sae", sae_password=100*"A", key_mgmt="SAE",
                   scan_freq="2412")

def test_sae_connect_cmd(dev, apdev):
    """SAE with connect command"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    if "SAE" not in wpas.get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    params = hostapd.wpa2_params(ssid="test-sae", passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

    wpas.request("SET sae_groups ")
    wpas.connect("test-sae", psk="12345678", key_mgmt="SAE",
                 scan_freq="2412", wait_connect=False)
    # mac80211_hwsim does not support SAE offload, so accept both a successful
    # connection and association rejection.
    ev = wpas.wait_event(["CTRL-EVENT-CONNECTED", "CTRL-EVENT-ASSOC-REJECT",
                          "Association request to the driver failed"],
                         timeout=15)
    if ev is None:
        raise Exception("No connection result reported")
