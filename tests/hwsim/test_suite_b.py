# Suite B tests
# Copyright (c) 2014-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hostapd
from utils import HwsimSkip, fail_test

def check_suite_b_capa(dev):
    if "GCMP" not in dev[0].get_capability("pairwise"):
        raise HwsimSkip("GCMP not supported")
    if "BIP-GMAC-128" not in dev[0].get_capability("group_mgmt"):
        raise HwsimSkip("BIP-GMAC-128 not supported")
    if "WPA-EAP-SUITE-B" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("WPA-EAP-SUITE-B not supported")
    check_suite_b_tls_lib(dev)

def check_suite_b_tls_lib(dev):
    tls = dev[0].request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("TLS library not supported for Suite B: " + tls)
    supported = False
    for ver in [ '1.0.2', '1.1.0' ]:
        if "build=OpenSSL " + ver in tls and "run=OpenSSL " + ver in tls:
            supported = True
            break
    if not supported:
        raise HwsimSkip("OpenSSL version not supported for Suite B: " + tls)

def suite_b_ap_params():
    params = { "ssid": "test-suite-b",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-EAP-SUITE-B",
               "rsn_pairwise": "GCMP",
               "group_mgmt_cipher": "BIP-GMAC-128",
               "ieee80211w": "2",
               "ieee8021x": "1",
               "openssl_ciphers": "SUITEB128",
               #"dh_file": "auth_serv/dh.conf",
               "eap_server": "1",
               "eap_user_file": "auth_serv/eap_user.conf",
               "ca_cert": "auth_serv/ec-ca.pem",
               "server_cert": "auth_serv/ec-server.pem",
               "private_key": "auth_serv/ec-server.key" }
    return params

def test_suite_b(dev, apdev):
    """WPA2/GCMP connection at Suite B 128-bit level"""
    check_suite_b_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B", ieee80211w="2",
                   openssl_ciphers="SUITEB128",
                   eap="TLS", identity="tls user",
                   ca_cert="auth_serv/ec-ca.pem",
                   client_cert="auth_serv/ec-user.pem",
                   private_key="auth_serv/ec-user.key",
                   pairwise="GCMP", group="GCMP", scan_freq="2412")
    tls_cipher = dev[0].get_status_field("EAP TLS cipher")
    if tls_cipher != "ECDHE-ECDSA-AES128-GCM-SHA256":
        raise Exception("Unexpected TLS cipher: " + tls_cipher)

    bss = dev[0].get_bss(apdev[0]['bssid'])
    if 'flags' not in bss:
        raise Exception("Could not get BSS flags from BSS table")
    if "[WPA2-EAP-SUITE-B-GCMP]" not in bss['flags']:
        raise Exception("Unexpected BSS flags: " + bss['flags'])

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=20)
    dev[0].dump_monitor()
    dev[0].request("RECONNECT")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=20)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")

    conf = hapd.get_config()
    if conf['key_mgmt'] != 'WPA-EAP-SUITE-B':
        raise Exception("Unexpected config key_mgmt: " + conf['key_mgmt'])

def suite_b_as_params():
    params = {}
    params['ssid'] = 'as'
    params['beacon_int'] = '2000'
    params['radius_server_clients'] = 'auth_serv/radius_clients.conf'
    params['radius_server_auth_port'] = '18129'
    params['eap_server'] = '1'
    params['eap_user_file'] = 'auth_serv/eap_user.conf'
    params['ca_cert'] = 'auth_serv/ec-ca.pem'
    params['server_cert'] = 'auth_serv/ec-server.pem'
    params['private_key'] = 'auth_serv/ec-server.key'
    params['openssl_ciphers'] = 'SUITEB128'
    return params

def test_suite_b_radius(dev, apdev):
    """WPA2/GCMP (RADIUS) connection at Suite B 128-bit level"""
    check_suite_b_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_as_params()
    hostapd.add_ap(apdev[1], params)

    params = { "ssid": "test-suite-b",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-EAP-SUITE-B",
               "rsn_pairwise": "GCMP",
               "group_mgmt_cipher": "BIP-GMAC-128",
               "ieee80211w": "2",
               "ieee8021x": "1",
               'auth_server_addr': "127.0.0.1",
               'auth_server_port': "18129",
               'auth_server_shared_secret': "radius",
               'nas_identifier': "nas.w1.fi" }
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B", ieee80211w="2",
                   openssl_ciphers="SUITEB128",
                   eap="TLS", identity="tls user",
                   ca_cert="auth_serv/ec-ca.pem",
                   client_cert="auth_serv/ec-user.pem",
                   private_key="auth_serv/ec-user.key",
                   pairwise="GCMP", group="GCMP", scan_freq="2412")

def check_suite_b_192_capa(dev):
    if "GCMP-256" not in dev[0].get_capability("pairwise"):
        raise HwsimSkip("GCMP-256 not supported")
    if "BIP-GMAC-256" not in dev[0].get_capability("group_mgmt"):
        raise HwsimSkip("BIP-GMAC-256 not supported")
    if "WPA-EAP-SUITE-B-192" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("WPA-EAP-SUITE-B-192 not supported")
    check_suite_b_tls_lib(dev)

def suite_b_192_ap_params():
    params = { "ssid": "test-suite-b",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-EAP-SUITE-B-192",
               "rsn_pairwise": "GCMP-256",
               "group_mgmt_cipher": "BIP-GMAC-256",
               "ieee80211w": "2",
               "ieee8021x": "1",
               "openssl_ciphers": "SUITEB192",
               "eap_server": "1",
               "eap_user_file": "auth_serv/eap_user.conf",
               "ca_cert": "auth_serv/ec2-ca.pem",
               "server_cert": "auth_serv/ec2-server.pem",
               "private_key": "auth_serv/ec2-server.key" }
    return params

def test_suite_b_192(dev, apdev):
    """WPA2/GCMP-256 connection at Suite B 192-bit level"""
    check_suite_b_192_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_192_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                   ieee80211w="2",
                   openssl_ciphers="SUITEB192",
                   eap="TLS", identity="tls user",
                   ca_cert="auth_serv/ec2-ca.pem",
                   client_cert="auth_serv/ec2-user.pem",
                   private_key="auth_serv/ec2-user.key",
                   pairwise="GCMP-256", group="GCMP-256", scan_freq="2412")
    tls_cipher = dev[0].get_status_field("EAP TLS cipher")
    if tls_cipher != "ECDHE-ECDSA-AES256-GCM-SHA384":
        raise Exception("Unexpected TLS cipher: " + tls_cipher)
    cipher = dev[0].get_status_field("mgmt_group_cipher")
    if cipher != "BIP-GMAC-256":
        raise Exception("Unexpected mgmt_group_cipher: " + cipher)

    bss = dev[0].get_bss(apdev[0]['bssid'])
    if 'flags' not in bss:
        raise Exception("Could not get BSS flags from BSS table")
    if "[WPA2-EAP-SUITE-B-192-GCMP-256]" not in bss['flags']:
        raise Exception("Unexpected BSS flags: " + bss['flags'])

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=20)
    dev[0].dump_monitor()
    dev[0].request("RECONNECT")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=20)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")

    conf = hapd.get_config()
    if conf['key_mgmt'] != 'WPA-EAP-SUITE-B-192':
        raise Exception("Unexpected config key_mgmt: " + conf['key_mgmt'])

def test_suite_b_192_radius(dev, apdev):
    """WPA2/GCMP-256 (RADIUS) connection at Suite B 192-bit level"""
    check_suite_b_192_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_as_params()
    params['ca_cert'] = 'auth_serv/ec2-ca.pem'
    params['server_cert'] = 'auth_serv/ec2-server.pem'
    params['private_key'] = 'auth_serv/ec2-server.key'
    params['openssl_ciphers'] = 'SUITEB192'
    hostapd.add_ap(apdev[1], params)

    params = { "ssid": "test-suite-b",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-EAP-SUITE-B-192",
               "rsn_pairwise": "GCMP-256",
               "group_mgmt_cipher": "BIP-GMAC-256",
               "ieee80211w": "2",
               "ieee8021x": "1",
               'auth_server_addr': "127.0.0.1",
               'auth_server_port': "18129",
               'auth_server_shared_secret': "radius",
               'nas_identifier': "nas.w1.fi" }
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                   ieee80211w="2",
                   openssl_ciphers="SUITEB192",
                   eap="TLS", identity="tls user",
                   ca_cert="auth_serv/ec2-ca.pem",
                   client_cert="auth_serv/ec2-user.pem",
                   private_key="auth_serv/ec2-user.key",
                   pairwise="GCMP-256", group="GCMP-256", scan_freq="2412")

def test_suite_b_pmkid_failure(dev, apdev):
    """WPA2/GCMP connection at Suite B 128-bit level and PMKID derivation failure"""
    check_suite_b_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)

    with fail_test(dev[0], 1, "rsn_pmkid_suite_b"):
        dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B",
                       ieee80211w="2",
                       openssl_ciphers="SUITEB128",
                       eap="TLS", identity="tls user",
                       ca_cert="auth_serv/ec-ca.pem",
                       client_cert="auth_serv/ec-user.pem",
                       private_key="auth_serv/ec-user.key",
                       pairwise="GCMP", group="GCMP", scan_freq="2412")

def test_suite_b_192_pmkid_failure(dev, apdev):
    """WPA2/GCMP-256 connection at Suite B 192-bit level and PMKID derivation failure"""
    check_suite_b_192_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_192_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)

    with fail_test(dev[0], 1, "rsn_pmkid_suite_b"):
        dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                       ieee80211w="2",
                       openssl_ciphers="SUITEB192",
                       eap="TLS", identity="tls user",
                       ca_cert="auth_serv/ec2-ca.pem",
                       client_cert="auth_serv/ec2-user.pem",
                       private_key="auth_serv/ec2-user.key",
                       pairwise="GCMP-256", group="GCMP-256", scan_freq="2412")

def test_suite_b_mic_failure(dev, apdev):
    """WPA2/GCMP connection at Suite B 128-bit level and MIC derivation failure"""
    check_suite_b_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)

    with fail_test(dev[0], 1, "wpa_eapol_key_mic"):
        dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B",
                       ieee80211w="2",
                       openssl_ciphers="SUITEB128",
                       eap="TLS", identity="tls user",
                       ca_cert="auth_serv/ec-ca.pem",
                       client_cert="auth_serv/ec-user.pem",
                       private_key="auth_serv/ec-user.key",
                       pairwise="GCMP", group="GCMP", scan_freq="2412",
                       wait_connect=False)
        dev[0].wait_disconnected()

def test_suite_b_192_mic_failure(dev, apdev):
    """WPA2/GCMP connection at Suite B 192-bit level and MIC derivation failure"""
    check_suite_b_192_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_192_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)

    with fail_test(dev[0], 1, "wpa_eapol_key_mic"):
        dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                       ieee80211w="2",
                       openssl_ciphers="SUITEB192",
                       eap="TLS", identity="tls user",
                       ca_cert="auth_serv/ec2-ca.pem",
                       client_cert="auth_serv/ec2-user.pem",
                       private_key="auth_serv/ec2-user.key",
                       pairwise="GCMP-256", group="GCMP-256", scan_freq="2412",
                       wait_connect=False)
        dev[0].wait_disconnected()

def suite_b_192_rsa_ap_params():
    params = { "ssid": "test-suite-b",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-EAP-SUITE-B-192",
               "rsn_pairwise": "GCMP-256",
               "group_mgmt_cipher": "BIP-GMAC-256",
               "ieee80211w": "2",
               "ieee8021x": "1",
               "tls_flags": "[SUITEB]",
               "dh_file": "auth_serv/dh_param_3072.pem",
               "eap_server": "1",
               "eap_user_file": "auth_serv/eap_user.conf",
               "ca_cert": "auth_serv/rsa3072-ca.pem",
               "server_cert": "auth_serv/rsa3072-server.pem",
               "private_key": "auth_serv/rsa3072-server.key" }
    return params

def test_suite_b_192_rsa(dev, apdev):
    """WPA2/GCMP-256 connection at Suite B 192-bit level and RSA"""
    run_suite_b_192_rsa(dev, apdev)

def test_suite_b_192_rsa_ecdhe(dev, apdev):
    """WPA2/GCMP-256 connection at Suite B 192-bit level and RSA (ECDHE)"""
    run_suite_b_192_rsa(dev, apdev, no_dhe=True)

def test_suite_b_192_rsa_dhe(dev, apdev):
    """WPA2/GCMP-256 connection at Suite B 192-bit level and RSA (DHE)"""
    run_suite_b_192_rsa(dev, apdev, no_ecdh=True)

def run_suite_b_192_rsa(dev, apdev, no_ecdh=False, no_dhe=False):
    check_suite_b_192_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_192_rsa_ap_params()
    if no_ecdh:
        params["tls_flags"] = "[SUITEB-NO-ECDH]"
    if no_dhe:
        del params["dh_file"]
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                   ieee80211w="2",
                   phase1="tls_suiteb=1",
                   eap="TLS", identity="tls user",
                   ca_cert="auth_serv/rsa3072-ca.pem",
                   client_cert="auth_serv/rsa3072-user.pem",
                   private_key="auth_serv/rsa3072-user.key",
                   pairwise="GCMP-256", group="GCMP-256", scan_freq="2412")
    tls_cipher = dev[0].get_status_field("EAP TLS cipher")
    if tls_cipher != "ECDHE-RSA-AES256-GCM-SHA384" and tls_cipher != "DHE-RSA-AES256-GCM-SHA384":
        raise Exception("Unexpected TLS cipher: " + tls_cipher)
    cipher = dev[0].get_status_field("mgmt_group_cipher")
    if cipher != "BIP-GMAC-256":
        raise Exception("Unexpected mgmt_group_cipher: " + cipher)

    bss = dev[0].get_bss(apdev[0]['bssid'])
    if 'flags' not in bss:
        raise Exception("Could not get BSS flags from BSS table")
    if "[WPA2-EAP-SUITE-B-192-GCMP-256]" not in bss['flags']:
        raise Exception("Unexpected BSS flags: " + bss['flags'])

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=20)
    dev[0].dump_monitor()
    dev[0].request("RECONNECT")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=20)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")

    conf = hapd.get_config()
    if conf['key_mgmt'] != 'WPA-EAP-SUITE-B-192':
        raise Exception("Unexpected config key_mgmt: " + conf['key_mgmt'])

def test_suite_b_192_rsa_insufficient_key(dev, apdev):
    """WPA2/GCMP-256 connection at Suite B 192-bit level and RSA with insufficient key length"""
    check_suite_b_192_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_192_rsa_ap_params()
    params["ca_cert"] = "auth_serv/ca.pem"
    params["server_cert"] = "auth_serv/server.pem"
    params["private_key"] = "auth_serv/server.key"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                   ieee80211w="2",
                   phase1="tls_suiteb=1",
                   eap="TLS", identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   pairwise="GCMP-256", group="GCMP-256", scan_freq="2412",
                   wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR"], timeout=10)
    dev[0].request("DISCONNECT")
    if ev is None:
        raise Exception("Certificate error not reported")
    if "reason=11" not in ev or "err='Insufficient RSA modulus size'" not in ev:
        raise Exception("Unexpected error reason: " + ev)

def test_suite_b_192_rsa_insufficient_dh(dev, apdev):
    """WPA2/GCMP-256 connection at Suite B 192-bit level and RSA with insufficient DH key length"""
    check_suite_b_192_capa(dev)
    dev[0].flush_scan_cache()
    params = suite_b_192_rsa_ap_params()
    params["tls_flags"] = "[SUITEB-NO-ECDH]"
    params["dh_file"] = "auth_serv/dh.conf"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                   ieee80211w="2",
                   phase1="tls_suiteb=1",
                   eap="TLS", identity="tls user",
                   ca_cert="auth_serv/rsa3072-ca.pem",
                   client_cert="auth_serv/rsa3072-user.pem",
                   private_key="auth_serv/rsa3072-user.key",
                   pairwise="GCMP-256", group="GCMP-256", scan_freq="2412",
                   wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STATUS status='local TLS alert'"],
                           timeout=10)
    dev[0].request("DISCONNECT")
    if ev is None:
        raise Exception("DH error not reported")
    if "insufficient security" not in ev and "internal error" not in ev:
        raise Exception("Unexpected error reason: " + ev)
