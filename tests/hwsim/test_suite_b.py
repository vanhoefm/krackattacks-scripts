# Suite B tests
# Copyright (c) 2014-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hostapd
from utils import HwsimSkip

def test_suite_b(dev, apdev):
    """WPA2-PSK/GCMP connection at Suite B 128-bit level"""
    if "GCMP" not in dev[0].get_capability("pairwise"):
        raise HwsimSkip("GCMP not supported")
    if "BIP-GMAC-128" not in dev[0].get_capability("group_mgmt"):
        raise HwsimSkip("BIP-GMAC-128 not supported")
    if "WPA-EAP-SUITE-B" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("WPA-EAP-SUITE-B not supported")
    tls = dev[0].request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("TLS library not supported for Suite B: " + tls);
    if "build=OpenSSL 1.0.2" not in tls or "run=OpenSSL 1.0.2" not in tls:
        raise HwsimSkip("OpenSSL version not supported for Suite B: " + tls)

    dev[0].flush_scan_cache()
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
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

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

def test_suite_b_192(dev, apdev):
    """WPA2-PSK/GCMP-256 connection at Suite B 192-bit level"""
    if "GCMP-256" not in dev[0].get_capability("pairwise"):
        raise HwsimSkip("GCMP-256 not supported")
    if "BIP-GMAC-256" not in dev[0].get_capability("group_mgmt"):
        raise HwsimSkip("BIP-GMAC-256 not supported")
    if "WPA-EAP-SUITE-B-192" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("WPA-EAP-SUITE-B-192 not supported")
    tls = dev[0].request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("TLS library not supported for Suite B: " + tls);
    if "build=OpenSSL 1.0.2" not in tls or "run=OpenSSL 1.0.2" not in tls:
        raise HwsimSkip("OpenSSL version not supported for Suite B: " + tls)

    dev[0].flush_scan_cache()
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
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

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
