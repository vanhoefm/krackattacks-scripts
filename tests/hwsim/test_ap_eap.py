#!/usr/bin/python
#
# WPA2-Enterprise tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()
import os.path

import hwsim_utils
import hostapd

def eap_connect(dev, method, identity, anonymous_identity=None, password=None,
                phase1=None, phase2=None, ca_cert=None,
                domain_suffix_match=None, password_hex=None,
                client_cert=None, private_key=None):
    dev.connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap=method,
                identity=identity, anonymous_identity=anonymous_identity,
                password=password, phase1=phase1, phase2=phase2,
                ca_cert=ca_cert, domain_suffix_match=domain_suffix_match,
                wait_connect=False, scan_freq="2412", password_hex=password_hex,
                client_cert=client_cert, private_key=private_key)
    ev = dev.wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")
    ev = dev.wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
    if ev is None:
        raise Exception("EAP method selection timed out")
    if method not in ev:
        raise Exception("Unexpected EAP method")
    ev = dev.wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("EAP success timed out")
    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Association with the AP timed out")

    status = dev.get_status()
    if status["wpa_state"] != "COMPLETED":
        raise Exception("Connection not completed")
    if status["suppPortStatus"] != "Authorized":
        raise Exception("Port not authorized")
    if method not in status["selectedMethod"]:
        raise Exception("Incorrect EAP method status")
    if status["key_mgmt"] != "WPA2/IEEE 802.1X/EAP":
        raise Exception("Unexpected key_mgmt status")

def test_ap_wpa2_eap_sim(dev, apdev):
    """WPA2-Enterprise connection using EAP-SIM"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_aka(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_aka_prime(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA'"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_pap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_chap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=CHAP")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_mschap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "mschap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                domain_suffix_match="server.w1.fi")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                domain_suffix_match="w1.fi")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_eap_gtc(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-GTC"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=GTC")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_eap_md5(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MD5"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MD5")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_peap_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAP/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "PEAP", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_tls(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TLS", "tls user", ca_cert="auth_serv/ca.pem",
                client_cert="auth_serv/user.pem",
                private_key="auth_serv/user.key")

def test_ap_wpa2_eap_tls_neg_incorrect_trust_root(dev, apdev):
    """WPA2-Enterprise negative test - incorrect trust root"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca-incorrect.pem",
                   wait_connect=False, scan_freq="2412")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
    if ev is None:
        raise Exception("EAP method selection timed out")
    if "TTLS" not in ev:
        raise Exception("Unexpected EAP method")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR",
                            "CTRL-EVENT-EAP-SUCCESS",
                            "CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("EAP result timed out")
    if "CTRL-EVENT-EAP-TLS-CERT-ERROR" not in ev:
        raise Exception("TLS certificate error not reported")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS",
                            "CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("EAP result(2) timed out")
    if "CTRL-EVENT-EAP-FAILURE" not in ev:
        raise Exception("EAP failure not reported")

    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("EAP result(3) timed out")
    if "CTRL-EVENT-DISCONNECTED" not in ev:
        raise Exception("Disconnection not reported")

    ev = dev[0].wait_event(["CTRL-EVENT-SSID-TEMP-DISABLED"], timeout=10)
    if ev is None:
        raise Exception("Network block disabling not reported")

def test_ap_wpa2_eap_tls_neg_suffix_match(dev, apdev):
    """WPA2-Enterprise negative test - domain suffix mismatch"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   domain_suffix_match="incorrect.example.com",
                   wait_connect=False, scan_freq="2412")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
    if ev is None:
        raise Exception("EAP method selection timed out")
    if "TTLS" not in ev:
        raise Exception("Unexpected EAP method")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR",
                            "CTRL-EVENT-EAP-SUCCESS",
                            "CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("EAP result timed out")
    if "CTRL-EVENT-EAP-TLS-CERT-ERROR" not in ev:
        raise Exception("TLS certificate error not reported")
    if "Domain suffix mismatch" not in ev:
        raise Exception("Domain suffix mismatch not reported")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS",
                            "CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("EAP result(2) timed out")
    if "CTRL-EVENT-EAP-FAILURE" not in ev:
        raise Exception("EAP failure not reported")

    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("EAP result(3) timed out")
    if "CTRL-EVENT-DISCONNECTED" not in ev:
        raise Exception("Disconnection not reported")

    ev = dev[0].wait_event(["CTRL-EVENT-SSID-TEMP-DISABLED"], timeout=10)
    if ev is None:
        raise Exception("Network block disabling not reported")

def test_ap_wpa2_eap_pwd(dev, apdev):
    """WPA2-Enterprise connection using EAP-pwd"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "PWD", "pwd user", password="secret password")

def test_ap_wpa2_eap_gpsk(dev, apdev):
    """WPA2-Enterprise connection using EAP-GPSK"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "GPSK", "gpsk user",
                password="abcdefghijklmnop0123456789abcdef")

def test_ap_wpa2_eap_sake(dev, apdev):
    """WPA2-Enterprise connection using EAP-SAKE"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "SAKE", "sake user",
                password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

def test_ap_wpa2_eap_eke(dev, apdev):
    """WPA2-Enterprise connection using EAP-EKE"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "EKE", "eke user", password="hello")

def test_ap_wpa2_eap_ikev2(dev, apdev):
    """WPA2-Enterprise connection using EAP-IKEv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "IKEV2", "ikev2 user", password="ike password")

def test_ap_wpa2_eap_pax(dev, apdev):
    """WPA2-Enterprise connection using EAP-PAX"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "PAX", "pax.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef")

def test_ap_wpa2_eap_psk(dev, apdev):
    """WPA2-Enterprise connection using EAP-PSK"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "PSK", "psk.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef")
