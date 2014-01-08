#!/usr/bin/python
#
# WPA2-Enterprise tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
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

def eap_connect(dev, ap, method, identity, anonymous_identity=None,
                password=None,
                phase1=None, phase2=None, ca_cert=None,
                domain_suffix_match=None, password_hex=None,
                client_cert=None, private_key=None, sha256=False,
                fragment_size=None, expect_failure=False,
                local_error_report=False,
                ca_cert2=None, client_cert2=None, private_key2=None,
                pac_file=None, subject_match=None, altsubject_match=None,
                private_key_passwd=None, ocsp=None):
    hapd = hostapd.Hostapd(ap['ifname'])
    id = dev.connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                     eap=method, identity=identity,
                     anonymous_identity=anonymous_identity,
                     password=password, phase1=phase1, phase2=phase2,
                     ca_cert=ca_cert, domain_suffix_match=domain_suffix_match,
                     wait_connect=False, scan_freq="2412",
                     password_hex=password_hex,
                     client_cert=client_cert, private_key=private_key,
                     ieee80211w="1", fragment_size=fragment_size,
                     ca_cert2=ca_cert2, client_cert2=client_cert2,
                     private_key2=private_key2, pac_file=pac_file,
                     subject_match=subject_match,
                     altsubject_match=altsubject_match,
                     private_key_passwd=private_key_passwd,
                     ocsp=ocsp)
    eap_check_auth(dev, method, True, sha256=sha256,
                   expect_failure=expect_failure,
                   local_error_report=local_error_report)
    if expect_failure:
        return id
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    return id

def eap_check_auth(dev, method, initial, rsn=True, sha256=False,
                   expect_failure=False, local_error_report=False):
    ev = dev.wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")
    ev = dev.wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
    if ev is None:
        raise Exception("EAP method selection timed out")
    if method not in ev:
        raise Exception("Unexpected EAP method")
    if expect_failure:
        ev = dev.wait_event(["CTRL-EVENT-EAP-FAILURE"])
        if ev is None:
            raise Exception("EAP failure timed out")
        ev = dev.wait_event(["CTRL-EVENT-DISCONNECTED"])
        if ev is None:
            raise Exception("Disconnection timed out")
        if not local_error_report:
            if "reason=23" not in ev:
                raise Exception("Proper reason code for disconnection not reported")
        return
    ev = dev.wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("EAP success timed out")

    if initial:
        ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    else:
        ev = dev.wait_event(["WPA: Key negotiation completed"], timeout=10)
    if ev is None:
        raise Exception("Association with the AP timed out")
    status = dev.get_status()
    if status["wpa_state"] != "COMPLETED":
        raise Exception("Connection not completed")

    if status["suppPortStatus"] != "Authorized":
        raise Exception("Port not authorized")
    if method not in status["selectedMethod"]:
        raise Exception("Incorrect EAP method status")
    if sha256:
        e = "WPA2-EAP-SHA256"
    elif rsn:
        e = "WPA2/IEEE 802.1X/EAP"
    else:
        e = "WPA/IEEE 802.1X/EAP"
    if status["key_mgmt"] != e:
        raise Exception("Unexpected key_mgmt status: " + status["key_mgmt"])

def eap_reauth(dev, method, rsn=True, sha256=False):
    dev.request("REAUTHENTICATE")
    eap_check_auth(dev, method, False, rsn=rsn, sha256=sha256)

def test_ap_wpa2_eap_sim(dev, apdev):
    """WPA2-Enterprise connection using EAP-SIM"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "SIM")

    logger.info("Negative test with incorrect key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                expect_failure=True)

def test_ap_wpa2_eap_aka(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "AKA")

    logger.info("Negative test with incorrect key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                expect_failure=True)

def test_ap_wpa2_eap_aka_prime(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA'"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "AKA'")

    logger.info("Negative test with incorrect key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="ff22250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_pap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                subject_match="/C=FI/O=w1.fi/CN=server.w1.fi",
                altsubject_match="EMAIL:noone@example.com;DNS:server.w1.fi;URI:http://example.com/")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_chap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.der", phase2="auth=CHAP")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_mschap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "mschap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                domain_suffix_match="server.w1.fi")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "TTLS")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "TTLS", "mschap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                fragment_size="200")

def test_ap_wpa2_eap_ttls_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                domain_suffix_match="w1.fi")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    sta1 = hapd.get_sta(dev[0].p2p_interface_addr())
    eapol1 = hapd.get_sta(dev[0].p2p_interface_addr(), info="eapol")
    eap_reauth(dev[0], "TTLS")
    sta2 = hapd.get_sta(dev[0].p2p_interface_addr())
    eapol2 = hapd.get_sta(dev[0].p2p_interface_addr(), info="eapol")
    if int(sta2['dot1xAuthEapolFramesRx']) <= int(sta1['dot1xAuthEapolFramesRx']):
        raise Exception("dot1xAuthEapolFramesRx did not increase")
    if int(eapol2['authAuthEapStartsWhileAuthenticated']) < 1:
        raise Exception("authAuthEapStartsWhileAuthenticated did not increase")
    if int(eapol2['backendAuthSuccesses']) <= int(eapol1['backendAuthSuccesses']):
        raise Exception("backendAuthSuccesses did not increase")

    logger.info("Password as hash value")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls",
                password_hex="hash:8846f7eaee8fb117ad06bdd830b7586c",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password1",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_eap_gtc(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-GTC"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=GTC")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_eap_md5(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MD5"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MD5")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "TTLS")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password1",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2",
                expect_failure=True)

def test_ap_wpa2_eap_peap_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAP/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "user",
                anonymous_identity="peap", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "PEAP")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PEAP", "user",
                anonymous_identity="peap", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                fragment_size="200")

    logger.info("Password as hash value")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PEAP", "user",
                anonymous_identity="peap",
                password_hex="hash:8846f7eaee8fb117ad06bdd830b7586c",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PEAP", "user",
                anonymous_identity="peap", password="password1",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_ap_wpa2_eap_peap_crypto_binding(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAPv0/EAP-MSCHAPv2 and crypto binding"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "user", password="password",
                ca_cert="auth_serv/ca.pem",
                phase1="peapver=0 crypto_binding=2",
                phase2="auth=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "PEAP")

def test_ap_wpa2_eap_peap_eap_tls(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAP/EAP-TLS"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "cert user",
                ca_cert="auth_serv/ca.pem", phase2="auth=TLS",
                ca_cert2="auth_serv/ca.pem",
                client_cert2="auth_serv/user.pem",
                private_key2="auth_serv/user.key")
    eap_reauth(dev[0], "PEAP")

def test_ap_wpa2_eap_tls(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TLS", "tls user", ca_cert="auth_serv/ca.pem",
                client_cert="auth_serv/user.pem",
                private_key="auth_serv/user.key")
    eap_reauth(dev[0], "TLS")

def test_ap_wpa2_eap_tls_pkcs12(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS and PKCS#12"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TLS", "tls user", ca_cert="auth_serv/ca.pem",
                private_key="auth_serv/user.pkcs12",
                private_key_passwd="whatever")
    dev[0].request("REMOVE_NETWORK all")
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-PASSPHRASE"])
    if ev is None:
        raise Exception("Request for private key passphrase timed out")
    id = ev.split(':')[0].split('-')[-1]
    dev[0].request("CTRL-RSP-PASSPHRASE-" + id + ":whatever")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection timed out")

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

def test_ap_wpa2_eap_tls_neg_subject_match(dev, apdev):
    """WPA2-Enterprise negative test - subject mismatch"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   subject_match="/C=FI/O=w1.fi/CN=example.com",
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
    if "Subject mismatch" not in ev:
        raise Exception("Subject mismatch not reported")

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

def test_ap_wpa2_eap_tls_neg_altsubject_match(dev, apdev):
    """WPA2-Enterprise negative test - altsubject mismatch"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   altsubject_match="incorrect.example.com",
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
    if "AltSubject mismatch" not in ev:
        raise Exception("altsubject mismatch not reported")

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

def test_ap_wpa2_eap_ttls_server_cert_hash(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS and server certificate hash"""
    srv_cert_hash = "0a3f81f63569226657a069855bb13f3b922670437a2b87585a4734f70ac7315b"
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="probe", ca_cert="probe://",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-PEER-CERT depth=0"], timeout=10)
    if ev is None:
        raise Exception("No peer server certificate event seen")
    if "hash=" + srv_cert_hash not in ev:
        raise Exception("Expected server certificate hash not reported")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR"], timeout=10)
    if ev is None:
        raise Exception("EAP result timed out")
    if "Server certificate chain probe" not in ev:
        raise Exception("Server certificate probe not reported")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Disconnection event not seen")
    dev[0].request("REMOVE_NETWORK all")

    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="hash://server/sha256/5a1bc1296205e6fdbe3979728efe3920798885c1c4590b5f90f43222d239ca6a",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR"], timeout=10)
    if ev is None:
        raise Exception("EAP result timed out")
    if "Server certificate mismatch" not in ev:
        raise Exception("Server certificate mismatch not reported")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Disconnection event not seen")
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password",
                ca_cert="hash://server/sha256/" + srv_cert_hash,
                phase2="auth=MSCHAPV2")

def test_ap_wpa2_eap_pwd(dev, apdev):
    """WPA2-Enterprise connection using EAP-pwd"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PWD", "pwd user", password="secret password")
    eap_reauth(dev[0], "PWD")

    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PWD", "pwd user", password="secret password",
                fragment_size="90")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PWD", "pwd user", password="secret-password",
                expect_failure=True, local_error_report=True)

def test_ap_wpa2_eap_pwd_groups(dev, apdev):
    """WPA2-Enterprise connection using various EAP-pwd groups"""
    params = { "ssid": "test-wpa2-eap", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
               "rsn_pairwise": "CCMP", "ieee8021x": "1",
               "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf" }
    for i in [ 19, 20, 21, 25, 26 ]:
        params['pwd_group'] = str(i)
        hostapd.add_ap(apdev[0]['ifname'], params)
        dev[0].request("REMOVE_NETWORK all")
        eap_connect(dev[0], apdev[0], "PWD", "pwd user", password="secret password")

def test_ap_wpa2_eap_gpsk(dev, apdev):
    """WPA2-Enterprise connection using EAP-GPSK"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    id = eap_connect(dev[0], apdev[0], "GPSK", "gpsk user",
                     password="abcdefghijklmnop0123456789abcdef")
    eap_reauth(dev[0], "GPSK")

    logger.info("Test forced algorithm selection")
    for phase1 in [ "cipher=1", "cipher=2" ]:
        dev[0].set_network_quoted(id, "phase1", phase1)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
        if ev is None:
            raise Exception("EAP success timed out")
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Association with the AP timed out")

    logger.info("Test failed algorithm negotiation")
    dev[0].set_network_quoted(id, "phase1", "cipher=9")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("EAP failure timed out")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "GPSK", "gpsk user",
                password="ffcdefghijklmnop0123456789abcdef",
                expect_failure=True)

def test_ap_wpa2_eap_sake(dev, apdev):
    """WPA2-Enterprise connection using EAP-SAKE"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "SAKE", "sake user",
                password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    eap_reauth(dev[0], "SAKE")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SAKE", "sake user",
                password_hex="ff23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                expect_failure=True)

def test_ap_wpa2_eap_eke(dev, apdev):
    """WPA2-Enterprise connection using EAP-EKE"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    id = eap_connect(dev[0], apdev[0], "EKE", "eke user", password="hello")
    eap_reauth(dev[0], "EKE")

    logger.info("Test forced algorithm selection")
    for phase1 in [ "dhgroup=5 encr=1 prf=2 mac=2",
                    "dhgroup=4 encr=1 prf=2 mac=2",
                    "dhgroup=3 encr=1 prf=2 mac=2",
                    "dhgroup=3 encr=1 prf=1 mac=1" ]:
        dev[0].set_network_quoted(id, "phase1", phase1)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
        if ev is None:
            raise Exception("EAP success timed out")
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Association with the AP timed out")

    logger.info("Test failed algorithm negotiation")
    dev[0].set_network_quoted(id, "phase1", "dhgroup=9 encr=9 prf=9 mac=9")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("EAP failure timed out")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "EKE", "eke user", password="hello1",
                expect_failure=True)

def test_ap_wpa2_eap_ikev2(dev, apdev):
    """WPA2-Enterprise connection using EAP-IKEv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "IKEV2", "ikev2 user",
                password="ike password")
    eap_reauth(dev[0], "IKEV2")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "IKEV2", "ikev2 user",
                password="ike password", fragment_size="250")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "IKEV2", "ikev2 user",
                password="ike-password", expect_failure=True)

def test_ap_wpa2_eap_pax(dev, apdev):
    """WPA2-Enterprise connection using EAP-PAX"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PAX", "pax.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef")
    eap_reauth(dev[0], "PAX")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PAX", "pax.user@example.com",
                password_hex="ff23456789abcdef0123456789abcdef",
                expect_failure=True)

def test_ap_wpa2_eap_psk(dev, apdev):
    """WPA2-Enterprise connection using EAP-PSK"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["ieee80211w"] = "2"
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PSK", "psk.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef", sha256=True)
    eap_reauth(dev[0], "PSK", sha256=True)

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PSK", "psk.user@example.com",
                password_hex="ff23456789abcdef0123456789abcdef", sha256=True,
                expect_failure=True)

def test_ap_wpa_eap_peap_eap_mschapv2(dev, apdev):
    """WPA-Enterprise connection using EAP-PEAP/EAP-MSCHAPv2"""
    params = hostapd.wpa_eap_params(ssid="test-wpa-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa-eap", key_mgmt="WPA-EAP", eap="PEAP",
                   identity="user", password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem", wait_connect=False,
                   scan_freq="2412")
    eap_check_auth(dev[0], "PEAP", True, rsn=False)
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "PEAP", rsn=False)

def test_ap_wpa2_eap_interactive(dev, apdev):
    """WPA2-Enterprise connection using interactive identity/password entry"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])

    tests = [ ("Connection with dynamic TTLS/MSCHAPv2 password entry",
               "TTLS", "ttls", "DOMAIN\mschapv2 user", "auth=MSCHAPV2",
               None, "password"),
              ("Connection with dynamic TTLS/MSCHAPv2 identity and password entry",
               "TTLS", "ttls", None, "auth=MSCHAPV2",
               "DOMAIN\mschapv2 user", "password"),
              ("Connection with dynamic TTLS/EAP-MSCHAPv2 password entry",
               "TTLS", "ttls", "user", "autheap=MSCHAPV2", None, "password"),
              ("Connection with dynamic TTLS/EAP-MD5 password entry",
               "TTLS", "ttls", "user", "autheap=MD5", None, "password"),
              ("Connection with dynamic PEAP/EAP-MSCHAPv2 password entry",
               "PEAP", None, "user", "auth=MSCHAPV2", None, "password"),
              ("Connection with dynamic PEAP/EAP-GTC password entry",
               "PEAP", None, "user", "auth=GTC", None, "password") ]
    for [desc,eap,anon,identity,phase2,req_id,req_pw] in tests:
        logger.info(desc)
        dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap=eap,
                       anonymous_identity=anon, identity=identity,
                       ca_cert="auth_serv/ca.pem", phase2=phase2,
                       wait_connect=False, scan_freq="2412")
        if req_id:
            ev = dev[0].wait_event(["CTRL-REQ-IDENTITY"])
            if ev is None:
                raise Exception("Request for identity timed out")
            id = ev.split(':')[0].split('-')[-1]
            dev[0].request("CTRL-RSP-IDENTITY-" + id + ":" + req_id)
        ev = dev[0].wait_event(["CTRL-REQ-PASSWORD","CTRL-REQ-OTP"])
        if ev is None:
            raise Exception("Request for password timed out")
        id = ev.split(':')[0].split('-')[-1]
        type = "OTP" if "CTRL-REQ-OTP" in ev else "PASSWORD"
        dev[0].request("CTRL-RSP-" + type + "-" + id + ":" + req_pw)
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Connection timed out")
        dev[0].request("REMOVE_NETWORK all")

def test_ap_wpa2_eap_vendor_test(dev, apdev):
    """WPA2-Enterprise connection using EAP vendor test"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "VENDOR-TEST", "vendor-test")
    eap_reauth(dev[0], "VENDOR-TEST")

def test_ap_wpa2_eap_fast_mschapv2_unauth_prov(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST/MSCHAPv2 and unauthenticated provisioning"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "FAST", "user",
                anonymous_identity="FAST", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                phase1="fast_provisioning=1", pac_file="blob://fast_pac")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "FAST")

def test_ap_wpa2_eap_fast_gtc_auth_prov(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST/GTC and authenticated provisioning"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "FAST", "user",
                anonymous_identity="FAST", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=GTC",
                phase1="fast_provisioning=2", pac_file="blob://fast_pac_auth")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "FAST")

def test_ap_wpa2_eap_tls_ocsp(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS and verifying OCSP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TLS", "tls user", ca_cert="auth_serv/ca.pem",
                private_key="auth_serv/user.pkcs12",
                private_key_passwd="whatever", ocsp=2)

def test_ap_wpa2_eap_tls_ocsp_invalid(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS and invalid OCSP response"""
    params = { "ssid": "test-wpa2-eap", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
               "rsn_pairwise": "CCMP", "ieee8021x": "1",
               "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf",
               "ca_cert": "auth_serv/ca.pem",
               "server_cert": "auth_serv/server.pem",
               "private_key": "auth_serv/server.key",
               "ocsp_stapling_response": "auth_serv/ocsp-server-cache.der-invalid" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever", ocsp=2,
                   wait_connect=False, scan_freq="2412")
    count = 0
    while True:
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-STATUS"])
        if ev is None:
            raise Exception("Timeout on EAP status")
        if 'bad certificate status response' in ev:
            break
        count = count + 1
        if count > 10:
            raise Exception("Unexpected number of EAP status messages")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")
