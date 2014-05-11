# -*- coding: utf-8 -*-
# WPA2-Enterprise tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import base64
import time
import subprocess
import logging
logger = logging.getLogger()
import os.path

import hwsim_utils
import hostapd
from test_ap_psk import check_mib

def read_pem(fname):
    with open(fname, "r") as f:
        lines = f.readlines()
        copy = False
        cert = ""
        for l in lines:
            if "-----END" in l:
                break
            if copy:
                cert = cert + l
            if "-----BEGIN" in l:
                copy = True
    return base64.b64decode(cert)

def eap_connect(dev, ap, method, identity,
                sha256=False, expect_failure=False, local_error_report=False,
                **kwargs):
    hapd = hostapd.Hostapd(ap['ifname'])
    id = dev.connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                     eap=method, identity=identity,
                     wait_connect=False, scan_freq="2412", ieee80211w="1",
                     **kwargs)
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

def eap_reauth(dev, method, rsn=True, sha256=False, expect_failure=False):
    dev.request("REAUTHENTICATE")
    eap_check_auth(dev, method, False, rsn=rsn, sha256=sha256,
                   expect_failure=expect_failure)

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

    eap_connect(dev[1], apdev[0], "SIM", "1232010000000001",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    eap_connect(dev[2], apdev[0], "SIM", "1232010000000002",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                expect_failure=True)

    logger.info("Negative test with incorrect key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                expect_failure=True)

def test_ap_wpa2_eap_sim_sql(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-SIM (SQL)"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    try:
        import sqlite3
    except ImportError:
        return "skip"
    con = sqlite3.connect(os.path.join(params['logdir'], "hostapd.db"))
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['auth_server_port'] = "1814"
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")

    logger.info("SIM fast re-authentication")
    eap_reauth(dev[0], "SIM")

    logger.info("SIM full auth with pseudonym")
    with con:
        cur = con.cursor()
        cur.execute("DELETE FROM reauth WHERE permanent='1232010000000000'")
    eap_reauth(dev[0], "SIM")

    logger.info("SIM full auth with permanent identity")
    with con:
        cur = con.cursor()
        cur.execute("DELETE FROM reauth WHERE permanent='1232010000000000'")
        cur.execute("DELETE FROM pseudonyms WHERE permanent='1232010000000000'")
    eap_reauth(dev[0], "SIM")

    logger.info("SIM reauth with mismatching MK")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET mk='0000000000000000000000000000000000000000' WHERE permanent='1232010000000000'")
    eap_reauth(dev[0], "SIM", expect_failure=True)
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='10' WHERE permanent='1232010000000000'")
    eap_reauth(dev[0], "SIM")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='10' WHERE permanent='1232010000000000'")
    logger.info("SIM reauth with mismatching counter")
    eap_reauth(dev[0], "SIM")
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='1001' WHERE permanent='1232010000000000'")
    logger.info("SIM reauth with max reauth count reached")
    eap_reauth(dev[0], "SIM")

def test_ap_wpa2_eap_sim_config(dev, apdev):
    """EAP-SIM configuration options"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="SIM",
                   identity="1232010000000000",
                   password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                   phase1="sim_min_num_chal=1",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["EAP: Failed to initialize EAP method: vendor 0 method 18 (SIM)"], timeout=10)
    if ev is None:
        raise Exception("No EAP error message seen")
    dev[0].request("REMOVE_NETWORK all")

    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="SIM",
                   identity="1232010000000000",
                   password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                   phase1="sim_min_num_chal=4",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["EAP: Failed to initialize EAP method: vendor 0 method 18 (SIM)"], timeout=10)
    if ev is None:
        raise Exception("No EAP error message seen (2)")
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                phase1="sim_min_num_chal=2")
    eap_connect(dev[1], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                anonymous_identity="345678")

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

def test_ap_wpa2_eap_aka_sql(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-AKA (SQL)"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    try:
        import sqlite3
    except ImportError:
        return "skip"
    con = sqlite3.connect(os.path.join(params['logdir'], "hostapd.db"))
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['auth_server_port'] = "1814"
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")

    logger.info("AKA fast re-authentication")
    eap_reauth(dev[0], "AKA")

    logger.info("AKA full auth with pseudonym")
    with con:
        cur = con.cursor()
        cur.execute("DELETE FROM reauth WHERE permanent='0232010000000000'")
    eap_reauth(dev[0], "AKA")

    logger.info("AKA full auth with permanent identity")
    with con:
        cur = con.cursor()
        cur.execute("DELETE FROM reauth WHERE permanent='0232010000000000'")
        cur.execute("DELETE FROM pseudonyms WHERE permanent='0232010000000000'")
    eap_reauth(dev[0], "AKA")

    logger.info("AKA reauth with mismatching MK")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET mk='0000000000000000000000000000000000000000' WHERE permanent='0232010000000000'")
    eap_reauth(dev[0], "AKA", expect_failure=True)
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='10' WHERE permanent='0232010000000000'")
    eap_reauth(dev[0], "AKA")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='10' WHERE permanent='0232010000000000'")
    logger.info("AKA reauth with mismatching counter")
    eap_reauth(dev[0], "AKA")
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='1001' WHERE permanent='0232010000000000'")
    logger.info("AKA reauth with max reauth count reached")
    eap_reauth(dev[0], "AKA")

def test_ap_wpa2_eap_aka_config(dev, apdev):
    """EAP-AKA configuration options"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                anonymous_identity="2345678")

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

def test_ap_wpa2_eap_aka_prime_sql(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-AKA' (SQL)"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    try:
        import sqlite3
    except ImportError:
        return "skip"
    con = sqlite3.connect(os.path.join(params['logdir'], "hostapd.db"))
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['auth_server_port'] = "1814"
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")

    logger.info("AKA' fast re-authentication")
    eap_reauth(dev[0], "AKA'")

    logger.info("AKA' full auth with pseudonym")
    with con:
        cur = con.cursor()
        cur.execute("DELETE FROM reauth WHERE permanent='6555444333222111'")
    eap_reauth(dev[0], "AKA'")

    logger.info("AKA' full auth with permanent identity")
    with con:
        cur = con.cursor()
        cur.execute("DELETE FROM reauth WHERE permanent='6555444333222111'")
        cur.execute("DELETE FROM pseudonyms WHERE permanent='6555444333222111'")
    eap_reauth(dev[0], "AKA'")

    logger.info("AKA' reauth with mismatching k_aut")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET k_aut='0000000000000000000000000000000000000000000000000000000000000000' WHERE permanent='6555444333222111'")
    eap_reauth(dev[0], "AKA'", expect_failure=True)
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='10' WHERE permanent='6555444333222111'")
    eap_reauth(dev[0], "AKA'")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='10' WHERE permanent='6555444333222111'")
    logger.info("AKA' reauth with mismatching counter")
    eap_reauth(dev[0], "AKA'")
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")
    with con:
        cur = con.cursor()
        cur.execute("UPDATE reauth SET counter='1001' WHERE permanent='6555444333222111'")
    logger.info("AKA' reauth with max reauth count reached")
    eap_reauth(dev[0], "AKA'")

def test_ap_wpa2_eap_ttls_pap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "WPA-EAP":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    eap_connect(dev[0], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                subject_match="/C=FI/O=w1.fi/CN=server.w1.fi",
                altsubject_match="EMAIL:noone@example.com;DNS:server.w1.fi;URI:http://example.com/")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    eap_reauth(dev[0], "TTLS")
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-1"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-1") ])

def test_ap_wpa2_eap_ttls_chap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.der", phase2="auth=CHAP",
                altsubject_match="EMAIL:noone@example.com;URI:http://example.com/;DNS:server.w1.fi")
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

def test_ap_wpa2_eap_ttls_mschapv2_utf8(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2 and UTF-8 password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    eap_connect(dev[0], apdev[0], "TTLS", "utf8-user-hash",
                anonymous_identity="ttls", password="secret-åäö-€-password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    eap_connect(dev[1], apdev[0], "TTLS", "utf8-user",
                anonymous_identity="ttls",
                password_hex="hash:bd5844fad2489992da7fe8c5a01559cf",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")

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

def test_ap_wpa2_eap_tls_blob(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS and config blobs"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    cert = read_pem("auth_serv/ca.pem")
    if "OK" not in dev[0].request("SET blob cacert " + cert.encode("hex")):
        raise Exception("Could not set cacert blob")
    cert = read_pem("auth_serv/user.pem")
    if "OK" not in dev[0].request("SET blob usercert " + cert.encode("hex")):
        raise Exception("Could not set usercert blob")
    key = read_pem("auth_serv/user.key")
    if "OK" not in dev[0].request("SET blob userkey " + key.encode("hex")):
        raise Exception("Could not set cacert blob")
    eap_connect(dev[0], apdev[0], "TLS", "tls user", ca_cert="blob://cacert",
                client_cert="blob://usercert",
                private_key="blob://userkey")

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

def test_ap_wpa2_eap_tls_pkcs12_blob(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS and PKCS#12 from configuration blob"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    cert = read_pem("auth_serv/ca.pem")
    if "OK" not in dev[0].request("SET blob cacert " + cert.encode("hex")):
        raise Exception("Could not set cacert blob")
    with open("auth_serv/user.pkcs12", "rb") as f:
        if "OK" not in dev[0].request("SET blob pkcs12 " + f.read().encode("hex")):
            raise Exception("Could not set pkcs12 blob")
    eap_connect(dev[0], apdev[0], "TLS", "tls user", ca_cert="blob://cacert",
                private_key="blob://pkcs12",
                private_key_passwd="whatever")

def test_ap_wpa2_eap_tls_neg_incorrect_trust_root(dev, apdev):
    """WPA2-Enterprise negative test - incorrect trust root"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    cert = read_pem("auth_serv/ca-incorrect.pem")
    if "OK" not in dev[0].request("SET blob cacert " + cert.encode("hex")):
        raise Exception("Could not set cacert blob")
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="blob://cacert",
                   wait_connect=False, scan_freq="2412")
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca-incorrect.pem",
                   wait_connect=False, scan_freq="2412")

    for dev in (dev[0], dev[1]):
        ev = dev.wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
        if ev is None:
            raise Exception("Association and EAP start timed out")

        ev = dev.wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
        if ev is None:
            raise Exception("EAP method selection timed out")
        if "TTLS" not in ev:
            raise Exception("Unexpected EAP method")

        ev = dev.wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR",
                             "CTRL-EVENT-EAP-SUCCESS",
                             "CTRL-EVENT-EAP-FAILURE",
                             "CTRL-EVENT-CONNECTED",
                             "CTRL-EVENT-DISCONNECTED"], timeout=10)
        if ev is None:
            raise Exception("EAP result timed out")
        if "CTRL-EVENT-EAP-TLS-CERT-ERROR" not in ev:
            raise Exception("TLS certificate error not reported")

        ev = dev.wait_event(["CTRL-EVENT-EAP-SUCCESS",
                             "CTRL-EVENT-EAP-FAILURE",
                             "CTRL-EVENT-CONNECTED",
                             "CTRL-EVENT-DISCONNECTED"], timeout=10)
        if ev is None:
            raise Exception("EAP result(2) timed out")
        if "CTRL-EVENT-EAP-FAILURE" not in ev:
            raise Exception("EAP failure not reported")

        ev = dev.wait_event(["CTRL-EVENT-CONNECTED",
                             "CTRL-EVENT-DISCONNECTED"], timeout=10)
        if ev is None:
            raise Exception("EAP result(3) timed out")
        if "CTRL-EVENT-DISCONNECTED" not in ev:
            raise Exception("Disconnection not reported")

        ev = dev.wait_event(["CTRL-EVENT-SSID-TEMP-DISABLED"], timeout=10)
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

def test_ap_wpa2_eap_ttls_server_cert_hash_invalid(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS and server certificate hash (invalid config)"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="hash://server/md5/5a1bc1296205e6fdbe3979728efe3920798885c1c4590b5f90f43222d239ca6a",
                   wait_connect=False, scan_freq="2412")
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="hash://server/sha256/5a1bc1296205e6fdbe3979728efe3920798885c1c4590b5f90f43222d239ca",
                   wait_connect=False, scan_freq="2412")
    dev[2].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="hash://server/sha256/5a1bc1296205e6fdbe3979728efe3920798885c1c4590b5f90f43222d239ca6Q",
                   wait_connect=False, scan_freq="2412")
    for i in range(0, 3):
        ev = dev[i].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
        if ev is None:
            raise Exception("Association and EAP start timed out")
        timeout = 1 if i == 0 else 0.1
        ev = dev[i].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=timeout)
        if ev is not None:
            raise Exception("Unexpected EAP start")

def test_ap_wpa2_eap_pwd(dev, apdev):
    """WPA2-Enterprise connection using EAP-pwd"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PWD", "pwd user", password="secret password")
    eap_reauth(dev[0], "PWD")
    dev[0].request("REMOVE_NETWORK all")

    eap_connect(dev[1], apdev[0], "PWD",
                "pwd.user@test123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.example.com",
                password="secret password",
                fragment_size="90")

    logger.info("Negative test with incorrect password")
    eap_connect(dev[2], apdev[0], "PWD", "pwd user", password="secret-password",
                expect_failure=True, local_error_report=True)

    eap_connect(dev[0], apdev[0], "PWD",
                "pwd.user@test123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.example.com",
                password="secret password",
                fragment_size="31")

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
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-5"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-5") ])

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
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-50-f2-1"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-50-f2-1") ])

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

def int_eap_server_params():
    params = { "ssid": "test-wpa2-eap", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
               "rsn_pairwise": "CCMP", "ieee8021x": "1",
               "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf",
               "ca_cert": "auth_serv/ca.pem",
               "server_cert": "auth_serv/server.pem",
               "private_key": "auth_serv/server.key" }
    return params
    
def test_ap_wpa2_eap_tls_ocsp_invalid(dev, apdev):
    """WPA2-Enterprise connection using EAP-TLS and invalid OCSP response"""
    params = int_eap_server_params()
    params["ocsp_stapling_response"] = "auth_serv/ocsp-server-cache.der-invalid"
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

def test_ap_wpa2_eap_tls_domain_suffix_match_cn(dev, apdev):
    """WPA2-Enterprise using EAP-TLS and domain suffix match (CN)"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-no-dnsname.pem"
    params["private_key"] = "auth_serv/server-no-dnsname.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever",
                   domain_suffix_match="server3.w1.fi",
                   scan_freq="2412")
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever",
                   domain_suffix_match="w1.fi",
                   scan_freq="2412")

def test_ap_wpa2_eap_tls_domain_suffix_mismatch_cn(dev, apdev):
    """WPA2-Enterprise using EAP-TLS and domain suffix mismatch (CN)"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-no-dnsname.pem"
    params["private_key"] = "auth_serv/server-no-dnsname.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever",
                   domain_suffix_match="example.com",
                   wait_connect=False,
                   scan_freq="2412")
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever",
                   domain_suffix_match="erver3.w1.fi",
                   wait_connect=False,
                   scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")
    ev = dev[1].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report (2)")

def test_ap_wpa2_eap_ttls_expired_cert(dev, apdev):
    """WPA2-Enterprise using EAP-TTLS and expired certificate"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-expired.pem"
    params["private_key"] = "auth_serv/server-expired.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="mschap user", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                   wait_connect=False,
                   scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR"])
    if ev is None:
        raise Exception("Timeout on EAP certificate error report")
    if "reason=4" not in ev or "certificate has expired" not in ev:
        raise Exception("Unexpected failure reason: " + ev)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")

def test_ap_wpa2_eap_ttls_ignore_expired_cert(dev, apdev):
    """WPA2-Enterprise using EAP-TTLS and ignore certificate expiration"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-expired.pem"
    params["private_key"] = "auth_serv/server-expired.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="mschap user", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                   phase1="tls_disable_time_checks=1",
                   scan_freq="2412")

def test_ap_wpa2_eap_ttls_server_cert_eku_client(dev, apdev):
    """WPA2-Enterprise using EAP-TTLS and server cert with client EKU"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-eku-client.pem"
    params["private_key"] = "auth_serv/server-eku-client.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="mschap user", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                   wait_connect=False,
                   scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")

def test_ap_wpa2_eap_ttls_server_cert_eku_client_server(dev, apdev):
    """WPA2-Enterprise using EAP-TTLS and server cert with client and server EKU"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-eku-client-server.pem"
    params["private_key"] = "auth_serv/server-eku-client-server.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="mschap user", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                   scan_freq="2412")

def test_ap_wpa2_eap_ttls_server_pkcs12(dev, apdev):
    """WPA2-Enterprise using EAP-TTLS and server PKCS#12 file"""
    params = int_eap_server_params()
    del params["server_cert"]
    params["private_key"] = "auth_serv/server.pkcs12"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="mschap user", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                   scan_freq="2412")

def test_ap_wpa2_eap_ttls_dh_params(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP and setting DH params"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.der", phase2="auth=CHAP",
                dh_file="auth_serv/dh.conf")

def test_ap_wpa2_eap_ttls_dh_params_blob(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP and setting DH params from blob"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dh = read_pem("auth_serv/dh.conf")
    if "OK" not in dev[0].request("SET blob dhparams " + dh.encode("hex")):
        raise Exception("Could not set dhparams blob")
    eap_connect(dev[0], apdev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.der", phase2="auth=CHAP",
                dh_file="blob://dhparams")

def test_ap_wpa2_eap_reauth(dev, apdev):
    """WPA2-Enterprise and Authenticator forcing reauthentication"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['eap_reauth_period'] = '2'
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PAX", "pax.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef")
    logger.info("Wait for reauthentication")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Timeout on reauthentication")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("Timeout on reauthentication")
    for i in range(0, 20):
        state = dev[0].get_status_field("wpa_state")
        if state == "COMPLETED":
            break
        time.sleep(0.1)
    if state != "COMPLETED":
        raise Exception("Reauthentication did not complete")

def test_ap_wpa2_eap_request_identity_message(dev, apdev):
    """Optional displayable message in EAP Request-Identity"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['eap_message'] = 'hello\\0networkid=netw,nasid=foo,portid=0,NAIRealms=example.com'
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PAX", "pax.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef")

def test_ap_wpa2_eap_sim_aka_result_ind(dev, apdev):
    """WPA2-Enterprise using EAP-SIM/AKA and protected result indication"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    params = int_eap_server_params()
    params['eap_sim_db'] = "unix:/tmp/hlr_auc_gw.sock"
    params['eap_sim_aka_result_ind'] = "1"
    hostapd.add_ap(apdev[0]['ifname'], params)

    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                phase1="result_ind=1")
    eap_reauth(dev[0], "SIM")
    eap_connect(dev[1], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")

    dev[0].request("REMOVE_NETWORK all")
    dev[1].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                phase1="result_ind=1")
    eap_reauth(dev[0], "AKA")
    eap_connect(dev[1], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")

    dev[0].request("REMOVE_NETWORK all")
    dev[1].request("REMOVE_NETWORK all")

    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
                phase1="result_ind=1")
    eap_reauth(dev[0], "AKA'")
    eap_connect(dev[1], apdev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")

def test_ap_wpa2_eap_too_many_roundtrips(dev, apdev):
    """WPA2-Enterprise connection resulting in too many EAP roundtrips"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                   eap="TTLS", identity="mschap user",
                   wait_connect=False, scan_freq="2412", ieee80211w="1",
                   anonymous_identity="ttls", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                   fragment_size="10")
    ev = dev[0].wait_event(["EAP: more than"], timeout=20)
    if ev is None:
        raise Exception("EAP roundtrip limit not reached")

def test_ap_wpa2_eap_expanded_nak(dev, apdev):
    """WPA2-Enterprise connection with EAP resulting in expanded NAK"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                   eap="PSK", identity="vendor-test",
                   password_hex="ff23456789abcdef0123456789abcdef",
                   wait_connect=False)

    found = False
    for i in range(0, 5):
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-STATUS"], timeout=10)
        if ev is None:
            raise Exception("Association and EAP start timed out")
        if "refuse proposed method" in ev:
            found = True
            break
    if not found:
        raise Exception("Unexpected EAP status: " + ev)

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("EAP failure timed out")
