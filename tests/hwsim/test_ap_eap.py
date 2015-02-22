# -*- coding: utf-8 -*-
# WPA2-Enterprise tests
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import base64
import binascii
import time
import subprocess
import logging
logger = logging.getLogger()
import os

import hwsim_utils
import hostapd
from utils import HwsimSkip, alloc_fail
from wpasupplicant import WpaSupplicant
from test_ap_psk import check_mib, find_wpas_process, read_process_memory, verify_not_present, get_key_locations

def check_hlr_auc_gw_support():
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        raise HwsimSkip("No hlr_auc_gw available")

def check_eap_capa(dev, method):
    res = dev.get_capability("eap")
    if method not in res:
        raise HwsimSkip("EAP method %s not supported in the build" % method)

def check_subject_match_support(dev):
    tls = dev.request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("subject_match not supported with this TLS library: " + tls)

def check_altsubject_match_support(dev):
    tls = dev.request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("altsubject_match not supported with this TLS library: " + tls)

def check_domain_match_full(dev):
    tls = dev.request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("domain_suffix_match requires full match with this TLS library: " + tls)

def check_cert_probe_support(dev):
    tls = dev.request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("Certificate probing not supported with this TLS library: " + tls)

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
        ev = dev.wait_disconnected(timeout=10)
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
    return status

def eap_reauth(dev, method, rsn=True, sha256=False, expect_failure=False):
    dev.request("REAUTHENTICATE")
    return eap_check_auth(dev, method, False, rsn=rsn, sha256=sha256,
                          expect_failure=expect_failure)

def test_ap_wpa2_eap_sim(dev, apdev):
    """WPA2-Enterprise connection using EAP-SIM"""
    check_hlr_auc_gw_support()
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    hwsim_utils.test_connectivity(dev[0], hapd)
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

    logger.info("Invalid GSM-Milenage key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a",
                expect_failure=True)

    logger.info("Invalid GSM-Milenage key(2)")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a8q:cb9cccc4b9258e6dca4760379fb82581",
                expect_failure=True)

    logger.info("Invalid GSM-Milenage key(3)")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb8258q",
                expect_failure=True)

    logger.info("Invalid GSM-Milenage key(4)")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89qcb9cccc4b9258e6dca4760379fb82581",
                expect_failure=True)

    logger.info("Missing key configuration")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "SIM", "1232010000000000",
                expect_failure=True)

def test_ap_wpa2_eap_sim_sql(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-SIM (SQL)"""
    check_hlr_auc_gw_support()
    try:
        import sqlite3
    except ImportError:
        raise HwsimSkip("No sqlite3 module available")
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

def test_ap_wpa2_eap_sim_ext(dev, apdev):
    """WPA2-Enterprise connection using EAP-SIM and external GSM auth"""
    try:
        _test_ap_wpa2_eap_sim_ext(dev, apdev)
    finally:
        dev[0].request("SET external_sim 0")

def _test_ap_wpa2_eap_sim_ext(dev, apdev):
    check_hlr_auc_gw_support()
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].request("SET external_sim 1")
    id = dev[0].connect("test-wpa2-eap", eap="SIM", key_mgmt="WPA-EAP",
                        identity="1232010000000000",
                        wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=15)
    if ev is None:
        raise Exception("Network connected timed out")

    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]

    # IK:CK:RES
    resp = "00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff:0011223344"
    # This will fail during processing, but the ctrl_iface command succeeds
    dev[0].request("CTRL-RSP-SIM-" + rid + ":UMTS-AUTH:" + resp)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during GSM auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":GSM-AUTH:q"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during GSM auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":GSM-AUTH:34"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during GSM auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":GSM-AUTH:0011223344556677"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during GSM auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":GSM-AUTH:0011223344556677:q"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during GSM auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":GSM-AUTH:0011223344556677:00112233"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during GSM auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":GSM-AUTH:0011223344556677:00112233:q"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")

def test_ap_wpa2_eap_aka(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA"""
    check_hlr_auc_gw_support()
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "AKA")

    logger.info("Negative test with incorrect key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                expect_failure=True)

    logger.info("Invalid Milenage key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a",
                expect_failure=True)

    logger.info("Invalid Milenage key(2)")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a8q:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                expect_failure=True)

    logger.info("Invalid Milenage key(3)")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb8258q:000000000123",
                expect_failure=True)

    logger.info("Invalid Milenage key(4)")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:00000000012q",
                expect_failure=True)

    logger.info("Invalid Milenage key(5)")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581q000000000123",
                expect_failure=True)

    logger.info("Invalid Milenage key(6)")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                password="ffdca4eda45b53cf0f12d7c9c3bc6a89qcb9cccc4b9258e6dca4760379fb82581q000000000123",
                expect_failure=True)

    logger.info("Missing key configuration")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA", "0232010000000000",
                expect_failure=True)

def test_ap_wpa2_eap_aka_sql(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-AKA (SQL)"""
    check_hlr_auc_gw_support()
    try:
        import sqlite3
    except ImportError:
        raise HwsimSkip("No sqlite3 module available")
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

def test_ap_wpa2_eap_aka_ext(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA and external UMTS auth"""
    try:
        _test_ap_wpa2_eap_aka_ext(dev, apdev)
    finally:
        dev[0].request("SET external_sim 0")

def _test_ap_wpa2_eap_aka_ext(dev, apdev):
    check_hlr_auc_gw_support()
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].request("SET external_sim 1")
    id = dev[0].connect("test-wpa2-eap", eap="AKA", key_mgmt="WPA-EAP",
                        identity="0232010000000000",
                        password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                        wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=15)
    if ev is None:
        raise Exception("Network connected timed out")

    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "UMTS-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]

    # IK:CK:RES
    resp = "00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff:0011223344"
    # This will fail during processing, but the ctrl_iface command succeeds
    dev[0].request("CTRL-RSP-SIM-" + rid + ":GSM-AUTH:" + resp)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "UMTS-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during UMTS auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":UMTS-AUTS:112233445566778899aabbccddee"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "UMTS-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    rid = p[0].split('-')[3]
    # This will fail during UMTS auth validation
    if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + ":UMTS-AUTS:12"):
        raise Exception("CTRL-RSP-SIM failed")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    time.sleep(0.1)

    tests = [ ":UMTS-AUTH:00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff:0011223344",
              ":UMTS-AUTH:34",
              ":UMTS-AUTH:00112233445566778899aabbccddeeff.00112233445566778899aabbccddeeff:0011223344",
              ":UMTS-AUTH:00112233445566778899aabbccddeeff:00112233445566778899aabbccddee:0011223344",
              ":UMTS-AUTH:00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff.0011223344",
              ":UMTS-AUTH:00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff0011223344",
              ":UMTS-AUTH:00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff:001122334q" ]
    for t in tests:
        dev[0].select_network(id, freq="2412")
        ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
        if ev is None:
            raise Exception("Wait for external SIM processing request timed out")
        p = ev.split(':', 2)
        if p[1] != "UMTS-AUTH":
            raise Exception("Unexpected CTRL-REQ-SIM type")
        rid = p[0].split('-')[3]
        # This will fail during UMTS auth validation
        if "OK" not in dev[0].request("CTRL-RSP-SIM-" + rid + t):
            raise Exception("CTRL-RSP-SIM failed")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
        if ev is None:
            raise Exception("EAP failure not reported")
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        time.sleep(0.1)

def test_ap_wpa2_eap_aka_prime(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA'"""
    check_hlr_auc_gw_support()
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "AKA'")

    logger.info("EAP-AKA' bidding protection when EAP-AKA enabled as well")
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="AKA' AKA",
                   identity="6555444333222111@both",
                   password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
                   wait_connect=False, scan_freq="2412")
    dev[1].wait_connected(timeout=15)

    logger.info("Negative test with incorrect key")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "AKA'", "6555444333222111",
                password="ff22250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
                expect_failure=True)

def test_ap_wpa2_eap_aka_prime_sql(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-AKA' (SQL)"""
    check_hlr_auc_gw_support()
    try:
        import sqlite3
    except ImportError:
        raise HwsimSkip("No sqlite3 module available")
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
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-1"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-1") ])

def test_ap_wpa2_eap_ttls_pap_subject_match(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP and (alt)subject_match"""
    check_subject_match_support(dev[0])
    check_altsubject_match_support(dev[0])
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                subject_match="/C=FI/O=w1.fi/CN=server.w1.fi",
                altsubject_match="EMAIL:noone@example.com;DNS:server.w1.fi;URI:http://example.com/")
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_pap_incorrect_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP - incorrect password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="wrong",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                expect_failure=True)
    eap_connect(dev[1], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_chap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.der", phase2="auth=CHAP")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_chap_altsubject_match(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP"""
    check_altsubject_match_support(dev[0])
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.der", phase2="auth=CHAP",
                altsubject_match="EMAIL:noone@example.com;URI:http://example.com/;DNS:server.w1.fi")
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_chap_incorrect_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP - incorrect password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="wrong",
                ca_cert="auth_serv/ca.pem", phase2="auth=CHAP",
                expect_failure=True)
    eap_connect(dev[1], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=CHAP",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_mschap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "mschap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                domain_suffix_match="server.w1.fi")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "TTLS", "mschap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                fragment_size="200")

def test_ap_wpa2_eap_ttls_mschap_incorrect_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP - incorrect password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "mschap user",
                anonymous_identity="ttls", password="wrong",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                expect_failure=True)
    eap_connect(dev[1], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                expect_failure=True)
    eap_connect(dev[2], apdev[0], "TTLS", "no such user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                domain_suffix_match="server.w1.fi")
    hwsim_utils.test_connectivity(dev[0], hapd)
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

def test_ap_wpa2_eap_ttls_mschapv2_suffix_match(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2"""
    check_domain_match_full(dev[0])
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                domain_suffix_match="w1.fi")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_mschapv2_domain_match(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2 (domain_match)"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                domain_match="Server.w1.fi")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_mschapv2_incorrect_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2 - incorrect password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password1",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)
    eap_connect(dev[1], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
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
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=GTC")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_eap_gtc_incorrect_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-GTC - incorrect password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="wrong",
                ca_cert="auth_serv/ca.pem", phase2="autheap=GTC",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_eap_gtc_no_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-GTC - no password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user-no-passwd",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=GTC",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_eap_gtc_server_oom(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-GTC - server OOM"""
    params = int_eap_server_params()
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    with alloc_fail(hapd, 1, "eap_gtc_init"):
        eap_connect(dev[0], apdev[0], "TTLS", "user",
                    anonymous_identity="ttls", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="autheap=GTC",
                    expect_failure=True)
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(hapd, 1, "eap_gtc_buildReq"):
        dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                       eap="TTLS", identity="user",
                       anonymous_identity="ttls", password="password",
                       ca_cert="auth_serv/ca.pem", phase2="autheap=GTC",
                       wait_connect=False, scan_freq="2412")
        # This would eventually time out, but we can stop after having reached
        # the allocation failure.
        for i in range(20):
            time.sleep(0.1)
            if hapd.request("GET_ALLOC_FAIL").startswith('0'):
                break

def test_ap_wpa2_eap_ttls_eap_md5(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MD5"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MD5")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")

def test_ap_wpa2_eap_ttls_eap_md5_incorrect_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MD5 - incorrect password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="wrong",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MD5",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_eap_md5_no_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MD5 - no password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user-no-passwd",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MD5",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_eap_md5_server_oom(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MD5 - server OOM"""
    params = int_eap_server_params()
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    with alloc_fail(hapd, 1, "eap_md5_init"):
        eap_connect(dev[0], apdev[0], "TTLS", "user",
                    anonymous_identity="ttls", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="autheap=MD5",
                    expect_failure=True)
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(hapd, 1, "eap_md5_buildReq"):
        dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                       eap="TTLS", identity="user",
                       anonymous_identity="ttls", password="password",
                       ca_cert="auth_serv/ca.pem", phase2="autheap=MD5",
                       wait_connect=False, scan_freq="2412")
        # This would eventually time out, but we can stop after having reached
        # the allocation failure.
        for i in range(20):
            time.sleep(0.1)
            if hapd.request("GET_ALLOC_FAIL").startswith('0'):
                break

def test_ap_wpa2_eap_ttls_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "TTLS")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password1",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_eap_mschapv2_no_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MSCHAPv2 - no password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "user-no-passwd",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2",
                expect_failure=True)

def test_ap_wpa2_eap_ttls_eap_mschapv2_server_oom(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MSCHAPv2 - server OOM"""
    params = int_eap_server_params()
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    with alloc_fail(hapd, 1, "eap_mschapv2_init"):
        eap_connect(dev[0], apdev[0], "TTLS", "user",
                    anonymous_identity="ttls", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2",
                    expect_failure=True)
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(hapd, 1, "eap_mschapv2_build_challenge"):
        dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                       eap="TTLS", identity="user",
                       anonymous_identity="ttls", password="password",
                       ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2",
                       wait_connect=False, scan_freq="2412")
        # This would eventually time out, but we can stop after having reached
        # the allocation failure.
        for i in range(20):
            time.sleep(0.1)
            if hapd.request("GET_ALLOC_FAIL").startswith('0'):
                break
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(hapd, 1, "eap_mschapv2_build_success_req"):
        dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                       eap="TTLS", identity="user",
                       anonymous_identity="ttls", password="password",
                       ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2",
                       wait_connect=False, scan_freq="2412")
        # This would eventually time out, but we can stop after having reached
        # the allocation failure.
        for i in range(20):
            time.sleep(0.1)
            if hapd.request("GET_ALLOC_FAIL").startswith('0'):
                break
        dev[0].request("REMOVE_NETWORK all")

    with alloc_fail(hapd, 1, "eap_mschapv2_build_failure_req"):
        dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP WPA-EAP-SHA256",
                       eap="TTLS", identity="user",
                       anonymous_identity="ttls", password="wrong",
                       ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2",
                       wait_connect=False, scan_freq="2412")
        # This would eventually time out, but we can stop after having reached
        # the allocation failure.
        for i in range(20):
            time.sleep(0.1)
            if hapd.request("GET_ALLOC_FAIL").startswith('0'):
                break
        dev[0].request("REMOVE_NETWORK all")

def test_ap_wpa2_eap_ttls_eap_aka(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-AKA"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "0232010000000000",
                anonymous_identity="0232010000000000@ttls",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                ca_cert="auth_serv/ca.pem", phase2="autheap=AKA")

def test_ap_wpa2_eap_peap_eap_aka(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAP/EAP-AKA"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "0232010000000000",
                anonymous_identity="0232010000000000@peap",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                ca_cert="auth_serv/ca.pem", phase2="auth=AKA")

def test_ap_wpa2_eap_fast_eap_aka(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST/EAP-AKA"""
    check_eap_capa(dev[0], "FAST")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "FAST", "0232010000000000",
                anonymous_identity="0232010000000000@fast",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                phase1="fast_provisioning=2",
                pac_file="blob://fast_pac_auth_aka",
                ca_cert="auth_serv/ca.pem", phase2="auth=AKA")

def test_ap_wpa2_eap_peap_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAP/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "user",
                anonymous_identity="peap", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0], hapd)
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

def test_ap_wpa2_eap_peap_eap_mschapv2_incorrect_password(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAP/EAP-MSCHAPv2 - incorrect password"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "user",
                anonymous_identity="peap", password="wrong",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                expect_failure=True)

def test_ap_wpa2_eap_peap_crypto_binding(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAPv0/EAP-MSCHAPv2 and crypto binding"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "user", password="password",
                ca_cert="auth_serv/ca.pem",
                phase1="peapver=0 crypto_binding=2",
                phase2="auth=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "PEAP")

    eap_connect(dev[1], apdev[0], "PEAP", "user", password="password",
                ca_cert="auth_serv/ca.pem",
                phase1="peapver=0 crypto_binding=1",
                phase2="auth=MSCHAPV2")
    eap_connect(dev[2], apdev[0], "PEAP", "user", password="password",
                ca_cert="auth_serv/ca.pem",
                phase1="peapver=0 crypto_binding=0",
                phase2="auth=MSCHAPV2")

def test_ap_wpa2_eap_peap_crypto_binding_server_oom(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAPv0/EAP-MSCHAPv2 and crypto binding with server OOM"""
    params = int_eap_server_params()
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    with alloc_fail(hapd, 1, "eap_mschapv2_getKey"):
        eap_connect(dev[0], apdev[0], "PEAP", "user", password="password",
                    ca_cert="auth_serv/ca.pem",
                    phase1="peapver=0 crypto_binding=2",
                    phase2="auth=MSCHAPV2",
                    expect_failure=True, local_error_report=True)

def test_ap_wpa2_eap_peap_params(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAPv0/EAP-MSCHAPv2 and various parameters"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "PEAP", "user",
                anonymous_identity="peap", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                phase1="peapver=0 peaplabel=1",
                expect_failure=True)
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[1], apdev[0], "PEAP", "user", password="password",
                ca_cert="auth_serv/ca.pem",
                phase1="peap_outer_success=1",
                phase2="auth=MSCHAPV2")
    eap_connect(dev[2], apdev[0], "PEAP", "user", password="password",
                ca_cert="auth_serv/ca.pem",
                phase1="peap_outer_success=2",
                phase2="auth=MSCHAPV2")
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="PEAP",
                   identity="user",
                   anonymous_identity="peap", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                   phase1="peapver=1 peaplabel=1",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("No EAP success seen")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection")

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
    key = read_pem("auth_serv/user.rsa-key")
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
    dev[0].wait_connected(timeout=10)

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

def test_ap_wpa2_eap_tls_diff_ca_trust(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP and different CA trust"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="pap user", anonymous_identity="ttls",
                   password="password", phase2="auth=PAP",
                   ca_cert="auth_serv/ca.pem",
                   wait_connect=True, scan_freq="2412")
    id = dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                        identity="pap user", anonymous_identity="ttls",
                        password="password", phase2="auth=PAP",
                        ca_cert="auth_serv/ca-incorrect.pem",
                        only_add_network=True, scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    dev[0].select_network(id, freq="2412")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21"], timeout=15)
    if ev is None:
        raise Exception("EAP-TTLS not re-started")
    
    ev = dev[0].wait_disconnected(timeout=15)
    if "reason=23" not in ev:
        raise Exception("Proper reason code for disconnection not reported")

def test_ap_wpa2_eap_tls_diff_ca_trust2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP and different CA trust"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="pap user", anonymous_identity="ttls",
                   password="password", phase2="auth=PAP",
                   wait_connect=True, scan_freq="2412")
    id = dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                        identity="pap user", anonymous_identity="ttls",
                        password="password", phase2="auth=PAP",
                        ca_cert="auth_serv/ca-incorrect.pem",
                        only_add_network=True, scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    dev[0].select_network(id, freq="2412")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21"], timeout=15)
    if ev is None:
        raise Exception("EAP-TTLS not re-started")
    
    ev = dev[0].wait_disconnected(timeout=15)
    if "reason=23" not in ev:
        raise Exception("Proper reason code for disconnection not reported")

def test_ap_wpa2_eap_tls_diff_ca_trust3(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP and different CA trust"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    id = dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                        identity="pap user", anonymous_identity="ttls",
                        password="password", phase2="auth=PAP",
                        ca_cert="auth_serv/ca.pem",
                        wait_connect=True, scan_freq="2412")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    dev[0].set_network_quoted(id, "ca_cert", "auth_serv/ca-incorrect.pem")
    dev[0].select_network(id, freq="2412")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21"], timeout=15)
    if ev is None:
        raise Exception("EAP-TTLS not re-started")
    
    ev = dev[0].wait_disconnected(timeout=15)
    if "reason=23" not in ev:
        raise Exception("Proper reason code for disconnection not reported")

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

def test_ap_wpa2_eap_tls_neg_domain_match(dev, apdev):
    """WPA2-Enterprise negative test - domain mismatch"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   domain_match="w1.fi",
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
    if "Domain mismatch" not in ev:
        raise Exception("Domain mismatch not reported")

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

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD",
                            "EAP: Failed to initialize EAP method"], timeout=10)
    if ev is None:
        raise Exception("EAP method selection timed out")
    if "EAP: Failed to initialize EAP method" in ev:
        tls = dev[0].request("GET tls_library")
        if tls.startswith("OpenSSL"):
            raise Exception("Failed to select EAP method")
        logger.info("subject_match not supported - connection failed, so test succeeded")
        return
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

    tests = [ "incorrect.example.com",
              "DNS:incorrect.example.com",
              "DNS:w1.fi",
              "DNS:erver.w1.fi" ]
    for match in tests:
        _test_ap_wpa2_eap_tls_neg_altsubject_match(dev, apdev, match)

def _test_ap_wpa2_eap_tls_neg_altsubject_match(dev, apdev, match):
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   altsubject_match=match,
                   wait_connect=False, scan_freq="2412")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD",
                            "EAP: Failed to initialize EAP method"], timeout=10)
    if ev is None:
        raise Exception("EAP method selection timed out")
    if "EAP: Failed to initialize EAP method" in ev:
        tls = dev[0].request("GET tls_library")
        if tls.startswith("OpenSSL"):
            raise Exception("Failed to select EAP method")
        logger.info("altsubject_match not supported - connection failed, so test succeeded")
        return
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

    dev[0].request("REMOVE_NETWORK all")

def test_ap_wpa2_eap_unauth_tls(dev, apdev):
    """WPA2-Enterprise connection using UNAUTH-TLS"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "UNAUTH-TLS", "unauth-tls",
                ca_cert="auth_serv/ca.pem")
    eap_reauth(dev[0], "UNAUTH-TLS")

def test_ap_wpa2_eap_ttls_server_cert_hash(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS and server certificate hash"""
    check_cert_probe_support(dev[0])
    srv_cert_hash = "1477c9cd88391609444b83eca45c4f9f324e3051c5c31fc233ac6aede30ce7cd"
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
    dev[0].wait_disconnected(timeout=10)
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
    dev[0].wait_disconnected(timeout=10)
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
        ev = dev[i].wait_event(["EAP: Failed to initialize EAP method: vendor 0 method 21 (TTLS)"], timeout=5)
        if ev is None:
            raise Exception("Did not report EAP method initialization failure")

def test_ap_wpa2_eap_pwd(dev, apdev):
    """WPA2-Enterprise connection using EAP-pwd"""
    check_eap_capa(dev[0], "PWD")
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
    check_eap_capa(dev[0], "PWD")
    params = { "ssid": "test-wpa2-eap", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
               "rsn_pairwise": "CCMP", "ieee8021x": "1",
               "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf" }
    for i in [ 19, 20, 21, 25, 26 ]:
        params['pwd_group'] = str(i)
        hostapd.add_ap(apdev[0]['ifname'], params)
        dev[0].request("REMOVE_NETWORK all")
        eap_connect(dev[0], apdev[0], "PWD", "pwd user", password="secret password")

def test_ap_wpa2_eap_pwd_invalid_group(dev, apdev):
    """WPA2-Enterprise connection using invalid EAP-pwd group"""
    check_eap_capa(dev[0], "PWD")
    params = { "ssid": "test-wpa2-eap", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
               "rsn_pairwise": "CCMP", "ieee8021x": "1",
               "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf" }
    params['pwd_group'] = "0"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="PWD",
                   identity="pwd user", password="secret password",
                   scan_freq="2412", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")

def test_ap_wpa2_eap_pwd_as_frag(dev, apdev):
    """WPA2-Enterprise connection using EAP-pwd with server fragmentation"""
    check_eap_capa(dev[0], "PWD")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params = { "ssid": "test-wpa2-eap", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
               "rsn_pairwise": "CCMP", "ieee8021x": "1",
               "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf",
               "pwd_group": "19", "fragment_size": "40" }
    hostapd.add_ap(apdev[0]['ifname'], params)
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
        dev[0].wait_connected(timeout=10)

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
        dev[0].wait_connected(timeout=10)

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
                password="ike password", fragment_size="50")

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "IKEV2", "ikev2 user",
                password="ike-password", expect_failure=True)

def test_ap_wpa2_eap_ikev2_as_frag(dev, apdev):
    """WPA2-Enterprise connection using EAP-IKEv2 with server fragmentation"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params = { "ssid": "test-wpa2-eap", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
               "rsn_pairwise": "CCMP", "ieee8021x": "1",
               "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf",
               "fragment_size": "50" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "IKEV2", "ikev2 user",
                password="ike password")
    eap_reauth(dev[0], "IKEV2")

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

    bss = dev[0].get_bss(apdev[0]['bssid'])
    if 'flags' not in bss:
        raise Exception("Could not get BSS flags from BSS table")
    if "[WPA2-EAP-SHA256-CCMP]" not in bss['flags']:
        raise Exception("Unexpected BSS flags: " + bss['flags'])

    logger.info("Negative test with incorrect password")
    dev[0].request("REMOVE_NETWORK all")
    eap_connect(dev[0], apdev[0], "PSK", "psk.user@example.com",
                password_hex="ff23456789abcdef0123456789abcdef", sha256=True,
                expect_failure=True)

def test_ap_wpa_eap_peap_eap_mschapv2(dev, apdev):
    """WPA-Enterprise connection using EAP-PEAP/EAP-MSCHAPv2"""
    params = hostapd.wpa_eap_params(ssid="test-wpa-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa-eap", key_mgmt="WPA-EAP", eap="PEAP",
                   identity="user", password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem", wait_connect=False,
                   scan_freq="2412")
    eap_check_auth(dev[0], "PEAP", True, rsn=False)
    hwsim_utils.test_connectivity(dev[0], hapd)
    eap_reauth(dev[0], "PEAP", rsn=False)
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-50-f2-1"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-50-f2-1") ])
    status = dev[0].get_status(extra="VERBOSE")
    if 'portControl' not in status:
        raise Exception("portControl missing from STATUS-VERBOSE")
    if status['portControl'] != 'Auto':
        raise Exception("Unexpected portControl value: " + status['portControl'])
    if 'eap_session_id' not in status:
        raise Exception("eap_session_id missing from STATUS-VERBOSE")
    if not status['eap_session_id'].startswith("19"):
        raise Exception("Unexpected eap_session_id value: " + status['eap_session_id'])

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
        dev[0].wait_connected(timeout=10)
        dev[0].request("REMOVE_NETWORK all")

def test_ap_wpa2_eap_vendor_test(dev, apdev):
    """WPA2-Enterprise connection using EAP vendor test"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "VENDOR-TEST", "vendor-test")
    eap_reauth(dev[0], "VENDOR-TEST")
    eap_connect(dev[1], apdev[0], "VENDOR-TEST", "vendor-test",
                password="pending")

def test_ap_wpa2_eap_fast_mschapv2_unauth_prov(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST/MSCHAPv2 and unauthenticated provisioning"""
    check_eap_capa(dev[0], "FAST")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "FAST", "user",
                anonymous_identity="FAST", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                phase1="fast_provisioning=1", pac_file="blob://fast_pac")
    hwsim_utils.test_connectivity(dev[0], hapd)
    res = eap_reauth(dev[0], "FAST")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-FAST could not use PAC session ticket")

def test_ap_wpa2_eap_fast_pac_file(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-FAST/MSCHAPv2 and PAC file"""
    check_eap_capa(dev[0], "FAST")
    pac_file = os.path.join(params['logdir'], "fast.pac")
    pac_file2 = os.path.join(params['logdir'], "fast-bin.pac")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)

    try:
        eap_connect(dev[0], apdev[0], "FAST", "user",
                    anonymous_identity="FAST", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                    phase1="fast_provisioning=1", pac_file=pac_file)
        with open(pac_file, "r") as f:
            data = f.read()
            if "wpa_supplicant EAP-FAST PAC file - version 1" not in data:
                raise Exception("PAC file header missing")
            if "PAC-Key=" not in data:
                raise Exception("PAC-Key missing from PAC file")
        dev[0].request("REMOVE_NETWORK all")
        eap_connect(dev[0], apdev[0], "FAST", "user",
                    anonymous_identity="FAST", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                    pac_file=pac_file)

        eap_connect(dev[1], apdev[0], "FAST", "user",
                    anonymous_identity="FAST", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                    phase1="fast_provisioning=1 fast_pac_format=binary",
                    pac_file=pac_file2)
        dev[1].request("REMOVE_NETWORK all")
        eap_connect(dev[1], apdev[0], "FAST", "user",
                    anonymous_identity="FAST", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                    phase1="fast_pac_format=binary",
                    pac_file=pac_file2)
    finally:
        try:
            os.remove(pac_file)
        except:
            pass
        try:
            os.remove(pac_file2)
        except:
            pass

def test_ap_wpa2_eap_fast_binary_pac(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST and binary PAC format"""
    check_eap_capa(dev[0], "FAST")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "FAST", "user",
                anonymous_identity="FAST", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                phase1="fast_provisioning=1 fast_max_pac_list_len=1 fast_pac_format=binary",
                pac_file="blob://fast_pac_bin")
    res = eap_reauth(dev[0], "FAST")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-FAST could not use PAC session ticket")

def test_ap_wpa2_eap_fast_missing_pac_config(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST and missing PAC config"""
    check_eap_capa(dev[0], "FAST")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="FAST",
                   identity="user", anonymous_identity="FAST",
                   password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                   pac_file="blob://fast_pac_not_in_use",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")
    dev[0].request("REMOVE_NETWORK all")

    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="FAST",
                   identity="user", anonymous_identity="FAST",
                   password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                   wait_connect=False, scan_freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")

def test_ap_wpa2_eap_fast_gtc_auth_prov(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST/GTC and authenticated provisioning"""
    check_eap_capa(dev[0], "FAST")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "FAST", "user",
                anonymous_identity="FAST", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=GTC",
                phase1="fast_provisioning=2", pac_file="blob://fast_pac_auth")
    hwsim_utils.test_connectivity(dev[0], hapd)
    res = eap_reauth(dev[0], "FAST")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-FAST could not use PAC session ticket")

def test_ap_wpa2_eap_fast_gtc_identity_change(dev, apdev):
    """WPA2-Enterprise connection using EAP-FAST/GTC and identity changing"""
    check_eap_capa(dev[0], "FAST")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    id = eap_connect(dev[0], apdev[0], "FAST", "user",
                     anonymous_identity="FAST", password="password",
                     ca_cert="auth_serv/ca.pem", phase2="auth=GTC",
                     phase1="fast_provisioning=2",
                     pac_file="blob://fast_pac_auth")
    dev[0].set_network_quoted(id, "identity", "user2")
    dev[0].wait_disconnected()
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=15)
    if ev is None:
        raise Exception("EAP-FAST not started")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=5)
    if ev is None:
        raise Exception("EAP failure not reported")
    dev[0].wait_disconnected()

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

def test_ap_wpa2_eap_ttls_ocsp_revoked(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-TTLS and OCSP status revoked"""
    ocsp = os.path.join(params['logdir'], "ocsp-server-cache-revoked.der")
    if not os.path.exists(ocsp):
        raise HwsimSkip("No OCSP response available")
    params = int_eap_server_params()
    params["ocsp_stapling_response"] = ocsp
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="pap user", ca_cert="auth_serv/ca.pem",
                   anonymous_identity="ttls", password="password",
                   phase2="auth=PAP", ocsp=2,
                   wait_connect=False, scan_freq="2412")
    count = 0
    while True:
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-STATUS"])
        if ev is None:
            raise Exception("Timeout on EAP status")
        if 'bad certificate status response' in ev:
            break
        if 'certificate revoked' in ev:
            break
        count = count + 1
        if count > 10:
            raise Exception("Unexpected number of EAP status messages")

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"])
    if ev is None:
        raise Exception("Timeout on EAP failure report")

def test_ap_wpa2_eap_ttls_ocsp_unknown(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-TTLS and OCSP status revoked"""
    ocsp = os.path.join(params['logdir'], "ocsp-server-cache-unknown.der")
    if not os.path.exists(ocsp):
        raise HwsimSkip("No OCSP response available")
    params = int_eap_server_params()
    params["ocsp_stapling_response"] = ocsp
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="pap user", ca_cert="auth_serv/ca.pem",
                   anonymous_identity="ttls", password="password",
                   phase2="auth=PAP", ocsp=2,
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

def test_ap_wpa2_eap_ttls_optional_ocsp_unknown(dev, apdev, params):
    """WPA2-Enterprise connection using EAP-TTLS and OCSP status revoked"""
    ocsp = os.path.join(params['logdir'], "ocsp-server-cache-unknown.der")
    if not os.path.exists(ocsp):
        raise HwsimSkip("No OCSP response available")
    params = int_eap_server_params()
    params["ocsp_stapling_response"] = ocsp
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="pap user", ca_cert="auth_serv/ca.pem",
                   anonymous_identity="ttls", password="password",
                   phase2="auth=PAP", ocsp=1, scan_freq="2412")

def test_ap_wpa2_eap_tls_domain_suffix_match_cn_full(dev, apdev):
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

def test_ap_wpa2_eap_tls_domain_match_cn(dev, apdev):
    """WPA2-Enterprise using EAP-TLS and domainmatch (CN)"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-no-dnsname.pem"
    params["private_key"] = "auth_serv/server-no-dnsname.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever",
                   domain_match="server3.w1.fi",
                   scan_freq="2412")

def test_ap_wpa2_eap_tls_domain_suffix_match_cn(dev, apdev):
    """WPA2-Enterprise using EAP-TLS and domain suffix match (CN)"""
    check_domain_match_full(dev[0])
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-no-dnsname.pem"
    params["private_key"] = "auth_serv/server-no-dnsname.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
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

def test_ap_wpa2_eap_tls_domain_mismatch_cn(dev, apdev):
    """WPA2-Enterprise using EAP-TLS and domain mismatch (CN)"""
    params = int_eap_server_params()
    params["server_cert"] = "auth_serv/server-no-dnsname.pem"
    params["private_key"] = "auth_serv/server-no-dnsname.key"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever",
                   domain_match="example.com",
                   wait_connect=False,
                   scan_freq="2412")
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user", ca_cert="auth_serv/ca.pem",
                   private_key="auth_serv/user.pkcs12",
                   private_key_passwd="whatever",
                   domain_match="w1.fi",
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
    check_hlr_auc_gw_support()
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

def test_ap_wpa2_eap_sql(dev, apdev, params):
    """WPA2-Enterprise connection using SQLite for user DB"""
    try:
        import sqlite3
    except ImportError:
        raise HwsimSkip("No sqlite3 module available")
    dbfile = os.path.join(params['logdir'], "eap-user.db")
    try:
        os.remove(dbfile)
    except:
        pass
    con = sqlite3.connect(dbfile)
    with con:
        cur = con.cursor()
        cur.execute("CREATE TABLE users(identity TEXT PRIMARY KEY, methods TEXT, password TEXT, remediation TEXT, phase2 INTEGER)")
        cur.execute("CREATE TABLE wildcards(identity TEXT PRIMARY KEY, methods TEXT)")
        cur.execute("INSERT INTO users(identity,methods,password,phase2) VALUES ('user-pap','TTLS-PAP','password',1)")
        cur.execute("INSERT INTO users(identity,methods,password,phase2) VALUES ('user-chap','TTLS-CHAP','password',1)")
        cur.execute("INSERT INTO users(identity,methods,password,phase2) VALUES ('user-mschap','TTLS-MSCHAP','password',1)")
        cur.execute("INSERT INTO users(identity,methods,password,phase2) VALUES ('user-mschapv2','TTLS-MSCHAPV2','password',1)")
        cur.execute("INSERT INTO wildcards(identity,methods) VALUES ('','TTLS,TLS')")
        cur.execute("CREATE TABLE authlog(timestamp TEXT, session TEXT, nas_ip TEXT, username TEXT, note TEXT)")

    try:
        params = int_eap_server_params()
        params["eap_user_file"] = "sqlite:" + dbfile
        hostapd.add_ap(apdev[0]['ifname'], params)
        eap_connect(dev[0], apdev[0], "TTLS", "user-mschapv2",
                    anonymous_identity="ttls", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
        dev[0].request("REMOVE_NETWORK all")
        eap_connect(dev[1], apdev[0], "TTLS", "user-mschap",
                    anonymous_identity="ttls", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP")
        dev[1].request("REMOVE_NETWORK all")
        eap_connect(dev[0], apdev[0], "TTLS", "user-chap",
                    anonymous_identity="ttls", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=CHAP")
        eap_connect(dev[1], apdev[0], "TTLS", "user-pap",
                    anonymous_identity="ttls", password="password",
                    ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
    finally:
        os.remove(dbfile)

def test_ap_wpa2_eap_non_ascii_identity(dev, apdev):
    """WPA2-Enterprise connection attempt using non-ASCII identity"""
    params = int_eap_server_params()
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="\x80", password="password", wait_connect=False)
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="a\x80", password="password", wait_connect=False)
    for i in range(0, 2):
        ev = dev[i].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
        if ev is None:
            raise Exception("Association and EAP start timed out")
        ev = dev[i].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
        if ev is None:
            raise Exception("EAP method selection timed out")

def test_ap_wpa2_eap_non_ascii_identity2(dev, apdev):
    """WPA2-Enterprise connection attempt using non-ASCII identity"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="\x80", password="password", wait_connect=False)
    dev[1].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="a\x80", password="password", wait_connect=False)
    for i in range(0, 2):
        ev = dev[i].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
        if ev is None:
            raise Exception("Association and EAP start timed out")
        ev = dev[i].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
        if ev is None:
            raise Exception("EAP method selection timed out")

def test_openssl_cipher_suite_config_wpas(dev, apdev):
    """OpenSSL cipher suite configuration on wpa_supplicant"""
    tls = dev[0].request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("TLS library is not OpenSSL: " + tls)
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                openssl_ciphers="AES128",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
    eap_connect(dev[1], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                openssl_ciphers="EXPORT",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                expect_failure=True)

def test_openssl_cipher_suite_config_hapd(dev, apdev):
    """OpenSSL cipher suite configuration on hostapd"""
    tls = dev[0].request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("wpa_supplicant TLS library is not OpenSSL: " + tls)
    params = int_eap_server_params()
    params['openssl_ciphers'] = "AES256"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    tls = hapd.request("GET tls_library")
    if not tls.startswith("OpenSSL"):
        raise HwsimSkip("hostapd TLS library is not OpenSSL: " + tls)
    eap_connect(dev[0], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
    eap_connect(dev[1], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                openssl_ciphers="AES128",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                expect_failure=True)
    eap_connect(dev[2], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                openssl_ciphers="HIGH:!ADH",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP")

def test_wpa2_eap_ttls_pap_key_lifetime_in_memory(dev, apdev, params):
    """Key lifetime in memory with WPA2-Enterprise using EAP-TTLS/PAP"""
    p = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], p)
    password = "63d2d21ac3c09ed567ee004a34490f1d16e7fa5835edf17ddba70a63f1a90a25"
    pid = find_wpas_process(dev[0])
    id = eap_connect(dev[0], apdev[0], "TTLS", "pap-secret",
                     anonymous_identity="ttls", password=password,
                     ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
    time.sleep(1)
    buf = read_process_memory(pid, password)

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].relog()
    msk = None
    emsk = None
    pmk = None
    ptk = None
    gtk = None
    with open(os.path.join(params['logdir'], 'log0'), 'r') as f:
        for l in f.readlines():
            if "EAP-TTLS: Derived key - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                msk = binascii.unhexlify(val)
            if "EAP-TTLS: Derived EMSK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                emsk = binascii.unhexlify(val)
            if "WPA: PMK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                pmk = binascii.unhexlify(val)
            if "WPA: PTK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                ptk = binascii.unhexlify(val)
            if "WPA: Group Key - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                gtk = binascii.unhexlify(val)
    if not msk or not emsk or not pmk or not ptk or not gtk:
        raise Exception("Could not find keys from debug log")
    if len(gtk) != 16:
        raise Exception("Unexpected GTK length")

    kck = ptk[0:16]
    kek = ptk[16:32]
    tk = ptk[32:48]

    fname = os.path.join(params['logdir'],
                         'wpa2_eap_ttls_pap_key_lifetime_in_memory.memctx-')

    logger.info("Checking keys in memory while associated")
    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    get_key_locations(buf, msk, "MSK")
    get_key_locations(buf, emsk, "EMSK")
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

    logger.info("Checking keys in memory after disassociation")
    buf = read_process_memory(pid, password)

    # Note: Password is still present in network configuration
    # Note: PMK is in PMKSA cache and EAP fast re-auth data

    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    get_key_locations(buf, msk, "MSK")
    get_key_locations(buf, emsk, "EMSK")
    verify_not_present(buf, kck, fname, "KCK")
    verify_not_present(buf, kek, fname, "KEK")
    verify_not_present(buf, tk, fname, "TK")
    verify_not_present(buf, gtk, fname, "GTK")

    dev[0].request("PMKSA_FLUSH")
    dev[0].set_network_quoted(id, "identity", "foo")
    logger.info("Checking keys in memory after PMKSA cache and EAP fast reauth flush")
    buf = read_process_memory(pid, password)
    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    get_key_locations(buf, msk, "MSK")
    get_key_locations(buf, emsk, "EMSK")
    verify_not_present(buf, pmk, fname, "PMK")

    dev[0].request("REMOVE_NETWORK all")

    logger.info("Checking keys in memory after network profile removal")
    buf = read_process_memory(pid, password)

    get_key_locations(buf, password, "Password")
    get_key_locations(buf, pmk, "PMK")
    get_key_locations(buf, msk, "MSK")
    get_key_locations(buf, emsk, "EMSK")
    verify_not_present(buf, password, fname, "password")
    verify_not_present(buf, pmk, fname, "PMK")
    verify_not_present(buf, kck, fname, "KCK")
    verify_not_present(buf, kek, fname, "KEK")
    verify_not_present(buf, tk, fname, "TK")
    verify_not_present(buf, gtk, fname, "GTK")
    verify_not_present(buf, msk, fname, "MSK")
    verify_not_present(buf, emsk, fname, "EMSK")

def test_ap_wpa2_eap_unexpected_wep_eapol_key(dev, apdev):
    """WPA2-Enterprise connection and unexpected WEP EAPOL-Key"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    eap_connect(dev[0], apdev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP")

    # Send unexpected WEP EAPOL-Key; this gets dropped
    res = dev[0].request("EAPOL_RX " + bssid + " 0203002c0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    if "OK" not in res:
        raise Exception("EAPOL_RX to wpa_supplicant failed")

def test_ap_wpa2_eap_in_bridge(dev, apdev):
    """WPA2-EAP and wpas interface in a bridge"""
    br_ifname='sta-br0'
    ifname='wlan5'
    try:
        _test_ap_wpa2_eap_in_bridge(dev, apdev)
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'down'])
        subprocess.call(['brctl', 'delif', br_ifname, ifname])
        subprocess.call(['brctl', 'delbr', br_ifname])
        subprocess.call(['iw', ifname, 'set', '4addr', 'off'])

def _test_ap_wpa2_eap_in_bridge(dev, apdev):
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    br_ifname='sta-br0'
    ifname='wlan5'
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    subprocess.call(['brctl', 'addbr', br_ifname])
    subprocess.call(['brctl', 'setfd', br_ifname, '0'])
    subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'up'])
    subprocess.call(['iw', ifname, 'set', '4addr', 'on'])
    subprocess.check_call(['brctl', 'addif', br_ifname, ifname])
    wpas.interface_add(ifname, br_ifname=br_ifname)

    id = eap_connect(wpas, apdev[0], "PAX", "pax.user@example.com",
                     password_hex="0123456789abcdef0123456789abcdef")
    eap_reauth(wpas, "PAX")
    # Try again as a regression test for packet socket workaround
    eap_reauth(wpas, "PAX")
    wpas.request("DISCONNECT")
    wpas.wait_disconnected()
    wpas.request("RECONNECT")
    wpas.wait_connected()
