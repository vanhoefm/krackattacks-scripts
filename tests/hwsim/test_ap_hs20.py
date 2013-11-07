#!/usr/bin/python
#
# Hotspot 2.0 tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()
import os.path
import subprocess

import hostapd

def hs20_ap_params():
    params = hostapd.wpa2_params(ssid="test-hs20")
    params['wpa_key_mgmt'] = "WPA-EAP"
    params['ieee80211w'] = "1"
    params['ieee8021x'] = "1"
    params['auth_server_addr'] = "127.0.0.1"
    params['auth_server_port'] = "1812"
    params['auth_server_shared_secret'] = "radius"
    params['interworking'] = "1"
    params['access_network_type'] = "14"
    params['internet'] = "1"
    params['asra'] = "0"
    params['esr'] = "0"
    params['uesa'] = "0"
    params['venue_group'] = "7"
    params['venue_type'] = "1"
    params['venue_name'] = [ "eng:Example venue", "fin:Esimerkkipaikka" ]
    params['roaming_consortium'] = [ "112233", "1020304050", "010203040506",
                                     "fedcba" ]
    params['domain_name'] = "example.com,another.example.com"
    params['nai_realm'] = [ "0,example.com,13[5:6],21[2:4][5:7]",
                            "0,another.example.com" ]
    params['hs20'] = "1"
    params['hs20_wan_metrics'] = "01:8000:1000:80:240:3000"
    params['hs20_conn_capab'] = [ "1:0:2", "6:22:1", "17:5060:0" ]
    params['hs20_operating_class'] = "5173"
    params['anqp_3gpp_cell_net'] = "244,91"
    return params

def interworking_select(dev, bssid, type=None, no_match=False):
    dev.dump_monitor()
    dev.request("INTERWORKING_SELECT")
    ev = dev.wait_event(["INTERWORKING-AP", "INTERWORKING-NO-MATCH"],
                        timeout=15)
    if ev is None:
        raise Exception("Network selection timed out");
    if no_match:
        if "INTERWORKING-NO-MATCH" not in ev:
            raise Exception("Unexpected network match")
        return
    if "INTERWORKING-NO-MATCH" in ev:
        raise Exception("Matching network not found")
    if bssid not in ev:
        raise Exception("Unexpected BSSID in match")
    if type and "type=" + type not in ev:
        raise Exception("Network type not recognized correctly")

def check_sp_type(dev, sp_type):
    type = dev.get_status_field("sp_type")
    if type is None:
        raise Exception("sp_type not available")
    if type != sp_type:
        raise Exception("sp_type did not indicate home network")

def hlr_auc_gw_available():
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return False
    if not os.path.exists("../../hostapd/hlr_auc_gw"):
        logger.info("No hlr_auc_gw available");
        return False
    return True

def interworking_ext_sim_connect(dev, bssid, method):
    dev.request("INTERWORKING_CONNECT " + bssid)

    ev = dev.wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=15)
    if ev is None:
        raise Exception("Network connected timed out")
    if "(" + method + ")" not in ev:
        raise Exception("Unexpected EAP method selection")

    ev = dev.wait_event(["CTRL-REQ-SIM"], timeout=15)
    if ev is None:
        raise Exception("Wait for external SIM processing request timed out")
    p = ev.split(':', 2)
    if p[1] != "GSM-AUTH":
        raise Exception("Unexpected CTRL-REQ-SIM type")
    id = p[0].split('-')[3]
    rand = p[2].split(' ')[0]

    res = subprocess.check_output(["../../hostapd/hlr_auc_gw",
                                   "-m",
                                   "auth_serv/hlr_auc_gw.milenage_db",
                                   "GSM-AUTH-REQ 232010000000000 " + rand])
    if "GSM-AUTH-RESP" not in res:
        raise Exception("Unexpected hlr_auc_gw response")
    resp = res.split(' ')[2].rstrip()

    dev.request("CTRL-RSP-SIM-" + id + ":GSM-AUTH:" + resp)
    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")

def interworking_connect(dev, bssid, method):
    dev.request("INTERWORKING_CONNECT " + bssid)

    ev = dev.wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=15)
    if ev is None:
        raise Exception("Network connected timed out")
    if "(" + method + ")" not in ev:
        raise Exception("Unexpected EAP method selection")

    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")

def test_ap_hs20_select(dev, apdev):
    """Hotspot 2.0 network selection"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com", 'username': "test",
                                  'password': "secret",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home")

    dev[0].remove_cred(id)
    id = dev[0].add_cred_values({ 'realm': "example.com", 'username': "test",
                                  'password': "secret",
                                  'domain': "no.match.example.com" })
    interworking_select(dev[0], bssid, "roaming")

    dev[0].set_cred_quoted(id, "realm", "no.match.example.com");
    interworking_select(dev[0], bssid, no_match=True)

def test_ap_hs20_ext_sim(dev, apdev):
    """Hotspot 2.0 with external SIM processing"""
    if not hlr_auc_gw_available():
        return "skip"
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    params['anqp_3gpp_cell_net'] = "232,01"
    params['domain_name'] = "wlan.mnc001.mcc232.3gppnetwork.org"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    dev[0].request("SET external_sim 1")
    dev[0].add_cred_values({ 'imsi': "23201-0000000000", 'eap': "SIM" })
    interworking_select(dev[0], "home")
    interworking_ext_sim_connect(dev[0], bssid, "SIM")
    check_sp_type(dev[0], "home")

def test_ap_hs20_ext_sim_roaming(dev, apdev):
    """Hotspot 2.0 with external SIM processing in roaming network"""
    if not hlr_auc_gw_available():
        return "skip"
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    params['anqp_3gpp_cell_net'] = "244,91;310,026;232,01;234,56"
    params['domain_name'] = "wlan.mnc091.mcc244.3gppnetwork.org"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    dev[0].request("SET external_sim 1")
    dev[0].add_cred_values({ 'imsi': "23201-0000000000", 'eap': "SIM" })
    interworking_select(dev[0], "roaming")
    interworking_ext_sim_connect(dev[0], bssid, "SIM")
    check_sp_type(dev[0], "roaming")

def test_ap_hs20_username(dev, apdev):
    """Hotspot 2.0 connection in username/password credential"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "home")

def test_ap_hs20_username_roaming(dev, apdev):
    """Hotspot 2.0 connection in username/password credential (roaming)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,13[5:6],21[2:4][5:7]",
                            "0,roaming.example.com,21[2:4][5:7]",
                            "0,another.example.com" ]
    params['domain_name'] = "another.example.com"
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "roaming.example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "roaming")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "roaming")

def test_ap_hs20_username_unknown(dev, apdev):
    """Hotspot 2.0 connection in username/password credential (no domain in cred)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password" })
    interworking_select(dev[0], bssid, "unknown")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "unknown")

def test_ap_hs20_username_unknown2(dev, apdev):
    """Hotspot 2.0 connection in username/password credential (no domain advertized)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    del params['domain_name']
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "unknown")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "unknown")

def test_ap_hs20_gas_while_associated(dev, apdev):
    """Hotspot 2.0 connection with GAS query while associated"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home")
    interworking_connect(dev[0], bssid, "TTLS")

    logger.info("Verifying GAS query while associated")
    dev[0].request("FETCH_ANQP")
    for i in range(0, 6):
        ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")

def test_ap_hs20_gas_frag_while_associated(dev, apdev):
    """Hotspot 2.0 connection with fragmented GAS query while associated"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.set("gas_frag_limit", "50")

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home")
    interworking_connect(dev[0], bssid, "TTLS")

    logger.info("Verifying GAS query while associated")
    dev[0].request("FETCH_ANQP")
    for i in range(0, 6):
        ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")

def test_ap_hs20_multiple_connects(dev, apdev):
    """Hotspot 2.0 connection through multiple network selections"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    values = { 'realm': "example.com",
               'username': "hs20-test",
               'password': "password",
               'domain': "example.com" }
    id = dev[0].add_cred_values(values)

    for i in range(0, 3):
        logger.info("Starting Interworking network selection")
        dev[0].request("INTERWORKING_SELECT auto")
        while True:
            ev = dev[0].wait_event(["INTERWORKING-NO-MATCH",
                                    "INTERWORKING-ALREADY-CONNECTED",
                                    "CTRL-EVENT-CONNECTED"], timeout=15)
            if ev is None:
                raise Exception("Connection timed out")
            if "INTERWORKING-NO-MATCH" in ev:
                raise Exception("Matching AP not found")
            if "CTRL-EVENT-CONNECTED" in ev:
                break
            if i == 2 and "INTERWORKING-ALREADY-CONNECTED" in ev:
                break
        if i == 0:
            dev[0].request("DISCONNECT")
        dev[0].dump_monitor()

    networks = dev[0].list_networks()
    if len(networks) > 1:
        raise Exception("Duplicated network block detected")

def test_ap_hs20_disallow_aps(dev, apdev):
    """Hotspot 2.0 connection and disallow_aps"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET ignore_old_scan_res 1")
    dev[0].hs20_enable()
    values = { 'realm': "example.com",
               'username': "hs20-test",
               'password': "password",
               'domain': "example.com" }
    id = dev[0].add_cred_values(values)

    logger.info("Verify disallow_aps bssid")
    dev[0].request("SET disallow_aps bssid " + bssid.translate(None, ':'))
    dev[0].request("INTERWORKING_SELECT auto")
    ev = dev[0].wait_event(["INTERWORKING-NO-MATCH"], timeout=15)
    if ev is None:
        raise Exception("Network selection timed out")
    dev[0].dump_monitor()

    logger.info("Verify disallow_aps ssid")
    dev[0].request("SET disallow_aps ssid 746573742d68733230")
    dev[0].request("INTERWORKING_SELECT auto")
    ev = dev[0].wait_event(["INTERWORKING-NO-MATCH"], timeout=15)
    if ev is None:
        raise Exception("Network selection timed out")
    dev[0].dump_monitor()

    logger.info("Verify disallow_aps clear")
    dev[0].request("SET disallow_aps ")
    interworking_select(dev[0], bssid, "home")

    dev[0].request("SET disallow_aps bssid " + bssid.translate(None, ':'))
    ret = dev[0].request("INTERWORKING_CONNECT " + bssid)
    if "FAIL" not in ret:
        raise Exception("INTERWORKING_CONNECT to disallowed BSS not rejected")

def policy_test(dev, ap, values, only_one=True):
    dev.dump_monitor()
    logger.info("Verify network selection to AP " + ap['ifname'])
    bssid = ap['bssid']
    dev.request("SET ignore_old_scan_res 1")
    dev.hs20_enable()
    id = dev.add_cred_values(values)
    dev.request("INTERWORKING_SELECT auto")
    while True:
        ev = dev.wait_event(["INTERWORKING-AP", "INTERWORKING-NO-MATCH",
                             "CTRL-EVENT-CONNECTED"], timeout=15)
        if ev is None:
            raise Exception("Connection timed out")
        if "INTERWORKING-NO-MATCH" in ev:
            raise Exception("Matching AP not found")
        if only_one and "INTERWORKING-AP" in ev and bssid not in ev:
            raise Exception("Unexpected AP claimed acceptable")
        if "CTRL-EVENT-CONNECTED" in ev:
            if bssid not in ev:
                raise Exception("Connected to incorrect BSS")
            break

    conn_bssid = dev.get_status_field("bssid")
    if conn_bssid != bssid:
        raise Exception("bssid information points to incorrect BSS")

    dev.remove_cred(id)
    dev.dump_monitor()

def default_cred():
    return { 'realm': "example.com",
             'username': "hs20-test",
             'password': "password" }

def test_ap_hs20_req_roaming_consortium(dev, apdev):
    """Hotspot 2.0 required roaming consortium"""
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    params['roaming_consortium'] = [ "223344" ]
    hostapd.add_ap(apdev[1]['ifname'], params)

    values = default_cred()
    values['required_roaming_consortium'] = "223344"
    policy_test(dev[0], apdev[1], values)
    values['required_roaming_consortium'] = "112233"
    policy_test(dev[0], apdev[0], values)

def test_ap_hs20_excluded_ssid(dev, apdev):
    """Hotspot 2.0 exclusion based on SSID"""
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    params['roaming_consortium'] = [ "223344" ]
    hostapd.add_ap(apdev[1]['ifname'], params)

    values = default_cred()
    values['excluded_ssid'] = "test-hs20"
    policy_test(dev[0], apdev[1], values)
    values['excluded_ssid'] = "test-hs20-other"
    policy_test(dev[0], apdev[0], values)
