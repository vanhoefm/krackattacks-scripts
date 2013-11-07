#!/usr/bin/python
#
# GAS tests
# Copyright (c) 2013, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()
import re

import hostapd

def hs20_ap_params():
    params = hostapd.wpa2_params(ssid="test-gas")
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
    params['anqp_3gpp_cell_net'] = "244,91"
    return params

def get_gas_response(dev, bssid, info, allow_fetch_failure=False):
    exp = r'<.>(GAS-RESPONSE-INFO) addr=([0-9a-f:]*) dialog_token=([0-9]*) status_code=([0-9]*) resp_len=([\-0-9]*)'
    res = re.split(exp, info)
    if len(res) < 6:
        raise Exception("Could not parse GAS-RESPONSE-INFO")
    if res[2] != bssid:
        raise Exception("Unexpected BSSID in response")
    token = res[3]
    status = res[4]
    if status != "0":
        raise Exception("GAS query failed")
    resp_len = res[5]
    if resp_len == "-1":
        raise Exception("GAS query reported invalid response length")
    if int(resp_len) > 2000:
        raise Exception("Unexpected long GAS response")

    resp = dev.request("GAS_RESPONSE_GET " + bssid + " " + token)
    if "FAIL" in resp:
        if allow_fetch_failure:
            logger.debug("GAS response was not available anymore")
            return
        raise Exception("Could not fetch GAS response")
    if len(resp) != int(resp_len) * 2:
        raise Exception("Unexpected GAS response length")
    logger.debug("GAS response: " + resp)

def test_gas_generic(dev, apdev):
    """Generic GAS query"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan()
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000101")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    ev = dev[0].wait_event(["GAS-RESPONSE-INFO"], timeout=10)
    if ev is None:
        raise Exception("GAS query timed out")
    get_gas_response(dev[0], bssid, ev)

def test_gas_concurrent_scan(dev, apdev):
    """Generic GAS queries with concurrent scan operation"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan()

    logger.info("Request concurrent operations")
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000101")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000801")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    dev[0].request("SCAN")
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000201")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000501")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")

    responses = 0
    for i in range(0, 5):
        ev = dev[0].wait_event(["GAS-RESPONSE-INFO", "CTRL-EVENT-SCAN-RESULTS"],
                               timeout=10)
        if ev is None:
            raise Exception("Operation timed out")
        if "GAS-RESPONSE-INFO" in ev:
            responses = responses + 1
            get_gas_response(dev[0], bssid, ev, allow_fetch_failure=True)

    if responses != 4:
        raise Exception("Unexpected number of GAS responses")

def test_gas_concurrent_connect(dev, apdev):
    """Generic GAS queries with concurrent connection operation"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan()

    logger.debug("Start concurrent connect and GAS request")
    dev[0].connect("test-gas", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem", wait_connect=False)
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000101")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")

    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED", "GAS-RESPONSE-INFO"],
                           timeout=20)
    if ev is None:
        raise Exception("Operation timed out")
    if "CTRL-EVENT-CONNECTED" not in ev:
        raise Exception("Unexpected operation order")

    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED", "GAS-RESPONSE-INFO"],
                           timeout=20)
    if ev is None:
        raise Exception("Operation timed out")
    if "GAS-RESPONSE-INFO" not in ev:
        raise Exception("Unexpected operation order")
    get_gas_response(dev[0], bssid, ev)

    dev[0].request("DISCONNECT")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Disconnection timed out")

    logger.debug("Wait six seconds for expiration of connect-without-scan")
    time.sleep(6)

    logger.debug("Start concurrent GAS request and connect")
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000101")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    dev[0].request("RECONNECT")

    ev = dev[0].wait_event(["GAS-RESPONSE-INFO"], timeout=10)
    if ev is None:
        raise Exception("Operation timed out")
    get_gas_response(dev[0], bssid, ev)

    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=20)
    if ev is None:
        raise Exception("No new scan results reported")

    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=20)
    if ev is None:
        raise Exception("Operation timed out")
    if "CTRL-EVENT-CONNECTED" not in ev:
        raise Exception("Unexpected operation order")

def test_gas_fragment(dev, apdev):
    """GAS fragmentation"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.set("gas_frag_limit", "50")

    dev[0].scan()
    dev[0].request("FETCH_ANQP")
    for i in range(0, 6):
        ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")
