#!/usr/bin/python
#
# GAS tests
# Copyright (c) 2013, Qualcomm Atheros, Inc.
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import binascii
import logging
logger = logging.getLogger()
import re
import struct

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
    params['network_auth_type'] = "02http://www.example.com/redirect/me/here/"
    params['ipaddr_type_availability'] = "14"
    params['hs20'] = "1"
    params['hs20_oper_friendly_name'] = [ "eng:Example operator", "fin:Esimerkkioperaattori" ]
    params['hs20_wan_metrics'] = "01:8000:1000:80:240:3000"
    params['hs20_conn_capab'] = [ "1:0:2", "6:22:1", "17:5060:0" ]
    params['hs20_operating_class'] = "5173"
    return params

def start_ap(ap):
    params = hs20_ap_params()
    params['hessid'] = ap['bssid']
    hostapd.add_ap(ap['ifname'], params)
    return hostapd.Hostapd(ap['ifname'])

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

    dev[0].scan(freq="2412")
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

    # get BSS entry available to allow GAS query
    dev[0].scan(freq="2412")

    logger.info("Request concurrent operations")
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000101")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000801")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    dev[0].scan(no_wait=True)
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

    dev[0].scan(freq="2412")

    logger.debug("Start concurrent connect and GAS request")
    dev[0].connect("test-gas", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="DOMAIN\mschapv2 user", anonymous_identity="ttls",
                   password="password", phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem", wait_connect=False,
                   scan_freq="2412")
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
    dev[0].dump_monitor()

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
    hapd = start_ap(apdev[0])
    hapd.set("gas_frag_limit", "50")

    dev[0].scan(freq="2412")
    dev[0].request("FETCH_ANQP")
    for i in range(0, 13):
        ev = dev[0].wait_event(["RX-ANQP", "RX-HS20-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")

def test_gas_comeback_delay(dev, apdev):
    """GAS fragmentation"""
    hapd = start_ap(apdev[0])
    hapd.set("gas_comeback_delay", "500")

    dev[0].scan(freq="2412")
    dev[0].request("FETCH_ANQP")
    for i in range(0, 6):
        ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")

def expect_gas_result(dev, result):
    ev = dev.wait_event(["GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("GAS query timed out")
    if "result=" + result not in ev:
        raise Exception("Unexpected GAS query result")

def anqp_get(dev, bssid, id):
    dev.request("ANQP_GET " + bssid + " " + str(id))
    ev = dev.wait_event(["GAS-QUERY-START"], timeout=5)
    if ev is None:
        raise Exception("GAS query start timed out")

def test_gas_timeout(dev, apdev):
    """GAS timeout"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan(freq="2412")
    hapd.set("ext_mgmt_frame_handling", "1")

    anqp_get(dev[0], bssid, 263)

    ev = hapd.wait_event(["MGMT-RX"], timeout=5)
    if ev is None:
        raise Exception("MGMT RX wait timed out")

    expect_gas_result(dev[0], "TIMEOUT")

MGMT_SUBTYPE_ACTION = 13
ACTION_CATEG_PUBLIC = 4

GAS_INITIAL_REQUEST = 10
GAS_INITIAL_RESPONSE = 11
GAS_COMEBACK_REQUEST = 12
GAS_COMEBACK_RESPONSE = 13
GAS_ACTIONS = [ GAS_INITIAL_REQUEST, GAS_INITIAL_RESPONSE,
                GAS_COMEBACK_REQUEST, GAS_COMEBACK_RESPONSE ]

def anqp_adv_proto():
    return struct.pack('BBBB', 108, 2, 127, 0)

def anqp_initial_resp(dialog_token, status_code):
    return struct.pack('<BBBHH', ACTION_CATEG_PUBLIC, GAS_INITIAL_RESPONSE,
                       dialog_token, status_code, 0) + anqp_adv_proto()

def anqp_comeback_resp(dialog_token):
    return struct.pack('<BBBHBH', ACTION_CATEG_PUBLIC, GAS_COMEBACK_RESPONSE,
                       dialog_token, 0, 0, 0) + anqp_adv_proto()

def gas_rx(hapd):
    count = 0
    while count < 30:
        count = count + 1
        query = hapd.mgmt_rx()
        if query is None:
            raise Exception("Action frame not received")
        if query['subtype'] != MGMT_SUBTYPE_ACTION:
            continue
        payload = query['payload']
        if len(payload) < 2:
            continue
        (category, action) = struct.unpack('BB', payload[0:2])
        if category != ACTION_CATEG_PUBLIC or action not in GAS_ACTIONS:
            continue
        return query
    raise Exception("No Action frame received")

def parse_gas(payload):
    pos = payload
    (category, action, dialog_token) = struct.unpack('BBB', pos[0:3])
    if category != ACTION_CATEG_PUBLIC:
        return None
    if action not in GAS_ACTIONS:
        return None
    gas = {}
    gas['action'] = action
    pos = pos[3:]

    if len(pos) < 1:
        return None

    gas['dialog_token'] = dialog_token
    return gas

def action_response(req):
    resp = {}
    resp['fc'] = req['fc']
    resp['da'] = req['sa']
    resp['sa'] = req['da']
    resp['bssid'] = req['bssid']
    return resp

def test_gas_invalid_response_type(dev, apdev):
    """GAS invalid response type"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan(freq="2412")
    hapd.set("ext_mgmt_frame_handling", "1")

    anqp_get(dev[0], bssid, 263)

    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])

    resp = action_response(query)
    # GAS Comeback Response instead of GAS Initial Response
    resp['payload'] = anqp_comeback_resp(gas['dialog_token']) + struct.pack('<H', 0)
    hapd.mgmt_tx(resp)
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Missing TX status for GAS response")
    if "ok=1" not in ev:
        raise Exception("GAS response not acknowledged")

    # station drops the invalid frame, so this needs to result in GAS timeout
    expect_gas_result(dev[0], "TIMEOUT")

def test_gas_failure_status_code(dev, apdev):
    """GAS failure status code"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan(freq="2412")
    hapd.set("ext_mgmt_frame_handling", "1")

    anqp_get(dev[0], bssid, 263)

    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])

    resp = action_response(query)
    resp['payload'] = anqp_initial_resp(gas['dialog_token'], 61) + struct.pack('<H', 0)
    hapd.mgmt_tx(resp)
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Missing TX status for GAS response")
    if "ok=1" not in ev:
        raise Exception("GAS response not acknowledged")

    expect_gas_result(dev[0], "FAILURE")

def test_gas_malformed(dev, apdev):
    """GAS malformed response frames"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan(freq="2412")
    hapd.set("ext_mgmt_frame_handling", "1")

    anqp_get(dev[0], bssid, 263)

    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])

    resp = action_response(query)

    resp['payload'] = struct.pack('<BBBH', ACTION_CATEG_PUBLIC,
                                  GAS_COMEBACK_RESPONSE,
                                  gas['dialog_token'], 0)
    hapd.mgmt_tx(resp)

    resp['payload'] = struct.pack('<BBBHB', ACTION_CATEG_PUBLIC,
                                  GAS_COMEBACK_RESPONSE,
                                  gas['dialog_token'], 0, 0)
    hapd.mgmt_tx(resp)

    hdr = struct.pack('<BBBHH', ACTION_CATEG_PUBLIC, GAS_INITIAL_RESPONSE,
                      gas['dialog_token'], 0, 0)
    resp['payload'] = hdr + struct.pack('B', 108)
    hapd.mgmt_tx(resp)
    resp['payload'] = hdr + struct.pack('BB', 108, 0)
    hapd.mgmt_tx(resp)
    resp['payload'] = hdr + struct.pack('BB', 108, 1)
    hapd.mgmt_tx(resp)
    resp['payload'] = hdr + struct.pack('BB', 108, 255)
    hapd.mgmt_tx(resp)
    resp['payload'] = hdr + struct.pack('BBB', 108, 1, 127)
    hapd.mgmt_tx(resp)
    resp['payload'] = hdr + struct.pack('BBB', 108, 2, 127)
    hapd.mgmt_tx(resp)
    resp['payload'] = hdr + struct.pack('BBBB', 0, 2, 127, 0)
    hapd.mgmt_tx(resp)

    resp['payload'] = anqp_initial_resp(gas['dialog_token'], 0) + struct.pack('<H', 1)
    hapd.mgmt_tx(resp)

    resp['payload'] = anqp_initial_resp(gas['dialog_token'], 0) + struct.pack('<HB', 2, 0)
    hapd.mgmt_tx(resp)

    resp['payload'] = anqp_initial_resp(gas['dialog_token'], 0) + struct.pack('<H', 65535)
    hapd.mgmt_tx(resp)

    resp['payload'] = anqp_initial_resp(gas['dialog_token'], 0) + struct.pack('<HBB', 1, 0, 0)
    hapd.mgmt_tx(resp)

    # Station drops invalid frames, but the last of the responses is valid from
    # GAS view point even though it has an extra octet in the end and the ANQP
    # part of the response is not valid. This is reported as successfulyl
    # completed GAS exchange.
    expect_gas_result(dev[0], "SUCCESS")
