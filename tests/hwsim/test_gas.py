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
from wpasupplicant import WpaSupplicant

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

def get_gas_response(dev, bssid, info, allow_fetch_failure=False,
                     extra_test=False):
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

    if extra_test:
        if "FAIL" not in dev.request("GAS_RESPONSE_GET " + bssid + " 123456"):
            raise Exception("Invalid dialog token accepted")
        if "FAIL-Invalid range" not in dev.request("GAS_RESPONSE_GET " + bssid + " " + token + " 10000,10001"):
            raise Exception("Invalid range accepted")
        if "FAIL-Invalid range" not in dev.request("GAS_RESPONSE_GET " + bssid + " " + token + " 0,10000"):
            raise Exception("Invalid range accepted")
        if "FAIL" not in dev.request("GAS_RESPONSE_GET " + bssid + " " + token + " 0"):
            raise Exception("Invalid GAS_RESPONSE_GET accepted")

        res1_2 = dev.request("GAS_RESPONSE_GET " + bssid + " " + token + " 1,2")
        res5_3 = dev.request("GAS_RESPONSE_GET " + bssid + " " + token + " 5,3")

    resp = dev.request("GAS_RESPONSE_GET " + bssid + " " + token)
    if "FAIL" in resp:
        if allow_fetch_failure:
            logger.debug("GAS response was not available anymore")
            return
        raise Exception("Could not fetch GAS response")
    if len(resp) != int(resp_len) * 2:
        raise Exception("Unexpected GAS response length")
    logger.debug("GAS response: " + resp)
    if extra_test:
        if resp[2:6] != res1_2:
            raise Exception("Unexpected response substring res1_2: " + res1_2)
        if resp[10:16] != res5_3:
            raise Exception("Unexpected response substring res5_3: " + res5_3)

def test_gas_generic(dev, apdev):
    """Generic GAS query"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    cmds = [ "foo",
             "00:11:22:33:44:55",
             "00:11:22:33:44:55 ",
             "00:11:22:33:44:55  ",
             "00:11:22:33:44:55 1",
             "00:11:22:33:44:55 1 1234",
             "00:11:22:33:44:55 qq",
             "00:11:22:33:44:55 qq 1234",
             "00:11:22:33:44:55 00      1",
             "00:11:22:33:44:55 00 123",
             "00:11:22:33:44:55 00 ",
             "00:11:22:33:44:55 00 qq" ]
    for cmd in cmds:
        if "FAIL" not in dev[0].request("GAS_REQUEST " + cmd):
            raise Exception("Invalid GAS_REQUEST accepted: " + cmd)

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
    req = dev[0].request("GAS_REQUEST " + bssid + " 00 000102000101")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    ev = dev[0].wait_event(["GAS-RESPONSE-INFO"], timeout=10)
    if ev is None:
        raise Exception("GAS query timed out")
    get_gas_response(dev[0], bssid, ev, extra_test=True)

    if "FAIL" not in dev[0].request("GAS_RESPONSE_GET ff"):
        raise Exception("Invalid GAS_RESPONSE_GET accepted")

def test_gas_concurrent_scan(dev, apdev):
    """Generic GAS queries with concurrent scan operation"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    # get BSS entry available to allow GAS query
    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)

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

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)

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
    dev[0].wait_disconnected(timeout=5)

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

    ev = dev[0].wait_connected(timeout=20, error="Operation tiemd out")
    if "CTRL-EVENT-CONNECTED" not in ev:
        raise Exception("Unexpected operation order")

def test_gas_fragment(dev, apdev):
    """GAS fragmentation"""
    hapd = start_ap(apdev[0])
    hapd.set("gas_frag_limit", "50")

    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    dev[0].request("FETCH_ANQP")
    for i in range(0, 13):
        ev = dev[0].wait_event(["RX-ANQP", "RX-HS20-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")

def test_gas_comeback_delay(dev, apdev):
    """GAS fragmentation"""
    hapd = start_ap(apdev[0])
    hapd.set("gas_comeback_delay", "500")

    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    dev[0].request("FETCH_ANQP")
    for i in range(0, 6):
        ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")

def test_gas_stop_fetch_anqp(dev, apdev):
    """Stop FETCH_ANQP operation"""
    hapd = start_ap(apdev[0])

    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412", force_scan=True)
    hapd.set("ext_mgmt_frame_handling", "1")
    dev[0].request("FETCH_ANQP")
    dev[0].request("STOP_FETCH_ANQP")
    hapd.set("ext_mgmt_frame_handling", "0")
    ev = dev[0].wait_event(["RX-ANQP", "GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("GAS-QUERY-DONE timed out")
    if "RX-ANQP" in ev:
        raise Exception("Unexpected ANQP response received")

def test_gas_anqp_get(dev, apdev):
    """GAS/ANQP query for both IEEE 802.11 and Hotspot 2.0 elements"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
    if "OK" not in dev[0].request("ANQP_GET " + bssid + " 258,268,hs20:3,hs20:4"):
        raise Exception("ANQP_GET command failed")

    ev = dev[0].wait_event(["GAS-QUERY-START"], timeout=5)
    if ev is None:
        raise Exception("GAS query start timed out")

    ev = dev[0].wait_event(["GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("GAS query timed out")

    ev = dev[0].wait_event(["RX-ANQP"], timeout=1)
    if ev is None or "Venue Name" not in ev:
        raise Exception("Did not receive Venue Name")

    ev = dev[0].wait_event(["RX-ANQP"], timeout=1)
    if ev is None or "Domain Name list" not in ev:
        raise Exception("Did not receive Domain Name list")

    ev = dev[0].wait_event(["RX-HS20-ANQP"], timeout=1)
    if ev is None or "Operator Friendly Name" not in ev:
        raise Exception("Did not receive Operator Friendly Name")

    ev = dev[0].wait_event(["RX-HS20-ANQP"], timeout=1)
    if ev is None or "WAN Metrics" not in ev:
        raise Exception("Did not receive WAN Metrics")

    ev = dev[0].wait_event(["ANQP-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("ANQP-QUERY-DONE event not seen")
    if "result=SUCCESS" not in ev:
        raise Exception("Unexpected result: " + ev)

    if "OK" not in dev[0].request("HS20_ANQP_GET " + bssid + " 3,4"):
        raise Exception("ANQP_GET command failed")

    ev = dev[0].wait_event(["RX-HS20-ANQP"], timeout=1)
    if ev is None or "Operator Friendly Name" not in ev:
        raise Exception("Did not receive Operator Friendly Name")

    ev = dev[0].wait_event(["RX-HS20-ANQP"], timeout=1)
    if ev is None or "WAN Metrics" not in ev:
        raise Exception("Did not receive WAN Metrics")

    cmds = [ "",
             "foo",
             "00:11:22:33:44:55 258,hs20:-1",
             "00:11:22:33:44:55 258,hs20:0",
             "00:11:22:33:44:55 258,hs20:32",
             "00:11:22:33:44:55 hs20:-1",
             "00:11:22:33:44:55 hs20:0",
             "00:11:22:33:44:55 hs20:32",
             "00:11:22:33:44:55",
             "00:11:22:33:44:55 ",
             "00:11:22:33:44:55 0" ]
    for cmd in cmds:
        if "FAIL" not in dev[0].request("ANQP_GET " + cmd):
            raise Exception("Invalid ANQP_GET accepted")

    cmds = [ "",
             "foo",
             "00:11:22:33:44:55 -1",
             "00:11:22:33:44:55 0",
             "00:11:22:33:44:55 32",
             "00:11:22:33:44:55",
             "00:11:22:33:44:55 ",
             "00:11:22:33:44:55 0" ]
    for cmd in cmds:
        if "FAIL" not in dev[0].request("HS20_ANQP_GET " + cmd):
            raise Exception("Invalid HS20_ANQP_GET accepted")

def expect_gas_result(dev, result, status=None):
    ev = dev.wait_event(["GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("GAS query timed out")
    if "result=" + result not in ev:
        raise Exception("Unexpected GAS query result")
    if status and "status_code=" + str(status) + ' ' not in ev:
        raise Exception("Unexpected GAS status code")

def anqp_get(dev, bssid, id):
    if "OK" not in dev.request("ANQP_GET " + bssid + " " + str(id)):
        raise Exception("ANQP_GET command failed")
    ev = dev.wait_event(["GAS-QUERY-START"], timeout=5)
    if ev is None:
        raise Exception("GAS query start timed out")

def test_gas_timeout(dev, apdev):
    """GAS timeout"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
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

def anqp_initial_resp(dialog_token, status_code, comeback_delay=0):
    return struct.pack('<BBBHH', ACTION_CATEG_PUBLIC, GAS_INITIAL_RESPONSE,
                       dialog_token, status_code, comeback_delay) + anqp_adv_proto()

def anqp_comeback_resp(dialog_token, status_code=0, id=0, more=False, comeback_delay=0, bogus_adv_proto=False):
    if more:
        id |= 0x80
    if bogus_adv_proto:
        adv = struct.pack('BBBB', 108, 2, 127, 1)
    else:
        adv = anqp_adv_proto()
    return struct.pack('<BBBHBH', ACTION_CATEG_PUBLIC, GAS_COMEBACK_RESPONSE,
                       dialog_token, status_code, id, comeback_delay) + adv

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

    if len(pos) < 1 and action != GAS_COMEBACK_REQUEST:
        return None

    gas['dialog_token'] = dialog_token

    if action == GAS_INITIAL_RESPONSE:
        if len(pos) < 4:
            return None
        (status_code, comeback_delay) = struct.unpack('<HH', pos[0:4])
        gas['status_code'] = status_code
        gas['comeback_delay'] = comeback_delay

    if action == GAS_COMEBACK_RESPONSE:
        if len(pos) < 5:
            return None
        (status_code, frag, comeback_delay) = struct.unpack('<HBH', pos[0:5])
        gas['status_code'] = status_code
        gas['frag'] = frag
        gas['comeback_delay'] = comeback_delay

    return gas

def action_response(req):
    resp = {}
    resp['fc'] = req['fc']
    resp['da'] = req['sa']
    resp['sa'] = req['da']
    resp['bssid'] = req['bssid']
    return resp

def send_gas_resp(hapd, resp):
    hapd.mgmt_tx(resp)
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("Missing TX status for GAS response")
    if "ok=1" not in ev:
        raise Exception("GAS response not acknowledged")

def test_gas_invalid_response_type(dev, apdev):
    """GAS invalid response type"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
    hapd.set("ext_mgmt_frame_handling", "1")

    anqp_get(dev[0], bssid, 263)

    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])

    resp = action_response(query)
    # GAS Comeback Response instead of GAS Initial Response
    resp['payload'] = anqp_comeback_resp(gas['dialog_token']) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)

    # station drops the invalid frame, so this needs to result in GAS timeout
    expect_gas_result(dev[0], "TIMEOUT")

def test_gas_failure_status_code(dev, apdev):
    """GAS failure status code"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
    hapd.set("ext_mgmt_frame_handling", "1")

    anqp_get(dev[0], bssid, 263)

    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])

    resp = action_response(query)
    resp['payload'] = anqp_initial_resp(gas['dialog_token'], 61) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)

    expect_gas_result(dev[0], "FAILURE")

def test_gas_malformed(dev, apdev):
    """GAS malformed response frames"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
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
    # part of the response is not valid. This is reported as successfully
    # completed GAS exchange.
    expect_gas_result(dev[0], "SUCCESS")

    ev = dev[0].wait_event(["ANQP-QUERY-DONE"], timeout=5)
    if ev is None:
        raise Exception("ANQP-QUERY-DONE not reported")
    if "result=INVALID_FRAME" not in ev:
        raise Exception("Unexpected result: " + ev)

def init_gas(hapd, bssid, dev):
    anqp_get(dev, bssid, 263)
    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])
    dialog_token = gas['dialog_token']

    resp = action_response(query)
    resp['payload'] = anqp_initial_resp(dialog_token, 0, comeback_delay=1) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)

    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])
    if gas['action'] != GAS_COMEBACK_REQUEST:
        raise Exception("Unexpected request action")
    if gas['dialog_token'] != dialog_token:
        raise Exception("Unexpected dialog token change")
    return query, dialog_token

def test_gas_malformed_comeback_resp(dev, apdev):
    """GAS malformed comeback response frames"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
    hapd.set("ext_mgmt_frame_handling", "1")

    logger.debug("Non-zero status code in comeback response")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token, status_code=2) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    expect_gas_result(dev[0], "FAILURE", status=2)

    logger.debug("Different advertisement protocol in comeback response")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token, bogus_adv_proto=True) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    expect_gas_result(dev[0], "PEER_ERROR")

    logger.debug("Non-zero frag id and comeback delay in comeback response")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token, id=1, comeback_delay=1) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    expect_gas_result(dev[0], "PEER_ERROR")

    logger.debug("Unexpected frag id in comeback response")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token, id=1) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    expect_gas_result(dev[0], "PEER_ERROR")

    logger.debug("Empty fragment and replay in comeback response")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token, more=True) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    query = gas_rx(hapd)
    gas = parse_gas(query['payload'])
    if gas['action'] != GAS_COMEBACK_REQUEST:
        raise Exception("Unexpected request action")
    if gas['dialog_token'] != dialog_token:
        raise Exception("Unexpected dialog token change")
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    resp['payload'] = anqp_comeback_resp(dialog_token, id=1) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    expect_gas_result(dev[0], "SUCCESS")

    logger.debug("Unexpected initial response when waiting for comeback response")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = anqp_initial_resp(dialog_token, 0) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    ev = hapd.wait_event(["MGMT-RX"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected management frame")
    expect_gas_result(dev[0], "TIMEOUT")

    logger.debug("Too short comeback response")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = struct.pack('<BBBH', ACTION_CATEG_PUBLIC,
                                  GAS_COMEBACK_RESPONSE, dialog_token, 0)
    send_gas_resp(hapd, resp)
    ev = hapd.wait_event(["MGMT-RX"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected management frame")
    expect_gas_result(dev[0], "TIMEOUT")

    logger.debug("Too short comeback response(2)")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = struct.pack('<BBBHBB', ACTION_CATEG_PUBLIC,
                                  GAS_COMEBACK_RESPONSE, dialog_token, 0, 0x80,
                                  0)
    send_gas_resp(hapd, resp)
    ev = hapd.wait_event(["MGMT-RX"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected management frame")
    expect_gas_result(dev[0], "TIMEOUT")

    logger.debug("Maximum comeback response fragment claiming more fragments")
    query, dialog_token = init_gas(hapd, bssid, dev[0])
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token, more=True) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    for i in range(1, 129):
        query = gas_rx(hapd)
        gas = parse_gas(query['payload'])
        if gas['action'] != GAS_COMEBACK_REQUEST:
            raise Exception("Unexpected request action")
        if gas['dialog_token'] != dialog_token:
            raise Exception("Unexpected dialog token change")
        resp = action_response(query)
        resp['payload'] = anqp_comeback_resp(dialog_token, id=i, more=True) + struct.pack('<H', 0)
        send_gas_resp(hapd, resp)
    expect_gas_result(dev[0], "PEER_ERROR")

def test_gas_comeback_resp_additional_delay(dev, apdev):
    """GAS comeback response requesting additional delay"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
    hapd.set("ext_mgmt_frame_handling", "1")

    query, dialog_token = init_gas(hapd, bssid, dev[0])
    for i in range(0, 2):
        resp = action_response(query)
        resp['payload'] = anqp_comeback_resp(dialog_token, status_code=95, comeback_delay=50) + struct.pack('<H', 0)
        send_gas_resp(hapd, resp)
        query = gas_rx(hapd)
        gas = parse_gas(query['payload'])
        if gas['action'] != GAS_COMEBACK_REQUEST:
            raise Exception("Unexpected request action")
        if gas['dialog_token'] != dialog_token:
            raise Exception("Unexpected dialog token change")
    resp = action_response(query)
    resp['payload'] = anqp_comeback_resp(dialog_token, status_code=0) + struct.pack('<H', 0)
    send_gas_resp(hapd, resp)
    expect_gas_result(dev[0], "SUCCESS")

def test_gas_unknown_adv_proto(dev, apdev):
    """Unknown advertisement protocol id"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)
    req = dev[0].request("GAS_REQUEST " + bssid + " 42 000102000101")
    if "FAIL" in req:
        raise Exception("GAS query request rejected")
    expect_gas_result(dev[0], "FAILURE", "59")
    ev = dev[0].wait_event(["GAS-RESPONSE-INFO"], timeout=10)
    if ev is None:
        raise Exception("GAS query timed out")
    exp = r'<.>(GAS-RESPONSE-INFO) addr=([0-9a-f:]*) dialog_token=([0-9]*) status_code=([0-9]*) resp_len=([\-0-9]*)'
    res = re.split(exp, ev)
    if len(res) < 6:
        raise Exception("Could not parse GAS-RESPONSE-INFO")
    if res[2] != bssid:
        raise Exception("Unexpected BSSID in response")
    status = res[4]
    if status != "59":
        raise Exception("Unexpected GAS-RESPONSE-INFO status")

def test_gas_max_pending(dev, apdev):
    """GAS and maximum pending query limit"""
    hapd = start_ap(apdev[0])
    hapd.set("gas_frag_limit", "50")
    bssid = apdev[0]['bssid']

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    if "OK" not in wpas.request("P2P_SET listen_channel 1"):
        raise Exception("Failed to set listen channel")
    if "OK" not in wpas.p2p_listen():
        raise Exception("Failed to start listen state")
    if "FAIL" in wpas.request("SET ext_mgmt_frame_handling 1"):
        raise Exception("Failed to enable external management frame handling")

    anqp_query = struct.pack('<HHHHHHHHHH', 256, 16, 257, 258, 260, 261, 262, 263, 264, 268)
    gas = struct.pack('<H', len(anqp_query)) + anqp_query

    for dialog_token in range(1, 10):
        msg = struct.pack('<BBB', ACTION_CATEG_PUBLIC, GAS_INITIAL_REQUEST,
                          dialog_token) + anqp_adv_proto() + gas
        req = "MGMT_TX {} {} freq=2412 wait_time=10 action={}".format(bssid, bssid, binascii.hexlify(msg))
        if "OK" not in wpas.request(req):
            raise Exception("Could not send management frame")
        resp = wpas.mgmt_rx()
        if resp is None:
            raise Exception("MGMT-RX timeout")
        if 'payload' not in resp:
            raise Exception("Missing payload")
        gresp = parse_gas(resp['payload'])
        if gresp['dialog_token'] != dialog_token:
            raise Exception("Dialog token mismatch")
        status_code = gresp['status_code']
        if dialog_token < 9 and status_code != 0:
            raise Exception("Unexpected failure status code {} for dialog token {}".format(status_code, dialog_token))
        if dialog_token > 8 and status_code == 0:
            raise Exception("Unexpected success status code {} for dialog token {}".format(status_code, dialog_token))

def test_gas_no_pending(dev, apdev):
    """GAS and no pending query for comeback request"""
    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    if "OK" not in wpas.request("P2P_SET listen_channel 1"):
        raise Exception("Failed to set listen channel")
    if "OK" not in wpas.p2p_listen():
        raise Exception("Failed to start listen state")
    if "FAIL" in wpas.request("SET ext_mgmt_frame_handling 1"):
        raise Exception("Failed to enable external management frame handling")

    msg = struct.pack('<BBB', ACTION_CATEG_PUBLIC, GAS_COMEBACK_REQUEST, 1)
    req = "MGMT_TX {} {} freq=2412 wait_time=10 action={}".format(bssid, bssid, binascii.hexlify(msg))
    if "OK" not in wpas.request(req):
        raise Exception("Could not send management frame")
    resp = wpas.mgmt_rx()
    if resp is None:
        raise Exception("MGMT-RX timeout")
    if 'payload' not in resp:
        raise Exception("Missing payload")
    gresp = parse_gas(resp['payload'])
    status_code = gresp['status_code']
    if status_code != 60:
        raise Exception("Unexpected status code {} (expected 60)".format(status_code))

def test_gas_missing_payload(dev, apdev):
    """No action code in the query frame"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq="2412", force_scan=True)

    cmd = "MGMT_TX {} {} freq=2412 action=040A".format(bssid, bssid)
    if "FAIL" in dev[0].request(cmd):
        raise Exception("Could not send test Action frame")
    ev = dev[0].wait_event(["MGMT-TX-STATUS"], timeout=10)
    if ev is None:
        raise Exception("Timeout on MGMT-TX-STATUS")
    if "result=SUCCESS" not in ev:
        raise Exception("AP did not ack Action frame")

    cmd = "MGMT_TX {} {} freq=2412 action=04".format(bssid, bssid)
    if "FAIL" in dev[0].request(cmd):
        raise Exception("Could not send test Action frame")
    ev = dev[0].wait_event(["MGMT-TX-STATUS"], timeout=10)
    if ev is None:
        raise Exception("Timeout on MGMT-TX-STATUS")
    if "result=SUCCESS" not in ev:
        raise Exception("AP did not ack Action frame")
