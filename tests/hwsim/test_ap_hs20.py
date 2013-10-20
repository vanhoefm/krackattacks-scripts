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
logger = logging.getLogger(__name__)
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

def test_ap_hs20_select(dev, apdev):
    """Hotspot 2.0 network selection"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET interworking 1")
    dev[0].request("SET hs20 1")

    id = dev[0].add_cred()
    dev[0].set_cred_quoted(id, "realm", "example.com");
    dev[0].set_cred_quoted(id, "username", "test");
    dev[0].set_cred_quoted(id, "password", "secret");
    dev[0].set_cred_quoted(id, "domain", "example.com");

    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT")
    ev = dev[0].wait_event(["INTERWORKING-AP", "INTERWORKING-NO-MATCH"],
                           timeout=15)
    if ev is None:
        raise Exception("Network selection timed out");
    if "INTERWORKING-NO-MATCH" in ev:
        raise Exception("Matching network not found")
    if bssid not in ev:
        raise Exception("Unexpected BSSID in match")
    if "type=home" not in ev:
        raise Exception("Home network not recognized")

    dev[0].remove_cred(id)
    id = dev[0].add_cred()
    dev[0].set_cred_quoted(id, "realm", "example.com")
    dev[0].set_cred_quoted(id, "username", "test")
    dev[0].set_cred_quoted(id, "password", "secret")
    dev[0].set_cred_quoted(id, "domain", "no.match.example.com")
    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT")
    ev = dev[0].wait_event(["INTERWORKING-AP", "INTERWORKING-NO-MATCH"],
                           timeout=15)
    if ev is None:
        raise Exception("Network selection timed out");
    if "INTERWORKING-NO-MATCH" in ev:
        raise Exception("Matching network not found")
    if bssid not in ev:
        raise Exception("Unexpected BSSID in match")
    if "type=roaming" not in ev:
        raise Exception("Roaming network not recognized")

    dev[0].set_cred_quoted(id, "realm", "no.match.example.com");
    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT")
    ev = dev[0].wait_event(["INTERWORKING-AP", "INTERWORKING-NO-MATCH"],
                           timeout=15)
    if ev is None:
        raise Exception("Network selection timed out");
    if "INTERWORKING-NO-MATCH" not in ev:
        raise Exception("Unexpected network match")

def test_ap_hs20_ext_sim(dev, apdev):
    """Hotspot 2.0 with external SIM processing"""
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    if not os.path.exists("../../hostapd/hlr_auc_gw"):
        logger.info("No hlr_auc_gw available");
        return "skip"
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    params['anqp_3gpp_cell_net'] = "232,01"
    params['domain_name'] = "wlan.mnc001.mcc232.3gppnetwork.org"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET interworking 1")
    dev[0].request("SET hs20 1")
    dev[0].request("SET external_sim 1")

    id = dev[0].add_cred()
    dev[0].set_cred_quoted(id, "imsi", "23201-0000000000")
    dev[0].set_cred(id, "eap", "SIM")

    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT")
    ev = dev[0].wait_event(["INTERWORKING-AP", "INTERWORKING-NO-MATCH"],
                           timeout=15)
    if ev is None:
        raise Exception("Network selection timed out")
    if "INTERWORKING-NO-MATCH" in ev:
        raise Exception("Matching network not found")
    if bssid not in ev:
        raise Exception("Unexpected BSSID in match")
    if "type=home" not in ev:
        raise Exception("Home network not recognized")

    dev[0].request("INTERWORKING_CONNECT " + bssid)

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=15)
    if ev is None:
        raise Exception("Network connected timed out")
    if "(SIM)" not in ev:
        raise Exception("Unexpected EAP method selection")

    ev = dev[0].wait_event(["CTRL-REQ-SIM"], timeout=15)
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

    dev[0].request("CTRL-RSP-SIM-" + id + ":GSM-AUTH:" + resp)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
