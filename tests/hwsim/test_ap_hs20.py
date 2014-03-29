# Hotspot 2.0 tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()
import os
import os.path
import subprocess

import hostapd
from wlantest import Wlantest
from wpasupplicant import WpaSupplicant

def hs20_ap_params(ssid="test-hs20"):
    params = hostapd.wpa2_params(ssid=ssid)
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

def check_auto_select(dev, bssid):
    dev.request("INTERWORKING_SELECT auto freq=2412")
    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if bssid not in ev:
        raise Exception("Connected to incorrect network")
    dev.request("REMOVE_NETWORK all")

def interworking_select(dev, bssid, type=None, no_match=False, freq=None):
    dev.dump_monitor()
    freq_extra = " freq=" + freq if freq else ""
    dev.request("INTERWORKING_SELECT" + freq_extra)
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
    if bssid and bssid not in ev:
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
    interworking_ext_sim_auth(dev, method)

def interworking_ext_sim_auth(dev, method):
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
    interworking_auth(dev, method)

def interworking_auth(dev, method):
    ev = dev.wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=15)
    if ev is None:
        raise Exception("Network connected timed out")
    if "(" + method + ")" not in ev:
        raise Exception("Unexpected EAP method selection")

    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")

def check_probe_resp(wt, bssid_unexpected, bssid_expected):
    if bssid_unexpected:
        count = wt.get_bss_counter("probe_response", bssid_unexpected)
        if count > 0:
            raise Exception("Unexpected Probe Response frame from AP")

    if bssid_expected:
        count = wt.get_bss_counter("probe_response", bssid_expected)
        if count == 0:
            raise Exception("No Probe Response frame from AP")

def test_ap_anqp_sharing(dev, apdev):
    """ANQP sharing within ESS and explicit unshare"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    params['nai_realm'] = [ "0,example.com,13[5:6],21[2:4][5:7]" ]
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com", 'username': "test",
                                  'password': "secret",
                                  'domain': "example.com" })
    logger.info("Normal network selection with shared ANQP results")
    interworking_select(dev[0], None, "home", freq="2412")
    dev[0].dump_monitor()

    res1 = dev[0].get_bss(bssid)
    res2 = dev[0].get_bss(bssid2)
    if res1['anqp_nai_realm'] != res2['anqp_nai_realm']:
        raise Exception("ANQP results were not shared between BSSes")

    logger.info("Explicit ANQP request to unshare ANQP results")
    dev[0].request("ANQP_GET " + bssid + " 263")
    ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
    if ev is None:
        raise Exception("ANQP operation timed out")

    dev[0].request("ANQP_GET " + bssid2 + " 263")
    ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
    if ev is None:
        raise Exception("ANQP operation timed out")

    res1 = dev[0].get_bss(bssid)
    res2 = dev[0].get_bss(bssid2)
    if res1['anqp_nai_realm'] == res2['anqp_nai_realm']:
        raise Exception("ANQP results were not unshared")

def test_ap_nai_home_realm_query(dev, apdev):
    """NAI Home Realm Query"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,13[5:6],21[2:4][5:7]",
                            "0,another.example.org" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan(freq="2412")
    dev[0].request("HS20_GET_NAI_HOME_REALM_LIST " + bssid + " realm=example.com")
    ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
    if ev is None:
        raise Exception("ANQP operation timed out")
    nai1 = dev[0].get_bss(bssid)['anqp_nai_realm']
    dev[0].dump_monitor()

    dev[0].request("ANQP_GET " + bssid + " 263")
    ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
    if ev is None:
        raise Exception("ANQP operation timed out")
    nai2 = dev[0].get_bss(bssid)['anqp_nai_realm']

    if len(nai1) >= len(nai2):
        raise Exception("Unexpected NAI Realm list response lengths")
    if "example.com".encode('hex') not in nai1:
        raise Exception("Home realm not reported")
    if "example.org".encode('hex') in nai1:
        raise Exception("Non-home realm reported")
    if "example.com".encode('hex') not in nai2:
        raise Exception("Home realm not reported in wildcard query")
    if "example.org".encode('hex') not in nai2:
        raise Exception("Non-home realm not reported in wildcard query ")

def test_ap_interworking_scan_filtering(dev, apdev):
    """Interworking scan filtering with HESSID and access network type"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    ssid = "test-hs20-ap1"
    params['ssid'] = ssid
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params()
    ssid2 = "test-hs20-ap2"
    params['ssid'] = ssid2
    params['hessid'] = bssid2
    params['access_network_type'] = "1"
    del params['venue_group']
    del params['venue_type']
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].hs20_enable()

    wt = Wlantest()
    wt.flush()

    logger.info("Check probe request filtering based on HESSID")

    dev[0].request("SET hessid " + bssid2)
    dev[0].scan(freq="2412")
    time.sleep(0.03)
    check_probe_resp(wt, bssid, bssid2)

    logger.info("Check probe request filtering based on access network type")

    wt.clear_bss_counters(bssid)
    wt.clear_bss_counters(bssid2)
    dev[0].request("SET hessid 00:00:00:00:00:00")
    dev[0].request("SET access_network_type 14")
    dev[0].scan(freq="2412")
    time.sleep(0.03)
    check_probe_resp(wt, bssid2, bssid)

    wt.clear_bss_counters(bssid)
    wt.clear_bss_counters(bssid2)
    dev[0].request("SET hessid 00:00:00:00:00:00")
    dev[0].request("SET access_network_type 1")
    dev[0].scan(freq="2412")
    time.sleep(0.03)
    check_probe_resp(wt, bssid, bssid2)

    logger.info("Check probe request filtering based on HESSID and ANT")

    wt.clear_bss_counters(bssid)
    wt.clear_bss_counters(bssid2)
    dev[0].request("SET hessid " + bssid)
    dev[0].request("SET access_network_type 14")
    dev[0].scan(freq="2412")
    time.sleep(0.03)
    check_probe_resp(wt, bssid2, bssid)

    wt.clear_bss_counters(bssid)
    wt.clear_bss_counters(bssid2)
    dev[0].request("SET hessid " + bssid2)
    dev[0].request("SET access_network_type 14")
    dev[0].scan(freq="2412")
    time.sleep(0.03)
    check_probe_resp(wt, bssid, None)
    check_probe_resp(wt, bssid2, None)

    wt.clear_bss_counters(bssid)
    wt.clear_bss_counters(bssid2)
    dev[0].request("SET hessid " + bssid)
    dev[0].request("SET access_network_type 1")
    dev[0].scan(freq="2412")
    time.sleep(0.03)
    check_probe_resp(wt, bssid, None)
    check_probe_resp(wt, bssid2, None)

def test_ap_hs20_select(dev, apdev):
    """Hotspot 2.0 network selection"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com", 'username': "test",
                                  'password': "secret",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home")

    dev[0].remove_cred(id)
    id = dev[0].add_cred_values({ 'realm': "example.com", 'username': "test",
                                  'password': "secret",
                                  'domain': "no.match.example.com" })
    interworking_select(dev[0], bssid, "roaming", freq="2412")

    dev[0].set_cred_quoted(id, "realm", "no.match.example.com");
    interworking_select(dev[0], bssid, no_match=True, freq="2412")

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.org,21" ]
    params['hessid'] = bssid2
    params['domain_name'] = "example.org"
    hostapd.add_ap(apdev[1]['ifname'], params)
    dev[0].remove_cred(id)
    id = dev[0].add_cred_values({ 'realm': "example.org", 'username': "test",
                                  'password': "secret",
                                  'domain': "example.org" })
    interworking_select(dev[0], bssid2, "home", freq="2412")

def hs20_simulated_sim(dev, ap, method):
    bssid = ap['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    params['anqp_3gpp_cell_net'] = "555,444"
    params['domain_name'] = "wlan.mnc444.mcc555.3gppnetwork.org"
    hostapd.add_ap(ap['ifname'], params)

    dev.hs20_enable()
    dev.add_cred_values({ 'imsi': "555444-333222111", 'eap': method,
                          'milenage': "5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123"})
    interworking_select(dev, "home", freq="2412")
    interworking_connect(dev, bssid, method)
    check_sp_type(dev, "home")

def test_ap_hs20_sim(dev, apdev):
    """Hotspot 2.0 with simulated SIM and EAP-SIM"""
    if not hlr_auc_gw_available():
        return "skip"
    hs20_simulated_sim(dev[0], apdev[0], "SIM")
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["INTERWORKING-ALREADY-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Timeout on already-connected event")

def test_ap_hs20_aka(dev, apdev):
    """Hotspot 2.0 with simulated USIM and EAP-AKA"""
    if not hlr_auc_gw_available():
        return "skip"
    hs20_simulated_sim(dev[0], apdev[0], "AKA")

def test_ap_hs20_aka_prime(dev, apdev):
    """Hotspot 2.0 with simulated USIM and EAP-AKA'"""
    if not hlr_auc_gw_available():
        return "skip"
    hs20_simulated_sim(dev[0], apdev[0], "AKA'")

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

    dev[0].hs20_enable()
    dev[0].request("SET external_sim 1")
    dev[0].add_cred_values({ 'imsi': "23201-0000000000", 'eap': "SIM" })
    interworking_select(dev[0], "home", freq="2412")
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

    dev[0].hs20_enable()
    dev[0].request("SET external_sim 1")
    dev[0].add_cred_values({ 'imsi': "23201-0000000000", 'eap': "SIM" })
    interworking_select(dev[0], "roaming", freq="2412")
    interworking_ext_sim_connect(dev[0], bssid, "SIM")
    check_sp_type(dev[0], "roaming")

def test_ap_hs20_username(dev, apdev):
    """Hotspot 2.0 connection in username/password credential"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    params['disable_dgaf'] = '1'
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'ca_cert': "auth_serv/ca.pem",
                                  'domain': "example.com",
                                  'update_identifier': "1234" })
    interworking_select(dev[0], bssid, "home", freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "home")
    status = dev[0].get_status()
    if status['pairwise_cipher'] != "CCMP":
        raise Exception("Unexpected pairwise cipher")
    if status['hs20'] != "2":
        raise Exception("Unexpected HS 2.0 support indication")

    dev[1].connect("test-hs20", key_mgmt="WPA-EAP", eap="TTLS",
                   identity="hs20-test", password="password",
                   ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                   scan_freq="2412")

def eap_test(dev, ap, eap_params, method, user):
    bssid = ap['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com," + eap_params ]
    hostapd.add_ap(ap['ifname'], params)

    dev.hs20_enable()
    dev.add_cred_values({ 'realm': "example.com",
                          'username': user,
                          'password': "password" })
    interworking_select(dev, bssid, freq="2412")
    interworking_connect(dev, bssid, method)

def test_ap_hs20_eap_unknown(dev, apdev):
    """Hotspot 2.0 connection with unknown EAP method"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = "0,example.com,99"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values(default_cred())
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_eap_peap_mschapv2(dev, apdev):
    """Hotspot 2.0 connection with PEAP/MSCHAPV2"""
    eap_test(dev[0], apdev[0], "25[3:26]", "PEAP", "user")

def test_ap_hs20_eap_peap_default(dev, apdev):
    """Hotspot 2.0 connection with PEAP/MSCHAPV2 (as default)"""
    eap_test(dev[0], apdev[0], "25", "PEAP", "user")

def test_ap_hs20_eap_peap_gtc(dev, apdev):
    """Hotspot 2.0 connection with PEAP/GTC"""
    eap_test(dev[0], apdev[0], "25[3:6]", "PEAP", "user")

def test_ap_hs20_eap_peap_unknown(dev, apdev):
    """Hotspot 2.0 connection with PEAP/unknown"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = "0,example.com,25[3:99]"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values(default_cred())
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_eap_ttls_chap(dev, apdev):
    """Hotspot 2.0 connection with TTLS/CHAP"""
    eap_test(dev[0], apdev[0], "21[2:2]", "TTLS", "chap user")

def test_ap_hs20_eap_ttls_mschap(dev, apdev):
    """Hotspot 2.0 connection with TTLS/MSCHAP"""
    eap_test(dev[0], apdev[0], "21[2:3]", "TTLS", "mschap user")

def test_ap_hs20_eap_ttls_eap_mschapv2(dev, apdev):
    """Hotspot 2.0 connection with TTLS/EAP-MSCHAPv2"""
    eap_test(dev[0], apdev[0], "21[3:26][6:7][99:99]", "TTLS", "user")

def test_ap_hs20_eap_ttls_eap_unknown(dev, apdev):
    """Hotspot 2.0 connection with TTLS/EAP-unknown"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = "0,example.com,21[3:99]"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values(default_cred())
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_eap_ttls_eap_unsupported(dev, apdev):
    """Hotspot 2.0 connection with TTLS/EAP-OTP(unsupported)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = "0,example.com,21[3:5]"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values(default_cred())
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_eap_ttls_unknown(dev, apdev):
    """Hotspot 2.0 connection with TTLS/unknown"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = "0,example.com,21[2:5]"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values(default_cred())
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_eap_fast_mschapv2(dev, apdev):
    """Hotspot 2.0 connection with FAST/EAP-MSCHAPV2"""
    eap_test(dev[0], apdev[0], "43[3:26]", "FAST", "user")

def test_ap_hs20_eap_fast_gtc(dev, apdev):
    """Hotspot 2.0 connection with FAST/EAP-GTC"""
    eap_test(dev[0], apdev[0], "43[3:6]", "FAST", "user")

def test_ap_hs20_eap_tls(dev, apdev):
    """Hotspot 2.0 connection with EAP-TLS"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,13[5:6]" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values({ 'realm': "example.com",
                             'username': "certificate-user",
                             'ca_cert': "auth_serv/ca.pem",
                             'client_cert': "auth_serv/user.pem",
                             'private_key': "auth_serv/user.key"})
    interworking_select(dev[0], bssid, freq="2412")
    interworking_connect(dev[0], bssid, "TLS")

def test_ap_hs20_eap_cert_unknown(dev, apdev):
    """Hotspot 2.0 connection with certificate, but unknown EAP method"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,99[5:6]" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values({ 'realm': "example.com",
                             'username': "certificate-user",
                             'ca_cert': "auth_serv/ca.pem",
                             'client_cert': "auth_serv/user.pem",
                             'private_key': "auth_serv/user.key"})
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_eap_cert_unsupported(dev, apdev):
    """Hotspot 2.0 connection with certificate, but unsupported TTLS"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,21[5:6]" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values({ 'realm': "example.com",
                             'username': "certificate-user",
                             'ca_cert': "auth_serv/ca.pem",
                             'client_cert': "auth_serv/user.pem",
                             'private_key': "auth_serv/user.key"})
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_eap_invalid_cred(dev, apdev):
    """Hotspot 2.0 connection with invalid cred configuration"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].add_cred_values({ 'realm': "example.com",
                             'username': "certificate-user",
                             'client_cert': "auth_serv/user.pem" })
    interworking_select(dev[0], None, no_match=True, freq="2412")

def test_ap_hs20_nai_realms(dev, apdev):
    """Hotspot 2.0 connection and multiple NAI realms and TTLS/PAP"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    params['nai_realm'] = [ "0,no.match.here;example.com;no.match.here.either,21[2:1][5:7]" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "pap user",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home", freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "home")

def test_ap_hs20_roaming_consortium(dev, apdev):
    """Hotspot 2.0 connection based on roaming consortium match"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    for consortium in [ "112233", "1020304050", "010203040506", "fedcba" ]:
        id = dev[0].add_cred_values({ 'username': "user",
                                      'password': "password",
                                      'domain': "example.com",
                                      'roaming_consortium': consortium,
                                      'eap': "PEAP" })
        interworking_select(dev[0], bssid, "home", freq="2412")
        interworking_connect(dev[0], bssid, "PEAP")
        check_sp_type(dev[0], "home")
        dev[0].request("INTERWORKING_SELECT auto freq=2412")
        ev = dev[0].wait_event(["INTERWORKING-ALREADY-CONNECTED"], timeout=15)
        if ev is None:
            raise Exception("Timeout on already-connected event")
        dev[0].remove_cred(id)

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

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "roaming.example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "roaming", freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "roaming")

def test_ap_hs20_username_unknown(dev, apdev):
    """Hotspot 2.0 connection in username/password credential (no domain in cred)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password" })
    interworking_select(dev[0], bssid, "unknown", freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "unknown")

def test_ap_hs20_username_unknown2(dev, apdev):
    """Hotspot 2.0 connection in username/password credential (no domain advertized)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    del params['domain_name']
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "unknown", freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    check_sp_type(dev[0], "unknown")

def test_ap_hs20_gas_while_associated(dev, apdev):
    """Hotspot 2.0 connection with GAS query while associated"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home", freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")

    logger.info("Verifying GAS query while associated")
    dev[0].request("FETCH_ANQP")
    for i in range(0, 6):
        ev = dev[0].wait_event(["RX-ANQP"], timeout=5)
        if ev is None:
            raise Exception("Operation timed out")

def test_ap_hs20_gas_while_associated_with_pmf(dev, apdev):
    """Hotspot 2.0 connection with GAS query while associated and using PMF"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid2
    params['nai_realm'] = [ "0,no-match.example.org,13[5:6],21[2:4][5:7]" ]
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].request("SET pmf 2")
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home", freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")

    logger.info("Verifying GAS query while associated")
    dev[0].request("FETCH_ANQP")
    for i in range(0, 2 * 6):
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

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    interworking_select(dev[0], bssid, "home", freq="2412")
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

    dev[0].hs20_enable()
    values = { 'realm': "example.com",
               'username': "hs20-test",
               'password': "password",
               'domain': "example.com" }
    id = dev[0].add_cred_values(values)

    for i in range(0, 3):
        logger.info("Starting Interworking network selection")
        dev[0].request("INTERWORKING_SELECT auto freq=2412")
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
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["INTERWORKING-NO-MATCH"], timeout=15)
    if ev is None:
        raise Exception("Network selection timed out")
    dev[0].dump_monitor()

    logger.info("Verify disallow_aps clear")
    dev[0].request("SET disallow_aps ")
    interworking_select(dev[0], bssid, "home", freq="2412")

    dev[0].request("SET disallow_aps bssid " + bssid.translate(None, ':'))
    ret = dev[0].request("INTERWORKING_CONNECT " + bssid)
    if "FAIL" not in ret:
        raise Exception("INTERWORKING_CONNECT to disallowed BSS not rejected")

def policy_test(dev, ap, values, only_one=True):
    dev.dump_monitor()
    if ap:
        logger.info("Verify network selection to AP " + ap['ifname'])
        bssid = ap['bssid']
    else:
        logger.info("Verify network selection")
        bssid = None
    dev.hs20_enable()
    id = dev.add_cred_values(values)
    dev.request("INTERWORKING_SELECT auto freq=2412")
    events = []
    while True:
        ev = dev.wait_event(["INTERWORKING-AP", "INTERWORKING-NO-MATCH",
                             "INTERWORKING-BLACKLISTED",
                             "INTERWORKING-SELECTED"], timeout=15)
        if ev is None:
            raise Exception("Network selection timed out")
        events.append(ev)
        if "INTERWORKING-NO-MATCH" in ev:
            raise Exception("Matching AP not found")
        if bssid and only_one and "INTERWORKING-AP" in ev and bssid not in ev:
            raise Exception("Unexpected AP claimed acceptable")
        if "INTERWORKING-SELECTED" in ev:
            if bssid and bssid not in ev:
                raise Exception("Selected incorrect BSS")
            break

    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if bssid and bssid not in ev:
        raise Exception("Connected to incorrect BSS")

    conn_bssid = dev.get_status_field("bssid")
    if bssid and conn_bssid != bssid:
        raise Exception("bssid information points to incorrect BSS")

    dev.remove_cred(id)
    dev.dump_monitor()
    return events

def default_cred(domain=None):
    cred = { 'realm': "example.com",
             'username': "hs20-test",
             'password': "password" }
    if domain:
        cred['domain'] = domain
    return cred

def test_ap_hs20_prefer_home(dev, apdev):
    """Hotspot 2.0 required roaming consortium"""
    params = hs20_ap_params()
    params['domain_name'] = "example.org"
    hostapd.add_ap(apdev[0]['ifname'], params)

    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    params['domain_name'] = "example.com"
    hostapd.add_ap(apdev[1]['ifname'], params)

    values = default_cred()
    values['domain'] = "example.com"
    policy_test(dev[0], apdev[1], values, only_one=False)
    values['domain'] = "example.org"
    policy_test(dev[0], apdev[0], values, only_one=False)

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

    id = dev[0].add_cred()
    dev[0].set_cred(id, "required_roaming_consortium", "112233")
    dev[0].set_cred(id, "required_roaming_consortium", "112233445566778899aabbccddeeff")

    for val in [ "", "1", "11", "1122", "1122334", "112233445566778899aabbccddeeff00" ]:
        if "FAIL" not in dev[0].request('SET_CRED {} required_roaming_consortium {}'.format(id, val)):
            raise Exception("Invalid roaming consortium value accepted: " + val)

def test_ap_hs20_excluded_ssid(dev, apdev):
    """Hotspot 2.0 exclusion based on SSID"""
    params = hs20_ap_params()
    params['roaming_consortium'] = [ "223344" ]
    params['anqp_3gpp_cell_net'] = "555,444"
    hostapd.add_ap(apdev[0]['ifname'], params)

    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    params['roaming_consortium'] = [ "223344" ]
    params['anqp_3gpp_cell_net'] = "555,444"
    hostapd.add_ap(apdev[1]['ifname'], params)

    values = default_cred()
    values['excluded_ssid'] = "test-hs20"
    events = policy_test(dev[0], apdev[1], values)
    ev = [e for e in events if "INTERWORKING-BLACKLISTED " + apdev[0]['bssid'] in e]
    if len(ev) != 1:
        raise Exception("Excluded network not reported")
    values['excluded_ssid'] = "test-hs20-other"
    events = policy_test(dev[0], apdev[0], values)
    ev = [e for e in events if "INTERWORKING-BLACKLISTED " + apdev[1]['bssid'] in e]
    if len(ev) != 1:
        raise Exception("Excluded network not reported")

    values = default_cred()
    values['roaming_consortium'] = "223344"
    values['eap'] = "TTLS"
    values['phase2'] = "auth=MSCHAPV2"
    values['excluded_ssid'] = "test-hs20"
    events = policy_test(dev[0], apdev[1], values)
    ev = [e for e in events if "INTERWORKING-BLACKLISTED " + apdev[0]['bssid'] in e]
    if len(ev) != 1:
        raise Exception("Excluded network not reported")

    values = { 'imsi': "555444-333222111", 'eap': "SIM",
               'milenage': "5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
               'excluded_ssid': "test-hs20" }
    events = policy_test(dev[0], apdev[1], values)
    ev = [e for e in events if "INTERWORKING-BLACKLISTED " + apdev[0]['bssid'] in e]
    if len(ev) != 1:
        raise Exception("Excluded network not reported")

def test_ap_hs20_roam_to_higher_prio(dev, apdev):
    """Hotspot 2.0 and roaming from current to higher priority network"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params(ssid="test-hs20-visited")
    params['domain_name'] = "visited.example.org"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com" })
    logger.info("Connect to the only network option")
    interworking_select(dev[0], bssid, "roaming", freq="2412")
    dev[0].dump_monitor()
    interworking_connect(dev[0], bssid, "TTLS")

    logger.info("Start another AP (home operator) and reconnect")
    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20-home")
    params['domain_name'] = "example.com"
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["INTERWORKING-NO-MATCH",
                            "INTERWORKING-ALREADY-CONNECTED",
                            "CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if "INTERWORKING-NO-MATCH" in ev:
        raise Exception("Matching AP not found")
    if "INTERWORKING-ALREADY-CONNECTED" in ev:
        raise Exception("Unexpected AP selected")
    if bssid2 not in ev:
        raise Exception("Unexpected BSSID after reconnection")

def test_ap_hs20_domain_suffix_match(dev, apdev):
    """Hotspot 2.0 and domain_suffix_match"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    id = dev[0].add_cred_values({ 'realm': "example.com",
                                  'username': "hs20-test",
                                  'password': "password",
                                  'domain': "example.com",
                                  'domain_suffix_match': "w1.fi" })
    interworking_select(dev[0], bssid, "home", freq="2412")
    dev[0].dump_monitor()
    interworking_connect(dev[0], bssid, "TTLS")
    dev[0].request("REMOVE_NETWORK all")
    dev[0].dump_monitor()

    dev[0].set_cred_quoted(id, "domain_suffix_match", "no-match.example.com")
    interworking_select(dev[0], bssid, "home", freq="2412")
    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_CONNECT " + bssid)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-TLS-CERT-ERROR"])
    if ev is None:
        raise Exception("TLS certificate error not reported")
    if "Domain suffix mismatch" not in ev:
        raise Exception("Domain suffix mismatch not reported")

def test_ap_hs20_roaming_partner_preference(dev, apdev):
    """Hotspot 2.0 and roaming partner preference"""
    params = hs20_ap_params()
    params['domain_name'] = "roaming.example.org"
    hostapd.add_ap(apdev[0]['ifname'], params)

    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    params['domain_name'] = "roaming.example.net"
    hostapd.add_ap(apdev[1]['ifname'], params)

    logger.info("Verify default vs. specified preference")
    values = default_cred()
    values['roaming_partner'] = "roaming.example.net,1,127,*"
    policy_test(dev[0], apdev[1], values, only_one=False)
    values['roaming_partner'] = "roaming.example.net,1,129,*"
    policy_test(dev[0], apdev[0], values, only_one=False)

    logger.info("Verify partial FQDN match")
    values['roaming_partner'] = "example.net,0,0,*"
    policy_test(dev[0], apdev[1], values, only_one=False)
    values['roaming_partner'] = "example.net,0,255,*"
    policy_test(dev[0], apdev[0], values, only_one=False)

def test_ap_hs20_max_bss_load(dev, apdev):
    """Hotspot 2.0 and maximum BSS load"""
    params = hs20_ap_params()
    params['bss_load_test'] = "12:200:20000"
    hostapd.add_ap(apdev[0]['ifname'], params)

    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    params['bss_load_test'] = "5:20:10000"
    hostapd.add_ap(apdev[1]['ifname'], params)

    logger.info("Verify maximum BSS load constraint")
    values = default_cred()
    values['domain'] = "example.com"
    values['max_bss_load'] = "100"
    events = policy_test(dev[0], apdev[1], values, only_one=False)

    ev = [e for e in events if "INTERWORKING-AP " + apdev[0]['bssid'] in e]
    if len(ev) != 1 or "over_max_bss_load=1" not in ev[0]:
        raise Exception("Maximum BSS Load case not noticed")
    ev = [e for e in events if "INTERWORKING-AP " + apdev[1]['bssid'] in e]
    if len(ev) != 1 or "over_max_bss_load=1" in ev[0]:
        raise Exception("Maximum BSS Load case reported incorrectly")

    logger.info("Verify maximum BSS load does not prevent connection")
    values['max_bss_load'] = "1"
    events = policy_test(dev[0], None, values)

    ev = [e for e in events if "INTERWORKING-AP " + apdev[0]['bssid'] in e]
    if len(ev) != 1 or "over_max_bss_load=1" not in ev[0]:
        raise Exception("Maximum BSS Load case not noticed")
    ev = [e for e in events if "INTERWORKING-AP " + apdev[1]['bssid'] in e]
    if len(ev) != 1 or "over_max_bss_load=1" not in ev[0]:
        raise Exception("Maximum BSS Load case not noticed")

def test_ap_hs20_max_bss_load2(dev, apdev):
    """Hotspot 2.0 and maximum BSS load with one AP not advertising"""
    params = hs20_ap_params()
    params['bss_load_test'] = "12:200:20000"
    hostapd.add_ap(apdev[0]['ifname'], params)

    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    hostapd.add_ap(apdev[1]['ifname'], params)

    logger.info("Verify maximum BSS load constraint with AP advertisement")
    values = default_cred()
    values['domain'] = "example.com"
    values['max_bss_load'] = "100"
    events = policy_test(dev[0], apdev[1], values, only_one=False)

    ev = [e for e in events if "INTERWORKING-AP " + apdev[0]['bssid'] in e]
    if len(ev) != 1 or "over_max_bss_load=1" not in ev[0]:
        raise Exception("Maximum BSS Load case not noticed")
    ev = [e for e in events if "INTERWORKING-AP " + apdev[1]['bssid'] in e]
    if len(ev) != 1 or "over_max_bss_load=1" in ev[0]:
        raise Exception("Maximum BSS Load case reported incorrectly")

def test_ap_hs20_multi_cred_sp_prio(dev, apdev):
    """Hotspot 2.0 multi-cred sp_priority"""
    if not hlr_auc_gw_available():
        return "skip"
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    del params['domain_name']
    params['anqp_3gpp_cell_net'] = "232,01"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].request("SET external_sim 1")
    id1 = dev[0].add_cred_values({ 'imsi': "23201-0000000000", 'eap': "SIM",
                                   'provisioning_sp': "example.com",
                                   'sp_priority' :"1" })
    id2 = dev[0].add_cred_values({ 'realm': "example.com",
                                   'username': "hs20-test",
                                   'password': "password",
                                   'domain': "example.com",
                                   'provisioning_sp': "example.com",
                                   'sp_priority': "2" })
    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    interworking_ext_sim_auth(dev[0], "SIM")
    check_sp_type(dev[0], "unknown")
    dev[0].request("REMOVE_NETWORK all")

    dev[0].set_cred(id1, "sp_priority", "2")
    dev[0].set_cred(id2, "sp_priority", "1")
    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    interworking_auth(dev[0], "TTLS")
    check_sp_type(dev[0], "unknown")

def test_ap_hs20_multi_cred_sp_prio2(dev, apdev):
    """Hotspot 2.0 multi-cred sp_priority with two BSSes"""
    if not hlr_auc_gw_available():
        return "skip"
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hessid'] = bssid
    del params['nai_realm']
    del params['domain_name']
    params['anqp_3gpp_cell_net'] = "232,01"
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params()
    params['ssid'] = "test-hs20-other"
    params['hessid'] = bssid2
    del params['domain_name']
    del params['anqp_3gpp_cell_net']
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].hs20_enable()
    dev[0].request("SET external_sim 1")
    id1 = dev[0].add_cred_values({ 'imsi': "23201-0000000000", 'eap': "SIM",
                                   'provisioning_sp': "example.com",
                                   'sp_priority': "1" })
    id2 = dev[0].add_cred_values({ 'realm': "example.com",
                                   'username': "hs20-test",
                                   'password': "password",
                                   'domain': "example.com",
                                   'provisioning_sp': "example.com",
                                   'sp_priority': "2" })
    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    interworking_ext_sim_auth(dev[0], "SIM")
    check_sp_type(dev[0], "unknown")
    conn_bssid = dev[0].get_status_field("bssid")
    if conn_bssid != bssid:
        raise Exception("Connected to incorrect BSS")
    dev[0].request("REMOVE_NETWORK all")

    dev[0].set_cred(id1, "sp_priority", "2")
    dev[0].set_cred(id2, "sp_priority", "1")
    dev[0].dump_monitor()
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    interworking_auth(dev[0], "TTLS")
    check_sp_type(dev[0], "unknown")
    conn_bssid = dev[0].get_status_field("bssid")
    if conn_bssid != bssid2:
        raise Exception("Connected to incorrect BSS")

def check_conn_capab_selection(dev, type, missing):
    dev.request("INTERWORKING_SELECT freq=2412")
    ev = dev.wait_event(["INTERWORKING-AP"])
    if ev is None:
        raise Exception("Network selection timed out");
    if "type=" + type not in ev:
        raise Exception("Unexpected network type")
    if missing and "conn_capab_missing=1" not in ev:
        raise Exception("conn_capab_missing not reported")
    if not missing and "conn_capab_missing=1" in ev:
        raise Exception("conn_capab_missing reported unexpectedly")

def conn_capab_cred(domain=None, req_conn_capab=None):
    cred = default_cred(domain=domain)
    if req_conn_capab:
        cred['req_conn_capab'] = req_conn_capab
    return cred

def test_ap_hs20_req_conn_capab(dev, apdev):
    """Hotspot 2.0 network selection with req_conn_capab"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    logger.info("Not used in home network")
    values = conn_capab_cred(domain="example.com", req_conn_capab="6:1234")
    id = dev[0].add_cred_values(values)
    check_conn_capab_selection(dev[0], "home", False)

    logger.info("Used in roaming network")
    dev[0].remove_cred(id)
    values = conn_capab_cred(domain="example.org", req_conn_capab="6:1234")
    id = dev[0].add_cred_values(values)
    check_conn_capab_selection(dev[0], "roaming", True)

    logger.info("Verify that req_conn_capab does not prevent connection if no other network is available")
    check_auto_select(dev[0], bssid)

    logger.info("Additional req_conn_capab checks")

    dev[0].remove_cred(id)
    values = conn_capab_cred(domain="example.org", req_conn_capab="1:0")
    id = dev[0].add_cred_values(values)
    check_conn_capab_selection(dev[0], "roaming", True)

    dev[0].remove_cred(id)
    values = conn_capab_cred(domain="example.org", req_conn_capab="17:5060")
    id = dev[0].add_cred_values(values)
    check_conn_capab_selection(dev[0], "roaming", True)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20b")
    params['hs20_conn_capab'] = [ "1:0:2", "6:22:1", "17:5060:0", "50:0:1" ]
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].remove_cred(id)
    values = conn_capab_cred(domain="example.org", req_conn_capab="50")
    id = dev[0].add_cred_values(values)
    dev[0].set_cred(id, "req_conn_capab", "6:22")
    dev[0].request("INTERWORKING_SELECT freq=2412")
    for i in range(0, 2):
        ev = dev[0].wait_event(["INTERWORKING-AP"])
        if ev is None:
            raise Exception("Network selection timed out");
        if bssid in ev and "conn_capab_missing=1" not in ev:
            raise Exception("Missing protocol connection capability not reported")
        if bssid2 in ev and "conn_capab_missing=1" in ev:
            raise Exception("Protocol connection capability not reported correctly")

def test_ap_hs20_req_conn_capab_and_roaming_partner_preference(dev, apdev):
    """Hotspot 2.0 and req_conn_capab with roaming partner preference"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['domain_name'] = "roaming.example.org"
    params['hs20_conn_capab'] = [ "1:0:2", "6:22:1", "17:5060:0", "50:0:1" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20-b")
    params['domain_name'] = "roaming.example.net"
    hostapd.add_ap(apdev[1]['ifname'], params)

    values = default_cred()
    values['roaming_partner'] = "roaming.example.net,1,127,*"
    id = dev[0].add_cred_values(values)
    check_auto_select(dev[0], bssid2)

    dev[0].set_cred(id, "req_conn_capab", "50")
    check_auto_select(dev[0], bssid)

    dev[0].remove_cred(id)
    id = dev[0].add_cred_values(values)
    dev[0].set_cred(id, "req_conn_capab", "51")
    check_auto_select(dev[0], bssid2)

def check_bandwidth_selection(dev, type, below):
    dev.request("INTERWORKING_SELECT freq=2412")
    ev = dev.wait_event(["INTERWORKING-AP"])
    if ev is None:
        raise Exception("Network selection timed out");
    if "type=" + type not in ev:
        raise Exception("Unexpected network type")
    if below and "below_min_backhaul=1" not in ev:
        raise Exception("below_min_backhaul not reported")
    if not below and "below_min_backhaul=1" in ev:
        raise Exception("below_min_backhaul reported unexpectedly")

def bw_cred(domain=None, dl_home=None, ul_home=None, dl_roaming=None, ul_roaming=None):
    cred = default_cred(domain=domain)
    if dl_home:
        cred['min_dl_bandwidth_home'] = str(dl_home)
    if ul_home:
        cred['min_ul_bandwidth_home'] = str(ul_home)
    if dl_roaming:
        cred['min_dl_bandwidth_roaming'] = str(dl_roaming)
    if ul_roaming:
        cred['min_ul_bandwidth_roaming'] = str(ul_roaming)
    return cred

def test_ap_hs20_min_bandwidth_home(dev, apdev):
    """Hotspot 2.0 network selection with min bandwidth (home)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    values = bw_cred(domain="example.com", dl_home=5490, ul_home=58)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "home", False)
    dev[0].remove_cred(id)

    values = bw_cred(domain="example.com", dl_home=5491, ul_home=58)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "home", True)
    dev[0].remove_cred(id)

    values = bw_cred(domain="example.com", dl_home=5490, ul_home=59)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "home", True)
    dev[0].remove_cred(id)

    values = bw_cred(domain="example.com", dl_home=5491, ul_home=59)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "home", True)
    check_auto_select(dev[0], bssid)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20-b")
    params['hs20_wan_metrics'] = "01:8000:1000:1:1:3000"
    hostapd.add_ap(apdev[1]['ifname'], params)

    check_auto_select(dev[0], bssid2)

def test_ap_hs20_min_bandwidth_roaming(dev, apdev):
    """Hotspot 2.0 network selection with min bandwidth (roaming)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    values = bw_cred(domain="example.org", dl_roaming=5490, ul_roaming=58)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "roaming", False)
    dev[0].remove_cred(id)

    values = bw_cred(domain="example.org", dl_roaming=5491, ul_roaming=58)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "roaming", True)
    dev[0].remove_cred(id)

    values = bw_cred(domain="example.org", dl_roaming=5490, ul_roaming=59)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "roaming", True)
    dev[0].remove_cred(id)

    values = bw_cred(domain="example.org", dl_roaming=5491, ul_roaming=59)
    id = dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "roaming", True)
    check_auto_select(dev[0], bssid)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20-b")
    params['hs20_wan_metrics'] = "01:8000:1000:1:1:3000"
    hostapd.add_ap(apdev[1]['ifname'], params)

    check_auto_select(dev[0], bssid2)

def test_ap_hs20_min_bandwidth_and_roaming_partner_preference(dev, apdev):
    """Hotspot 2.0 and minimum bandwidth with roaming partner preference"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['domain_name'] = "roaming.example.org"
    params['hs20_wan_metrics'] = "01:8000:1000:1:1:3000"
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20-b")
    params['domain_name'] = "roaming.example.net"
    hostapd.add_ap(apdev[1]['ifname'], params)

    values = default_cred()
    values['roaming_partner'] = "roaming.example.net,1,127,*"
    id = dev[0].add_cred_values(values)
    check_auto_select(dev[0], bssid2)

    dev[0].set_cred(id, "min_dl_bandwidth_roaming", "6000")
    check_auto_select(dev[0], bssid)

    dev[0].set_cred(id, "min_dl_bandwidth_roaming", "10000")
    check_auto_select(dev[0], bssid2)

def test_ap_hs20_min_bandwidth_no_wan_metrics(dev, apdev):
    """Hotspot 2.0 network selection with min bandwidth but no WAN Metrics"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    del params['hs20_wan_metrics']
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    values = bw_cred(domain="example.com", dl_home=10000, ul_home=10000,
                     dl_roaming=10000, ul_roaming=10000)
    dev[0].add_cred_values(values)
    check_bandwidth_selection(dev[0], "home", False)

def test_ap_hs20_deauth_req_ess(dev, apdev):
    """Hotspot 2.0 connection and deauthentication request for ESS"""
    dev[0].request("SET pmf 2")
    eap_test(dev[0], apdev[0], "21[3:26]", "TTLS", "user")
    dev[0].dump_monitor()
    addr = dev[0].p2p_interface_addr()
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("HS20_DEAUTH_REQ " + addr + " 1 120 http://example.com/")
    ev = dev[0].wait_event(["HS20-DEAUTH-IMMINENT-NOTICE"])
    if ev is None:
        raise Exception("Timeout on deauth imminent notice")
    if "1 120 http://example.com/" not in ev:
        raise Exception("Unexpected deauth imminent notice: " + ev)
    hapd.request("DEAUTHENTICATE " + addr)
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout on disconnection")
    if "[TEMP-DISABLED]" not in dev[0].list_networks()[0]['flags']:
        raise Exception("Network not marked temporarily disabled")
    ev = dev[0].wait_event(["SME: Trying to authenticate",
                            "Trying to associate",
                            "CTRL-EVENT-CONNECTED"], timeout=5)
    if ev is not None:
        raise Exception("Unexpected connection attempt")

def test_ap_hs20_deauth_req_bss(dev, apdev):
    """Hotspot 2.0 connection and deauthentication request for BSS"""
    dev[0].request("SET pmf 2")
    eap_test(dev[0], apdev[0], "21[3:26]", "TTLS", "user")
    dev[0].dump_monitor()
    addr = dev[0].p2p_interface_addr()
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("HS20_DEAUTH_REQ " + addr + " 0 120 http://example.com/")
    ev = dev[0].wait_event(["HS20-DEAUTH-IMMINENT-NOTICE"])
    if ev is None:
        raise Exception("Timeout on deauth imminent notice")
    if "0 120 http://example.com/" not in ev:
        raise Exception("Unexpected deauth imminent notice: " + ev)
    hapd.request("DEAUTHENTICATE " + addr + " reason=4")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout on disconnection")
    if "reason=4" not in ev:
        raise Exception("Unexpected disconnection reason")
    if "[TEMP-DISABLED]" not in dev[0].list_networks()[0]['flags']:
        raise Exception("Network not marked temporarily disabled")
    ev = dev[0].wait_event(["SME: Trying to authenticate",
                            "Trying to associate",
                            "CTRL-EVENT-CONNECTED"], timeout=5)
    if ev is not None:
        raise Exception("Unexpected connection attempt")

def test_ap_hs20_deauth_req_from_radius(dev, apdev):
    """Hotspot 2.0 connection and deauthentication request from RADIUS"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,21[2:4]" ]
    params['hs20_deauth_req_timeout'] = "2"
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET pmf 2")
    dev[0].hs20_enable()
    dev[0].add_cred_values({ 'realm': "example.com",
                             'username': "hs20-deauth-test",
                             'password': "password" })
    interworking_select(dev[0], bssid, freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    ev = dev[0].wait_event(["HS20-DEAUTH-IMMINENT-NOTICE"], timeout=5)
    if ev is None:
        raise Exception("Timeout on deauth imminent notice")
    if " 1 100" not in ev:
        raise Exception("Unexpected deauth imminent contents")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=3)
    if ev is None:
        raise Exception("Timeout on disconnection")

def test_ap_hs20_remediation_required(dev, apdev):
    """Hotspot 2.0 connection and remediation required from RADIUS"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,21[2:4]" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET pmf 1")
    dev[0].hs20_enable()
    dev[0].add_cred_values({ 'realm': "example.com",
                             'username': "hs20-subrem-test",
                             'password': "password" })
    interworking_select(dev[0], bssid, freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    ev = dev[0].wait_event(["HS20-SUBSCRIPTION-REMEDIATION"], timeout=5)
    if ev is None:
        raise Exception("Timeout on subscription remediation notice")
    if " 1 https://example.com/" not in ev:
        raise Exception("Unexpected subscription remediation event contents")

def test_ap_hs20_remediation_required_ctrl(dev, apdev):
    """Hotspot 2.0 connection and subrem from ctrl_iface"""
    bssid = apdev[0]['bssid']
    addr = dev[0].p2p_dev_addr()
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,21[2:4]" ]
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET pmf 1")
    dev[0].hs20_enable()
    dev[0].add_cred_values(default_cred())
    interworking_select(dev[0], bssid, freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")

    hapd.request("HS20_WNM_NOTIF " + addr + " https://example.com/")
    ev = dev[0].wait_event(["HS20-SUBSCRIPTION-REMEDIATION"], timeout=5)
    if ev is None:
        raise Exception("Timeout on subscription remediation notice")
    if " 1 https://example.com/" not in ev:
        raise Exception("Unexpected subscription remediation event contents")

    hapd.request("HS20_WNM_NOTIF " + addr)
    ev = dev[0].wait_event(["HS20-SUBSCRIPTION-REMEDIATION"], timeout=5)
    if ev is None:
        raise Exception("Timeout on subscription remediation notice")
    if not ev.endswith("HS20-SUBSCRIPTION-REMEDIATION "):
        raise Exception("Unexpected subscription remediation event contents: " + ev)

    if "FAIL" not in hapd.request("HS20_WNM_NOTIF "):
        raise Exception("Unexpected HS20_WNM_NOTIF success")
    if "FAIL" not in hapd.request("HS20_WNM_NOTIF foo"):
        raise Exception("Unexpected HS20_WNM_NOTIF success")
    if "FAIL" not in hapd.request("HS20_WNM_NOTIF " + addr + " https://12345678923456789842345678456783456712345678923456789842345678456783456712345678923456789842345678456783456712345678923456789842345678456783456712345678923456789842345678456783456712345678923456789842345678456783456712345678923456789842345678456783456712345678927.very.long.example.com/"):
        raise Exception("Unexpected HS20_WNM_NOTIF success")

def test_ap_hs20_session_info(dev, apdev):
    """Hotspot 2.0 connection and session information from RADIUS"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['nai_realm'] = [ "0,example.com,21[2:4]" ]
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("SET pmf 1")
    dev[0].hs20_enable()
    dev[0].add_cred_values({ 'realm': "example.com",
                             'username': "hs20-session-info-test",
                             'password': "password" })
    interworking_select(dev[0], bssid, freq="2412")
    interworking_connect(dev[0], bssid, "TTLS")
    ev = dev[0].wait_event(["ESS-DISASSOC-IMMINENT"], timeout=10)
    if ev is None:
        raise Exception("Timeout on ESS disassociation imminent notice")
    if " 1 59904 https://example.com/" not in ev:
        raise Exception("Unexpected ESS disassociation imminent event contents")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"])
    if ev is None:
        raise Exception("Scan not started")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Scan not completed")

def test_ap_hs20_osen(dev, apdev):
    """Hotspot 2.0 OSEN connection"""
    params = { 'ssid': "osen",
               'osen': "1",
               'auth_server_addr': "127.0.0.1",
               'auth_server_port': "1812",
               'auth_server_shared_secret': "radius" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[1].connect("osen", key_mgmt="NONE", scan_freq="2412",
                   wait_connect=False)
    dev[2].connect("osen", key_mgmt="NONE", wep_key0='"hello"',
                   scan_freq="2412", wait_connect=False)
    dev[0].connect("osen", proto="OSEN", key_mgmt="OSEN", pairwise="CCMP",
                   group="GTK_NOT_USED",
                   eap="WFA-UNAUTH-TLS", identity="osen@example.com",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412")

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    wpas.connect("osen", proto="OSEN", key_mgmt="OSEN", pairwise="CCMP",
                 group="GTK_NOT_USED",
                 eap="WFA-UNAUTH-TLS", identity="osen@example.com",
                 ca_cert="auth_serv/ca.pem",
                 scan_freq="2412")
    wpas.request("DISCONNECT")

def test_ap_hs20_network_preference(dev, apdev):
    """Hotspot 2.0 network selection with preferred home network"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].hs20_enable()
    values = { 'realm': "example.com",
               'username': "hs20-test",
               'password': "password",
               'domain': "example.com" }
    dev[0].add_cred_values(values)

    id = dev[0].add_network()
    dev[0].set_network_quoted(id, "ssid", "home")
    dev[0].set_network_quoted(id, "psk", "12345678")
    dev[0].set_network(id, "priority", "1")
    dev[0].request("ENABLE_NETWORK %s no-connect" % id)

    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if bssid not in ev:
        raise Exception("Unexpected network selected")

    bssid2 = apdev[1]['bssid']
    params = hostapd.wpa2_params(ssid="home", passphrase="12345678")
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                            "INTERWORKING-ALREADY-CONNECTED" ], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if "INTERWORKING-ALREADY-CONNECTED" in ev:
        raise Exception("No roam to higher priority network")
    if bssid2 not in ev:
        raise Exception("Unexpected network selected")

def test_ap_hs20_network_preference2(dev, apdev):
    """Hotspot 2.0 network selection with preferred credential"""
    bssid2 = apdev[1]['bssid']
    params = hostapd.wpa2_params(ssid="home", passphrase="12345678")
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].hs20_enable()
    values = { 'realm': "example.com",
               'username': "hs20-test",
               'password': "password",
               'domain': "example.com",
               'priority': "1" }
    dev[0].add_cred_values(values)

    id = dev[0].add_network()
    dev[0].set_network_quoted(id, "ssid", "home")
    dev[0].set_network_quoted(id, "psk", "12345678")
    dev[0].request("ENABLE_NETWORK %s no-connect" % id)

    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if bssid2 not in ev:
        raise Exception("Unexpected network selected")

    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                            "INTERWORKING-ALREADY-CONNECTED" ], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if "INTERWORKING-ALREADY-CONNECTED" in ev:
        raise Exception("No roam to higher priority network")
    if bssid not in ev:
        raise Exception("Unexpected network selected")

def test_ap_hs20_network_preference3(dev, apdev):
    """Hotspot 2.0 network selection with two credential (one preferred)"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20b")
    params['nai_realm'] = "0,example.org,13[5:6],21[2:4][5:7]"
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].hs20_enable()
    values = { 'realm': "example.com",
               'username': "hs20-test",
               'password': "password",
               'priority': "1" }
    dev[0].add_cred_values(values)
    values = { 'realm': "example.org",
               'username': "hs20-test",
               'password': "password" }
    id = dev[0].add_cred_values(values)

    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if bssid not in ev:
        raise Exception("Unexpected network selected")

    dev[0].set_cred(id, "priority", "2")
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                            "INTERWORKING-ALREADY-CONNECTED" ], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if "INTERWORKING-ALREADY-CONNECTED" in ev:
        raise Exception("No roam to higher priority network")
    if bssid2 not in ev:
        raise Exception("Unexpected network selected")

def test_ap_hs20_network_preference4(dev, apdev):
    """Hotspot 2.0 network selection with username vs. SIM credential"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20b")
    params['hessid'] = bssid2
    params['anqp_3gpp_cell_net'] = "555,444"
    params['domain_name'] = "wlan.mnc444.mcc555.3gppnetwork.org"
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].hs20_enable()
    values = { 'realm': "example.com",
               'username': "hs20-test",
               'password': "password",
               'priority': "1" }
    dev[0].add_cred_values(values)
    values = { 'imsi': "555444-333222111",
               'eap': "SIM",
               'milenage': "5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123" }
    id = dev[0].add_cred_values(values)

    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if bssid not in ev:
        raise Exception("Unexpected network selected")

    dev[0].set_cred(id, "priority", "2")
    dev[0].request("INTERWORKING_SELECT auto freq=2412")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                            "INTERWORKING-ALREADY-CONNECTED" ], timeout=15)
    if ev is None:
        raise Exception("Connection timed out")
    if "INTERWORKING-ALREADY-CONNECTED" in ev:
        raise Exception("No roam to higher priority network")
    if bssid2 not in ev:
        raise Exception("Unexpected network selected")

def test_ap_hs20_fetch_osu(dev, apdev):
    """Hotspot 2.0 OSU provider and icon fetch"""
    bssid = apdev[0]['bssid']
    params = hs20_ap_params()
    params['hs20_icon'] = "128:80:zxx:image/png:w1fi_logo:w1fi_logo.png"
    params['osu_ssid'] = '"HS 2.0 OSU open"'
    params['osu_method_list'] = "1"
    params['osu_friendly_name'] = [ "eng:Test OSU", "fin:Testi-OSU" ]
    params['osu_icon'] = "w1fi_logo"
    params['osu_service_desc'] = [ "eng:Example services", "fin:Esimerkkipalveluja" ]
    params['osu_server_uri'] = "https://example.com/osu/"
    hostapd.add_ap(apdev[0]['ifname'], params)

    bssid2 = apdev[1]['bssid']
    params = hs20_ap_params(ssid="test-hs20b")
    params['hessid'] = bssid2
    params['hs20_icon'] = "128:80:zxx:image/png:w1fi_logo:w1fi_logo.png"
    params['osu_ssid'] = '"HS 2.0 OSU OSEN"'
    params['osu_method_list'] = "0"
    params['osu_friendly_name'] = [ "eng:Test2 OSU", "fin:Testi2-OSU" ]
    params['osu_icon'] = "w1fi_logo"
    params['osu_service_desc'] = [ "eng:Example services2", "fin:Esimerkkipalveluja2" ]
    params['osu_server_uri'] = "https://example.org/osu/"
    hostapd.add_ap(apdev[1]['ifname'], params)

    with open("w1fi_logo.png", "r") as f:
        orig_logo = f.read()
    dev[0].hs20_enable()
    dir = "/tmp/osu-fetch"
    if os.path.isdir(dir):
       files = [ f for f in os.listdir(dir) if f.startswith("osu-") ]
       for f in files:
           os.remove(dir + "/" + f)
    else:
        try:
            os.makedirs(dir)
        except:
            pass
    try:
        dev[0].request("SET osu_dir " + dir)
        dev[0].request("FETCH_OSU")
        icons = 0
        while True:
            ev = dev[0].wait_event(["OSU provider fetch completed",
                                    "RX-HS20-ANQP-ICON"], timeout=15)
            if ev is None:
                raise Exception("Timeout on OSU fetch")
            if "OSU provider fetch completed" in ev:
                break
            if "RX-HS20-ANQP-ICON" in ev:
                with open(ev.split(' ')[1], "r") as f:
                    logo = f.read()
                    if logo == orig_logo:
                        icons += 1

        with open(dir + "/osu-providers.txt", "r") as f:
            prov = f.read()
        if "OSU-PROVIDER " + bssid not in prov:
            raise Exception("Missing OSU_PROVIDER")
        if "OSU-PROVIDER " + bssid2 not in prov:
            raise Exception("Missing OSU_PROVIDER")
    finally:
        files = [ f for f in os.listdir(dir) if f.startswith("osu-") ]
        for f in files:
            os.remove(dir + "/" + f)
        os.rmdir(dir)

    if icons != 2:
        raise Exception("Unexpected number of icons fetched")
