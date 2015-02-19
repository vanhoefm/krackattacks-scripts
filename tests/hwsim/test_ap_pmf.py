# Protected management frames tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd
from wlantest import Wlantest
from wpasupplicant import WpaSupplicant
from test_ap_eap import eap_connect

def test_ap_pmf_required(dev, apdev):
    """WPA2-PSK AP with PMF required"""
    ssid = "test-pmf-required"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256";
    params["ieee80211w"] = "2";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "WPA-PSK-SHA256":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    if "[WPA2-PSK-SHA256-CCMP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing RSN element info")
    hwsim_utils.test_connectivity(dev[0], hapd)
    dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[1], hapd)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.request("SA_QUERY " + dev[0].p2p_interface_addr())
    hapd.request("SA_QUERY " + dev[1].p2p_interface_addr())
    wt.require_ap_pmf_mandatory(apdev[0]['bssid'])
    wt.require_sta_pmf(apdev[0]['bssid'], dev[0].p2p_interface_addr())
    wt.require_sta_pmf_mandatory(apdev[0]['bssid'], dev[1].p2p_interface_addr())
    time.sleep(0.1)
    if wt.get_sta_counter("valid_saqueryresp_tx", apdev[0]['bssid'],
                          dev[0].p2p_interface_addr()) < 1:
        raise Exception("STA did not reply to SA Query")
    if wt.get_sta_counter("valid_saqueryresp_tx", apdev[0]['bssid'],
                          dev[1].p2p_interface_addr()) < 1:
        raise Exception("STA did not reply to SA Query")

def test_ap_pmf_optional(dev, apdev):
    """WPA2-PSK AP with PMF optional"""
    ssid = "test-pmf-optional"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK";
    params["ieee80211w"] = "1";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)
    dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[1], hapd)
    wt.require_ap_pmf_optional(apdev[0]['bssid'])
    wt.require_sta_pmf(apdev[0]['bssid'], dev[0].p2p_interface_addr())
    wt.require_sta_pmf_mandatory(apdev[0]['bssid'], dev[1].p2p_interface_addr())

def test_ap_pmf_optional_2akm(dev, apdev):
    """WPA2-PSK AP with PMF optional (2 AKMs)"""
    ssid = "test-pmf-optional-2akm"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK WPA-PSK-SHA256";
    params["ieee80211w"] = "1";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)
    dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[1], hapd)
    wt.require_ap_pmf_optional(apdev[0]['bssid'])
    wt.require_sta_pmf(apdev[0]['bssid'], dev[0].p2p_interface_addr())
    wt.require_sta_key_mgmt(apdev[0]['bssid'], dev[0].p2p_interface_addr(),
                            "PSK-SHA256")
    wt.require_sta_pmf_mandatory(apdev[0]['bssid'], dev[1].p2p_interface_addr())
    wt.require_sta_key_mgmt(apdev[0]['bssid'], dev[1].p2p_interface_addr(),
                            "PSK-SHA256")

def test_ap_pmf_negative(dev, apdev):
    """WPA2-PSK AP without PMF (negative test)"""
    ssid = "test-pmf-negative"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)
    try:
        dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                       key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                       scan_freq="2412")
        hwsim_utils.test_connectivity(dev[1], hapd)
        raise Exception("PMF required STA connected to no PMF AP")
    except Exception, e:
        logger.debug("Ignore expected exception: " + str(e))
    wt.require_ap_no_pmf(apdev[0]['bssid'])

def test_ap_pmf_assoc_comeback(dev, apdev):
    """WPA2-PSK AP with PMF association comeback"""
    ssid = "assoc-comeback"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256";
    params["ieee80211w"] = "2";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hapd.set("ext_mgmt_frame_handling", "1")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=10)
    hapd.set("ext_mgmt_frame_handling", "0")
    dev[0].request("REASSOCIATE")
    dev[0].wait_connected(timeout=10, error="Timeout on re-connection")
    if wt.get_sta_counter("assocresp_comeback", apdev[0]['bssid'],
                          dev[0].p2p_interface_addr()) < 1:
        raise Exception("AP did not use association comeback request")

def test_ap_pmf_assoc_comeback2(dev, apdev):
    """WPA2-PSK AP with PMF association comeback (using DROP_SA)"""
    ssid = "assoc-comeback"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK";
    params["ieee80211w"] = "1";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK", proto="WPA2", scan_freq="2412")
    if "OK" not in dev[0].request("DROP_SA"):
        raise Exception("DROP_SA failed")
    dev[0].request("REASSOCIATE")
    dev[0].wait_connected(timeout=10, error="Timeout on re-connection")
    if wt.get_sta_counter("reassocresp_comeback", apdev[0]['bssid'],
                          dev[0].p2p_interface_addr()) < 1:
        raise Exception("AP did not use reassociation comeback request")

def test_ap_pmf_sta_sa_query(dev, apdev):
    """WPA2-PSK AP with station using SA Query"""
    ssid = "assoc-comeback"
    addr = dev[0].own_addr()
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="use_monitor=1")
    id = wpas.add_network()
    wpas.set_network(id, "mode", "2")
    wpas.set_network_quoted(id, "ssid", ssid)
    wpas.set_network(id, "proto", "WPA2")
    wpas.set_network(id, "key_mgmt", "WPA-PSK-SHA256")
    wpas.set_network(id, "ieee80211w", "2")
    wpas.set_network_quoted(id, "psk", "12345678")
    wpas.set_network(id, "pairwise", "CCMP")
    wpas.set_network(id, "group", "CCMP")
    wpas.set_network(id, "frequency", "2412")
    wpas.connect_network(id)
    bssid = wpas.own_addr()

    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    wpas.request("DEAUTHENTICATE " + addr + " test=0")
    wpas.request("DISASSOCIATE " + addr + " test=0")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")

    wpas.request("DEAUTHENTICATE " + addr + " reason=6 test=0")
    wpas.request("DISASSOCIATE " + addr + " reason=7 test=0")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")
    if wt.get_sta_counter("valid_saqueryreq_tx", bssid, addr) < 1:
        raise Exception("STA did not send SA Query")
    if wt.get_sta_counter("valid_saqueryresp_rx", bssid, addr) < 1:
        raise Exception("AP did not reply to SA Query")

def test_ap_pmf_sta_sa_query_no_response(dev, apdev):
    """WPA2-PSK AP with station using SA Query and getting no response"""
    ssid = "assoc-comeback"
    addr = dev[0].p2p_dev_addr()

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="use_monitor=1")
    id = wpas.add_network()
    wpas.set_network(id, "mode", "2")
    wpas.set_network_quoted(id, "ssid", ssid)
    wpas.set_network(id, "proto", "WPA2")
    wpas.set_network(id, "key_mgmt", "WPA-PSK-SHA256")
    wpas.set_network(id, "ieee80211w", "2")
    wpas.set_network_quoted(id, "psk", "12345678")
    wpas.set_network(id, "pairwise", "CCMP")
    wpas.set_network(id, "group", "CCMP")
    wpas.set_network(id, "frequency", "2412")
    wpas.connect_network(id)
    bssid = wpas.own_addr()

    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    wpas.request("DEAUTHENTICATE " + addr + " test=0")
    wpas.request("DISASSOCIATE " + addr + " test=0")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")

    wpas.request("SET ext_mgmt_frame_handling 1")
    wpas.request("DEAUTHENTICATE " + addr + " reason=6 test=0")
    wpas.request("DISASSOCIATE " + addr + " reason=7 test=0")
    dev[0].wait_disconnected()
    wpas.request("SET ext_mgmt_frame_handling 0")
    dev[0].wait_connected()

def test_ap_pmf_sta_unprot_deauth_burst(dev, apdev):
    """WPA2-PSK AP with station receiving burst of unprotected Deauthentication frames"""
    ssid = "deauth-attack"
    addr = dev[0].own_addr()
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="use_monitor=1")
    id = wpas.add_network()
    wpas.set_network(id, "mode", "2")
    wpas.set_network_quoted(id, "ssid", ssid)
    wpas.set_network(id, "proto", "WPA2")
    wpas.set_network(id, "key_mgmt", "WPA-PSK-SHA256")
    wpas.set_network(id, "ieee80211w", "2")
    wpas.set_network_quoted(id, "psk", "12345678")
    wpas.set_network(id, "pairwise", "CCMP")
    wpas.set_network(id, "group", "CCMP")
    wpas.set_network(id, "frequency", "2412")
    wpas.connect_network(id)
    bssid = wpas.p2p_dev_addr()

    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")

    for i in range(0, 10):
        wpas.request("DEAUTHENTICATE " + addr + " reason=6 test=0")
        wpas.request("DISASSOCIATE " + addr + " reason=7 test=0")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")
    num_req = wt.get_sta_counter("valid_saqueryreq_tx", bssid, addr)
    num_resp = wt.get_sta_counter("valid_saqueryresp_rx", bssid, addr)
    if num_req < 1:
        raise Exception("STA did not send SA Query")
    if num_resp < 1:
        raise Exception("AP did not reply to SA Query")
    if num_req > 1:
        raise Exception("STA initiated too many SA Query procedures (%d)" % num_req)

    time.sleep(10)
    for i in range(0, 5):
        wpas.request("DEAUTHENTICATE " + addr + " reason=6 test=0")
        wpas.request("DISASSOCIATE " + addr + " reason=7 test=0")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")
    num_req = wt.get_sta_counter("valid_saqueryreq_tx", bssid, addr)
    num_resp = wt.get_sta_counter("valid_saqueryresp_rx", bssid, addr)
    if num_req != 2 or num_resp != 2:
        raise Exception("Unexpected number of SA Query procedures (req=%d resp=%d)" % (num_req, num_resp))

def test_ap_pmf_required_eap(dev, apdev):
    """WPA2-EAP AP with PMF required"""
    ssid = "test-pmf-required-eap"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256";
    params["ieee80211w"] = "2";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "WPA-EAP-SHA256":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    dev[0].connect("test-pmf-required-eap", key_mgmt="WPA-EAP-SHA256",
                   ieee80211w="2", eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef")

def test_ap_pmf_required_sha1(dev, apdev):
    """WPA2-PSK AP with PMF required with SHA1 AKM"""
    ssid = "test-pmf-required-sha1"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK";
    params["ieee80211w"] = "2";
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "WPA-PSK":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    dev[0].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK", proto="WPA2", scan_freq="2412")
    if "[WPA2-PSK-CCMP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing RSN element info")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_pmf_toggle(dev, apdev):
    """WPA2-PSK AP with PMF optional and changing PMF on reassociation"""
    try:
        _test_ap_pmf_toggle(dev, apdev)
    finally:
        dev[0].request("SET reassoc_same_bss_optim 0")

def _test_ap_pmf_toggle(dev, apdev):
    ssid = "test-pmf-optional"
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK";
    params["ieee80211w"] = "1";
    params["assoc_sa_query_max_timeout"] = "1"
    params["assoc_sa_query_retry_timeout"] = "1"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    addr = dev[0].own_addr()
    dev[0].request("SET reassoc_same_bss_optim 1")
    id = dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                        key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                        scan_freq="2412")
    wt.require_ap_pmf_optional(bssid)
    wt.require_sta_pmf(bssid, addr)
    sta = hapd.get_sta(addr)
    if '[MFP]' not in sta['flags']:
        raise Exception("MFP flag not present for STA")

    dev[0].set_network(id, "ieee80211w", "0")
    dev[0].request("REASSOCIATE")
    dev[0].wait_connected()
    wt.require_sta_no_pmf(bssid, addr)
    sta = hapd.get_sta(addr)
    if '[MFP]' in sta['flags']:
        raise Exception("MFP flag unexpectedly present for STA")
    cmd = subprocess.Popen(['iw', 'dev', apdev[0]['ifname'], 'station', 'get',
                            addr], stdout=subprocess.PIPE)
    (data,err) = cmd.communicate()
    if "yes" in [l for l in data.splitlines() if "MFP" in l][0]:
        raise Exception("Kernel STA entry had MFP enabled")

    dev[0].set_network(id, "ieee80211w", "1")
    dev[0].request("REASSOCIATE")
    dev[0].wait_connected()
    wt.require_sta_pmf(bssid, addr)
    sta = hapd.get_sta(addr)
    if '[MFP]' not in sta['flags']:
        raise Exception("MFP flag not present for STA")
    cmd = subprocess.Popen(['iw', 'dev', apdev[0]['ifname'], 'station', 'get',
                            addr], stdout=subprocess.PIPE)
    (data,err) = cmd.communicate()
    if "yes" not in [l for l in data.splitlines() if "MFP" in l][0]:
        raise Exception("Kernel STA entry did not have MFP enabled")
