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
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[1].ifname, apdev[0]['ifname'])
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
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[1].ifname, apdev[0]['ifname'])
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
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[1].ifname, apdev[0]['ifname'])
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
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk="12345678", ieee80211w="1",
                   key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                   scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    try:
        dev[1].connect(ssid, psk="12345678", ieee80211w="2",
                       key_mgmt="WPA-PSK WPA-PSK-SHA256", proto="WPA2",
                       scan_freq="2412")
        hwsim_utils.test_connectivity(dev[1].ifname, apdev[0]['ifname'])
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
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout on disconnection")
    hapd.set("ext_mgmt_frame_handling", "0")
    dev[0].request("REASSOCIATE")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout on re-connection")
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
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout on re-connection")
    if wt.get_sta_counter("reassocresp_comeback", apdev[0]['bssid'],
                          dev[0].p2p_interface_addr()) < 1:
        raise Exception("AP did not use reassociation comeback request")

def test_ap_pmf_sta_sa_query(dev, apdev):
    """WPA2-PSK AP with station using SA Query"""
    ssid = "assoc-comeback"
    addr = dev[0].p2p_dev_addr()
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
