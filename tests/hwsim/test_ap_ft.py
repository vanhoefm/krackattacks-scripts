# Fast BSS Transition tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
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
from test_ap_psk import check_mib

def ft_base_rsn():
    params = { "wpa": "2",
               "wpa_key_mgmt": "FT-PSK",
               "rsn_pairwise": "CCMP" }
    return params

def ft_base_mixed():
    params = { "wpa": "3",
               "wpa_key_mgmt": "WPA-PSK FT-PSK",
               "wpa_pairwise": "TKIP",
               "rsn_pairwise": "CCMP" }
    return params

def ft_params(rsn=True, ssid=None, passphrase=None):
    if rsn:
        params = ft_base_rsn()
    else:
        params = ft_base_mixed()
    if ssid:
        params["ssid"] = ssid
    if passphrase:
        params["wpa_passphrase"] = passphrase

    params["mobility_domain"] = "a1b2"
    params["r0_key_lifetime"] = "10000"
    params["pmk_r1_push"] = "1"
    params["reassociation_deadline"] = "1000"
    return params

def ft_params1(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas1.w1.fi"
    params['r1_key_holder'] = "000102030405"
    params['r0kh'] = [ "02:00:00:00:03:00 nas1.w1.fi 100102030405060708090a0b0c0d0e0f",
                       "02:00:00:00:04:00 nas2.w1.fi 300102030405060708090a0b0c0d0e0f" ]
    params['r1kh'] = "02:00:00:00:04:00 00:01:02:03:04:06 200102030405060708090a0b0c0d0e0f"
    return params

def ft_params2(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas2.w1.fi"
    params['r1_key_holder'] = "000102030406"
    params['r0kh'] = [ "02:00:00:00:03:00 nas1.w1.fi 200102030405060708090a0b0c0d0e0f",
                       "02:00:00:00:04:00 nas2.w1.fi 000102030405060708090a0b0c0d0e0f" ]
    params['r1kh'] = "02:00:00:00:03:00 00:01:02:03:04:05 300102030405060708090a0b0c0d0e0f"
    return params

def ft_params1_r0kh_mismatch(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas1.w1.fi"
    params['r1_key_holder'] = "000102030405"
    params['r0kh'] = [ "02:00:00:00:03:00 nas1.w1.fi 100102030405060708090a0b0c0d0e0f",
                       "12:00:00:00:04:00 nas2.w1.fi 300102030405060708090a0b0c0d0e0f" ]
    params['r1kh'] = "12:00:00:00:04:00 10:01:02:03:04:06 200102030405060708090a0b0c0d0e0f"
    return params

def ft_params2_incorrect_rrb_key(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas2.w1.fi"
    params['r1_key_holder'] = "000102030406"
    params['r0kh'] = [ "02:00:00:00:03:00 nas1.w1.fi 200102030405060708090a0b0c0d0ef1",
                       "02:00:00:00:04:00 nas2.w1.fi 000102030405060708090a0b0c0d0ef2" ]
    params['r1kh'] = "02:00:00:00:03:00 00:01:02:03:04:05 300102030405060708090a0b0c0d0ef3"
    return params

def ft_params2_r0kh_mismatch(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas2.w1.fi"
    params['r1_key_holder'] = "000102030406"
    params['r0kh'] = [ "12:00:00:00:03:00 nas1.w1.fi 200102030405060708090a0b0c0d0e0f",
                       "02:00:00:00:04:00 nas2.w1.fi 000102030405060708090a0b0c0d0e0f" ]
    params['r1kh'] = "12:00:00:00:03:00 10:01:02:03:04:05 300102030405060708090a0b0c0d0e0f"
    return params

def run_roams(dev, apdev, hapd0, hapd1, ssid, passphrase, over_ds=False, sae=False, eap=False, fail_test=False, roams=1):
    logger.info("Connect to first AP")
    if eap:
        dev.connect(ssid, key_mgmt="FT-EAP", proto="WPA2", ieee80211w="1",
                    eap="EKE", identity="eke user", password="hello")
    else:
        if sae:
            key_mgmt="FT-SAE"
        else:
            key_mgmt="FT-PSK"
        dev.connect(ssid, psk=passphrase, key_mgmt=key_mgmt, proto="WPA2",
                    ieee80211w="1")
    if dev.get_status_field('bssid') == apdev[0]['bssid']:
        ap1 = apdev[0]
        ap2 = apdev[1]
        hapd1ap = hapd0
        hapd2ap = hapd1
    else:
        ap1 = apdev[1]
        ap2 = apdev[0]
        hapd1ap = hapd1
        hapd2ap = hapd0
    hwsim_utils.test_connectivity(dev, hapd1ap)

    dev.scan_for_bss(ap2['bssid'], freq="2412")

    for i in range(0, roams):
        logger.info("Roam to the second AP")
        if over_ds:
            dev.roam_over_ds(ap2['bssid'], fail_test=fail_test)
        else:
            dev.roam(ap2['bssid'], fail_test=fail_test)
        if fail_test:
            return
        if dev.get_status_field('bssid') != ap2['bssid']:
            raise Exception("Did not connect to correct AP")
        if i == 0 or i == roams - 1:
            hwsim_utils.test_connectivity(dev, hapd2ap)

        logger.info("Roam back to the first AP")
        if over_ds:
            dev.roam_over_ds(ap1['bssid'])
        else:
            dev.roam(ap1['bssid'])
        if dev.get_status_field('bssid') != ap1['bssid']:
            raise Exception("Did not connect to correct AP")
        if i == 0 or i == roams - 1:
            hwsim_utils.test_connectivity(dev, hapd1ap)

def test_ap_ft(dev, apdev):
    """WPA2-PSK-FT AP"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase)
    if "[WPA2-FT/PSK-CCMP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing RSN element info")

def test_ap_ft_many(dev, apdev):
    """WPA2-PSK-FT AP multiple times"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, roams=50)

def test_ap_ft_mixed(dev, apdev):
    """WPA2-PSK-FT mixed-mode AP"""
    ssid = "test-ft-mixed"
    passphrase="12345678"

    params = ft_params1(rsn=False, ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    vals = key_mgmt.split(' ')
    if vals[0] != "WPA-PSK" or vals[1] != "FT-PSK":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    params = ft_params2(rsn=False, ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd, hapd1, ssid, passphrase)

def test_ap_ft_pmf(dev, apdev):
    """WPA2-PSK-FT AP with PMF"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase)

def test_ap_ft_over_ds(dev, apdev):
    """WPA2-PSK-FT AP over DS"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True)
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-4"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-4") ])

def test_ap_ft_over_ds_many(dev, apdev):
    """WPA2-PSK-FT AP over DS multiple times"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              roams=50)

def test_ap_ft_over_ds_unknown_target(dev, apdev):
    """WPA2-PSK-FT AP"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")
    dev[0].roam_over_ds("02:11:22:33:44:55", fail_test=True)

def test_ap_ft_pmf_over_ds(dev, apdev):
    """WPA2-PSK-FT AP over DS with PMF"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True)

def test_ap_ft_over_ds_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS (pull PMK)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True)

def test_ap_ft_sae(dev, apdev):
    """WPA2-PSK-FT-SAE AP"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-SAE"
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-SAE"
    hapd = hostapd.add_ap(apdev[1]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "FT-SAE":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)

    dev[0].request("SET sae_groups ")
    run_roams(dev[0], apdev, hapd0, hapd, ssid, passphrase, sae=True)

def test_ap_ft_sae_over_ds(dev, apdev):
    """WPA2-PSK-FT-SAE AP over DS"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-SAE"
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-SAE"
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].request("SET sae_groups ")
    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, sae=True,
              over_ds=True)

def test_ap_ft_eap(dev, apdev):
    """WPA2-EAP-FT AP"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "FT-EAP":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd, hapd1, ssid, passphrase, eap=True)
    if "[WPA2-FT/EAP-CCMP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing RSN element info")
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-3"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-3") ])

def test_ap_ft_eap_pull(dev, apdev):
    """WPA2-EAP-FT AP (pull PMK)"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params["pmk_r1_push"] = "0"
    params = dict(radius.items() + params.items())
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "FT-EAP":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params["pmk_r1_push"] = "0"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd, hapd1, ssid, passphrase, eap=True)

def test_ap_ft_mismatching_rrb_key_push(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching RRB key (push)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2_incorrect_rrb_key(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

def test_ap_ft_mismatching_rrb_key_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching RRB key (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2_incorrect_rrb_key(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

def test_ap_ft_mismatching_r0kh_id_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching R0KH-ID (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params["nas_identifier"] = "nas0.w1.fi"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2")

    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    dev[0].roam_over_ds(apdev[1]['bssid'], fail_test=True)

def test_ap_ft_mismatching_rrb_r0kh_push(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching R0KH key (push)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2_r0kh_mismatch(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

def test_ap_ft_mismatching_rrb_r0kh_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching R0KH key (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1_r0kh_mismatch(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

def test_ap_ft_gtk_rekey(dev, apdev):
    """WPA2-PSK-FT AP and GTK rekey"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   ieee80211w="1")

    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out after initial association")
    hwsim_utils.test_connectivity(dev[0], hapd)

    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_group_rekey'] = '1'
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    dev[0].roam(apdev[1]['bssid'])
    if dev[0].get_status_field('bssid') != apdev[1]['bssid']:
        raise Exception("Did not connect to correct AP")
    hwsim_utils.test_connectivity(dev[0], hapd1)

    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out after FT protocol")
    hwsim_utils.test_connectivity(dev[0], hapd1)
