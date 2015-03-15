# Fast BSS Transition tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import os
import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd
from utils import HwsimSkip
from wlantest import Wlantest
from test_ap_psk import check_mib, find_wpas_process, read_process_memory, verify_not_present, get_key_locations

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
                    eap="GPSK", identity="gpsk user",
                    password="abcdefghijklmnop0123456789abcdef",
                    scan_freq="2412")
    else:
        if sae:
            key_mgmt="FT-SAE"
        else:
            key_mgmt="FT-PSK"
        dev.connect(ssid, psk=passphrase, key_mgmt=key_mgmt, proto="WPA2",
                    ieee80211w="1", scan_freq="2412")
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

def test_ap_ft_over_ds_unexpected(dev, apdev):
    """WPA2-PSK-FT AP over DS and unexpected response"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")
    if dev[0].get_status_field('bssid') == apdev[0]['bssid']:
        ap1 = apdev[0]
        ap2 = apdev[1]
        hapd1ap = hapd0
        hapd2ap = hapd1
    else:
        ap1 = apdev[1]
        ap2 = apdev[0]
        hapd1ap = hapd1
        hapd2ap = hapd0

    addr = dev[0].own_addr()
    hapd1ap.set("ext_mgmt_frame_handling", "1")
    logger.info("Foreign STA address")
    msg = {}
    msg['fc'] = 13 << 4
    msg['da'] = addr
    msg['sa'] = ap1['bssid']
    msg['bssid'] = ap1['bssid']
    msg['payload'] = binascii.unhexlify("06021122334455660102030405060000")
    hapd1ap.mgmt_tx(msg)

    logger.info("No over-the-DS in progress")
    msg['payload'] = binascii.unhexlify("0602" + addr.replace(':', '') + "0102030405060000")
    hapd1ap.mgmt_tx(msg)

    logger.info("Non-zero status code")
    msg['payload'] = binascii.unhexlify("0602" + addr.replace(':', '') + "0102030405060100")
    hapd1ap.mgmt_tx(msg)

    hapd1ap.dump_monitor()

    dev[0].scan_for_bss(ap2['bssid'], freq="2412")
    if "OK" not in dev[0].request("FT_DS " + ap2['bssid']):
            raise Exception("FT_DS failed")

    req = hapd1ap.mgmt_rx()

    logger.info("Foreign Target AP")
    msg['payload'] = binascii.unhexlify("0602" + addr.replace(':', '') + "0102030405060000")
    hapd1ap.mgmt_tx(msg)

    addrs = addr.replace(':', '') + ap2['bssid'].replace(':', '')

    logger.info("No IEs")
    msg['payload'] = binascii.unhexlify("0602" + addrs + "0000")
    hapd1ap.mgmt_tx(msg)

    logger.info("Invalid IEs (trigger parsing failure)")
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003700")
    hapd1ap.mgmt_tx(msg)

    logger.info("Too short MDIE")
    msg['payload'] = binascii.unhexlify("0602" + addrs + "000036021122")
    hapd1ap.mgmt_tx(msg)

    logger.info("Mobility domain mismatch")
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003603112201")
    hapd1ap.mgmt_tx(msg)

    logger.info("No FTIE")
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003603a1b201")
    hapd1ap.mgmt_tx(msg)

    logger.info("FTIE SNonce mismatch")
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003603a1b201375e0000" + "00000000000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000" + "1000000000000000000000000000000000000000000000000000000000000001" + "030a6e6173322e77312e6669")
    hapd1ap.mgmt_tx(msg)

    logger.info("No R0KH-ID subelem in FTIE")
    snonce = binascii.hexlify(req['payload'][111:111+32])
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003603a1b20137520000" + "00000000000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000" + snonce)
    hapd1ap.mgmt_tx(msg)

    logger.info("No R0KH-ID subelem mismatch in FTIE")
    snonce = binascii.hexlify(req['payload'][111:111+32])
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003603a1b201375e0000" + "00000000000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000" + snonce + "030a11223344556677889900")
    hapd1ap.mgmt_tx(msg)

    logger.info("No R1KH-ID subelem in FTIE")
    r0khid = binascii.hexlify(req['payload'][145:145+10])
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003603a1b201375e0000" + "00000000000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000" + snonce + "030a" + r0khid)
    hapd1ap.mgmt_tx(msg)

    logger.info("No RSNE")
    r0khid = binascii.hexlify(req['payload'][145:145+10])
    msg['payload'] = binascii.unhexlify("0602" + addrs + "00003603a1b20137660000" + "00000000000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000" + snonce + "030a" + r0khid + "0106000102030405")
    hapd1ap.mgmt_tx(msg)

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
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
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
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
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
    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")

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
                   ieee80211w="1", scan_freq="2412")

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

def test_ft_psk_key_lifetime_in_memory(dev, apdev, params):
    """WPA2-PSK-FT and key lifetime in memory"""
    ssid = "test-ft"
    passphrase="04c2726b4b8d5f1b4db9c07aa4d9e9d8f765cb5d25ec817e6cc4fcdd5255db0"
    psk = '93c90846ff67af9037ed83fb72b63dbeddaa81d47f926c20909b5886f1d9358d'
    pmk = binascii.unhexlify(psk)
    p = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], p)
    p = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], p)

    pid = find_wpas_process(dev[0])

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")
    time.sleep(1)

    buf = read_process_memory(pid, pmk)

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].relog()
    pmkr0 = None
    pmkr1 = None
    ptk = None
    gtk = None
    with open(os.path.join(params['logdir'], 'log0'), 'r') as f:
        for l in f.readlines():
            if "FT: PMK-R0 - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                pmkr0 = binascii.unhexlify(val)
            if "FT: PMK-R1 - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                pmkr1 = binascii.unhexlify(val)
            if "FT: KCK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                kck = binascii.unhexlify(val)
            if "FT: KEK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                kek = binascii.unhexlify(val)
            if "FT: TK - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                tk = binascii.unhexlify(val)
            if "WPA: Group Key - hexdump" in l:
                val = l.strip().split(':')[3].replace(' ', '')
                gtk = binascii.unhexlify(val)
    if not pmkr0 or not pmkr1 or not kck or not kek or not tk or not gtk:
        raise Exception("Could not find keys from debug log")
    if len(gtk) != 16:
        raise Exception("Unexpected GTK length")

    logger.info("Checking keys in memory while associated")
    get_key_locations(buf, pmk, "PMK")
    get_key_locations(buf, pmkr0, "PMK-R0")
    get_key_locations(buf, pmkr1, "PMK-R1")
    if pmk not in buf:
        raise HwsimSkip("PMK not found while associated")
    if pmkr0 not in buf:
        raise HwsimSkip("PMK-R0 not found while associated")
    if pmkr1 not in buf:
        raise HwsimSkip("PMK-R1 not found while associated")
    if kck not in buf:
        raise Exception("KCK not found while associated")
    if kek not in buf:
        raise Exception("KEK not found while associated")
    if tk in buf:
        raise Exception("TK found from memory")
    if gtk in buf:
        raise Exception("GTK found from memory")

    logger.info("Checking keys in memory after disassociation")
    buf = read_process_memory(pid, pmk)
    get_key_locations(buf, pmk, "PMK")
    get_key_locations(buf, pmkr0, "PMK-R0")
    get_key_locations(buf, pmkr1, "PMK-R1")

    # Note: PMK/PSK is still present in network configuration

    fname = os.path.join(params['logdir'],
                         'ft_psk_key_lifetime_in_memory.memctx-')
    verify_not_present(buf, pmkr0, fname, "PMK-R0")
    verify_not_present(buf, pmkr1, fname, "PMK-R1")
    verify_not_present(buf, kck, fname, "KCK")
    verify_not_present(buf, kek, fname, "KEK")
    verify_not_present(buf, tk, fname, "TK")
    verify_not_present(buf, gtk, fname, "GTK")

    dev[0].request("REMOVE_NETWORK all")

    logger.info("Checking keys in memory after network profile removal")
    buf = read_process_memory(pid, pmk)
    get_key_locations(buf, pmk, "PMK")
    get_key_locations(buf, pmkr0, "PMK-R0")
    get_key_locations(buf, pmkr1, "PMK-R1")

    verify_not_present(buf, pmk, fname, "PMK")
    verify_not_present(buf, pmkr0, fname, "PMK-R0")
    verify_not_present(buf, pmkr1, fname, "PMK-R1")
    verify_not_present(buf, kck, fname, "KCK")
    verify_not_present(buf, kek, fname, "KEK")
    verify_not_present(buf, tk, fname, "TK")
    verify_not_present(buf, gtk, fname, "GTK")
