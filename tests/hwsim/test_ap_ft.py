# Fast BSS Transition tests
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import binascii
import os
import time
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd
from utils import HwsimSkip, alloc_fail, fail_test, skip_with_fips
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

def ft_params1a(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas1.w1.fi"
    params['r1_key_holder'] = "000102030405"
    return params

def ft_params1(rsn=True, ssid=None, passphrase=None):
    params = ft_params1a(rsn, ssid, passphrase)
    params['r0kh'] = [ "02:00:00:00:03:00 nas1.w1.fi 100102030405060708090a0b0c0d0e0f",
                       "02:00:00:00:04:00 nas2.w1.fi 300102030405060708090a0b0c0d0e0f" ]
    params['r1kh'] = "02:00:00:00:04:00 00:01:02:03:04:06 200102030405060708090a0b0c0d0e0f"
    return params

def ft_params2a(rsn=True, ssid=None, passphrase=None):
    params = ft_params(rsn, ssid, passphrase)
    params['nas_identifier'] = "nas2.w1.fi"
    params['r1_key_holder'] = "000102030406"
    return params

def ft_params2(rsn=True, ssid=None, passphrase=None):
    params = ft_params2a(rsn, ssid, passphrase)
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

def run_roams(dev, apdev, hapd0, hapd1, ssid, passphrase, over_ds=False,
              sae=False, eap=False, fail_test=False, roams=1,
              pairwise_cipher="CCMP", group_cipher="TKIP CCMP", ptk_rekey="0"):
    logger.info("Connect to first AP")
    if eap:
        dev.connect(ssid, key_mgmt="FT-EAP", proto="WPA2", ieee80211w="1",
                    eap="GPSK", identity="gpsk user",
                    password="abcdefghijklmnop0123456789abcdef",
                    scan_freq="2412",
                    pairwise=pairwise_cipher, group=group_cipher,
                    wpa_ptk_rekey=ptk_rekey)
    else:
        if sae:
            key_mgmt="FT-SAE"
        else:
            key_mgmt="FT-PSK"
        dev.connect(ssid, psk=passphrase, key_mgmt=key_mgmt, proto="WPA2",
                    ieee80211w="1", scan_freq="2412",
                    pairwise=pairwise_cipher, group=group_cipher,
                    wpa_ptk_rekey=ptk_rekey)
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
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase)
    if "[WPA2-FT/PSK-CCMP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing RSN element info")

def test_ap_ft_local_key_gen(dev, apdev):
    """WPA2-PSK-FT AP with local key generation (without pull/push)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1a(ssid=ssid, passphrase=passphrase)
    params['ft_psk_generate_local'] = "1";
    del params['pmk_r1_push']
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2a(ssid=ssid, passphrase=passphrase)
    params['ft_psk_generate_local'] = "1";
    del params['pmk_r1_push']
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase)
    if "[WPA2-FT/PSK-CCMP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing RSN element info")

def test_ap_ft_many(dev, apdev):
    """WPA2-PSK-FT AP multiple times"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, roams=50)

def test_ap_ft_mixed(dev, apdev):
    """WPA2-PSK-FT mixed-mode AP"""
    ssid = "test-ft-mixed"
    passphrase="12345678"

    params = ft_params1(rsn=False, ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    vals = key_mgmt.split(' ')
    if vals[0] != "WPA-PSK" or vals[1] != "FT-PSK":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    params = ft_params2(rsn=False, ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd, hapd1, ssid, passphrase)

def test_ap_ft_pmf(dev, apdev):
    """WPA2-PSK-FT AP with PMF"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase)

def test_ap_ft_over_ds(dev, apdev):
    """WPA2-PSK-FT AP over DS"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True)
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-4"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-4") ])

def test_ap_ft_over_ds_many(dev, apdev):
    """WPA2-PSK-FT AP over DS multiple times"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              roams=50)

@remote_compatible
def test_ap_ft_over_ds_unknown_target(dev, apdev):
    """WPA2-PSK-FT AP"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")
    dev[0].roam_over_ds("02:11:22:33:44:55", fail_test=True)

@remote_compatible
def test_ap_ft_over_ds_unexpected(dev, apdev):
    """WPA2-PSK-FT AP over DS and unexpected response"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

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
    params["ieee80211w"] = "2"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True)

def test_ap_ft_over_ds_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS (pull PMK)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True)

def test_ap_ft_sae(dev, apdev):
    """WPA2-PSK-FT-SAE AP"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-SAE"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-SAE"
    hapd = hostapd.add_ap(apdev[1], params)
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
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-SAE"
    hapd1 = hostapd.add_ap(apdev[1], params)

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
    hapd = hostapd.add_ap(apdev[0], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "FT-EAP":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd, hapd1, ssid, passphrase, eap=True)
    if "[WPA2-FT/EAP-CCMP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing RSN element info")
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-3"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-3") ])

    # Verify EAPOL reauthentication after FT protocol
    if dev[0].get_status_field('bssid') == apdev[0]['bssid']:
        ap = hapd
    else:
        ap = hapd1
    ap.request("EAPOL_REAUTH " + dev[0].own_addr())
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=5)
    if ev is None:
        raise Exception("EAP authentication did not start")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("EAP authentication did not succeed")
    time.sleep(0.1)
    hwsim_utils.test_connectivity(dev[0], ap)

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
    hapd = hostapd.add_ap(apdev[0], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "FT-EAP":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params["pmk_r1_push"] = "0"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd, hapd1, ssid, passphrase, eap=True)

@remote_compatible
def test_ap_ft_mismatching_rrb_key_push(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching RRB key (push)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2_incorrect_rrb_key(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

@remote_compatible
def test_ap_ft_mismatching_rrb_key_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching RRB key (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2_incorrect_rrb_key(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

@remote_compatible
def test_ap_ft_mismatching_r0kh_id_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching R0KH-ID (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params["nas_identifier"] = "nas0.w1.fi"
    hostapd.add_ap(apdev[0], params)
    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")

    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hostapd.add_ap(apdev[1], params)

    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    dev[0].roam_over_ds(apdev[1]['bssid'], fail_test=True)

@remote_compatible
def test_ap_ft_mismatching_rrb_r0kh_push(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching R0KH key (push)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2_r0kh_mismatch(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

@remote_compatible
def test_ap_ft_mismatching_rrb_r0kh_pull(dev, apdev):
    """WPA2-PSK-FT AP over DS with mismatching R0KH key (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1_r0kh_mismatch(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True)

def test_ap_ft_mismatching_rrb_key_push_eap(dev, apdev):
    """WPA2-EAP-FT AP over DS with mismatching RRB key (push)"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2_incorrect_rrb_key(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True, eap=True)

def test_ap_ft_mismatching_rrb_key_pull_eap(dev, apdev):
    """WPA2-EAP-FT AP over DS with mismatching RRB key (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2_incorrect_rrb_key(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True, eap=True)

def test_ap_ft_mismatching_r0kh_id_pull_eap(dev, apdev):
    """WPA2-EAP-FT AP over DS with mismatching R0KH-ID (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params["nas_identifier"] = "nas0.w1.fi"
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="FT-EAP", proto="WPA2", ieee80211w="1",
                   eap="GPSK", identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")

    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    dev[0].roam_over_ds(apdev[1]['bssid'], fail_test=True)

def test_ap_ft_mismatching_rrb_r0kh_push_eap(dev, apdev):
    """WPA2-EAP-FT AP over DS with mismatching R0KH key (push)"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2_r0kh_mismatch(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "2";
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True, eap=True)

def test_ap_ft_mismatching_rrb_r0kh_pull_eap(dev, apdev):
    """WPA2-EAP-FT AP over DS with mismatching R0KH key (pull)"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1_r0kh_mismatch(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd0 = hostapd.add_ap(apdev[0]['ifname'], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params["pmk_r1_push"] = "0"
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd1 = hostapd.add_ap(apdev[1]['ifname'], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, over_ds=True,
              fail_test=True, eap=True)

def test_ap_ft_gtk_rekey(dev, apdev):
    """WPA2-PSK-FT AP and GTK rekey"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   ieee80211w="1", scan_freq="2412")

    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out after initial association")
    hwsim_utils.test_connectivity(dev[0], hapd)

    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_group_rekey'] = '1'
    hapd1 = hostapd.add_ap(apdev[1], params)

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
    hapd0 = hostapd.add_ap(apdev[0], p)
    p = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], p)

    pid = find_wpas_process(dev[0])

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")
    # The decrypted copy of GTK is freed only after the CTRL-EVENT-CONNECTED
    # event has been delivered, so verify that wpa_supplicant has returned to
    # eloop before reading process memory.
    time.sleep(1)
    dev[0].ping()

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
        get_key_locations(buf, gtk, "GTK")
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

@remote_compatible
def test_ap_ft_invalid_resp(dev, apdev):
    """WPA2-PSK-FT AP and invalid response IEs"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")

    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    tests = [
        # Various IEs for test coverage. The last one is FTIE with invalid
        # R1KH-ID subelement.
        "020002000000" + "3800" + "38051122334455" + "3754000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010100",
        # FTIE with invalid R0KH-ID subelement (len=0).
        "020002000000" + "3754000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010300",
        # FTIE with invalid R0KH-ID subelement (len=49).
        "020002000000" + "378500010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001033101020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849",
        # Invalid RSNE.
        "020002000000" + "3000",
        # Required IEs missing from protected IE count.
        "020002000000" + "3603a1b201" + "375200010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001" + "3900",
        # RIC missing from protected IE count.
        "020002000000" + "3603a1b201" + "375200020203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001" + "3900",
        # Protected IE missing.
        "020002000000" + "3603a1b201" + "375200ff0203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809000102030405060708090001" + "3900" + "0000" ]
    for t in tests:
        dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
        hapd1.set("ext_mgmt_frame_handling", "1")
        hapd1.dump_monitor()
        if "OK" not in dev[0].request("ROAM " + apdev[1]['bssid']):
            raise Exception("ROAM failed")
        auth = None
        for i in range(20):
            msg = hapd1.mgmt_rx()
            if msg['subtype'] == 11:
                auth = msg
                break
        if not auth:
            raise Exception("Authentication frame not seen")

        resp = {}
        resp['fc'] = auth['fc']
        resp['da'] = auth['sa']
        resp['sa'] = auth['da']
        resp['bssid'] = auth['bssid']
        resp['payload'] = binascii.unhexlify(t)
        hapd1.mgmt_tx(resp)
        hapd1.set("ext_mgmt_frame_handling", "0")
        dev[0].wait_disconnected()

        dev[0].request("RECONNECT")
        dev[0].wait_connected()

def test_ap_ft_gcmp_256(dev, apdev):
    """WPA2-PSK-FT AP with GCMP-256 cipher"""
    if "GCMP-256" not in dev[0].get_capability("pairwise"):
        raise HwsimSkip("Cipher GCMP-256 not supported")
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['rsn_pairwise'] = "GCMP-256"
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['rsn_pairwise'] = "GCMP-256"
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase,
              pairwise_cipher="GCMP-256", group_cipher="GCMP-256")

def test_ap_ft_oom(dev, apdev):
    """WPA2-PSK-FT and OOM"""
    skip_with_fips(dev[0])
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")
    if dev[0].get_status_field('bssid') == apdev[0]['bssid']:
        dst = apdev[1]['bssid']
    else:
        dst = apdev[0]['bssid']

    dev[0].scan_for_bss(dst, freq="2412")
    with alloc_fail(dev[0], 1, "wpa_ft_gen_req_ies"):
        dev[0].roam(dst)
    with fail_test(dev[0], 1, "wpa_ft_mic"):
        dev[0].roam(dst, fail_test=True)
    with fail_test(dev[0], 1, "os_get_random;wpa_ft_prepare_auth_request"):
        dev[0].roam(dst, fail_test=True)

    dev[0].request("REMOVE_NETWORK all")
    with alloc_fail(dev[0], 1, "=sme_update_ft_ies"):
        dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                       scan_freq="2412")

def test_ap_ft_over_ds_proto(dev, apdev):
    """WPA2-PSK-FT AP over DS protocol testing"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")

    # FT Action Response while no FT-over-DS in progress
    msg = {}
    msg['fc'] = 13 << 4
    msg['da'] = dev[0].own_addr()
    msg['sa'] = apdev[0]['bssid']
    msg['bssid'] = apdev[0]['bssid']
    msg['payload'] = binascii.unhexlify("06020200000000000200000004000000")
    hapd0.mgmt_tx(msg)

    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)
    dev[0].scan_for_bss(apdev[1]['bssid'], freq="2412")
    hapd0.set("ext_mgmt_frame_handling", "1")
    hapd0.dump_monitor()
    dev[0].request("FT_DS " + apdev[1]['bssid'])
    for i in range(0, 10):
        req = hapd0.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out")
        if req['subtype'] == 13:
            break
        req = None
    if not req:
        raise Exception("FT Action frame not received")

    # FT Action Response for unexpected Target AP
    msg['payload'] = binascii.unhexlify("0602020000000000" + "f20000000400" + "0000")
    hapd0.mgmt_tx(msg)

    # FT Action Response without MDIE
    msg['payload'] = binascii.unhexlify("0602020000000000" + "020000000400" + "0000")
    hapd0.mgmt_tx(msg)

    # FT Action Response without FTIE
    msg['payload'] = binascii.unhexlify("0602020000000000" + "020000000400" + "0000" + "3603a1b201")
    hapd0.mgmt_tx(msg)

    # FT Action Response with FTIE SNonce mismatch
    msg['payload'] = binascii.unhexlify("0602020000000000" + "020000000400" + "0000" + "3603a1b201" + "3766000000000000000000000000000000000000c4e67ac1999bebd00ff4ae4d5dcaf87896bb060b469f7c78d49623fb395c3455ffffff6b693fe6f8d8c5dfac0a22344750775bd09437f98b238c9f87b97f790c0106000102030406030a6e6173312e77312e6669")
    hapd0.mgmt_tx(msg)

@remote_compatible
def test_ap_ft_rrb(dev, apdev):
    """WPA2-PSK-FT RRB protocol testing"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")

    _dst_ll = binascii.unhexlify(apdev[0]['bssid'].replace(':',''))
    _src_ll = binascii.unhexlify(dev[0].own_addr().replace(':',''))
    proto = '\x89\x0d'
    ehdr = _dst_ll + _src_ll + proto

    # Too short RRB frame
    pkt = ehdr + '\x01'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # RRB discarded frame wikth unrecognized type
    pkt = ehdr + '\x02' + '\x02' + '\x01\x00' + _src_ll
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # RRB frame too short for action frame
    pkt = ehdr + '\x01' + '\x02' + '\x01\x00' + _src_ll
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Too short RRB frame (not enough room for Action Frame body)
    pkt = ehdr + '\x01' + '\x02' + '\x00\x00' + _src_ll
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Unexpected Action frame category
    pkt = ehdr + '\x01' + '\x02' + '\x0e\x00' + _src_ll + '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Unexpected Action in RRB Request
    pkt = ehdr + '\x01' + '\x00' + '\x0e\x00' + _src_ll + '\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Target AP address in RRB Request does not match with own address
    pkt = ehdr + '\x01' + '\x00' + '\x0e\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Not enough room for status code in RRB Response
    pkt = ehdr + '\x01' + '\x01' + '\x0e\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # RRB discarded frame with unknown packet_type
    pkt = ehdr + '\x01' + '\x02' + '\x0e\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # RRB Response with non-zero status code; no STA match
    pkt = ehdr + '\x01' + '\x01' + '\x10\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + '\xff\xff'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # RRB Response with zero status code and extra data; STA match
    pkt = ehdr + '\x01' + '\x01' + '\x11\x00' + _src_ll + '\x06\x01' + _src_ll + '\x00\x00\x00\x00\x00\x00' + '\x00\x00' + '\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Too short PMK-R1 pull
    pkt = ehdr + '\x01' + '\xc8' + '\x0e\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Too short PMK-R1 resp
    pkt = ehdr + '\x01' + '\xc9' + '\x0e\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # Too short PMK-R1 push
    pkt = ehdr + '\x01' + '\xca' + '\x0e\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

    # No matching R0KH address found for PMK-R0 pull response
    pkt = ehdr + '\x01' + '\xc9' + '\x5a\x00' + _src_ll + '\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 76*'\00'
    if "OK" not in dev[0].request("DATA_TEST_FRAME " + binascii.hexlify(pkt)):
        raise Exception("DATA_TEST_FRAME failed")

@remote_compatible
def test_rsn_ie_proto_ft_psk_sta(dev, apdev):
    """RSN element protocol testing for FT-PSK + PMF cases on STA side"""
    bssid = apdev[0]['bssid']
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["ieee80211w"] = "1"
    # This is the RSN element used normally by hostapd
    params['own_ie_override'] = '30140100000fac040100000fac040100000fac048c00' + '3603a1b201'
    hapd = hostapd.add_ap(apdev[0], params)
    id = dev[0].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                        ieee80211w="1", scan_freq="2412",
                        pairwise="CCMP", group="CCMP")

    tests = [ ('PMKIDCount field included',
               '30160100000fac040100000fac040100000fac048c000000' + '3603a1b201'),
              ('Extra IE before RSNE',
               'dd0400000000' + '30140100000fac040100000fac040100000fac048c00' + '3603a1b201'),
              ('PMKIDCount and Group Management Cipher suite fields included',
               '301a0100000fac040100000fac040100000fac048c000000000fac06' + '3603a1b201'),
              ('Extra octet after defined fields (future extensibility)',
               '301b0100000fac040100000fac040100000fac048c000000000fac0600' + '3603a1b201'),
              ('No RSN Capabilities field (PMF disabled in practice)',
               '30120100000fac040100000fac040100000fac04' + '3603a1b201') ]
    for txt,ie in tests:
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        logger.info(txt)
        hapd.disable()
        hapd.set('own_ie_override', ie)
        hapd.enable()
        dev[0].request("BSS_FLUSH 0")
        dev[0].scan_for_bss(bssid, 2412, force_scan=True, only_new=True)
        dev[0].select_network(id, freq=2412)
        dev[0].wait_connected()

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    logger.info('Invalid RSNE causing internal hostapd error')
    hapd.disable()
    hapd.set('own_ie_override', '30130100000fac040100000fac040100000fac048c' + '3603a1b201')
    hapd.enable()
    dev[0].request("BSS_FLUSH 0")
    dev[0].scan_for_bss(bssid, 2412, force_scan=True, only_new=True)
    dev[0].select_network(id, freq=2412)
    # hostapd fails to generate EAPOL-Key msg 3/4, so this connection cannot
    # complete.
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection")
    dev[0].request("DISCONNECT")

    logger.info('Unexpected PMKID causing internal hostapd error')
    hapd.disable()
    hapd.set('own_ie_override', '30260100000fac040100000fac040100000fac048c000100ffffffffffffffffffffffffffffffff' + '3603a1b201')
    hapd.enable()
    dev[0].request("BSS_FLUSH 0")
    dev[0].scan_for_bss(bssid, 2412, force_scan=True, only_new=True)
    dev[0].select_network(id, freq=2412)
    # hostapd fails to generate EAPOL-Key msg 3/4, so this connection cannot
    # complete.
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection")
    dev[0].request("DISCONNECT")

def test_ap_ft_ptk_rekey(dev, apdev):
    """WPA2-PSK-FT PTK rekeying triggered by station after roam"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase, ptk_rekey="1")

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED",
                            "WPA: Key negotiation completed"], timeout=5)
    if ev is None:
        raise Exception("No event received after roam")
    if "CTRL-EVENT-DISCONNECTED" in ev:
        raise Exception("Unexpected disconnection after roam")

    if dev[0].get_status_field('bssid') == apdev[0]['bssid']:
        hapd = hapd0
    else:
        hapd = hapd1
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_ft_ptk_rekey_ap(dev, apdev):
    """WPA2-PSK-FT PTK rekeying triggered by AP after roam"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_ptk_rekey'] = '2'
    hapd0 = hostapd.add_ap(apdev[0], params)
    params = ft_params2(ssid=ssid, passphrase=passphrase)
    params['wpa_ptk_rekey'] = '2'
    hapd1 = hostapd.add_ap(apdev[1], params)

    run_roams(dev[0], apdev, hapd0, hapd1, ssid, passphrase)

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED",
                            "WPA: Key negotiation completed"], timeout=5)
    if ev is None:
        raise Exception("No event received after roam")
    if "CTRL-EVENT-DISCONNECTED" in ev:
        raise Exception("Unexpected disconnection after roam")

    if dev[0].get_status_field('bssid') == apdev[0]['bssid']:
        hapd = hapd0
    else:
        hapd = hapd1
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_ft_internal_rrb_check(dev, apdev):
    """RRB internal delivery only to WPA enabled BSS"""
    ssid = "test-ft"
    passphrase="12345678"

    radius = hostapd.radius_params()
    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "FT-EAP"
    params["ieee8021x"] = "1"
    params = dict(radius.items() + params.items())
    hapd = hostapd.add_ap(apdev[0], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "FT-EAP":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)

    hapd1 = hostapd.add_ap(apdev[1], { "ssid" : ssid })

    # Connect to WPA enabled AP
    dev[0].connect(ssid, key_mgmt="FT-EAP", proto="WPA2", ieee80211w="1",
                   eap="GPSK", identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")

    # Try over_ds roaming to non-WPA-enabled AP.
    # If hostapd does not check hapd->wpa_auth internally, it will crash now.
    dev[0].roam_over_ds(apdev[1]['bssid'], fail_test=True)

def test_ap_ft_extra_ie(dev, apdev):
    """WPA2-PSK-FT AP with WPA2-PSK enabled and unexpected MDE"""
    ssid = "test-ft"
    passphrase="12345678"

    params = ft_params1(ssid=ssid, passphrase=passphrase)
    params["wpa_key_mgmt"] = "WPA-PSK FT-PSK"
    hapd0 = hostapd.add_ap(apdev[0], params)
    dev[1].connect(ssid, psk=passphrase, key_mgmt="FT-PSK", proto="WPA2",
                   scan_freq="2412")
    dev[2].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK", proto="WPA2",
                   scan_freq="2412")
    try:
        # Add Mobility Domain element to test AP validation code.
        dev[0].request("VENDOR_ELEM_ADD 13 3603a1b201")
        dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK", proto="WPA2",
                       scan_freq="2412", wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                                "CTRL-EVENT-ASSOC-REJECT"], timeout=10)
        if ev is None:
            raise Exception("No connection result")
        if "CTRL-EVENT-CONNECTED" in ev:
            raise Exception("Non-FT association accepted with MDE")
        if "status_code=43" not in ev:
            raise Exception("Unexpected status code: " + ev)
        dev[0].request("DISCONNECT")
    finally:
        dev[0].request("VENDOR_ELEM_REMOVE 13 *")
