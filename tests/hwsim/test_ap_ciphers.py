# Cipher suite tests
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import time
import logging
logger = logging.getLogger()
import os.path

import hwsim_utils
import hostapd
from utils import HwsimSkip, skip_with_fips
from wlantest import Wlantest

def check_cipher(dev, ap, cipher):
    if cipher not in dev.get_capability("pairwise"):
        raise HwsimSkip("Cipher %s not supported" % cipher)
    params = { "ssid": "test-wpa2-psk",
               "wpa_passphrase": "12345678",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": cipher }
    hapd = hostapd.add_ap(ap, params)
    dev.connect("test-wpa2-psk", psk="12345678",
                pairwise=cipher, group=cipher, scan_freq="2412")
    hwsim_utils.test_connectivity(dev, hapd)

def check_group_mgmt_cipher(dev, ap, cipher):
    if cipher not in dev.get_capability("group_mgmt"):
        raise HwsimSkip("Cipher %s not supported" % cipher)
    params = { "ssid": "test-wpa2-psk-pmf",
               "wpa_passphrase": "12345678",
               "wpa": "2",
               "ieee80211w": "2",
               "wpa_key_mgmt": "WPA-PSK-SHA256",
               "rsn_pairwise": "CCMP",
               "group_mgmt_cipher": cipher }
    hapd = hostapd.add_ap(ap, params)

    Wlantest.setup(hapd)
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")

    dev.connect("test-wpa2-psk-pmf", psk="12345678", ieee80211w="2",
                key_mgmt="WPA-PSK-SHA256",
                pairwise="CCMP", group="CCMP", scan_freq="2412")
    hwsim_utils.test_connectivity(dev, hapd)
    hapd.request("DEAUTHENTICATE ff:ff:ff:ff:ff:ff")
    dev.wait_disconnected()
    if wt.get_bss_counter('valid_bip_mmie', ap['bssid']) < 1:
        raise Exception("No valid BIP MMIE seen")
    if wt.get_bss_counter('bip_deauth', ap['bssid']) < 1:
        raise Exception("No valid BIP deauth seen")

    if cipher == "AES-128-CMAC":
        group_mgmt = "BIP"
    else:
        group_mgmt = cipher
    res =  wt.info_bss('group_mgmt', ap['bssid']).strip()
    if res != group_mgmt:
        raise Exception("Unexpected group mgmt cipher: " + res)

@remote_compatible
def test_ap_cipher_tkip(dev, apdev):
    """WPA2-PSK/TKIP connection"""
    skip_with_fips(dev[0])
    check_cipher(dev[0], apdev[0], "TKIP")

@remote_compatible
def test_ap_cipher_tkip_countermeasures_ap(dev, apdev):
    """WPA-PSK/TKIP countermeasures (detected by AP)"""
    skip_with_fips(dev[0])
    testfile = "/sys/kernel/debug/ieee80211/%s/netdev:%s/tkip_mic_test" % (dev[0].get_driver_status_field("phyname"), dev[0].ifname)
    if dev[0].cmd_execute([ "ls", testfile ])[0] != 0:
        raise HwsimSkip("tkip_mic_test not supported in mac80211")

    params = { "ssid": "tkip-countermeasures",
               "wpa_passphrase": "12345678",
               "wpa": "1",
               "wpa_key_mgmt": "WPA-PSK",
               "wpa_pairwise": "TKIP" }
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("tkip-countermeasures", psk="12345678",
                   pairwise="TKIP", group="TKIP", scan_freq="2412")

    dev[0].dump_monitor()
    dev[0].cmd_execute([ "echo", "-n", apdev[0]['bssid'], ">", testfile ],
                       shell=True)
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection on first Michael MIC failure")

    dev[0].cmd_execute([ "echo", "-n", "ff:ff:ff:ff:ff:ff", ">", testfile ],
                       shell=True)
    ev = dev[0].wait_disconnected(timeout=10,
                                  error="No disconnection after two Michael MIC failures")
    if "reason=14" not in ev:
        raise Exception("Unexpected disconnection reason: " + ev)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection during TKIP countermeasures")

@remote_compatible
def test_ap_cipher_tkip_countermeasures_sta(dev, apdev):
    """WPA-PSK/TKIP countermeasures (detected by STA)"""
    skip_with_fips(dev[0])
    params = { "ssid": "tkip-countermeasures",
               "wpa_passphrase": "12345678",
               "wpa": "1",
               "wpa_key_mgmt": "WPA-PSK",
               "wpa_pairwise": "TKIP" }
    hapd = hostapd.add_ap(apdev[0], params)

    testfile = "/sys/kernel/debug/ieee80211/%s/netdev:%s/tkip_mic_test" % (hapd.get_driver_status_field("phyname"), apdev[0]['ifname'])
    if hapd.cmd_execute([ "ls", testfile ])[0] != 0:
        raise HwsimSkip("tkip_mic_test not supported in mac80211")

    dev[0].connect("tkip-countermeasures", psk="12345678",
                   pairwise="TKIP", group="TKIP", scan_freq="2412")

    dev[0].dump_monitor()
    hapd.cmd_execute([ "echo", "-n", dev[0].own_addr(), ">", testfile ],
                     shell=True)
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection on first Michael MIC failure")

    hapd.cmd_execute([ "echo", "-n", "ff:ff:ff:ff:ff:ff", ">", testfile ],
                     shell=True)
    ev = dev[0].wait_disconnected(timeout=10,
                                  error="No disconnection after two Michael MIC failures")
    if "reason=14 locally_generated=1" not in ev:
        raise Exception("Unexpected disconnection reason: " + ev)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection during TKIP countermeasures")

@remote_compatible
def test_ap_cipher_ccmp(dev, apdev):
    """WPA2-PSK/CCMP connection"""
    check_cipher(dev[0], apdev[0], "CCMP")

def test_ap_cipher_gcmp(dev, apdev):
    """WPA2-PSK/GCMP connection"""
    check_cipher(dev[0], apdev[0], "GCMP")

def test_ap_cipher_ccmp_256(dev, apdev):
    """WPA2-PSK/CCMP-256 connection"""
    check_cipher(dev[0], apdev[0], "CCMP-256")

def test_ap_cipher_gcmp_256(dev, apdev):
    """WPA2-PSK/GCMP-256 connection"""
    check_cipher(dev[0], apdev[0], "GCMP-256")

@remote_compatible
def test_ap_cipher_mixed_wpa_wpa2(dev, apdev):
    """WPA2-PSK/CCMP/ and WPA-PSK/TKIP mixed configuration"""
    skip_with_fips(dev[0])
    ssid = "test-wpa-wpa2-psk"
    passphrase = "12345678"
    params = { "ssid": ssid,
               "wpa_passphrase": passphrase,
               "wpa": "3",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": "CCMP",
               "wpa_pairwise": "TKIP" }
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].connect(ssid, psk=passphrase, proto="WPA2",
                   pairwise="CCMP", group="TKIP", scan_freq="2412")
    status = dev[0].get_status()
    if status['key_mgmt'] != 'WPA2-PSK':
        raise Exception("Incorrect key_mgmt reported")
    if status['pairwise_cipher'] != 'CCMP':
        raise Exception("Incorrect pairwise_cipher reported")
    if status['group_cipher'] != 'TKIP':
        raise Exception("Incorrect group_cipher reported")
    bss = dev[0].get_bss(apdev[0]['bssid'])
    if bss['ssid'] != ssid:
        raise Exception("Unexpected SSID in the BSS entry")
    if "[WPA-PSK-TKIP]" not in bss['flags']:
        raise Exception("Missing BSS flag WPA-PSK-TKIP")
    if "[WPA2-PSK-CCMP]" not in bss['flags']:
        raise Exception("Missing BSS flag WPA2-PSK-CCMP")
    hwsim_utils.test_connectivity(dev[0], hapd)

    dev[1].connect(ssid, psk=passphrase, proto="WPA",
                   pairwise="TKIP", group="TKIP", scan_freq="2412")
    status = dev[1].get_status()
    if status['key_mgmt'] != 'WPA-PSK':
        raise Exception("Incorrect key_mgmt reported")
    if status['pairwise_cipher'] != 'TKIP':
        raise Exception("Incorrect pairwise_cipher reported")
    if status['group_cipher'] != 'TKIP':
        raise Exception("Incorrect group_cipher reported")
    hwsim_utils.test_connectivity(dev[1], hapd)
    hwsim_utils.test_connectivity(dev[0], dev[1])

@remote_compatible
def test_ap_cipher_bip(dev, apdev):
    """WPA2-PSK with BIP"""
    check_group_mgmt_cipher(dev[0], apdev[0], "AES-128-CMAC")

def test_ap_cipher_bip_gmac_128(dev, apdev):
    """WPA2-PSK with BIP-GMAC-128"""
    check_group_mgmt_cipher(dev[0], apdev[0], "BIP-GMAC-128")

def test_ap_cipher_bip_gmac_256(dev, apdev):
    """WPA2-PSK with BIP-GMAC-256"""
    check_group_mgmt_cipher(dev[0], apdev[0], "BIP-GMAC-256")

def test_ap_cipher_bip_cmac_256(dev, apdev):
    """WPA2-PSK with BIP-CMAC-256"""
    check_group_mgmt_cipher(dev[0], apdev[0], "BIP-CMAC-256")
