# Cipher suite tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()
import os.path

import hwsim_utils
import hostapd

def check_cipher(dev, ap, cipher):
    if cipher not in dev.get_capability("pairwise"):
        return "skip"
    params = { "ssid": "test-wpa2-psk",
               "wpa_passphrase": "12345678",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": cipher }
    hostapd.add_ap(ap['ifname'], params)
    dev.connect("test-wpa2-psk", psk="12345678",
                pairwise=cipher, group=cipher, scan_freq="2412")
    hwsim_utils.test_connectivity(dev.ifname, ap['ifname'])

def test_ap_cipher_tkip(dev, apdev):
    """WPA2-PSK/TKIP connection"""
    return check_cipher(dev[0], apdev[0], "TKIP")

def test_ap_cipher_tkip_countermeasures_ap(dev, apdev):
    """WPA-PSK/TKIP countermeasures (detected by AP)"""
    testfile = "/sys/kernel/debug/ieee80211/%s/netdev:%s/tkip_mic_test" % (dev[0].get_driver_status_field("phyname"), dev[0].ifname)
    if not os.path.exists(testfile):
        return "skip"

    params = { "ssid": "tkip-countermeasures",
               "wpa_passphrase": "12345678",
               "wpa": "1",
               "wpa_key_mgmt": "WPA-PSK",
               "wpa_pairwise": "TKIP" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("tkip-countermeasures", psk="12345678",
                   pairwise="TKIP", group="TKIP", scan_freq="2412")

    dev[0].dump_monitor()
    cmd = subprocess.Popen(["sudo", "tee", testfile],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.stdin.write(apdev[0]['bssid'])
    cmd.stdin.close()
    cmd.stdout.read()
    cmd.stdout.close()
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection on first Michael MIC failure")

    cmd = subprocess.Popen(["sudo", "tee", testfile],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.stdin.write("ff:ff:ff:ff:ff:ff")
    cmd.stdin.close()
    cmd.stdout.read()
    cmd.stdout.close()
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("No disconnection after two Michael MIC failures")
    if "reason=14" not in ev:
        raise Exception("Unexpected disconnection reason: " + ev)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection during TKIP countermeasures")

def test_ap_cipher_tkip_countermeasures_sta(dev, apdev):
    """WPA-PSK/TKIP countermeasures (detected by STA)"""
    params = { "ssid": "tkip-countermeasures",
               "wpa_passphrase": "12345678",
               "wpa": "1",
               "wpa_key_mgmt": "WPA-PSK",
               "wpa_pairwise": "TKIP" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    testfile = "/sys/kernel/debug/ieee80211/%s/netdev:%s/tkip_mic_test" % (hapd.get_driver_status_field("phyname"), apdev[0]['ifname'])
    if not os.path.exists(testfile):
        return "skip"

    dev[0].connect("tkip-countermeasures", psk="12345678",
                   pairwise="TKIP", group="TKIP", scan_freq="2412")

    dev[0].dump_monitor()
    cmd = subprocess.Popen(["sudo", "tee", testfile],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.stdin.write(dev[0].p2p_dev_addr())
    cmd.stdin.close()
    cmd.stdout.read()
    cmd.stdout.close()
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection on first Michael MIC failure")

    cmd = subprocess.Popen(["sudo", "tee", testfile],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.stdin.write("ff:ff:ff:ff:ff:ff")
    cmd.stdin.close()
    cmd.stdout.read()
    cmd.stdout.close()
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("No disconnection after two Michael MIC failures")
    if "reason=14 locally_generated=1" not in ev:
        raise Exception("Unexpected disconnection reason: " + ev)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection during TKIP countermeasures")

def test_ap_cipher_ccmp(dev, apdev):
    """WPA2-PSK/CCMP connection"""
    return check_cipher(dev[0], apdev[0], "CCMP")

def test_ap_cipher_gcmp(dev, apdev):
    """WPA2-PSK/GCMP connection"""
    return check_cipher(dev[0], apdev[0], "GCMP")

def test_ap_cipher_ccmp_256(dev, apdev):
    """WPA2-PSK/CCMP-256 connection"""
    return check_cipher(dev[0], apdev[0], "CCMP-256")

def test_ap_cipher_gcmp_256(dev, apdev):
    """WPA2-PSK/GCMP-256 connection"""
    return check_cipher(dev[0], apdev[0], "GCMP-256")

def test_ap_cipher_mixed_wpa_wpa2(dev, apdev):
    """WPA2-PSK/CCMP/ and WPA-PSK/TKIP mixed configuration"""
    ssid = "test-wpa-wpa2-psk"
    passphrase = "12345678"
    params = { "ssid": ssid,
               "wpa_passphrase": passphrase,
               "wpa": "3",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": "CCMP",
               "wpa_pairwise": "TKIP" }
    hostapd.add_ap(apdev[0]['ifname'], params)
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
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

    dev[1].connect(ssid, psk=passphrase, proto="WPA",
                   pairwise="TKIP", group="TKIP", scan_freq="2412")
    status = dev[1].get_status()
    if status['key_mgmt'] != 'WPA-PSK':
        raise Exception("Incorrect key_mgmt reported")
    if status['pairwise_cipher'] != 'TKIP':
        raise Exception("Incorrect pairwise_cipher reported")
    if status['group_cipher'] != 'TKIP':
        raise Exception("Incorrect group_cipher reported")
    hwsim_utils.test_connectivity(dev[1].ifname, apdev[0]['ifname'])
    hwsim_utils.test_connectivity(dev[0].ifname, dev[1].ifname)
