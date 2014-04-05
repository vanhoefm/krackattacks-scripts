# WPA2-Personal tests
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os

import hostapd
import hwsim_utils

def check_mib(dev, vals):
    mib = dev.get_mib()
    for v in vals:
        if mib[v[0]] != v[1]:
            raise Exception("Unexpected {} = {} (expected {})".format(v[0], mib[v[0]], v[1]))

def test_ap_wpa2_psk(dev, apdev):
    """WPA2-PSK AP with PSK instead of passphrase"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    psk = '602e323e077bc63bd80307ef4745b754b0ae0a925c2638ecd13a794b9527b9e6'
    params = hostapd.wpa2_params(ssid=ssid)
    params['wpa_psk'] = psk
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    key_mgmt = hapd.get_config()['key_mgmt']
    if key_mgmt.split(' ')[0] != "WPA-PSK":
        raise Exception("Unexpected GET_CONFIG(key_mgmt): " + key_mgmt)
    dev[0].connect(ssid, raw_psk=psk, scan_freq="2412")
    dev[1].connect(ssid, psk=passphrase, scan_freq="2412")

def test_ap_wpa2_psk_file(dev, apdev):
    """WPA2-PSK AP with PSK from a file"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    psk = '602e323e077bc63bd80307ef4745b754b0ae0a925c2638ecd13a794b9527b9e6'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['wpa_psk_file'] = 'hostapd.wpa_psk'
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[1].connect(ssid, psk="very secret", scan_freq="2412", wait_connect=False)
    dev[2].connect(ssid, raw_psk=psk, scan_freq="2412")
    dev[2].request("REMOVE_NETWORK all")
    dev[0].connect(ssid, psk="very secret", scan_freq="2412")
    dev[0].request("REMOVE_NETWORK all")
    dev[2].connect(ssid, psk="another passphrase for all STAs", scan_freq="2412")
    dev[0].connect(ssid, psk="another passphrase for all STAs", scan_freq="2412")
    ev = dev[1].wait_event(["WPA: 4-Way Handshake failed"], timeout=10)
    if ev is None:
        raise Exception("Timed out while waiting for failure report")
    dev[1].request("REMOVE_NETWORK all")

def test_ap_wpa2_ptk_rekey(dev, apdev):
    """WPA2-PSK AP and PTK rekey enforced by station"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, wpa_ptk_rekey="1", scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_sha256_ptk_rekey(dev, apdev):
    """WPA2-PSK/SHA256 AKM AP and PTK rekey enforced by station"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK-SHA256",
                   wpa_ptk_rekey="1", scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-6"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-6") ])

def test_ap_wpa_ptk_rekey(dev, apdev):
    """WPA-PSK/TKIP AP and PTK rekey enforced by station"""
    ssid = "test-wpa-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa_params(ssid=ssid, passphrase=passphrase)
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, wpa_ptk_rekey="1", scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa_ccmp(dev, apdev):
    """WPA-PSK/CCMP"""
    ssid = "test-wpa-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa_params(ssid=ssid, passphrase=passphrase)
    params['wpa_pairwise'] = "CCMP"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
    check_mib(dev[0], [ ("dot11RSNAConfigGroupCipherSize", "128"),
                        ("dot11RSNAGroupCipherRequested", "00-50-f2-4"),
                        ("dot11RSNAPairwiseCipherRequested", "00-50-f2-4"),
                        ("dot11RSNAAuthenticationSuiteRequested", "00-50-f2-2"),
                        ("dot11RSNAGroupCipherSelected", "00-50-f2-4"),
                        ("dot11RSNAPairwiseCipherSelected", "00-50-f2-4"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-50-f2-2"),
                        ("dot1xSuppSuppControlledPortStatus", "Authorized") ])

def test_ap_wpa2_psk_file(dev, apdev):
    """WPA2-PSK AP with various PSK file error and success cases"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()
    ssid = "psk"
    pskfile = "/tmp/ap_wpa2_psk_file_errors.psk_file"
    try:
        os.remove(pskfile)
    except:
        pass

    params = { "ssid": ssid, "wpa": "2", "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": "CCMP", "wpa_psk_file": pskfile }

    try:
        # missing PSK file
        hapd = hostapd.add_ap(apdev[0]['ifname'], params, no_enable=True)
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("Unexpected ENABLE success")
        hapd.request("DISABLE")

        # invalid MAC address
        with open(pskfile, "w") as f:
            f.write("\n")
            f.write("foo\n")
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("Unexpected ENABLE success")
        hapd.request("DISABLE")

        # no PSK on line
        with open(pskfile, "w") as f:
            f.write("00:11:22:33:44:55\n")
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("Unexpected ENABLE success")
        hapd.request("DISABLE")

        # invalid PSK
        with open(pskfile, "w") as f:
            f.write("00:11:22:33:44:55 1234567\n")
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("Unexpected ENABLE success")
        hapd.request("DISABLE")

        # valid PSK file
        with open(pskfile, "w") as f:
            f.write("00:11:22:33:44:55 12345678\n")
            f.write(addr0 + " 123456789\n")
            f.write(addr1 + " 123456789a\n")
            f.write(addr2 + " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
        if "FAIL" in hapd.request("ENABLE"):
            raise Exception("Unexpected ENABLE failure")

        dev[0].connect(ssid, psk="123456789", scan_freq="2412")
        dev[1].connect(ssid, psk="123456789a", scan_freq="2412")
        dev[2].connect(ssid, raw_psk="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", scan_freq="2412")

    finally:
        try:
            os.remove(pskfile)
        except:
            pass
