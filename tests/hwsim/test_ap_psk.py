# WPA2-Personal tests
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import hashlib
import hmac
import logging
logger = logging.getLogger()
import os
import struct
import subprocess
import time

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

    sig = dev[0].request("SIGNAL_POLL").splitlines()
    pkt = dev[0].request("PKTCNT_POLL").splitlines()
    if "FREQUENCY=2412" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value: " + str(sig))
    if "TXBAD=0" not in pkt:
        raise Exception("Unexpected TXBAD value: " + str(pkt))

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
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, wpa_ptk_rekey="1", scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa2_ptk_rekey_ap(dev, apdev):
    """WPA2-PSK AP and PTK rekey enforced by AP"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['wpa_ptk_rekey'] = '2'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa2_sha256_ptk_rekey(dev, apdev):
    """WPA2-PSK/SHA256 AKM AP and PTK rekey enforced by station"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK-SHA256",
                   wpa_ptk_rekey="1", scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-6"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-6") ])

def test_ap_wpa2_sha256_ptk_rekey_ap(dev, apdev):
    """WPA2-PSK/SHA256 AKM AP and PTK rekey enforced by AP"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params['wpa_ptk_rekey'] = '2'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK-SHA256",
                   scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)
    check_mib(dev[0], [ ("dot11RSNAAuthenticationSuiteRequested", "00-0f-ac-6"),
                        ("dot11RSNAAuthenticationSuiteSelected", "00-0f-ac-6") ])

def test_ap_wpa_ptk_rekey(dev, apdev):
    """WPA-PSK/TKIP AP and PTK rekey enforced by station"""
    ssid = "test-wpa-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, wpa_ptk_rekey="1", scan_freq="2412")
    if "[WPA-PSK-TKIP]" not in dev[0].request("SCAN_RESULTS"):
        raise Exception("Scan results missing WPA element info")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"])
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa_ptk_rekey_ap(dev, apdev):
    """WPA-PSK/TKIP AP and PTK rekey enforced by AP"""
    ssid = "test-wpa-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa_params(ssid=ssid, passphrase=passphrase)
    params['wpa_ptk_rekey'] = '2'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Key negotiation completed"], timeout=10)
    if ev is None:
        raise Exception("PTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa_ccmp(dev, apdev):
    """WPA-PSK/CCMP"""
    ssid = "test-wpa-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa_params(ssid=ssid, passphrase=passphrase)
    params['wpa_pairwise'] = "CCMP"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)
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

def test_ap_wpa2_psk_wildcard_ssid(dev, apdev):
    """WPA2-PSK AP and wildcard SSID configuration"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    psk = '602e323e077bc63bd80307ef4745b754b0ae0a925c2638ecd13a794b9527b9e6'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("", bssid=apdev[0]['bssid'], psk=passphrase,
                   scan_freq="2412")
    dev[1].connect("", bssid=apdev[0]['bssid'], raw_psk=psk, scan_freq="2412")

def test_ap_wpa2_gtk_rekey(dev, apdev):
    """WPA2-PSK AP and GTK rekey enforced by AP"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa_gtk_rekey(dev, apdev):
    """WPA-PSK/TKIP AP and GTK rekey enforced by AP"""
    ssid = "test-wpa-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa_params(ssid=ssid, passphrase=passphrase)
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa2_gmk_rekey(dev, apdev):
    """WPA2-PSK AP and GMK and GTK rekey enforced by AP"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['wpa_group_rekey'] = '1'
    params['wpa_gmk_rekey'] = '2'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    for i in range(0, 3):
        ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
        if ev is None:
            raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa2_strict_rekey(dev, apdev):
    """WPA2-PSK AP and strict GTK rekey enforced by AP"""
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['wpa_strict_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    dev[1].connect(ssid, psk=passphrase, scan_freq="2412")
    dev[1].request("DISCONNECT")
    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_wpa2_bridge_fdb(dev, apdev):
    """Bridge FDB entry removal"""
    try:
        ssid = "test-wpa2-psk"
        passphrase = "12345678"
        params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
        params['bridge'] = 'ap-br0'
        hostapd.add_ap(apdev[0]['ifname'], params)
        subprocess.call(['sudo', 'brctl', 'setfd', 'ap-br0', '0'])
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', 'ap-br0', 'up'])
        dev[0].connect(ssid, psk=passphrase, scan_freq="2412",
                       bssid=apdev[0]['bssid'])
        dev[1].connect(ssid, psk=passphrase, scan_freq="2412",
                       bssid=apdev[0]['bssid'])
        addr0 = dev[0].p2p_interface_addr()
        hwsim_utils.test_connectivity_sta(dev[0], dev[1])
        cmd = subprocess.Popen(['brctl', 'showmacs', 'ap-br0'],
                               stdout=subprocess.PIPE)
        macs1 = cmd.stdout.read()
        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        time.sleep(1)
        cmd = subprocess.Popen(['brctl', 'showmacs', 'ap-br0'],
                               stdout=subprocess.PIPE)
        macs2 = cmd.stdout.read()

        addr1 = dev[1].p2p_interface_addr()
        if addr0 not in macs1 or addr1 not in macs1:
            raise Exception("Bridge FDB entry missing")
        if addr0 in macs2 or addr1 in macs2:
            raise Exception("Bridge FDB entry was not removed")
    finally:
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', 'ap-br0', 'down'])
        subprocess.call(['sudo', 'brctl', 'delbr', 'ap-br0'])

def test_ap_wpa2_already_in_bridge(dev, apdev):
    """hostapd behavior with interface already in bridge"""
    ifname = apdev[0]['ifname']
    br_ifname = 'ext-ap-br0'
    try:
        ssid = "test-wpa2-psk"
        passphrase = "12345678"
        subprocess.call(['brctl', 'addbr', br_ifname])
        subprocess.call(['brctl', 'setfd', br_ifname, '0'])
        subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'up'])
        subprocess.call(['iw', ifname, 'set', 'type', '__ap'])
        subprocess.call(['brctl', 'addif', br_ifname, ifname])
        params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
        hapd = hostapd.add_ap(ifname, params)
        if hapd.get_driver_status_field('brname') != br_ifname:
            raise Exception("Bridge name not identified correctly")
        dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'down'])
        subprocess.call(['brctl', 'delif', br_ifname, ifname])
        subprocess.call(['iw', ifname, 'set', 'type', 'station'])
        subprocess.call(['brctl', 'delbr', br_ifname])

def test_ap_wpa2_ext_add_to_bridge(dev, apdev):
    """hostapd behavior with interface added to bridge externally"""
    ifname = apdev[0]['ifname']
    br_ifname = 'ext-ap-br0'
    try:
        ssid = "test-wpa2-psk"
        passphrase = "12345678"
        params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
        hapd = hostapd.add_ap(ifname, params)

        subprocess.call(['brctl', 'addbr', br_ifname])
        subprocess.call(['brctl', 'setfd', br_ifname, '0'])
        subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'up'])
        subprocess.call(['brctl', 'addif', br_ifname, ifname])
        dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
        if hapd.get_driver_status_field('brname') != br_ifname:
            raise Exception("Bridge name not identified correctly")
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'down'])
        subprocess.call(['brctl', 'delif', br_ifname, ifname])
        subprocess.call(['brctl', 'delbr', br_ifname])

def test_ap_wpa2_psk_ext(dev, apdev):
    """WPA2-PSK AP using external EAPOL I/O"""
    bssid = apdev[0]['bssid']
    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    psk = '602e323e077bc63bd80307ef4745b754b0ae0a925c2638ecd13a794b9527b9e6'
    params = hostapd.wpa2_params(ssid=ssid)
    params['wpa_psk'] = psk
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    hapd.request("SET ext_eapol_frame_io 1")
    dev[0].request("SET ext_eapol_frame_io 1")
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412", wait_connect=False)
    addr = dev[0].p2p_interface_addr()
    while True:
        ev = hapd.wait_event(["EAPOL-TX", "AP-STA-CONNECTED"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAPOL-TX from hostapd")
        if "AP-STA-CONNECTED" in ev:
            ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
            if ev is None:
                raise Exception("Timeout on connection event from wpa_supplicant")
            break
        res = dev[0].request("EAPOL_RX " + bssid + " " + ev.split(' ')[2])
        if "OK" not in res:
            raise Exception("EAPOL_RX to wpa_supplicant failed")
        ev = dev[0].wait_event(["EAPOL-TX", "CTRL-EVENT-CONNECTED"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAPOL-TX from wpa_supplicant")
        if "CTRL-EVENT-CONNECTED" in ev:
            break
        res = hapd.request("EAPOL_RX " + addr + " " + ev.split(' ')[2])
        if "OK" not in res:
            raise Exception("EAPOL_RX to hostapd failed")

def parse_eapol(data):
    (version, type, length) = struct.unpack('>BBH', data[0:4])
    payload = data[4:]
    if length > len(payload):
        raise Exception("Invalid EAPOL length")
    if length < len(payload):
        payload = payload[0:length]
    eapol = {}
    eapol['version'] = version
    eapol['type'] = type
    eapol['length'] = length
    eapol['payload'] = payload
    if type == 3:
        # EAPOL-Key
        (eapol['descr_type'],) = struct.unpack('B', payload[0:1])
        payload = payload[1:]
        if eapol['descr_type'] == 2 or eapol['descr_type'] == 254:
            # RSN EAPOL-Key
            (key_info, key_len) = struct.unpack('>HH', payload[0:4])
            eapol['rsn_key_info'] = key_info
            eapol['rsn_key_len'] = key_len
            eapol['rsn_replay_counter'] = payload[4:12]
            eapol['rsn_key_nonce'] = payload[12:44]
            eapol['rsn_key_iv'] = payload[44:60]
            eapol['rsn_key_rsc'] = payload[60:68]
            eapol['rsn_key_id'] = payload[68:76]
            eapol['rsn_key_mic'] = payload[76:92]
            payload = payload[92:]
            (eapol['rsn_key_data_len'],) = struct.unpack('>H', payload[0:2])
            payload = payload[2:]
            eapol['rsn_key_data'] = payload
    return eapol

def build_eapol(msg):
    data = struct.pack(">BBH", msg['version'], msg['type'], msg['length'])
    if msg['type'] == 3:
        data += struct.pack('>BHH', msg['descr_type'], msg['rsn_key_info'],
                            msg['rsn_key_len'])
        data += msg['rsn_replay_counter']
        data += msg['rsn_key_nonce']
        data += msg['rsn_key_iv']
        data += msg['rsn_key_rsc']
        data += msg['rsn_key_id']
        data += msg['rsn_key_mic']
        data += struct.pack('>H', msg['rsn_key_data_len'])
        data += msg['rsn_key_data']
    else:
        data += msg['payload']
    return data

def sha1_prf(key, label, data, outlen):
    res = ''
    counter = 0
    while outlen > 0:
        m = hmac.new(key, label, hashlib.sha1)
        m.update(struct.pack('B', 0))
        m.update(data)
        m.update(struct.pack('B', counter))
        counter += 1
        hash = m.digest()
        if outlen > len(hash):
            res += hash
            outlen -= len(hash)
        else:
            res += hash[0:outlen]
            outlen = 0
    return res

def pmk_to_ptk(pmk, addr1, addr2, nonce1, nonce2):
    if addr1 < addr2:
        data = binascii.unhexlify(addr1.replace(':','')) + binascii.unhexlify(addr2.replace(':',''))
    else:
        data = binascii.unhexlify(addr2.replace(':','')) + binascii.unhexlify(addr1.replace(':',''))
    if nonce1 < nonce2:
        data += nonce1 + nonce2
    else:
        data += nonce2 + nonce1
    label = "Pairwise key expansion"
    ptk = sha1_prf(pmk, label, data, 48)
    kck = ptk[0:16]
    kek = ptk[16:32]
    return (ptk, kck, kek)

def eapol_key_mic(kck, msg):
    msg['rsn_key_mic'] = binascii.unhexlify('00000000000000000000000000000000')
    data = build_eapol(msg)
    m = hmac.new(kck, data, hashlib.sha1)
    msg['rsn_key_mic'] = m.digest()[0:16]

def rsn_eapol_key_set(msg, key_info, key_len, nonce, data):
    msg['rsn_key_info'] = key_info
    msg['rsn_key_len'] = key_len
    if nonce:
        msg['rsn_key_nonce'] = nonce
    else:
        msg['rsn_key_nonce'] = binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
    if data:
        msg['rsn_key_data_len'] = len(data)
        msg['rsn_key_data'] = data
        msg['length'] = 95 + len(data)
    else:
        msg['rsn_key_data_len'] = 0
        msg['rsn_key_data'] = ''
        msg['length'] = 95

def recv_eapol(hapd):
    ev = hapd.wait_event(["EAPOL-TX"], timeout=15)
    if ev is None:
        raise Exception("Timeout on EAPOL-TX from hostapd")
    eapol = binascii.unhexlify(ev.split(' ')[2])
    return parse_eapol(eapol)

def send_eapol(hapd, addr, data):
    res = hapd.request("EAPOL_RX " + addr + " " + binascii.hexlify(data))
    if "OK" not in res:
        raise Exception("EAPOL_RX to hostapd failed")

def reply_eapol(info, hapd, addr, msg, key_info, nonce, data, kck):
    logger.info("Send EAPOL-Key msg " + info)
    rsn_eapol_key_set(msg, key_info, 0, nonce, data)
    eapol_key_mic(kck, msg)
    send_eapol(hapd, addr, build_eapol(msg))

def hapd_connected(hapd):
    ev = hapd.wait_event(["AP-STA-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Timeout on AP-STA-CONNECTED from hostapd")

def eapol_test(apdev, dev, wpa2=True):
    bssid = apdev['bssid']
    if wpa2:
        ssid = "test-wpa2-psk"
    else:
        ssid = "test-wpa-psk"
    psk = '602e323e077bc63bd80307ef4745b754b0ae0a925c2638ecd13a794b9527b9e6'
    pmk = binascii.unhexlify(psk)
    if wpa2:
        params = hostapd.wpa2_params(ssid=ssid)
    else:
        params = hostapd.wpa_params(ssid=ssid)
    params['wpa_psk'] = psk
    hapd = hostapd.add_ap(apdev['ifname'], params)
    hapd.request("SET ext_eapol_frame_io 1")
    dev.request("SET ext_eapol_frame_io 1")
    dev.connect(ssid, psk="not used", scan_freq="2412", wait_connect=False)
    addr = dev.p2p_interface_addr()
    if wpa2:
        rsne = binascii.unhexlify('30140100000fac040100000fac040100000fac020000')
    else:
        rsne = binascii.unhexlify('dd160050f20101000050f20201000050f20201000050f202')
    snonce = binascii.unhexlify('1111111111111111111111111111111111111111111111111111111111111111')
    return (bssid,ssid,hapd,snonce,pmk,addr,rsne)

def test_ap_wpa2_psk_ext_eapol(dev, apdev):
    """WPA2-PSK AP using external EAPOL supplicant"""
    (bssid,ssid,hapd,snonce,pmk,addr,rsne) = eapol_test(apdev[0], dev[0])

    msg = recv_eapol(hapd)
    anonce = msg['rsn_key_nonce']
    logger.info("Replay same data back")
    send_eapol(hapd, addr, build_eapol(msg))

    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)

    logger.info("Truncated Key Data in EAPOL-Key msg 2/4")
    rsn_eapol_key_set(msg, 0x0101, 0, snonce, rsne)
    msg['length'] = 95 + 22 - 1
    send_eapol(hapd, addr, build_eapol(msg))

    reply_eapol("2/4", hapd, addr, msg, 0x010a, snonce, rsne, kck)

    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")
    logger.info("Replay same data back")
    send_eapol(hapd, addr, build_eapol(msg))

    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)

def test_ap_wpa2_psk_ext_eapol_retry1(dev, apdev):
    """WPA2 4-way handshake with EAPOL-Key 1/4 retransmitted"""
    (bssid,ssid,hapd,snonce,pmk,addr,rsne) = eapol_test(apdev[0], dev[0])

    msg1 = recv_eapol(hapd)
    anonce = msg1['rsn_key_nonce']

    msg2 = recv_eapol(hapd)
    if anonce != msg2['rsn_key_nonce']:
        raise Exception("ANonce changed")

    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)

    logger.info("Send EAPOL-Key msg 2/4")
    msg = msg2
    rsn_eapol_key_set(msg, 0x010a, 0, snonce, rsne)
    eapol_key_mic(kck, msg)
    send_eapol(hapd, addr, build_eapol(msg))

    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")

    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)

def test_ap_wpa2_psk_ext_eapol_retry1b(dev, apdev):
    """WPA2 4-way handshake with EAPOL-Key 1/4 and 2/4 retransmitted"""
    (bssid,ssid,hapd,snonce,pmk,addr,rsne) = eapol_test(apdev[0], dev[0])

    msg1 = recv_eapol(hapd)
    anonce = msg1['rsn_key_nonce']
    msg2 = recv_eapol(hapd)
    if anonce != msg2['rsn_key_nonce']:
        raise Exception("ANonce changed")

    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)
    reply_eapol("2/4 (a)", hapd, addr, msg1, 0x010a, snonce, rsne, kck)
    reply_eapol("2/4 (b)", hapd, addr, msg2, 0x010a, snonce, rsne, kck)

    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")

    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)

def test_ap_wpa2_psk_ext_eapol_retry1c(dev, apdev):
    """WPA2 4-way handshake with EAPOL-Key 1/4 and 2/4 retransmitted and SNonce changing"""
    (bssid,ssid,hapd,snonce,pmk,addr,rsne) = eapol_test(apdev[0], dev[0])

    msg1 = recv_eapol(hapd)
    anonce = msg1['rsn_key_nonce']

    msg2 = recv_eapol(hapd)
    if anonce != msg2['rsn_key_nonce']:
        raise Exception("ANonce changed")
    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)
    reply_eapol("2/4 (a)", hapd, addr, msg1, 0x010a, snonce, rsne, kck)

    snonce2 = binascii.unhexlify('2222222222222222222222222222222222222222222222222222222222222222')
    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce2, anonce)
    reply_eapol("2/4 (b)", hapd, addr, msg2, 0x010a, snonce2, rsne, kck)

    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")
    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)

def test_ap_wpa2_psk_ext_eapol_retry1d(dev, apdev):
    """WPA2 4-way handshake with EAPOL-Key 1/4 and 2/4 retransmitted and SNonce changing and older used"""
    (bssid,ssid,hapd,snonce,pmk,addr,rsne) = eapol_test(apdev[0], dev[0])

    msg1 = recv_eapol(hapd)
    anonce = msg1['rsn_key_nonce']
    msg2 = recv_eapol(hapd)
    if anonce != msg2['rsn_key_nonce']:
        raise Exception("ANonce changed")

    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)
    reply_eapol("2/4 (a)", hapd, addr, msg1, 0x010a, snonce, rsne, kck)

    snonce2 = binascii.unhexlify('2222222222222222222222222222222222222222222222222222222222222222')
    (ptk2, kck2, kek2) = pmk_to_ptk(pmk, addr, bssid, snonce2, anonce)

    reply_eapol("2/4 (b)", hapd, addr, msg2, 0x010a, snonce2, rsne, kck2)
    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")
    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)

def test_ap_wpa2_psk_ext_eapol_type_diff(dev, apdev):
    """WPA2 4-way handshake using external EAPOL supplicant"""
    (bssid,ssid,hapd,snonce,pmk,addr,rsne) = eapol_test(apdev[0], dev[0])

    msg = recv_eapol(hapd)
    anonce = msg['rsn_key_nonce']

    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)

    # Incorrect descriptor type (frame dropped)
    msg['descr_type'] = 253
    rsn_eapol_key_set(msg, 0x010a, 0, snonce, rsne)
    eapol_key_mic(kck, msg)
    send_eapol(hapd, addr, build_eapol(msg))

    # Incorrect descriptor type, but with a workaround (frame processed)
    msg['descr_type'] = 254
    rsn_eapol_key_set(msg, 0x010a, 0, snonce, rsne)
    eapol_key_mic(kck, msg)
    send_eapol(hapd, addr, build_eapol(msg))

    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")
    logger.info("Replay same data back")
    send_eapol(hapd, addr, build_eapol(msg))

    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)

def test_ap_wpa_psk_ext_eapol(dev, apdev):
    """WPA2-PSK AP using external EAPOL supplicant"""
    (bssid,ssid,hapd,snonce,pmk,addr,wpae) = eapol_test(apdev[0], dev[0],
                                                        wpa2=False)

    msg = recv_eapol(hapd)
    anonce = msg['rsn_key_nonce']
    logger.info("Replay same data back")
    send_eapol(hapd, addr, build_eapol(msg))
    logger.info("Too short data")
    send_eapol(hapd, addr, build_eapol(msg)[0:98])

    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)
    msg['descr_type'] = 2
    reply_eapol("2/4(invalid type)", hapd, addr, msg, 0x010a, snonce, wpae, kck)
    msg['descr_type'] = 254
    reply_eapol("2/4", hapd, addr, msg, 0x010a, snonce, wpae, kck)

    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")
    logger.info("Replay same data back")
    send_eapol(hapd, addr, build_eapol(msg))

    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)

def test_ap_wpa2_psk_ext_eapol_key_info(dev, apdev):
    """WPA2-PSK 4-way handshake with strange key info values"""
    (bssid,ssid,hapd,snonce,pmk,addr,rsne) = eapol_test(apdev[0], dev[0])

    msg = recv_eapol(hapd)
    anonce = msg['rsn_key_nonce']

    (ptk, kck, kek) = pmk_to_ptk(pmk, addr, bssid, snonce, anonce)
    rsn_eapol_key_set(msg, 0x0000, 0, snonce, rsne)
    send_eapol(hapd, addr, build_eapol(msg))
    rsn_eapol_key_set(msg, 0xffff, 0, snonce, rsne)
    send_eapol(hapd, addr, build_eapol(msg))
    # SMK M1
    rsn_eapol_key_set(msg, 0x2802, 0, snonce, rsne)
    send_eapol(hapd, addr, build_eapol(msg))
    # SMK M3
    rsn_eapol_key_set(msg, 0x2002, 0, snonce, rsne)
    send_eapol(hapd, addr, build_eapol(msg))
    # Request
    rsn_eapol_key_set(msg, 0x0902, 0, snonce, rsne)
    send_eapol(hapd, addr, build_eapol(msg))
    # Request
    rsn_eapol_key_set(msg, 0x0902, 0, snonce, rsne)
    tmp_kck = binascii.unhexlify('00000000000000000000000000000000')
    eapol_key_mic(tmp_kck, msg)
    send_eapol(hapd, addr, build_eapol(msg))

    reply_eapol("2/4", hapd, addr, msg, 0x010a, snonce, rsne, kck)

    msg = recv_eapol(hapd)
    if anonce != msg['rsn_key_nonce']:
        raise Exception("ANonce changed")

    # Request (valic MIC)
    rsn_eapol_key_set(msg, 0x0902, 0, snonce, rsne)
    eapol_key_mic(kck, msg)
    send_eapol(hapd, addr, build_eapol(msg))
    # Request (valid MIC, replayed counter)
    rsn_eapol_key_set(msg, 0x0902, 0, snonce, rsne)
    eapol_key_mic(kck, msg)
    send_eapol(hapd, addr, build_eapol(msg))

    reply_eapol("4/4", hapd, addr, msg, 0x030a, None, None, kck)
    hapd_connected(hapd)
