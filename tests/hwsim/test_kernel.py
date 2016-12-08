# Test a few kernel bugs
# Copyright (c) 2016, Intel Deutschland GmbH
#
# Author: Johannes Berg <johannes.berg@intel.com>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
import binascii

def _test_kernel_bss_leak(dev, apdev, deauth):
    ssid = "test-bss-leak"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0], params)
    hapd.set("ext_mgmt_frame_handling", "1")
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412", wait_connect=False)
    while True:
        pkt = hapd.mgmt_rx()
        if not pkt:
            raise Exception("MGMT RX wait timed out for auth frame")
        if pkt['fc'] & 0xc:
            continue
        if pkt['subtype'] == 0: # assoc request
            if deauth:
                # return a deauth immediately
                hapd.mgmt_tx({
                    'fc': 0xc0,
                    'sa': pkt['da'],
                    'da': pkt['sa'],
                    'bssid': pkt['bssid'],
                    'payload': '\x01\x00',
                })
            break
        else:
            hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % (
                         binascii.hexlify(pkt['frame']), ))
    hapd.set("ext_mgmt_frame_handling", "0")

    hapd.request("STOP_AP")

    dev[0].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected()

    dev[0].flush_scan_cache(freq=5180)
    res = dev[0].request("SCAN_RESULTS")
    if len(res.splitlines()) > 1:
        raise Exception("BSS entry should no longer be around")

def test_kernel_bss_leak_deauth(dev, apdev):
    """cfg80211/mac80211 BSS leak on deauthentication"""
    return _test_kernel_bss_leak(dev, apdev, deauth=True)

def test_kernel_bss_leak_timeout(dev, apdev):
    """cfg80211/mac80211 BSS leak on timeout"""
    return _test_kernel_bss_leak(dev, apdev, deauth=False)
