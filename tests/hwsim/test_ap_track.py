# Test cases for hostapd tracking unconnected stations
# Copyright (c) 2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess
import time

import hostapd
from wpasupplicant import WpaSupplicant

def test_ap_track_sta(dev, apdev):
    """Dualband AP tracking unconnected stations"""
    try:
        _test_ap_track_sta(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])

def _test_ap_track_sta(dev, apdev):
    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "g",
               "channel": "6",
               "track_sta_max_num": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "a",
               "channel": "40",
               "track_sta_max_num": "100",
               "track_sta_max_age": "1" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    for i in range(2):
        dev[0].scan_for_bss(bssid, freq=2437, force_scan=True)
        dev[0].scan_for_bss(bssid2, freq=5200, force_scan=True)
        dev[1].scan_for_bss(bssid, freq=2437, force_scan=True)
        dev[2].scan_for_bss(bssid2, freq=5200, force_scan=True)

    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    addr2 = dev[2].own_addr()

    track = hapd.request("TRACK_STA_LIST")
    if addr0 not in track or addr1 not in track:
        raise Exception("Station missing from 2.4 GHz tracking")
    if addr2 in track:
        raise Exception("Unexpected station included in 2.4 GHz tracking")
    
    track = hapd2.request("TRACK_STA_LIST")
    if addr0 not in track or addr2 not in track:
        raise Exception("Station missing from 5 GHz tracking")
    if addr1 in track:
        raise Exception("Unexpected station included in 5 GHz tracking")

    # Test expiration
    time.sleep(1.1)
    track = hapd.request("TRACK_STA_LIST")
    if addr0 not in track or addr1 not in track:
        raise Exception("Station missing from 2.4 GHz tracking (expiration)")
    track = hapd2.request("TRACK_STA_LIST")
    if addr0 in track or addr2 in track:
        raise Exception("Station not expired from 5 GHz tracking")

    # Test maximum list length
    dev[0].scan_for_bss(bssid, freq=2437, force_scan=True)
    dev[1].scan_for_bss(bssid, freq=2437, force_scan=True)
    dev[2].scan_for_bss(bssid, freq=2437, force_scan=True)
    track = hapd.request("TRACK_STA_LIST")
    if len(track.splitlines()) != 2:
        raise Exception("Unexpected number of entries: %d" % len(track.splitlines()))
    if addr1 not in track or addr2 not in track:
        raise Exception("Station missing from 2.4 GHz tracking (max limit)")
