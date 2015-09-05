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

def test_ap_track_sta_no_probe_resp(dev, apdev):
    """Dualband AP not replying to probes from dualband STA on 2.4 GHz"""
    try:
        _test_ap_track_sta_no_probe_resp(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])

def _test_ap_track_sta_no_probe_resp(dev, apdev):
    dev[0].flush_scan_cache()

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "g",
               "channel": "6",
               "beacon_int": "10000",
               "no_probe_resp_if_seen_on": apdev[1]['ifname'] }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "a",
               "channel": "40",
               "track_sta_max_num": "100" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].scan_for_bss(bssid2, freq=5200, force_scan=True)
    dev[1].scan_for_bss(bssid, freq=2437, force_scan=True)
    dev[0].scan(freq=2437, type="ONLY")
    dev[0].scan(freq=2437, type="ONLY")

    if dev[0].get_bss(bssid):
        raise Exception("2.4 GHz AP found unexpectedly")

def test_ap_track_sta_no_auth(dev, apdev):
    """Dualband AP rejecting authentication from dualband STA on 2.4 GHz"""
    try:
        _test_ap_track_sta_no_auth(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])

def _test_ap_track_sta_no_auth(dev, apdev):
    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "g",
               "channel": "6",
               "track_sta_max_num": "100",
               "no_auth_if_seen_on": apdev[1]['ifname'] }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "a",
               "channel": "40",
               "track_sta_max_num": "100" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].scan_for_bss(bssid, freq=2437, force_scan=True)
    dev[0].scan_for_bss(bssid2, freq=5200, force_scan=True)
    dev[1].scan_for_bss(bssid, freq=2437, force_scan=True)

    dev[1].connect("track", key_mgmt="NONE", scan_freq="2437")

    dev[0].connect("track", key_mgmt="NONE", scan_freq="2437",
                   freq_list="2437", wait_connect=False)
    dev[1].request("DISCONNECT")
    ev = dev[0].wait_event([ "CTRL-EVENT-CONNECTED",
                             "CTRL-EVENT-AUTH-REJECT" ], timeout=10)
    if ev is None:
        raise Exception("Unknown connection result")
    if "CTRL-EVENT-CONNECTED" in ev:
        raise Exception("Unexpected connection")
    if "status_code=82" not in ev:
        raise Exception("Unexpected rejection reason: " + ev)
    if "ie=34" not in ev:
        raise Exception("No Neighbor Report element: " + ev)
    dev[0].request("DISCONNECT")

def test_ap_track_sta_no_auth_passive(dev, apdev):
    """AP rejecting authentication from dualband STA on 2.4 GHz (passive)"""
    try:
        _test_ap_track_sta_no_auth_passive(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])

def _test_ap_track_sta_no_auth_passive(dev, apdev):
    dev[0].flush_scan_cache()

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "g",
               "channel": "6",
               "no_auth_if_seen_on": apdev[1]['ifname'] }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "a",
               "channel": "40",
               "interworking": "1",
               "venue_name": "eng:Venue",
               "track_sta_max_num": "100" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].scan_for_bss(bssid, freq=2437, force_scan=True)
    for i in range(10):
        dev[0].request("SCAN freq=5200 passive=1")
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=5)
        if ev is None:
            raise Exception("Scan did not complete")
        if dev[0].get_bss(bssid2):
            break
        if i == 9:
            raise Exception("AP not found with passive scans")

    if "OK" not in dev[0].request("ANQP_GET " + bssid2 + " 258"):
        raise Exception("ANQP_GET command failed")
    ev = dev[0].wait_event(["RX-ANQP"], timeout=1)
    if ev is None or "Venue Name" not in ev:
        raise Exception("Did not receive Venue Name")

    dev[0].connect("track", key_mgmt="NONE", scan_freq="2437",
                   freq_list="2437", wait_connect=False)
    ev = dev[0].wait_event([ "CTRL-EVENT-CONNECTED",
                             "CTRL-EVENT-AUTH-REJECT" ], timeout=10)
    if ev is None:
        raise Exception("Unknown connection result")
    if "CTRL-EVENT-CONNECTED" in ev:
        raise Exception("Unexpected connection")
    if "status_code=82" not in ev:
        raise Exception("Unexpected rejection reason: " + ev)
    dev[0].request("DISCONNECT")

def test_ap_track_sta_force_5ghz(dev, apdev):
    """Dualband AP forcing dualband STA to connect on 5 GHz"""
    try:
        _test_ap_track_sta_force_5ghz(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])

def _test_ap_track_sta_force_5ghz(dev, apdev):
    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "g",
               "channel": "6",
               "no_probe_resp_if_seen_on": apdev[1]['ifname'],
               "no_auth_if_seen_on": apdev[1]['ifname'] }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "a",
               "channel": "40",
               "track_sta_max_num": "100" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].scan_for_bss(bssid, freq=2437, force_scan=True)
    dev[0].scan_for_bss(bssid2, freq=5200, force_scan=True)

    dev[0].connect("track", key_mgmt="NONE", scan_freq="2437 5200")
    freq = dev[0].get_status_field('freq')
    if freq != '5200':
        raise Exception("Unexpected operating channel")
    dev[0].request("DISCONNECT")

def test_ap_track_sta_force_2ghz(dev, apdev):
    """Dualband AP forcing dualband STA to connect on 2.4 GHz"""
    try:
        _test_ap_track_sta_force_2ghz(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])

def _test_ap_track_sta_force_2ghz(dev, apdev):
    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "g",
               "channel": "6",
               "track_sta_max_num": "100" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']

    params = { "ssid": "track",
               "country_code": "US",
               "hw_mode": "a",
               "channel": "40",
               "no_probe_resp_if_seen_on": apdev[0]['ifname'],
               "no_auth_if_seen_on": apdev[0]['ifname'] }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)
    bssid2 = apdev[1]['bssid']

    dev[0].scan_for_bss(bssid2, freq=5200, force_scan=True)
    dev[0].scan_for_bss(bssid, freq=2437, force_scan=True)

    dev[0].connect("track", key_mgmt="NONE", scan_freq="2437 5200")
    freq = dev[0].get_status_field('freq')
    if freq != '2437':
        raise Exception("Unexpected operating channel")
    dev[0].request("DISCONNECT")
