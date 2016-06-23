# Test cases for automatic channel selection with hostapd
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

import hostapd
from utils import skip_with_fips
from test_ap_ht import clear_scan_cache

def force_prev_ap_on_24g(ap):
    # For now, make sure the last operating channel was on 2.4 GHz band to get
    # sufficient survey data from mac80211_hwsim.
    hostapd.add_ap(ap, { "ssid": "open" })
    time.sleep(0.1)
    hostapd.remove_bss(ap)

def force_prev_ap_on_5g(ap):
    # For now, make sure the last operating channel was on 5 GHz band to get
    # sufficient survey data from mac80211_hwsim.
    hostapd.add_ap(ap, { "ssid": "open", "hw_mode": "a",
                         "channel": "36", "country_code": "US" })
    time.sleep(0.1)
    hostapd.remove_bss(ap)

def wait_acs(hapd):
    ev = hapd.wait_event(["ACS-STARTED", "ACS-COMPLETED", "ACS-FAILED",
                          "AP-ENABLED", "AP-DISABLED"], timeout=5)
    if not ev:
        raise Exception("ACS start timed out")
    if "ACS-STARTED" not in ev:
        raise Exception("Unexpected ACS event: " + ev)

    state = hapd.get_status_field("state")
    if state != "ACS":
        raise Exception("Unexpected interface state")

    ev = hapd.wait_event(["ACS-COMPLETED", "ACS-FAILED", "AP-ENABLED",
                          "AP-DISABLED"], timeout=20)
    if not ev:
        raise Exception("ACS timed out")
    if "ACS-COMPLETED" not in ev:
        raise Exception("Unexpected ACS event: " + ev)

    ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=5)
    if not ev:
        raise Exception("AP setup timed out")
    if "AP-ENABLED" not in ev:
        raise Exception("Unexpected ACS event: " + ev)

    state = hapd.get_status_field("state")
    if state != "ENABLED":
        raise Exception("Unexpected interface state")

def test_ap_acs(dev, apdev):
    """Automatic channel selection"""
    force_prev_ap_on_24g(apdev[0])
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

def test_ap_acs_chanlist(dev, apdev):
    """Automatic channel selection with chanlist set"""
    force_prev_ap_on_24g(apdev[0])
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    params['chanlist'] = '1 6 11'
    hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

def test_ap_multi_bss_acs(dev, apdev):
    """hostapd start with a multi-BSS configuration file using ACS"""
    skip_with_fips(dev[0])
    force_prev_ap_on_24g(apdev[0])

    # start the actual test
    hapd = hostapd.add_iface(apdev[0], 'multi-bss-acs.conf')
    hapd.enable()
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    dev[0].connect("bss-1", key_mgmt="NONE", scan_freq=freq)
    dev[1].connect("bss-2", psk="12345678", scan_freq=freq)
    dev[2].connect("bss-3", psk="qwertyuiop", scan_freq=freq)

def test_ap_acs_40mhz(dev, apdev):
    """Automatic channel selection for 40 MHz channel"""
    clear_scan_cache(apdev[0])
    force_prev_ap_on_24g(apdev[0])
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    params['ht_capab'] = '[HT40+]'
    hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")
    sec = hapd.get_status_field("secondary_channel")
    if int(sec) == 0:
        raise Exception("Secondary channel not set")

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

def test_ap_acs_5ghz(dev, apdev):
    """Automatic channel selection on 5 GHz"""
    try:
        hapd = None
        force_prev_ap_on_5g(apdev[0])
        params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params['channel'] = '0'
        params['country_code'] = 'US'
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        wait_acs(hapd)
        freq = hapd.get_status_field("freq")
        if int(freq) < 5000:
            raise Exception("Unexpected frequency")

        dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        hostapd.cmd_execute(apdev[0], ['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_acs_5ghz_40mhz(dev, apdev):
    """Automatic channel selection on 5 GHz for 40 MHz channel"""
    try:
        hapd = None
        force_prev_ap_on_5g(apdev[0])
        params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params['channel'] = '0'
        params['ht_capab'] = '[HT40+]'
        params['country_code'] = 'US'
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        wait_acs(hapd)
        freq = hapd.get_status_field("freq")
        if int(freq) < 5000:
            raise Exception("Unexpected frequency")

        sec = hapd.get_status_field("secondary_channel")
        if int(sec) == 0:
            raise Exception("Secondary channel not set")

        dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        hostapd.cmd_execute(apdev[0], ['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_acs_vht(dev, apdev):
    """Automatic channel selection for VHT"""
    try:
        hapd = None
        force_prev_ap_on_5g(apdev[0])
        params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params['channel'] = '0'
        params['ht_capab'] = '[HT40+]'
        params['country_code'] = 'US'
        params['ieee80211ac'] = '1'
        params['vht_oper_chwidth'] = '1'
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        wait_acs(hapd)
        freq = hapd.get_status_field("freq")
        if int(freq) < 5000:
            raise Exception("Unexpected frequency")

        sec = hapd.get_status_field("secondary_channel")
        if int(sec) == 0:
            raise Exception("Secondary channel not set")

        dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        hostapd.cmd_execute(apdev[0], ['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_acs_bias(dev, apdev):
    """Automatic channel selection with bias values"""
    force_prev_ap_on_24g(apdev[0])
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    params['acs_chan_bias'] = '1:0.8 3:1.2 6:0.7 11:0.8'
    hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)
