# Test cases for automatic channel selection with hostapd
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess

import hostapd

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
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

def test_ap_multi_bss_acs(dev, apdev):
    """hostapd start with a multi-BSS configuration file using ACS"""
    ifname = apdev[0]['ifname']
    hostapd.add_iface(ifname, 'multi-bss-acs.conf')
    hapd = hostapd.Hostapd(ifname)
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
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    params['ht_capab'] = '[HT40+]'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)
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
        params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params['channel'] = '0'
        params['country_code'] = 'US'
        hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)
        # TODO: Remove exception acceptance once mac80211_hwsim supports ACS on
        # 5 GHz
        run = False
        try:
            wait_acs(hapd)
            run = True
        except Exception, e:
            logger.info("Ignore exception due to missing hwsim support: " + str(e))

        if run:
            freq = hapd.get_status_field("freq")
            if int(freq) < 5000:
                raise Exception("Unexpected frequency")

            dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_ap_acs_5ghz_40mhz(dev, apdev):
    """Automatic channel selection on 5 GHz for 40 MHz channel"""
    try:
        params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params['channel'] = '0'
        params['ht_capab'] = '[HT40+]'
        params['country_code'] = 'US'
        hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)
        # TODO: Remove exception acceptance once mac80211_hwsim supports ACS on
        # 5 GHz
        run = False
        try:
            wait_acs(hapd)
            run = True
        except Exception, e:
            logger.info("Ignore exception due to missing hwsim support: " + str(e))

        if run:
            freq = hapd.get_status_field("freq")
            if int(freq) < 5000:
                raise Exception("Unexpected frequency")

            sec = hapd.get_status_field("secondary_channel")
            if int(sec) == 0:
                raise Exception("Secondary channel not set")

            dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_ap_acs_vht(dev, apdev):
    """Automatic channel selection for VHT"""
    try:
        params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params['channel'] = '0'
        params['ht_capab'] = '[HT40+]'
        params['country_code'] = 'US'
        params['ieee80211ac'] = '1'
        params['vht_oper_chwidth'] = '1'
        hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)
        # TODO: Remove exception acceptance once mac80211_hwsim supports ACS on
        # 5 GHz
        run = False
        try:
            wait_acs(hapd)
            run = True
        except Exception, e:
            logger.info("Ignore exception due to missing hwsim support: " + str(e))

        if run:
            freq = hapd.get_status_field("freq")
            if int(freq) < 5000:
                raise Exception("Unexpected frequency")

            sec = hapd.get_status_field("secondary_channel")
            if int(sec) == 0:
                raise Exception("Secondary channel not set")

            dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])
