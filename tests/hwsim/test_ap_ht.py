# Test cases for HT operations with hostapd
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()
import struct
import subprocess

import hostapd

def clear_scan_cache(ifname):
    subprocess.call(['sudo', 'ifconfig', ifname, 'up'])
    subprocess.call(['sudo', 'iw', ifname, 'scan', 'freq', '2412', 'flush'])
    time.sleep(0.1)
    subprocess.call(['sudo', 'ifconfig', ifname, 'down'])

def test_ap_ht40_scan(dev, apdev):
    """HT40 co-ex scan"""
    clear_scan_cache(apdev[0]['ifname'])
    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-]"}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    state = hapd.get_status_field("state")
    if state != "HT_SCAN":
        time.sleep(0.1)
        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            raise Exception("Unexpected interface state - expected HT_SCAN")

    ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
    if not ev:
        raise Exception("AP setup timed out")

    state = hapd.get_status_field("state")
    if state != "ENABLED":
        raise Exception("Unexpected interface state - expected ENABLED")

    freq = hapd.get_status_field("freq")
    if freq != "2432":
        raise Exception("Unexpected frequency")
    pri = hapd.get_status_field("channel")
    if pri != "5":
        raise Exception("Unexpected primary channel")
    sec = hapd.get_status_field("secondary_channel")
    if sec != "-1":
        raise Exception("Unexpected secondary channel")

    dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)

def test_ap_ht40_scan_conflict(dev, apdev):
    """HT40 co-ex scan conflict"""
    clear_scan_cache(apdev[0]['ifname'])
    params = { "ssid": "test-ht40",
               "channel": "6",
               "ht_capab": "[HT40+]"}
    hostapd.add_ap(apdev[1]['ifname'], params)

    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-]"}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    state = hapd.get_status_field("state")
    if state != "HT_SCAN":
        time.sleep(0.1)
        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            raise Exception("Unexpected interface state - expected HT_SCAN")

    ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
    if not ev:
        raise Exception("AP setup timed out")

    state = hapd.get_status_field("state")
    if state != "ENABLED":
        raise Exception("Unexpected interface state - expected ENABLED")

    freq = hapd.get_status_field("freq")
    if freq != "2432":
        raise Exception("Unexpected frequency")
    pri = hapd.get_status_field("channel")
    if pri != "5":
        raise Exception("Unexpected primary channel")
    sec = hapd.get_status_field("secondary_channel")
    if sec != "0":
        raise Exception("Unexpected secondary channel: " + sec)

    dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)

def test_ap_ht40_scan_legacy_conflict(dev, apdev):
    """HT40 co-ex scan conflict with legacy 20 MHz AP"""
    clear_scan_cache(apdev[0]['ifname'])
    params = { "ssid": "legacy-20",
               "channel": "7", "ieee80211n": "0" }
    hostapd.add_ap(apdev[1]['ifname'], params)

    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-]"}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    state = hapd.get_status_field("state")
    if state != "HT_SCAN":
        time.sleep(0.1)
        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            raise Exception("Unexpected interface state - expected HT_SCAN")

    ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
    if not ev:
        raise Exception("AP setup timed out")

    state = hapd.get_status_field("state")
    if state != "ENABLED":
        raise Exception("Unexpected interface state - expected ENABLED")

    freq = hapd.get_status_field("freq")
    if freq != "2432":
        raise Exception("Unexpected frequency: " + freq)
    pri = hapd.get_status_field("channel")
    if pri != "5":
        raise Exception("Unexpected primary channel: " + pri)
    sec = hapd.get_status_field("secondary_channel")
    if sec != "0":
        raise Exception("Unexpected secondary channel: " + sec)

    dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)

def test_ap_ht40_scan_match(dev, apdev):
    """HT40 co-ex scan matching configuration"""
    clear_scan_cache(apdev[0]['ifname'])
    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-]"}
    hostapd.add_ap(apdev[1]['ifname'], params)

    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-]"}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    state = hapd.get_status_field("state")
    if state != "HT_SCAN":
        time.sleep(0.1)
        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            raise Exception("Unexpected interface state - expected HT_SCAN")

    ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
    if not ev:
        raise Exception("AP setup timed out")

    state = hapd.get_status_field("state")
    if state != "ENABLED":
        raise Exception("Unexpected interface state - expected ENABLED")

    freq = hapd.get_status_field("freq")
    if freq != "2432":
        raise Exception("Unexpected frequency")
    pri = hapd.get_status_field("channel")
    if pri != "5":
        raise Exception("Unexpected primary channel")
    sec = hapd.get_status_field("secondary_channel")
    if sec != "-1":
        raise Exception("Unexpected secondary channel: " + sec)

    dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)

def test_ap_ht40_5ghz_match(dev, apdev):
    """HT40 co-ex scan on 5 GHz with matching pri/sec channel"""
    clear_scan_cache(apdev[0]['ifname'])
    try:
        params = { "ssid": "test-ht40",
                   "hw_mode": "a",
                   "channel": "36",
                   "country_code": "US",
                   "ht_capab": "[HT40+]"}
        hostapd.add_ap(apdev[1]['ifname'], params)

        params = { "ssid": "test-ht40",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]"}
        hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            time.sleep(0.1)
            state = hapd.get_status_field("state")
            if state != "HT_SCAN":
                raise Exception("Unexpected interface state - expected HT_SCAN")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
        if not ev:
            raise Exception("AP setup timed out")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state - expected ENABLED")

        freq = hapd.get_status_field("freq")
        if freq != "5180":
            raise Exception("Unexpected frequency")
        pri = hapd.get_status_field("channel")
        if pri != "36":
            raise Exception("Unexpected primary channel")
        sec = hapd.get_status_field("secondary_channel")
        if sec != "1":
            raise Exception("Unexpected secondary channel: " + sec)

        dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)
    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_ap_ht40_5ghz_switch(dev, apdev):
    """HT40 co-ex scan on 5 GHz switching pri/sec channel"""
    clear_scan_cache(apdev[0]['ifname'])
    try:
        params = { "ssid": "test-ht40",
                   "hw_mode": "a",
                   "channel": "36",
                   "country_code": "US",
                   "ht_capab": "[HT40+]"}
        hostapd.add_ap(apdev[1]['ifname'], params)

        params = { "ssid": "test-ht40",
                   "hw_mode": "a",
                   "channel": "40",
                   "ht_capab": "[HT40-]"}
        hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            time.sleep(0.1)
            state = hapd.get_status_field("state")
            if state != "HT_SCAN":
                raise Exception("Unexpected interface state - expected HT_SCAN")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
        if not ev:
            raise Exception("AP setup timed out")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state - expected ENABLED")

        freq = hapd.get_status_field("freq")
        if freq != "5180":
            raise Exception("Unexpected frequency: " + freq)
        pri = hapd.get_status_field("channel")
        if pri != "36":
            raise Exception("Unexpected primary channel: " + pri)
        sec = hapd.get_status_field("secondary_channel")
        if sec != "1":
            raise Exception("Unexpected secondary channel: " + sec)

        dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)
    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_ap_ht40_5ghz_switch2(dev, apdev):
    """HT40 co-ex scan on 5 GHz switching pri/sec channel (2)"""
    clear_scan_cache(apdev[0]['ifname'])
    try:
        params = { "ssid": "test-ht40",
                   "hw_mode": "a",
                   "channel": "36",
                   "country_code": "US",
                   "ht_capab": "[HT40+]"}
        hostapd.add_ap(apdev[1]['ifname'], params)

        id = dev[0].add_network()
        dev[0].set_network(id, "mode", "2")
        dev[0].set_network_quoted(id, "ssid", "wpas-ap-open")
        dev[0].set_network(id, "key_mgmt", "NONE")
        dev[0].set_network(id, "frequency", "5200")
        dev[0].set_network(id, "scan_freq", "5200")
        dev[0].select_network(id)
        time.sleep(1)

        params = { "ssid": "test-ht40",
                   "hw_mode": "a",
                   "channel": "40",
                   "ht_capab": "[HT40-]"}
        hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

        state = hapd.get_status_field("state")
        if state != "HT_SCAN":
            time.sleep(0.1)
            state = hapd.get_status_field("state")
            if state != "HT_SCAN":
                raise Exception("Unexpected interface state - expected HT_SCAN")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=10)
        if not ev:
            raise Exception("AP setup timed out")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state - expected ENABLED")

        freq = hapd.get_status_field("freq")
        if freq != "5180":
            raise Exception("Unexpected frequency: " + freq)
        pri = hapd.get_status_field("channel")
        if pri != "36":
            raise Exception("Unexpected primary channel: " + pri)
        sec = hapd.get_status_field("secondary_channel")
        if sec != "1":
            raise Exception("Unexpected secondary channel: " + sec)

        dev[0].connect("test-ht40", key_mgmt="NONE", scan_freq=freq)
    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_obss_scan(dev, apdev):
    """Overlapping BSS scan request"""
    params = { "ssid": "obss-scan",
               "channel": "6",
               "ht_capab": "[HT40-]",
               "obss_interval": "10" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    params = { "ssid": "another-bss",
               "channel": "9",
               "ieee80211n": "0" }
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].connect("obss-scan", key_mgmt="NONE", scan_freq="2437")
    hapd.set("ext_mgmt_frame_handling", "1")
    logger.info("Waiting for OBSS scan to occur")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=15)
    if ev is None:
        raise Exception("Timed out while waiting for OBSS scan to start")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=10)
    if ev is None:
        raise Exception("Timed out while waiting for OBSS scan results")
    received = False
    for i in range(0, 4):
        frame = hapd.mgmt_rx(timeout=5)
        if frame is None:
            raise Exception("MGMT RX wait timed out")
        if frame['subtype'] != 13:
            continue
        payload = frame['payload']
        if len(payload) < 3:
            continue
        (category, action, ie) = struct.unpack('BBB', payload[0:3])
        if category != 4:
            continue
        if action != 0:
            continue
        if ie == 72:
            logger.info("20/40 BSS Coexistence report received")
            received = True
            break
    if not received:
        raise Exception("20/40 BSS Coexistence report not seen")

def test_obss_scan_40_intolerant(dev, apdev):
    """Overlapping BSS scan request with 40 MHz intolerant AP"""
    params = { "ssid": "obss-scan",
               "channel": "6",
               "ht_capab": "[HT40-]",
               "obss_interval": "10" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    params = { "ssid": "another-bss",
               "channel": "7",
               "ht_capab": "[40-INTOLERANT]" }
    hostapd.add_ap(apdev[1]['ifname'], params)

    dev[0].connect("obss-scan", key_mgmt="NONE", scan_freq="2437")
    hapd.set("ext_mgmt_frame_handling", "1")
    logger.info("Waiting for OBSS scan to occur")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=15)
    if ev is None:
        raise Exception("Timed out while waiting for OBSS scan to start")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=10)
    if ev is None:
        raise Exception("Timed out while waiting for OBSS scan results")
    received = False
    for i in range(0, 4):
        frame = hapd.mgmt_rx(timeout=5)
        if frame is None:
            raise Exception("MGMT RX wait timed out")
        if frame['subtype'] != 13:
            continue
        payload = frame['payload']
        if len(payload) < 3:
            continue
        (category, action, ie) = struct.unpack('BBB', payload[0:3])
        if category != 4:
            continue
        if action != 0:
            continue
        if ie == 72:
            logger.info("20/40 BSS Coexistence report received")
            received = True
            break
    if not received:
        raise Exception("20/40 BSS Coexistence report not seen")

def test_olbc(dev, apdev):
    """OLBC detection"""
    params = { "ssid": "test-olbc",
               "channel": "6",
               "ht_capab": "[HT40-]",
               "ap_table_expiration_time": "2" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    status = hapd.get_status()
    if status['olbc'] != '0' or status['olbc_ht'] != '0':
        raise Exception("Unexpected OLBC information")

    params = { "ssid": "olbc-ap",
               "hw_mode": "b",
               "channel": "6",
               "wmm_enabled": "0" }
    hostapd.add_ap(apdev[1]['ifname'], params)
    time.sleep(0.5)
    status = hapd.get_status()
    if status['olbc'] != '1' or status['olbc_ht'] != '1':
        raise Exception("Missing OLBC information")

    hapd_global = hostapd.HostapdGlobal()
    hapd_global.remove(apdev[1]['ifname'])

    logger.info("Waiting for OLBC state to time out")
    cleared = False
    for i in range(0, 15):
        time.sleep(1)
        status = hapd.get_status()
        if status['olbc'] == '0' and status['olbc_ht'] == '0':
            cleared = True
            break
    if not cleared:
        raise Exception("OLBC state did nto time out")

def test_olbc_5ghz(dev, apdev):
    """OLBC detection on 5 GHz"""
    try:
        params = { "ssid": "test-olbc",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]" }
        hapd = hostapd.add_ap(apdev[0]['ifname'], params)
        status = hapd.get_status()
        if status['olbc'] != '0' or status['olbc_ht'] != '0':
            raise Exception("Unexpected OLBC information")

        params = { "ssid": "olbc-ap",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ieee80211n": "0",
                   "wmm_enabled": "0" }
        hostapd.add_ap(apdev[1]['ifname'], params)
        time.sleep(0.5)
        status = hapd.get_status()
        if status['olbc_ht'] != '1':
            raise Exception("Missing OLBC information")
    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_ap_require_ht(dev, apdev):
    """Require HT"""
    params = { "ssid": "require-ht",
               "require_ht": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    dev[1].connect("require-ht", key_mgmt="NONE", scan_freq="2412",
                   disable_ht="1", wait_connect=False)
    dev[0].connect("require-ht", key_mgmt="NONE", scan_freq="2412")
    ev = dev[1].wait_event(["CTRL-EVENT-ASSOC-REJECT"])
    if ev is None:
        raise Exception("Association rejection timed out")
    if "status_code=27" not in ev:
        raise Exception("Unexpected rejection status code")
    dev[2].connect("require-ht", key_mgmt="NONE", scan_freq="2412",
                   ht_mcs="0x01 00 00 00 00 00 00 00 00 00",
                   disable_max_amsdu="1", ampdu_factor="2",
                   ampdu_density="1", disable_ht40="1", disable_sgi="1",
                   disable_ldpc="1")

def test_ap_require_ht_limited_rates(dev, apdev):
    """Require HT with limited supported rates"""
    params = { "ssid": "require-ht",
               "supported_rates": "60 120 240 360 480 540",
               "require_ht": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, wait_enabled=False)

    dev[1].connect("require-ht", key_mgmt="NONE", scan_freq="2412",
                   disable_ht="1", wait_connect=False)
    dev[0].connect("require-ht", key_mgmt="NONE", scan_freq="2412")
    ev = dev[1].wait_event(["CTRL-EVENT-ASSOC-REJECT"])
    if ev is None:
        raise Exception("Association rejection timed out")
    if "status_code=27" not in ev:
        raise Exception("Unexpected rejection status code")

def test_ap_ht_capab_not_supported(dev, apdev):
    """HT configuration with driver not supporting all ht_capab entries"""
    params = { "ssid": "test-ht40",
               "channel": "5",
               "ht_capab": "[HT40-][LDPC][SMPS-STATIC][SMPS-DYNAMIC][GF][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][RX-STBC12][RX-STBC123][DELAYED-BA][MAX-AMSDU-7935][DSSS_CCK-40][LSIG-TXOP-PROT]"}
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success")

def test_ap_ht_40mhz_intolerant_sta(dev, apdev):
    """Associated STA indicating 40 MHz intolerant"""
    clear_scan_cache(apdev[0]['ifname'])
    params = { "ssid": "intolerant",
               "channel": "6",
               "ht_capab": "[HT40-]" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if hapd.get_status_field("num_sta_ht40_intolerant") != "0":
        raise Exception("Unexpected num_sta_ht40_intolerant value")
    if hapd.get_status_field("secondary_channel") != "-1":
        raise Exception("Unexpected secondary_channel")

    dev[0].connect("intolerant", key_mgmt="NONE", scan_freq="2437")
    if hapd.get_status_field("num_sta_ht40_intolerant") != "0":
        raise Exception("Unexpected num_sta_ht40_intolerant value")
    if hapd.get_status_field("secondary_channel") != "-1":
        raise Exception("Unexpected secondary_channel")

    dev[2].connect("intolerant", key_mgmt="NONE", scan_freq="2437",
                   ht40_intolerant="1")
    time.sleep(1)
    if hapd.get_status_field("num_sta_ht40_intolerant") != "1":
        raise Exception("Unexpected num_sta_ht40_intolerant value (expected 1)")
    if hapd.get_status_field("secondary_channel") != "0":
        raise Exception("Unexpected secondary_channel (did not disable 40 MHz)")

    dev[2].request("DISCONNECT")
    time.sleep(1)
    if hapd.get_status_field("num_sta_ht40_intolerant") != "0":
        raise Exception("Unexpected num_sta_ht40_intolerant value (expected 0)")
    if hapd.get_status_field("secondary_channel") != "-1":
        raise Exception("Unexpected secondary_channel (did not re-enable 40 MHz)")

def test_ap_ht_40mhz_intolerant_ap(dev, apdev):
    """Associated STA reports 40 MHz intolerant AP after association"""
    clear_scan_cache(apdev[0]['ifname'])
    params = { "ssid": "ht",
               "channel": "6",
               "ht_capab": "[HT40-]",
               "obss_interval": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("ht", key_mgmt="NONE", scan_freq="2437")

    if hapd.get_status_field("secondary_channel") != "-1":
        raise Exception("Unexpected secondary channel information")

    logger.info("Start 40 MHz intolerant AP")
    params = { "ssid": "intolerant",
               "channel": "5",
               "ht_capab": "[40-INTOLERANT]" }
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], params)

    logger.info("Waiting for co-ex report from STA")
    ok = False
    for i in range(0, 20):
        time.sleep(1)
        if hapd.get_status_field("secondary_channel") == "0":
            logger.info("AP moved to 20 MHz channel")
            ok = True
            break
    if not ok:
        raise Exception("AP did not move to 20 MHz channel")

    if "OK" not in hapd2.request("DISABLE"):
        raise Exception("Failed to disable 40 MHz intolerant AP")

    # make sure the intolerant AP disappears from scan results more quickly
    dev[0].scan(only_new=True)
    dev[0].scan(freq="2432", only_new=True)

    logger.info("Waiting for AP to move back to 40 MHz channel")
    ok = False
    for i in range(0, 30):
        time.sleep(1)
        if hapd.get_status_field("secondary_channel") == "-1":
            ok = True
    if not ok:
        raise Exception("AP did not move to 40 MHz channel")
