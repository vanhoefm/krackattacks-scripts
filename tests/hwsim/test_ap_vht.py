# Test cases for VHT operations with hostapd
# Copyright (c) 2014, Qualcomm Atheros, Inc.
# Copyright (c) 2013, Intel Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import subprocess, time

import hwsim_utils
import hostapd
from utils import HwsimSkip
from test_dfs import wait_dfs_event
from test_ap_csa import csa_supported
from test_ap_ht import clear_scan_cache

def vht_supported():
    cmd = subprocess.Popen(["iw", "reg", "get"], stdout=subprocess.PIPE)
    reg = cmd.stdout.read()
    if "@ 80)" in reg or "@ 160)" in reg:
        return True
    return False

def test_ap_vht80(dev, apdev):
    """VHT with 80 MHz channel width"""
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "42" }
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        dev[0].connect("vht", key_mgmt="NONE", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5180" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=80 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        est = dev[0].get_bss(bssid)['est_throughput']
        if est != "390001":
            raise Exception("Unexpected BSS est_throughput: " + est)
        status = hapd.get_status()
        logger.info("hostapd STATUS: " + str(status))
        if status["ieee80211n"] != "1":
            raise Exception("Unexpected STATUS ieee80211n value")
        if status["ieee80211ac"] != "1":
            raise Exception("Unexpected STATUS ieee80211ac value")
        if status["secondary_channel"] != "1":
            raise Exception("Unexpected STATUS secondary_channel value")
        if status["vht_oper_chwidth"] != "1":
            raise Exception("Unexpected STATUS vht_oper_chwidth value")
        if status["vht_oper_centr_freq_seg0_idx"] != "42":
            raise Exception("Unexpected STATUS vht_oper_centr_freq_seg0_idx value")
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def vht80_test(apdev, dev, channel, ht_capab):
    clear_scan_cache(apdev)
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": str(channel),
                   "ht_capab": ht_capab,
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "42" }
        hapd = hostapd.add_ap(apdev, params)
        bssid = apdev['bssid']

        dev.connect("vht", key_mgmt="NONE", scan_freq=str(5000 + 5 * channel))
        hwsim_utils.test_connectivity(dev, hapd)
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev.request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev.flush_scan_cache()

def test_ap_vht80b(dev, apdev):
    """VHT with 80 MHz channel width (HT40- channel 40)"""
    vht80_test(apdev[0], dev[0], 40, "[HT40-]")

def test_ap_vht80c(dev, apdev):
    """VHT with 80 MHz channel width (HT40+ channel 44)"""
    vht80_test(apdev[0], dev[0], 44, "[HT40+]")

def test_ap_vht80d(dev, apdev):
    """VHT with 80 MHz channel width (HT40- channel 48)"""
    vht80_test(apdev[0], dev[0], 48, "[HT40-]")

def test_ap_vht80_params(dev, apdev):
    """VHT with 80 MHz channel width and number of optional features enabled"""
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+][SHORT-GI-40][DSS_CCK-40]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_capab": "[MAX-MPDU-11454][RXLDPC][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1][MAX-A-MPDU-LEN-EXP0]",
                   "vht_oper_centr_freq_seg0_idx": "42",
                   "require_vht": "1" }
        hapd = hostapd.add_ap(apdev[0], params)

        dev[1].connect("vht", key_mgmt="NONE", scan_freq="5180",
                       disable_vht="1", wait_connect=False)
        dev[0].connect("vht", key_mgmt="NONE", scan_freq="5180")
        ev = dev[1].wait_event(["CTRL-EVENT-ASSOC-REJECT"])
        if ev is None:
            raise Exception("Association rejection timed out")
        if "status_code=104" not in ev:
            raise Exception("Unexpected rejection status code")
        dev[1].request("DISCONNECT")
        hwsim_utils.test_connectivity(dev[0], hapd)
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def test_ap_vht80_invalid(dev, apdev):
    """VHT with invalid 80 MHz channel configuration (seg1)"""
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "US",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "42",
                   "vht_oper_centr_freq_seg1_idx": "155",
                   'ieee80211d': '1',
                   'ieee80211h': '1' }
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This fails due to unexpected seg1 configuration
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("AP-DISABLED not reported")
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])

def test_ap_vht80_invalid2(dev, apdev):
    """VHT with invalid 80 MHz channel configuration (seg0)"""
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "US",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "46",
                   'ieee80211d': '1',
                   'ieee80211h': '1' }
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This fails due to invalid seg0 configuration
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("AP-DISABLED not reported")
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])

def test_ap_vht_20(devs, apdevs):
    """VHT and 20 MHz channel"""
    dev = devs[0]
    ap = apdevs[0]
    try:
        hapd = None
        params = { "ssid": "test-vht20",
                   "country_code": "DE",
                   "hw_mode": "a",
                   "channel": "36",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "ht_capab": "",
                   "vht_capab": "",
                   "vht_oper_chwidth": "0",
                   "vht_oper_centr_freq_seg0_idx": "0",
                   "supported_rates": "60 120 240 360 480 540",
                   "require_vht": "1",
                 }
        hapd = hostapd.add_ap(ap, params)
        dev.connect("test-vht20", scan_freq="5180", key_mgmt="NONE")
        hwsim_utils.test_connectivity(dev, hapd)
    finally:
        dev.request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev.flush_scan_cache()

def test_ap_vht_40(devs, apdevs):
    """VHT and 40 MHz channel"""
    dev = devs[0]
    ap = apdevs[0]
    try:
        hapd = None
        params = { "ssid": "test-vht40",
                   "country_code": "DE",
                   "hw_mode": "a",
                   "channel": "36",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "ht_capab": "[HT40+]",
                   "vht_capab": "",
                   "vht_oper_chwidth": "0",
                   "vht_oper_centr_freq_seg0_idx": "0",
                 }
        hapd = hostapd.add_ap(ap, params)
        dev.connect("test-vht40", scan_freq="5180", key_mgmt="NONE")
        hwsim_utils.test_connectivity(dev, hapd)
    finally:
        dev.request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev.flush_scan_cache()

def test_ap_vht_capab_not_supported(dev, apdev):
    """VHT configuration with driver not supporting all vht_capab entries"""
    try:
        params = { "ssid": "vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+][SHORT-GI-40][DSS_CCK-40]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_capab": "[MAX-MPDU-7991][MAX-MPDU-11454][VHT160][VHT160-80PLUS80][RXLDPC][SHORT-GI-80][SHORT-GI-160][TX-STBC-2BY1][RX-STBC-1][RX-STBC-12][RX-STBC-123][RX-STBC-1234][SU-BEAMFORMER][SU-BEAMFORMEE][BF-ANTENNA-2][BF-ANTENNA-3][BF-ANTENNA-4][SOUNDING-DIMENSION-2][SOUNDING-DIMENSION-3][SOUNDING-DIMENSION-4][MU-BEAMFORMER][VHT-TXOP-PS][HTC-VHT][MAX-A-MPDU-LEN-EXP0][MAX-A-MPDU-LEN-EXP7][VHT-LINK-ADAPT2][VHT-LINK-ADAPT3][RX-ANTENNA-PATTERN][TX-ANTENNA-PATTERN]",
                   "vht_oper_centr_freq_seg0_idx": "42",
                   "require_vht": "1" }
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("Startup failure not reported")
        for i in range(1, 7):
            if "OK" not in hapd.request("SET vht_capab [MAX-A-MPDU-LEN-EXP%d]" % i):
                raise Exception("Unexpected SET failure")
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])

def test_ap_vht160(dev, apdev):
    """VHT with 160 MHz channel width"""
    try:
        hapd = None
        hapd2 = None
        params = { "ssid": "vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "2",
                   "vht_oper_centr_freq_seg0_idx": "50",
                   'ieee80211d': '1',
                   'ieee80211h': '1' }
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)

        ev = wait_dfs_event(hapd, "DFS-CAC-START", 5)
        if "DFS-CAC-START" not in ev:
            raise Exception("Unexpected DFS event")

        state = hapd.get_status_field("state")
        if state != "DFS":
            if state == "DISABLED" and not os.path.exists("dfs"):
                # Not all systems have recent enough CRDA version and
                # wireless-regdb changes to support 160 MHz and DFS. For now,
                # do not report failures for this test case.
                raise HwsimSkip("CRDA or wireless-regdb did not support 160 MHz")
            raise Exception("Unexpected interface state: " + state)

        params = { "ssid": "vht2",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "104",
                   "ht_capab": "[HT40-]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "2",
                   "vht_oper_centr_freq_seg0_idx": "114",
                   'ieee80211d': '1',
                   'ieee80211h': '1' }
        hapd2 = hostapd.add_ap(apdev[1], params, wait_enabled=False)

        ev = wait_dfs_event(hapd2, "DFS-CAC-START", 5)
        if "DFS-CAC-START" not in ev:
            raise Exception("Unexpected DFS event(2)")

        state = hapd2.get_status_field("state")
        if state != "DFS":
            raise Exception("Unexpected interface state(2): " + state)

        logger.info("Waiting for CAC to complete")

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 70)
        if "success=1" not in ev:
            raise Exception("CAC failed")
        if "freq=5180" not in ev:
            raise Exception("Unexpected DFS freq result")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state")

        ev = wait_dfs_event(hapd2, "DFS-CAC-COMPLETED", 70)
        if "success=1" not in ev:
            raise Exception("CAC failed(2)")
        if "freq=5520" not in ev:
            raise Exception("Unexpected DFS freq result(2)")

        ev = hapd2.wait_event(["AP-ENABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out(2)")

        state = hapd2.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state(2)")

        freq = hapd2.get_status_field("freq")
        if freq != "5520":
            raise Exception("Unexpected frequency(2)")

        dev[0].connect("vht", key_mgmt="NONE", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5180" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=160 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        dev[1].connect("vht2", key_mgmt="NONE", scan_freq="5520")
        hwsim_utils.test_connectivity(dev[1], hapd2)
        sig = dev[1].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5520" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=160 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def test_ap_vht160_no_dfs(dev, apdev):
    """VHT with 160 MHz channel width and no DFS"""
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "ZA",
                   "hw_mode": "a",
                   "channel": "104",
                   "ht_capab": "[HT40-]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "2",
                   "vht_oper_centr_freq_seg0_idx": "114",
                   'ieee80211d': '1',
                   'ieee80211h': '1' }
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        ev = hapd.wait_event(["AP-ENABLED"], timeout=2)
        if not ev:
            cmd = subprocess.Popen(["iw", "reg", "get"], stdout=subprocess.PIPE)
            reg = cmd.stdout.readlines()
            for r in reg:
                if "5490" in r and "DFS" in r:
                    raise HwsimSkip("ZA regulatory rule did not have DFS requirement removed")
            raise Exception("AP setup timed out")

        dev[0].connect("vht", key_mgmt="NONE", scan_freq="5520")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5520" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=160 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_vht80plus80(dev, apdev):
    """VHT with 80+80 MHz channel width"""
    try:
        hapd = None
        hapd2 = None
        params = { "ssid": "vht",
                   "country_code": "US",
                   "hw_mode": "a",
                   "channel": "52",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "3",
                   "vht_oper_centr_freq_seg0_idx": "58",
                   "vht_oper_centr_freq_seg1_idx": "155",
                   'ieee80211d': '1',
                   'ieee80211h': '1' }
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This will actually fail since DFS on 80+80 is not yet supported
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        # ignore result to avoid breaking the test once 80+80 DFS gets enabled

        params = { "ssid": "vht2",
                   "country_code": "US",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "3",
                   "vht_oper_centr_freq_seg0_idx": "42",
                   "vht_oper_centr_freq_seg1_idx": "155" }
        hapd2 = hostapd.add_ap(apdev[1], params, wait_enabled=False)

        ev = hapd2.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out(2)")
        if "AP-DISABLED" in ev:
            # Assume this failed due to missing regulatory update for now
            raise HwsimSkip("80+80 MHz channel not supported in regulatory information")

        state = hapd2.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state(2)")

        dev[1].connect("vht2", key_mgmt="NONE", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[1], hapd2)
        sig = dev[1].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5180" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=80+80 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        if "CENTER_FRQ1=5210" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(3): " + str(sig))
        if "CENTER_FRQ2=5775" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(4): " + str(sig))
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def test_ap_vht80plus80_invalid(dev, apdev):
    """VHT with invalid 80+80 MHz channel"""
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "US",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "3",
                   "vht_oper_centr_freq_seg0_idx": "42",
                   "vht_oper_centr_freq_seg1_idx": "0",
                   'ieee80211d': '1',
                   'ieee80211h': '1' }
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This fails due to missing(invalid) seg1 configuration
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("AP-DISABLED not reported")
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])

def test_ap_vht80_csa(dev, apdev):
    """VHT with 80 MHz channel width and CSA"""
    csa_supported(dev[0])
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "US",
                   "hw_mode": "a",
                   "channel": "149",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "155" }
        hapd = hostapd.add_ap(apdev[0], params)

        dev[0].connect("vht", key_mgmt="NONE", scan_freq="5745")
        hwsim_utils.test_connectivity(dev[0], hapd)

        hapd.request("CHAN_SWITCH 5 5180 ht vht blocktx center_freq1=5210 sec_channel_offset=1 bandwidth=80")
        ev = hapd.wait_event(["AP-CSA-FINISHED"], timeout=10)
        if ev is None:
            raise Exception("CSA finished event timed out")
        if "freq=5180" not in ev:
            raise Exception("Unexpected channel in CSA finished event")
        time.sleep(0.5)
        hwsim_utils.test_connectivity(dev[0], hapd)

        hapd.request("CHAN_SWITCH 5 5745")
        ev = hapd.wait_event(["AP-CSA-FINISHED"], timeout=10)
        if ev is None:
            raise Exception("CSA finished event timed out")
        if "freq=5745" not in ev:
            raise Exception("Unexpected channel in CSA finished event")
        time.sleep(0.5)
        hwsim_utils.test_connectivity(dev[0], hapd)

        # This CSA to same channel will fail in kernel, so use this only for
        # extra code coverage.
        hapd.request("CHAN_SWITCH 5 5745")
        hapd.wait_event(["AP-CSA-FINISHED"], timeout=1)
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_vht_on_24ghz(dev, apdev):
    """Subset of VHT features on 2.4 GHz"""
    hapd = None
    params = { "ssid": "test-vht-2g",
               "hw_mode": "g",
               "channel": "1",
               "ieee80211n": "1",
               "vendor_vht": "1",
               "vht_capab": "[MAX-MPDU-11454]",
               "vht_oper_chwidth": "0",
               "vht_oper_centr_freq_seg0_idx": "1"
    }
    hapd = hostapd.add_ap(apdev[0], params)
    try:
        if "OK" not in dev[0].request("VENDOR_ELEM_ADD 13 dd1300904c0400bf0c3240820feaff0000eaff0000"):
            raise Exception("Failed to add vendor element")
        dev[0].connect("test-vht-2g", scan_freq="2412", key_mgmt="NONE")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sta = hapd.get_sta(dev[0].own_addr())
        if '[VENDOR_VHT]' not in sta['flags']:
            raise Exception("No VENDOR_VHT STA flag")

        dev[1].connect("test-vht-2g", scan_freq="2412", key_mgmt="NONE")
        sta = hapd.get_sta(dev[1].own_addr())
        if '[VENDOR_VHT]' in sta['flags']:
            raise Exception("Unexpected VENDOR_VHT STA flag")
    finally:
        dev[0].request("VENDOR_ELEM_REMOVE 13 *")

def test_prefer_vht40(dev, apdev):
    """Preference on VHT40 over HT40"""
    try:
        hapd2 = None

        params = { "ssid": "test",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ieee80211n": "1",
                   "ht_capab": "[HT40+]" }
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        params = { "ssid": "test",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "ht_capab": "[HT40+]",
                   "vht_capab": "",
                   "vht_oper_chwidth": "0",
                   "vht_oper_centr_freq_seg0_idx": "0",
                 }
        hapd2 = hostapd.add_ap(apdev[1], params)
        bssid2 = apdev[1]['bssid']

        dev[0].scan_for_bss(bssid, freq=5180)
        dev[0].scan_for_bss(bssid2, freq=5180)
        dev[0].connect("test", scan_freq="5180", key_mgmt="NONE")
        if dev[0].get_status_field('bssid') != bssid2:
            raise Exception("Unexpected BSS selected")

        est = dev[0].get_bss(bssid)['est_throughput']
        if est != "135000":
            raise Exception("Unexpected BSS0 est_throughput: " + est)

        est = dev[0].get_bss(bssid2)['est_throughput']
        if est != "135001":
            raise Exception("Unexpected BSS1 est_throughput: " + est)
    finally:
        dev[0].request("DISCONNECT")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_vht80_pwr_constraint(dev, apdev):
    """VHT with 80 MHz channel width and local power constraint"""
    hapd = None
    try:
        params = { "ssid": "vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211d": "1",
                   "local_pwr_constraint": "3",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "42" }
        hapd = hostapd.add_ap(apdev[0], params)

        dev[0].connect("vht", key_mgmt="NONE", scan_freq="5180")
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_ap_vht_use_sta_nsts(dev, apdev):
    """VHT with 80 MHz channel width and use_sta_nsts=1"""
    try:
        hapd = None
        params = { "ssid": "vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "42",
                   "use_sta_nsts": "1" }
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        dev[0].connect("vht", key_mgmt="NONE", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[0], hapd)
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
