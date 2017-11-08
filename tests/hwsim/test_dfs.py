# Test cases for DFS
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import os
import subprocess
import time
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd
from utils import HwsimSkip

def wait_dfs_event(hapd, event, timeout):
    dfs_events = [ "DFS-RADAR-DETECTED", "DFS-NEW-CHANNEL",
                   "DFS-CAC-START", "DFS-CAC-COMPLETED",
                   "DFS-NOP-FINISHED", "AP-ENABLED", "AP-CSA-FINISHED" ]
    ev = hapd.wait_event(dfs_events, timeout=timeout)
    if not ev:
        raise Exception("DFS event timed out")
    if event and event not in ev:
        raise Exception("Unexpected DFS event")
    return ev

def start_dfs_ap(ap, allow_failure=False, ssid="dfs", ht=True, ht40=False,
                 ht40minus=False, vht80=False, vht20=False, chanlist=None,
                 channel=None):
    ifname = ap['ifname']
    logger.info("Starting AP " + ifname + " on DFS channel")
    hapd = hostapd.add_ap(ap, {}, no_enable=True)
    hapd.set("ssid", ssid)
    hapd.set("country_code", "FI")
    hapd.set("ieee80211d", "1")
    hapd.set("ieee80211h", "1")
    hapd.set("hw_mode", "a")
    hapd.set("channel", "52")
    if not ht:
        hapd.set("ieee80211n", "0")
    if ht40:
        hapd.set("ht_capab", "[HT40+]")
    elif ht40minus:
        hapd.set("ht_capab", "[HT40-]")
        hapd.set("channel", "56")
    if vht80:
        hapd.set("ieee80211ac", "1")
        hapd.set("vht_oper_chwidth", "1")
        hapd.set("vht_oper_centr_freq_seg0_idx", "58")
    if vht20:
        hapd.set("ieee80211ac", "1")
        hapd.set("vht_oper_chwidth", "0")
        hapd.set("vht_oper_centr_freq_seg0_idx", "0")
    if chanlist:
        hapd.set("chanlist", chanlist)
    if channel:
        hapd.set("channel", str(channel))
    hapd.enable()

    ev = wait_dfs_event(hapd, "DFS-CAC-START", 5)
    if "DFS-CAC-START" not in ev:
        raise Exception("Unexpected DFS event")

    state = hapd.get_status_field("state")
    if state != "DFS":
        if allow_failure:
            logger.info("Interface state not DFS: " + state)
            if not os.path.exists("dfs"):
                raise HwsimSkip("Assume DFS testing not supported")
            raise Exception("Failed to start DFS AP")
        raise Exception("Unexpected interface state: " + state)

    return hapd

def dfs_simulate_radar(hapd):
    logger.info("Trigger a simulated radar event")
    phyname = hapd.get_driver_status_field("phyname")
    radar_file = '/sys/kernel/debug/ieee80211/' + phyname + '/hwsim/dfs_simulate_radar'
    with open(radar_file, 'w') as f:
        f.write('1')

def test_dfs(dev, apdev):
    """DFS CAC functionality on clear channel"""
    try:
        hapd = None
        hapd = start_dfs_ap(apdev[0], allow_failure=True)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 70)
        if "success=1" not in ev:
            raise Exception("CAC failed")
        if "freq=5260" not in ev:
            raise Exception("Unexpected DFS freq result")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state")

        freq = hapd.get_status_field("freq")
        if freq != "5260":
            raise Exception("Unexpected frequency")

        dev[0].connect("dfs", key_mgmt="NONE")
        hwsim_utils.test_connectivity(dev[0], hapd)

        hapd.request("RADAR DETECTED freq=5260 ht_enabled=1 chan_width=1")
        ev = hapd.wait_event(["DFS-RADAR-DETECTED"], timeout=10)
        if ev is None:
            raise Exception("DFS-RADAR-DETECTED event not reported")
        if "freq=5260" not in ev:
            raise Exception("Incorrect frequency in radar detected event: " + ev)
        ev = hapd.wait_event(["DFS-NEW-CHANNEL"], timeout=70)
        if ev is None:
            raise Exception("DFS-NEW-CHANNEL event not reported")
        if "freq=5260" in ev:
            raise Exception("Channel did not change after radar was detected")

        ev = hapd.wait_event(["AP-CSA-FINISHED"], timeout=70)
        if ev is None:
            raise Exception("AP-CSA-FINISHED event not reported")
        if "freq=5260" in ev:
            raise Exception("Channel did not change after radar was detected(2)")
        time.sleep(1)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_dfs_radar(dev, apdev):
    """DFS CAC functionality with radar detected"""
    try:
        hapd = None
        hapd2 = None
        hapd = start_dfs_ap(apdev[0], allow_failure=True)
        time.sleep(1)

        dfs_simulate_radar(hapd)

        hapd2 = start_dfs_ap(apdev[1], ssid="dfs2", ht40=True)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 5)
        if ev is None:
            raise Exception("Timeout on DFS aborted event")
        if "success=0 freq=5260" not in ev:
            raise Exception("Unexpected DFS aborted event contents: " + ev)

        ev = wait_dfs_event(hapd, "DFS-RADAR-DETECTED", 5)
        if "freq=5260" not in ev:
            raise Exception("Unexpected DFS radar detection freq")

        ev = wait_dfs_event(hapd, "DFS-NEW-CHANNEL", 5)
        if "freq=5260" in ev:
            raise Exception("Unexpected DFS new freq")

        ev = wait_dfs_event(hapd, None, 5)
        if "AP-ENABLED" in ev:
            logger.info("Started AP on non-DFS channel")
        else:
            logger.info("Trying to start AP on another DFS channel")
            if "DFS-CAC-START" not in ev:
                raise Exception("Unexpected DFS event")
            if "freq=5260" in ev:
                raise Exception("Unexpected DFS CAC freq")

            ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 70)
            if "success=1" not in ev:
                raise Exception("CAC failed")
            if "freq=5260" in ev:
                raise Exception("Unexpected DFS freq result - radar channel")

            ev = hapd.wait_event(["AP-ENABLED"], timeout=5)
            if not ev:
                raise Exception("AP setup timed out")

            state = hapd.get_status_field("state")
            if state != "ENABLED":
                raise Exception("Unexpected interface state")

            freq = hapd.get_status_field("freq")
            if freq == "5260":
                raise Exception("Unexpected frequency: " + freq)

        dev[0].connect("dfs", key_mgmt="NONE")

        ev = hapd2.wait_event(["AP-ENABLED"], timeout=70)
        if not ev:
            raise Exception("AP2 setup timed out")

        dfs_simulate_radar(hapd2)

        ev = wait_dfs_event(hapd2, "DFS-RADAR-DETECTED", 5)
        if "freq=5260 ht_enabled=1 chan_offset=1 chan_width=2" not in ev:
            raise Exception("Unexpected DFS radar detection freq from AP2")

        ev = wait_dfs_event(hapd2, "DFS-NEW-CHANNEL", 5)
        if "freq=5260" in ev:
            raise Exception("Unexpected DFS new freq for AP2")

        wait_dfs_event(hapd2, None, 5)
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

@remote_compatible
def test_dfs_radar_on_non_dfs_channel(dev, apdev):
    """DFS radar detection test code on non-DFS channel"""
    params = { "ssid": "radar" }
    hapd = hostapd.add_ap(apdev[0], params)

    hapd.request("RADAR DETECTED freq=5260 ht_enabled=1 chan_width=1")
    hapd.request("RADAR DETECTED freq=2412 ht_enabled=1 chan_width=1")

def test_dfs_radar_chanlist(dev, apdev):
    """DFS chanlist when radar is detected"""
    try:
        hapd = None
        hapd = start_dfs_ap(apdev[0], chanlist="40 44", allow_failure=True)
        time.sleep(1)

        dfs_simulate_radar(hapd)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 5)
        if ev is None:
            raise Exception("Timeout on DFS aborted event")
        if "success=0 freq=5260" not in ev:
            raise Exception("Unexpected DFS aborted event contents: " + ev)

        ev = wait_dfs_event(hapd, "DFS-RADAR-DETECTED", 5)
        if "freq=5260" not in ev:
            raise Exception("Unexpected DFS radar detection freq")

        ev = wait_dfs_event(hapd, "DFS-NEW-CHANNEL", 5)
        if "freq=5200 chan=40" not in ev and "freq=5220 chan=44" not in ev:
            raise Exception("Unexpected DFS new freq: " + ev)

        ev = wait_dfs_event(hapd, None, 5)
        if "AP-ENABLED" not in ev:
            raise Exception("Unexpected DFS event")
        dev[0].connect("dfs", key_mgmt="NONE")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_dfs_radar_chanlist_vht80(dev, apdev):
    """DFS chanlist when radar is detected and VHT80 configured"""
    try:
        hapd = None
        hapd = start_dfs_ap(apdev[0], chanlist="36", ht40=True, vht80=True,
                            allow_failure=True)
        time.sleep(1)

        dfs_simulate_radar(hapd)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 5)
        if ev is None:
            raise Exception("Timeout on DFS aborted event")
        if "success=0 freq=5260" not in ev:
            raise Exception("Unexpected DFS aborted event contents: " + ev)

        ev = wait_dfs_event(hapd, "DFS-RADAR-DETECTED", 5)
        if "freq=5260" not in ev:
            raise Exception("Unexpected DFS radar detection freq")

        ev = wait_dfs_event(hapd, "DFS-NEW-CHANNEL", 5)
        if "freq=5180 chan=36 sec_chan=1" not in ev:
            raise Exception("Unexpected DFS new freq: " + ev)

        ev = wait_dfs_event(hapd, None, 5)
        if "AP-ENABLED" not in ev:
            raise Exception("Unexpected DFS event")
        dev[0].connect("dfs", key_mgmt="NONE")

        if hapd.get_status_field('vht_oper_centr_freq_seg0_idx') != "42":
            raise Exception("Unexpected seg0 idx")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_dfs_radar_chanlist_vht20(dev, apdev):
    """DFS chanlist when radar is detected and VHT40 configured"""
    try:
        hapd = None
        hapd = start_dfs_ap(apdev[0], chanlist="36", vht20=True,
                            allow_failure=True)
        time.sleep(1)

        dfs_simulate_radar(hapd)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 5)
        if ev is None:
            raise Exception("Timeout on DFS aborted event")
        if "success=0 freq=5260" not in ev:
            raise Exception("Unexpected DFS aborted event contents: " + ev)

        ev = wait_dfs_event(hapd, "DFS-RADAR-DETECTED", 5)
        if "freq=5260" not in ev:
            raise Exception("Unexpected DFS radar detection freq")

        ev = wait_dfs_event(hapd, "DFS-NEW-CHANNEL", 5)
        if "freq=5180 chan=36 sec_chan=0" not in ev:
            raise Exception("Unexpected DFS new freq: " + ev)

        ev = wait_dfs_event(hapd, None, 5)
        if "AP-ENABLED" not in ev:
            raise Exception("Unexpected DFS event")
        dev[0].connect("dfs", key_mgmt="NONE")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_dfs_radar_no_ht(dev, apdev):
    """DFS chanlist when radar is detected and no HT configured"""
    try:
        hapd = None
        hapd = start_dfs_ap(apdev[0], chanlist="36", ht=False,
                            allow_failure=True)
        time.sleep(1)

        dfs_simulate_radar(hapd)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 5)
        if ev is None:
            raise Exception("Timeout on DFS aborted event")
        if "success=0 freq=5260" not in ev:
            raise Exception("Unexpected DFS aborted event contents: " + ev)

        ev = wait_dfs_event(hapd, "DFS-RADAR-DETECTED", 5)
        if "freq=5260 ht_enabled=0" not in ev:
            raise Exception("Unexpected DFS radar detection freq: " + ev)

        ev = wait_dfs_event(hapd, "DFS-NEW-CHANNEL", 5)
        if "freq=5180 chan=36 sec_chan=0" not in ev:
            raise Exception("Unexpected DFS new freq: " + ev)

        ev = wait_dfs_event(hapd, None, 5)
        if "AP-ENABLED" not in ev:
            raise Exception("Unexpected DFS event")
        dev[0].connect("dfs", key_mgmt="NONE")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_dfs_radar_ht40minus(dev, apdev):
    """DFS chanlist when radar is detected and HT40- configured"""
    try:
        hapd = None
        hapd = start_dfs_ap(apdev[0], chanlist="36", ht40minus=True,
                            allow_failure=True)
        time.sleep(1)

        dfs_simulate_radar(hapd)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 5)
        if ev is None:
            raise Exception("Timeout on DFS aborted event")
        if "success=0 freq=5280 ht_enabled=1 chan_offset=-1" not in ev:
            raise Exception("Unexpected DFS aborted event contents: " + ev)

        ev = wait_dfs_event(hapd, "DFS-RADAR-DETECTED", 5)
        if "freq=5280 ht_enabled=1 chan_offset=-1" not in ev:
            raise Exception("Unexpected DFS radar detection freq: " + ev)

        ev = wait_dfs_event(hapd, "DFS-NEW-CHANNEL", 5)
        if "freq=5180 chan=36 sec_chan=1" not in ev:
            raise Exception("Unexpected DFS new freq: " + ev)

        ev = wait_dfs_event(hapd, None, 5)
        if "AP-ENABLED" not in ev:
            raise Exception("Unexpected DFS event")
        dev[0].connect("dfs", key_mgmt="NONE")
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()

def test_dfs_ht40_minus(dev, apdev, params):
    """DFS CAC functionality on channel 104 HT40- [long]"""
    if not params['long']:
        raise HwsimSkip("Skip test case with long duration due to --long not specified")
    try:
        hapd = None
        hapd = start_dfs_ap(apdev[0], allow_failure=True, ht40minus=True,
                            channel=104)

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 70)
        if "success=1" not in ev:
            raise Exception("CAC failed")
        if "freq=5520" not in ev:
            raise Exception("Unexpected DFS freq result")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state")

        freq = hapd.get_status_field("freq")
        if freq != "5520":
            raise Exception("Unexpected frequency")

        dev[0].connect("dfs", key_mgmt="NONE", scan_freq="5520")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
