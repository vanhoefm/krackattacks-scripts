# Test cases for DFS
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import subprocess
import time
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd

def wait_dfs_event(hapd, event, timeout):
    dfs_events = [ "DFS-RADAR-DETECTED", "DFS-NEW-CHANNEL",
                   "DFS-CAC-START", "DFS-CAC-COMPLETED",
                   "DFS-NOP-FINISHED", "AP-ENABLED" ]
    ev = hapd.wait_event(dfs_events, timeout=timeout)
    if not ev:
        raise Exception("DFS event timed out")
    if event and event not in ev:
        raise Exception("Unexpected DFS event")
    return ev

def start_dfs_ap(ap, allow_failure=False):
    ifname = ap['ifname']
    logger.info("Starting AP " + ifname + " on DFS channel")
    hapd_global = hostapd.HostapdGlobal()
    hapd_global.remove(ifname)
    hapd_global.add(ifname)
    hapd = hostapd.Hostapd(ifname)
    if not hapd.ping():
        raise Exception("Could not ping hostapd")
    hapd.set_defaults()
    hapd.set("ssid", "dfs")
    hapd.set("country_code", "FI")
    hapd.set("ieee80211d", "1")
    hapd.set("ieee80211h", "1")
    hapd.set("hw_mode", "a")
    hapd.set("channel", "52")
    hapd.enable()

    ev = wait_dfs_event(hapd, "DFS-CAC-START", 5)
    if "DFS-CAC-START" not in ev:
        raise Exception("Unexpected DFS event")

    state = hapd.get_status_field("state")
    if state != "DFS":
        if allow_failure:
            logger.info("Interface state not DFS: " + state)
            return None
        raise Exception("Unexpected interface state: " + state)

    return hapd

def test_dfs(dev, apdev):
    """DFS CAC functionality on clear channel"""
    try:
        hapd = start_dfs_ap(apdev[0], allow_failure=True)
        if hapd is None:
            if not os.path.exists("dfs"):
                return "skip"
            raise Exception("Failed to start DFS AP")

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
            raise Exception("Incorrect frequency in radar detected event: " + ev);
        ev = hapd.wait_event(["DFS-NEW-CHANNEL"], timeout=70)
        if ev is None:
            raise Exception("DFS-NEW-CHANNEL event not reported")
        if "freq=5260" in ev:
            raise Exception("Channel did not change after radar was detected");

        ev = hapd.wait_event(["AP-CSA-FINISHED"], timeout=70)
        if ev is None:
            raise Exception("AP-CSA-FINISHED event not reported")
        if "freq=5260" in ev:
            raise Exception("Channel did not change after radar was detected(2)");
        time.sleep(1)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_dfs_radar(dev, apdev):
    """DFS CAC functionality with radar detected"""
    try:
        hapd = start_dfs_ap(apdev[0])
        if hapd is None:
            if not os.path.exists("dfs"):
                return "skip"
            raise Exception("Failed to start DFS AP")
        time.sleep(1)

        phyname = hapd.get_driver_status_field("phyname")
        radar_file = '/sys/kernel/debug/ieee80211/' + phyname + '/hwsim/dfs_simulate_radar'
        cmd = subprocess.Popen(["sudo", "tee", radar_file],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        cmd.stdin.write("1")
        cmd.stdin.close()
        cmd.stdout.read()
        cmd.stdout.close()

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
    finally:
        subprocess.call(['sudo', 'iw', 'reg', 'set', '00'])

def test_dfs_radar_on_non_dfs_channel(dev, apdev):
    """DFS radar detection test code on non-DFS channel"""
    params = { "ssid": "radar" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    hapd.request("RADAR DETECTED freq=5260 ht_enabled=1 chan_width=1")
    hapd.request("RADAR DETECTED freq=2412 ht_enabled=1 chan_width=1")
