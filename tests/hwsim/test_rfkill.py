# rfkill tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess
import time

import hostapd
from hostapd import HostapdGlobal
import hwsim_utils

def get_rfkill_id(dev):
    try:
        cmd = subprocess.Popen(["rfkill", "list"], stdout=subprocess.PIPE)
    except Exception, e:
        logger.info("No rfkill available: " + str(e))
        return None
    res = cmd.stdout.read()
    cmd.stdout.close()
    phy = dev.get_driver_status_field("phyname")
    matches = [ line for line in res.splitlines() if phy + ':' in line ]
    if len(matches) != 1:
        return None
    return matches[0].split(':')[0]

def test_rfkill_open(dev, apdev):
    """rfkill block/unblock during open mode connection"""
    id = get_rfkill_id(dev[0])
    if id is None:
        return "skip"

    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    try:
        logger.info("rfkill block")
        subprocess.call(['sudo', 'rfkill', 'block', id])
        dev[0].wait_disconnected(timeout=10,
                                 error="Missing disconnection event on rfkill block")

        if "FAIL" not in dev[0].request("REASSOCIATE"):
            raise Exception("REASSOCIATE accepted while disabled")
        if "FAIL" not in dev[0].request("REATTACH"):
            raise Exception("REATTACH accepted while disabled")
        if "FAIL" not in dev[0].request("RECONNECT"):
            raise Exception("RECONNECT accepted while disabled")
        if "FAIL" not in dev[0].request("FETCH_OSU"):
            raise Exception("FETCH_OSU accepted while disabled")

        logger.info("rfkill unblock")
        subprocess.call(['sudo', 'rfkill', 'unblock', id])
        dev[0].wait_connected(timeout=10,
                              error="Missing connection event on rfkill unblock")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        subprocess.call(['sudo', 'rfkill', 'unblock', id])

def test_rfkill_wpa2_psk(dev, apdev):
    """rfkill block/unblock during WPA2-PSK connection"""
    id = get_rfkill_id(dev[0])
    if id is None:
        return "skip"

    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    try:
        logger.info("rfkill block")
        subprocess.call(['sudo', 'rfkill', 'block', id])
        dev[0].wait_disconnected(timeout=10,
                                 error="Missing disconnection event on rfkill block")

        logger.info("rfkill unblock")
        subprocess.call(['sudo', 'rfkill', 'unblock', id])
        dev[0].wait_connected(timeout=10,
                              error="Missing connection event on rfkill unblock")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        subprocess.call(['sudo', 'rfkill', 'unblock', id])

def test_rfkill_autogo(dev, apdev):
    """rfkill block/unblock for autonomous P2P GO"""
    id0 = get_rfkill_id(dev[0])
    if id0 is None:
        return "skip"
    id1 = get_rfkill_id(dev[1])
    if id1 is None:
        return "skip"

    dev[0].p2p_start_go()
    dev[1].request("SET p2p_no_group_iface 0")
    dev[1].p2p_start_go()

    try:
        logger.info("rfkill block 0")
        subprocess.call(['sudo', 'rfkill', 'block', id0])
        ev = dev[0].wait_global_event(["P2P-GROUP-REMOVED"], timeout=10)
        if ev is None:
            raise Exception("Group removal not reported")
        if "reason=UNAVAILABLE" not in ev:
            raise Exception("Unexpected group removal reason: " + ev)
        if "FAIL" not in dev[0].request("P2P_LISTEN 1"):
            raise Exception("P2P_LISTEN accepted unexpectedly")
        if "FAIL" not in dev[0].request("P2P_LISTEN"):
            raise Exception("P2P_LISTEN accepted unexpectedly")

        logger.info("rfkill block 1")
        subprocess.call(['sudo', 'rfkill', 'block', id1])
        ev = dev[1].wait_global_event(["P2P-GROUP-REMOVED"], timeout=10)
        if ev is None:
            raise Exception("Group removal not reported")
        if "reason=UNAVAILABLE" not in ev:
            raise Exception("Unexpected group removal reason: " + ev)

        logger.info("rfkill unblock 0")
        subprocess.call(['sudo', 'rfkill', 'unblock', id0])
        logger.info("rfkill unblock 1")
        subprocess.call(['sudo', 'rfkill', 'unblock', id1])
        time.sleep(1)
    finally:
        subprocess.call(['sudo', 'rfkill', 'unblock', id0])
        subprocess.call(['sudo', 'rfkill', 'unblock', id1])

def test_rfkill_hostapd(dev, apdev):
    """rfkill block/unblock during and prior to hostapd operations"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })

    id = get_rfkill_id(hapd)
    if id is None:
        return "skip"

    try:
        subprocess.call(['rfkill', 'block', id])
        ev = hapd.wait_event(["INTERFACE-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("INTERFACE-DISABLED event not seen")
        subprocess.call(['rfkill', 'unblock', id])
        ev = hapd.wait_event(["INTERFACE-ENABLED"], timeout=5)
        if ev is None:
            raise Exception("INTERFACE-ENABLED event not seen")
        # hostapd does not current re-enable beaconing automatically
        hapd.disable()
        hapd.enable()
        dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
        subprocess.call(['rfkill', 'block', id])
        ev = hapd.wait_event(["INTERFACE-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("INTERFACE-DISABLED event not seen")
        dev[0].wait_disconnected(timeout=10)
        dev[0].request("DISCONNECT")
        hapd.disable()

        hglobal = HostapdGlobal()
        hglobal.flush()
        hglobal.remove(apdev[0]['ifname'])

        hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open2" },
                              no_enable=True)
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("ENABLE succeeded unexpectedly (rfkill)")
    finally:
        subprocess.call(['rfkill', 'unblock', id])
