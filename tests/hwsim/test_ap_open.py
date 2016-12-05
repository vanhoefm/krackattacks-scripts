# Open mode AP tests
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import logging
logger = logging.getLogger()
import struct
import subprocess
import time
import os

import hostapd
import hwsim_utils
from tshark import run_tshark
from utils import alloc_fail, fail_test, wait_fail_trigger
from wpasupplicant import WpaSupplicant

@remote_compatible
def test_ap_open(dev, apdev):
    """AP with open mode (no security) configuration"""
    _test_ap_open(dev, apdev)

def _test_ap_open(dev, apdev):
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bg_scan_period="0")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    hwsim_utils.test_connectivity(dev[0], hapd)

    dev[0].request("DISCONNECT")
    ev = hapd.wait_event([ "AP-STA-DISCONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No disconnection event received from hostapd")

def test_ap_open_packet_loss(dev, apdev):
    """AP with open mode configuration and large packet loss"""
    params = { "ssid": "open",
               "ignore_probe_probability": "0.5",
               "ignore_auth_probability": "0.5",
               "ignore_assoc_probability": "0.5",
               "ignore_reassoc_probability": "0.5" }
    hapd = hostapd.add_ap(apdev[0], params)
    for i in range(0, 3):
        dev[i].connect("open", key_mgmt="NONE", scan_freq="2412",
                       wait_connect=False)
    for i in range(0, 3):
        dev[i].wait_connected(timeout=20)

@remote_compatible
def test_ap_open_unknown_action(dev, apdev):
    """AP with open mode configuration and unknown Action frame"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    bssid = apdev[0]['bssid']
    cmd = "MGMT_TX {} {} freq=2412 action=765432".format(bssid, bssid)
    if "FAIL" in dev[0].request(cmd):
        raise Exception("Could not send test Action frame")
    ev = dev[0].wait_event(["MGMT-TX-STATUS"], timeout=10)
    if ev is None:
        raise Exception("Timeout on MGMT-TX-STATUS")
    if "result=SUCCESS" not in ev:
        raise Exception("AP did not ack Action frame")

def test_ap_open_invalid_wmm_action(dev, apdev):
    """AP with open mode configuration and invalid WMM Action frame"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    bssid = apdev[0]['bssid']
    cmd = "MGMT_TX {} {} freq=2412 action=1100".format(bssid, bssid)
    if "FAIL" in dev[0].request(cmd):
        raise Exception("Could not send test Action frame")
    ev = dev[0].wait_event(["MGMT-TX-STATUS"], timeout=10)
    if ev is None or "result=SUCCESS" not in ev:
        raise Exception("AP did not ack Action frame")

@remote_compatible
def test_ap_open_reconnect_on_inactivity_disconnect(dev, apdev):
    """Reconnect to open mode AP after inactivity related disconnection"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    hapd.request("DEAUTHENTICATE " + dev[0].p2p_interface_addr() + " reason=4")
    dev[0].wait_disconnected(timeout=5)
    dev[0].wait_connected(timeout=2, error="Timeout on reconnection")

@remote_compatible
def test_ap_open_assoc_timeout(dev, apdev):
    """AP timing out association"""
    ssid = "test"
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].scan(freq="2412")
    hapd.set("ext_mgmt_frame_handling", "1")
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   wait_connect=False)
    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out")
        if req['subtype'] == 11:
            break
        req = None
    if not req:
        raise Exception("Authentication frame not received")

    resp = {}
    resp['fc'] = req['fc']
    resp['da'] = req['sa']
    resp['sa'] = req['da']
    resp['bssid'] = req['bssid']
    resp['payload'] = struct.pack('<HHH', 0, 2, 0)
    hapd.mgmt_tx(resp)

    assoc = 0
    for i in range(0, 10):
        req = hapd.mgmt_rx()
        if req is None:
            raise Exception("MGMT RX wait timed out")
        if req['subtype'] == 0:
            assoc += 1
            if assoc == 3:
                break
    if assoc != 3:
        raise Exception("Association Request frames not received: assoc=%d" % assoc)
    hapd.set("ext_mgmt_frame_handling", "0")
    dev[0].wait_connected(timeout=15)

@remote_compatible
def test_ap_open_id_str(dev, apdev):
    """AP with open mode and id_str"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412", id_str="foo",
                   wait_connect=False)
    ev = dev[0].wait_connected(timeout=10)
    if "id_str=foo" not in ev:
        raise Exception("CTRL-EVENT-CONNECT did not have matching id_str: " + ev)
    if dev[0].get_status_field("id_str") != "foo":
        raise Exception("id_str mismatch")

@remote_compatible
def test_ap_open_select_any(dev, apdev):
    """AP with open mode and select any network"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    id = dev[0].connect("unknown", key_mgmt="NONE", scan_freq="2412",
                        only_add_network=True)
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   only_add_network=True)
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-NETWORK-NOT-FOUND",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("No result reported")
    if "CTRL-EVENT-CONNECTED" in ev:
        raise Exception("Unexpected connection")

    dev[0].select_network("any")
    dev[0].wait_connected(timeout=10)

@remote_compatible
def test_ap_open_unexpected_assoc_event(dev, apdev):
    """AP with open mode and unexpected association event"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=15)
    dev[0].dump_monitor()
    # This will be accepted due to matching network
    dev[0].cmd_execute(['iw', 'dev', dev[0].ifname, 'connect', 'open', "2412",
                        apdev[0]['bssid']])
    dev[0].wait_connected(timeout=15)
    dev[0].dump_monitor()

    dev[0].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected(timeout=5)
    dev[0].dump_monitor()
    # This will result in disconnection due to no matching network
    dev[0].cmd_execute(['iw', 'dev', dev[0].ifname, 'connect', 'open', "2412",
                        apdev[0]['bssid']])
    dev[0].wait_disconnected(timeout=15)

def test_ap_open_external_assoc(dev, apdev):
    """AP with open mode and external association"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open-ext-assoc" })
    try:
        dev[0].request("STA_AUTOCONNECT 0")
        id = dev[0].connect("open-ext-assoc", key_mgmt="NONE", scan_freq="2412",
                            only_add_network=True)
        dev[0].request("ENABLE_NETWORK %s no-connect" % id)
        dev[0].dump_monitor()
        # This will be accepted due to matching network
        dev[0].cmd_execute(['iw', 'dev', dev[0].ifname, 'connect',
                            'open-ext-assoc', "2412", apdev[0]['bssid']])
        ev = dev[0].wait_event([ "CTRL-EVENT-DISCONNECTED",
                                 "CTRL-EVENT-CONNECTED" ], timeout=10)
        if ev is None:
            raise Exception("Connection timed out")
        if "CTRL-EVENT-DISCONNECTED" in ev:
            raise Exception("Unexpected disconnection event")
        dev[0].dump_monitor()
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=5)
    finally:
        dev[0].request("STA_AUTOCONNECT 1")

@remote_compatible
def test_ap_bss_load(dev, apdev):
    """AP with open mode (no security) configuration"""
    hapd = hostapd.add_ap(apdev[0],
                          { "ssid": "open",
                            "bss_load_update_period": "10" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    # this does not really get much useful output with mac80211_hwsim currently,
    # but run through the channel survey update couple of times
    for i in range(0, 10):
        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[0], hapd)
        time.sleep(0.15)

def hapd_out_of_mem(hapd, apdev, count, func):
    with alloc_fail(hapd, count, func):
        started = False
        try:
            hostapd.add_ap(apdev, { "ssid": "open" })
            started = True
        except:
            pass
        if started:
            raise Exception("hostapd interface started even with memory allocation failure: %d:%s" % (count, func))

def test_ap_open_out_of_memory(dev, apdev):
    """hostapd failing to setup interface due to allocation failure"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    hapd_out_of_mem(hapd, apdev[1], 1, "hostapd_alloc_bss_data")

    for i in range(1, 3):
        hapd_out_of_mem(hapd, apdev[1], i, "hostapd_iface_alloc")

    for i in range(1, 5):
        hapd_out_of_mem(hapd, apdev[1], i, "hostapd_config_defaults;hostapd_config_alloc")

    hapd_out_of_mem(hapd, apdev[1], 1, "hostapd_config_alloc")

    hapd_out_of_mem(hapd, apdev[1], 1, "hostapd_driver_init")

    for i in range(1, 3):
        hapd_out_of_mem(hapd, apdev[1], i, "=wpa_driver_nl80211_drv_init")

    # eloop_register_read_sock() call from i802_init()
    hapd_out_of_mem(hapd, apdev[1], 1, "eloop_sock_table_add_sock;?eloop_register_sock;?eloop_register_read_sock;=i802_init")

    # verify that a new interface can still be added when memory allocation does
    # not fail
    hostapd.add_ap(apdev[1], { "ssid": "open" })

def test_bssid_black_white_list(dev, apdev):
    """BSSID black/white list"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    hapd2 = hostapd.add_ap(apdev[1], { "ssid": "open" })

    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bssid_whitelist=apdev[1]['bssid'])
    dev[1].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bssid_blacklist=apdev[1]['bssid'])
    dev[2].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bssid_whitelist="00:00:00:00:00:00/00:00:00:00:00:00",
                   bssid_blacklist=apdev[1]['bssid'])
    if dev[0].get_status_field('bssid') != apdev[1]['bssid']:
        raise Exception("dev[0] connected to unexpected AP")
    if dev[1].get_status_field('bssid') != apdev[0]['bssid']:
        raise Exception("dev[1] connected to unexpected AP")
    if dev[2].get_status_field('bssid') != apdev[0]['bssid']:
        raise Exception("dev[2] connected to unexpected AP")
    dev[0].request("REMOVE_NETWORK all")
    dev[1].request("REMOVE_NETWORK all")
    dev[2].request("REMOVE_NETWORK all")

    dev[2].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bssid_whitelist="00:00:00:00:00:00", wait_connect=False)
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bssid_whitelist="11:22:33:44:55:66/ff:00:00:00:00:00 " + apdev[1]['bssid'] + " aa:bb:cc:dd:ee:ff")
    dev[1].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bssid_blacklist="11:22:33:44:55:66/ff:00:00:00:00:00 " + apdev[1]['bssid'] + " aa:bb:cc:dd:ee:ff")
    if dev[0].get_status_field('bssid') != apdev[1]['bssid']:
        raise Exception("dev[0] connected to unexpected AP")
    if dev[1].get_status_field('bssid') != apdev[0]['bssid']:
        raise Exception("dev[1] connected to unexpected AP")
    dev[0].request("REMOVE_NETWORK all")
    dev[1].request("REMOVE_NETWORK all")
    ev = dev[2].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected dev[2] connectin")
    dev[2].request("REMOVE_NETWORK all")

def test_ap_open_wpas_in_bridge(dev, apdev):
    """Open mode AP and wpas interface in a bridge"""
    br_ifname='sta-br0'
    ifname='wlan5'
    try:
        _test_ap_open_wpas_in_bridge(dev, apdev)
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'down'])
        subprocess.call(['brctl', 'delif', br_ifname, ifname])
        subprocess.call(['brctl', 'delbr', br_ifname])
        subprocess.call(['iw', ifname, 'set', '4addr', 'off'])

def _test_ap_open_wpas_in_bridge(dev, apdev):
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })

    br_ifname='sta-br0'
    ifname='wlan5'
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    # First, try a failure case of adding an interface
    try:
        wpas.interface_add(ifname, br_ifname=br_ifname)
        raise Exception("Interface addition succeeded unexpectedly")
    except Exception, e:
        if "Failed to add" in str(e):
            logger.info("Ignore expected interface_add failure due to missing bridge interface: " + str(e))
        else:
            raise

    # Next, add the bridge interface and add the interface again
    subprocess.call(['brctl', 'addbr', br_ifname])
    subprocess.call(['brctl', 'setfd', br_ifname, '0'])
    subprocess.call(['ip', 'link', 'set', 'dev', br_ifname, 'up'])
    subprocess.call(['iw', ifname, 'set', '4addr', 'on'])
    subprocess.check_call(['brctl', 'addif', br_ifname, ifname])
    wpas.interface_add(ifname, br_ifname=br_ifname)

    wpas.connect("open", key_mgmt="NONE", scan_freq="2412")

@remote_compatible
def test_ap_open_start_disabled(dev, apdev):
    """AP with open mode and beaconing disabled"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open",
                                      "start_disabled": "1" })
    bssid = apdev[0]['bssid']

    dev[0].flush_scan_cache()
    dev[0].scan(freq=2412, only_new=True)
    if dev[0].get_bss(bssid) is not None:
        raise Exception("AP was seen beaconing")
    if "OK" not in hapd.request("RELOAD"):
        raise Exception("RELOAD failed")
    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")

@remote_compatible
def test_ap_open_start_disabled2(dev, apdev):
    """AP with open mode and beaconing disabled (2)"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open",
                                      "start_disabled": "1" })
    bssid = apdev[0]['bssid']

    dev[0].flush_scan_cache()
    dev[0].scan(freq=2412, only_new=True)
    if dev[0].get_bss(bssid) is not None:
        raise Exception("AP was seen beaconing")
    if "OK" not in hapd.request("UPDATE_BEACON"):
        raise Exception("UPDATE_BEACON failed")
    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    if "OK" not in hapd.request("UPDATE_BEACON"):
        raise Exception("UPDATE_BEACON failed")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].request("RECONNECT")
    dev[0].wait_connected()

@remote_compatible
def test_ap_open_ifdown(dev, apdev):
    """AP with open mode and external ifconfig down"""
    params = { "ssid": "open",
               "ap_max_inactivity": "1" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']

    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    dev[1].connect("open", key_mgmt="NONE", scan_freq="2412")
    hapd.cmd_execute(['ip', 'link', 'set', 'dev', apdev[0]['ifname'], 'down'])
    ev = hapd.wait_event(["AP-STA-DISCONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Timeout on AP-STA-DISCONNECTED (1)")
    ev = hapd.wait_event(["AP-STA-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Timeout on AP-STA-DISCONNECTED (2)")
    ev = hapd.wait_event(["INTERFACE-DISABLED"], timeout=5)
    if ev is None:
        raise Exception("No INTERFACE-DISABLED event")
    # The following wait tests beacon loss detection in mac80211 on dev0.
    # dev1 is used to test stopping of AP side functionality on client polling.
    dev[1].request("REMOVE_NETWORK all")
    hapd.cmd_execute(['ip', 'link', 'set', 'dev', apdev[0]['ifname'], 'up'])
    dev[0].wait_disconnected()
    dev[1].wait_disconnected()
    ev = hapd.wait_event(["INTERFACE-ENABLED"], timeout=10)
    if ev is None:
        raise Exception("No INTERFACE-ENABLED event")
    dev[0].wait_connected()
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ap_open_disconnect_in_ps(dev, apdev, params):
    """Disconnect with the client in PS to regression-test a kernel bug"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bg_scan_period="0")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")

    time.sleep(0.2)
    hwsim_utils.set_powersave(dev[0], hwsim_utils.PS_MANUAL_POLL)
    try:
        # inject some traffic
        sa = hapd.own_addr()
        da = dev[0].own_addr()
        hapd.request('DATA_TEST_CONFIG 1')
        hapd.request('DATA_TEST_TX {} {} 0'.format(da, sa))
        hapd.request('DATA_TEST_CONFIG 0')

        # let the AP send couple of Beacon frames
        time.sleep(0.3)

        # disconnect - with traffic pending - shouldn't cause kernel warnings
        dev[0].request("DISCONNECT")
    finally:
        hwsim_utils.set_powersave(dev[0], hwsim_utils.PS_DISABLED)

    time.sleep(0.2)
    out = run_tshark(os.path.join(params['logdir'], "hwsim0.pcapng"),
                     "wlan_mgt.tim.partial_virtual_bitmap",
                     ["wlan_mgt.tim.partial_virtual_bitmap"])
    if out is not None:
        state = 0
        for l in out.splitlines():
            pvb = int(l, 16)
            if pvb > 0 and state == 0:
                state = 1
            elif pvb == 0 and state == 1:
                state = 2
        if state != 2:
            raise Exception("Didn't observe TIM bit getting set and unset (state=%d)" % state)

@remote_compatible
def test_ap_open_select_network(dev, apdev):
    """Open mode connection and SELECT_NETWORK to change network"""
    hapd1 = hostapd.add_ap(apdev[0], { "ssid": "open" })
    bssid1 = apdev[0]['bssid']
    hapd2 = hostapd.add_ap(apdev[1], { "ssid": "open2" })
    bssid2 = apdev[1]['bssid']

    id1 = dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                         only_add_network=True)
    id2 = dev[0].connect("open2", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd2)

    dev[0].select_network(id1)
    dev[0].wait_connected()
    res = dev[0].request("BLACKLIST")
    if bssid1 in res or bssid2 in res:
        raise Exception("Unexpected blacklist entry")
    hwsim_utils.test_connectivity(dev[0], hapd1)

    dev[0].select_network(id2)
    dev[0].wait_connected()
    hwsim_utils.test_connectivity(dev[0], hapd2)
    res = dev[0].request("BLACKLIST")
    if bssid1 in res or bssid2 in res:
        raise Exception("Unexpected blacklist entry(2)")

@remote_compatible
def test_ap_open_disable_enable(dev, apdev):
    """AP with open mode getting disabled and re-enabled"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   bg_scan_period="0")

    for i in range(2):
        hapd.request("DISABLE")
        dev[0].wait_disconnected()
        hapd.request("ENABLE")
        dev[0].wait_connected()
        hwsim_utils.test_connectivity(dev[0], hapd)

def sta_enable_disable(dev, bssid):
    dev.scan_for_bss(bssid, freq=2412)
    work_id = dev.request("RADIO_WORK add block-work")
    ev = dev.wait_event(["EXT-RADIO-WORK-START"])
    if ev is None:
        raise Exception("Timeout while waiting radio work to start")
    id = dev.connect("open", key_mgmt="NONE", scan_freq="2412",
                     only_add_network=True)
    dev.request("ENABLE_NETWORK %d" % id)
    if "connect@" not in dev.request("RADIO_WORK show"):
        raise Exception("connect radio work missing")
    dev.request("DISABLE_NETWORK %d" % id)
    dev.request("RADIO_WORK done " + work_id)

    ok = False
    for i in range(30):
        if "connect@" not in dev.request("RADIO_WORK show"):
            ok = True
            break
        time.sleep(0.1)
    if not ok:
        raise Exception("connect radio work not completed")
    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected connection")
    dev.request("DISCONNECT")

def test_ap_open_sta_enable_disable(dev, apdev):
    """AP with open mode and wpa_supplicant ENABLE/DISABLE_NETWORK"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    bssid = apdev[0]['bssid']

    sta_enable_disable(dev[0], bssid)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    sta_enable_disable(wpas, bssid)

@remote_compatible
def test_ap_open_select_twice(dev, apdev):
    """AP with open mode and select network twice"""
    id = dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                        only_add_network=True)
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-NETWORK-NOT-FOUND"], timeout=10)
    if ev is None:
        raise Exception("No result reported")
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    # Verify that the second SELECT_NETWORK starts a new scan immediately by
    # waiting less than the default scan period.
    dev[0].select_network(id)
    dev[0].wait_connected(timeout=3)

@remote_compatible
def test_ap_open_reassoc_not_found(dev, apdev):
    """AP with open mode and REASSOCIATE not finding a match"""
    id = dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                        only_add_network=True)
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-NETWORK-NOT-FOUND"], timeout=10)
    if ev is None:
        raise Exception("No result reported")
    dev[0].request("DISCONNECT")

    time.sleep(0.1)
    dev[0].dump_monitor()

    dev[0].request("REASSOCIATE")
    ev = dev[0].wait_event(["CTRL-EVENT-NETWORK-NOT-FOUND"], timeout=10)
    if ev is None:
        raise Exception("No result reported")
    dev[0].request("DISCONNECT")

@remote_compatible
def test_ap_open_sta_statistics(dev, apdev):
    """AP with open mode and STA statistics"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    stats1 = hapd.get_sta(addr)
    logger.info("stats1: " + str(stats1))
    time.sleep(0.4)
    stats2 = hapd.get_sta(addr)
    logger.info("stats2: " + str(stats2))
    hwsim_utils.test_connectivity(dev[0], hapd)
    stats3 = hapd.get_sta(addr)
    logger.info("stats3: " + str(stats3))

    # Cannot require specific inactive_msec changes without getting rid of all
    # unrelated traffic, so for now, just print out the results in the log for
    # manual checks.

@remote_compatible
def test_ap_open_poll_sta(dev, apdev):
    """AP with open mode and STA poll"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    if "OK" not in hapd.request("POLL_STA " + addr):
        raise Exception("POLL_STA failed")
    ev = hapd.wait_event(["AP-STA-POLL-OK"], timeout=5)
    if ev is None:
        raise Exception("Poll response not seen")
    if addr not in ev:
        raise Exception("Unexpected poll response: " + ev)

def test_ap_open_pmf_default(dev, apdev):
    """AP with open mode (no security) configuration and pmf=2"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })
    dev[1].connect("open", key_mgmt="NONE", scan_freq="2412",
                   ieee80211w="2", wait_connect=False)
    dev[2].connect("open", key_mgmt="NONE", scan_freq="2412",
                   ieee80211w="1")
    try:
        dev[0].request("SET pmf 2")
        dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")

        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
    finally:
        dev[0].request("SET pmf 0")
    dev[2].request("DISCONNECT")
    dev[2].wait_disconnected()

    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected dev[1] connection")
    dev[1].request("DISCONNECT")

def test_ap_open_drv_fail(dev, apdev):
    """AP with open mode and driver operations failing"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })

    with fail_test(dev[0], 1, "wpa_driver_nl80211_authenticate"):
        dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                       wait_connect=False)
        wait_fail_trigger(dev[0], "GET_FAIL")
        dev[0].request("REMOVE_NETWORK all")

    with fail_test(dev[0], 1, "wpa_driver_nl80211_associate"):
        dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                       wait_connect=False)
        wait_fail_trigger(dev[0], "GET_FAIL")
        dev[0].request("REMOVE_NETWORK all")

def run_multicast_to_unicast(dev, apdev, convert):
    params = { "ssid": "open" }
    params["multicast_to_unicast"] = "1" if convert else "0"
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].scan_for_bss(hapd.own_addr(), freq=2412)
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    hwsim_utils.test_connectivity(dev[0], hapd, multicast_to_unicast=convert)
    dev[0].request("DISCONNECT")
    ev = hapd.wait_event([ "AP-STA-DISCONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No disconnection event received from hostapd")

def test_ap_open_multicast_to_unicast(dev, apdev):
    """Multicast-to-unicast conversion enabled"""
    run_multicast_to_unicast(dev, apdev, True)

def test_ap_open_multicast_to_unicast_disabled(dev, apdev):
    """Multicast-to-unicast conversion disabled"""
    run_multicast_to_unicast(dev, apdev, False)
