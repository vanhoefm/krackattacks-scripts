# Open mode AP tests
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import struct
import subprocess
import time

import hostapd
import hwsim_utils

def test_ap_open(dev, apdev):
    """AP with open mode (no security) configuration"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
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
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    for i in range(0, 3):
        dev[i].connect("open", key_mgmt="NONE", scan_freq="2412",
                       wait_connect=False)
    for i in range(0, 3):
        dev[i].wait_connected(timeout=20)

def test_ap_open_unknown_action(dev, apdev):
    """AP with open mode configuration and unknown Action frame"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
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

def test_ap_open_reconnect_on_inactivity_disconnect(dev, apdev):
    """Reconnect to open mode AP after inactivity related disconnection"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    hapd.request("DEAUTHENTICATE " + dev[0].p2p_interface_addr() + " reason=4")
    dev[0].wait_disconnected(timeout=5)
    dev[0].wait_connected(timeout=2, error="Timeout on reconnection")

def test_ap_open_assoc_timeout(dev, apdev):
    """AP timing out association"""
    ssid = "test"
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
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

def test_ap_open_id_str(dev, apdev):
    """AP with open mode and id_str"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412", id_str="foo",
                   wait_connect=False)
    ev = dev[0].wait_connected(timeout=10)
    if "id_str=foo" not in ev:
        raise Exception("CTRL-EVENT-CONNECT did not have matching id_str: " + ev)
    if dev[0].get_status_field("id_str") != "foo":
        raise Exception("id_str mismatch")

def test_ap_open_select_any(dev, apdev):
    """AP with open mode and select any network"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    id = dev[0].connect("unknown", key_mgmt="NONE", scan_freq="2412",
                        only_add_network=True)
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   only_add_network=True)
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected connection")

    dev[0].select_network("any")
    dev[0].wait_connected(timeout=10)

def test_ap_open_unexpected_assoc_event(dev, apdev):
    """AP with open mode and unexpected association event"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=15)
    dev[0].dump_monitor()
    # This will be accepted due to matching network
    subprocess.call(['iw', 'dev', dev[0].ifname, 'connect', 'open', "2412",
                     apdev[0]['bssid']])
    dev[0].wait_connected(timeout=15)
    dev[0].dump_monitor()

    dev[0].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected(timeout=5)
    dev[0].dump_monitor()
    # This will result in disconnection due to no matching network
    subprocess.call(['iw', 'dev', dev[0].ifname, 'connect', 'open', "2412",
                     apdev[0]['bssid']])
    dev[0].wait_disconnected(timeout=15)

def test_ap_bss_load(dev, apdev):
    """AP with open mode (no security) configuration"""
    hapd = hostapd.add_ap(apdev[0]['ifname'],
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
