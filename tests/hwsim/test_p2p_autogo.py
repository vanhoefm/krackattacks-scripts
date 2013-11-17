#!/usr/bin/python
#
# P2P autonomous GO test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
from wlantest import Wlantest

def autogo(go, freq=None):
    logger.info("Start autonomous GO " + go.ifname)
    res = go.p2p_start_go(freq=freq)
    logger.debug("res: " + str(res))
    return res

def connect_cli(go, client):
    logger.info("Try to connect the client to the GO")
    pin = client.wps_read_pin()
    go.p2p_go_authorize_client(pin)
    client.p2p_connect_group(go.p2p_dev_addr(), pin, timeout=60)
    logger.info("Client connected")
    hwsim_utils.test_connectivity_p2p(go, client)

def test_autogo(dev):
    """P2P autonomous GO and client joining group"""
    autogo(dev[0])
    connect_cli(dev[0], dev[1])
    dev[0].remove_group()
    dev[1].wait_go_ending_session()

def test_autogo_2cli(dev):
    """P2P autonomous GO and two clients joining group"""
    autogo(dev[0])
    connect_cli(dev[0], dev[1])
    connect_cli(dev[0], dev[2])
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    dev[0].global_request("P2P_REMOVE_CLIENT " + dev[1].p2p_dev_addr())
    dev[1].wait_go_ending_session()
    dev[0].remove_group()
    dev[2].wait_go_ending_session()

def test_autogo_tdls(dev):
    """P2P autonomous GO and two clients using TDLS"""
    wt = Wlantest()
    go = dev[0]
    logger.info("Start autonomous GO with fixed parameters " + go.ifname)
    id = go.add_network()
    go.set_network_quoted(id, "ssid", "DIRECT-tdls")
    go.set_network_quoted(id, "psk", "12345678")
    go.set_network(id, "mode", "3")
    go.set_network(id, "disabled", "2")
    res = go.p2p_start_go(persistent=id)
    logger.debug("res: " + str(res))
    wt.flush()
    wt.add_passphrase("12345678")
    connect_cli(go, dev[1])
    connect_cli(go, dev[2])
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    bssid = dev[0].p2p_interface_addr()
    addr1 = dev[1].p2p_interface_addr()
    addr2 = dev[2].p2p_interface_addr()
    dev[1].tdls_setup(addr2)
    time.sleep(1)
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    conf = wt.get_tdls_counter("setup_conf_ok", bssid, addr1, addr2);
    if conf == 0:
        raise Exception("No TDLS Setup Confirm (success) seen")
    dl = wt.get_tdls_counter("valid_direct_link", bssid, addr1, addr2);
    if dl == 0:
        raise Exception("No valid frames through direct link")
    wt.tdls_clear(bssid, addr1, addr2);
    dev[1].tdls_teardown(addr2)
    time.sleep(1)
    teardown = wt.get_tdls_counter("teardown", bssid, addr1, addr2);
    if teardown == 0:
        raise Exception("No TDLS Setup Teardown seen")
    wt.tdls_clear(bssid, addr1, addr2);
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    ap_path = wt.get_tdls_counter("valid_ap_path", bssid, addr1, addr2);
    if ap_path == 0:
        raise Exception("No valid frames via AP path")
    direct_link = wt.get_tdls_counter("valid_direct_link", bssid, addr1, addr2);
    if direct_link > 0:
        raise Exception("Unexpected frames through direct link")
    idirect_link = wt.get_tdls_counter("invalid_direct_link", bssid, addr1,
                                       addr2);
    if idirect_link > 0:
        raise Exception("Unexpected frames through direct link (invalid)")
    dev[2].remove_group()
    dev[1].remove_group()
    dev[0].remove_group()

def test_autogo_legacy(dev):
    """P2P autonomous GO and legacy clients"""
    res = autogo(dev[0])

    logger.info("Connect P2P client")
    connect_cli(dev[0], dev[1])

    logger.info("Connect legacy WPS client")
    pin = dev[2].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    dev[2].request("SET ignore_old_scan_res 1")
    dev[2].request("P2P_SET disabled 1")
    dev[2].dump_monitor()
    dev[2].request("WPS_PIN any " + pin)
    ev = dev[2].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the GO timed out")
    status = dev[2].get_status()
    if status['wpa_state'] != 'COMPLETED':
        raise Exception("Not fully connected")
    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])
    dev[2].request("DISCONNECT")

    logger.info("Connect legacy non-WPS client")
    dev[2].request("FLUSH")
    dev[2].request("P2P_SET disabled 1")
    dev[2].connect(ssid=res['ssid'], psk=res['passphrase'], proto='RSN',
                   key_mgmt='WPA-PSK', pairwise='CCMP', group='CCMP',
                   scan_freq=res['freq'])
    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])
    dev[2].request("DISCONNECT")

    dev[0].remove_group()
    dev[1].wait_go_ending_session()

def test_autogo_chan_switch(dev):
    """P2P autonomous GO switching channels"""
    autogo(dev[0], freq=2417)
    connect_cli(dev[0], dev[1])
    res = dev[0].request("CHAN_SWITCH 5 2422")
    if "FAIL" in res:
        # for now, skip test since mac80211_hwsim support is not yet widely
        # deployed
        return 'skip'
    ev = dev[0].wait_event(["AP-CSA-FINISHED"], timeout=10)
    if ev is None:
        raise Exception("CSA finished event timed out")
    if "freq=2422" not in ev:
        raise Exception("Unexpected cahnnel in CSA finished event")
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    time.sleep(0.1)
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])
