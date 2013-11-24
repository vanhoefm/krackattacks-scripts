#!/usr/bin/python
#
# P2P concurrency test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

import hwsim_utils
import hostapd
from test_p2p_grpform import go_neg_pin_authorized
from test_p2p_grpform import go_neg_pbc
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group

def test_concurrent_autogo(dev, apdev):
    """Concurrent P2P autonomous GO"""
    logger.info("Connect to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

    logger.info("Start a P2P group while associated to an AP")
    dev[0].request("SET p2p_no_group_iface 0")
    dev[0].p2p_start_go()
    pin = dev[1].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    dev[1].p2p_connect_group(dev[0].p2p_dev_addr(), pin, timeout=60,
                             social=True)
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])
    dev[0].remove_group()
    dev[1].wait_go_ending_session()

    logger.info("Confirm AP connection after P2P group removal")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_concurrent_p2pcli(dev, apdev):
    """Concurrent P2P client join"""
    logger.info("Connect to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

    logger.info("Join a P2P group while associated to an AP")
    dev[0].request("SET p2p_no_group_iface 0")
    dev[1].p2p_start_go(freq=2412)
    pin = dev[0].wps_read_pin()
    dev[1].p2p_go_authorize_client(pin)
    dev[0].p2p_connect_group(dev[1].p2p_dev_addr(), pin, timeout=60,
                             social=True)
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])
    dev[1].remove_group()
    dev[0].wait_go_ending_session()

    logger.info("Confirm AP connection after P2P group removal")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_concurrent_grpform_go(dev, apdev):
    """Concurrent P2P group formation to become GO"""
    logger.info("Connect to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

    logger.info("Form a P2P group while associated to an AP")
    dev[0].request("SET p2p_no_group_iface 0")

    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])

    logger.info("Confirm AP connection after P2P group removal")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_concurrent_grpform_cli(dev, apdev):
    """Concurrent P2P group formation to become P2P Client"""
    logger.info("Connect to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

    logger.info("Form a P2P group while associated to an AP")
    dev[0].request("SET p2p_no_group_iface 0")

    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=15)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])

    logger.info("Confirm AP connection after P2P group removal")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_concurrent_grpform_while_connecting(dev, apdev):
    """Concurrent P2P group formation while connecting to an AP"""
    logger.info("Start connection to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE", wait_connect=False)

    logger.info("Form a P2P group while connecting to an AP")
    dev[0].request("SET p2p_no_group_iface 0")

    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_freq=2412,
                                           r_dev=dev[1], r_freq=2412)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])

    logger.info("Confirm AP connection after P2P group removal")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_concurrent_grpform_while_connecting2(dev, apdev):
    """Concurrent P2P group formation while connecting to an AP (2)"""
    logger.info("Start connection to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE", wait_connect=False)

    logger.info("Form a P2P group while connecting to an AP")
    dev[0].request("SET p2p_no_group_iface 0")

    [i_res, r_res] = go_neg_pbc(i_dev=dev[0], i_intent=15, i_freq=2412,
                                r_dev=dev[1], r_intent=0, r_freq=2412)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])

    logger.info("Confirm AP connection after P2P group removal")
    dev[0].wait_completed()
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_concurrent_grpform_while_connecting3(dev, apdev):
    """Concurrent P2P group formation while connecting to an AP (3)"""
    logger.info("Start connection to an infrastructure AP")
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-open" })
    dev[0].connect("test-open", key_mgmt="NONE", wait_connect=False)

    logger.info("Form a P2P group while connecting to an AP")
    dev[0].request("SET p2p_no_group_iface 0")

    [i_res, r_res] = go_neg_pbc(i_dev=dev[1], i_intent=15, i_freq=2412,
                                r_dev=dev[0], r_intent=0, r_freq=2412)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])

    logger.info("Confirm AP connection after P2P group removal")
    dev[0].wait_completed()
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])
