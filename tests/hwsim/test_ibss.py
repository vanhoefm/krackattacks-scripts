#!/usr/bin/python
#
# IBSS test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger(__name__)
import time

import hwsim_utils

def connect_ibss_cmd(dev, id):
    dev.dump_monitor()
    dev.select_network(id)

def wait_ibss_connection(dev):
    logger.info(dev.ifname + " waiting for IBSS start/join to complete")
    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=20)
    if ev is None:
        raise Exception("Connection to the IBSS timed out")

def wait_4way_handshake(dev1, dev2):
    logger.info(dev1.ifname + " waiting for 4-way handshake completion with " + dev2.ifname + " " + dev2.p2p_interface_addr())
    ev = dev1.wait_event(["IBSS-RSN-COMPLETED " + dev2.p2p_interface_addr()],
                         timeout=20)
    if ev is None:
        raise Exception("4-way handshake in IBSS timed out")

def add_ibss(dev, ssid, psk=None, proto=None, key_mgmt=None, pairwise=None, group=None):
    id = dev.add_network()
    dev.set_network(id, "mode", "1")
    dev.set_network(id, "frequency", "2412")
    dev.set_network_quoted(id, "ssid", ssid)
    if psk:
        dev.set_network_quoted(id, "psk", psk)
    if proto:
        dev.set_network(id, "proto", proto)
    if key_mgmt:
        dev.set_network(id, "key_mgmt", key_mgmt)
    if pairwise:
        dev.set_network(id, "pairwise", pairwise)
    if group:
        dev.set_network(id, "group", group)
    return id

def add_ibss_rsn(dev, ssid):
    return add_ibss(dev, ssid, "12345678", "RSN", "WPA-PSK", "CCMP", "CCMP")

def test_ibss_rsn(dev):
    """IBSS RSN"""
    ssid="ibss-rsn"

    logger.info("Start IBSS on the first STA")
    id = add_ibss_rsn(dev[0], ssid)
    connect_ibss_cmd(dev[0], id)
    wait_ibss_connection(dev[0])

    logger.info("Join two STAs to the IBSS")

    id = add_ibss_rsn(dev[1], ssid)
    connect_ibss_cmd(dev[1], id)
    wait_ibss_connection(dev[1])
    wait_4way_handshake(dev[0], dev[1])
    wait_4way_handshake(dev[1], dev[0])

    id = add_ibss_rsn(dev[2], ssid)
    connect_ibss_cmd(dev[2], id)
    wait_ibss_connection(dev[2])
    wait_4way_handshake(dev[0], dev[2])
    wait_4way_handshake(dev[2], dev[0])

    # Allow some time for all peers to complete key setup
    time.sleep(3)
    hwsim_utils.test_connectivity(dev[0].ifname, dev[1].ifname)
    hwsim_utils.test_connectivity(dev[0].ifname, dev[2].ifname)
    time.sleep(2)
    hwsim_utils.test_connectivity(dev[1].ifname, dev[2].ifname)
