#!/usr/bin/python
#
# P2P autonomous GO test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger(__name__)

import hwsim_utils

def autogo(go):
    logger.info("Start autonomous GO " + go.ifname)
    res = go.p2p_start_go()
    logger.debug("res: " + str(res))

def connect_cli(go, client):
    logger.info("Try to connect the client to the GO")
    pin = client.wps_read_pin()
    go.p2p_go_authorize_client(pin)
    client.p2p_connect_group(go.p2p_dev_addr(), pin, timeout=60)
    logger.info("Client connected")
    hwsim_utils.test_connectivity_p2p(go, client)

def test_autogo(dev):
    autogo(dev[0])
    connect_cli(dev[0], dev[1])
    dev[0].remove_group()
    try:
        dev[1].remove_group()
    except:
        pass

def test_autogo_2cli(dev):
    autogo(dev[0])
    connect_cli(dev[0], dev[1])
    connect_cli(dev[0], dev[2])
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    dev[2].remove_group()
    dev[1].remove_group()
    dev[0].remove_group()

def test_autogo_tdls(dev):
    autogo(dev[0])
    connect_cli(dev[0], dev[1])
    connect_cli(dev[0], dev[2])
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    addr2 = dev[2].p2p_interface_addr()
    dev[1].tdls_setup(addr2)
    time.sleep(1)
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    dev[1].tdls_teardown(addr2)
    time.sleep(1)
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    dev[2].remove_group()
    dev[1].remove_group()
    dev[0].remove_group()

def add_tests(tests):
    tests.append(test_autogo)
    tests.append(test_autogo_2cli)
    tests.append(test_autogo_tdls)
