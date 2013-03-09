#!/usr/bin/python
#
# P2P autonomous GO test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger(__name__)

import hwsim_utils

def autogo(go, client):
    logger.info("Start autonomous GO " + go.ifname)
    res = go.p2p_start_go()
    logger.debug("res: " + str(res))

    logger.info("Try to connect the client to the GO")
    pin = client.wps_read_pin()
    go.p2p_go_authorize_client(pin)
    client.p2p_connect_group(go.p2p_dev_addr(), pin, timeout=60)
    logger.info("Group formed")
    hwsim_utils.test_connectivity_p2p(go, client)

def test_autogo(dev):
    autogo(go=dev[0], client=dev[1])
    dev[0].remove_group()
    try:
        dev[1].remove_group()
    except:
        pass

def add_tests(tests):
    tests.append(test_autogo)
