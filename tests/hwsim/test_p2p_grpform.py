#!/usr/bin/python
#
# P2P group formation test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger(__name__)

import hwsim_utils

def go_neg_pin_authorized(i_dev, r_dev, i_intent=None, r_intent=None, expect_failure=False):
    r_dev.p2p_listen()
    i_dev.p2p_listen()
    pin = r_dev.wps_read_pin()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.p2p_go_neg_auth(i_dev.p2p_dev_addr(), pin, "display", go_intent=r_intent)
    i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), pin, "enter", timeout=15, go_intent=i_intent, expect_failure=expect_failure)
    r_res = r_dev.p2p_go_neg_auth_result(expect_failure=expect_failure)
    logger.debug("i_res: " + str(i_res))
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    i_dev.dump_monitor()
    if expect_failure:
        return
    logger.info("Group formed")
    hwsim_utils.test_connectivity_p2p(r_dev, i_dev)

def test_grpform(dev):
    go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    dev[0].remove_group()
    try:
        dev[1].remove_group()
    except:
        pass

def test_grpform2(dev):
    go_neg_pin_authorized(i_dev=dev[0], i_intent=0, r_dev=dev[1], r_intent=15)
    dev[0].remove_group()
    try:
        dev[1].remove_group()
    except:
        pass

def test_both_go_intent_15(dev):
    go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=15, expect_failure=True)

def add_tests(tests):
    tests.append(test_grpform)
    tests.append(test_grpform2)
    tests.append(test_both_go_intent_15)
