#!/usr/bin/python
#
# P2P device discovery test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger(__name__)

def test_discovery(dev):
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    logger.info("Start device discovery")
    dev[0].p2p_find()
    dev[1].p2p_find()
    ev0 = dev[0].wait_event(["P2P-DEVICE-FOUND"], timeout=15)
    if ev0 is None:
        raise Exception("Device discovery timed out")
    ev1 = dev[1].wait_event(["P2P-DEVICE-FOUND"], timeout=15)
    if ev1 is None:
        raise Exception("Device discovery timed out")
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    if addr1 not in ev0:
        raise Exception("Dev1 not found properly")
    if addr0 not in ev1:
        raise Exception("Dev0 not found properly")

    logger.info("Test provision discovery for display")
    dev[0].request("P2P_PROV_DISC " + addr1 + " display")
    ev1 = dev[1].wait_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=15)
    if ev1 is None:
        raise Exception("Provision discovery timed out")
    if addr0 not in ev1:
        raise Exception("Dev0 not in provision discovery event")
    ev0 = dev[0].wait_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=15)
    if ev0 is None:
        raise Exception("Provision discovery timed out")
    if addr1 not in ev0:
        raise Exception("Dev1 not in provision discovery event")

    logger.info("Test provision discovery for keypad")
    dev[0].request("P2P_PROV_DISC " + addr1 + " keypad")
    ev1 = dev[1].wait_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=15)
    if ev1 is None:
        raise Exception("Provision discovery timed out")
    if addr0 not in ev1:
        raise Exception("Dev0 not in provision discovery event")
    ev0 = dev[0].wait_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=15)
    if ev0 is None:
        raise Exception("Provision discovery timed out")
    if addr1 not in ev0:
        raise Exception("Dev1 not in provision discovery event")

    logger.info("Test provision discovery for push button")
    dev[0].request("P2P_PROV_DISC " + addr1 + " pbc")
    ev1 = dev[1].wait_event(["P2P-PROV-DISC-PBC-REQ"], timeout=15)
    if ev1 is None:
        raise Exception("Provision discovery timed out")
    if addr0 not in ev1:
        raise Exception("Dev0 not in provision discovery event")
    ev0 = dev[0].wait_event(["P2P-PROV-DISC-PBC-RESP"], timeout=15)
    if ev0 is None:
        raise Exception("Provision discovery timed out")
    if addr1 not in ev0:
        raise Exception("Dev1 not in provision discovery event")

    dev[0].p2p_stop_find
    dev[1].p2p_stop_find


def add_tests(tests):
    tests.append(test_discovery)
