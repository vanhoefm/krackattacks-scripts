#!/usr/bin/python
#
# P2P invitation test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hwsim_utils

def test_p2p_go_invite(dev):
    """P2P GO inviting a client to join"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()

    logger.info("Generate BSS table entry for old group")
    # this adds more coverage to testing by forcing the GO to be found with an
    # older entry in the BSS table and with that entry having a different
    # operating channel.
    dev[0].p2p_start_go(freq=2422)
    dev[1].scan()
    dev[0].remove_group()

    logger.info("Discover peer")
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1, social=True):
        raise Exception("Peer " + addr1 + " not found")

    logger.info("Start GO on non-social channel")
    res = dev[0].p2p_start_go(freq=2417)
    logger.debug("res: " + str(res))

    logger.info("Invite peer to join the group")
    dev[0].global_request("P2P_INVITE group=" + dev[0].group_ifname + " peer=" + addr1)
    ev = dev[1].wait_global_event(["P2P-INVITATION-RECEIVED"], timeout=10)
    if ev is None:
        raise Exception("Timeout on invitation on peer")
    ev = dev[0].wait_global_event(["P2P-INVITATION-RESULT"], timeout=10)
    if ev is None:
        raise Exception("Timeout on invitation on GO")
    if "status=1" not in ev:
        raise Exception("Unexpected invitation result")

    logger.info("Join the group")
    pin = dev[1].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    dev[1].p2p_connect_group(addr0, pin, timeout=60)
    logger.info("Client connected")
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])

    logger.info("Terminate group")
    dev[0].remove_group()
    dev[1].wait_go_ending_session()

def test_p2p_go_invite_auth(dev):
    """P2P GO inviting a client to join (authorized invitation)"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()

    logger.info("Generate BSS table entry for old group")
    # this adds more coverage to testing by forcing the GO to be found with an
    # older entry in the BSS table and with that entry having a different
    # operating channel.
    dev[0].p2p_start_go(freq=2432)
    dev[1].scan()
    dev[0].remove_group()
    dev[0].dump_monitor()
    dev[1].dump_monitor()

    logger.info("Discover peer")
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1, social=True):
        raise Exception("Peer " + addr1 + " not found")
    dev[0].p2p_listen()
    if not dev[1].discover_peer(addr0, social=True):
        raise Exception("Peer " + addr0 + " not found")
    dev[1].p2p_listen()

    logger.info("Authorize invitation")
    pin = dev[1].wps_read_pin()
    dev[1].global_request("P2P_CONNECT " + addr0 + " " + pin + " join auth")

    logger.info("Start GO on non-social channel")
    res = dev[0].p2p_start_go(freq=2427)
    logger.debug("res: " + str(res))

    logger.info("Invite peer to join the group")
    dev[0].p2p_go_authorize_client(pin)
    dev[0].global_request("P2P_INVITE group=" + dev[0].group_ifname + " peer=" + addr1)
    ev = dev[1].wait_global_event(["P2P-INVITATION-RECEIVED",
                                   "P2P-GROUP-STARTED"], timeout=20)
    if ev is None:
        raise Exception("Timeout on invitation on peer")
    if "P2P-INVITATION-RECEIVED" in ev:
        raise Exception("Unexpected request to accept pre-authorized invitaton")
    dev[0].dump_monitor()

    logger.info("Client connected")
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])

    logger.info("Terminate group")
    dev[0].remove_group()
    dev[1].wait_go_ending_session()
