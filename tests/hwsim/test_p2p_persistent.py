#!/usr/bin/python
#
# P2P persistent group test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger(__name__)

import hwsim_utils

def go_neg_pin_authorized_persistent(i_dev, r_dev, i_intent=None, r_intent=None, i_method='enter', r_method='display'):
    r_dev.p2p_listen()
    i_dev.p2p_listen()
    pin = r_dev.wps_read_pin()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.p2p_go_neg_auth(i_dev.p2p_dev_addr(), pin, r_method,
                          go_intent=r_intent, persistent=True)
    i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), pin, i_method,
                                  timeout=20, go_intent=i_intent,
                                  persistent=True)
    r_res = r_dev.p2p_go_neg_auth_result()
    logger.debug("i_res: " + str(i_res))
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    i_dev.dump_monitor()
    logger.info("Group formed")
    hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    return [i_res, r_res]

def test_persistent_group(dev):
    """P2P persistent group formation and re-invocation"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    logger.info("Form a persistent group")
    [i_res, r_res] = go_neg_pin_authorized_persistent(i_dev=dev[0], i_intent=15,
                                                      r_dev=dev[1], r_intent=0)
    if not i_res['persistent'] or not r_res['persistent']:
        raise Exception("Formed group was not persistent")

    logger.info("Terminate persistent group")
    dev[0].remove_group()
    ev = dev[1].wait_event(["P2P-GROUP-REMOVED"], timeout=3)
    if ev is None:
        raise Exception("Group removal event timed out")
    if "reason=GO_ENDING_SESSION" not in ev:
        raise Exception("Unexpected group removal reason")

    logger.info("Re-invoke persistent group from client")
    dev[0].request("SET persistent_reconnect 1")
    dev[0].p2p_listen()
    if not dev[1].discover_peer(addr0, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[1].dump_monitor()
    peer = dev[1].get_peer(addr0)
    dev[1].global_request("P2P_INVITE persistent=" + peer['persistent'] + " peer=" + addr0)
    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group re-invocation (on GO)")
    go_res = dev[0].group_form_result(ev)
    if go_res['role'] != 'GO':
        raise Exception("Persistent group GO did not become GO")
    if not go_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (GO)")
    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group re-invocation (on client)")
    cli_res = dev[1].group_form_result(ev)
    if cli_res['role'] != 'client':
        raise Exception("Persistent group client did not become client")
    if not cli_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (cli)")
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])

    logger.info("Terminate persistent group")
    dev[0].remove_group()
    ev = dev[1].wait_event(["P2P-GROUP-REMOVED"], timeout=3)
    if ev is None:
        raise Exception("Group removal event timed out")
    if "reason=GO_ENDING_SESSION" not in ev:
        raise Exception("Unexpected group removal reason")

    logger.info("Re-invoke persistent group from GO")
    dev[1].request("SET persistent_reconnect 1")
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[0].dump_monitor()
    peer = dev[0].get_peer(addr1)
    dev[0].global_request("P2P_INVITE persistent=" + peer['persistent'] + " peer=" + addr1)
    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group re-invocation (on GO)")
    go_res = dev[0].group_form_result(ev)
    if go_res['role'] != 'GO':
        raise Exception("Persistent group GO did not become GO")
    if not go_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (GO)")
    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group re-invocation (on client)")
    cli_res = dev[1].group_form_result(ev)
    if cli_res['role'] != 'client':
        raise Exception("Persistent group client did not become client")
    if not cli_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (cli)")
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])

    logger.info("Terminate persistent group")
    dev[0].remove_group()
    ev = dev[1].wait_event(["P2P-GROUP-REMOVED"], timeout=3)
    if ev is None:
        raise Exception("Group removal event timed out")
    if "reason=GO_ENDING_SESSION" not in ev:
        raise Exception("Unexpected group removal reason")

def test_persistent_group_per_sta_psk(dev):
    """P2P persistent group formation and re-invocation using per-client PSK"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()
    dev[0].request("P2P_SET per_sta_psk 1")
    logger.info("Form a persistent group")
    [i_res, r_res] = go_neg_pin_authorized_persistent(i_dev=dev[0], i_intent=15,
                                                      r_dev=dev[1], r_intent=0)
    if not i_res['persistent'] or not r_res['persistent']:
        raise Exception("Formed group was not persistent")

    logger.info("Join another client to the group")
    pin = dev[2].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    c_res = dev[2].p2p_connect_group(addr0, pin, timeout=60)
    if not c_res['persistent']:
        raise Exception("Joining client did not recognize persistent group")
    if r_res['psk'] == c_res['psk']:
        raise Exception("Same PSK assigned for both clients")
    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])

    logger.info("Leave persistent group and rejoin it")
    dev[2].remove_group()
    ev = dev[2].wait_event(["P2P-GROUP-REMOVED"], timeout=3)
    if ev is None:
        raise Exception("Group removal event timed out")
    if not dev[2].discover_peer(addr0, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[2].dump_monitor()
    peer = dev[2].get_peer(addr0)
    dev[2].global_request("P2P_GROUP_ADD persistent=" + peer['persistent'])
    ev = dev[2].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group restart (on client)")
    cli_res = dev[2].group_form_result(ev)
    if not cli_res['persistent']:
        raise Exception("Persistent group not restarted as persistent (cli)")
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])

    logger.info("Remove one of the clients from the group")
    dev[0].global_request("P2P_REMOVE_CLIENT " + addr2)
    ev = dev[2].wait_event(["P2P-GROUP-REMOVED"], timeout=3)
    if ev is None:
        raise Exception("Group removal event timed out")
    if "reason=GO_ENDING_SESSION" not in ev:
        raise Exception("Unexpected group removal reason")

    logger.info("Try to reconnect after having been removed from group")
    if not dev[2].discover_peer(addr0, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[2].dump_monitor()
    peer = dev[2].get_peer(addr0)
    dev[2].global_request("P2P_GROUP_ADD persistent=" + peer['persistent'])
    ev = dev[2].wait_global_event(["P2P-GROUP-STARTED","WPA: 4-Way Handshake failed"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group restart (on client)")
    if "P2P-GROUP-STARTED" in ev:
        raise Exception("Client managed to connect after being removed")

    logger.info("Remove the remaining client from the group")
    dev[0].global_request("P2P_REMOVE_CLIENT " + addr1)
    ev = dev[1].wait_event(["P2P-GROUP-REMOVED"], timeout=3)
    if ev is None:
        raise Exception("Group removal event timed out")
    if "reason=GO_ENDING_SESSION" not in ev:
        raise Exception("Unexpected group removal reason")

    logger.info("Terminate persistent group")
    dev[0].remove_group()
    dev[0].dump_monitor()

    logger.info("Try to re-invoke persistent group from client")
    dev[0].request("SET persistent_reconnect 1")
    dev[0].p2p_listen()
    if not dev[1].discover_peer(addr0, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[1].dump_monitor()
    peer = dev[1].get_peer(addr0)
    dev[1].global_request("P2P_INVITE persistent=" + peer['persistent'] + " peer=" + addr0)
    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED","WPA: 4-Way Handshake failed"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group restart (on client)")
    if "P2P-GROUP-STARTED" in ev:
        raise Exception("Client managed to re-invoke after being removed")
    dev[0].dump_monitor()

    logger.info("Terminate persistent group")
    dev[0].remove_group()
    dev[0].dump_monitor()
