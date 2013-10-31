#!/usr/bin/python
#
# P2P persistent group test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hwsim_utils

def go_neg_pin_authorized_persistent(i_dev, r_dev, i_intent=None, r_intent=None, i_method='enter', r_method='display', test_data=True):
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
    if test_data:
        hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    return [i_res, r_res]

def terminate_group(go, cli):
    logger.info("Terminate persistent group")
    go.remove_group()
    cli.wait_go_ending_session()

def invite(inv, resp, extra=None):
    addr = resp.p2p_dev_addr()
    resp.request("SET persistent_reconnect 1")
    resp.p2p_listen()
    if not inv.discover_peer(addr, social=True):
        raise Exception("Peer " + addr + " not found")
    inv.dump_monitor()
    peer = inv.get_peer(addr)
    cmd = "P2P_INVITE persistent=" + peer['persistent'] + " peer=" + addr
    if extra:
        cmd = cmd + " " + extra;
    inv.global_request(cmd)

def check_result(go, cli):
    ev = go.wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group re-invocation (on GO)")
    go_res = go.group_form_result(ev)
    if go_res['role'] != 'GO':
        raise Exception("Persistent group GO did not become GO")
    if not go_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (GO)")
    ev = cli.wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group re-invocation (on client)")
    cli_res = cli.group_form_result(ev)
    if cli_res['role'] != 'client':
        raise Exception("Persistent group client did not become client")
    if not cli_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (cli)")
    return [go_res, cli_res]

def form(go, cli, test_data=True):
    logger.info("Form a persistent group")
    [i_res, r_res] = go_neg_pin_authorized_persistent(i_dev=go, i_intent=15,
                                                      r_dev=cli, r_intent=0,
                                                      test_data=test_data)
    if not i_res['persistent'] or not r_res['persistent']:
        raise Exception("Formed group was not persistent")
    terminate_group(go, cli)

def invite_from_cli(go, cli):
    logger.info("Re-invoke persistent group from client")
    invite(cli, go)
    check_result(go, cli)
    hwsim_utils.test_connectivity_p2p(go, cli)
    terminate_group(go, cli)

def invite_from_go(go, cli):
    logger.info("Re-invoke persistent group from GO")
    invite(go, cli)
    check_result(go, cli)
    hwsim_utils.test_connectivity_p2p(go, cli)
    terminate_group(go, cli)

def test_persistent_group(dev):
    """P2P persistent group formation and re-invocation"""
    form(dev[0], dev[1])
    invite_from_cli(dev[0], dev[1])
    invite_from_go(dev[0], dev[1])

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
    dev[2].wait_go_ending_session()

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
    dev[1].wait_go_ending_session()

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

def test_persistent_group_invite_removed_client(dev):
    """P2P persistent group client removal and re-invitation"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[0].request("P2P_SET per_sta_psk 1")
    logger.info("Form a persistent group")
    [i_res, r_res] = go_neg_pin_authorized_persistent(i_dev=dev[0], i_intent=15,
                                                      r_dev=dev[1], r_intent=0)
    if not i_res['persistent'] or not r_res['persistent']:
        raise Exception("Formed group was not persistent")

    logger.info("Remove client from the group")
    dev[0].global_request("P2P_REMOVE_CLIENT " + addr1)
    dev[1].wait_go_ending_session()

    logger.info("Re-invite the removed client to join the group")
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[0].global_request("P2P_INVITE group=" + dev[0].group_ifname + " peer=" + addr1)
    ev = dev[1].wait_global_event(["P2P-INVITATION-RECEIVED"], timeout=10)
    if ev is None:
        raise Exception("Timeout on invitation")
    if "sa=" + addr0 + " persistent=" not in ev:
        raise Exception("Unexpected invitation event")
    [event,addr,persistent] = ev.split(' ', 2)
    dev[1].global_request("P2P_GROUP_ADD " + persistent)
    ev = dev[1].wait_global_event(["P2P-PERSISTENT-PSK-FAIL"], timeout=30)
    if ev is None:
        raise Exception("Did not receive PSK failure report")
    [tmp,id] = ev.split('=', 1)
    ev = dev[1].wait_global_event(["P2P-GROUP-REMOVED"], timeout=10)
    if ev is None:
        raise Exception("Group removal event timed out")
    if "reason=PSK_FAILURE" not in ev:
        raise Exception("Unexpected group removal reason")
    dev[1].request("REMOVE_NETWORK " + id)

    logger.info("Re-invite after client removed persistent group info")
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[0].global_request("P2P_INVITE group=" + dev[0].group_ifname + " peer=" + addr1)
    ev = dev[1].wait_global_event(["P2P-INVITATION-RECEIVED"], timeout=10)
    if ev is None:
        raise Exception("Timeout on invitation")
    if " persistent=" in ev:
        raise Exception("Unexpected invitation event")
    pin = dev[1].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    c_res = dev[1].p2p_connect_group(addr0, pin, timeout=60)
    if not c_res['persistent']:
        raise Exception("Joining client did not recognize persistent group")
    if r_res['psk'] == c_res['psk']:
        raise Exception("Same PSK assigned on both times")
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])

    terminate_group(dev[0], dev[1])

def test_persistent_group_channel(dev):
    """P2P persistent group re-invocation with channel selection"""
    form(dev[0], dev[1], test_data=False)

    logger.info("Re-invoke persistent group from client with forced channel")
    invite(dev[1], dev[0], "freq=2427")
    [go_res, cli_res] = check_result(dev[0], dev[1])
    if go_res['freq'] != "2427":
        raise Exception("Persistent group client forced channel not followed")
    terminate_group(dev[0], dev[1])

    logger.info("Re-invoke persistent group from GO with forced channel")
    invite(dev[0], dev[1], "freq=2432")
    [go_res, cli_res] = check_result(dev[0], dev[1])
    if go_res['freq'] != "2432":
        raise Exception("Persistent group GO channel preference not followed")
    terminate_group(dev[0], dev[1])

    logger.info("Re-invoke persistent group from client with channel preference")
    invite(dev[1], dev[0], "pref=2417")
    [go_res, cli_res] = check_result(dev[0], dev[1])
    if go_res['freq'] != "2417":
        raise Exception("Persistent group client channel preference not followed")
    terminate_group(dev[0], dev[1])
