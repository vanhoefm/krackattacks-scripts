# P2P persistent group test cases
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import re
import time

import hwsim_utils
from test_p2p_autogo import connect_cli

def go_neg_pin_authorized_persistent(i_dev, r_dev, i_intent=None, r_intent=None, i_method='enter', r_method='display', test_data=True):
    r_dev.p2p_listen()
    i_dev.p2p_listen()
    pin = r_dev.wps_read_pin()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.p2p_go_neg_auth(i_dev.p2p_dev_addr(), pin, r_method,
                          go_intent=r_intent, persistent=True)
    r_dev.p2p_listen()
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

def invite(inv, resp, extra=None, persistent_reconnect=True):
    addr = resp.p2p_dev_addr()
    if persistent_reconnect:
        resp.request("SET persistent_reconnect 1")
    else:
        resp.request("SET persistent_reconnect 0")
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
    if "[PERSISTENT]" not in ev:
        raise Exception("Re-invoked group not marked persistent")
    go_res = go.group_form_result(ev)
    if go_res['role'] != 'GO':
        raise Exception("Persistent group GO did not become GO")
    if not go_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (GO)")
    ev = cli.wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group re-invocation (on client)")
    if "[PERSISTENT]" not in ev:
        raise Exception("Re-invoked group not marked persistent")
    cli_res = cli.group_form_result(ev)
    if cli_res['role'] != 'client':
        raise Exception("Persistent group client did not become client")
    if not cli_res['persistent']:
        raise Exception("Persistent group not re-invoked as persistent (cli)")
    return [go_res, cli_res]

def form(go, cli, test_data=True, reverse_init=False):
    logger.info("Form a persistent group")
    if reverse_init:
        [i_res, r_res] = go_neg_pin_authorized_persistent(i_dev=cli, i_intent=0,
                                                          r_dev=go, r_intent=15,
                                                          test_data=test_data)
    else:
        [i_res, r_res] = go_neg_pin_authorized_persistent(i_dev=go, i_intent=15,
                                                          r_dev=cli, r_intent=0,
                                                          test_data=test_data)
    if not i_res['persistent'] or not r_res['persistent']:
        raise Exception("Formed group was not persistent")
    terminate_group(go, cli)
    if reverse_init:
        return r_res
    else:
        return i_res

def invite_from_cli(go, cli):
    logger.info("Re-invoke persistent group from client")
    invite(cli, go)
    [go_res, cli_res] = check_result(go, cli)
    hwsim_utils.test_connectivity_p2p(go, cli)
    terminate_group(go, cli)
    return [go_res, cli_res]

def invite_from_go(go, cli):
    logger.info("Re-invoke persistent group from GO")
    invite(go, cli)
    [go_res, cli_res] = check_result(go, cli)
    hwsim_utils.test_connectivity_p2p(go, cli)
    terminate_group(go, cli)
    return [go_res, cli_res]

def test_persistent_group(dev):
    """P2P persistent group formation and re-invocation"""
    form(dev[0], dev[1])
    invite_from_cli(dev[0], dev[1])
    invite_from_go(dev[0], dev[1])

    logger.info("Remove group on the client and try to invite from GO")
    id = None
    for n in dev[0].list_networks():
        if "[P2P-PERSISTENT]" in n['flags']:
            id = n['id']
            break
    if id is None:
        raise Exception("Could not find persistent group entry")
    clients = dev[0].request("GET_NETWORK " + id + " p2p_client_list").rstrip()
    if dev[1].p2p_dev_addr() not in clients:
        raise Exception("Peer missing from client list")
    if "FAIL" not in dev[1].request("SELECT_NETWORK " + str(id)):
        raise Exception("SELECT_NETWORK succeeded unexpectedly")
    if "FAIL" not in dev[1].request("SELECT_NETWORK 1234567"):
        raise Exception("SELECT_NETWORK succeeded unexpectedly(2)")
    if "FAIL" not in dev[1].request("ENABLE_NETWORK " + str(id)):
        raise Exception("ENABLE_NETWORK succeeded unexpectedly")
    if "FAIL" not in dev[1].request("ENABLE_NETWORK 1234567"):
        raise Exception("ENABLE_NETWORK succeeded unexpectedly(2)")
    if "FAIL" not in dev[1].request("DISABLE_NETWORK " + str(id)):
        raise Exception("DISABLE_NETWORK succeeded unexpectedly")
    if "FAIL" not in dev[1].request("DISABLE_NETWORK 1234567"):
        raise Exception("DISABLE_NETWORK succeeded unexpectedly(2)")
    if "FAIL" not in dev[1].request("REMOVE_NETWORK 1234567"):
        raise Exception("REMOVE_NETWORK succeeded unexpectedly")
    dev[1].request("REMOVE_NETWORK all")
    if len(dev[1].list_networks()) > 0:
        raise Exception("Unexpected network block remaining")
    invite(dev[0], dev[1])
    ev = dev[0].wait_global_event(["P2P-INVITATION-RESULT"], timeout=10)
    if ev is None:
        raise Exception("No invitation result seen")
    if "status=8" not in ev:
        raise Exception("Unexpected invitation result: " + ev)
    clients = dev[0].request("GET_NETWORK " + id + " p2p_client_list").rstrip()
    if dev[1].p2p_dev_addr() in clients:
        raise Exception("Peer was still in client list")

def test_persistent_group2(dev):
    """P2P persistent group formation with reverse roles"""
    form(dev[0], dev[1], reverse_init=True)
    invite_from_cli(dev[0], dev[1])
    invite_from_go(dev[0], dev[1])

def test_persistent_group3(dev):
    """P2P persistent group formation and re-invocation with empty BSS table"""
    form(dev[0], dev[1])
    dev[1].request("BSS_FLUSH 0")
    invite_from_cli(dev[0], dev[1])
    dev[1].request("BSS_FLUSH 0")
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
    c_res = dev[2].p2p_connect_group(addr0, pin, timeout=60, social=True,
                                     freq=i_res['freq'])
    if not c_res['persistent']:
        raise Exception("Joining client did not recognize persistent group")
    if r_res['psk'] == c_res['psk']:
        raise Exception("Same PSK assigned for both clients")
    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])

    logger.info("Remove persistent group and re-start it manually")
    dev[0].remove_group()
    dev[1].wait_go_ending_session()
    dev[2].wait_go_ending_session()
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    dev[2].dump_monitor()

    for i in range(0, 3):
        networks = dev[i].list_networks()
        if len(networks) != 1:
            raise Exception("Unexpected number of networks")
        if "[P2P-PERSISTENT]" not in networks[0]['flags']:
            raise Exception("Not the persistent group data")
        if i > 0:
            # speed up testing by avoiding use of the old BSS entry since the
            # GO may have changed channels
            dev[i].request("BSS_FLUSH 0")
            dev[i].scan(freq="2412", only_new=True)
        if "OK" not in dev[i].global_request("P2P_GROUP_ADD persistent=" + networks[0]['id'] + " freq=2412"):
            raise Exception("Could not re-start persistent group")
        ev = dev[i].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
        if ev is None:
            raise Exception("Timeout on group restart")

    logger.info("Leave persistent group and rejoin it")
    dev[2].remove_group()
    ev = dev[2].wait_event(["P2P-GROUP-REMOVED"], timeout=3)
    if ev is None:
        raise Exception("Group removal event timed out")
    if not dev[2].discover_peer(addr0, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[2].dump_monitor()
    peer = dev[2].get_peer(addr0)
    dev[2].global_request("P2P_GROUP_ADD persistent=" + peer['persistent'] + " freq=2412")
    ev = dev[2].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group restart (on client)")
    cli_res = dev[2].group_form_result(ev)
    if not cli_res['persistent']:
        raise Exception("Persistent group not restarted as persistent (cli)")
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])

    logger.info("Remove one of the clients from the group without removing persistent group information for the client")
    dev[0].global_request("P2P_REMOVE_CLIENT iface=" + dev[2].p2p_interface_addr())
    dev[2].wait_go_ending_session()

    logger.info("Try to reconnect after having been removed from group (but persistent group info still present)")
    if not dev[2].discover_peer(addr0, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[2].dump_monitor()
    peer = dev[2].get_peer(addr0)
    dev[2].global_request("P2P_GROUP_ADD persistent=" + peer['persistent'] + " freq=2412")
    ev = dev[2].wait_global_event(["P2P-GROUP-STARTED","WPA: 4-Way Handshake failed"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group restart (on client)")
    if "P2P-GROUP-STARTED" not in ev:
        raise Exception("Connection failed")

    logger.info("Remove one of the clients from the group")
    dev[0].global_request("P2P_REMOVE_CLIENT " + addr2)
    dev[2].wait_go_ending_session()

    logger.info("Try to reconnect after having been removed from group")
    if not dev[2].discover_peer(addr0, social=True):
        raise Exception("Peer " + peer + " not found")
    dev[2].dump_monitor()
    peer = dev[2].get_peer(addr0)
    dev[2].global_request("P2P_GROUP_ADD persistent=" + peer['persistent'] + " freq=2412")
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
    c_res = dev[1].p2p_connect_group(addr0, pin, timeout=60, social=True,
                                     freq=i_res['freq'])
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

def test_persistent_group_and_role_change(dev):
    """P2P persistent group, auto GO in another role, and re-invocation"""
    form(dev[0], dev[1])

    logger.info("Start and stop autonomous GO on previous P2P client device")
    dev[1].p2p_start_go()
    dev[1].remove_group()
    dev[1].dump_monitor()

    logger.info("Re-invoke the persistent group")
    invite_from_go(dev[0], dev[1])

def test_persistent_go_client_list(dev):
    """P2P GO and list of clients in persistent group"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()

    res = dev[0].p2p_start_go(persistent=True)
    id = None
    for n in dev[0].list_networks():
        if "[P2P-PERSISTENT]" in n['flags']:
            id = n['id']
            break
    if id is None:
        raise Exception("Could not find persistent group entry")

    connect_cli(dev[0], dev[1], social=True, freq=res['freq'])
    clients = dev[0].request("GET_NETWORK " + id + " p2p_client_list").rstrip()
    if clients != addr1:
        raise Exception("Unexpected p2p_client_list entry(2): " + clients)
    connect_cli(dev[0], dev[2], social=True, freq=res['freq'])
    clients = dev[0].request("GET_NETWORK " + id + " p2p_client_list").rstrip()
    if clients != addr2 + " " + addr1:
        raise Exception("Unexpected p2p_client_list entry(3): " + clients)

    peer = dev[1].get_peer(res['go_dev_addr'])
    dev[1].remove_group()
    dev[1].request("P2P_GROUP_ADD persistent=" + peer['persistent'])
    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Timeout on group restart (on client)")
    clients = dev[0].request("GET_NETWORK " + id + " p2p_client_list").rstrip()
    if clients != addr1 + " " + addr2:
        raise Exception("Unexpected p2p_client_list entry(4): " + clients)

    dev[2].remove_group()
    dev[1].remove_group()
    dev[0].remove_group()

    clients = dev[0].request("GET_NETWORK " + id + " p2p_client_list").rstrip()
    if clients != addr1 + " " + addr2:
        raise Exception("Unexpected p2p_client_list entry(5): " + clients)

    dev[1].p2p_listen()
    dev[2].p2p_listen()
    dev[0].request("P2P_FLUSH")
    dev[0].discover_peer(addr1, social=True)
    peer = dev[0].get_peer(addr1)
    if 'persistent' not in peer or peer['persistent'] != id:
        raise Exception("Persistent group client not recognized(1)")

    dev[0].discover_peer(addr2, social=True)
    peer = dev[0].get_peer(addr2)
    if 'persistent' not in peer or peer['persistent'] != id:
        raise Exception("Persistent group client not recognized(2)")

def test_persistent_group_in_grpform(dev):
    """P2P persistent group parameters re-used in group formation"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    form(dev[0], dev[1])
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1, social=True):
        raise Exception("Could not discover peer")
    peer = dev[0].get_peer(addr1)
    if "persistent" not in peer:
        raise Exception("Could not map peer to a persistent group")

    pin = dev[1].wps_read_pin()
    dev[1].p2p_go_neg_auth(addr0, pin, "display", go_intent=0)
    i_res = dev[0].p2p_go_neg_init(addr1, pin, "enter", timeout=20,
                                   go_intent=15,
                                   persistent_id=peer['persistent'])
    r_res = dev[1].p2p_go_neg_auth_result()
    logger.debug("i_res: " + str(i_res))
    logger.debug("r_res: " + str(r_res))

def test_persistent_group_without_persistent_reconnect(dev):
    """P2P persistent group re-invocation without persistent reconnect"""
    form(dev[0], dev[1])
    dev[0].dump_monitor()
    dev[1].dump_monitor()

    logger.info("Re-invoke persistent group from client")
    invite(dev[1], dev[0], persistent_reconnect=False)

    ev = dev[0].wait_global_event(["P2P-INVITATION-RECEIVED"], timeout=15)
    if ev is None:
        raise Exception("No invitation request reported");
    if "persistent=" not in ev:
        raise Exception("Invalid invitation type reported: " + ev)

    ev2 = dev[1].wait_global_event(["P2P-INVITATION-RESULT"], timeout=15)
    if ev2 is None:
        raise Exception("No invitation response reported");
    if "status=1" not in ev2:
        raise Exception("Unexpected status: " + ev2)
    dev[1].p2p_listen()

    exp = r'<.>(P2P-INVITATION-RECEIVED) sa=([0-9a-f:]*) persistent=([0-9]*) freq=([0-9]*)'
    s = re.split(exp, ev)
    if len(s) < 5:
        raise Exception("Could not parse invitation event")
    sa = s[2]
    id = s[3]
    freq = s[4]
    logger.info("Invalid P2P_INVITE test coverage")
    if "FAIL" not in dev[0].global_request("P2P_INVITE persistent=" + id + " peer=" + sa + " freq=0"):
        raise Exception("Invalid P2P_INVITE accepted")
    if "FAIL" not in dev[0].global_request("P2P_INVITE persistent=" + id + " peer=" + sa + " pref=0"):
        raise Exception("Invalid P2P_INVITE accepted")
    logger.info("Re-initiate invitation based on upper layer acceptance")
    if "OK" not in dev[0].global_request("P2P_INVITE persistent=" + id + " peer=" + sa + " freq=" + freq):
        raise Exception("Invitation command failed")
    [go_res, cli_res] = check_result(dev[0], dev[1])
    if go_res['freq'] != freq:
        raise Exception("Unexpected channel on GO: {} MHz, expected {} MHz".format(go_res['freq'], freq))
    if cli_res['freq'] != freq:
        raise Exception("Unexpected channel on CLI: {} MHz, expected {} MHz".format(cli_res['freq'], freq))
    terminate_group(dev[0], dev[1])
    dev[0].dump_monitor()
    dev[1].dump_monitor()

    logger.info("Re-invoke persistent group from GO")
    invite(dev[0], dev[1], persistent_reconnect=False)

    ev = dev[1].wait_global_event(["P2P-INVITATION-RECEIVED"], timeout=15)
    if ev is None:
        raise Exception("No invitation request reported");
    if "persistent=" not in ev:
        raise Exception("Invalid invitation type reported: " + ev)

    ev2 = dev[0].wait_global_event(["P2P-INVITATION-RESULT"], timeout=15)
    if ev2 is None:
        raise Exception("No invitation response reported");
    if "status=1" not in ev2:
        raise Exception("Unexpected status: " + ev2)
    dev[0].p2p_listen()

    exp = r'<.>(P2P-INVITATION-RECEIVED) sa=([0-9a-f:]*) persistent=([0-9]*)'
    s = re.split(exp, ev)
    if len(s) < 4:
        raise Exception("Could not parse invitation event")
    sa = s[2]
    id = s[3]
    logger.info("Re-initiate invitation based on upper layer acceptance")
    if "OK" not in dev[1].global_request("P2P_INVITE persistent=" + id + " peer=" + sa + " freq=" + freq):
        raise Exception("Invitation command failed")
    [go_res, cli_res] = check_result(dev[0], dev[1])
    terminate_group(dev[0], dev[1])

def test_persistent_group_already_running(dev):
    """P2P persistent group formation and invitation while GO already running"""
    form(dev[0], dev[1])
    peer = dev[1].get_peer(dev[0].p2p_dev_addr())
    listen_freq = peer['listen_freq']
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    networks = dev[0].list_networks()
    if len(networks) != 1:
        raise Exception("Unexpected number of networks")
    if "[P2P-PERSISTENT]" not in networks[0]['flags']:
        raise Exception("Not the persistent group data")
    if "OK" not in dev[0].global_request("P2P_GROUP_ADD persistent=" + networks[0]['id'] + " freq=" + listen_freq):
        raise Exception("Could not state GO")
    invite_from_cli(dev[0], dev[1])

def test_persistent_group_add_cli_chan(dev):
    """P2P persistent group formation and re-invocation with p2p_add_cli_chan=1"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    form(dev[0], dev[1])
    dev[1].request("BSS_FLUSH 0")
    dev[1].scan(freq="2412", only_new=True)
    dev[1].scan(freq="2437", only_new=True)
    dev[1].scan(freq="2462", only_new=True)
    dev[1].request("BSS_FLUSH 0")
    invite_from_cli(dev[0], dev[1])
    invite_from_go(dev[0], dev[1])

def test_persistent_invalid_group_add(dev):
    """Invalid P2P_GROUP_ADD command"""
    id = dev[0].add_network()
    if "FAIL" not in dev[0].global_request("P2P_GROUP_ADD persistent=12345"):
        raise Exception("Invalid P2P_GROUP_ADD accepted")
    if "FAIL" not in dev[0].global_request("P2P_GROUP_ADD persistent=%d" % id):
        raise Exception("Invalid P2P_GROUP_ADD accepted")
    if "FAIL" not in dev[0].global_request("P2P_GROUP_ADD foo"):
        raise Exception("Invalid P2P_GROUP_ADD accepted")
