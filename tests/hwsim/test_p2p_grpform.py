#!/usr/bin/python
#
# P2P group formation test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time
import threading
import Queue

import hwsim_utils

def check_grpform_results(i_res, r_res):
    if i_res['result'] != 'success' or r_res['result'] != 'success':
        raise Exception("Failed group formation")
    if i_res['ssid'] != r_res['ssid']:
        raise Exception("SSID mismatch")
    if i_res['freq'] != r_res['freq']:
        raise Exception("freq mismatch")
    if 'go_neg_freq' in r_res and i_res['go_neg_freq'] != r_res['go_neg_freq']:
        raise Exception("go_neg_freq mismatch")
    if i_res['freq'] != i_res['go_neg_freq']:
        raise Exception("freq/go_neg_freq mismatch")
    if i_res['role'] != i_res['go_neg_role']:
        raise Exception("role/go_neg_role mismatch")
    if 'go_neg_role' in r_res and r_res['role'] != r_res['go_neg_role']:
        raise Exception("role/go_neg_role mismatch")
    if i_res['go_dev_addr'] != r_res['go_dev_addr']:
        raise Exception("GO Device Address mismatch")

def go_neg_init(i_dev, r_dev, pin, i_method, i_intent, res):
    logger.debug("Initiate GO Negotiation from i_dev")
    i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), pin, i_method, timeout=20, go_intent=i_intent)
    logger.debug("i_res: " + str(i_res))
    res.put(i_res)

def go_neg_pin(i_dev, r_dev, i_intent=None, r_intent=None, i_method='enter', r_method='display'):
    r_dev.p2p_listen()
    i_dev.p2p_listen()
    pin = r_dev.wps_read_pin()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.dump_monitor()
    res = Queue.Queue()
    t = threading.Thread(target=go_neg_init, args=(i_dev, r_dev, pin, i_method, i_intent, res))
    t.start()
    logger.debug("Wait for GO Negotiation Request on r_dev")
    ev = r_dev.wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation timed out")
    r_dev.dump_monitor()
    logger.debug("Re-initiate GO Negotiation from r_dev")
    r_res = r_dev.p2p_go_neg_init(i_dev.p2p_dev_addr(), pin, r_method, go_intent=r_intent, timeout=20)
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    t.join()
    i_res = res.get()
    logger.debug("i_res: " + str(i_res))
    logger.info("Group formed")
    hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    i_dev.dump_monitor()

def go_neg_pin_authorized(i_dev, r_dev, i_intent=None, r_intent=None, expect_failure=False, i_go_neg_status=None, i_method='enter', r_method='display', test_data=True, i_freq=None, r_freq=None):
    r_dev.p2p_listen()
    i_dev.p2p_listen()
    pin = r_dev.wps_read_pin()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.p2p_go_neg_auth(i_dev.p2p_dev_addr(), pin, r_method, go_intent=r_intent, freq=r_freq)
    i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), pin, i_method, timeout=20, go_intent=i_intent, expect_failure=expect_failure, freq=i_freq)
    r_res = r_dev.p2p_go_neg_auth_result(expect_failure=expect_failure)
    logger.debug("i_res: " + str(i_res))
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    i_dev.dump_monitor()
    if i_go_neg_status:
        if i_res['result'] != 'go-neg-failed':
            raise Exception("Expected GO Negotiation failure not reported")
        if i_res['status'] != i_go_neg_status:
            raise Exception("Expected GO Negotiation status not seen")
    if expect_failure:
        return
    logger.info("Group formed")
    if test_data:
        hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    return [i_res, r_res]

def go_neg_init_pbc(i_dev, r_dev, i_intent, res):
    logger.debug("Initiate GO Negotiation from i_dev")
    i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), None, "pbc", timeout=20, go_intent=i_intent)
    logger.debug("i_res: " + str(i_res))
    res.put(i_res)

def go_neg_pbc(i_dev, r_dev, i_intent=None, r_intent=None):
    r_dev.p2p_find(social=True)
    i_dev.p2p_find(social=True)
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.dump_monitor()
    res = Queue.Queue()
    t = threading.Thread(target=go_neg_init_pbc, args=(i_dev, r_dev, i_intent, res))
    t.start()
    logger.debug("Wait for GO Negotiation Request on r_dev")
    ev = r_dev.wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation timed out")
    r_dev.dump_monitor()
    logger.debug("Re-initiate GO Negotiation from r_dev")
    r_res = r_dev.p2p_go_neg_init(i_dev.p2p_dev_addr(), None, "pbc", go_intent=r_intent, timeout=20)
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    t.join()
    i_res = res.get()
    logger.debug("i_res: " + str(i_res))
    logger.info("Group formed")
    hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    i_dev.dump_monitor()
    return [i_res, r_res]

def remove_group(dev1, dev2):
    dev1.remove_group()
    try:
        dev2.remove_group()
    except:
        pass

def test_grpform(dev):
    """P2P group formation using PIN and authorized connection (init -> GO)"""
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])

def test_grpform2(dev):
    """P2P group formation using PIN and authorized connection (resp -> GO)"""
    go_neg_pin_authorized(i_dev=dev[0], i_intent=0, r_dev=dev[1], r_intent=15)
    remove_group(dev[0], dev[1])

def test_grpform3(dev):
    """P2P group formation using PIN and re-init GO Negotiation"""
    go_neg_pin(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    remove_group(dev[0], dev[1])

def test_grpform_pbc(dev):
    """P2P group formation using PBC and re-init GO Negotiation"""
    dev[0].request("SET ignore_old_scan_res 1")
    dev[1].request("SET ignore_old_scan_res 1")
    [i_res, r_res] = go_neg_pbc(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)
    if i_res['role'] != 'GO' or r_res['role'] != 'client':
        raise Exception("Unexpected device roles")
    remove_group(dev[0], dev[1])

def test_both_go_intent_15(dev):
    """P2P GO Negotiation with both devices using GO intent 15"""
    go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=15, expect_failure=True, i_go_neg_status=9)

def test_both_go_neg_display(dev):
    """P2P GO Negotiation with both devices trying to display PIN"""
    go_neg_pin_authorized(i_dev=dev[0], r_dev=dev[1], expect_failure=True, i_go_neg_status=10, i_method='display', r_method='display')

def test_both_go_neg_enter(dev):
    """P2P GO Negotiation with both devices trying to enter PIN"""
    go_neg_pin_authorized(i_dev=dev[0], r_dev=dev[1], expect_failure=True, i_go_neg_status=10, i_method='enter', r_method='enter')

def test_grpform_per_sta_psk(dev):
    """P2P group formation with per-STA PSKs"""
    dev[0].request("P2P_SET per_sta_psk 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)

    pin = dev[2].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    c_res = dev[2].p2p_connect_group(dev[0].p2p_dev_addr(), pin, timeout=60)
    check_grpform_results(i_res, c_res)

    if r_res['psk'] == c_res['psk']:
        raise Exception("Same PSK assigned for both clients")

    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])

    dev[0].remove_group()
    dev[1].wait_go_ending_session()
    dev[2].wait_go_ending_session()

def test_grpform_per_sta_psk_wps(dev):
    """P2P group formation with per-STA PSKs with non-P2P WPS STA"""
    dev[0].request("P2P_SET per_sta_psk 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)

    dev[0].p2p_go_authorize_client_pbc()
    dev[2].request("WPS_PBC")
    ev = dev[2].wait_event(["CTRL-EVENT-CONNECTED"], timeout=30)
    if ev is None:
        raise Exception("Association with the GO timed out")

    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])

    dev[0].remove_group()
    dev[2].request("DISCONNECT")
    dev[1].wait_go_ending_session()

def test_grpform_force_chan_go(dev):
    """P2P group formation forced channel selection by GO"""
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           i_freq=2432,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2432":
        raise Exception("Unexpected channel - did not follow GO's forced channel")
    remove_group(dev[0], dev[1])

def test_grpform_force_chan_cli(dev):
    """P2P group formation forced channel selection by client"""
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           i_freq=2417,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2417":
        raise Exception("Unexpected channel - did not follow GO's forced channel")
    remove_group(dev[0], dev[1])

def test_grpform_force_chan_conflict(dev):
    """P2P group formation fails due to forced channel mismatch"""
    go_neg_pin_authorized(i_dev=dev[0], i_intent=0, i_freq=2422,
                          r_dev=dev[1], r_intent=15, r_freq=2427,
                          expect_failure=True, i_go_neg_status=7)

def test_grpform_pref_chan_go(dev):
    """P2P group formation preferred channel selection by GO"""
    dev[0].request("SET p2p_pref_chan 81:7")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2442":
        raise Exception("Unexpected channel - did not follow GO's p2p_pref_chan")
    remove_group(dev[0], dev[1])

def test_grpform_pref_chan_go_overridden(dev):
    """P2P group formation preferred channel selection by GO overridden by client"""
    dev[1].request("SET p2p_pref_chan 81:7")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           i_freq=2422,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2422":
        raise Exception("Unexpected channel - did not follow client's forced channel")
    remove_group(dev[0], dev[1])

def test_grpform_no_go_freq_forcing_chan(dev):
    """P2P group formation with no-GO freq forcing channel"""
    dev[1].request("SET p2p_no_go_freq 100-200,300,4000-6000")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow no-GO freq")
    remove_group(dev[0], dev[1])

def test_grpform_no_go_freq_conflict(dev):
    """P2P group formation fails due to no-GO range forced by client"""
    dev[1].request("SET p2p_no_go_freq 2000-3000")
    go_neg_pin_authorized(i_dev=dev[0], i_intent=0, i_freq=2422,
                          r_dev=dev[1], r_intent=15,
                          expect_failure=True, i_go_neg_status=7)

def test_grpform_no_5ghz_world_roaming(dev):
    """P2P group formation with world roaming regulatory"""
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=14,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli2(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1 (reverse)"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=14,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli3(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1 (intent 15)"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli4(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1 (reverse; intent 15)"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])
