# P2P channel selection test cases
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import subprocess
import time

from test_p2p_grpform import go_neg_pin_authorized
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group

def set_country(country):
    subprocess.call(['sudo', 'iw', 'reg', 'set', country])
    time.sleep(0.1)

def test_p2p_channel_5ghz(dev):
    """P2P group formation with 5 GHz preference"""
    try:
        set_country("US")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq < 5000:
            raise Exception("Unexpected channel %d MHz - did not follow 5 GHz preference" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")

def test_p2p_channel_5ghz_no_vht(dev):
    """P2P group formation with 5 GHz preference when VHT channels are disallowed"""
    try:
        set_country("US")
        dev[0].request("P2P_SET disallow_freq 5180-5240")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq < 5000:
            raise Exception("Unexpected channel %d MHz - did not follow 5 GHz preference" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")

def test_p2p_channel_random_social(dev):
    """P2P group formation with 5 GHz preference but all 5 GHz channels disabled"""
    try:
        set_country("US")
        dev[0].request("SET p2p_oper_channel 11")
        dev[0].request("P2P_SET disallow_freq 5000-6000,2462")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq not in [ 2412, 2437, 2462 ]:
            raise Exception("Unexpected channel %d MHz - did not pick random social channel" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")

def test_p2p_channel_random(dev):
    """P2P group formation with 5 GHz preference but all 5 GHz channels and all social channels disabled"""
    try:
        set_country("US")
        dev[0].request("SET p2p_oper_channel 11")
        dev[0].request("P2P_SET disallow_freq 5000-6000,2412,2437,2462")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq > 2500 or freq in [ 2412, 2437, 2462 ]:
            raise Exception("Unexpected channel %d MHz" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")

def test_p2p_channel_random_social_with_op_class_change(dev, apdev, params):
    """P2P group formation using random social channel with oper class change needed"""
    try:
        set_country("US")
        logger.info("Start group on 5 GHz")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq < 5000:
            raise Exception("Unexpected channel %d MHz - did not pick 5 GHz preference" % freq)
        remove_group(dev[0], dev[1])

        logger.info("Disable 5 GHz and try to re-start group based on 5 GHz preference")
        dev[0].request("SET p2p_oper_reg_class 115")
        dev[0].request("SET p2p_oper_channel 36")
        dev[0].request("P2P_SET disallow_freq 5000-6000")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq not in [ 2412, 2437, 2462 ]:
            raise Exception("Unexpected channel %d MHz - did not pick random social channel" % freq)
        remove_group(dev[0], dev[1])

        try:
            arg = [ "tshark",
                    "-r", os.path.join(params['logdir'], "hwsim0.pcapng"),
                    "-R", "wifi_p2p.public_action.subtype == 0",
                    "-V" ]
            cmd = subprocess.Popen(arg, stdout=subprocess.PIPE,
                                   stderr=open('/dev/null', 'w'))
        except Exception, e:
            logger.info("Could run run tshark check: " + str(e))
            cmd = None
            pass

        if cmd:
            last = None
            for l in cmd.stdout.read().splitlines():
                if "Operating Channel:" not in l:
                    continue
                last = l
            if last is None:
                raise Exception("Could not find GO Negotiation Request")
            if "Operating Class 81" not in last:
                raise Exception("Unexpected operating class: " + last.strip())
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")
        dev[0].request("SET p2p_oper_reg_class 81")
        dev[0].request("SET p2p_oper_channel 11")
