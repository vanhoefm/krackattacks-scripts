#!/usr/bin/python
#
# cfg80211 P2P Device
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

from wpasupplicant import WpaSupplicant
from test_p2p_grpform import go_neg_pin_authorized
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group

def test_p2p_device_grpform(dev, apdev):
    """P2P group formation with driver using cfg80211 P2P Device"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=wpas, r_intent=0)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], wpas)

def test_p2p_device_grpform2(dev, apdev):
    """P2P group formation with driver using cfg80211 P2P Device (reverse)"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=wpas, i_intent=15,
                                           r_dev=dev[0], r_intent=0)
    check_grpform_results(i_res, r_res)
    remove_group(wpas, dev[0])
