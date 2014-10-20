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
from hwsim import HWSimRadio

def test_p2p_device_grpform(dev, apdev):
    """P2P group formation with driver using cfg80211 P2P Device"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=wpas, r_intent=0)
        check_grpform_results(i_res, r_res)
        remove_group(dev[0], wpas)

def test_p2p_device_grpform2(dev, apdev):
    """P2P group formation with driver using cfg80211 P2P Device (reverse)"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        [i_res, r_res] = go_neg_pin_authorized(i_dev=wpas, i_intent=15,
                                               r_dev=dev[0], r_intent=0)
        check_grpform_results(i_res, r_res)
        remove_group(wpas, dev[0])

def test_p2p_device_group_remove(dev, apdev):
    """P2P group removal via the P2P ctrl interface with driver using cfg80211 P2P Device"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=wpas, r_intent=0)
        check_grpform_results(i_res, r_res)
        # Issue the remove request on the interface which will be removed
        p2p_iface_wpas = WpaSupplicant(ifname=r_res['ifname'])
        res = p2p_iface_wpas.request("P2P_GROUP_REMOVE *")
        if "OK" not in res:
            raise Exception("Failed to remove P2P group")
        ev = wpas.wait_global_event(["P2P-GROUP-REMOVED"], timeout=10)
        if ev is None:
            raise Exception("Group removal event not received")
        if not wpas.global_ping():
            raise Exception("Could not ping global ctrl_iface after group removal")
