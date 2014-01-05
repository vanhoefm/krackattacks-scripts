#!/usr/bin/python
#
# Wi-Fi Display test cases
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
import utils

def test_wifi_display(dev):
    """Wi-Fi Display extensions to P2P"""
    wfd_devinfo = "00011c440028"
    dev[0].request("SET wifi_display 1")
    dev[0].request("WFD_SUBELEM_SET 0 0006" + wfd_devinfo)
    if wfd_devinfo not in dev[0].request("WFD_SUBELEM_GET 0"):
        raise Exception("Could not fetch back configured subelement")

    wfd_devinfo2 = "00001c440028"
    dev[1].request("SET wifi_display 1")
    dev[1].request("WFD_SUBELEM_SET 0 0006" + wfd_devinfo2)
    if wfd_devinfo2 not in dev[1].request("WFD_SUBELEM_GET 0"):
        raise Exception("Could not fetch back configured subelement")

    dev[0].p2p_listen()
    dev[1].p2p_find(social=True)
    ev = dev[1].wait_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Device discovery timed out")
    if "wfd_dev_info=0x" + wfd_devinfo not in ev:
        raise Exception("Wi-Fi Display Info not in P2P-DEVICE-FOUND event")

    pin = dev[0].wps_read_pin()
    dev[0].p2p_go_neg_auth(dev[1].p2p_dev_addr(), pin, 'display')
    res1 = dev[1].p2p_go_neg_init(dev[0].p2p_dev_addr(), pin, 'enter', timeout=20, go_intent=15)
    res2 = dev[0].p2p_go_neg_auth_result()

    bss = dev[0].get_bss("p2p_dev_addr=" + dev[1].p2p_dev_addr())
    if bss['bssid'] != dev[1].p2p_interface_addr():
        raise Exception("Unexpected BSSID in the BSS entry for the GO")
    if wfd_devinfo2 not in bss['wfd_subelems']:
        raise Exception("Could not see wfd_subelems in GO's BSS entry")
    peer = dev[0].get_peer(dev[1].p2p_dev_addr())
    if wfd_devinfo2 not in peer['wfd_subelems']:
        raise Exception("Could not see wfd_subelems in GO's peer entry")
    peer = dev[1].get_peer(dev[0].p2p_dev_addr())
    if wfd_devinfo not in peer['wfd_subelems']:
        raise Exception("Could not see wfd_subelems in client's peer entry")

    wfd_devinfo3 = "00001c440028"
    dev[2].request("SET wifi_display 1")
    dev[2].request("WFD_SUBELEM_SET 0 0006" + wfd_devinfo3)
    dev[2].p2p_find(social=True)
    ev = dev[2].wait_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Device discovery timed out")
    if dev[1].p2p_dev_addr() not in ev:
        ev = dev[2].wait_event(["P2P-DEVICE-FOUND"], timeout=5)
        if ev is None:
            raise Exception("Device discovery timed out")
        if dev[1].p2p_dev_addr() not in ev:
            raise Exception("Could not discover GO")
    if "wfd_dev_info=0x" + wfd_devinfo2 not in ev:
        raise Exception("Wi-Fi Display Info not in P2P-DEVICE-FOUND event")
    bss = dev[2].get_bss("p2p_dev_addr=" + dev[1].p2p_dev_addr())
    if bss['bssid'] != dev[1].p2p_interface_addr():
        raise Exception("Unexpected BSSID in the BSS entry for the GO")
    if wfd_devinfo2 not in bss['wfd_subelems']:
        raise Exception("Could not see wfd_subelems in GO's BSS entry")
    peer = dev[2].get_peer(dev[1].p2p_dev_addr())
    if wfd_devinfo2 not in peer['wfd_subelems']:
        raise Exception("Could not see wfd_subelems in GO's peer entry")
