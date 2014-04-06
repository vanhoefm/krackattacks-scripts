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
    wfd_devinfo = "00411c440028"
    dev[0].request("SET wifi_display 1")
    dev[0].request("WFD_SUBELEM_SET 0 0006" + wfd_devinfo)
    if wfd_devinfo not in dev[0].request("WFD_SUBELEM_GET 0"):
        raise Exception("Could not fetch back configured subelement")

    # Associated BSSID
    dev[0].request("WFD_SUBELEM_SET 1 0006020304050607")
    # Coupled Sink
    dev[0].request("WFD_SUBELEM_SET 6 000700000000000000")
    # Session Info
    dev[0].request("WFD_SUBELEM_SET 9 0000")
    # WFD Extended Capability
    dev[0].request("WFD_SUBELEM_SET 7 00020000")
    # WFD Content Protection
    prot = "0001" + "00"
    dev[0].request("WFD_SUBELEM_SET 5 " + prot)
    # WFD Video Formats
    video = "0015" + "010203040506070809101112131415161718192021"
    dev[0].request("WFD_SUBELEM_SET 3 " + video)
    # WFD 3D Video Formats
    video_3d = "0011" + "0102030405060708091011121314151617"
    dev[0].request("WFD_SUBELEM_SET 4 " + video_3d)
    # WFD Audio Formats
    audio = "000f" + "010203040506070809101112131415"
    dev[0].request("WFD_SUBELEM_SET 2 " + audio)

    wfd_devinfo2 = "00001c440028"
    dev[1].request("SET wifi_display 1")
    dev[1].request("WFD_SUBELEM_SET 0 0006" + wfd_devinfo2)
    if wfd_devinfo2 not in dev[1].request("WFD_SUBELEM_GET 0"):
        raise Exception("Could not fetch back configured subelement")

    dev[0].p2p_listen()
    if "FAIL" in dev[1].request("P2P_SERV_DISC_REQ " + dev[0].p2p_dev_addr() + " wifi-display [source][pri-sink] 2,3,4,5"):
        raise Exception("Setting SD request failed")
    dev[1].p2p_find(social=True)
    ev = dev[0].wait_global_event(["P2P-SERV-DISC-REQ"], timeout=10)
    if ev is None:
        raise Exception("Device discovery request not reported")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Device discovery timed out")
    if "wfd_dev_info=0x" + wfd_devinfo not in ev:
        raise Exception("Wi-Fi Display Info not in P2P-DEVICE-FOUND event")
    ev = dev[1].wait_global_event(["P2P-SERV-DISC-RESP"], timeout=5)
    if ev is None:
        raise Exception("Service discovery timed out")
    if prot not in ev:
        raise Exception("WFD Content Protection missing from WSD response")
    if video not in ev:
        raise Exception("WFD Video Formats missing from WSD response")
    if video_3d not in ev:
        raise Exception("WFD 3D Video Formats missing from WSD response")
    if audio not in ev:
        raise Exception("WFD Audio Formats missing from WSD response")

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
    dev[2].p2p_stop_find()

    if dev[0].request("WFD_SUBELEM_GET 2") != audio:
        raise Exception("Unexpected WFD_SUBELEM_GET 2 value")
    if dev[0].request("WFD_SUBELEM_GET 3") != video:
        raise Exception("Unexpected WFD_SUBELEM_GET 3 value")
    if dev[0].request("WFD_SUBELEM_GET 4") != video_3d:
        raise Exception("Unexpected WFD_SUBELEM_GET 42 value")
    if dev[0].request("WFD_SUBELEM_GET 5") != prot:
        raise Exception("Unexpected WFD_SUBELEM_GET 5 value")
    if "FAIL" not in dev[0].request("WFD_SUBELEM_SET "):
        raise Exception("Unexpected WFD_SUBELEM_SET success")
    if "FAIL" not in dev[0].request("WFD_SUBELEM_SET 6"):
        raise Exception("Unexpected WFD_SUBELEM_SET success")
    if "OK" not in dev[0].request("WFD_SUBELEM_SET 6 "):
        raise Exception("Unexpected WFD_SUBELEM_SET failure")
    if "FAIL" not in dev[0].request("WFD_SUBELEM_SET 6 0"):
        raise Exception("Unexpected WFD_SUBELEM_SET success")
    if "FAIL" not in dev[0].request("WFD_SUBELEM_SET 6 0q"):
        raise Exception("Unexpected WFD_SUBELEM_SET success")
    if dev[0].request("WFD_SUBELEM_GET 6") != "":
        raise Exception("Unexpected WFD_SUBELEM_GET 6 response")
    if dev[0].request("WFD_SUBELEM_GET 8") != "":
        raise Exception("Unexpected WFD_SUBELEM_GET 8 response")

    dev[0].request("SET wifi_display 0")
    dev[1].request("SET wifi_display 0")
    dev[2].request("SET wifi_display 0")
