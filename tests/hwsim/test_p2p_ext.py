# P2P vendor specific extension tests
# Copyright (c) 2014, Qualcomm Atheros, Inc.

import logging
logger = logging.getLogger()

def test_p2p_ext_discovery(dev):
    """P2P device discovery with vendor specific extensions"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()

    try:
        if "OK" not in dev[0].request("VENDOR_ELEM_ADD 1 dd050011223344"):
            raise Exception("VENDOR_ELEM_ADD failed")
        res = dev[0].request("VENDOR_ELEM_GET 1")
        if res != "dd050011223344":
            raise Exception("Unexpected VENDOR_ELEM_GET result: " + res)
        if "OK" not in dev[0].request("VENDOR_ELEM_ADD 1 dd06001122335566"):
            raise Exception("VENDOR_ELEM_ADD failed")
        res = dev[0].request("VENDOR_ELEM_GET 1")
        if res != "dd050011223344dd06001122335566":
            raise Exception("Unexpected VENDOR_ELEM_GET result(2): " + res)
        res = dev[0].request("VENDOR_ELEM_GET 2")
        if res != "":
            raise Exception("Unexpected VENDOR_ELEM_GET result(3): " + res)
        if "OK" not in dev[0].request("VENDOR_ELEM_REMOVE 1 dd050011223344"):
            raise Exception("VENDOR_ELEM_REMOVE failed")
        res = dev[0].request("VENDOR_ELEM_GET 1")
        if res != "dd06001122335566":
            raise Exception("Unexpected VENDOR_ELEM_GET result(4): " + res)
        if "OK" not in dev[0].request("VENDOR_ELEM_REMOVE 1 dd06001122335566"):
            raise Exception("VENDOR_ELEM_REMOVE failed")
        res = dev[0].request("VENDOR_ELEM_GET 1")
        if res != "":
            raise Exception("Unexpected VENDOR_ELEM_GET result(5): " + res)
        if "OK" not in dev[0].request("VENDOR_ELEM_ADD 1 dd050011223344dd06001122335566"):
            raise Exception("VENDOR_ELEM_ADD failed(2)")

        if "FAIL" not in dev[0].request("VENDOR_ELEM_REMOVE 1 dd051122334455"):
            raise Exception("Unexpected VENDOR_ELEM_REMOVE success")
        if "FAIL" not in dev[0].request("VENDOR_ELEM_REMOVE 1 dd"):
            raise Exception("Unexpected VENDOR_ELEM_REMOVE success(2)")
        if "FAIL" not in dev[0].request("VENDOR_ELEM_ADD 1 ddff"):
            raise Exception("Unexpected VENDOR_ELEM_ADD success(3)")

        dev[0].p2p_listen()
        if not dev[1].discover_peer(addr0):
            raise Exception("Device discovery timed out")
        if not dev[0].discover_peer(addr1):
            raise Exception("Device discovery timed out")

        peer = dev[1].get_peer(addr0)
        if peer['vendor_elems'] != "dd050011223344dd06001122335566":
            raise Exception("Vendor elements not reported correctly")

        res = dev[0].request("VENDOR_ELEM_GET 1")
        if res != "dd050011223344dd06001122335566":
            raise Exception("Unexpected VENDOR_ELEM_GET result(6): " + res)
        if "OK" not in dev[0].request("VENDOR_ELEM_REMOVE 1 dd06001122335566"):
            raise Exception("VENDOR_ELEM_REMOVE failed")
        res = dev[0].request("VENDOR_ELEM_GET 1")
        if res != "dd050011223344":
            raise Exception("Unexpected VENDOR_ELEM_GET result(7): " + res)
    finally:
        dev[0].request("VENDOR_ELEM_REMOVE 1 *")

def test_p2p_ext_discovery_go(dev):
    """P2P device discovery with vendor specific extensions for GO"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()

    try:
        if "OK" not in dev[0].request("VENDOR_ELEM_ADD 2 dd050011223344dd06001122335566"):
            raise Exception("VENDOR_ELEM_ADD failed")
        if "OK" not in dev[0].request("VENDOR_ELEM_ADD 3 dd050011223344dd06001122335566"):
            raise Exception("VENDOR_ELEM_ADD failed")
        if "OK" not in dev[0].request("VENDOR_ELEM_ADD 12 dd050011223344dd06001122335566"):
            raise Exception("VENDOR_ELEM_ADD failed")

        dev[0].p2p_start_go(freq="2412")
        if not dev[1].discover_peer(addr0):
            raise Exception("Device discovery timed out")
        peer = dev[1].get_peer(addr0)
        if peer['vendor_elems'] != "dd050011223344dd06001122335566":
            print peer['vendor_elems']
            raise Exception("Vendor elements not reported correctly")
    finally:
        dev[0].request("VENDOR_ELEM_REMOVE 2 *")
        dev[0].request("VENDOR_ELEM_REMOVE 3 *")
        dev[0].request("VENDOR_ELEM_REMOVE 12 *")
