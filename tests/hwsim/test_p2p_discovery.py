#!/usr/bin/python
#
# P2P device discovery test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hwsim_utils

def test_discovery(dev):
    """P2P device discovery and provision discovery"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    logger.info("Start device discovery")
    dev[0].p2p_find(social=True)
    if not dev[1].discover_peer(addr0):
        raise Exception("Device discovery timed out")
    if not dev[0].discover_peer(addr1):
        raise Exception("Device discovery timed out")

    logger.info("Test provision discovery for display")
    dev[0].global_request("P2P_PROV_DISC " + addr1 + " display")
    ev1 = dev[1].wait_global_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=15)
    if ev1 is None:
        raise Exception("Provision discovery timed out (display/dev1)")
    if addr0 not in ev1:
        raise Exception("Dev0 not in provision discovery event")
    ev0 = dev[0].wait_global_event(["P2P-PROV-DISC-ENTER-PIN",
                                    "P2P-PROV-DISC-FAILURE"], timeout=15)
    if ev0 is None:
        raise Exception("Provision discovery timed out (display/dev0)")
    if "P2P-PROV-DISC-FAILURE" in ev0:
        raise Exception("Provision discovery failed (display/dev0)")
    if addr1 not in ev0:
        raise Exception("Dev1 not in provision discovery event")

    logger.info("Test provision discovery for keypad")
    dev[0].global_request("P2P_PROV_DISC " + addr1 + " keypad")
    ev1 = dev[1].wait_global_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=15)
    if ev1 is None:
        raise Exception("Provision discovery timed out (keypad/dev1)")
    if addr0 not in ev1:
        raise Exception("Dev0 not in provision discovery event")
    ev0 = dev[0].wait_global_event(["P2P-PROV-DISC-SHOW-PIN",
                                    "P2P-PROV-DISC-FAILURE"],
                                   timeout=15)
    if ev0 is None:
        raise Exception("Provision discovery timed out (keypad/dev0)")
    if "P2P-PROV-DISC-FAILURE" in ev0:
        raise Exception("Provision discovery failed (keypad/dev0)")
    if addr1 not in ev0:
        raise Exception("Dev1 not in provision discovery event")

    logger.info("Test provision discovery for push button")
    dev[0].global_request("P2P_PROV_DISC " + addr1 + " pbc")
    ev1 = dev[1].wait_global_event(["P2P-PROV-DISC-PBC-REQ"], timeout=15)
    if ev1 is None:
        raise Exception("Provision discovery timed out (pbc/dev1)")
    if addr0 not in ev1:
        raise Exception("Dev0 not in provision discovery event")
    ev0 = dev[0].wait_global_event(["P2P-PROV-DISC-PBC-RESP",
                                    "P2P-PROV-DISC-FAILURE"],
                                   timeout=15)
    if ev0 is None:
        raise Exception("Provision discovery timed out (pbc/dev0)")
    if "P2P-PROV-DISC-FAILURE" in ev0:
        raise Exception("Provision discovery failed (pbc/dev0)")
    if addr1 not in ev0:
        raise Exception("Dev1 not in provision discovery event")

    dev[0].p2p_stop_find
    dev[1].p2p_stop_find

def test_discovery_group_client(dev):
    """P2P device discovery for a client in a group"""
    logger.info("Start autonomous GO " + dev[0].ifname)
    res = dev[0].p2p_start_go(freq="2422")
    logger.debug("res: " + str(res))
    logger.info("Connect a client to the GO")
    pin = dev[1].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    dev[1].p2p_connect_group(dev[0].p2p_dev_addr(), pin, timeout=60)
    logger.info("Client connected")
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])
    logger.info("Try to discover a P2P client in a group")
    if not dev[2].discover_peer(dev[1].p2p_dev_addr(), social=False):
        raise Exception("Could not discover group client")

    # This is not really perfect, but something to get a bit more testing
    # coverage.. For proper discoverability mechanism validation, the P2P
    # client would need to go to sleep to avoid acknowledging the GO Negotiation
    # Request frame. Offchannel Listen mode operation on the P2P Client with
    # mac80211_hwsim is apparently not enough to avoid the acknowledgement on
    # the operating channel, so need to disconnect from the group which removes
    # the GO-to-P2P Client part of the discoverability exchange in practice.

    pin = dev[2].wps_read_pin()
    # make group client non-responsive on operating channel
    dev[1].dump_monitor()
    dev[1].group_request("DISCONNECT")
    ev = dev[1].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout on waiting disconnection")
    dev[2].request("P2P_CONNECT {} {} display".format(dev[1].p2p_dev_addr(),
                                                      pin))
    ev = dev[1].wait_event(["P2P-GO-NEG-REQUEST"], timeout=2)
    if ev:
        raise Exception("Unexpected frame RX on P2P client")
    # make group client available on operating channe
    dev[1].request("REASSOCIATE")
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED", "P2P-GO-NEG-REQUEST"])
    if ev is None:
        raise Exception("Timeout on reconnection to group")
    if "P2P-GO-NEG-REQUEST" not in ev:
        ev = dev[1].wait_event(["P2P-GO-NEG-REQUEST"])
        if ev is None:
            raise Exception("Timeout on waiting for GO Negotiation Request")

def test_discovery_dev_type(dev):
    """P2P device discovery with Device Type filter"""
    dev[1].request("SET sec_device_type 1-0050F204-2")
    dev[1].p2p_listen()
    dev[0].p2p_find(social=True, dev_type="5-0050F204-1")
    ev = dev[0].wait_event(['P2P-DEVICE-FOUND'], timeout=1)
    if ev:
        raise Exception("Unexpected P2P device found")
    dev[0].p2p_find(social=True, dev_type="1-0050F204-2")
    ev = dev[0].wait_event(['P2P-DEVICE-FOUND'], timeout=1)
    if ev is None:
        raise Exception("P2P device not found")

def test_discovery_dev_type_go(dev):
    """P2P device discovery with Device Type filter on GO"""
    addr1 = dev[1].p2p_dev_addr()
    dev[1].request("SET sec_device_type 1-0050F204-2")
    res = dev[0].p2p_start_go(freq="2412")
    pin = dev[1].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    dev[1].p2p_connect_group(dev[0].p2p_dev_addr(), pin, timeout=60)

    dev[2].p2p_find(social=True, dev_type="5-0050F204-1")
    ev = dev[2].wait_event(['P2P-DEVICE-FOUND'], timeout=1)
    if ev:
        raise Exception("Unexpected P2P device found")
    dev[2].p2p_find(social=True, dev_type="1-0050F204-2")
    ev = dev[2].wait_event(['P2P-DEVICE-FOUND ' + addr1], timeout=1)
    if ev is None:
        raise Exception("P2P device not found")

def test_discovery_dev_id(dev):
    """P2P device discovery with Device ID filter"""
    addr1 = dev[1].p2p_dev_addr()
    dev[1].p2p_listen()
    dev[0].p2p_find(social=True, dev_id="02:03:04:05:06:07")
    ev = dev[0].wait_event(['P2P-DEVICE-FOUND'], timeout=1)
    if ev:
        raise Exception("Unexpected P2P device found")
    dev[0].p2p_find(social=True, dev_id=addr1)
    ev = dev[0].wait_event(['P2P-DEVICE-FOUND'], timeout=1)
    if ev is None:
        raise Exception("P2P device not found")

def test_discovery_dev_id_go(dev):
    """P2P device discovery with Device ID filter on GO"""
    addr1 = dev[1].p2p_dev_addr()
    res = dev[0].p2p_start_go(freq="2412")
    pin = dev[1].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    dev[1].p2p_connect_group(dev[0].p2p_dev_addr(), pin, timeout=60)

    dev[2].p2p_find(social=True, dev_id="02:03:04:05:06:07")
    ev = dev[2].wait_event(['P2P-DEVICE-FOUND'], timeout=1)
    if ev:
        raise Exception("Unexpected P2P device found")
    dev[2].p2p_find(social=True, dev_id=addr1)
    ev = dev[2].wait_event(['P2P-DEVICE-FOUND ' + addr1], timeout=1)
    if ev is None:
        raise Exception("P2P device not found")
