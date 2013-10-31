#!/usr/bin/python
#
# P2P service discovery test cases
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hwsim_utils

def add_bonjour_services(dev):
    dev.request("P2P_SERVICE_ADD bonjour 0b5f6166706f766572746370c00c000c01 074578616d706c65c027")
    dev.request("P2P_SERVICE_ADD bonjour 076578616d706c650b5f6166706f766572746370c00c001001 00")
    dev.request("P2P_SERVICE_ADD bonjour 045f697070c00c000c01 094d795072696e746572c027")
    dev.request("P2P_SERVICE_ADD bonjour 096d797072696e746572045f697070c00c001001 09747874766572733d311a70646c3d6170706c69636174696f6e2f706f7374736372797074")

def add_upnp_services(dev):
    dev.request("P2P_SERVICE_ADD upnp 10 uuid:6859dede-8574-59ab-9332-123456789012::upnp:rootdevice")
    dev.request("P2P_SERVICE_ADD upnp 10 uuid:5566d33e-9774-09ab-4822-333456785632::upnp:rootdevice")
    dev.request("P2P_SERVICE_ADD upnp 10 uuid:1122de4e-8574-59ab-9322-333456789044::urn:schemas-upnp-org:service:ContentDirectory:2")
    dev.request("P2P_SERVICE_ADD upnp 10 uuid:5566d33e-9774-09ab-4822-333456785632::urn:schemas-upnp-org:service:ContentDirectory:2")
    dev.request("P2P_SERVICE_ADD upnp 10 uuid:6859dede-8574-59ab-9332-123456789012::urn:schemas-upnp-org:device:InternetGatewayDevice:1")

def run_sd(dev, dst, query, exp_query=None):
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    add_bonjour_services(dev[0])
    add_upnp_services(dev[0])
    dev[0].p2p_listen()

    dev[1].request("P2P_FLUSH")
    dev[1].request("P2P_SERV_DISC_REQ " + dst + " " + query)
    if not dev[1].discover_peer(addr0, social=True):
        raise Exception("Peer " + addr0 + " not found")

    ev = dev[0].wait_event(["P2P-SERV-DISC-REQ"], timeout=10)
    if ev is None:
        raise Exception("Service discovery timed out")
    if addr1 not in ev:
        raise Exception("Unexpected service discovery request source")
    if exp_query is None:
        exp_query = query
    if exp_query not in ev:
        raise Exception("Unexpected service discovery request contents")

    ev = dev[1].wait_event(["P2P-SERV-DISC-RESP"], timeout=10)
    if ev is None:
        raise Exception("Service discovery timed out")
    if addr0 not in ev:
        raise Exception("Unexpected service discovery response source")
    return ev

def test_p2p_service_discovery(dev):
    """P2P service discovery"""
    ev = run_sd(dev, "00:00:00:00:00:00", "02000001")
    if "0b5f6166706f766572746370c00c000c01" not in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour)")
    if "496e7465726e6574" not in ev:
        raise Exception("Unexpected service discovery response contents (UPnP)")

def test_p2p_service_discovery_bonjour(dev):
    """P2P service discovery (Bonjour)"""
    ev = run_sd(dev, "00:00:00:00:00:00", "02000101")
    if "0b5f6166706f766572746370c00c000c01" not in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour)")
    if "045f697070c00c000c01" not in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour)")
    if "496e7465726e6574" in ev:
        raise Exception("Unexpected service discovery response contents (UPnP not expected)")

def test_p2p_service_discovery_bonjour2(dev):
    """P2P service discovery (Bonjour AFS)"""
    ev = run_sd(dev, "00:00:00:00:00:00", "130001010b5f6166706f766572746370c00c000c01")
    if "0b5f6166706f766572746370c00c000c01" not in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour)")
    if "045f697070c00c000c01" in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour mismatching)")
    if "496e7465726e6574" in ev:
        raise Exception("Unexpected service discovery response contents (UPnP not expected)")

def test_p2p_service_discovery_upnp(dev):
    """P2P service discovery (UPnP)"""
    ev = run_sd(dev, "00:00:00:00:00:00", "02000201")
    if "0b5f6166706f766572746370c00c000c01" in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour not expected)")
    if "496e7465726e6574" not in ev:
        raise Exception("Unexpected service discovery response contents (UPnP)")

def test_p2p_service_discovery_upnp2(dev):
    """P2P service discovery (UPnP using request helper)"""
    ev = run_sd(dev, "00:00:00:00:00:00", "upnp 10 ssdp:all", "0b00020110737364703a616c6c")
    if "0b5f6166706f766572746370c00c000c01" in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour not expected)")
    if "496e7465726e6574" not in ev:
        raise Exception("Unexpected service discovery response contents (UPnP)")

def test_p2p_service_discovery_ws(dev):
    """P2P service discovery (WS-Discovery)"""
    ev = run_sd(dev, "00:00:00:00:00:00", "02000301")
    if "0b5f6166706f766572746370c00c000c01" in ev:
        raise Exception("Unexpected service discovery response contents (Bonjour not expected)")
    if "496e7465726e6574" in ev:
        raise Exception("Unexpected service discovery response contents (UPnP not expected)")
    if "0300030101" not in ev:
        raise Exception("Unexpected service discovery response contents (WS)")
