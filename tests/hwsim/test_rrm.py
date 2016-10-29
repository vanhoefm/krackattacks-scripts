# Radio measurement
# Copyright(c) 2013 - 2016 Intel Mobile Communications GmbH.
# Copyright(c) 2011 - 2016 Intel Corporation. All rights reserved.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import re
import logging
logger = logging.getLogger()

import hostapd
from utils import HwsimSkip

nr="00112233445500000000510107"
lci="01000800101298c0b512926666f6c2f1001c00004104050000c00012"
civic="01000b0011223344556677889900998877665544332211aabbccddeeff"

def check_nr_results(dev, bssids=None, lci=False, civic=False):
    if bssids is None:
        ev = dev.wait_event(["RRM-NEIGHBOR-REP-REQUEST-FAILED" ], timeout=10)
        if ev is None:
            raise Exception("RRM neighbor report failure not received")
        return

    received = []
    for bssid in bssids:
        ev = dev.wait_event(["RRM-NEIGHBOR-REP-RECEIVED"], timeout=10)
        if ev is None:
            raise Exception("RRM report result not indicated")
        received.append(ev)

    for bssid in bssids:
        found = False
        for r in received:
            if "RRM-NEIGHBOR-REP-RECEIVED bssid=" + bssid in r:
                if lci and "lci=" not in r:
                    raise Exception("LCI data not reported for %s" % bssid)
                if civic and "civic=" not in r:
                    raise Exception("civic data not reported for %s" % bssid)
                received.remove(r)
                found = True
                break
        if not found:
            raise Exception("RRM report result for %s not indicated" % bssid)

def test_rrm_neighbor_db(dev, apdev):
    """hostapd ctrl_iface SET_NEIGHBOR"""
    params = { "ssid": "test", "rrm_neighbor_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    # Bad BSSID
    if "FAIL" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:gg ssid=\"test1\" nr=" + nr):
        raise Exception("Set neighbor succeeded unexpectedly")

    # Bad SSID
    if "FAIL" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=test1 nr=" + nr):
        raise Exception("Set neighbor succeeded unexpectedly")

    # No SSID
    if "FAIL" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 nr=" + nr):
        raise Exception("Set neighbor succeeded unexpectedly")

    # No NR
    if "FAIL" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\""):
        raise Exception("Set neighbor succeeded unexpectedly")

    # Odd length of NR
    if "FAIL" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\" nr=" + nr[:-1]):
        raise Exception("Set neighbor succeeded unexpectedly")

    # No entry yet in database
    if "FAIL" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\""):
        raise Exception("Remove neighbor succeeded unexpectedly")

    # Add a neighbor entry
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\" nr=" + nr + " lci=" + lci + " civic=" + civic):
        raise Exception("Set neighbor failed")

    # Another BSSID with the same SSID
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:56 ssid=\"test1\" nr=" + nr + " lci=" + lci + " civic=" + civic):
        raise Exception("Set neighbor failed")

    # Fewer parameters
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\" nr=" + nr):
        raise Exception("Set neighbor failed")

    # SSID in hex format
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=7465737431 nr=" + nr):
        raise Exception("Set neighbor failed")

    # With more parameters
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\" nr=" + nr + " civic=" + civic):
        raise Exception("Set neighbor failed")

    # With all parameters
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\" nr=" + nr + " lci=" + lci + " civic=" + civic):
        raise Exception("Set neighbor failed")

    # Another SSID on the same BSSID
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test2\" nr=" + nr + " lci=" + lci):
        raise Exception("Set neighbor failed")

    if "OK" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\""):
        raise Exception("Remove neighbor failed")

    if "OK" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:56 ssid=\"test1\""):
        raise Exception("Remove neighbor failed")

    if "OK" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:55 ssid=\"test2\""):
        raise Exception("Remove neighbor failed")

    # Double remove
    if "FAIL" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\""):
        raise Exception("Remove neighbor succeeded unexpectedly")

    # Stationary AP
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test3\" nr=" + nr + " lci=" + lci + " civic=" + civic + " stat"):
        raise Exception("Set neighbor failed")

    if "OK" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:55 ssid=\"test3\""):
        raise Exception("Remove neighbor failed")

def test_rrm_neighbor_rep_req(dev, apdev):
    """wpa_supplicant ctrl_iface NEIGHBOR_REP_REQUEST"""
    nr1="00112233445500000000510107"
    nr2="00112233445600000000510107"
    nr3="dd112233445500000000510107"

    params = { "ssid": "test" }
    hostapd.add_ap(apdev[0]['ifname'], params)
    params = { "ssid": "test2", "rrm_neighbor_report": "1" }
    hapd = hostapd.add_ap(apdev[1]['ifname'], params)

    bssid1 = apdev[1]['bssid']

    dev[0].connect("test", key_mgmt="NONE", scan_freq="2412")
    if "FAIL" not in dev[0].request("NEIGHBOR_REP_REQUEST"):
        raise Exception("Request succeeded unexpectedly (AP without RRM)")
    if "FAIL" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"abcdef\""):
        raise Exception("Request succeeded unexpectedly (AP without RRM 2)")
    dev[0].request("DISCONNECT")

    rrm = int(dev[0].get_driver_status_field("capa.rrm_flags"), 16)
    if rrm & 0x5 != 0x5 and rrm & 0x10 != 0x10:
        raise HwsimSkip("Required RRM capabilities are not supported")

    dev[0].connect("test2", key_mgmt="NONE", scan_freq="2412")

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST"):
        raise Exception("Request failed")
    check_nr_results(dev[0], [bssid1])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST lci"):
        raise Exception("Request failed")
    check_nr_results(dev[0], [bssid1])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST lci civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0], [bssid1])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test3\""):
        raise Exception("Request failed")
    check_nr_results(dev[0])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test3\" lci civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0])

    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test3\" nr=" + nr1 + " lci=" + lci + " civic=" + civic):
        raise Exception("Set neighbor failed")
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:56 ssid=\"test3\" nr=" + nr2 + " lci=" + lci + " civic=" + civic):
        raise Exception("Set neighbor failed")
    if "OK" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:56 ssid=\"test4\" nr=" + nr2 + " lci=" + lci + " civic=" + civic):
        raise Exception("Set neighbor failed")
    if "OK" not in hapd.request("SET_NEIGHBOR dd:11:22:33:44:55 ssid=\"test5\" nr=" + nr3 + " lci=" + lci):
        raise Exception("Set neighbor failed")

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test3\""):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:55", "00:11:22:33:44:56"])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test3\" lci"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:55", "00:11:22:33:44:56"],
                     lci=True)

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test3\" civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:55", "00:11:22:33:44:56"],
                     civic=True)

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test3\" lci civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:55", "00:11:22:33:44:56"],
                     lci=True, civic=True)

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test4\""):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:56"])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test4\" lci"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:56"], lci=True)

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test4\" civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:56"], civic=True)

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test4\" lci civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["00:11:22:33:44:56"], lci=True, civic=True)

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test5\""):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["dd:11:22:33:44:55"])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test5\" lci"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["dd:11:22:33:44:55"], lci=True)

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test5\" civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["dd:11:22:33:44:55"])

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST ssid=\"test5\" lci civic"):
        raise Exception("Request failed")
    check_nr_results(dev[0], ["dd:11:22:33:44:55"], lci=True)

def test_rrm_lci_req(dev, apdev):
    """hostapd lci request"""

    rrm = int(dev[0].get_driver_status_field("capa.rrm_flags"), 16)
    if rrm & 0x5 != 0x5 and rrm & 0x10 != 0x10:
        raise HwsimSkip("Required RRM capabilities are not supported")

    params = { "ssid": "rrm", "rrm_neighbor_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    # station not specified
    if "FAIL" not in hapd.request("REQ_LCI "):
        raise Exception("REQ_LCI with no station succeeded unexpectedly")

    # station that is not connected specified
    if "FAIL" not in hapd.request("REQ_LCI " + dev[0].own_addr()):
        raise Exception("REQ_LCI succeeded unexpectedly (station not connected)")

    dev[0].request("SET LCI ")
    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")

    # station connected without LCI
    if "FAIL" not in hapd.request("REQ_LCI " + dev[0].own_addr()):
        raise Exception("REQ_LCI succeeded unexpectedly (station without lci)")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=2)

    dev[0].request("SET LCI " + lci)

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")

    # station connected with LCI
    if "OK" not in hapd.request("REQ_LCI " + dev[0].own_addr()):
        raise Exception("REQ_LCI failed unexpectedly")

def test_rrm_neighbor_rep_req_from_conf(dev, apdev):
    """wpa_supplicant ctrl_iface NEIGHBOR_REP_REQUEST and hostapd config"""
    params = { "ssid": "test2", "rrm_neighbor_report": "1",
               "stationary_ap": "1", "lci": lci, "civic": civic }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    bssid = apdev[0]['bssid']

    rrm = int(dev[0].get_driver_status_field("capa.rrm_flags"), 16)
    if rrm & 0x5 != 0x5 and rrm & 0x10 != 0x10:
        raise HwsimSkip("Required RRM capabilities are not supported")

    dev[0].connect("test2", key_mgmt="NONE", scan_freq="2412")

    if "OK" not in dev[0].request("NEIGHBOR_REP_REQUEST"):
        raise Exception("Request failed")
    check_nr_results(dev[0], [bssid])

def test_rrm_ftm_range_req(dev, apdev):
    """hostapd FTM range request command"""

    rrm = int(dev[0].get_driver_status_field("capa.rrm_flags"), 16)
    if rrm & 0x5 != 0x5 and rrm & 0x10 != 0x10:
        raise HwsimSkip("Required RRM capabilities are not supported")

    params = { "ssid": "rrm", "rrm_neighbor_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    # station not specified
    if "FAIL" not in hapd.request("REQ_RANGE "):
        raise Exception("REQ_RANGE with no station succeeded unexpectedly")

    # station that is not connected specified
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr()):
        raise Exception("REQ_RANGE succeeded unexpectedly (station not connected)")

    # No responders specified
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10 10"):
        raise Exception("REQ_RANGE succeeded unexpectedly (no responder)")

    # Bad responder address
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10 10 00:11:22:33:44:"):
        raise Exception("REQ_RANGE succeeded unexpectedly (bad responder address)")

    # Bad responder address
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10 10 00:11:22:33:44:55 00:11:22:33:44"):
        raise Exception("REQ_RANGE succeeded unexpectedly (bad responder address 2)")

    # Bad min_ap value
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 20 10 00:11:22:33:44:55"):
        raise Exception("REQ_RANGE succeeded unexpectedly (invalid min_ap value)")

    # Bad rand value
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10 300 00:11:22:33:44:55"):
        raise Exception("REQ_RANGE succeeded unexpectedly (invalid rand value)")

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")

    # Responder not in database
    # Note: this check would pass since the station does not support FTM range
    # request and not because the responder is not in the database.
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10 10 00:11:22:33:44:55"):
        raise Exception("REQ_RANGE succeeded unexpectedly (responder not in database)")

def test_rrm_ftm_capa_indication(dev, apdev):
    """FTM capability indication"""
    try:
        _test_rrm_ftm_capa_indication(dev, apdev)
    finally:
        dev[0].request("SET ftm_initiator 0")
        dev[0].request("SET ftm_responder 0")

def _test_rrm_ftm_capa_indication(dev, apdev):
    params = { "ssid": "ftm",
               "ftm_responder": "1",
               "ftm_initiator": "1", }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    if "OK" not in dev[0].request("SET ftm_initiator 1"):
        raise Exception("could not set ftm_initiator")
    if "OK" not in dev[0].request("SET ftm_responder 1"):
        raise Exception("could not set ftm_responder")
    dev[0].scan_for_bss(apdev[0]['bssid'], freq=2412, force_scan=True)
