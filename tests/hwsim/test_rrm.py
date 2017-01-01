# Radio measurement
# Copyright(c) 2013 - 2016 Intel Mobile Communications GmbH.
# Copyright(c) 2011 - 2016 Intel Corporation. All rights reserved.
# Copyright (c) 2017, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import re
import logging
logger = logging.getLogger()
import struct
import subprocess

import hostapd
from utils import HwsimSkip, alloc_fail, fail_test, wait_fail_trigger
from test_ap_ht import clear_scan_cache

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

    # Invalid lci
    if "FAIL" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\" nr=" + nr + " lci=1"):
        raise Exception("Set neighbor succeeded unexpectedly")

    # Invalid civic
    if "FAIL" not in hapd.request("SET_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1\" nr=" + nr + " civic=1"):
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

    # Invalid remove - bad BSSID
    if "FAIL" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:5 ssid=\"test1\""):
        raise Exception("Remove neighbor succeeded unexpectedly")

    # Invalid remove - bad SSID
    if "FAIL" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:55 ssid=\"test1"):
        raise Exception("Remove neighbor succeeded unexpectedly")

    # Invalid remove - missing SSID
    if "FAIL" not in hapd.request("REMOVE_NEIGHBOR 00:11:22:33:44:55"):
        raise Exception("Remove neighbor succeeded unexpectedly")

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
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10 300 00:11:22:33:44:55"):
        raise Exception("REQ_RANGE succeeded unexpectedly (invalid min_ap value)")

    # Bad rand value
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " -1 10 00:11:22:33:44:55"):
        raise Exception("REQ_RANGE succeeded unexpectedly (invalid rand value)")
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 65536 10 00:11:22:33:44:55"):
        raise Exception("REQ_RANGE succeeded unexpectedly (invalid rand value)")

    # Missing min_ap value
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10"):
        raise Exception("REQ_RANGE succeeded unexpectedly (missing min_ap value)")

    # Too many responders
    if "FAIL" not in hapd.request("REQ_RANGE " + dev[0].own_addr() + " 10 10" + 20*" 00:11:22:33:44:55"):
        raise Exception("REQ_RANGE succeeded unexpectedly (too many responders)")

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

class BeaconReport:
    def __init__(self, report):
        self.opclass, self.channel, self.start, self.duration, self.frame_info, self.rcpi, self.rsni = struct.unpack("<BBQHBBB", report[0:15])
        report = report[15:]
        self.bssid = report[0:6]
        self.bssid_str = "%02x:%02x:%02x:%02x:%02x:%02x" % (struct.unpack('6B', self.bssid))
        report = report[6:]
        self.antenna_id, self.parent_tsf = struct.unpack("<BI", report[0:5])
        report = report[5:]
        self.subelems = report
        self.frame_body = None
        while len(report) >= 2:
            eid,elen = struct.unpack('BB', report[0:2])
            report = report[2:]
            if len(report) < elen:
                raise Exception("Invalid subelement in beacon report")
            if eid == 1:
                # Reported Frame Body
                # Contents depends on the reporting detail request:
                # 0 = no Reported Frame Body subelement
                # 1 = all fixed fields and any elements identified in Request
                #     element
                # 2 = all fixed fields and all elements
                # Fixed fields: Timestamp[8] BeaconInt[2] CapabInfo[2]
                self.frame_body = report[0:elen]
            report = report[elen:]
    def __str__(self):
        txt = "opclass={} channel={} start={} duration={} frame_info={} rcpi={} rsni={} bssid={} antenna_id={} parent_tsf={}".format(self.opclass, self.channel, self.start, self.duration, self.frame_info, self.rcpi, self.rsni, self.bssid_str, self.antenna_id, self.parent_tsf)
        if self.frame_body:
            txt += " frame_body=" + binascii.hexlify(self.frame_body)
        return txt

def run_req_beacon(hapd, addr, request):
    token = hapd.request("REQ_BEACON " + addr + " " + request)
    if "FAIL" in token:
        raise Exception("REQ_BEACON failed")

    ev = hapd.wait_event(["BEACON-REQ-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("No TX status event for beacon request received")
    fields = ev.split(' ')
    if fields[1] != addr:
        raise Exception("Unexpected STA address in TX status: " + fields[1])
    if fields[2] != token:
        raise Exception("Unexpected dialog token in TX status: " + fields[2] + " (expected " + token + ")")
    if fields[3] != "ack=1":
        raise Exception("Unexected ACK status in TX status: " + fields[3])
    return token

def test_rrm_beacon_req_table(dev, apdev):
    """Beacon request - beacon table mode"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], { "ssid": "another" })

    tests = [ "REQ_BEACON ",
              "REQ_BEACON q",
              "REQ_BEACON 11:22:33:44:55:66 1",
              "REQ_BEACON 11:22:33:44:55:66 1q",
              "REQ_BEACON 11:22:33:44:55:66 11223344556677889900aabbccddeeff" ]
    for t in tests:
        if "FAIL" not in hapd.request(t):
            raise Exception("Invalid command accepted: " + t)

    dev[0].scan_for_bss(apdev[1]['bssid'], freq=2412)
    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff")

    for i in range(1, 3):
        ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
        if ev is None:
            raise Exception("Beacon report %d response not received" % i)
        fields = ev.split(' ')
        if fields[1] != addr:
            raise Exception("Unexpected STA address in beacon report response: " + fields[1])
        if fields[2] != token:
            raise Exception("Unexpected dialog token in beacon report response: " + fields[2] + " (expected " + token + ")")
        if fields[3] != "00":
            raise Exception("Unexpected measurement report mode")

        report = BeaconReport(binascii.unhexlify(fields[4]))
        logger.info("Received beacon report: " + str(report))

        # Default reporting detail is 2, i.e., all fixed fields and elements.
        if not report.frame_body:
            raise Exception("Reported Frame Body subelement missing")
        if len(report.frame_body) <= 12:
            raise Exception("Too short Reported Frame Body subelement")

def test_rrm_beacon_req_table_detail(dev, apdev):
    """Beacon request - beacon table mode - reporting detail"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    logger.info("Reporting Detail 0")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020100")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))
    if report.frame_body:
        raise Exception("Reported Frame Body subelement included with Reporting Detail 0")
    hapd.dump_monitor()

    logger.info("Reporting Detail 1")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))
    if not report.frame_body:
        raise Exception("Reported Frame Body subelement missing")
    if len(report.frame_body) != 12:
        raise Exception("Unexpected Reported Frame Body subelement length with Reporting Detail 1")
    hapd.dump_monitor()

    logger.info("Reporting Detail 2")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020102")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))
    if not report.frame_body:
        raise Exception("Reported Frame Body subelement missing")
    if len(report.frame_body) <= 12:
        raise Exception("Unexpected Reported Frame Body subelement length with Reporting Detail 2")
    hapd.dump_monitor()

    logger.info("Reporting Detail 3 (invalid)")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020103")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response to invalid reporting detail 3")
    hapd.dump_monitor()

    logger.info("Reporting Detail (too short)")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "0200")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response to invalid reporting detail")
    hapd.dump_monitor()

def test_rrm_beacon_req_table_request(dev, apdev):
    """Beacon request - beacon table mode - request element"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a03000106")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))
    if not report.frame_body:
        raise Exception("Reported Frame Body subelement missing")
    if len(report.frame_body) != 12 + 5 + 10:
        raise Exception("Unexpected Reported Frame Body subelement length with Reporting Detail 1 and requested elements SSID + SuppRates")
    hapd.dump_monitor()

    logger.info("Incorrect reporting detail with request subelement")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020102" + "0a03000106")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response (invalid reporting detail)")
    hapd.dump_monitor()

    logger.info("Invalid request subelement length")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a00")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response (invalid request subelement length)")
    hapd.dump_monitor()

    logger.info("Multiple request subelements")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a0100" + "0a0101")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response (multiple request subelements)")
    hapd.dump_monitor()

def test_rrm_beacon_req_table_request_oom(dev, apdev):
    """Beacon request - beacon table mode - request element OOM"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    with alloc_fail(dev[0], 1,
                    "bitfield_alloc;wpas_rm_handle_beacon_req_subelem"):
        token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a03000106")
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
        ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected beacon report response received (OOM)")

    with alloc_fail(dev[0], 1,
                    "wpabuf_alloc;wpas_rrm_send_msr_report_mpdu"):
        token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a03000106")
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
        ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected beacon report response received (OOM)")

    with fail_test(dev[0], 1,
                    "wpa_driver_nl80211_send_action;wpas_rrm_send_msr_report_mpdu"):
        token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a03000106")
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
        ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected beacon report response received (OOM)")

    with alloc_fail(dev[0], 1,
                    "wpabuf_resize;wpas_add_beacon_rep"):
        token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a03000106")
        ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
        if ev is None:
            raise Exception("Beacon report response not received (OOM -> empty report)")
        fields = ev.split(' ')
        if len(fields[4]) > 0:
            raise Exception("Unexpected beacon report received")

def test_rrm_beacon_req_table_bssid(dev, apdev):
    """Beacon request - beacon table mode - specific BSSID"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], { "ssid": "another" })

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    bssid2 = hapd2.own_addr()
    token = run_req_beacon(hapd, addr, "51000000000002" + bssid2.replace(':', ''))
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))
    if "bssid=" + bssid2 not in str(report):
        raise Exception("Report for unexpect BSS")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected beacon report response")

def test_rrm_beacon_req_table_ssid(dev, apdev):
    """Beacon request - beacon table mode - specific SSID"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], { "ssid": "another" })

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    bssid2 = hapd2.own_addr()
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "0007" + "another".encode('hex'))
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))
    if "bssid=" + bssid2 not in str(report):
        raise Exception("Report for unexpect BSS")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected beacon report response")
    hapd.dump_monitor()

    logger.info("Wildcard SSID")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "0000")
    for i in range(2):
        ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
        if ev is None:
            raise Exception("Beacon report response not received")
        fields = ev.split(' ')
        report = BeaconReport(binascii.unhexlify(fields[4]))
        logger.info("Received beacon report: " + str(report))
    hapd.dump_monitor()

    logger.info("Too long SSID")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "0021" + 33*"00")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response (invalid SSID subelement in request)")
    hapd.dump_monitor()

def test_rrm_beacon_req_table_info(dev, apdev):
    """Beacon request - beacon table mode - Reporting Information subelement"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    logger.info("Unsupported reporting information 1")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "01020100")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response (unsupported reporting information 1)")
    hapd.dump_monitor()

    logger.info("Invalid reporting information length")
    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "010100")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response (invalid reporting information length)")
    hapd.dump_monitor()

def test_rrm_beacon_req_table_unknown_subelem(dev, apdev):
    """Beacon request - beacon table mode - unknown subelement"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "330101" + "fe00")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))

def test_rrm_beacon_req_table_truncated_subelem(dev, apdev):
    """Beacon request - beacon table mode - Truncated subelement"""
    params = { "ssid": "rrm", "rrm_beacon_report": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("rrm", key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].own_addr()

    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "0001")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=0.2)
    if ev is not None:
        raise Exception("Unexpected beacon report response (truncated subelement)")
    hapd.dump_monitor()

def test_rrm_beacon_req_table_rsne(dev, apdev):
    """Beacon request - beacon table mode - RSNE truncation"""
    params = hostapd.wpa2_params(ssid="rrm-rsn", passphrase="12345678")
    params["rrm_beacon_report"] = "1"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect("rrm-rsn", psk="12345678", scan_freq="2412")
    addr = dev[0].own_addr()

    token = run_req_beacon(hapd, addr, "51000000000002ffffffffffff" + "020101" + "0a0130")
    ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
    if ev is None:
        raise Exception("Beacon report response not received")
    fields = ev.split(' ')
    report = BeaconReport(binascii.unhexlify(fields[4]))
    logger.info("Received beacon report: " + str(report))
    if not report.frame_body:
        raise Exception("Reported Frame Body subelement missing")
    if len(report.frame_body) != 12 + 6:
        raise Exception("Unexpected Reported Frame Body subelement length with Reporting Detail 1 and requested element RSNE")
    if binascii.unhexlify("30040100000f") not in report.frame_body:
        raise Exception("Truncated RSNE not found")

def test_rrm_beacon_req_table_vht(dev, apdev):
    """Beacon request - beacon table mode - VHT"""
    clear_scan_cache(apdev[0])
    try:
        hapd = None
        params = { "ssid": "rrm-vht",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "36",
                   "ht_capab": "[HT40+]",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "vht_oper_chwidth": "1",
                   "vht_oper_centr_freq_seg0_idx": "42",
                   "rrm_beacon_report": "1" }
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        params = { "ssid": "test-vht40",
                   "country_code": "FI",
                   "hw_mode": "a",
                   "channel": "48",
                   "ieee80211n": "1",
                   "ieee80211ac": "1",
                   "ht_capab": "[HT40-]",
                   "vht_capab": "",
                   "vht_oper_chwidth": "0",
                   "vht_oper_centr_freq_seg0_idx": "0",
                 }
        hapd2 = hostapd.add_ap(apdev[1], params)

        dev[0].scan_for_bss(apdev[1]['bssid'], freq=5240)
        dev[0].connect("rrm-vht", key_mgmt="NONE", scan_freq="5180")

        addr = dev[0].own_addr()

        token = run_req_beacon(hapd, addr, "f0000000000002ffffffffffff")
        for i in range(2):
            ev = hapd.wait_event(["BEACON-RESP-RX"], timeout=10)
            if ev is None:
                raise Exception("Beacon report %d response not received" % i)
            fields = ev.split(' ')
            report = BeaconReport(binascii.unhexlify(fields[4]))
            logger.info("Received beacon report: " + str(report))
            if report.bssid_str == apdev[0]['bssid']:
                if report.opclass != 128 or report.channel != 36:
                    raise Exception("Incorrect opclass/channel for AP0")
            elif report.bssid_str == apdev[1]['bssid']:
                if report.opclass != 117 or report.channel != 48:
                    raise Exception("Incorrect opclass/channel for AP1")
    except Exception, e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not vht_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
