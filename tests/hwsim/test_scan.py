# Scanning tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()
import os
import subprocess

import hostapd

def check_scan(dev, params, other_started=False):
    if not other_started:
        dev.dump_monitor()
    id = dev.request("SCAN " + params)
    if "FAIL" in id:
        raise Exception("Failed to start scan")
    id = int(id)

    if other_started:
        ev = dev.wait_event(["CTRL-EVENT-SCAN-STARTED"])
        if ev is None:
            raise Exception("Other scan did not start")
        if "id=" + str(id) in ev:
            raise Exception("Own scan id unexpectedly included in start event")

        ev = dev.wait_event(["CTRL-EVENT-SCAN-RESULTS"])
        if ev is None:
            raise Exception("Other scan did not complete")
        if "id=" + str(id) in ev:
            raise Exception("Own scan id unexpectedly included in completed event")

    ev = dev.wait_event(["CTRL-EVENT-SCAN-STARTED"])
    if ev is None:
        raise Exception("Scan did not start")
    if "id=" + str(id) not in ev:
        raise Exception("Scan id not included in start event")

    ev = dev.wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Scan did not complete")
    if "id=" + str(id) not in ev:
        raise Exception("Scan id not included in completed event")

def check_scan_retry(dev, params, bssid):
    for i in range(0, 5):
        check_scan(dev, "freq=2412-2462,5180 use_id=1")
        if int(dev.get_bss(bssid)['age']) <= 1:
            return
    raise Exception("Unexpectedly old BSS entry")

def test_scan(dev, apdev):
    """Control interface behavior on scan parameters"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-scan" })
    bssid = apdev[0]['bssid']

    logger.info("Full scan")
    check_scan(dev[0], "use_id=1")

    logger.info("Limited channel scan")
    check_scan_retry(dev[0], "freq=2412-2462,5180 use_id=1", bssid)

    # wait long enough to allow next scans to be verified not to find the AP
    time.sleep(2)

    logger.info("Passive single-channel scan")
    check_scan(dev[0], "freq=2457 passive=1 use_id=1")
    logger.info("Active single-channel scan")
    check_scan(dev[0], "freq=2452 passive=0 use_id=1")
    if int(dev[0].get_bss(bssid)['age']) < 2:
        raise Exception("Unexpectedly updated BSS entry")

    logger.info("Active single-channel scan on AP's operating channel")
    check_scan_retry(dev[0], "freq=2412 passive=0 use_id=1", bssid)

def test_scan_only(dev, apdev):
    """Control interface behavior on scan parameters with type=only"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-scan" })
    bssid = apdev[0]['bssid']

    logger.info("Full scan")
    check_scan(dev[0], "type=only use_id=1")

    logger.info("Limited channel scan")
    check_scan_retry(dev[0], "type=only freq=2412-2462,5180 use_id=1", bssid)

    # wait long enough to allow next scans to be verified not to find the AP
    time.sleep(2)

    logger.info("Passive single-channel scan")
    check_scan(dev[0], "type=only freq=2457 passive=1 use_id=1")
    logger.info("Active single-channel scan")
    check_scan(dev[0], "type=only freq=2452 passive=0 use_id=1")
    if int(dev[0].get_bss(bssid)['age']) < 2:
        raise Exception("Unexpectedly updated BSS entry")

    logger.info("Active single-channel scan on AP's operating channel")
    check_scan_retry(dev[0], "type=only freq=2412 passive=0 use_id=1", bssid)

def test_scan_external_trigger(dev, apdev):
    """Avoid operations during externally triggered scan"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-scan" })
    bssid = apdev[0]['bssid']
    subprocess.call(['sudo', 'iw', dev[0].ifname, 'scan', 'trigger'])
    check_scan(dev[0], "use_id=1", other_started=True)

def test_scan_bss_expiration_count(dev, apdev):
    """BSS entry expiration based on scan results without match"""
    if "FAIL" not in dev[0].request("BSS_EXPIRE_COUNT 0"):
        raise Exception("Invalid BSS_EXPIRE_COUNT accepted")
    if "OK" not in dev[0].request("BSS_EXPIRE_COUNT 2"):
        raise Exception("BSS_EXPIRE_COUNT failed")
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-scan" })
    bssid = apdev[0]['bssid']
    dev[0].scan(freq="2412", only_new=True)
    if bssid not in dev[0].request("SCAN_RESULTS"):
        raise Exception("BSS not found in initial scan")
    hapd.request("DISABLE")
    dev[0].scan(freq="2412", only_new=True)
    if bssid not in dev[0].request("SCAN_RESULTS"):
        raise Exception("BSS not found in first scan without match")
    dev[0].scan(freq="2412", only_new=True)
    if bssid in dev[0].request("SCAN_RESULTS"):
        raise Exception("BSS found after two scans without match")

def test_scan_bss_expiration_age(dev, apdev):
    """BSS entry expiration based on age"""
    try:
        if "FAIL" not in dev[0].request("BSS_EXPIRE_AGE COUNT 9"):
            raise Exception("Invalid BSS_EXPIRE_AGE accepted")
        if "OK" not in dev[0].request("BSS_EXPIRE_AGE 10"):
            raise Exception("BSS_EXPIRE_AGE failed")
        hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-scan" })
        bssid = apdev[0]['bssid']
        dev[0].scan(freq="2412")
        if bssid not in dev[0].request("SCAN_RESULTS"):
            raise Exception("BSS not found in initial scan")
        hapd.request("DISABLE")
        logger.info("Waiting for BSS entry to expire")
        time.sleep(7)
        if bssid not in dev[0].request("SCAN_RESULTS"):
            raise Exception("BSS expired too quickly")
        ev = dev[0].wait_event(["CTRL-EVENT-BSS-REMOVED"], timeout=15)
        if ev is None:
            raise Exception("BSS entry expiration timed out")
        if bssid in dev[0].request("SCAN_RESULTS"):
            raise Exception("BSS not removed after expiration time")
    finally:
        dev[0].request("BSS_EXPIRE_AGE 180")

def test_scan_filter(dev, apdev):
    """Filter scan results based on SSID"""
    try:
        if "OK" not in dev[0].request("SET filter_ssids 1"):
            raise Exception("SET failed")
        dev[0].connect("test-scan", key_mgmt="NONE", only_add_network=True)
        hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-scan" })
        bssid = apdev[0]['bssid']
        hostapd.add_ap(apdev[1]['ifname'], { "ssid": "test-scan2" })
        bssid2 = apdev[1]['bssid']
        dev[0].scan(freq="2412", only_new=True)
        if bssid not in dev[0].request("SCAN_RESULTS"):
            raise Exception("BSS not found in scan results")
        if bssid2 in dev[0].request("SCAN_RESULTS"):
            raise Exception("Unexpected BSS found in scan results")
    finally:
        dev[0].request("SET filter_ssids 0")

def test_scan_int(dev, apdev):
    """scan interval configuration"""
    try:
        if "FAIL" not in dev[0].request("SCAN_INTERVAL -1"):
            raise Exception("Accepted invalid scan interval")
        if "OK" not in dev[0].request("SCAN_INTERVAL 1"):
            raise Exception("Failed to set scan interval")
        dev[0].connect("not-used", key_mgmt="NONE", scan_freq="2412",
                       wait_connect=False)
        times = {}
        for i in range(0, 3):
            logger.info("Waiting for scan to start")
            start = os.times()[4]
            ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=5)
            if ev is None:
                raise Exception("did not start a scan")
            stop = os.times()[4]
            times[i] = stop - start
            logger.info("Waiting for scan to complete")
            ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
            if ev is None:
                raise Exception("did not complete a scan")
        print times
        if times[0] > 1 or times[1] < 0.5 or times[1] > 1.5 or times[2] < 0.5 or times[2] > 1.5:
            raise Exception("Unexpected scan timing: " + str(times))
    finally:
        dev[0].request("SCAN_INTERVAL 5")

def test_scan_bss_operations(dev, apdev):
    """Control interface behavior on BSS parameters"""
    hostapd.add_ap(apdev[0]['ifname'], { "ssid": "test-scan" })
    bssid = apdev[0]['bssid']
    hostapd.add_ap(apdev[1]['ifname'], { "ssid": "test2-scan" })
    bssid2 = apdev[1]['bssid']

    dev[0].scan(freq="2412")
    dev[0].scan(freq="2412")
    dev[0].scan(freq="2412")

    id1 = dev[0].request("BSS FIRST MASK=0x1").splitlines()[0].split('=')[1]
    id2 = dev[0].request("BSS LAST MASK=0x1").splitlines()[0].split('=')[1]

    res = dev[0].request("BSS RANGE=ALL MASK=0x20001")
    if "id=" + id1 not in res:
        raise Exception("Missing BSS " + id1)
    if "id=" + id2 not in res:
        raise Exception("Missing BSS " + id2)
    if "====" not in res:
        raise Exception("Missing delim")
    if "####" not in res:
        raise Exception("Missing end")

    res = dev[0].request("BSS RANGE=ALL MASK=0x1").splitlines()
    if len(res) != 2:
        raise Exception("Unexpected result")
    res = dev[0].request("BSS FIRST MASK=0x1")
    if "id=" + id1 not in res:
        raise Exception("Unexpected result: " + res)
    res = dev[0].request("BSS LAST MASK=0x1")
    if "id=" + id2 not in res:
        raise Exception("Unexpected result: " + res)
    res = dev[0].request("BSS ID-" + id1 + " MASK=0x1")
    if "id=" + id1 not in res:
        raise Exception("Unexpected result: " + res)
    res = dev[0].request("BSS NEXT-" + id1 + " MASK=0x1")
    if "id=" + id2 not in res:
        raise Exception("Unexpected result: " + res)

    if len(dev[0].request("BSS RANGE=" + id2 + " MASK=0x1").splitlines()) != 0:
        raise Exception("Unexpected RANGE=1 result")
    if len(dev[0].request("BSS RANGE=" + id1 + "- MASK=0x1").splitlines()) != 2:
        raise Exception("Unexpected RANGE=0- result")
    if len(dev[0].request("BSS RANGE=-" + id2 + " MASK=0x1").splitlines()) != 2:
        raise Exception("Unexpected RANGE=-1 result")
    if len(dev[0].request("BSS RANGE=" + id1 + "-" + id2 + " MASK=0x1").splitlines()) != 2:
        raise Exception("Unexpected RANGE=0-1 result")
    if len(dev[0].request("BSS RANGE=" + id2 + "-" + id2 + " MASK=0x1").splitlines()) != 1:
        raise Exception("Unexpected RANGE=1-1 result")
    if len(dev[0].request("BSS RANGE=" + str(int(id2) + 1) + "-" + str(int(id2) + 10) + " MASK=0x1").splitlines()) != 0:
        raise Exception("Unexpected RANGE=2-10 result")
    if len(dev[0].request("BSS RANGE=0-" + str(int(id2) + 10) + " MASK=0x1").splitlines()) != 2:
        raise Exception("Unexpected RANGE=0-10 result")

def test_scan_and_interface_disabled(dev, apdev):
    """Scan operation when interface gets disabled"""
    try:
        dev[0].request("SCAN")
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"])
        if ev is None:
            raise Exception("Scan did not start")
        dev[0].request("DRIVER_EVENT INTERFACE_DISABLED")
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=7)
        if ev is not None:
            raise Exception("Scan completed unexpectedly")

        # verify that scan is rejected
        if "FAIL" not in dev[0].request("SCAN"):
            raise Exception("New scan request was accepted unexpectedly")

        dev[0].request("DRIVER_EVENT INTERFACE_ENABLED")
        dev[0].scan(freq="2412")
    finally:
        dev[0].request("DRIVER_EVENT INTERFACE_ENABLED")

def test_scan_for_auth(dev, apdev):
    """cfg80211 workaround with scan-for-auth"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    dev[0].scan_for_bss(apdev[0]['bssid'], freq="2412")
    # Block sme-connect radio work with an external radio work item, so that
    # SELECT_NETWORK can decide to use fast associate without a new scan while
    # cfg80211 still has the matching BSS entry, but the actual connection is
    # not yet started.
    id = dev[0].request("RADIO_WORK add block-work")
    ev = dev[0].wait_event(["EXT-RADIO-WORK-START"])
    if ev is None:
        raise Exception("Timeout while waiting radio work to start")
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                   wait_connect=False)
    # Clear cfg80211 BSS table.
    subprocess.call(['sudo', 'iw', dev[0].ifname, 'scan', 'trigger',
                     'freq', '2462', 'flush'])
    time.sleep(0.1)
    # Release blocking radio work to allow connection to go through with the
    # cfg80211 BSS entry missing.
    dev[0].request("RADIO_WORK done " + id)

    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Association with the AP timed out")
