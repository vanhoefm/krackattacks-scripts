#!/usr/bin/python
#
# Radio work tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()
import subprocess

import hostapd

def test_ext_radio_work(dev, apdev):
    """External radio work item"""
    id = dev[0].request("RADIO_WORK add test-work-a")
    if "FAIL" in id:
        raise Exception("Failed to add radio work")
    id2 = dev[0].request("RADIO_WORK add test-work-b freq=2417")
    if "FAIL" in id2:
        raise Exception("Failed to add radio work")
    id3 = dev[0].request("RADIO_WORK add test-work-c")
    if "FAIL" in id3:
        raise Exception("Failed to add radio work")

    ev = dev[0].wait_event(["EXT-RADIO-WORK-START"])
    if ev is None:
        raise Exception("Timeout while waiting radio work to start")
    if "EXT-RADIO-WORK-START " + id not in ev:
        raise Exception("Unexpected radio work start id")

    items = dev[0].request("RADIO_WORK show")
    if "ext:test-work-a@wlan0:0:1:" not in items:
        logger.info("Pending radio work items:\n" + items)
        raise Exception("Radio work item(a) missing from the list")
    if "ext:test-work-b@wlan0:2417:0:" not in items:
        logger.info("Pending radio work items:\n" + items)
        raise Exception("Radio work item(b) missing from the list")
    if "ext:test-work-c@wlan0:0:0:" not in items:
        logger.info("Pending radio work items:\n" + items)
        raise Exception("Radio work item(c) missing from the list")

    dev[0].request("RADIO_WORK done " + id2)
    dev[0].request("RADIO_WORK done " + id)

    ev = dev[0].wait_event(["EXT-RADIO-WORK-START"])
    if ev is None:
        raise Exception("Timeout while waiting radio work to start")
    if "EXT-RADIO-WORK-START " + id3 not in ev:
        raise Exception("Unexpected radio work start id")
    dev[0].request("RADIO_WORK done " + id3)
    items = dev[0].request("RADIO_WORK show")
    if "ext:" in items:
        logger.info("Pending radio work items:\n" + items)
        raise Exception("Unexpected remaining radio work item")
