#!/usr/bin/python
#
# AP tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import re
import sys
import time
from datetime import datetime

import logging
logger = logging.getLogger(__name__)

from wpasupplicant import WpaSupplicant
from hostapd import HostapdGlobal

def reset_devs(dev, apdev):
    hapd = HostapdGlobal()
    for d in dev:
        try:
            d.reset()
        except Exception, e:
            logger.info("Failed to reset device " + d.ifname)
            print str(e)
    for ap in apdev:
        hapd.remove(ap['ifname'])

def main():
    test_file = None
    error_file = None
    log_file = None
    results_file = None
    idx = 1
    print_res = False
    if len(sys.argv) > 1 and sys.argv[1] == '-d':
        logging.basicConfig(level=logging.DEBUG)
        idx = idx + 1
    elif len(sys.argv) > 1 and sys.argv[1] == '-q':
        logging.basicConfig(level=logging.WARNING)
        print_res = True
        idx = idx + 1
    elif len(sys.argv) > 2 and sys.argv[1] == '-l':
        log_file = sys.argv[2]
        logging.basicConfig(filename=log_file,level=logging.DEBUG)
        idx = idx + 2
    else:
        logging.basicConfig(level=logging.INFO)

    while len(sys.argv) > idx:
        if len(sys.argv) > idx + 1 and sys.argv[idx] == '-e':
            error_file = sys.argv[idx + 1]
            idx = idx + 2
        elif len(sys.argv) > idx + 1 and sys.argv[idx] == '-r':
            results_file = sys.argv[idx + 1]
            idx = idx + 2
        elif len(sys.argv) > idx + 1 and sys.argv[idx] == '-f':
            test_file = sys.argv[idx + 1]
            idx = idx + 2
        else:
            break

    tests = []
    for t in os.listdir("."):
        m = re.match(r'(test_.*)\.py$', t)
        if m:
            if test_file and test_file not in t:
                continue
            logger.debug("Import test cases from " + t)
            mod = __import__(m.group(1))
            for s in dir(mod):
                if s.startswith("test_"):
                    func = mod.__dict__.get(s)
                    tests.append(func)

    if len(sys.argv) > 1 and sys.argv[1] == '-L':
        for t in tests:
            print t.__name__ + " - " + t.__doc__
        sys.exit(0)

    if len(sys.argv) > idx:
        test_filter = sys.argv[idx]
    else:
        test_filter = None

    dev0 = WpaSupplicant('wlan0', '/tmp/wpas-wlan0')
    dev1 = WpaSupplicant('wlan1', '/tmp/wpas-wlan1')
    dev2 = WpaSupplicant('wlan2', '/tmp/wpas-wlan2')
    dev = [ dev0, dev1, dev2 ]
    apdev = [ ]
    apdev.append({"ifname": 'wlan3', "bssid": "02:00:00:00:03:00"})
    apdev.append({"ifname": 'wlan4', "bssid": "02:00:00:00:04:00"})

    for d in dev:
        if not d.ping():
            logger.info(d.ifname + ": No response from wpa_supplicant")
            return
        logger.info("DEV: " + d.ifname + ": " + d.p2p_dev_addr())
    for ap in apdev:
        logger.info("APDEV: " + ap['ifname'])

    passed = []
    skipped = []
    failed = []

    for t in tests:
        if test_filter:
            if test_filter != t.__name__:
                continue
        reset_devs(dev, apdev)
        logger.info("START " + t.__name__)
        if log_file:
            print "START " + t.__name__
        if t.__doc__:
            logger.info("Test: " + t.__doc__)
        start = datetime.now()
        for d in dev:
            try:
                d.request("NOTE TEST-START " + t.__name__)
            except Exception, e:
                logger.info("Failed to issue TEST-START before " + t.__name__ + " for " + d.ifname)
                logger.info(e)
        try:
            if t.func_code.co_argcount > 1:
                res = t(dev, apdev)
            else:
                res = t(dev)
            end = datetime.now()
            diff = end - start
            if res == "skip":
                skipped.append(t.__name__)
                result = "SKIP "
            else:
                passed.append(t.__name__)
                result = "PASS "
            result = result + t.__name__ + " "
            result = result + str(diff.total_seconds()) + " " + str(end)
            logger.info(result)
            if log_file or print_res:
                print result
            if results_file:
                f = open(results_file, 'a')
                f.write(result + "\n")
                f.close()
        except Exception, e:
            end = datetime.now()
            diff = end - start
            logger.info(e)
            failed.append(t.__name__)
            result = "FAIL " + t.__name__ + " " + str(diff.total_seconds()) + " " + str(end)
            logger.info(result)
            if log_file:
                print result
            if results_file:
                f = open(results_file, 'a')
                f.write(result + "\n")
                f.close()
        for d in dev:
            try:
                d.request("NOTE TEST-STOP " + t.__name__)
            except Exception, e:
                logger.info("Failed to issue TEST-STOP after " + t.__name__ + " for " + d.ifname)
                logger.info(e)

    if not test_filter:
        reset_devs(dev, apdev)

    if len(failed):
        logger.info("passed " + str(len(passed)) + " test case(s)")
        logger.info("skipped " + str(len(skipped)) + " test case(s)")
        logger.info("failed tests: " + str(failed))
        if error_file:
            f = open(error_file, 'w')
            f.write(str(failed) + '\n')
            f.close()
        sys.exit(1)
    logger.info("passed all " + str(len(passed)) + " test case(s)")
    if len(skipped):
        logger.info("skipped " + str(len(skipped)) + " test case(s)")
    if log_file:
        print "passed all " + str(len(passed)) + " test case(s)"
        if len(skipped):
            print "skipped " + str(len(skipped)) + " test case(s)"

if __name__ == "__main__":
    main()
