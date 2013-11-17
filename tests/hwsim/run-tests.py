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
import argparse
import subprocess

import logging
logger = logging.getLogger()

sys.path.append('../../wpaspy')

from wpasupplicant import WpaSupplicant
from hostapd import HostapdGlobal
from check_kernel import check_kernel
from wlantest import Wlantest

def reset_devs(dev, apdev):
    ok = True
    for d in dev:
        try:
            d.reset()
        except Exception, e:
            logger.info("Failed to reset device " + d.ifname)
            print str(e)
            ok = False
    try:
        hapd = HostapdGlobal()
        hapd.remove('wlan3-3')
        hapd.remove('wlan3-2')
        for ap in apdev:
            hapd.remove(ap['ifname'])
    except Exception, e:
        logger.info("Failed to remove hostapd interface")
        print str(e)
        ok = False
    return ok

def report(conn, prefill, build, commit, run, test, result, duration):
    if conn:
        if not build:
            build = ''
        if not commit:
            commit = ''
        if prefill:
            conn.execute('DELETE FROM results WHERE test=? AND run=? AND result=?', (test, run, 'NOTRUN'))
        sql = "INSERT INTO results(test,result,run,time,duration,build,commitid) VALUES(?, ?, ?, ?, ?, ?, ?)"
        params = (test, result, run, time.time(), duration, build, commit)
        try:
            conn.execute(sql, params)
            conn.commit()
        except Exception, e:
            print "sqlite: " + str(e)
            print "sql: %r" % (params, )

class DataCollector(object):
    def __init__(self, logdir, testname, tracing, dmesg):
        self._logdir = logdir
        self._testname = testname
        self._tracing = tracing
        self._dmesg = dmesg
    def __enter__(self):
        if self._tracing:
            output = os.path.join(self._logdir, '%s.dat' % (self._testname, ))
            self._trace_cmd = subprocess.Popen(['sudo', 'trace-cmd', 'record', '-o', output, '-e', 'mac80211', '-e', 'cfg80211', 'sh', '-c', 'echo STARTED ; read l'],
                                               stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE,
                                               stderr=open('/dev/null', 'w'),
                                               cwd=self._logdir)
            l = self._trace_cmd.stdout.read(7)
            while not 'STARTED' in l:
                l += self._trace_cmd.stdout.read(1)
    def __exit__(self, type, value, traceback):
        if self._tracing:
            self._trace_cmd.stdin.write('DONE\n')
            self._trace_cmd.wait()
        if self._dmesg:
            output = os.path.join(self._logdir, '%s.dmesg' % (self._testname, ))
            subprocess.call(['sudo', 'dmesg', '-c'], stdout=open(output, 'w'))

def rename_log(logdir, basename, testname, dev):
    try:
        import getpass
        srcname = os.path.join(logdir, basename)
        dstname = os.path.join(logdir, testname + '.' + basename)
        num = 0
        while os.path.exists(dstname):
            dstname = os.path.join(logdir,
                                   testname + '.' + basename + '-' + str(num))
            num = num + 1
        os.rename(srcname, dstname)
        if dev:
            dev.relog()
            subprocess.call(['sudo', 'chown', '-f', getpass.getuser(), srcname])
    except Exception, e:
        logger.info("Failed to rename log files")
        logger.info(e)

def main():
    tests = []
    test_modules = []
    for t in os.listdir("."):
        m = re.match(r'(test_.*)\.py$', t)
        if m:
            logger.debug("Import test cases from " + t)
            mod = __import__(m.group(1))
            test_modules.append(mod.__name__.replace('test_', '', 1))
            for s in dir(mod):
                if s.startswith("test_"):
                    func = mod.__dict__.get(s)
                    tests.append(func)
    test_names = list(set([t.__name__.replace('test_', '', 1) for t in tests]))

    run = None

    parser = argparse.ArgumentParser(description='hwsim test runner')
    parser.add_argument('--logdir', metavar='<directory>',
                        help='log output directory for all other options, ' +
                             'must be given if other log options are used')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-d', const=logging.DEBUG, action='store_const',
                       dest='loglevel', default=logging.INFO,
                       help="verbose debug output")
    group.add_argument('-q', const=logging.WARNING, action='store_const',
                       dest='loglevel', help="be quiet")

    parser.add_argument('-S', metavar='<sqlite3 db>', dest='database',
                        help='database to write results to')
    parser.add_argument('--prefill-tests', action='store_true', dest='prefill',
                        help='prefill test database with NOTRUN before all tests')
    parser.add_argument('--commit', metavar='<commit id>',
                        help='commit ID, only for database')
    parser.add_argument('-b', metavar='<build>', dest='build', help='build ID')
    parser.add_argument('-L', action='store_true', dest='update_tests_db',
                        help='List tests (and update descriptions in DB)')
    parser.add_argument('-T', action='store_true', dest='tracing',
                        help='collect tracing per test case (in log directory)')
    parser.add_argument('-D', action='store_true', dest='dmesg',
                        help='collect dmesg per test case (in log directory)')
    parser.add_argument('--shuffle-tests', action='store_true',
                        dest='shuffle_tests',
                        help='Shuffle test cases to randomize order')
    parser.add_argument('--no-reset', action='store_true', dest='no_reset',
                        help='Do not reset devices at the end of the test')
    parser.add_argument('-f', dest='testmodules', metavar='<test module>',
                        help='execute only tests from these test modules',
                        type=str, choices=[[]] + test_modules, nargs='+')
    parser.add_argument('tests', metavar='<test>', nargs='*', type=str,
                        help='tests to run (only valid without -f)',
                        choices=[[]] + test_names)

    args = parser.parse_args()

    if args.tests and args.testmodules:
        print 'Invalid arguments - both test module and tests given'
        sys.exit(2)

    if not args.logdir:
        if os.path.exists('logs/current'):
            args.logdir = 'logs/current'
        else:
            args.logdir = 'logs'

    # Write debug level log to a file and configurable verbosity to stdout
    logger.setLevel(logging.DEBUG)

    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(args.loglevel)
    logger.addHandler(stdout_handler)

    file_name = os.path.join(args.logdir, 'run-tests.log')
    log_handler = logging.FileHandler(file_name)
    log_handler.setLevel(logging.DEBUG)
    fmt = "%(asctime)s %(levelname)s %(message)s"
    log_formatter = logging.Formatter(fmt)
    log_handler.setFormatter(log_formatter)
    logger.addHandler(log_handler)

    if args.database:
        import sqlite3
        conn = sqlite3.connect(args.database)
        conn.execute('CREATE TABLE IF NOT EXISTS results (test,result,run,time,duration,build,commitid)')
        conn.execute('CREATE TABLE IF NOT EXISTS tests (test,description)')
    else:
        conn = None

    if conn:
        run = int(time.time())

    if args.update_tests_db:
        for t in tests:
            name = t.__name__.replace('test_', '', 1)
            print name + " - " + t.__doc__
            if conn:
                sql = 'INSERT OR REPLACE INTO tests(test,description) VALUES (?, ?)'
                params = (name, t.__doc__)
                try:
                    conn.execute(sql, params)
                except Exception, e:
                    print "sqlite: " + str(e)
                    print "sql: %r" % (params,)
        if conn:
            conn.commit()
            conn.close()
        sys.exit(0)


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

    # make sure nothing is left over from previous runs
    # (if there were any other manual runs or we crashed)
    if not reset_devs(dev, apdev):
        if conn:
            conn.close()
            conn = None
        sys.exit(1)

    if args.dmesg:
        subprocess.call(['sudo', 'dmesg', '-c'], stdout=open('/dev/null', 'w'))

    tests_to_run = []
    for t in tests:
        name = t.__name__.replace('test_', '', 1)
        if args.tests:
            if not name in args.tests:
                continue
        if args.testmodules:
            if not t.__module__.replace('test_', '', 1) in args.testmodules:
                continue
        tests_to_run.append(t)

    if conn and args.prefill:
        for t in tests_to_run:
            name = t.__name__.replace('test_', '', 1)
            report(conn, False, args.build, args.commit, run, name, 'NOTRUN', 0)

    if args.shuffle_tests:
        from random import shuffle
        shuffle(tests_to_run)

    for t in tests_to_run:
        name = t.__name__.replace('test_', '', 1)
        if log_handler:
            log_handler.stream.close()
            logger.removeHandler(log_handler)
            file_name = os.path.join(args.logdir, name + '.log')
            log_handler = logging.FileHandler(file_name)
            log_handler.setLevel(logging.DEBUG)
            log_handler.setFormatter(log_formatter)
            logger.addHandler(log_handler)

        reset_ok = True
        with DataCollector(args.logdir, name, args.tracing, args.dmesg):
            logger.info("START " + name)
            if args.loglevel == logging.WARNING:
                print "START " + name
                sys.stdout.flush()
            if t.__doc__:
                logger.info("Test: " + t.__doc__)
            start = datetime.now()
            for d in dev:
                try:
                    d.request("NOTE TEST-START " + name)
                except Exception, e:
                    logger.info("Failed to issue TEST-START before " + name + " for " + d.ifname)
                    logger.info(e)
                    print "FAIL " + name + " - could not start test"
                    if conn:
                        conn.close()
                        conn = None
                    sys.exit(1)
            try:
                if t.func_code.co_argcount > 1:
                    res = t(dev, apdev)
                else:
                    res = t(dev)
                if res == "skip":
                    result = "SKIP"
                else:
                    result = "PASS"
            except Exception, e:
                logger.info(e)
                result = "FAIL"
            for d in dev:
                try:
                    d.request("NOTE TEST-STOP " + name)
                except Exception, e:
                    logger.info("Failed to issue TEST-STOP after {} for {}".format(name, d.ifname))
                    logger.info(e)
                    result = "FAIL"
            if args.no_reset:
                print "Leaving devices in current state"
            else:
                reset_ok = reset_devs(dev, apdev)

            for i in range(0, 3):
                rename_log(args.logdir, 'log' + str(i), name, dev[i])

            try:
                hapd = HostapdGlobal()
            except Exception, e:
                print "Failed to connect to hostapd interface"
                print str(e)
                reset_ok = False
                result = "FAIL"
                hapd = None
            rename_log(args.logdir, 'hostapd', name, hapd)

            wt = Wlantest()
            rename_log(args.logdir, 'hwsim0.pcapng', name, wt)
            rename_log(args.logdir, 'hwsim0', name, wt)

        end = datetime.now()
        diff = end - start

        if result == 'PASS' and args.dmesg:
            if not check_kernel(os.path.join(args.logdir, name + '.dmesg')):
                result = 'FAIL'

        if result == 'PASS':
            passed.append(name)
        elif result == 'SKIP':
            skipped.append(name)
        else:
            failed.append(name)

        report(conn, args.prefill, args.build, args.commit, run, name, result, diff.total_seconds())
        result = "{} {} {} {}".format(result, name, diff.total_seconds(), end)
        logger.info(result)
        if args.loglevel == logging.WARNING:
            print result
            sys.stdout.flush()

        if not reset_ok:
            print "Terminating early due to device reset failure"
            break

    if log_handler:
        log_handler.stream.close()
        logger.removeHandler(log_handler)
        file_name = os.path.join(args.logdir, 'run-tests.log')
        log_handler = logging.FileHandler(file_name)
        log_handler.setLevel(logging.DEBUG)
        log_handler.setFormatter(log_formatter)
        logger.addHandler(log_handler)

    if conn:
        conn.close()

    if len(failed):
        logger.info("passed {} test case(s)".format(len(passed)))
        logger.info("skipped {} test case(s)".format(len(skipped)))
        logger.info("failed tests: " + ' '.join(failed))
        if args.loglevel == logging.WARNING:
            print "failed tests: " + ' '.join(failed)
        sys.exit(1)
    logger.info("passed all {} test case(s)".format(len(passed)))
    if len(skipped):
        logger.info("skipped {} test case(s)".format(len(skipped)))
    if args.loglevel == logging.WARNING:
        print "passed all {} test case(s)".format(len(passed))
        if len(skipped):
            print "skipped {} test case(s)".format(len(skipped))

if __name__ == "__main__":
    main()
