#!/usr/bin/env python2
#
# Parallel VM test case executor
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import curses
import fcntl
import os
import subprocess
import sys
import time

def get_results():
    global vm
    started = []
    passed = []
    failed = []
    skipped = []
    for i in range(0, num_servers):
        lines = vm[i]['out'].splitlines()
        started += [ l for l in lines if l.startswith('START ') ]
        passed += [ l for l in lines if l.startswith('PASS ') ]
        failed += [ l for l in lines if l.startswith('FAIL ') ]
        skipped += [ l for l in lines if l.startswith('SKIP ') ]
    return (started, passed, failed, skipped)

def show_progress(scr):
    global num_servers
    global vm
    global dir
    global timestamp
    global tests

    total_tests = len(tests)

    scr.leaveok(1)
    scr.addstr(0, 0, "Parallel test execution status", curses.A_BOLD)
    for i in range(0, num_servers):
        scr.addstr(i + 1, 0, "VM %d:" % (i + 1), curses.A_BOLD)
        scr.addstr(i + 1, 10, "starting VM")
    scr.addstr(num_servers + 1, 0, "Total:", curses.A_BOLD)
    scr.addstr(num_servers + 1, 20, "TOTAL={} STARTED=0 PASS=0 FAIL=0 SKIP=0".format(total_tests))
    scr.refresh()

    while True:
        running = False
        updated = False
        for i in range(0, num_servers):
            if not vm[i]['proc']:
                continue
            if vm[i]['proc'].poll() is not None:
                vm[i]['proc'] = None
                scr.move(i + 1, 10)
                scr.clrtoeol()
                log = '{}/{}.srv.{}/console'.format(dir, timestamp, i + 1)
                with open(log, 'r') as f:
                    if "Kernel panic" in f.read():
                        scr.addstr("kernel panic")
                    else:
                        scr.addstr("completed run")
                updated = True
                continue

            running = True
            try:
                err = vm[i]['proc'].stderr.read()
                vm[i]['err'] += err
            except:
                pass

            try:
                out = vm[i]['proc'].stdout.read()
                if "READY" in out or "PASS" in out or "FAIL" in out or "SKIP" in out:
                    if not tests:
                        vm[i]['proc'].stdin.write('\n')
                    else:
                        name = tests.pop(0)
                        vm[i]['proc'].stdin.write(name + '\n')
            except:
                continue
            #print("VM {}: '{}'".format(i, out))
            vm[i]['out'] += out
            lines = vm[i]['out'].splitlines()
            last = [ l for l in lines if l.startswith('START ') ]
            if len(last) > 0:
                try:
                    info = last[-1].split(' ')
                    scr.move(i + 1, 10)
                    scr.clrtoeol()
                    scr.addstr(info[1])
                    updated = True
                except:
                    pass

        if not running:
            break

        if updated:
            (started, passed, failed, skipped) = get_results()
            scr.move(num_servers + 1, 10)
            scr.clrtoeol()
            scr.addstr("{} %".format(int(100.0 * (len(passed) + len(failed) + len(skipped)) / total_tests)))
            scr.addstr(num_servers + 1, 20, "TOTAL={} STARTED={} PASS={} FAIL={} SKIP={}".format(total_tests, len(started), len(passed), len(failed), len(skipped)))
            if len(failed) > 0:
                scr.move(num_servers + 2, 0)
                scr.clrtoeol()
                scr.addstr("Failed test cases: ")
                for f in failed:
                    scr.addstr(f.split(' ')[1])
                    scr.addstr(' ')
            scr.refresh()

        time.sleep(0.5)

    scr.refresh()
    time.sleep(0.3)

def main():
    global num_servers
    global vm
    global dir
    global timestamp
    global tests

    if len(sys.argv) < 2:
        sys.exit("Usage: %s <number of VMs> [--codecov] [params..]" % sys.argv[0])
    num_servers = int(sys.argv[1])
    if num_servers < 1:
        sys.exit("Too small number of VMs")

    timestamp = int(time.time())

    if len(sys.argv) > 2 and sys.argv[2] == "--codecov":
        idx = 3
        print "Code coverage - build separate binaries"
        logdir = "/tmp/hwsim-test-logs/" + str(timestamp)
        os.makedirs(logdir)
        subprocess.check_call(['./build-codecov.sh', logdir])
        codecov_args = ['--codecov_dir', logdir]
        codecov = True
    else:
        idx = 2
        codecov_args = []
        codecov = False

    tests = []
    cmd = [ '../run-tests.py', '-L' ] + sys.argv[idx:]
    lst = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    for l in lst.stdout.readlines():
        name = l.split(' ')[0]
        tests.append(name)
    if len(tests) == 0:
        sys.exit("No test cases selected")
    if '-f' in sys.argv[idx:]:
        extra_args = sys.argv[idx:]
    else:
        extra_args = [x for x in sys.argv[idx:] if x not in tests]

    dir = '/tmp/hwsim-test-logs'
    try:
        os.mkdir(dir)
    except:
        pass

    vm = {}
    for i in range(0, num_servers):
        print("\rStarting virtual machine {}/{}".format(i + 1, num_servers)),
        cmd = ['./vm-run.sh', '--timestamp', str(timestamp),
               '--ext', 'srv.%d' % (i + 1),
               '-i'] + codecov_args + extra_args
        vm[i] = {}
        vm[i]['proc'] = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        vm[i]['out'] = ""
        vm[i]['err'] = ""
        for stream in [ vm[i]['proc'].stdout, vm[i]['proc'].stderr ]:
            fd = stream.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    print

    curses.wrapper(show_progress)

    with open('{}/{}-parallel.log'.format(dir, timestamp), 'w') as f:
        for i in range(0, num_servers):
            f.write('VM {}\n{}\n{}\n'.format(i, vm[i]['out'], vm[i]['err']))

    (started, passed, failed, skipped) = get_results()

    if len(failed) > 0:
        print "Failed test cases:"
        for f in failed:
            print f.split(' ')[1],
        print
    print("TOTAL={} PASS={} FAIL={} SKIP={}".format(len(started), len(passed), len(failed), len(skipped)))
    print "Logs: " + dir + '/' + str(timestamp)

    for i in range(0, num_servers):
        log = '{}/{}.srv.{}/console'.format(dir, timestamp, i + 1)
        with open(log, 'r') as f:
            if "Kernel panic" in f.read():
                print "Kernel panic in " + log

    if codecov:
        print "Code coverage - preparing report"
        for i in range(num_servers):
            subprocess.check_call(['./process-codecov.sh',
                                   logdir + ".srv.%d" % (i + 1),
                                   str(i)])
        subprocess.check_call(['./combine-codecov.sh', logdir])
        print "file://%s/index.html" % logdir

if __name__ == "__main__":
    main()
