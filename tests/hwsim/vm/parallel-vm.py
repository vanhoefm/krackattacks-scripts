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

    scr.leaveok(1)
    scr.addstr(0, 0, "Parallel test execution status", curses.A_BOLD)
    for i in range(0, num_servers):
        scr.addstr(i + 1, 0, "VM %d:" % (i + 1), curses.A_BOLD)
        scr.addstr(i + 1, 20, "starting VM")
    scr.addstr(num_servers + 1, 0, "Total:", curses.A_BOLD)
    scr.refresh()

    while True:
        running = False
        updated = False
        for i in range(0, num_servers):
            if not vm[i]['proc']:
                continue
            if vm[i]['proc'].poll() is not None:
                vm[i]['proc'] = None
                vm[i]['done'] = vm[i]['total']
                scr.move(i + 1, 10)
                scr.clrtoeol()
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
            except:
                continue
            #print("VM {}: '{}'".format(i, out))
            vm[i]['out'] += out
            lines = vm[i]['out'].splitlines()
            last = [ l for l in lines if l.startswith('START ') ]
            if len(last) > 0:
                try:
                    info = last[-1].split(' ')
                    vm[i]['pos'] = info[2]
                    pos = info[2].split('/')
                    if int(pos[0]) > 0:
                        vm[i]['done'] = int(pos[0]) - 1
                    vm[i]['total'] = int(pos[1])
                    p = float(pos[0]) / float(pos[1]) * 100.0
                    scr.move(i + 1, 10)
                    scr.clrtoeol()
                    scr.addstr("{} %".format(int(p)))
                    scr.addstr(i + 1, 20, info[1])
                    updated = True
                except:
                    pass
            else:
                vm[i]['pos'] = ''

        if not running:
            break

        if updated:
            done = 0
            total = 0
            for i in range(0, num_servers):
                done += vm[i]['done']
                total += vm[i]['total']
            scr.move(num_servers + 1, 10)
            scr.clrtoeol()
            if total > 0:
                scr.addstr("{} %".format(int(100.0 * done / total)))

            (started, passed, failed, skipped) = get_results()
            scr.addstr(num_servers + 1, 20, "TOTAL={} PASS={} FAIL={} SKIP={}".format(len(started), len(passed), len(failed), len(skipped)))
            if len(failed) > 0:
                scr.move(num_servers + 2, 0)
                scr.clrtoeol()
                scr.addstr("Failed test cases: ")
                for f in failed:
                    scr.addstr(f.split(' ')[1])
                    scr.addstr(' ')
            scr.refresh()

        time.sleep(1)

def main():
    global num_servers
    global vm

    if len(sys.argv) < 2:
        sys.exit("Usage: %s <number of VMs> [params..]" % sys.argv[0])
    num_servers = int(sys.argv[1])
    if num_servers < 1:
        sys.exit("Too small number of VMs")

    timestamp = int(time.time())
    vm = {}
    for i in range(0, num_servers):
        print("\rStarting virtual machine {}/{}".format(i + 1, num_servers)),
        cmd = ['./vm-run.sh', '--timestamp', str(timestamp),
               '--ext', 'srv.%d' % (i + 1),
               '--split', '%d/%d' % (i + 1, num_servers)] + sys.argv[2:]
        vm[i] = {}
        vm[i]['proc'] = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        vm[i]['out'] = ""
        vm[i]['err'] = ""
        vm[i]['pos'] = ""
        vm[i]['done'] = 0
        vm[i]['total'] = 0
        for stream in [ vm[i]['proc'].stdout, vm[i]['proc'].stderr ]:
            fd = stream.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    print

    curses.wrapper(show_progress)

    dir = '/tmp/hwsim-test-logs'
    try:
        os.mkdir(dir)
    except:
        pass
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

if __name__ == "__main__":
    main()
