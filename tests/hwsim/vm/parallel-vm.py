#!/usr/bin/env python2
#
# Parallel VM test case executor
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import fcntl
import os
import subprocess
import sys
import time

def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: %s <number of VMs> [params..]" % sys.argv[0])
    num_servers = int(sys.argv[1])
    if num_servers < 1:
        sys.exit("Too small number of VMs")

    timestamp = int(time.time())
    vm = {}
    for i in range(0, num_servers):
        print("\rStarting virtual machine {}/{}".format(i + 1, num_servers)),
        cmd = ['./vm-run.sh', '--ext', 'srv.%d' % (i + 1),
               '--split', '%d/%d' % (i + 1, num_servers)] + sys.argv[2:]
        vm[i] = {}
        vm[i]['proc'] = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        vm[i]['out'] = ""
        vm[i]['err'] = ""
        vm[i]['pos'] = ""
        for stream in [ vm[i]['proc'].stdout, vm[i]['proc'].stderr ]:
            fd = stream.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    print

    while True:
        running = False
        updated = False
        for i in range(0, num_servers):
            if not vm[i]['proc']:
                continue
            if vm[i]['proc'].poll() is not None:
                vm[i]['proc'] = None
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
                    pos = last[-1].split(' ')[2]
                    vm[i]['pos'] = pos
                    updated = True
                except:
                    pass
            else:
                vm[i]['pos'] = ''

        if not running:
            print("All VMs completed")
            break

        if updated:
            status = {}
            for i in range(0, num_servers):
                if not vm[i]['proc']:
                    continue
                status[i] = vm[i]['pos']
            print status

        time.sleep(1)

    dir = '/tmp/hwsim-test-logs'
    try:
        os.mkdir(dir)
    except:
        pass
    with open('{}/{}-parallel.log'.format(dir, timestamp), 'w') as f:
        for i in range(0, num_servers):
            f.write('VM {}\n{}\n{}\n'.format(i, vm[i]['out'], vm[i]['err']))

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

    if len(failed) > 0:
        print "Failed test cases:"
        for f in failed:
            print f.split(' ')[1],
        print
    print("TOTAL={} PASS={} FAIL={} SKIP={}".format(len(started), len(passed), len(failed), len(skipped)))

if __name__ == "__main__":
    main()
