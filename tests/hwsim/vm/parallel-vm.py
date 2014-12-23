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
    global first_run_failures

    total_tests = len(tests)

    scr.leaveok(1)
    scr.addstr(0, 0, "Parallel test execution status", curses.A_BOLD)
    for i in range(0, num_servers):
        scr.addstr(i + 1, 0, "VM %d:" % (i + 1), curses.A_BOLD)
        scr.addstr(i + 1, 10, "starting VM")
    scr.addstr(num_servers + 1, 0, "Total:", curses.A_BOLD)
    scr.addstr(num_servers + 1, 20, "TOTAL={} STARTED=0 PASS=0 FAIL=0 SKIP=0".format(total_tests))
    scr.refresh()

    completed_first_pass = False
    rerun_tests = []

    while True:
        running = False
        first_running = False
        updated = False

        for i in range(0, num_servers):
            if completed_first_pass:
                continue
            if vm[i]['first_run_done']:
                continue
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
                        scr.addstr("unexpected exit")
                updated = True
                continue

            running = True
            first_running = True
            try:
                err = vm[i]['proc'].stderr.read()
                vm[i]['err'] += err
            except:
                pass

            try:
                out = vm[i]['proc'].stdout.read()
                vm[i]['out'] += out
                if "READY" in out or "PASS" in out or "FAIL" in out or "SKIP" in out:
                    scr.move(i + 1, 10)
                    scr.clrtoeol()
                    updated = True
                    if not tests:
                        vm[i]['first_run_done'] = True
                        scr.addstr("completed first round")
                        continue
                    else:
                        name = tests.pop(0)
                        vm[i]['proc'].stdin.write(name + '\n')
                        scr.addstr(name)
            except:
                pass

        if not first_running and not completed_first_pass:
            if tests:
                raise Exception("Unexpected test cases remaining from first round")
            completed_first_pass = True
            (started, passed, failed, skipped) = get_results()
            for f in failed:
                name = f.split(' ')[1]
                rerun_tests.append(name)
                first_run_failures.append(name)

        for i in range(num_servers):
            if not completed_first_pass:
                continue
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
                ready = False
                if vm[i]['first_run_done']:
                    vm[i]['first_run_done'] = False
                    ready = True
                else:
                    out = vm[i]['proc'].stdout.read()
                    vm[i]['out'] += out
                    if "READY" in out or "PASS" in out or "FAIL" in out or "SKIP" in out:
                        ready = True
                if ready:
                    scr.move(i + 1, 10)
                    scr.clrtoeol()
                    updated = True
                    if not rerun_tests:
                        vm[i]['proc'].stdin.write('\n')
                        scr.addstr("shutting down")
                    else:
                        name = rerun_tests.pop(0)
                        vm[i]['proc'].stdin.write(name + '\n')
                        scr.addstr(name + "(*)")
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

            scr.move(0, 35)
            scr.clrtoeol()
            if rerun_tests:
                scr.addstr("(RETRY FAILED %d)" % len(rerun_tests))
            elif first_run_failures:
                scr.addstr("(RETRY FAILED)")

            scr.refresh()

        time.sleep(0.25)

    scr.refresh()
    time.sleep(0.3)

def main():
    global num_servers
    global vm
    global dir
    global timestamp
    global tests
    global first_run_failures

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

    first_run_failures = []
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

    if num_servers > 2 and len(tests) > 100:
        # Move test cases with long duration to the beginning as an
        # optimization to avoid last part of the test execution running a long
        # duration test case on a single VM while all other VMs have already
        # completed their work.
        long = [ "ap_roam_open",
                 "ap_hs20_fetch_osu_stop",
                 "ap_roam_wpa2_psk",
                 "ibss_wpa_none_ccmp",
                 "nfc_wps_er_handover_pk_hash_mismatch_sta",
                 "go_neg_peers_force_diff_freq",
                 "p2p_cli_invite",
                 "sta_ap_scan_2b",
                 "ap_pmf_sta_unprot_deauth_burst",
                 "ap_bss_add_remove_during_ht_scan",
                 "wext_scan_hidden",
                 "autoscan_exponential",
                 "nfc_p2p_client",
                 "wnm_bss_keep_alive",
                 "ap_inactivity_disconnect",
                 "scan_bss_expiration_age",
                 "autoscan_periodic",
                 "discovery_group_client",
                 "concurrent_p2pcli",
                 "ap_bss_add_remove",
                 "wpas_ap_wps",
                 "wext_pmksa_cache",
                 "ibss_wpa_none",
                 "ap_ht_40mhz_intolerant_ap",
                 "ibss_rsn",
                 "discovery_pd_retries",
                 "ap_wps_setup_locked_timeout",
                 "ap_vht160",
                 "dfs_radar",
                 "dfs",
                 "grpform_cred_ready_timeout",
                 "ap_wps_pbc_timeout" ]
        for l in long:
            if l in tests:
                tests.remove(l)
                tests.insert(0, l)

    vm = {}
    for i in range(0, num_servers):
        print("\rStarting virtual machine {}/{}".format(i + 1, num_servers)),
        cmd = ['./vm-run.sh', '--delay', str(i), '--timestamp', str(timestamp),
               '--ext', 'srv.%d' % (i + 1),
               '-i'] + codecov_args + extra_args
        vm[i] = {}
        vm[i]['first_run_done'] = False
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

    if first_run_failures:
        print "Failed test cases:"
        for f in first_run_failures:
            print f,
        print
    double_failed = []
    for f in failed:
        name = f.split(' ')[1]
        double_failed.append(name)
    for test in first_run_failures:
        double_failed.remove(test)
    if failed and not double_failed:
        print "All failed cases passed on retry"
    elif double_failed:
        print "Failed even on retry:"
        for f in double_failed:
            print f,
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

    if double_failed:
        sys.exit(2)
    if failed:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
