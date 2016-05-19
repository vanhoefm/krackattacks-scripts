#!/usr/bin/env python2
#
# Show/check devices
# Copyright (c) 2016, Tieto Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import traceback
import config
import os
import sys
import getopt
import re

import logging
logger = logging.getLogger()

import rutils
from remotehost import Host
from wpasupplicant import WpaSupplicant
import hostapd

def show_devices(devices, setup_params):
    """Show/check available devices"""
    print "Devices:"
    for device in devices:
        host = rutils.get_host(devices, device['name'])
        # simple check if authorized_keys works correctly
        status, buf = host.execute(["id"])
        if status != 0:
            print "[" + host.name + "] - ssh communication:  FAILED"
            continue
        else:
            print "[" + host.name + "] - ssh communication: OK"
        # check setup_hw works correctly
        try:
            setup_hw = setup_params['setup_hw']
            try:
                restart_device = setup_params['restart_device']
            except:
                restart_device = "0"
            host.execute([setup_hw, "-I", host.ifname, "-R", restart_device])
        except:
            pass
        # show uname
        status, buf = host.execute(["uname", "-s", "-n", "-r", "-m", "-o"])
        print "\t" + buf
        # show ifconfig
        status, buf = host.execute(["ifconfig", host.ifname])
        if status != 0:
            print "\t" + host.ifname + " failed\n"
            continue
        lines = buf.splitlines()
        for line in lines:
            print "\t" + line
        # check hostapd, wpa_supplicant, iperf exist
        status, buf = host.execute([setup_params['wpa_supplicant'], "-v"])
        if status != 0:
            print "\t" + setup_params['wpa_supplicant'] + " not find\n"
            continue
        lines = buf.splitlines()
        for line in lines:
            print "\t" + line
        print ""
        status, buf = host.execute([setup_params['hostapd'], "-v"])
        if status != 1:
            print "\t" + setup_params['hostapd'] + " not find\n"
            continue
        lines = buf.splitlines()
        for line in lines:
            print "\t" + line
        print ""
        status, buf = host.execute([setup_params['iperf'], "-v"])
        if status != 0 and status != 1:
            print "\t" + setup_params['iperf'] + " not find\n"
            continue
        lines = buf.splitlines()
        for line in lines:
            print "\t" + line
        print ""

def check_device(devices, setup_params, dev_name, monitor=False):
    host = rutils.get_host(devices, dev_name)
    # simple check if authorized_keys works correctly
    status, buf = host.execute(["id"])
    if status != 0:
        raise Exception(dev_name + " - ssh communication FAILED: " + buf)

    ifaces = re.split('; | |, ', host.ifname)
    # try to setup host/ifaces
    for iface in ifaces:
        try:
            setup_hw = setup_params['setup_hw']
            try:
                restart_device = setup_params['restart_device']
            except:
                restart_device = "0"
            host.execute(setup_hw + " -I " + iface + " -R " + restart_device)
        except:
            pass

    # check interfaces (multi for monitor)
    for iface in ifaces:
        status, buf = host.execute(["ifconfig", iface])
        if status != 0:
            raise Exception(dev_name + " ifconfig " + iface + " failed: " + buf)

    # monitor doesn't need wpa_supplicant/hostapd ...
    if monitor == True:
        return

    status, buf = host.execute(["ls", "-l", setup_params['wpa_supplicant']])
    if status != 0:
        raise Exception(dev_name + " - wpa_supplicant: " + buf)

    status, buf = host.execute(["ls", "-l", setup_params['hostapd']])
    if status != 0:
        raise Exception(dev_name + " - hostapd: " + buf)

    status, buf = host.execute(["which", setup_params['iperf']])
    if status != 0:
        raise Exception(dev_name + " - iperf: " + buf)

    status, buf = host.execute(["which", "tshark"])
    if status != 0:
        logger.debug(dev_name + " - tshark: " + buf)

def check_devices(devices, setup_params, refs, duts, monitors):
    """Check duts/refs/monitors devices"""
    for dut in duts:
        check_device(devices, setup_params, dut)
    for ref in refs:
        check_device(devices, setup_params, ref)
    for monitor in monitors:
        if monitor == "all":
            continue
        check_device(devices, setup_params, monitor, monitor=True)
