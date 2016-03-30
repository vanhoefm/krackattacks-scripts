# Hotspot 2.0 filtering tests
# Copyright (c) 2015, Intel Deutschland GmbH
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
import hwsim_utils
import socket
import subprocess
import binascii
from utils import HwsimSkip, require_under_vm
import os
import time
from test_ap_hs20 import build_arp, build_na
import struct

class IPAssign(object):
    def __init__(self, iface, addr, ipv6=False):
        self._iface = iface
        self._addr = addr
        self._cmd = ['ip']
        if ipv6:
            self._cmd.append('-6')
        self._cmd.append('addr')
        self._ipv6 = ipv6
    def __enter__(self):
        subprocess.call(self._cmd + ['add', self._addr, 'dev', self._iface])
        if self._ipv6:
            # wait for DAD to finish
            while True:
                o = subprocess.check_output(self._cmd + ['show', 'tentative', 'dev', self._iface])
                if not self._addr in o:
                    break
                time.sleep(0.1)
    def __exit__(self, type, value, traceback):
        subprocess.call(self._cmd + ['del', self._addr, 'dev', self._iface])

def _test_ip4_gtk_drop(devs, apdevs, params, dst):
    require_under_vm()
    dev = devs[0]
    procfile = '/proc/sys/net/ipv4/conf/%s/drop_unicast_in_l2_multicast' % dev.ifname
    if not os.path.exists(procfile):
        raise HwsimSkip("kernel doesn't have capability")

    ap_params = { 'ssid': 'open', 'channel': '5' }
    hapd = hostapd.add_ap(apdevs[0], ap_params)
    dev.connect('open', key_mgmt="NONE", scan_freq="2432")

    with IPAssign(dev.ifname, '10.0.0.1/24'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("10.0.0.1", 12345))
        s.settimeout(0.1)

        pkt = dst
        pkt += hapd.own_addr().replace(':', '')
        pkt += '0800'
        pkt += '45000020786840004011ae600a0000040a000001'
        pkt += '30393039000c0000'
        pkt += '61736466' # "asdf"
        if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
            raise Exception("DATA_TEST_FRAME failed")

        data, addr = s.recvfrom(1024)
        if data != 'asdf':
            raise Exception("invalid data received")

        open(procfile, 'w').write('1')
        try:
            if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
                raise Exception("DATA_TEST_FRAME failed")

            try:
                print s.recvfrom(1024)
                raise Exception("erroneously received frame!")
            except socket.timeout:
                # this is the expected behaviour
                pass
        finally:
            open(procfile, 'w').write('0')

def test_ip4_gtk_drop_bcast(devs, apdevs, params):
    _test_ip4_gtk_drop(devs, apdevs, params, dst='ffffffffffff')

def test_ip4_gtk_drop_mcast(devs, apdevs, params):
    _test_ip4_gtk_drop(devs, apdevs, params, dst='ff0000000000')

def _test_ip6_gtk_drop(devs, apdevs, params, dst):
    require_under_vm()
    dev = devs[0]
    procfile = '/proc/sys/net/ipv6/conf/%s/drop_unicast_in_l2_multicast' % dev.ifname
    if not os.path.exists(procfile):
        raise HwsimSkip("kernel doesn't have capability")

    ap_params = { 'ssid': 'open', 'channel': '5' }
    hapd = hostapd.add_ap(apdevs[0], ap_params)
    dev.connect('open', key_mgmt="NONE", scan_freq="2432")

    with IPAssign(dev.ifname, 'fdaa::1/48', ipv6=True):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("fdaa::1", 12345))
        s.settimeout(0.1)

        pkt = dst
        pkt += hapd.own_addr().replace(':', '')
        pkt += '86dd'
        pkt += '60000000000c1140fdaa0000000000000000000000000002fdaa0000000000000000000000000001'
        pkt += '30393039000cde31'
        pkt += '61736466' # "asdf"
        if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
            raise Exception("DATA_TEST_FRAME failed")

        data, addr = s.recvfrom(1024)
        if data != 'asdf':
            raise Exception("invalid data received")

        open(procfile, 'w').write('1')
        try:
            if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
                raise Exception("DATA_TEST_FRAME failed")

            try:
                print s.recvfrom(1024)
                raise Exception("erroneously received frame!")
            except socket.timeout:
                # this is the expected behaviour
                pass
        finally:
            open(procfile, 'w').write('0')

def test_ip6_gtk_drop_bcast(devs, apdevs, params):
    _test_ip6_gtk_drop(devs, apdevs, params, dst='ffffffffffff')

def test_ip6_gtk_drop_mcast(devs, apdevs, params):
    _test_ip6_gtk_drop(devs, apdevs, params, dst='ff0000000000')

def test_ip4_drop_gratuitous_arp(devs, apdevs, params):
    require_under_vm()
    dev = devs[0]
    procfile = '/proc/sys/net/ipv4/conf/%s/drop_gratuitous_arp' % dev.ifname
    if not os.path.exists(procfile):
        raise HwsimSkip("kernel doesn't have capability")

    ap_params = { 'ssid': 'open', 'channel': '5' }
    hapd = hostapd.add_ap(apdevs[0], ap_params)
    dev.connect('open', key_mgmt="NONE", scan_freq="2432")

    with IPAssign(dev.ifname, '10.0.0.2/24'):
        # add an entry that can be updated by gratuitous ARP
        subprocess.call(['ip', 'neigh', 'add', '10.0.0.1', 'lladdr', '02:00:00:00:00:ff', 'nud', 'reachable', 'dev', dev.ifname])
        # wait for lock-time
        time.sleep(1)
        try:
            ap_addr = hapd.own_addr()
            cl_addr = dev.own_addr()
            pkt = build_arp(cl_addr, ap_addr, 2, ap_addr, '10.0.0.1', ap_addr, '10.0.0.1')
            pkt = binascii.hexlify(pkt)

            if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
                raise Exception("DATA_TEST_FRAME failed")

            if not hapd.own_addr() in subprocess.check_output(['ip', 'neigh', 'show']):
                raise Exception("gratuitous ARP frame failed to update")

            subprocess.call(['ip', 'neigh', 'replace', '10.0.0.1', 'lladdr', '02:00:00:00:00:ff', 'nud', 'reachable', 'dev', dev.ifname])
            # wait for lock-time
            time.sleep(1)

            open(procfile, 'w').write('1')

            if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
                raise Exception("DATA_TEST_FRAME failed")

            if hapd.own_addr() in subprocess.check_output(['ip', 'neigh', 'show']):
                raise Exception("gratuitous ARP frame updated erroneously")
        finally:
            subprocess.call(['ip', 'neigh', 'del', '10.0.0.1', 'dev', dev.ifname])
            open(procfile, 'w').write('0')

def test_ip6_drop_unsolicited_na(devs, apdevs, params):
    require_under_vm()
    dev = devs[0]
    procfile = '/proc/sys/net/ipv6/conf/%s/drop_unsolicited_na' % dev.ifname
    if not os.path.exists(procfile):
        raise HwsimSkip("kernel doesn't have capability")

    ap_params = { 'ssid': 'open', 'channel': '5' }
    hapd = hostapd.add_ap(apdevs[0], ap_params)
    dev.connect('open', key_mgmt="NONE", scan_freq="2432")

    with IPAssign(dev.ifname, 'fdaa::1/48', ipv6=True):
        # add an entry that can be updated by unsolicited NA
        subprocess.call(['ip', '-6', 'neigh', 'add', 'fdaa::2', 'lladdr', '02:00:00:00:00:ff', 'nud', 'reachable', 'dev', dev.ifname])
        try:
            ap_addr = hapd.own_addr()
            cl_addr = dev.own_addr()
            pkt = build_na(ap_addr, 'fdaa::2', 'ff02::1', 'fdaa::2', flags=0x20,
                           opt=binascii.unhexlify('0201' + ap_addr.replace(':', '')))
            pkt = binascii.hexlify(pkt)

            if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
                raise Exception("DATA_TEST_FRAME failed")

            if not hapd.own_addr() in subprocess.check_output(['ip', 'neigh', 'show']):
                raise Exception("unsolicited NA frame failed to update")

            subprocess.call(['ip', '-6', 'neigh', 'replace', 'fdaa::2', 'lladdr', '02:00:00:00:00:ff', 'nud', 'reachable', 'dev', dev.ifname])

            open(procfile, 'w').write('1')

            if "OK" not in hapd.request('DATA_TEST_FRAME ' + pkt):
                raise Exception("DATA_TEST_FRAME failed")

            if hapd.own_addr() in subprocess.check_output(['ip', 'neigh', 'show']):
                raise Exception("unsolicited NA frame updated erroneously")
        finally:
            subprocess.call(['ip', '-6', 'neigh', 'del', 'fdaa::2', 'dev', dev.ifname])
            open(procfile, 'w').write('0')
