# hwsim testing utilities
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time
import logging
logger = logging.getLogger()

from wpasupplicant import WpaSupplicant

def run_connectivity_test(dev1, dev2, tos, dev1group=False, dev2group=False,
                          ifname1=None, ifname2=None, config=True, timeout=5,
                          multicast_to_unicast=False):
    addr1 = dev1.own_addr()
    if not dev1group and isinstance(dev1, WpaSupplicant):
        addr1 = dev1.get_driver_status_field('addr')

    addr2 = dev2.own_addr()
    if not dev2group and isinstance(dev2, WpaSupplicant):
        addr2 = dev2.get_driver_status_field('addr')

    dev1.dump_monitor()
    dev2.dump_monitor()

    if dev1.hostname is None and dev2.hostname is None:
        broadcast_retry_c = 1
    else:
        broadcast_retry_c = 10

    try:
        if config:
            cmd = "DATA_TEST_CONFIG 1"
            if ifname1:
                cmd = cmd + " ifname=" + ifname1
            if dev1group:
                res = dev1.group_request(cmd)
            else:
                res = dev1.request(cmd)
            if "OK" not in res:
                raise Exception("Failed to enable data test functionality")

            cmd = "DATA_TEST_CONFIG 1"
            if ifname2:
                cmd = cmd + " ifname=" + ifname2
            if dev2group:
                res = dev2.group_request(cmd)
            else:
                res = dev2.request(cmd)
            if "OK" not in res:
                raise Exception("Failed to enable data test functionality")

        cmd = "DATA_TEST_TX {} {} {}".format(addr2, addr1, tos)
        if dev1group:
            dev1.group_request(cmd)
        else:
            dev1.request(cmd)
        if dev2group:
            ev = dev2.wait_group_event(["DATA-TEST-RX"], timeout=timeout)
        else:
            ev = dev2.wait_event(["DATA-TEST-RX"], timeout=timeout)
        if ev is None:
            raise Exception("dev1->dev2 unicast data delivery failed")
        if "DATA-TEST-RX {} {}".format(addr2, addr1) not in ev:
            raise Exception("Unexpected dev1->dev2 unicast data result")

        cmd = "DATA_TEST_TX ff:ff:ff:ff:ff:ff {} {}".format(addr1, tos)
        for i in xrange(broadcast_retry_c):
            try:
                if dev1group:
                    dev1.group_request(cmd)
                else:
                    dev1.request(cmd)
                if dev2group:
                    ev = dev2.wait_group_event(["DATA-TEST-RX"],
                                               timeout=timeout)
                else:
                    ev = dev2.wait_event(["DATA-TEST-RX"], timeout=timeout)
                if ev is None:
                    raise Exception("dev1->dev2 broadcast data delivery failed")
                if "DATA-TEST-RX ff:ff:ff:ff:ff:ff {}".format(addr1) not in ev:
                    raise Exception("Unexpected dev1->dev2 broadcast data result")
                break
            except Exception as e:
                if i == broadcast_retry_c - 1:
                    raise

        cmd = "DATA_TEST_TX {} {} {}".format(addr1, addr2, tos)
        if dev2group:
            dev2.group_request(cmd)
        else:
            dev2.request(cmd)
        if dev1group:
            ev = dev1.wait_group_event(["DATA-TEST-RX"], timeout=timeout)
        else:
            ev = dev1.wait_event(["DATA-TEST-RX"], timeout=timeout)
        if ev is None:
            raise Exception("dev2->dev1 unicast data delivery failed")
        if "DATA-TEST-RX {} {}".format(addr1, addr2) not in ev:
            raise Exception("Unexpected dev2->dev1 unicast data result")

        cmd = "DATA_TEST_TX ff:ff:ff:ff:ff:ff {} {}".format(addr2, tos)
        for i in xrange(broadcast_retry_c):
            try:
                if dev2group:
                    dev2.group_request(cmd)
                else:
                    dev2.request(cmd)
                if dev1group:
                    ev = dev1.wait_group_event(["DATA-TEST-RX"],
                                               timeout=timeout)
                else:
                    ev = dev1.wait_event(["DATA-TEST-RX"], timeout=timeout)
                if ev is None:
                    raise Exception("dev2->dev1 broadcast data delivery failed")
                if multicast_to_unicast:
                   if "DATA-TEST-RX ff:ff:ff:ff:ff:ff {}".format(addr2) in ev:
                        raise Exception("Unexpected dev2->dev1 broadcast data result: multicast to unicast conversion missing")
                   if "DATA-TEST-RX {} {}".format(addr1, addr2) not in ev:
                        raise Exception("Unexpected dev2->dev1 broadcast data result (multicast to unicast enabled)")
                else:
                   if "DATA-TEST-RX ff:ff:ff:ff:ff:ff {}".format(addr2) not in ev:
                        raise Exception("Unexpected dev2->dev1 broadcast data result")
                break
            except Exception as e:
                if i == broadcast_retry_c - 1:
                    raise
    finally:
        if config:
            if dev1group:
                dev1.group_request("DATA_TEST_CONFIG 0")
            else:
                dev1.request("DATA_TEST_CONFIG 0")
            if dev2group:
                dev2.group_request("DATA_TEST_CONFIG 0")
            else:
                dev2.request("DATA_TEST_CONFIG 0")

def test_connectivity(dev1, dev2, dscp=None, tos=None, max_tries=1,
                      dev1group=False, dev2group=False,
                      ifname1=None, ifname2=None, config=True, timeout=5,
                      multicast_to_unicast=False):
    if dscp:
        tos = dscp << 2
    if not tos:
        tos = 0

    success = False
    last_err = None
    for i in range(0, max_tries):
        try:
            run_connectivity_test(dev1, dev2, tos, dev1group, dev2group,
                                  ifname1, ifname2, config=config,
                                  timeout=timeout,
                                  multicast_to_unicast=multicast_to_unicast)
            success = True
            break
        except Exception, e:
            last_err = e
            if i + 1 < max_tries:
                time.sleep(1)
    if not success:
        raise Exception(last_err)

def test_connectivity_iface(dev1, dev2, ifname, dscp=None, tos=None,
                            max_tries=1, timeout=5):
    test_connectivity(dev1, dev2, dscp, tos, ifname2=ifname,
                      max_tries=max_tries, timeout=timeout)

def test_connectivity_p2p(dev1, dev2, dscp=None, tos=None):
    test_connectivity(dev1, dev2, dscp, tos, dev1group=True, dev2group=True)

def test_connectivity_p2p_sta(dev1, dev2, dscp=None, tos=None):
    test_connectivity(dev1, dev2, dscp, tos, dev1group=True, dev2group=False)

def test_connectivity_sta(dev1, dev2, dscp=None, tos=None):
    test_connectivity(dev1, dev2, dscp, tos)

(PS_DISABLED, PS_ENABLED, PS_AUTO_POLL, PS_MANUAL_POLL) = range(4)

def set_powersave(dev, val):
    phy = dev.get_driver_status_field("phyname")
    fname = '/sys/kernel/debug/ieee80211/%s/hwsim/ps' % phy
    data = '%d' % val
    (res, data) = dev.cmd_execute(["echo", data, ">", fname], shell=True)
    if res != 0:
        raise Exception("Failed to set power save for device")
