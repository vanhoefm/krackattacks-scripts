# Testing utilities
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

def get_ifnames():
    ifnames = []
    with open("/proc/net/dev", "r") as f:
        lines = f.readlines()
        for l in lines:
            val = l.split(':', 1)
            if len(val) == 2:
                ifnames.append(val[0].strip(' '))
    return ifnames

class HwsimSkip(Exception):
    def __init__(self, reason):
        self.reason = reason
    def __str__(self):
        return self.reason

class alloc_fail(object):
    def __init__(self, dev, count, funcs):
        self._dev = dev
        self._count = count
        self._funcs = funcs
    def __enter__(self):
        cmd = "TEST_ALLOC_FAIL %d:%s" % (self._count, self._funcs)
        if "OK" not in self._dev.request(cmd):
            raise HwsimSkip("TEST_ALLOC_FAIL not supported")
    def __exit__(self, type, value, traceback):
        if type is None:
            if self._dev.request("GET_ALLOC_FAIL") != "0:%s" % self._funcs:
                raise Exception("Allocation failure did not trigger")

def require_under_vm():
    with open('/proc/1/cmdline', 'r') as f:
        cmd = f.read()
        if "inside.sh" not in cmd:
            raise HwsimSkip("Not running under VM")
