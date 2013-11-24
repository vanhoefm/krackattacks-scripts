#!/usr/bin/python
#
# Testing utilities
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
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
