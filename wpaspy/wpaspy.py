#!/usr/bin/python
#
# wpa_supplicant/hostapd control interface using Python
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import socket
import select

counter = 0

class Ctrl:
    def __init__(self, path):
        global counter
        self.started = False
        self.attached = False
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.dest = path
        self.local = "/tmp/wpa_ctrl_" + str(os.getpid()) + '-' + str(counter)
        counter += 1
        self.s.bind(self.local)
        try:
            self.s.connect(self.dest)
        except Exception, e:
            self.s.close()
            os.unlink(self.local)
            raise
        self.started = True

    def __del__(self):
        self.close()

    def close(self):
        if self.attached:
            try:
                self.detach()
            except Exception, e:
                # Need to ignore this allow the socket to be closed
                pass
        if self.started:
            self.s.close()
            os.unlink(self.local)
            self.started = False

    def request(self, cmd):
        self.s.send(cmd)
        [r, w, e] = select.select([self.s], [], [], 10)
        if r:
            return self.s.recv(4096)
        raise Exception("Timeout on waiting response")

    def attach(self):
        if self.attached:
            return None
        res = self.request("ATTACH")
        if "OK" in res:
            self.attached = True
            return None
        raise Exception("ATTACH failed")

    def detach(self):
        if not self.attached:
            return None
        res = self.request("DETACH")
        if "OK" in res:
            self.attached = False
            return None
        raise Exception("DETACH failed")

    def pending(self, timeout=0):
        [r, w, e] = select.select([self.s], [], [], timeout)
        if r:
            return True
        return False

    def recv(self):
        res = self.s.recv(4096)
        return res
