#!/usr/bin/python
#
# Python class for controlling wpa_supplicant
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time
import logging
import wpaspy

logger = logging.getLogger(__name__)
wpas_ctrl = '/var/run/wpa_supplicant'

class WpaSupplicant:
    def __init__(self, ifname):
        self.ifname = ifname
        self.ctrl = wpaspy.Ctrl(os.path.join(wpas_ctrl, ifname))
        self.mon = wpaspy.Ctrl(os.path.join(wpas_ctrl, ifname))
        self.mon.attach()

    def request(self, cmd):
        logger.debug(self.ifname + ": CTRL: " + cmd)
        return self.ctrl.request(cmd)

    def ping(self):
        return "PONG" in self.request("PING")

    def reset(self):
        self.request("P2P_STOP_FIND")
        self.request("P2P_FLUSH")
        self.request("P2P_GROUP_REMOVE *")
        self.request("REMOVE_NETWORK *")
        self.request("REMOVE_CRED *")

    def get_status(self, field):
        res = self.request("STATUS")
        lines = res.splitlines()
        for l in lines:
            [name,value] = l.split('=', 1)
            if name == field:
                return value
        return None

    def p2p_dev_addr(self):
        return self.get_status("p2p_device_address")

    def p2p_listen(self):
        return self.request("P2P_LISTEN")

    def p2p_find(self, social=False):
        if social:
            return self.request("P2P_FIND type=social")
        return self.request("P2P_FIND")

    def wps_read_pin(self):
        #TODO: make this random
        self.pin = "12345670"
        return self.pin

    def peer_known(self, peer, full=True):
        res = self.request("P2P_PEER " + peer)
        if peer.lower() not in res.lower():
            return False
        if not full:
            return True
        return "[PROBE_REQ_ONLY]" not in res

    def discover_peer(self, peer, full=True, timeout=15):
        logger.info(self.ifname + ": Trying to discover peer " + peer)
        if self.peer_known(peer, full):
            return True
        self.p2p_find()
        count = 0
        while count < timeout:
            time.sleep(1)
            count = count + 1
            if self.peer_known(peer, full):
                return True
        return False

    def p2p_go_neg_auth(self, peer, pin, method):
        if not self.discover_peer(peer):
            raise Exception("Peer " + peer + " not found")
        self.dump_monitor()
        cmd = "P2P_CONNECT " + peer + " " + pin + " " + method + " auth"
        if "OK" in self.request(cmd):
            return None
        raise Exception("P2P_CONNECT (auth) failed")

    def p2p_go_neg_init(self, peer, pin, method, timeout=0):
        if not self.discover_peer(peer):
            raise Exception("Peer " + peer + " not found")
        self.dump_monitor()
        cmd = "P2P_CONNECT " + peer + " " + pin + " " + method
        if "OK" in self.request(cmd):
            if timeout == 0:
                self.dump_monitor()
                return None
            if self.wait_event("P2P-GROUP-STARTED", timeout):
                self.dump_monitor()
                return None
            raise Exception("Group formation timed out")
        raise Exception("P2P_CONNECT failed")

    def wait_event(self, event, timeout):
        count = 0
        while count < timeout * 2:
            count = count + 1
            time.sleep(0.5)
            while self.mon.pending():
                ev = self.mon.recv()
                if event in ev:
                    return True
        return False

    def dump_monitor(self):
        while self.mon.pending():
            ev = self.mon.recv()
            logger.debug(self.ifname + ": " + ev)

    def remove_group(self, ifname):
        if "OK" not in self.request("P2P_GROUP_REMOVE " + ifname):
            raise Exception("Group could not be removed")
