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
import re
import wpaspy

logger = logging.getLogger(__name__)
wpas_ctrl = '/var/run/wpa_supplicant'

class WpaSupplicant:
    def __init__(self, ifname):
        self.ifname = ifname
        self.group_ifname = None
        self.ctrl = wpaspy.Ctrl(os.path.join(wpas_ctrl, ifname))
        self.mon = wpaspy.Ctrl(os.path.join(wpas_ctrl, ifname))
        self.mon.attach()

    def request(self, cmd):
        logger.debug(self.ifname + ": CTRL: " + cmd)
        return self.ctrl.request(cmd)

    def group_request(self, cmd):
        if self.group_ifname and self.group_ifname != self.ifname:
            logger.debug(self.group_ifname + ": CTRL: " + cmd)
            gctrl = wpaspy.Ctrl(os.path.join(wpas_ctrl, self.group_ifname))
            return gctrl.request(cmd)
        return self.request(cmd)

    def ping(self):
        return "PONG" in self.request("PING")

    def reset(self):
        self.request("P2P_STOP_FIND")
        self.request("P2P_FLUSH")
        self.request("P2P_GROUP_REMOVE *")
        self.request("REMOVE_NETWORK *")
        self.request("REMOVE_CRED *")
        self.request("SET tdls_disabled 0")
        self.request("SET tdls_testing 0")
        self.group_ifname = None

    def add_network(self):
        id = self.request("ADD_NETWORK")
        if "FAIL" in id:
            raise Exception("ADD_NETWORK failed")
        return int(id)

    def remove_network(self, id):
        id = self.request("REMOVE_NETWORK " + str(id))
        if "FAIL" in id:
            raise Exception("REMOVE_NETWORK failed")
        return None

    def set_network(self, id, field, value):
        res = self.request("SET_NETWORK " + str(id) + " " + field + " " + value)
        if "FAIL" in res:
            raise Exception("SET_NETWORK failed")
        return None

    def set_network_quoted(self, id, field, value):
        res = self.request("SET_NETWORK " + str(id) + " " + field + ' "' + value + '"')
        if "FAIL" in res:
            raise Exception("SET_NETWORK failed")
        return None

    def select_network(self, id):
        id = self.request("SELECT_NETWORK " + str(id))
        if "FAIL" in id:
            raise Exception("SELECT_NETWORK failed")
        return None

    def connect_network(self, id):
        self.dump_monitor()
        self.select_network(id)
        ev = self.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Association with the AP timed out")
        self.dump_monitor()

    def get_status(self, field):
        res = self.request("STATUS")
        lines = res.splitlines()
        for l in lines:
            [name,value] = l.split('=', 1)
            if name == field:
                return value
        return None

    def get_group_status(self, field):
        res = self.group_request("STATUS")
        lines = res.splitlines()
        for l in lines:
            [name,value] = l.split('=', 1)
            if name == field:
                return value
        return None

    def p2p_dev_addr(self):
        return self.get_status("p2p_device_address")

    def p2p_interface_addr(self):
        return self.get_group_status("address")

    def p2p_listen(self):
        return self.request("P2P_LISTEN")

    def p2p_find(self, social=False):
        if social:
            return self.request("P2P_FIND type=social")
        return self.request("P2P_FIND")

    def p2p_stop_find(self):
        return self.request("P2P_STOP_FIND")

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

    def discover_peer(self, peer, full=True, timeout=15, social=True):
        logger.info(self.ifname + ": Trying to discover peer " + peer)
        if self.peer_known(peer, full):
            return True
        self.p2p_find(social)
        count = 0
        while count < timeout:
            time.sleep(1)
            count = count + 1
            if self.peer_known(peer, full):
                return True
        return False

    def group_form_result(self, ev, expect_failure=False):
        if expect_failure:
            if "P2P-GROUP-STARTED" in ev:
                raise Exception("Group formation succeeded when expecting failure")
            exp = r'<.>(P2P-GO-NEG-FAILURE) status=([0-9]*)'
            s = re.split(exp, ev)
            if len(s) < 3:
                return None
            res = {}
            res['result'] = 'go-neg-failed'
            res['status'] = int(s[2])
            return res

        if "P2P-GROUP-STARTED" not in ev:
            raise Exception("No P2P-GROUP-STARTED event seen")

        exp = r'<.>(P2P-GROUP-STARTED) ([^ ]*) ([^ ]*) ssid="(.*)" freq=([0-9]*) ((?:psk=.*)|(?:passphrase=".*")) go_dev_addr=([0-9a-f:]*)'
        s = re.split(exp, ev)
        if len(s) < 8:
            raise Exception("Could not parse P2P-GROUP-STARTED")
        res = {}
        res['result'] = 'success'
        res['ifname'] = s[2]
        self.group_ifname = s[2]
        res['role'] = s[3]
        res['ssid'] = s[4]
        res['freq'] = s[5]
        p = re.match(r'psk=([0-9a-f]*)', s[6])
        if p:
            res['psk'] = p.group(1)
        p = re.match(r'passphrase="(.*)"', s[6])
        if p:
            res['passphrase'] = p.group(1)
        res['go_dev_addr'] = s[7]
        return res

    def p2p_go_neg_auth(self, peer, pin, method, go_intent=None):
        if not self.discover_peer(peer):
            raise Exception("Peer " + peer + " not found")
        self.dump_monitor()
        cmd = "P2P_CONNECT " + peer + " " + pin + " " + method + " auth"
        if go_intent:
            cmd = cmd + ' go_intent=' + str(go_intent)
        if "OK" in self.request(cmd):
            return None
        raise Exception("P2P_CONNECT (auth) failed")

    def p2p_go_neg_auth_result(self, timeout=1, expect_failure=False):
        ev = self.wait_event(["P2P-GROUP-STARTED","P2P-GO-NEG-FAILURE"], timeout);
        if ev is None:
            if expect_failure:
                return None
            raise Exception("Group formation timed out")
        self.dump_monitor()
        return self.group_form_result(ev, expect_failure)

    def p2p_go_neg_init(self, peer, pin, method, timeout=0, go_intent=None, expect_failure=False):
        if not self.discover_peer(peer):
            raise Exception("Peer " + peer + " not found")
        self.dump_monitor()
        if pin:
            cmd = "P2P_CONNECT " + peer + " " + pin + " " + method
        else:
            cmd = "P2P_CONNECT " + peer + " " + method
        if go_intent:
            cmd = cmd + ' go_intent=' + str(go_intent)
        if "OK" in self.request(cmd):
            if timeout == 0:
                self.dump_monitor()
                return None
            ev = self.wait_event(["P2P-GROUP-STARTED","P2P-GO-NEG-FAILURE"], timeout)
            if ev is None:
                if expect_failure:
                    return None
                raise Exception("Group formation timed out")
            self.dump_monitor()
            return self.group_form_result(ev, expect_failure)
        raise Exception("P2P_CONNECT failed")

    def wait_event(self, events, timeout):
        count = 0
        while count < timeout * 10:
            count = count + 1
            time.sleep(0.1)
            while self.mon.pending():
                ev = self.mon.recv()
                logger.debug(self.ifname + ": " + ev)
                for event in events:
                    if event in ev:
                        return ev
        return None

    def dump_monitor(self):
        while self.mon.pending():
            ev = self.mon.recv()
            logger.debug(self.ifname + ": " + ev)

    def remove_group(self, ifname=None):
        if ifname is None:
            ifname = self.group_ifname if self.group_ifname else self.iname
        if "OK" not in self.request("P2P_GROUP_REMOVE " + ifname):
            raise Exception("Group could not be removed")
        self.group_ifname = None

    def p2p_start_go(self, persistent=None):
        self.dump_monitor()
        cmd = "P2P_GROUP_ADD"
        if persistent is None:
            pass
        elif persistent is True:
            cmd = cmd + " persistent"
        else:
            cmd = cmd + " persistent=" + str(persistent)
        if "OK" in self.request(cmd):
            ev = self.wait_event(["P2P-GROUP-STARTED"], timeout=5)
            if ev is None:
                raise Exception("GO start up timed out")
            self.dump_monitor()
            return self.group_form_result(ev)
        raise Exception("P2P_GROUP_ADD failed")

    def p2p_go_authorize_client(self, pin):
        cmd = "WPS_PIN any " + pin
        if "FAIL" in self.group_request(cmd):
            raise Exception("Failed to authorize client connection on GO")
        return None

    def p2p_connect_group(self, go_addr, pin, timeout=0):
        self.dump_monitor()
        if not self.discover_peer(go_addr, social=False):
            raise Exception("GO " + go_addr + " not found")
        self.dump_monitor()
        cmd = "P2P_CONNECT " + go_addr + " " + pin + " join"
        if "OK" in self.request(cmd):
            if timeout == 0:
                self.dump_monitor()
                return None
            ev = self.wait_event(["P2P-GROUP-STARTED"], timeout)
            if ev is None:
                raise Exception("Joining the group timed out")
            self.dump_monitor()
            return self.group_form_result(ev)
        raise Exception("P2P_CONNECT(join) failed")

    def tdls_setup(self, peer):
        cmd = "TDLS_SETUP " + peer
        if "FAIL" in self.group_request(cmd):
            raise Exception("Failed to request TDLS setup")
        return None

    def tdls_teardown(self, peer):
        cmd = "TDLS_TEARDOWN " + peer
        if "FAIL" in self.group_request(cmd):
            raise Exception("Failed to request TDLS teardown")
        return None

    def connect(self, ssid, psk=None, proto=None, key_mgmt=None, wep_key0=None):
        logger.info("Connect STA " + self.ifname + " to AP")
        id = self.add_network()
        self.set_network_quoted(id, "ssid", ssid)
        if psk:
            self.set_network_quoted(id, "psk", psk)
        if proto:
            self.set_network(id, "proto", proto)
        if key_mgmt:
            self.set_network(id, "key_mgmt", key_mgmt)
        if wep_key0:
            self.set_network(id, "wep_key0", wep_key0)
        self.connect_network(id)

    def scan(self, type=None):
        if type:
            cmd = "SCAN TYPE=" + type
        else:
            cmd = "SCAN"
        self.dump_monitor()
        if not "OK" in self.request(cmd):
            raise Exception("Failed to trigger scan")
        ev = self.wait_event(["CTRL-EVENT-SCAN-RESULTS"], 15)
        if ev is None:
            raise Exception("Scan timed out")

    def roam(self, bssid):
        self.dump_monitor()
        self.request("ROAM " + bssid)
        ev = self.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Roaming with the AP timed out")
        self.dump_monitor()
