# Python class for controlling wpa_supplicant
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time
import logging
import binascii
import re
import struct
import subprocess
import wpaspy

logger = logging.getLogger()
wpas_ctrl = '/var/run/wpa_supplicant'

class WpaSupplicant:
    def __init__(self, ifname=None, global_iface=None):
        self.group_ifname = None
        self.gctrl_mon = None
        if ifname:
            self.set_ifname(ifname)
        else:
            self.ifname = None

        self.global_iface = global_iface
        if global_iface:
            self.global_ctrl = wpaspy.Ctrl(global_iface)
            self.global_mon = wpaspy.Ctrl(global_iface)
            self.global_mon.attach()
        else:
            self.global_mon = None

    def close_ctrl(self):
        if self.global_mon:
            self.global_mon.detach()
            self.global_mon = None
            self.global_ctrl = None
        self.remove_ifname()

    def set_ifname(self, ifname):
        self.ifname = ifname
        self.ctrl = wpaspy.Ctrl(os.path.join(wpas_ctrl, ifname))
        self.mon = wpaspy.Ctrl(os.path.join(wpas_ctrl, ifname))
        self.mon.attach()

    def remove_ifname(self):
        if self.ifname:
            self.mon.detach()
            self.mon = None
            self.ctrl = None
            self.ifname = None

    def interface_add(self, ifname, config="", driver="nl80211",
                      drv_params=None, br_ifname=None):
        try:
            groups = subprocess.check_output(["id"])
            group = "admin" if "(admin)" in groups else "adm"
        except Exception, e:
            group = "admin"
        cmd = "INTERFACE_ADD " + ifname + "\t" + config + "\t" + driver + "\tDIR=/var/run/wpa_supplicant GROUP=" + group
        if drv_params:
            cmd = cmd + '\t' + drv_params
        if br_ifname:
            if not drv_params:
                cmd += '\t'
            cmd += '\t' + br_ifname
        if "FAIL" in self.global_request(cmd):
            raise Exception("Failed to add a dynamic wpa_supplicant interface")
        self.set_ifname(ifname)

    def interface_remove(self, ifname):
        self.remove_ifname()
        self.global_request("INTERFACE_REMOVE " + ifname)

    def request(self, cmd, timeout=10):
        logger.debug(self.ifname + ": CTRL: " + cmd)
        return self.ctrl.request(cmd, timeout=timeout)

    def global_request(self, cmd):
        if self.global_iface is None:
            self.request(cmd)
        else:
            ifname = self.ifname or self.global_iface
            logger.debug(ifname + ": CTRL(global): " + cmd)
            return self.global_ctrl.request(cmd)

    def group_request(self, cmd):
        if self.group_ifname and self.group_ifname != self.ifname:
            logger.debug(self.group_ifname + ": CTRL: " + cmd)
            gctrl = wpaspy.Ctrl(os.path.join(wpas_ctrl, self.group_ifname))
            return gctrl.request(cmd)
        return self.request(cmd)

    def ping(self):
        return "PONG" in self.request("PING")

    def global_ping(self):
        return "PONG" in self.global_request("PING")

    def reset(self):
        self.dump_monitor()
        res = self.request("FLUSH")
        if not "OK" in res:
            logger.info("FLUSH to " + self.ifname + " failed: " + res)
        self.request("SET p2p_add_cli_chan 0")
        self.request("SET p2p_no_go_freq ")
        self.request("SET p2p_pref_chan ")
        self.request("SET p2p_no_group_iface 1")
        self.request("SET p2p_go_intent 7")
        self.request("SET ignore_old_scan_res 0")
        if self.gctrl_mon:
            try:
                self.gctrl_mon.detach()
            except:
                pass
            self.gctrl_mon = None
        self.group_ifname = None
        self.dump_monitor()

        iter = 0
        while iter < 60:
            state = self.get_driver_status_field("scan_state")
            if "SCAN_STARTED" in state or "SCAN_REQUESTED" in state:
                logger.info(self.ifname + ": Waiting for scan operation to complete before continuing")
                time.sleep(1)
            else:
                break
            iter = iter + 1
        if iter == 60:
            logger.error(self.ifname + ": Driver scan state did not clear")
            print "Trying to clear cfg80211/mac80211 scan state"
            try:
                cmd = ["ifconfig", self.ifname, "down"]
                subprocess.call(cmd)
            except subprocess.CalledProcessError, e:
                logger.info("ifconfig failed: " + str(e.returncode))
                logger.info(e.output)
            try:
                cmd = ["ifconfig", self.ifname, "up"]
                subprocess.call(cmd)
            except subprocess.CalledProcessError, e:
                logger.info("ifconfig failed: " + str(e.returncode))
                logger.info(e.output)
        if iter > 0:
            # The ongoing scan could have discovered BSSes or P2P peers
            logger.info("Run FLUSH again since scan was in progress")
            self.request("FLUSH")
            self.dump_monitor()

        if not self.ping():
            logger.info("No PING response from " + self.ifname + " after reset")

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

    def get_network(self, id, field):
        res = self.request("GET_NETWORK " + str(id) + " " + field)
        if res == "FAIL\n":
            return None
        return res

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

    def list_networks(self):
        res = self.request("LIST_NETWORKS")
        lines = res.splitlines()
        networks = []
        for l in lines:
            if "network id" in l:
                continue
            [id,ssid,bssid,flags] = l.split('\t')
            network = {}
            network['id'] = id
            network['ssid'] = ssid
            network['bssid'] = bssid
            network['flags'] = flags
            networks.append(network)
        return networks

    def hs20_enable(self, auto_interworking=False):
        self.request("SET interworking 1")
        self.request("SET hs20 1")
        if auto_interworking:
            self.request("SET auto_interworking 1")
        else:
            self.request("SET auto_interworking 0")

    def interworking_add_network(self, bssid):
        id = self.request("INTERWORKING_ADD_NETWORK " + bssid)
        if "FAIL" in id or "OK" in id:
            raise Exception("INTERWORKING_ADD_NETWORK failed")
        return int(id)

    def add_cred(self):
        id = self.request("ADD_CRED")
        if "FAIL" in id:
            raise Exception("ADD_CRED failed")
        return int(id)

    def remove_cred(self, id):
        id = self.request("REMOVE_CRED " + str(id))
        if "FAIL" in id:
            raise Exception("REMOVE_CRED failed")
        return None

    def set_cred(self, id, field, value):
        res = self.request("SET_CRED " + str(id) + " " + field + " " + value)
        if "FAIL" in res:
            raise Exception("SET_CRED failed")
        return None

    def set_cred_quoted(self, id, field, value):
        res = self.request("SET_CRED " + str(id) + " " + field + ' "' + value + '"')
        if "FAIL" in res:
            raise Exception("SET_CRED failed")
        return None

    def get_cred(self, id, field):
        return self.request("GET_CRED " + str(id) + " " + field)

    def add_cred_values(self, params):
        id = self.add_cred()

        quoted = [ "realm", "username", "password", "domain", "imsi",
                   "excluded_ssid", "milenage", "ca_cert", "client_cert",
                   "private_key", "domain_suffix_match", "provisioning_sp",
                   "roaming_partner", "phase1", "phase2" ]
        for field in quoted:
            if field in params:
                self.set_cred_quoted(id, field, params[field])

        not_quoted = [ "eap", "roaming_consortium", "priority",
                       "required_roaming_consortium", "sp_priority",
                       "max_bss_load", "update_identifier", "req_conn_capab",
                       "min_dl_bandwidth_home", "min_ul_bandwidth_home",
                       "min_dl_bandwidth_roaming", "min_ul_bandwidth_roaming" ]
        for field in not_quoted:
            if field in params:
                self.set_cred(id, field, params[field])

        return id;

    def select_network(self, id, freq=None):
        if freq:
            extra = " freq=" + str(freq)
        else:
            extra = ""
        id = self.request("SELECT_NETWORK " + str(id) + extra)
        if "FAIL" in id:
            raise Exception("SELECT_NETWORK failed")
        return None

    def mesh_group_add(self, id):
        id = self.request("MESH_GROUP_ADD " + str(id))
        if "FAIL" in id:
            raise Exception("MESH_GROUP_ADD failed")
        return None

    def mesh_group_remove(self):
        id = self.request("MESH_GROUP_REMOVE " + str(self.ifname))
        if "FAIL" in id:
            raise Exception("MESH_GROUP_REMOVE failed")
        return None

    def connect_network(self, id, timeout=10):
        self.dump_monitor()
        self.select_network(id)
        self.wait_connected(timeout=timeout)
        self.dump_monitor()

    def get_status(self, extra=None):
        if extra:
            extra = "-" + extra
        else:
            extra = ""
        res = self.request("STATUS" + extra)
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            try:
                [name,value] = l.split('=', 1)
                vals[name] = value
            except ValueError, e:
                logger.info(self.ifname + ": Ignore unexpected STATUS line: " + l)
        return vals

    def get_status_field(self, field, extra=None):
        vals = self.get_status(extra)
        if field in vals:
            return vals[field]
        return None

    def get_group_status(self, extra=None):
        if extra:
            extra = "-" + extra
        else:
            extra = ""
        res = self.group_request("STATUS" + extra)
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            try:
                [name,value] = l.split('=', 1)
            except ValueError:
                logger.info(self.ifname + ": Ignore unexpected status line: " + l)
                continue
            vals[name] = value
        return vals

    def get_group_status_field(self, field, extra=None):
        vals = self.get_group_status(extra)
        if field in vals:
            return vals[field]
        return None

    def get_driver_status(self):
        res = self.request("STATUS-DRIVER")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            try:
                [name,value] = l.split('=', 1)
            except ValueError:
                logger.info(self.ifname + ": Ignore unexpected status-driver line: " + l)
                continue
            vals[name] = value
        return vals

    def get_driver_status_field(self, field):
        vals = self.get_driver_status()
        if field in vals:
            return vals[field]
        return None

    def get_mcc(self):
	mcc = int(self.get_driver_status_field('capa.num_multichan_concurrent'))
	return 1 if mcc < 2 else mcc

    def get_mib(self):
        res = self.request("MIB")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            try:
                [name,value] = l.split('=', 1)
                vals[name] = value
            except ValueError, e:
                logger.info(self.ifname + ": Ignore unexpected MIB line: " + l)
        return vals

    def p2p_dev_addr(self):
        return self.get_status_field("p2p_device_address")

    def p2p_interface_addr(self):
        return self.get_group_status_field("address")

    def own_addr(self):
        try:
            res = self.p2p_interface_addr()
        except:
            res = self.p2p_dev_addr()
        return res

    def p2p_listen(self):
        return self.global_request("P2P_LISTEN")

    def p2p_find(self, social=False, progressive=False, dev_id=None,
                 dev_type=None, delay=None, freq=None):
        cmd = "P2P_FIND"
        if social:
            cmd = cmd + " type=social"
        elif progressive:
            cmd = cmd + " type=progressive"
        if dev_id:
            cmd = cmd + " dev_id=" + dev_id
        if dev_type:
            cmd = cmd + " dev_type=" + dev_type
        if delay:
            cmd = cmd + " delay=" + str(delay)
        if freq:
            cmd = cmd + " freq=" + str(freq)
        return self.global_request(cmd)

    def p2p_stop_find(self):
        return self.global_request("P2P_STOP_FIND")

    def wps_read_pin(self):
        self.pin = self.request("WPS_PIN get").rstrip("\n")
        if "FAIL" in self.pin:
            raise Exception("Could not generate PIN")
        return self.pin

    def peer_known(self, peer, full=True):
        res = self.global_request("P2P_PEER " + peer)
        if peer.lower() not in res.lower():
            return False
        if not full:
            return True
        return "[PROBE_REQ_ONLY]" not in res

    def discover_peer(self, peer, full=True, timeout=15, social=True, force_find=False):
        logger.info(self.ifname + ": Trying to discover peer " + peer)
        if not force_find and self.peer_known(peer, full):
            return True
        self.p2p_find(social)
        count = 0
        while count < timeout * 4:
            time.sleep(0.25)
            count = count + 1
            if self.peer_known(peer, full):
                return True
        return False

    def get_peer(self, peer):
        res = self.global_request("P2P_PEER " + peer)
        if peer.lower() not in res.lower():
            raise Exception("Peer information not available")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            if '=' in l:
                [name,value] = l.split('=', 1)
                vals[name] = value
        return vals

    def group_form_result(self, ev, expect_failure=False, go_neg_res=None):
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

        exp = r'<.>(P2P-GROUP-STARTED) ([^ ]*) ([^ ]*) ssid="(.*)" freq=([0-9]*) ((?:psk=.*)|(?:passphrase=".*")) go_dev_addr=([0-9a-f:]*) ip_addr=([0-9.]*) ip_mask=([0-9.]*) go_ip_addr=([0-9.]*)'
        s = re.split(exp, ev)
        if len(s) < 11:
            exp = r'<.>(P2P-GROUP-STARTED) ([^ ]*) ([^ ]*) ssid="(.*)" freq=([0-9]*) ((?:psk=.*)|(?:passphrase=".*")) go_dev_addr=([0-9a-f:]*)'
            s = re.split(exp, ev)
            if len(s) < 8:
                raise Exception("Could not parse P2P-GROUP-STARTED")
        res = {}
        res['result'] = 'success'
        res['ifname'] = s[2]
        self.group_ifname = s[2]
        try:
            self.gctrl_mon = wpaspy.Ctrl(os.path.join(wpas_ctrl, self.group_ifname))
            self.gctrl_mon.attach()
        except:
            logger.debug("Could not open monitor socket for group interface")
            self.gctrl_mon = None
        res['role'] = s[3]
        res['ssid'] = s[4]
        res['freq'] = s[5]
        if "[PERSISTENT]" in ev:
            res['persistent'] = True
        else:
            res['persistent'] = False
        p = re.match(r'psk=([0-9a-f]*)', s[6])
        if p:
            res['psk'] = p.group(1)
        p = re.match(r'passphrase="(.*)"', s[6])
        if p:
            res['passphrase'] = p.group(1)
        res['go_dev_addr'] = s[7]

        if len(s) > 8 and len(s[8]) > 0:
            res['ip_addr'] = s[8]
        if len(s) > 9:
            res['ip_mask'] = s[9]
        if len(s) > 10:
            res['go_ip_addr'] = s[10]

        if go_neg_res:
            exp = r'<.>(P2P-GO-NEG-SUCCESS) role=(GO|client) freq=([0-9]*)'
            s = re.split(exp, go_neg_res)
            if len(s) < 4:
                raise Exception("Could not parse P2P-GO-NEG-SUCCESS")
            res['go_neg_role'] = s[2]
            res['go_neg_freq'] = s[3]

        return res

    def p2p_go_neg_auth(self, peer, pin, method, go_intent=None, persistent=False, freq=None):
        if not self.discover_peer(peer):
            raise Exception("Peer " + peer + " not found")
        self.dump_monitor()
        if pin:
            cmd = "P2P_CONNECT " + peer + " " + pin + " " + method + " auth"
        else:
            cmd = "P2P_CONNECT " + peer + " " + method + " auth"
        if go_intent:
            cmd = cmd + ' go_intent=' + str(go_intent)
        if freq:
            cmd = cmd + ' freq=' + str(freq)
        if persistent:
            cmd = cmd + " persistent"
        if "OK" in self.global_request(cmd):
            return None
        raise Exception("P2P_CONNECT (auth) failed")

    def p2p_go_neg_auth_result(self, timeout=1, expect_failure=False):
        go_neg_res = None
        ev = self.wait_global_event(["P2P-GO-NEG-SUCCESS",
                                     "P2P-GO-NEG-FAILURE"], timeout);
        if ev is None:
            if expect_failure:
                return None
            raise Exception("Group formation timed out")
        if "P2P-GO-NEG-SUCCESS" in ev:
            go_neg_res = ev
            ev = self.wait_global_event(["P2P-GROUP-STARTED"], timeout);
            if ev is None:
                if expect_failure:
                    return None
                raise Exception("Group formation timed out")
        self.dump_monitor()
        return self.group_form_result(ev, expect_failure, go_neg_res)

    def p2p_go_neg_init(self, peer, pin, method, timeout=0, go_intent=None, expect_failure=False, persistent=False, persistent_id=None, freq=None, provdisc=False, wait_group=True):
        if not self.discover_peer(peer):
            raise Exception("Peer " + peer + " not found")
        self.dump_monitor()
        if pin:
            cmd = "P2P_CONNECT " + peer + " " + pin + " " + method
        else:
            cmd = "P2P_CONNECT " + peer + " " + method
        if go_intent:
            cmd = cmd + ' go_intent=' + str(go_intent)
        if freq:
            cmd = cmd + ' freq=' + str(freq)
        if persistent:
            cmd = cmd + " persistent"
        elif persistent_id:
            cmd = cmd + " persistent=" + persistent_id
        if provdisc:
            cmd = cmd + " provdisc"
        if "OK" in self.global_request(cmd):
            if timeout == 0:
                self.dump_monitor()
                return None
            go_neg_res = None
            ev = self.wait_global_event(["P2P-GO-NEG-SUCCESS",
                                         "P2P-GO-NEG-FAILURE"], timeout)
            if ev is None:
                if expect_failure:
                    return None
                raise Exception("Group formation timed out")
            if "P2P-GO-NEG-SUCCESS" in ev:
                if not wait_group:
                    return ev
                go_neg_res = ev
                ev = self.wait_global_event(["P2P-GROUP-STARTED"], timeout)
                if ev is None:
                    if expect_failure:
                        return None
                    raise Exception("Group formation timed out")
            self.dump_monitor()
            return self.group_form_result(ev, expect_failure, go_neg_res)
        raise Exception("P2P_CONNECT failed")

    def wait_event(self, events, timeout=10):
        start = os.times()[4]
        while True:
            while self.mon.pending():
                ev = self.mon.recv()
                logger.debug(self.ifname + ": " + ev)
                for event in events:
                    if event in ev:
                        return ev
            now = os.times()[4]
            remaining = start + timeout - now
            if remaining <= 0:
                break
            if not self.mon.pending(timeout=remaining):
                break
        return None

    def wait_global_event(self, events, timeout):
        if self.global_iface is None:
            self.wait_event(events, timeout)
        else:
            start = os.times()[4]
            while True:
                while self.global_mon.pending():
                    ev = self.global_mon.recv()
                    logger.debug(self.ifname + "(global): " + ev)
                    for event in events:
                        if event in ev:
                            return ev
                now = os.times()[4]
                remaining = start + timeout - now
                if remaining <= 0:
                    break
                if not self.global_mon.pending(timeout=remaining):
                    break
        return None

    def wait_group_event(self, events, timeout=10):
        if self.group_ifname and self.group_ifname != self.ifname:
            if self.gctrl_mon is None:
                return None
            start = os.times()[4]
            while True:
                while self.gctrl_mon.pending():
                    ev = self.gctrl_mon.recv()
                    logger.debug(self.group_ifname + ": " + ev)
                    for event in events:
                        if event in ev:
                            return ev
                now = os.times()[4]
                remaining = start + timeout - now
                if remaining <= 0:
                    break
                if not self.gctrl_mon.pending(timeout=remaining):
                    break
            return None

        return self.wait_event(events, timeout)

    def wait_go_ending_session(self):
        if self.gctrl_mon:
            try:
                self.gctrl_mon.detach()
            except:
                pass
            self.gctrl_mon = None
        ev = self.wait_global_event(["P2P-GROUP-REMOVED"], timeout=3)
        if ev is None:
            raise Exception("Group removal event timed out")
        if "reason=GO_ENDING_SESSION" not in ev:
            raise Exception("Unexpected group removal reason")

    def dump_monitor(self):
        while self.mon.pending():
            ev = self.mon.recv()
            logger.debug(self.ifname + ": " + ev)
        while self.global_mon and self.global_mon.pending():
            ev = self.global_mon.recv()
            logger.debug(self.ifname + "(global): " + ev)

    def remove_group(self, ifname=None):
        if self.gctrl_mon:
            try:
                self.gctrl_mon.detach()
            except:
                pass
            self.gctrl_mon = None
        if ifname is None:
            ifname = self.group_ifname if self.group_ifname else self.ifname
        if "OK" not in self.global_request("P2P_GROUP_REMOVE " + ifname):
            raise Exception("Group could not be removed")
        self.group_ifname = None

    def p2p_start_go(self, persistent=None, freq=None, no_event_clear=False):
        self.dump_monitor()
        cmd = "P2P_GROUP_ADD"
        if persistent is None:
            pass
        elif persistent is True:
            cmd = cmd + " persistent"
        else:
            cmd = cmd + " persistent=" + str(persistent)
        if freq:
            cmd = cmd + " freq=" + str(freq)
        if "OK" in self.global_request(cmd):
            ev = self.wait_global_event(["P2P-GROUP-STARTED"], timeout=5)
            if ev is None:
                raise Exception("GO start up timed out")
            if not no_event_clear:
                self.dump_monitor()
            return self.group_form_result(ev)
        raise Exception("P2P_GROUP_ADD failed")

    def p2p_go_authorize_client(self, pin):
        cmd = "WPS_PIN any " + pin
        if "FAIL" in self.group_request(cmd):
            raise Exception("Failed to authorize client connection on GO")
        return None

    def p2p_go_authorize_client_pbc(self):
        cmd = "WPS_PBC"
        if "FAIL" in self.group_request(cmd):
            raise Exception("Failed to authorize client connection on GO")
        return None

    def p2p_connect_group(self, go_addr, pin, timeout=0, social=False,
                          freq=None):
        self.dump_monitor()
        if not self.discover_peer(go_addr, social=social):
            if social or not self.discover_peer(go_addr, social=social):
                raise Exception("GO " + go_addr + " not found")
        self.dump_monitor()
        cmd = "P2P_CONNECT " + go_addr + " " + pin + " join"
        if freq:
            cmd += " freq=" + str(freq)
        if "OK" in self.global_request(cmd):
            if timeout == 0:
                self.dump_monitor()
                return None
            ev = self.wait_global_event(["P2P-GROUP-STARTED"], timeout)
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

    def tspecs(self):
        """Return (tsid, up) tuples representing current tspecs"""
        res = self.request("WMM_AC_STATUS")
        tspecs = re.findall(r"TSID=(\d+) UP=(\d+)", res)
        tspecs = [tuple(map(int, tspec)) for tspec in tspecs]

        logger.debug("tspecs: " + str(tspecs))
        return tspecs

    def add_ts(self, tsid, up, direction="downlink", expect_failure=False,
               extra=None):
        params = {
            "sba": 9000,
            "nominal_msdu_size": 1500,
            "min_phy_rate": 6000000,
            "mean_data_rate": 1500,
        }
        cmd = "WMM_AC_ADDTS %s tsid=%d up=%d" % (direction, tsid, up)
        for (key, value) in params.iteritems():
            cmd += " %s=%d" % (key, value)
        if extra:
            cmd += " " + extra

        if self.request(cmd).strip() != "OK":
            raise Exception("ADDTS failed (tsid=%d up=%d)" % (tsid, up))

        if expect_failure:
            ev = self.wait_event(["TSPEC-REQ-FAILED"], timeout=2)
            if ev is None:
                raise Exception("ADDTS failed (time out while waiting failure)")
            if "tsid=%d" % (tsid) not in ev:
                raise Exception("ADDTS failed (invalid tsid in TSPEC-REQ-FAILED")
            return

        ev = self.wait_event(["TSPEC-ADDED"], timeout=1)
        if ev is None:
            raise Exception("ADDTS failed (time out)")
        if "tsid=%d" % (tsid) not in ev:
            raise Exception("ADDTS failed (invalid tsid in TSPEC-ADDED)")

        if not (tsid, up) in self.tspecs():
            raise Exception("ADDTS failed (tsid not in tspec list)")

    def del_ts(self, tsid):
        if self.request("WMM_AC_DELTS %d" % (tsid)).strip() != "OK":
            raise Exception("DELTS failed")

        ev = self.wait_event(["TSPEC-REMOVED"], timeout=1)
        if ev is None:
            raise Exception("DELTS failed (time out)")
        if "tsid=%d" % (tsid) not in ev:
            raise Exception("DELTS failed (invalid tsid in TSPEC-REMOVED)")

        tspecs = [(t, u) for (t, u) in self.tspecs() if t == tsid]
        if tspecs:
            raise Exception("DELTS failed (still in tspec list)")

    def connect(self, ssid=None, ssid2=None, **kwargs):
        logger.info("Connect STA " + self.ifname + " to AP")
        id = self.add_network()
        if ssid:
            self.set_network_quoted(id, "ssid", ssid)
        elif ssid2:
            self.set_network(id, "ssid", ssid2)

        quoted = [ "psk", "identity", "anonymous_identity", "password",
                   "ca_cert", "client_cert", "private_key",
                   "private_key_passwd", "ca_cert2", "client_cert2",
                   "private_key2", "phase1", "phase2", "domain_suffix_match",
                   "altsubject_match", "subject_match", "pac_file", "dh_file",
                   "bgscan", "ht_mcs", "id_str", "openssl_ciphers",
                   "domain_match" ]
        for field in quoted:
            if field in kwargs and kwargs[field]:
                self.set_network_quoted(id, field, kwargs[field])

        not_quoted = [ "proto", "key_mgmt", "ieee80211w", "pairwise",
                       "group", "wep_key0", "wep_key1", "wep_key2", "wep_key3",
                       "wep_tx_keyidx", "scan_freq", "eap",
                       "eapol_flags", "fragment_size", "scan_ssid", "auth_alg",
                       "wpa_ptk_rekey", "disable_ht", "disable_vht", "bssid",
                       "disable_max_amsdu", "ampdu_factor", "ampdu_density",
                       "disable_ht40", "disable_sgi", "disable_ldpc",
                       "ht40_intolerant", "update_identifier", "mac_addr",
                       "erp", "bg_scan_period", "bssid_blacklist",
                       "bssid_whitelist" ]
        for field in not_quoted:
            if field in kwargs and kwargs[field]:
                self.set_network(id, field, kwargs[field])

        if "raw_psk" in kwargs and kwargs['raw_psk']:
            self.set_network(id, "psk", kwargs['raw_psk'])
        if "password_hex" in kwargs and kwargs['password_hex']:
            self.set_network(id, "password", kwargs['password_hex'])
        if "peerkey" in kwargs and kwargs['peerkey']:
            self.set_network(id, "peerkey", "1")
        if "okc" in kwargs and kwargs['okc']:
            self.set_network(id, "proactive_key_caching", "1")
        if "ocsp" in kwargs and kwargs['ocsp']:
            self.set_network(id, "ocsp", str(kwargs['ocsp']))
        if "only_add_network" in kwargs and kwargs['only_add_network']:
            return id
        if "wait_connect" not in kwargs or kwargs['wait_connect']:
            if "eap" in kwargs:
                self.connect_network(id, timeout=20)
            else:
                self.connect_network(id)
        else:
            self.dump_monitor()
            self.select_network(id)
        return id

    def scan(self, type=None, freq=None, no_wait=False, only_new=False):
        if type:
            cmd = "SCAN TYPE=" + type
        else:
            cmd = "SCAN"
        if freq:
            cmd = cmd + " freq=" + str(freq)
        if only_new:
            cmd += " only_new=1"
        if not no_wait:
            self.dump_monitor()
        if not "OK" in self.request(cmd):
            raise Exception("Failed to trigger scan")
        if no_wait:
            return
        ev = self.wait_event(["CTRL-EVENT-SCAN-RESULTS"], 15)
        if ev is None:
            raise Exception("Scan timed out")

    def scan_for_bss(self, bssid, freq=None, force_scan=False, only_new=False):
        if not force_scan and self.get_bss(bssid) is not None:
            return
        for i in range(0, 10):
            self.scan(freq=freq, type="ONLY", only_new=only_new)
            if self.get_bss(bssid) is not None:
                return
        raise Exception("Could not find BSS " + bssid + " in scan")

    def flush_scan_cache(self, freq=2417):
        self.request("BSS_FLUSH 0")
        self.scan(freq=freq, only_new=True)

    def roam(self, bssid, fail_test=False):
        self.dump_monitor()
        if "OK" not in self.request("ROAM " + bssid):
            raise Exception("ROAM failed")
        if fail_test:
            ev = self.wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
            if ev is not None:
                raise Exception("Unexpected connection")
            self.dump_monitor()
            return
        self.wait_connected(timeout=10, error="Roaming with the AP timed out")
        self.dump_monitor()

    def roam_over_ds(self, bssid, fail_test=False):
        self.dump_monitor()
        if "OK" not in self.request("FT_DS " + bssid):
            raise Exception("FT_DS failed")
        if fail_test:
            ev = self.wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
            if ev is not None:
                raise Exception("Unexpected connection")
            self.dump_monitor()
            return
        self.wait_connected(timeout=10, error="Roaming with the AP timed out")
        self.dump_monitor()

    def wps_reg(self, bssid, pin, new_ssid=None, key_mgmt=None, cipher=None,
                new_passphrase=None, no_wait=False):
        self.dump_monitor()
        if new_ssid:
            self.request("WPS_REG " + bssid + " " + pin + " " +
                         new_ssid.encode("hex") + " " + key_mgmt + " " +
                         cipher + " " + new_passphrase.encode("hex"))
            if no_wait:
                return
            ev = self.wait_event(["WPS-SUCCESS"], timeout=15)
        else:
            self.request("WPS_REG " + bssid + " " + pin)
            if no_wait:
                return
            ev = self.wait_event(["WPS-CRED-RECEIVED"], timeout=15)
            if ev is None:
                raise Exception("WPS cred timed out")
            ev = self.wait_event(["WPS-FAIL"], timeout=15)
        if ev is None:
            raise Exception("WPS timed out")
        self.wait_connected(timeout=15)

    def relog(self):
        self.global_request("RELOG")

    def wait_completed(self, timeout=10):
        for i in range(0, timeout * 2):
            if self.get_status_field("wpa_state") == "COMPLETED":
                return
            time.sleep(0.5)
        raise Exception("Timeout while waiting for COMPLETED state")

    def get_capability(self, field):
        res = self.request("GET_CAPABILITY " + field)
        if "FAIL" in res:
            return None
        return res.split(' ')

    def get_bss(self, bssid, ifname=None):
	if not ifname or ifname == self.ifname:
            res = self.request("BSS " + bssid)
        elif ifname == self.group_ifname:
            res = self.group_request("BSS " + bssid)
        else:
            return None

        if "FAIL" in res:
            return None
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            [name,value] = l.split('=', 1)
            vals[name] = value
        if len(vals) == 0:
            return None
        return vals

    def get_pmksa(self, bssid):
        res = self.request("PMKSA")
        lines = res.splitlines()
        for l in lines:
            if bssid not in l:
                continue
            vals = dict()
            [index,aa,pmkid,expiration,opportunistic] = l.split(' ')
            vals['index'] = index
            vals['pmkid'] = pmkid
            vals['expiration'] = expiration
            vals['opportunistic'] = opportunistic
            return vals
        return None

    def get_sta(self, addr, info=None, next=False):
        cmd = "STA-NEXT " if next else "STA "
        if addr is None:
            res = self.request("STA-FIRST")
        elif info:
            res = self.request(cmd + addr + " " + info)
        else:
            res = self.request(cmd + addr)
        lines = res.splitlines()
        vals = dict()
        first = True
        for l in lines:
            if first:
                vals['addr'] = l
                first = False
            else:
                [name,value] = l.split('=', 1)
                vals[name] = value
        return vals

    def mgmt_rx(self, timeout=5):
        ev = self.wait_event(["MGMT-RX"], timeout=timeout)
        if ev is None:
            return None
        msg = {}
        items = ev.split(' ')
        field,val = items[1].split('=')
        if field != "freq":
            raise Exception("Unexpected MGMT-RX event format: " + ev)
        msg['freq'] = val
        frame = binascii.unhexlify(items[4])
        msg['frame'] = frame

        hdr = struct.unpack('<HH6B6B6BH', frame[0:24])
        msg['fc'] = hdr[0]
        msg['subtype'] = (hdr[0] >> 4) & 0xf
        hdr = hdr[1:]
        msg['duration'] = hdr[0]
        hdr = hdr[1:]
        msg['da'] = "%02x:%02x:%02x:%02x:%02x:%02x" % hdr[0:6]
        hdr = hdr[6:]
        msg['sa'] = "%02x:%02x:%02x:%02x:%02x:%02x" % hdr[0:6]
        hdr = hdr[6:]
        msg['bssid'] = "%02x:%02x:%02x:%02x:%02x:%02x" % hdr[0:6]
        hdr = hdr[6:]
        msg['seq_ctrl'] = hdr[0]
        msg['payload'] = frame[24:]

        return msg

    def wait_connected(self, timeout=10, error="Connection timed out"):
        ev = self.wait_event(["CTRL-EVENT-CONNECTED"], timeout=timeout)
        if ev is None:
            raise Exception(error)
        return ev

    def wait_disconnected(self, timeout=10, error="Disconnection timed out"):
        ev = self.wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=timeout)
        if ev is None:
            raise Exception(error)
        return ev

    def get_group_ifname(self):
        return self.group_ifname if self.group_ifname else self.ifname

    def get_config(self):
        res = self.request("DUMP")
        if res.startswith("FAIL"):
            raise Exception("DUMP failed")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            [name,value] = l.split('=', 1)
            vals[name] = value
        return vals
