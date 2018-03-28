# Python class for controlling hostapd
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time
import logging
import binascii
import struct
import wpaspy
import remotehost
import utils
import subprocess

logger = logging.getLogger()
hapd_ctrl = '/var/run/hostapd'
hapd_global = '/var/run/hostapd-global'

def mac2tuple(mac):
    return struct.unpack('6B', binascii.unhexlify(mac.replace(':','')))

class HostapdGlobal:
    def __init__(self, apdev=None):
        try:
            hostname = apdev['hostname']
            port = apdev['port']
        except:
            hostname = None
            port = 8878
        self.host = remotehost.Host(hostname)
        self.hostname = hostname
        self.port = port
        if hostname is None:
            self.ctrl = wpaspy.Ctrl(hapd_global)
            self.mon = wpaspy.Ctrl(hapd_global)
            self.dbg = ""
        else:
            self.ctrl = wpaspy.Ctrl(hostname, port)
            self.mon = wpaspy.Ctrl(hostname, port)
            self.dbg = hostname + "/" + str(port)
        self.mon.attach()

    def cmd_execute(self, cmd_array, shell=False):
        if self.hostname is None:
            if shell:
                cmd = ' '.join(cmd_array)
            else:
                cmd = cmd_array
            proc = subprocess.Popen(cmd, stderr=subprocess.STDOUT,
                                    stdout=subprocess.PIPE, shell=shell)
            out = proc.communicate()[0]
            ret = proc.returncode
            return ret, out
        else:
            return self.host.execute(cmd_array)

    def request(self, cmd, timeout=10):
        logger.debug(self.dbg + ": CTRL(global): " + cmd)
        return self.ctrl.request(cmd, timeout)

    def wait_event(self, events, timeout):
        start = os.times()[4]
        while True:
            while self.mon.pending():
                ev = self.mon.recv()
                logger.debug(self.dbg + "(global): " + ev)
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

    def add(self, ifname, driver=None):
        cmd = "ADD " + ifname + " " + hapd_ctrl
        if driver:
            cmd += " " + driver
        res = self.request(cmd)
        if not "OK" in res:
            raise Exception("Could not add hostapd interface " + ifname)

    def add_iface(self, ifname, confname):
        res = self.request("ADD " + ifname + " config=" + confname)
        if not "OK" in res:
            raise Exception("Could not add hostapd interface")

    def add_bss(self, phy, confname, ignore_error=False):
        res = self.request("ADD bss_config=" + phy + ":" + confname)
        if not "OK" in res:
            if not ignore_error:
                raise Exception("Could not add hostapd BSS")

    def remove(self, ifname):
        self.request("REMOVE " + ifname, timeout=30)

    def relog(self):
        self.request("RELOG")

    def flush(self):
        self.request("FLUSH")

    def get_ctrl_iface_port(self, ifname):
        if self.hostname is None:
            return None

        res = self.request("INTERFACES ctrl")
        lines = res.splitlines()
        found = False
        for line in lines:
            words = line.split()
            if words[0] == ifname:
                found = True
                break
        if not found:
            raise Exception("Could not find UDP port for " + ifname)
        res = line.find("ctrl_iface=udp:")
        if res == -1:
            raise Exception("Wrong ctrl_interface format")
        words = line.split(":")
        return int(words[1])

    def terminate(self):
        self.mon.detach()
        self.mon.close()
        self.mon = None
        self.ctrl.terminate()
        self.ctrl = None

class Hostapd:
    def __init__(self, ifname, bssidx=0, hostname=None, port=8877):
        self.hostname = hostname
        self.host = remotehost.Host(hostname, ifname)
        self.ifname = ifname
        if hostname is None:
            self.ctrl = wpaspy.Ctrl(os.path.join(hapd_ctrl, ifname))
            self.mon = wpaspy.Ctrl(os.path.join(hapd_ctrl, ifname))
            self.dbg = ifname
        else:
            self.ctrl = wpaspy.Ctrl(hostname, port)
            self.mon = wpaspy.Ctrl(hostname, port)
            self.dbg = hostname + "/" + ifname
        self.mon.attach()
        self.bssid = None
        self.bssidx = bssidx

    def cmd_execute(self, cmd_array, shell=False):
        if self.hostname is None:
            if shell:
                cmd = ' '.join(cmd_array)
            else:
                cmd = cmd_array
            proc = subprocess.Popen(cmd, stderr=subprocess.STDOUT,
                                    stdout=subprocess.PIPE, shell=shell)
            out = proc.communicate()[0]
            ret = proc.returncode
            return ret, out
        else:
            return self.host.execute(cmd_array)

    def close_ctrl(self):
        if self.mon is not None:
            self.mon.detach()
            self.mon.close()
            self.mon = None
            self.ctrl.close()
            self.ctrl = None

    def own_addr(self):
        if self.bssid is None:
            self.bssid = self.get_status_field('bssid[%d]' % self.bssidx)
        return self.bssid

    def request(self, cmd):
        logger.debug(self.dbg + ": CTRL: " + cmd)
        return self.ctrl.request(cmd)

    def ping(self):
        return "PONG" in self.request("PING")

    def set(self, field, value):
        if not "OK" in self.request("SET " + field + " " + value):
            raise Exception("Failed to set hostapd parameter " + field)

    def set_defaults(self):
        self.set("driver", "nl80211")
        self.set("hw_mode", "g")
        self.set("channel", "1")
        self.set("ieee80211n", "1")
        self.set("logger_stdout", "-1")
        self.set("logger_stdout_level", "0")

    def set_open(self, ssid):
        self.set_defaults()
        self.set("ssid", ssid)

    def set_wpa2_psk(self, ssid, passphrase):
        self.set_defaults()
        self.set("ssid", ssid)
        self.set("wpa_passphrase", passphrase)
        self.set("wpa", "2")
        self.set("wpa_key_mgmt", "WPA-PSK")
        self.set("rsn_pairwise", "CCMP")

    def set_wpa_psk(self, ssid, passphrase):
        self.set_defaults()
        self.set("ssid", ssid)
        self.set("wpa_passphrase", passphrase)
        self.set("wpa", "1")
        self.set("wpa_key_mgmt", "WPA-PSK")
        self.set("wpa_pairwise", "TKIP")

    def set_wpa_psk_mixed(self, ssid, passphrase):
        self.set_defaults()
        self.set("ssid", ssid)
        self.set("wpa_passphrase", passphrase)
        self.set("wpa", "3")
        self.set("wpa_key_mgmt", "WPA-PSK")
        self.set("wpa_pairwise", "TKIP")
        self.set("rsn_pairwise", "CCMP")

    def set_wep(self, ssid, key):
        self.set_defaults()
        self.set("ssid", ssid)
        self.set("wep_key0", key)

    def enable(self):
        if not "OK" in self.request("ENABLE"):
            raise Exception("Failed to enable hostapd interface " + self.ifname)

    def disable(self):
        if not "OK" in self.request("DISABLE"):
            raise Exception("Failed to disable hostapd interface " + self.ifname)

    def dump_monitor(self):
        while self.mon.pending():
            ev = self.mon.recv()
            logger.debug(self.dbg + ": " + ev)

    def wait_event(self, events, timeout):
        start = os.times()[4]
        while True:
            while self.mon.pending():
                ev = self.mon.recv()
                logger.debug(self.dbg + ": " + ev)
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

    def get_status(self):
        res = self.request("STATUS")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            [name,value] = l.split('=', 1)
            vals[name] = value
        return vals

    def get_status_field(self, field):
        vals = self.get_status()
        if field in vals:
            return vals[field]
        return None

    def get_driver_status(self):
        res = self.request("STATUS-DRIVER")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            [name,value] = l.split('=', 1)
            vals[name] = value
        return vals

    def get_driver_status_field(self, field):
        vals = self.get_driver_status()
        if field in vals:
            return vals[field]
        return None

    def get_config(self):
        res = self.request("GET_CONFIG")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            [name,value] = l.split('=', 1)
            vals[name] = value
        return vals

    def mgmt_rx(self, timeout=5):
        ev = self.wait_event(["MGMT-RX"], timeout=timeout)
        if ev is None:
            return None
        msg = {}
        frame = binascii.unhexlify(ev.split(' ')[1])
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

    def mgmt_tx(self, msg):
        t = (msg['fc'], 0) + mac2tuple(msg['da']) + mac2tuple(msg['sa']) + mac2tuple(msg['bssid']) + (0,)
        hdr = struct.pack('<HH6B6B6BH', *t)
        if "OK" not in self.request("MGMT_TX " + binascii.hexlify(hdr + msg['payload'])):
            raise Exception("MGMT_TX command to hostapd failed")

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
            if first and '=' not in l:
                vals['addr'] = l
                first = False
            else:
                [name,value] = l.split('=', 1)
                vals[name] = value
        return vals

    def get_mib(self, param=None):
        if param:
            res = self.request("MIB " + param)
        else:
            res = self.request("MIB")
        lines = res.splitlines()
        vals = dict()
        for l in lines:
            name_val = l.split('=', 1)
            if len(name_val) > 1:
                vals[name_val[0]] = name_val[1]
        return vals

    def get_pmksa(self, addr):
        res = self.request("PMKSA")
        lines = res.splitlines()
        for l in lines:
            if addr not in l:
                continue
            vals = dict()
            [index,aa,pmkid,expiration,opportunistic] = l.split(' ')
            vals['index'] = index
            vals['pmkid'] = pmkid
            vals['expiration'] = expiration
            vals['opportunistic'] = opportunistic
            return vals
        return None

def add_ap(apdev, params, wait_enabled=True, no_enable=False, timeout=30):
        if isinstance(apdev, dict):
            ifname = apdev['ifname']
            try:
                hostname = apdev['hostname']
                port = apdev['port']
                logger.info("Starting AP " + hostname + "/" + port + " " + ifname)
            except:
                logger.info("Starting AP " + ifname)
                hostname = None
                port = 8878
        else:
            ifname = apdev
            logger.info("Starting AP " + ifname + " (old add_ap argument type)")
            hostname = None
            port = 8878
        hapd_global = HostapdGlobal(apdev)
        hapd_global.remove(ifname)
        hapd_global.add(ifname)
        port = hapd_global.get_ctrl_iface_port(ifname)
        hapd = Hostapd(ifname, hostname=hostname, port=port)
        if not hapd.ping():
            raise Exception("Could not ping hostapd")
        hapd.set_defaults()
        fields = [ "ssid", "wpa_passphrase", "nas_identifier", "wpa_key_mgmt",
                   "wpa",
                   "wpa_pairwise", "rsn_pairwise", "auth_server_addr",
                   "acct_server_addr", "osu_server_uri" ]
        for field in fields:
            if field in params:
                hapd.set(field, params[field])
        for f,v in params.items():
            if f in fields:
                continue
            if isinstance(v, list):
                for val in v:
                    hapd.set(f, val)
            else:
                hapd.set(f, v)
        if no_enable:
            return hapd
        hapd.enable()
        if wait_enabled:
            ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=timeout)
            if ev is None:
                raise Exception("AP startup timed out")
            if "AP-ENABLED" not in ev:
                raise Exception("AP startup failed")
        return hapd

def add_bss(apdev, ifname, confname, ignore_error=False):
    phy = utils.get_phy(apdev)
    try:
        hostname = apdev['hostname']
        port = apdev['port']
        logger.info("Starting BSS " + hostname + "/" + port + " phy=" + phy + " ifname=" + ifname)
    except:
        logger.info("Starting BSS phy=" + phy + " ifname=" + ifname)
        hostname = None
        port = 8878
    hapd_global = HostapdGlobal(apdev)
    hapd_global.add_bss(phy, confname, ignore_error)
    port = hapd_global.get_ctrl_iface_port(ifname)
    hapd = Hostapd(ifname, hostname=hostname, port=port)
    if not hapd.ping():
        raise Exception("Could not ping hostapd")
    return hapd

def add_iface(apdev, confname):
    ifname = apdev['ifname']
    try:
        hostname = apdev['hostname']
        port = apdev['port']
        logger.info("Starting interface " + hostname + "/" + port + " " + ifname)
    except:
        logger.info("Starting interface " + ifname)
        hostname = None
        port = 8878
    hapd_global = HostapdGlobal(apdev)
    hapd_global.add_iface(ifname, confname)
    port = hapd_global.get_ctrl_iface_port(ifname)
    hapd = Hostapd(ifname, hostname=hostname, port=port)
    if not hapd.ping():
        raise Exception("Could not ping hostapd")
    return hapd

def remove_bss(apdev, ifname=None):
    if ifname == None:
        ifname = apdev['ifname']
    try:
        hostname = apdev['hostname']
        port = apdev['port']
        logger.info("Removing BSS " + hostname + "/" + port + " " + ifname)
    except:
        logger.info("Removing BSS " + ifname)
    hapd_global = HostapdGlobal(apdev)
    hapd_global.remove(ifname)

def terminate(apdev):
    try:
        hostname = apdev['hostname']
        port = apdev['port']
        logger.info("Terminating hostapd " + hostname + "/" + port)
    except:
        logger.info("Terminating hostapd")
    hapd_global = HostapdGlobal(apdev)
    hapd_global.terminate()

def wpa2_params(ssid=None, passphrase=None):
    params = { "wpa": "2",
               "wpa_key_mgmt": "WPA-PSK",
               "rsn_pairwise": "CCMP" }
    if ssid:
        params["ssid"] = ssid
    if passphrase:
        params["wpa_passphrase"] = passphrase
    return params

def wpa_params(ssid=None, passphrase=None):
    params = { "wpa": "1",
               "wpa_key_mgmt": "WPA-PSK",
               "wpa_pairwise": "TKIP" }
    if ssid:
        params["ssid"] = ssid
    if passphrase:
        params["wpa_passphrase"] = passphrase
    return params

def wpa_mixed_params(ssid=None, passphrase=None):
    params = { "wpa": "3",
               "wpa_key_mgmt": "WPA-PSK",
               "wpa_pairwise": "TKIP",
               "rsn_pairwise": "CCMP" }
    if ssid:
        params["ssid"] = ssid
    if passphrase:
        params["wpa_passphrase"] = passphrase
    return params

def radius_params():
    params = { "auth_server_addr": "127.0.0.1",
               "auth_server_port": "1812",
               "auth_server_shared_secret": "radius",
               "nas_identifier": "nas.w1.fi" }
    return params

def wpa_eap_params(ssid=None):
    params = radius_params()
    params["wpa"] = "1"
    params["wpa_key_mgmt"] = "WPA-EAP"
    params["wpa_pairwise"] = "TKIP"
    params["ieee8021x"] = "1"
    if ssid:
        params["ssid"] = ssid
    return params

def wpa2_eap_params(ssid=None):
    params = radius_params()
    params["wpa"] = "2"
    params["wpa_key_mgmt"] = "WPA-EAP"
    params["rsn_pairwise"] = "CCMP"
    params["ieee8021x"] = "1"
    if ssid:
        params["ssid"] = ssid
    return params

def b_only_params(channel="1", ssid=None, country=None):
    params = { "hw_mode" : "b",
               "channel" : channel }
    if ssid:
        params["ssid"] = ssid
    if country:
        params["country_code"] = country
    return params

def g_only_params(channel="1", ssid=None, country=None):
    params = { "hw_mode" : "g",
               "channel" : channel }
    if ssid:
        params["ssid"] = ssid
    if country:
        params["country_code"] = country
    return params

def a_only_params(channel="36", ssid=None, country=None):
    params = { "hw_mode" : "a",
               "channel" : channel }
    if ssid:
        params["ssid"] = ssid
    if country:
        params["country_code"] = country
    return params

def ht20_params(channel="1", ssid=None, country=None):
    params = { "ieee80211n" : "1",
               "channel" : channel,
               "hw_mode" : "g" }
    if int(channel) > 14:
        params["hw_mode"] = "a"
    if ssid:
        params["ssid"] = ssid
    if country:
        params["country_code"] = country
    return params

def ht40_plus_params(channel="1", ssid=None, country=None):
    params = ht20_params(channel, ssid, country)
    params['ht_capab'] = "[HT40+]"
    return params

def ht40_minus_params(channel="1", ssid=None, country=None):
    params = ht20_params(channel, ssid, country)
    params['ht_capab'] = "[HT40-]"
    return params

def cmd_execute(apdev, cmd, shell=False):
    hapd_global = HostapdGlobal(apdev)
    return hapd_global.cmd_execute(cmd, shell=shell)
