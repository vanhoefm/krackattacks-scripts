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

logger = logging.getLogger()
hapd_ctrl = '/var/run/hostapd'
hapd_global = '/var/run/hostapd-global'

def mac2tuple(mac):
    return struct.unpack('6B', binascii.unhexlify(mac.replace(':','')))

class HostapdGlobal:
    def __init__(self):
        self.ctrl = wpaspy.Ctrl(hapd_global)

    def add(self, ifname):
        res = self.ctrl.request("ADD " + ifname + " " + hapd_ctrl)
        if not "OK" in res:
            raise Exception("Could not add hostapd interface " + ifname)

    def add_iface(self, ifname, confname):
        res = self.ctrl.request("ADD " + ifname + " config=" + confname)
        if not "OK" in res:
            raise Exception("Could not add hostapd interface")

    def add_bss(self, phy, confname, ignore_error=False):
        res = self.ctrl.request("ADD bss_config=" + phy + ":" + confname)
        if not "OK" in res:
            if not ignore_error:
                raise Exception("Could not add hostapd BSS")

    def remove(self, ifname):
        self.ctrl.request("REMOVE " + ifname, timeout=30)

    def relog(self):
        self.ctrl.request("RELOG")

    def flush(self):
        self.ctrl.request("FLUSH")


class Hostapd:
    def __init__(self, ifname):
        self.ifname = ifname
        self.ctrl = wpaspy.Ctrl(os.path.join(hapd_ctrl, ifname))
        self.mon = wpaspy.Ctrl(os.path.join(hapd_ctrl, ifname))
        self.mon.attach()
        self.bssid = None

    def own_addr(self):
        if self.bssid is None:
            self.bssid = self.get_status_field('bssid[0]')
        return self.bssid

    def request(self, cmd):
        logger.debug(self.ifname + ": CTRL: " + cmd)
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
            logger.debug(self.ifname + ": " + ev)

    def wait_event(self, events, timeout):
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
        self.request("MGMT_TX " + binascii.hexlify(hdr + msg['payload']))

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

def add_ap(ifname, params, wait_enabled=True, no_enable=False):
        logger.info("Starting AP " + ifname)
        hapd_global = HostapdGlobal()
        hapd_global.remove(ifname)
        hapd_global.add(ifname)
        hapd = Hostapd(ifname)
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
            ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=30)
            if ev is None:
                raise Exception("AP startup timed out")
            if "AP-ENABLED" not in ev:
                raise Exception("AP startup failed")
        return hapd

def add_bss(phy, ifname, confname, ignore_error=False):
    logger.info("Starting BSS phy=" + phy + " ifname=" + ifname)
    hapd_global = HostapdGlobal()
    hapd_global.add_bss(phy, confname, ignore_error)
    hapd = Hostapd(ifname)
    if not hapd.ping():
        raise Exception("Could not ping hostapd")

def add_iface(ifname, confname):
    logger.info("Starting interface " + ifname)
    hapd_global = HostapdGlobal()
    hapd_global.add_iface(ifname, confname)
    hapd = Hostapd(ifname)
    if not hapd.ping():
        raise Exception("Could not ping hostapd")

def remove_bss(ifname):
    logger.info("Removing BSS " + ifname)
    hapd_global = HostapdGlobal()
    hapd_global.remove(ifname)

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
