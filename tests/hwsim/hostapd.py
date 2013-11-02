#!/usr/bin/python
#
# Python class for controlling hostapd
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time
import logging
import wpaspy

logger = logging.getLogger()
hapd_ctrl = '/var/run/hostapd'
hapd_global = '/var/run/hostapd-global'

class HostapdGlobal:
    def __init__(self):
        self.ctrl = wpaspy.Ctrl(hapd_global)

    def add(self, ifname):
        res = self.ctrl.request("ADD " + ifname + " " + hapd_ctrl)
        if not "OK" in res:
            raise Exception("Could not add hostapd interface " + ifname)

    def add_bss(self, phy, confname, ignore_error=False):
        res = self.ctrl.request("ADD bss_config=" + phy + ":" + confname)
        if not "OK" in res:
            if not ignore_error:
                raise Exception("Could not add hostapd BSS")

    def remove(self, ifname):
        self.ctrl.request("REMOVE " + ifname)

    def relog(self):
        self.ctrl.request("RELOG")


class Hostapd:
    def __init__(self, ifname):
        self.ifname = ifname
        self.ctrl = wpaspy.Ctrl(os.path.join(hapd_ctrl, ifname))

    def request(self, cmd):
        logger.debug(self.ifname + ": CTRL: " + cmd)
        return self.ctrl.request(cmd)

    def ping(self):
        return "PONG" in self.request("PING")

    def set(self, field, value):
        logger.debug(self.ifname + ": SET " + field + "=" + value)
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
        if not "OK" in self.ctrl.request("ENABLE"):
            raise Exception("Failed to enable hostapd interface " + self.ifname)

    def disable(self):
        if not "OK" in self.ctrl.request("ENABLE"):
            raise Exception("Failed to disable hostapd interface " + self.ifname)

def add_ap(ifname, params):
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
                   "wpa_pairwise", "rsn_pairwise", "auth_server_addr" ]
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
        hapd.enable()

def add_bss(phy, ifname, confname, ignore_error=False):
    logger.info("Starting BSS phy=" + phy + " ifname=" + ifname)
    hapd_global = HostapdGlobal()
    hapd_global.add_bss(phy, confname, ignore_error)
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

def wpa2_eap_params(ssid=None):
    params = radius_params()
    params["wpa"] = "2"
    params["wpa_key_mgmt"] = "WPA-EAP"
    params["rsn_pairwise"] = "CCMP"
    params["ieee8021x"] = "1"
    if ssid:
        params["ssid"] = ssid
    return params
