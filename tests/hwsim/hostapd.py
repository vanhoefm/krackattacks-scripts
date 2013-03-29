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

logger = logging.getLogger(__name__)
hapd_ctrl = '/var/run/hostapd'
hapd_global = 'hostapd-global'

class HostapdGlobal:
    def __init__(self):
        self.ctrl = wpaspy.Ctrl(hapd_global)

    def add(self, ifname):
        res = self.ctrl.request("ADD " + ifname + " " + hapd_ctrl)
        if not "OK" in res:
            raise Exception("Could not add hostapd interface " + ifname)

    def remove(self, ifname):
        self.ctrl.request("REMOVE " + ifname)


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

    def enable(self):
        if not "OK" in self.ctrl.request("ENABLE"):
            raise Exception("Failed to enable hostapd interface " + self.ifname)

    def disable(self):
        if not "OK" in self.ctrl.request("ENABLE"):
            raise Exception("Failed to disable hostapd interface " + self.ifname)
