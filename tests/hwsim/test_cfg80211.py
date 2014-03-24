# cfg80211 test cases
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii

import hostapd
from nl80211 import *

def nl80211_command(dev, cmd, attr):
    res = dev.request("VENDOR ffffffff {} {}".format(nl80211_cmd[cmd],
                                                     binascii.hexlify(attr)))
    if "FAIL" in res:
        raise Exception("nl80211 command failed")
    return binascii.unhexlify(res)

def test_cfg80211_disassociate(dev, apdev):
    """cfg80211 disassociation command"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")

    ifindex = int(dev[0].get_driver_status_field("ifindex"))
    attrs = build_nl80211_attr_u32('IFINDEX', ifindex)
    attrs += build_nl80211_attr_u16('REASON_CODE', 1)
    attrs += build_nl80211_attr_mac('MAC', apdev[0]['bssid'])
    nl80211_command(dev[0], 'DISASSOCIATE', attrs)

    ev = hapd.wait_event([ "AP-STA-DISCONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No disconnection event received from hostapd")
