# Test cases for wpa_supplicant WMM-AC operations
# Copyright (c) 2014, Intel Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd

def add_wmm_ap(apdev, acm_list):
    params = { "ssid": "wmm_ac",
               "hw_mode": "g",
               "channel": "11",
               "wmm_enabled" : "1"}

    for ac in acm_list:
        params["wmm_ac_%s_acm" % (ac.lower())] = "1"

    return hostapd.add_ap(apdev[0]['ifname'], params)

def test_tspec(dev, apdev):
    """Basic addts/delts tests"""
    # configure ap with VO and VI requiring admission-control
    hapd = add_wmm_ap(apdev, ["VO", "VI"])
    dev[0].connect("wmm_ac", key_mgmt="NONE", scan_freq="2462")
    hwsim_utils.test_connectivity(dev[0], hapd)
    status = dev[0].request("WMM_AC_STATUS")
    if "WMM AC is Enabled" not in status:
        raise Exception("WMM-AC not enabled")
    if "TSID" in status:
        raise Exception("Unexpected TSID info")
    if "BK: acm=0 uapsd=0" not in status:
        raise Exception("Unexpected BK info" + status)
    if "BE: acm=0 uapsd=0" not in status:
        raise Exception("Unexpected BE info" + status)
    if "VI: acm=1 uapsd=0" not in status:
        raise Exception("Unexpected VI info" + status)
    if "VO: acm=1 uapsd=0" not in status:
        raise Exception("Unexpected VO info" + status)

    tsid = 5

    # make sure we fail when the ac is not configured for acm
    try:
        dev[0].add_ts(tsid, 3)
        raise Exception("ADDTS succeeded although it should have failed")
    except Exception, e:
        if not str(e).startswith("ADDTS failed"):
            raise
    status = dev[0].request("WMM_AC_STATUS")
    if "TSID" in status:
        raise Exception("Unexpected TSID info")

    # add tspec for UP=6
    dev[0].add_ts(tsid, 6)
    status = dev[0].request("WMM_AC_STATUS")
    if "TSID" not in status:
        raise Exception("Missing TSID info")

    # using the same tsid for a different ac is invalid
    try:
        dev[0].add_ts(tsid, 5)
        raise Exception("ADDTS succeeded although it should have failed")
    except Exception, e:
        if not str(e).startswith("ADDTS failed"):
            raise

    # update the tspec for a different UP of the same ac
    dev[0].add_ts(tsid, 7)
    dev[0].del_ts(tsid)
    status = dev[0].request("WMM_AC_STATUS")
    if "TSID" in status:
        raise Exception("Unexpected TSID info")
