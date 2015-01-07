# Suite B tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hostapd
from utils import HwsimSkip

def test_suite_b(dev, apdev):
    """WPA2-PSK/GCMP connection"""
    if "GCMP" not in dev[0].get_capability("pairwise"):
        raise HwsimSkip("GCMP not supported")
    params = hostapd.wpa2_eap_params(ssid="test-suite-b")
    params["wpa_key_mgmt"] = "WPA-EAP-SUITE-B"
    params['rsn_pairwise'] = "GCMP"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    # TODO: Force Suite B configuration for TLS
    dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B",
                   eap="TLS", identity="tls user", ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   pairwise="GCMP", group="GCMP", scan_freq="2412")

    bss = dev[0].get_bss(apdev[0]['bssid'])
    if 'flags' not in bss:
        raise Exception("Could not get BSS flags from BSS table")
    if "[WPA2-EAP-SUITE-B-GCMP]" not in bss['flags']:
        raise Exception("Unexpected BSS flags: " + bss['flags'])

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=20)
    dev[0].dump_monitor()
    dev[0].request("RECONNECT")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=20)
    if ev is None:
        raise Exception("Roaming with the AP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
