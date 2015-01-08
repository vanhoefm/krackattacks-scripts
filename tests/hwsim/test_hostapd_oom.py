# hostapd and out-of-memory error paths
# Copyright (c) 2015, Jouni Malinen
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd
from utils import HwsimSkip

def hostapd_oom_loop(apdev, params):
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "ctrl" })
    hapd_global = hostapd.HostapdGlobal()

    count = 0
    for i in range(1, 1000):
        if "OK" not in hapd.request("TEST_ALLOC_FAIL %d:main" % i):
            raise HwsimSkip("TEST_ALLOC_FAIL not supported")
        try:
            hostapd.add_ap(apdev[1]['ifname'], params)
            logger.info("Iteration %d - success" % i)
            hapd_global.remove(apdev[1]['ifname'])

            state = hapd.request('GET_ALLOC_FAIL')
            logger.info("GET_ALLOC_FAIL: " + state)
            hapd.request("TEST_ALLOC_FAIL 0:")
            if i < 3:
                raise Exception("AP setup succeeded during out-of-memory")
            if not state.startswith('0:'):
                count += 1
                if count == 5:
                    break
        except Exception, e:
            logger.info("Iteration %d - %s" % (i, str(e)))

def test_hostapd_oom_open(dev, apdev):
    """hostapd failing to setup open mode due to OOM"""
    params = { "ssid": "open" }
    hostapd_oom_loop(apdev, params)

def test_hostapd_oom_wpa2_psk(dev, apdev):
    """hostapd failing to setup WPA2-PSK mode due to OOM"""
    params = hostapd.wpa2_params(ssid="test", passphrase="12345678")
    hostapd_oom_loop(apdev, params)

def test_hostapd_oom_wpa2_eap(dev, apdev):
    """hostapd failing to setup WPA2-EAP mode due to OOM"""
    params = hostapd.wpa2_eap_params(ssid="test")
    hostapd_oom_loop(apdev, params)
