# PeerKey tests
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import logging
logger = logging.getLogger()
import time

import hwsim_utils
import hostapd
from utils import skip_with_fips
from wlantest import Wlantest

@remote_compatible
def test_peerkey(dev, apdev):
    """RSN AP and PeerKey between two STAs"""
    ssid = "test-peerkey"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['peerkey'] = "1"
    hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True)
    dev[1].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True)
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

    dev[0].request("STKSTART " + dev[1].p2p_interface_addr())
    time.sleep(0.5)
    # NOTE: Actual use of the direct link (DLS) is not supported in
    # mac80211_hwsim, so this operation fails at setting the keys after
    # successfully completed 4-way handshake. This test case does allow the
    # key negotiation part to be tested for coverage, though.

def test_peerkey_unknown_peer(dev, apdev):
    """RSN AP and PeerKey attempt with unknown peer"""
    ssid = "test-peerkey"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['peerkey'] = "1"
    hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True)
    dev[1].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True)
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

    dev[0].request("STKSTART " + dev[2].p2p_interface_addr())
    time.sleep(0.5)

@remote_compatible
def test_peerkey_pairwise_mismatch(dev, apdev):
    """RSN TKIP+CCMP AP and PeerKey between two STAs using different ciphers"""
    skip_with_fips(dev[0])
    ssid = "test-peerkey"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['peerkey'] = "1"
    params['rsn_pairwise'] = "TKIP CCMP"
    hapd = hostapd.add_ap(apdev[0], params)

    Wlantest.setup(hapd)
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")

    dev[0].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True,
                   pairwise="CCMP")
    dev[1].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True,
                   pairwise="TKIP")
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

    dev[0].request("STKSTART " + dev[1].p2p_interface_addr())
    time.sleep(0.5)
    dev[1].request("STKSTART " + dev[0].p2p_interface_addr())
    time.sleep(0.5)
