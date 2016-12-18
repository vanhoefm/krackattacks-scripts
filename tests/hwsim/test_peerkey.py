# PeerKey tests
# Copyright (c) 2013-2016, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import logging
logger = logging.getLogger()
import os
import time

import hwsim_utils
import hostapd
from utils import skip_with_fips
from wlantest import Wlantest
from tshark import run_tshark

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

def test_peerkey_sniffer_check(dev, apdev, params):
    """RSN AP and PeerKey between two STAs with sniffer check"""
    ssid = "test-peerkey"
    passphrase = "12345678"
    hparams = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hparams['peerkey'] = "1"
    hapd = hostapd.add_ap(apdev[0], hparams)

    Wlantest.setup(hapd)
    wt = Wlantest()
    wt.flush()
    wt.add_passphrase("12345678")

    dev[0].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True)
    dev[1].connect(ssid, psk=passphrase, scan_freq="2412", peerkey=True)
    hwsim_utils.test_connectivity_sta(dev[0], dev[1])

    dev[0].request("STKSTART " + dev[1].p2p_interface_addr())
    time.sleep(1)
    # NOTE: Actual use of the direct link (DLS) is not supported in
    # mac80211_hwsim, so this operation fails at setting the keys after
    # successfully completed 4-way handshake. This test case does allow the
    # key negotiation part to be tested for coverage, though. Use sniffer to
    # verify that all the SMK and STK handshake messages were transmitted.

    bssid = hapd.own_addr()
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()

    out = run_tshark(os.path.join(params['logdir'], "hwsim0.pcapng"),
                     "eapol.type == 3",
                     display=["wlan.sa", "wlan.da", "eapol.keydes.key_info"])

    smk = [ False, False, False, False, False ]
    stk = [ False, False, False, False ]

    for pkt in out.splitlines():
        sa, da, key_info = pkt.split('\t')
        key_info = int(key_info, 16)
        if sa == addr0 and da == bssid and key_info == 0x2b02:
            # Initiator -> AP: MIC+Secure+Request+SMK = SMK 1
            smk[0] = True
        elif sa == bssid and da == addr1 and key_info == 0x2382:
            # AP -> Responder: ACK+MIC+Secure+SMK = SMK 2
            smk[1] = True
        elif sa == addr1 and da == bssid and key_info == 0x2302:
            # Responder -> AP: MIC+Secure+SMK = SMK 3
            smk[2] = True
        elif sa == bssid and da == addr1 and key_info == 0x3342:
            # AP -> Responder: Install+MIC+Secure+EncrKeyData+SMK = SMK 4
            smk[3] = True
        elif sa == bssid and da == addr0 and key_info == 0x3302:
            # AP -> Initiator: MIC+Secure+EncrKeyData+SMK = SMK 5
            smk[4] = True
        elif sa == addr0 and da == addr1 and key_info == 0x008a:
            # Initiator -> Responder: Pairwise+ACK = STK 1
            stk[0] = True
        elif sa == addr1 and da == addr0 and key_info == 0x010a:
            # Responder -> Initiator: Pairwise+MIC = STK 2
            stk[1] = True
        elif sa == addr0 and da == addr1 and key_info == 0x038a:
            # Initiator -> Responder: Pairwise+ACK+MIC+Secure = STK 3
            stk[2] = True
        elif sa == addr1 and da == addr0 and key_info == 0x030a:
            # Responder -> Initiator: Pairwise+MIC+Secure = STK 4
            stk[3] = True

    logger.info("Seen SMK messages: " + str(smk))
    logger.info("Seen STK messages: " + str(stk))
    if False in smk:
        raise Exception("Missing SMK message: " + str(smk))
    if False in stk:
        raise Exception("Missing STK message: " + str(stk))

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
