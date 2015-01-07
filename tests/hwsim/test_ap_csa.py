# AP CSA tests
# Copyright (c) 2013, Luciano Coelho <luciano.coelho@intel.com>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hwsim_utils
import hostapd
from utils import HwsimSkip

def connect(dev, apdev):
    params = { "ssid": "ap-csa",
               "channel": "1" }
    ap = hostapd.add_ap(apdev[0]['ifname'], params)
    dev.connect("ap-csa", key_mgmt="NONE")
    return ap

def switch_channel(ap, count, freq):
    ap.request("CHAN_SWITCH " + str(count) + " " + str(freq))
    ev = ap.wait_event(["AP-CSA-FINISHED"], timeout=10)
    if ev is None:
        raise Exception("CSA finished event timed out")
    if "freq=" + str(freq) not in ev:
        raise Exception("Unexpected channel in CSA finished event")
    time.sleep(0.1)

# This function checks whether the provided dev, which may be either
# WpaSupplicant or Hostapd supports CSA.
def csa_supported(dev):
    res = dev.get_driver_status()
    if (int(res['capa.flags'], 0) & 0x80000000) == 0:
        raise HwsimSkip("CSA not supported")

def test_ap_csa_1_switch(dev, apdev):
    """AP Channel Switch, one switch"""
    csa_supported(dev[0])
    ap = connect(dev[0], apdev)

    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 10, 2462)
    hwsim_utils.test_connectivity(dev[0], ap)

def test_ap_csa_2_switches(dev, apdev):
    """AP Channel Switch, two switches"""
    csa_supported(dev[0])
    ap = connect(dev[0], apdev)

    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 10, 2462)
    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 10, 2412)
    hwsim_utils.test_connectivity(dev[0], ap)

def test_ap_csa_1_switch_count_0(dev, apdev):
    """AP Channel Switch, one switch with count 0"""
    csa_supported(dev[0])
    ap = connect(dev[0], apdev)

    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 0, 2462)
    # this does not result in CSA currently, so do not bother checking
    # connectivity

def test_ap_csa_2_switches_count_0(dev, apdev):
    """AP Channel Switch, two switches with count 0"""
    csa_supported(dev[0])
    ap = connect(dev[0], apdev)

    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 0, 2462)
    # this does not result in CSA currently, so do not bother checking
    # connectivity
    switch_channel(ap, 0, 2412)
    # this does not result in CSA currently, so do not bother checking
    # connectivity

def test_ap_csa_1_switch_count_1(dev, apdev):
    """AP Channel Switch, one switch with count 1"""
    csa_supported(dev[0])
    ap = connect(dev[0], apdev)

    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 1, 2462)
    # this does not result in CSA currently, so do not bother checking
    # connectivity

def test_ap_csa_2_switches_count_1(dev, apdev):
    """AP Channel Switch, two switches with count 1"""
    csa_supported(dev[0])
    ap = connect(dev[0], apdev)

    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 1, 2462)
    # this does not result in CSA currently, so do not bother checking
    # connectivity
    switch_channel(ap, 1, 2412)
    # this does not result in CSA currently, so do not bother checking
    # connectivity

def test_ap_csa_1_switch_count_2(dev, apdev):
    """AP Channel Switch, one switch with count 2"""
    csa_supported(dev[0])
    ap = connect(dev[0], apdev)

    hwsim_utils.test_connectivity(dev[0], ap)
    switch_channel(ap, 2, 2462)
    hwsim_utils.test_connectivity(dev[0], ap)
