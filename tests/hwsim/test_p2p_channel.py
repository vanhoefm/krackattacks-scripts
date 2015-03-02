# P2P channel selection test cases
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import subprocess
import time

import hostapd
import hwsim_utils
from tshark import run_tshark
from wpasupplicant import WpaSupplicant
from hwsim import HWSimRadio
from test_p2p_grpform import go_neg_pin_authorized
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group
from test_p2p_grpform import go_neg_pbc
from test_p2p_autogo import autogo

def set_country(country, dev=None):
    subprocess.call(['iw', 'reg', 'set', country])
    time.sleep(0.1)
    if dev:
        for i in range(10):
            ev = dev.wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=15)
            if ev is None:
                raise Exception("No regdom change event seen")
            if "type=COUNTRY alpha2=" + country in ev:
                return
        raise Exception("No matching regdom event seen for set_country(%s)" % country)

def test_p2p_channel_5ghz(dev):
    """P2P group formation with 5 GHz preference"""
    try:
        set_country("US", dev[0])
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq < 5000:
            raise Exception("Unexpected channel %d MHz - did not follow 5 GHz preference" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")
        dev[1].flush_scan_cache()

def test_p2p_channel_5ghz_no_vht(dev):
    """P2P group formation with 5 GHz preference when VHT channels are disallowed"""
    try:
        set_country("US", dev[0])
        dev[0].request("P2P_SET disallow_freq 5180-5240")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq < 5000:
            raise Exception("Unexpected channel %d MHz - did not follow 5 GHz preference" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")
        dev[1].flush_scan_cache()

def test_p2p_channel_random_social(dev):
    """P2P group formation with 5 GHz preference but all 5 GHz channels disabled"""
    try:
        set_country("US", dev[0])
        dev[0].request("SET p2p_oper_channel 11")
        dev[0].request("P2P_SET disallow_freq 5000-6000,2462")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq not in [ 2412, 2437, 2462 ]:
            raise Exception("Unexpected channel %d MHz - did not pick random social channel" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")
        dev[1].flush_scan_cache()

def test_p2p_channel_random(dev):
    """P2P group formation with 5 GHz preference but all 5 GHz channels and all social channels disabled"""
    try:
        set_country("US", dev[0])
        dev[0].request("SET p2p_oper_channel 11")
        dev[0].request("P2P_SET disallow_freq 5000-6000,2412,2437,2462")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq > 2500 or freq in [ 2412, 2437, 2462 ]:
            raise Exception("Unexpected channel %d MHz" % freq)
        remove_group(dev[0], dev[1])
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")
        dev[1].flush_scan_cache()

def test_p2p_channel_random_social_with_op_class_change(dev, apdev, params):
    """P2P group formation using random social channel with oper class change needed"""
    try:
        set_country("US", dev[0])
        logger.info("Start group on 5 GHz")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq < 5000:
            raise Exception("Unexpected channel %d MHz - did not pick 5 GHz preference" % freq)
        remove_group(dev[0], dev[1])

        logger.info("Disable 5 GHz and try to re-start group based on 5 GHz preference")
        dev[0].request("SET p2p_oper_reg_class 115")
        dev[0].request("SET p2p_oper_channel 36")
        dev[0].request("P2P_SET disallow_freq 5000-6000")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq not in [ 2412, 2437, 2462 ]:
            raise Exception("Unexpected channel %d MHz - did not pick random social channel" % freq)
        remove_group(dev[0], dev[1])

        out = run_tshark(os.path.join(params['logdir'], "hwsim0.pcapng"),
                         "wifi_p2p.public_action.subtype == 0")
        if out is not None:
            last = None
            for l in out.splitlines():
                if "Operating Channel:" not in l:
                    continue
                last = l
            if last is None:
                raise Exception("Could not find GO Negotiation Request")
            if "Operating Class 81" not in last:
                raise Exception("Unexpected operating class: " + last.strip())
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")
        dev[0].request("SET p2p_oper_reg_class 0")
        dev[0].request("SET p2p_oper_channel 0")
        dev[1].flush_scan_cache()

def test_p2p_channel_avoid(dev):
    """P2P and avoid frequencies driver event"""
    try:
        set_country("US", dev[0])
        if "OK" not in dev[0].request("DRIVER_EVENT AVOID_FREQUENCIES 5000-6000,2412,2437,2462"):
            raise Exception("Could not simulate driver event")
        ev = dev[0].wait_event(["CTRL-EVENT-AVOID-FREQ"], timeout=10)
        if ev is None:
            raise Exception("No CTRL-EVENT-AVOID-FREQ event")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0,
                                               test_data=False)
        check_grpform_results(i_res, r_res)
        freq = int(i_res['freq'])
        if freq > 2500 or freq in [ 2412, 2437, 2462 ]:
            raise Exception("Unexpected channel %d MHz" % freq)

        if "OK" not in dev[0].request("DRIVER_EVENT AVOID_FREQUENCIES"):
            raise Exception("Could not simulate driver event(2)")
        ev = dev[0].wait_event(["CTRL-EVENT-AVOID-FREQ"], timeout=10)
        if ev is None:
            raise Exception("No CTRL-EVENT-AVOID-FREQ event")
        ev = dev[0].wait_group_event(["P2P-REMOVE-AND-REFORM-GROUP"], timeout=1)
        if ev is not None:
            raise Exception("Unexpected P2P-REMOVE-AND-REFORM-GROUP event")

        if "OK" not in dev[0].request("DRIVER_EVENT AVOID_FREQUENCIES " + str(freq)):
            raise Exception("Could not simulate driver event(3)")
        ev = dev[0].wait_event(["CTRL-EVENT-AVOID-FREQ"], timeout=10)
        if ev is None:
            raise Exception("No CTRL-EVENT-AVOID-FREQ event")
        ev = dev[0].wait_group_event(["P2P-REMOVE-AND-REFORM-GROUP"],
                                     timeout=10)
        if ev is None:
            raise Exception("No P2P-REMOVE-AND-REFORM-GROUP event")
    finally:
        set_country("00")
        dev[0].request("DRIVER_EVENT AVOID_FREQUENCIES")
        dev[1].flush_scan_cache()

def test_autogo_following_bss(dev, apdev):
    """P2P autonomous GO operate on the same channel as station interface"""
    if dev[0].get_mcc() > 1:
        logger.info("test mode: MCC")

    dev[0].request("SET p2p_no_group_iface 0")

    channels = { 3 : "2422", 5 : "2432", 9 : "2452" }
    for key in channels:
        hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid" : 'ap-test',
                                                    "channel" : str(key) })
        dev[0].connect("ap-test", key_mgmt="NONE",
                       scan_freq=str(channels[key]))
        res_go = autogo(dev[0])
        if res_go['freq'] != channels[key]:
            raise Exception("Group operation channel is not the same as on connected station interface")
        hwsim_utils.test_connectivity(dev[0], hapd)
        dev[0].remove_group(res_go['ifname'])

def test_go_neg_with_bss_connected(dev, apdev):
    """P2P channel selection: GO negotiation when station interface is connected"""

    dev[0].flush_scan_cache()
    dev[1].flush_scan_cache()
    dev[0].request("SET p2p_no_group_iface 0")

    hapd = hostapd.add_ap(apdev[0]['ifname'],
                          { "ssid": 'bss-2.4ghz', "channel": '5' })
    dev[0].connect("bss-2.4ghz", key_mgmt="NONE", scan_freq="2432")
    #dev[0] as GO
    [i_res, r_res] = go_neg_pbc(i_dev=dev[0], i_intent=10, r_dev=dev[1],
                                r_intent=1)
    check_grpform_results(i_res, r_res)
    if i_res['role'] != "GO":
       raise Exception("GO not selected according to go_intent")
    if i_res['freq'] != "2432":
       raise Exception("Group formed on a different frequency than BSS")
    hwsim_utils.test_connectivity(dev[0], hapd)
    dev[0].remove_group(i_res['ifname'])

    if dev[0].get_mcc() > 1:
        logger.info("Skip as-client case due to MCC being enabled")
        return;

    #dev[0] as client
    [i_res2, r_res2] = go_neg_pbc(i_dev=dev[0], i_intent=1, r_dev=dev[1],
                                  r_intent=10)
    check_grpform_results(i_res2, r_res2)
    if i_res2['role'] != "client":
       raise Exception("GO not selected according to go_intent")
    if i_res2['freq'] != "2432":
       raise Exception("Group formed on a different frequency than BSS")
    hwsim_utils.test_connectivity(dev[0], hapd)
    dev[1].remove_group(r_res['ifname'])
    dev[0].wait_go_ending_session()
    dev[0].request("DISCONNECT")
    hapd.disable()
    dev[0].flush_scan_cache()
    dev[1].flush_scan_cache()

def test_autogo_with_bss_on_disallowed_chan(dev, apdev):
    """P2P channel selection: Autonomous GO with BSS on a disallowed channel"""

    with HWSimRadio(n_channels=2) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        wpas.request("SET p2p_no_group_iface 0")

        if wpas.get_mcc() < 2:
           raise Exception("New radio does not support MCC")

        try:
            hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": 'bss-2.4ghz',
                                                        "channel": '1' })
            wpas.request("P2P_SET disallow_freq 2412")
            wpas.connect("bss-2.4ghz", key_mgmt="NONE", scan_freq="2412")
            res = autogo(wpas)
            if res['freq'] == "2412":
               raise Exception("GO set on a disallowed channel")
            hwsim_utils.test_connectivity(wpas, hapd)
        finally:
            wpas.request("P2P_SET disallow_freq ")

def test_go_neg_with_bss_on_disallowed_chan(dev, apdev):
    """P2P channel selection: GO negotiation with station interface on a disallowed channel"""

    with HWSimRadio(n_channels=2) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        wpas.request("SET p2p_no_group_iface 0")

        if wpas.get_mcc() < 2:
           raise Exception("New radio does not support MCC")

        try:
            hapd = hostapd.add_ap(apdev[0]['ifname'],
                                  { "ssid": 'bss-2.4ghz', "channel": '1' })
            # make sure PBC overlap from old test cases is not maintained
            dev[1].flush_scan_cache()
            wpas.connect("bss-2.4ghz", key_mgmt="NONE", scan_freq="2412")
            wpas.request("P2P_SET disallow_freq 2412")

            #wpas as GO
            [i_res, r_res] = go_neg_pbc(i_dev=wpas, i_intent=10, r_dev=dev[1],
                                        r_intent=1)
            check_grpform_results(i_res, r_res)
            if i_res['role'] != "GO":
               raise Exception("GO not selected according to go_intent")
            if i_res['freq'] == "2412":
               raise Exception("Group formed on a disallowed channel")
            hwsim_utils.test_connectivity(wpas, hapd)
            wpas.remove_group(i_res['ifname'])
            dev[1].wait_go_ending_session()
            dev[1].flush_scan_cache()

            wpas.dump_monitor()
            dev[1].dump_monitor()

            #wpas as client
            [i_res2, r_res2] = go_neg_pbc(i_dev=wpas, i_intent=1, r_dev=dev[1],
                                          r_intent=10)
            check_grpform_results(i_res2, r_res2)
            if i_res2['role'] != "client":
               raise Exception("GO not selected according to go_intent")
            if i_res2['freq'] == "2412":
               raise Exception("Group formed on a disallowed channel")
            hwsim_utils.test_connectivity(wpas, hapd)
            dev[1].remove_group(r_res2['ifname'])
            wpas.wait_go_ending_session()
            ev = dev[1].wait_global_event(["P2P-GROUP-REMOVED"], timeout=5)
            if ev is None:
                raise Exception("Group removal not indicated")
            wpas.request("DISCONNECT")
            hapd.disable()
        finally:
            wpas.request("P2P_SET disallow_freq ")

def test_autogo_force_diff_channel(dev, apdev):
    """P2P autonomous GO and station interface operate on different channels"""
    with HWSimRadio(n_channels=2) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        if wpas.get_mcc() < 2:
           raise Exception("New radio does not support MCC")

        wpas.request("SET p2p_no_group_iface 0")

        hapd = hostapd.add_ap(apdev[0]['ifname'],
                              {"ssid" : 'ap-test', "channel" : '1'})
        wpas.connect("ap-test", key_mgmt = "NONE", scan_freq = "2412")
        channels = { 2 : 2417, 5 : 2432, 9 : 2452 }
        for key in channels:
            res_go = autogo(wpas, channels[key])
            hwsim_utils.test_connectivity(wpas, hapd)
            if int(res_go['freq']) == 2412:
                raise Exception("Group operation channel is: 2412 excepted: " + res_go['freq'])
            wpas.remove_group(res_go['ifname'])

def test_go_neg_forced_freq_diff_than_bss_freq(dev, apdev):
    """P2P channel selection: GO negotiation with forced freq different than station interface"""
    with HWSimRadio(n_channels=2) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        if wpas.get_mcc() < 2:
           raise Exception("New radio does not support MCC")

        # Clear possible PBC session overlap from previous test case
        dev[1].flush_scan_cache()

        wpas.request("SET p2p_no_group_iface 0")

        hapd = hostapd.add_ap(apdev[0]['ifname'],
                              { "country_code": 'US',
                                "ssid": 'bss-5ghz', "hw_mode": 'a',
                                "channel": '40' })
        wpas.connect("bss-5ghz", key_mgmt="NONE", scan_freq="5200")

        # GO and peer force the same freq, different than BSS freq,
        # wpas to become GO
        [i_res, r_res] = go_neg_pbc(i_dev=dev[1], i_intent=1, i_freq=5180,
                                    r_dev=wpas, r_intent=14, r_freq=5180)
        check_grpform_results(i_res, r_res)
        if i_res['freq'] != "5180":
           raise Exception("P2P group formed on unexpected frequency: " + i_res['freq'])
        if r_res['role'] != "GO":
           raise Exception("GO not selected according to go_intent")
        hwsim_utils.test_connectivity(wpas, hapd)
        wpas.remove_group(r_res['ifname'])
        dev[1].wait_go_ending_session()
        dev[1].flush_scan_cache()

        # GO and peer force the same freq, different than BSS freq, wpas to
        # become client
        [i_res2, r_res2] = go_neg_pbc(i_dev=dev[1], i_intent=14, i_freq=2422,
                                      r_dev=wpas, r_intent=1, r_freq=2422)
        check_grpform_results(i_res2, r_res2)
        if i_res2['freq'] != "2422":
           raise Exception("P2P group formed on unexpected frequency: " + i_res2['freq'])
        if r_res2['role'] != "client":
           raise Exception("GO not selected according to go_intent")
        hwsim_utils.test_connectivity(wpas, hapd)

        wpas.request("DISCONNECT")
        hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        wpas.flush_scan_cache()

def test_go_pref_chan_bss_on_diff_chan(dev, apdev):
    """P2P channel selection: Station on different channel than GO configured pref channel"""

    dev[0].request("SET p2p_no_group_iface 0")

    try:
        hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": 'bss-2.4ghz',
                                                    "channel": '1' })
        dev[0].request("SET p2p_pref_chan 81:2")
        dev[0].connect("bss-2.4ghz", key_mgmt="NONE", scan_freq="2412")
        res = autogo(dev[0])
        if res['freq'] != "2412":
           raise Exception("GO channel did not follow BSS")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].request("SET p2p_pref_chan ")

def test_go_pref_chan_bss_on_disallowed_chan(dev, apdev):
    """P2P channel selection: Station interface on different channel than GO configured pref channel, and station channel is disallowed"""
    with HWSimRadio(n_channels=2) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        if wpas.get_mcc() < 2:
           raise Exception("New radio does not support MCC")

        wpas.request("SET p2p_no_group_iface 0")

        try:
            hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": 'bss-2.4ghz',
                                                        "channel": '1' })
            wpas.request("P2P_SET disallow_freq 2412")
            wpas.request("SET p2p_pref_chan 81:2")
            wpas.connect("bss-2.4ghz", key_mgmt="NONE", scan_freq="2412")
            res2 = autogo(wpas)
            if res2['freq'] != "2417":
               raise Exception("GO channel did not follow pref_chan configuration")
            hwsim_utils.test_connectivity(wpas, hapd)
        finally:
            wpas.request("P2P_SET disallow_freq ")
            wpas.request("SET p2p_pref_chan ")

def test_no_go_freq(dev, apdev):
    """P2P channel selection: no GO freq"""
    try:
       dev[0].request("SET p2p_no_go_freq 2412")
       # dev[0] as client, channel 1 is ok
       [i_res, r_res] = go_neg_pbc(i_dev=dev[0], i_intent=1,
                                   r_dev=dev[1], r_intent=14, r_freq=2412)
       check_grpform_results(i_res, r_res)
       if i_res['freq'] != "2412":
          raise Exception("P2P group not formed on forced freq")

       dev[1].remove_group(r_res['ifname'])
       dev[0].wait_go_ending_session()
       dev[0].flush_scan_cache()

       fail = False
       # dev[0] as GO, channel 1 is not allowed
       try:
          dev[0].request("SET p2p_no_go_freq 2412")
          [i_res2, r_res2] = go_neg_pbc(i_dev=dev[0], i_intent=14,
                                        r_dev=dev[1], r_intent=1, r_freq=2412)
          check_grpform_results(i_res2, r_res2)
          fail = True
       except:
           pass
       if fail:
           raise Exception("GO set on a disallowed freq")
    finally:
       dev[0].request("SET p2p_no_go_freq ")

def test_go_neg_peers_force_diff_freq(dev, apdev):
    """P2P channel selection when peers for different frequency"""
    try:
       [i_res2, r_res2] = go_neg_pbc(i_dev=dev[0], i_intent=14, i_freq=5180,
                                     r_dev=dev[1], r_intent=0, r_freq=5200)
    except Exception, e:
        return
    raise Exception("Unexpected group formation success")

def test_autogo_random_channel(dev, apdev):
    """P2P channel selection: GO instantiated on random channel 1, 6, 11"""
    freqs = []
    go_freqs = ["2412", "2437", "2462"]
    for i in range(0, 20):
        result = autogo(dev[0])
        if result['freq'] not in go_freqs:
           raise Exception("Unexpected frequency selected: " + result['freq'])
        if result['freq'] not in freqs:
            freqs.append(result['freq'])
        if len(freqs) == 3:
            break
        dev[0].remove_group(result['ifname'])
    if i == 20:
       raise Exception("GO created 20 times and not all social channels were selected. freqs not selected: " + str(list(set(go_freqs) - set(freqs))))

def test_p2p_autogo_pref_chan_disallowed(dev, apdev):
    """P2P channel selection: GO preferred channels are disallowed"""
    try:
       dev[0].request("SET p2p_pref_chan 81:1,81:3,81:6,81:9,81:11")
       dev[0].request("P2P_SET disallow_freq 2412,2422,2437,2452,2462")
       for i in range(0, 5):
           res = autogo(dev[0])
           if res['freq'] in [ "2412", "2422", "2437", "2452", "2462" ]:
               raise Exception("GO channel is disallowed")
           dev[0].remove_group(res['ifname'])
    finally:
       dev[0].request("P2P_SET disallow_freq ")
       dev[0].request("SET p2p_pref_chan ")

def test_p2p_autogo_pref_chan_not_in_regulatory(dev, apdev):
    """P2P channel selection: GO preferred channel not allowed in the regulatory rules"""
    try:
        set_country("US", dev[0])
        dev[0].request("SET p2p_pref_chan 124:149")
        res = autogo(dev[0], persistent=True)
        if res['freq'] != "5745":
            raise Exception("Unexpected channel selected: " + res['freq'])
        dev[0].remove_group(res['ifname'])

        netw = dev[0].list_networks()
        if len(netw) != 1:
            raise Exception("Unexpected number of network blocks: " + str(netw))
        id = netw[0]['id']

        set_country("DE", dev[0])
        res = autogo(dev[0], persistent=id)
        if res['freq'] == "5745":
            raise Exception("Unexpected channel selected(2): " + res['freq'])
        dev[0].remove_group(res['ifname'])
    finally:
        dev[0].request("SET p2p_pref_chan ")
        set_country("00")

def run_autogo(dev, param):
    if "OK" not in dev.global_request("P2P_GROUP_ADD " + param):
        raise Exception("P2P_GROUP_ADD failed: " + param)
    ev = dev.wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("GO start up timed out")
    res = dev.group_form_result(ev)
    dev.remove_group()
    return res

def _test_autogo_ht_vht(dev):
    res = run_autogo(dev[0], "ht40")

    res = run_autogo(dev[0], "vht")

    res = run_autogo(dev[0], "freq=2")
    freq = int(res['freq'])
    if freq < 2412 or freq > 2462:
        raise Exception("Unexpected freq=2 channel: " + str(freq))

    res = run_autogo(dev[0], "freq=5")
    freq = int(res['freq'])
    if freq < 5000 or freq >= 6000:
        raise Exception("Unexpected freq=5 channel: " + str(freq))

    res = run_autogo(dev[0], "freq=5 ht40 vht")
    logger.info(str(res))
    freq = int(res['freq'])
    if freq < 5000 or freq >= 6000:
        raise Exception("Unexpected freq=5 ht40 vht channel: " + str(freq))

def test_autogo_ht_vht(dev):
    """P2P autonomous GO with HT/VHT parameters"""
    try:
        set_country("US", dev[0])
        _test_autogo_ht_vht(dev)
    finally:
        set_country("00")

def test_p2p_listen_chan_optimize(dev, apdev):
    """P2P listen channel optimization"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    addr5 = wpas.p2p_dev_addr()
    try:
        if "OK" not in wpas.request("SET p2p_optimize_listen_chan 1"):
            raise Exception("Failed to set p2p_optimize_listen_chan")
        wpas.p2p_listen()
        if not dev[0].discover_peer(addr5):
            raise Exception("Could not discover peer")
        peer = dev[0].get_peer(addr5)
        lfreq = peer['listen_freq']
        wpas.p2p_stop_find()
        dev[0].p2p_stop_find()

        channel = "1" if lfreq != '2412' else "6"
        freq = "2412" if lfreq != '2412' else "2437"
        params = { "ssid": "test-open", "channel": channel }
        hapd = hostapd.add_ap(apdev[0]['ifname'], params)

        id = wpas.connect("test-open", key_mgmt="NONE", scan_freq=freq)
        wpas.p2p_listen()

        if "OK" not in dev[0].request("P2P_FLUSH"):
            raise Exception("P2P_FLUSH failed")
        if not dev[0].discover_peer(addr5):
            raise Exception("Could not discover peer")
        peer = dev[0].get_peer(addr5)
        lfreq2 = peer['listen_freq']
        if lfreq == lfreq2:
            raise Exception("Listen channel did not change")
        if lfreq2 != freq:
            raise Exception("Listen channel not on AP's operating channel")
        wpas.p2p_stop_find()
        dev[0].p2p_stop_find()

        wpas.request("DISCONNECT")
        wpas.wait_disconnected()

        # for larger coverage, cover case of current channel matching
        wpas.select_network(id)
        wpas.wait_connected()
        wpas.request("DISCONNECT")
        wpas.wait_disconnected()

        lchannel = "1" if channel != "1" else "6"
        lfreq3 = "2412" if channel != "1" else "2437"
        if "OK" not in wpas.request("P2P_SET listen_channel " + lchannel):
            raise Exception("Failed to set listen channel")

        wpas.select_network(id)
        wpas.wait_connected()
        wpas.p2p_listen()

        if "OK" not in dev[0].request("P2P_FLUSH"):
            raise Exception("P2P_FLUSH failed")
        if not dev[0].discover_peer(addr5):
            raise Exception("Could not discover peer")
        peer = dev[0].get_peer(addr5)
        lfreq4 = peer['listen_freq']
        if lfreq4 != lfreq3:
            raise Exception("Unexpected Listen channel after configuration")
        wpas.p2p_stop_find()
        dev[0].p2p_stop_find()
    finally:
        wpas.request("SET p2p_optimize_listen_chan 0")

def test_p2p_channel_5ghz_only(dev):
    """P2P GO start with only 5 GHz band allowed"""
    try:
        set_country("US", dev[0])
        dev[0].request("P2P_SET disallow_freq 2400-2500")
        res = autogo(dev[0])
        freq = int(res['freq'])
        if freq < 5000:
            raise Exception("Unexpected channel %d MHz" % freq)
        dev[0].remove_group()
    finally:
        set_country("00")
        dev[0].request("P2P_SET disallow_freq ")
