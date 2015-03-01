# cfg80211 P2P Device
# Copyright (c) 2013-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time

from wpasupplicant import WpaSupplicant
from test_p2p_grpform import go_neg_pin_authorized
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group
from test_nfc_p2p import set_ip_addr_info, check_ip_addr, grpform_events
from hwsim import HWSimRadio
import hostapd
import hwsim_utils

def test_p2p_device_grpform(dev, apdev):
    """P2P group formation with driver using cfg80211 P2P Device"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=wpas, r_intent=0)
        check_grpform_results(i_res, r_res)
        remove_group(dev[0], wpas)

        res = wpas.global_request("IFNAME=p2p-dev-" + iface + " STATUS-DRIVER")
        lines = res.splitlines()
        found = False
        for l in lines:
            try:
                [name,value] = l.split('=', 1)
                if name == "wdev_id":
                    found = True
                    break
            except ValueError:
                pass
        if not found:
            raise Exception("wdev_id not found")

def test_p2p_device_grpform2(dev, apdev):
    """P2P group formation with driver using cfg80211 P2P Device (reverse)"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        [i_res, r_res] = go_neg_pin_authorized(i_dev=wpas, i_intent=15,
                                               r_dev=dev[0], r_intent=0)
        check_grpform_results(i_res, r_res)
        remove_group(wpas, dev[0])

def test_p2p_device_group_remove(dev, apdev):
    """P2P group removal via the P2P ctrl interface with driver using cfg80211 P2P Device"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=wpas, r_intent=0)
        check_grpform_results(i_res, r_res)
        # Issue the remove request on the interface which will be removed
        p2p_iface_wpas = WpaSupplicant(ifname=r_res['ifname'])
        res = p2p_iface_wpas.request("P2P_GROUP_REMOVE *")
        if "OK" not in res:
            raise Exception("Failed to remove P2P group")
        ev = wpas.wait_global_event(["P2P-GROUP-REMOVED"], timeout=10)
        if ev is None:
            raise Exception("Group removal event not received")
        if not wpas.global_ping():
            raise Exception("Could not ping global ctrl_iface after group removal")

def test_p2p_device_concurrent_scan(dev, apdev):
    """Concurrent P2P and station mode scans with driver using cfg80211 P2P Device"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        wpas.p2p_find()
        time.sleep(0.1)
        wpas.request("SCAN")
        ev = wpas.wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=15)
        if ev is None:
            raise Exception("Station mode scan did not start")

def test_p2p_device_nfc_invite(dev, apdev):
    """P2P NFC invitiation with driver using cfg80211 P2P Device"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        set_ip_addr_info(dev[0])
        logger.info("Start autonomous GO")
        dev[0].p2p_start_go()

        logger.info("Write NFC Tag on the P2P Client")
        res = wpas.global_request("P2P_LISTEN")
        if "FAIL" in res:
            raise Exception("Failed to start Listen mode")
        pw = wpas.global_request("WPS_NFC_TOKEN NDEF").rstrip()
        if "FAIL" in pw:
            raise Exception("Failed to generate password token")
        res = wpas.global_request("P2P_SET nfc_tag 1").rstrip()
        if "FAIL" in res:
            raise Exception("Failed to enable NFC Tag for P2P static handover")
        sel = wpas.global_request("NFC_GET_HANDOVER_SEL NDEF P2P-CR-TAG").rstrip()
        if "FAIL" in sel:
            raise Exception("Failed to generate NFC connection handover select")

        logger.info("Read NFC Tag on the GO to trigger invitation")
        res = dev[0].request("WPS_NFC_TAG_READ " + sel)
        if "FAIL" in res:
            raise Exception("Failed to provide NFC tag contents to wpa_supplicant")

        ev = wpas.wait_global_event(grpform_events, timeout=20)
        if ev is None:
            raise Exception("Joining the group timed out")
        res = wpas.group_form_result(ev)
        hwsim_utils.test_connectivity_p2p(dev[0], wpas)
        check_ip_addr(res)

def test_p2p_device_misuses(dev, apdev):
    """cfg80211 P2P Device misuses"""
    hapd = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "open" })
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        # Add a normal network profile to the P2P Device management only
        # interface to verify that it does not get used.
        id = int(wpas.global_request('IFNAME=p2p-dev-%s ADD_NETWORK' % iface).strip())
        wpas.global_request('IFNAME=p2p-dev-%s SET_NETWORK %d ssid "open"' % (iface, id))
        wpas.global_request('IFNAME=p2p-dev-%s SET_NETWORK %d key_mgmt NONE' % (iface, id))
        wpas.global_request('IFNAME=p2p-dev-%s ENABLE_NETWORK %d' % (iface, id))

        # Scan requests get ignored on p2p-dev
        wpas.global_request('IFNAME=p2p-dev-%s SCAN' % iface)

        dev[0].p2p_start_go(freq=2412)
        addr = dev[0].p2p_interface_addr()
        wpas.scan_for_bss(addr, freq=2412)
        wpas.connect("open", key_mgmt="NONE", scan_freq="2412")
        hwsim_utils.test_connectivity(wpas, hapd)

        pin = wpas.wps_read_pin()
        dev[0].p2p_go_authorize_client(pin)
        res = wpas.p2p_connect_group(dev[0].p2p_dev_addr(), pin, timeout=60,
                                     social=True, freq=2412)
        hwsim_utils.test_connectivity_p2p(dev[0], wpas)

        # Optimize scan-after-disconnect
        wpas.group_request("SET_NETWORK 0 scan_freq 2412")

        dev[0].request("DISASSOCIATE " + wpas.p2p_interface_addr())
        ev = wpas.wait_group_event(["CTRL-EVENT-DISCONNECT"])
        if ev is None:
            raise Exception("Did not see disconnect event on P2P group interface")
        dev[0].remove_group()

        ev = wpas.wait_group_event(["CTRL-EVENT-SCAN-STARTED"], timeout=5)
        if ev is None:
            raise Exception("Scan not started")
        ev = wpas.wait_group_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=15)
        if ev is None:
            raise Exception("Scan not completed")
        time.sleep(1)
        hwsim_utils.test_connectivity(wpas, hapd)

        ev = hapd.wait_event([ "AP-STA-DISCONNECTED" ], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected disconnection event received from hostapd")
        ev = wpas.wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected disconnection event received from wpa_supplicant")

        wpas.request("DISCONNECT")
        wpas.wait_disconnected()

def test_p2p_device_incorrect_command_interface(dev, apdev):
    """cfg80211 P2P Device and P2P_* command on incorrect interface"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        dev[0].p2p_listen()
        wpas.request('P2P_FIND type=social')
        ev = wpas.wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
        if ev is None:
            raise Exception("Peer not found")
        ev = wpas.wait_event(["P2P-DEVICE-FOUND"], timeout=0.1)
        if ev is not None:
            raise Exception("Unexpected P2P-DEVICE-FOUND event on station interface")

        pin = wpas.wps_read_pin()
        dev[0].p2p_go_neg_auth(wpas.p2p_dev_addr(), pin, "enter", go_intent=14,
                               freq=2412)
        wpas.request('P2P_STOP_FIND')
        if "OK" not in wpas.request('P2P_CONNECT ' + dev[0].p2p_dev_addr() + ' ' + pin + ' display go_intent=1'):
            raise Exception("P2P_CONNECT failed")

        ev = wpas.wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
        if ev is None:
            raise Exception("Group formation timed out")
        wpas.group_form_result(ev)

        ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
        if ev is None:
            raise Exception("Group formation timed out(2)")
        dev[0].group_form_result(ev)

        dev[0].remove_group()
        wpas.wait_go_ending_session()

def test_p2p_device_incorrect_command_interface2(dev, apdev):
    """cfg80211 P2P Device and P2P_GROUP_ADD command on incorrect interface"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        print wpas.request('P2P_GROUP_ADD')
        ev = wpas.wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
        if ev is None:
            raise Exception("Group formation timed out")
        res = wpas.group_form_result(ev)
        logger.info("Group results: " + str(res))
        wpas.remove_group()
        if not res['ifname'].startswith('p2p-' + iface + '-'):
            raise Exception("Unexpected group ifname: " + res['ifname'])
