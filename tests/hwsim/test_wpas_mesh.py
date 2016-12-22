# wpa_supplicant mesh mode tests
# Copyright (c) 2014, cozybit Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import struct
import subprocess
import time

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from utils import HwsimSkip, alloc_fail, fail_test, wait_fail_trigger
from tshark import run_tshark
from test_ap_ht import set_world_reg

def check_mesh_support(dev, secure=False):
    if "MESH" not in dev.get_capability("modes"):
        raise HwsimSkip("Driver does not support mesh")
    if secure and "SAE" not in dev.get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")

def check_mesh_scan(dev, params, other_started=False, beacon_int=0):
    if not other_started:
        dev.dump_monitor()
    id = dev.request("SCAN " + params)
    if "FAIL" in id:
        raise Exception("Failed to start scan")
    id = int(id)

    if other_started:
        ev = dev.wait_event(["CTRL-EVENT-SCAN-STARTED"])
        if ev is None:
            raise Exception("Other scan did not start")
        if "id=" + str(id) in ev:
            raise Exception("Own scan id unexpectedly included in start event")

        ev = dev.wait_event(["CTRL-EVENT-SCAN-RESULTS"])
        if ev is None:
            raise Exception("Other scan did not complete")
        if "id=" + str(id) in ev:
            raise Exception(
                "Own scan id unexpectedly included in completed event")

    ev = dev.wait_event(["CTRL-EVENT-SCAN-STARTED"])
    if ev is None:
        raise Exception("Scan did not start")
    if "id=" + str(id) not in ev:
        raise Exception("Scan id not included in start event")

    ev = dev.wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Scan did not complete")
    if "id=" + str(id) not in ev:
        raise Exception("Scan id not included in completed event")

    res = dev.request("SCAN_RESULTS")

    if res.find("[MESH]") < 0:
        raise Exception("Scan did not contain a MESH network")

    bssid = res.splitlines()[1].split(' ')[0]
    bss = dev.get_bss(bssid)
    if bss is None:
        raise Exception("Could not get BSS entry for mesh")
    if 'mesh_capability' not in bss:
        raise Exception("mesh_capability missing from BSS entry")
    if beacon_int:
        if 'beacon_int' not in bss:
            raise Exception("beacon_int missing from BSS entry")
        if str(beacon_int) != bss['beacon_int']:
            raise Exception("Unexpected beacon_int in BSS entry: " + bss['beacon_int'])
    if '[MESH]' not in bss['flags']:
        raise Exception("BSS output did not include MESH flag")

def check_mesh_group_added(dev):
    ev = dev.wait_event(["MESH-GROUP-STARTED"])
    if ev is None:
        raise Exception("Test exception: Couldn't join mesh")


def check_mesh_group_removed(dev):
    ev = dev.wait_event(["MESH-GROUP-REMOVED"])
    if ev is None:
        raise Exception("Test exception: Couldn't leave mesh")


def check_mesh_peer_connected(dev, timeout=10):
    ev = dev.wait_event(["MESH-PEER-CONNECTED"], timeout=timeout)
    if ev is None:
        raise Exception("Test exception: Remote peer did not connect.")


def check_mesh_peer_disconnected(dev):
    ev = dev.wait_event(["MESH-PEER-DISCONNECTED"])
    if ev is None:
        raise Exception("Test exception: Peer disconnect event not detected.")


def test_wpas_add_set_remove_support(dev):
    """wpa_supplicant MESH add/set/remove network support"""
    check_mesh_support(dev[0])
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].remove_network(id)

def add_open_mesh_network(dev, freq="2412", start=True, beacon_int=0,
                          basic_rates=None, chwidth=0):
    id = dev.add_network()
    dev.set_network(id, "mode", "5")
    dev.set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev.set_network(id, "key_mgmt", "NONE")
    if freq:
        dev.set_network(id, "frequency", freq)
    if chwidth > 0:
        dev.set_network(id, "max_oper_chwidth", str(chwidth))
    if beacon_int:
        dev.set_network(id, "beacon_int", str(beacon_int))
    if basic_rates:
        dev.set_network(id, "mesh_basic_rates", basic_rates)
    if start:
        dev.mesh_group_add(id)
    return id

def test_wpas_mesh_group_added(dev):
    """wpa_supplicant MESH group add"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])

    # Check for MESH-GROUP-STARTED event
    check_mesh_group_added(dev[0])


def test_wpas_mesh_group_remove(dev):
    """wpa_supplicant MESH group remove"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    # Check for MESH-GROUP-STARTED event
    check_mesh_group_added(dev[0])
    dev[0].mesh_group_remove()
    # Check for MESH-GROUP-REMOVED event
    check_mesh_group_removed(dev[0])
    dev[0].mesh_group_remove()

def test_wpas_mesh_peer_connected(dev):
    """wpa_supplicant MESH peer connected"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0], beacon_int=160)
    add_open_mesh_network(dev[1], beacon_int=160)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])


def test_wpas_mesh_peer_disconnected(dev):
    """wpa_supplicant MESH peer disconnected"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    add_open_mesh_network(dev[1])

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Remove group on dev 1
    dev[1].mesh_group_remove()
    # Device 0 should get a disconnection event
    check_mesh_peer_disconnected(dev[0])


def test_wpas_mesh_mode_scan(dev):
    """wpa_supplicant MESH scan support"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    add_open_mesh_network(dev[1], beacon_int=175)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for Mesh scan
    check_mesh_scan(dev[0], "use_id=1 freq=2412", beacon_int=175)

def test_wpas_mesh_open(dev, apdev):
    """wpa_supplicant open MESH network connectivity"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0], freq="2462", basic_rates="60 120 240")
    add_open_mesh_network(dev[1], freq="2462", basic_rates="60 120 240")

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

    state = dev[0].get_status_field("wpa_state")
    if state != "COMPLETED":
        raise Exception("Unexpected wpa_state on dev0: " + state)
    state = dev[1].get_status_field("wpa_state")
    if state != "COMPLETED":
        raise Exception("Unexpected wpa_state on dev1: " + state)

    mode = dev[0].get_status_field("mode")
    if mode != "mesh":
        raise Exception("Unexpected mode: " + mode)

def test_wpas_mesh_open_no_auto(dev, apdev):
    """wpa_supplicant open MESH network connectivity"""
    check_mesh_support(dev[0])
    id = add_open_mesh_network(dev[0], start=False)
    dev[0].set_network(id, "dot11MeshMaxRetries", "16")
    dev[0].set_network(id, "dot11MeshRetryTimeout", "255")
    dev[0].mesh_group_add(id)

    id = add_open_mesh_network(dev[1], start=False)
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0], timeout=30)
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

def test_mesh_open_no_auto2(dev, apdev):
    """Open mesh network connectivity, no_auto on both peers"""
    check_mesh_support(dev[0])
    id = add_open_mesh_network(dev[0], start=False)
    dev[0].set_network(id, "no_auto_peer", "1")
    dev[0].mesh_group_add(id)

    id = add_open_mesh_network(dev[1], start=False)
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message")
    addr1 = dev[1].own_addr()
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed")
    if "FAIL" not in dev[0].request("MESH_PEER_ADD ff:ff:ff:ff:ff:ff"):
        raise Exception("MESH_PEER_ADD with unknown STA succeeded")
    check_mesh_peer_connected(dev[0], timeout=30)
    check_mesh_peer_connected(dev[1])
    if "FAIL" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD succeeded for connected STA")
    hwsim_utils.test_connectivity(dev[0], dev[1])

def add_mesh_secure_net(dev, psk=True, pmf=False, pairwise=None, group=None):
    id = dev.add_network()
    dev.set_network(id, "mode", "5")
    dev.set_network_quoted(id, "ssid", "wpas-mesh-sec")
    dev.set_network(id, "key_mgmt", "SAE")
    dev.set_network(id, "frequency", "2412")
    if psk:
        dev.set_network_quoted(id, "psk", "thisismypassphrase!")
    if pmf:
        dev.set_network(id, "ieee80211w", "2")
    if pairwise:
        dev.set_network(id, "pairwise", pairwise)
    if group:
        dev.set_network(id, "group", group)
    return id

def test_wpas_mesh_secure(dev, apdev):
    """wpa_supplicant secure MESH network connectivity"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

    state = dev[0].get_status_field("wpa_state")
    if state != "COMPLETED":
        raise Exception("Unexpected wpa_state on dev0: " + state)
    state = dev[1].get_status_field("wpa_state")
    if state != "COMPLETED":
        raise Exception("Unexpected wpa_state on dev1: " + state)

def test_mesh_secure_pmf(dev, apdev):
    """Secure mesh network connectivity with PMF enabled"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0], pmf=True)
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1], pmf=True)
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

def run_mesh_secure(dev, cipher):
    if cipher not in dev[0].get_capability("pairwise"):
        raise HwsimSkip("Cipher %s not supported" % cipher)
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0], pairwise=cipher, group=cipher)
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1], pairwise=cipher, group=cipher)
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

def test_mesh_secure_ccmp(dev, apdev):
    """Secure mesh with CCMP"""
    run_mesh_secure(dev, "CCMP")

def test_mesh_secure_gcmp(dev, apdev):
    """Secure mesh with GCMP"""
    run_mesh_secure(dev, "GCMP")

def test_mesh_secure_gcmp_256(dev, apdev):
    """Secure mesh with GCMP-256"""
    run_mesh_secure(dev, "GCMP-256")

def test_mesh_secure_ccmp_256(dev, apdev):
    """Secure mesh with CCMP-256"""
    run_mesh_secure(dev, "CCMP-256")

def test_mesh_secure_invalid_pairwise_cipher(dev, apdev):
    """Secure mesh and invalid group cipher"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0], pairwise="TKIP", group="CCMP")
    if dev[0].mesh_group_add(id) != None:
        raise Exception("Unexpected group add success")
    ev = dev[0].wait_event(["mesh: Invalid pairwise cipher"], timeout=1)
    if ev is None:
        raise Exception("Invalid pairwise cipher not reported")

def test_mesh_secure_invalid_group_cipher(dev, apdev):
    """Secure mesh and invalid group cipher"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0], pairwise="CCMP", group="TKIP")
    if dev[0].mesh_group_add(id) != None:
        raise Exception("Unexpected group add success")
    ev = dev[0].wait_event(["mesh: Invalid group cipher"], timeout=1)
    if ev is None:
        raise Exception("Invalid group cipher not reported")

def test_wpas_mesh_secure_sae_group_mismatch(dev, apdev):
    """wpa_supplicant secure MESH and SAE group mismatch"""
    check_mesh_support(dev[0], secure=True)
    addr0 = dev[0].p2p_interface_addr()
    addr1 = dev[1].p2p_interface_addr()
    addr2 = dev[2].p2p_interface_addr()

    dev[0].request("SET sae_groups 19 25")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups 19")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    dev[2].request("SET sae_groups 26")
    id = add_mesh_secure_net(dev[2])
    dev[2].mesh_group_add(id)

    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])
    check_mesh_group_added(dev[2])

    ev = dev[0].wait_event(["MESH-PEER-CONNECTED"])
    if ev is None:
        raise Exception("Remote peer did not connect")
    if addr1 not in ev:
        raise Exception("Unexpected peer connected: " + ev)

    ev = dev[1].wait_event(["MESH-PEER-CONNECTED"])
    if ev is None:
        raise Exception("Remote peer did not connect")
    if addr0 not in ev:
        raise Exception("Unexpected peer connected: " + ev)

    ev = dev[2].wait_event(["MESH-PEER-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected peer connection at dev[2]: " + ev)

    ev = dev[0].wait_event(["MESH-PEER-CONNECTED"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected peer connection: " + ev)

    ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected peer connection: " + ev)

    dev[0].request("SET sae_groups ")
    dev[1].request("SET sae_groups ")
    dev[2].request("SET sae_groups ")

def test_wpas_mesh_secure_sae_group_negotiation(dev, apdev):
    """wpa_supplicant secure MESH and SAE group negotiation"""
    check_mesh_support(dev[0], secure=True)
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()

    #dev[0].request("SET sae_groups 21 20 25 26")
    dev[0].request("SET sae_groups 25")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups 19 25")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    dev[0].request("SET sae_groups ")
    dev[1].request("SET sae_groups ")

def test_wpas_mesh_secure_sae_missing_password(dev, apdev):
    """wpa_supplicant secure MESH and missing SAE password"""
    check_mesh_support(dev[0], secure=True)
    id = add_mesh_secure_net(dev[0], psk=False)
    dev[0].set_network(id, "psk", "8f20b381f9b84371d61b5080ad85cac3c61ab3ca9525be5b2d0f4da3d979187a")
    dev[0].mesh_group_add(id)
    ev = dev[0].wait_event(["MESH-GROUP-STARTED", "Could not join mesh"],
                           timeout=5)
    if ev is None:
        raise Exception("Timeout on mesh start event")
    if "MESH-GROUP-STARTED" in ev:
        raise Exception("Unexpected mesh group start")
    ev = dev[0].wait_event(["MESH-GROUP-STARTED"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected mesh group start")

def test_wpas_mesh_secure_no_auto(dev, apdev):
    """wpa_supplicant secure MESH network connectivity"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups 19")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups 19")
    id = add_mesh_secure_net(dev[1])
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0], timeout=30)
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

    dev[0].request("SET sae_groups ")
    dev[1].request("SET sae_groups ")

def test_wpas_mesh_secure_dropped_frame(dev, apdev):
    """Secure mesh network connectivity when the first plink Open is dropped"""
    check_mesh_support(dev[0], secure=True)

    dev[0].request("SET ext_mgmt_frame_handling 1")
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Drop the first Action frame (plink Open) to test unexpected order of
    # Confirm/Open messages.
    count = 0
    while True:
        count += 1
        if count > 10:
            raise Exception("Did not see Action frames")
        rx_msg = dev[0].mgmt_rx()
        if rx_msg is None:
            raise Exception("MGMT-RX timeout")
        if rx_msg['subtype'] == 13:
            logger.info("Drop the first Action frame")
            break
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(rx_msg['freq'], rx_msg['datarate'], rx_msg['ssi_signal'], rx_msg['frame'].encode('hex'))):
            raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("SET ext_mgmt_frame_handling 0")

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

def test_mesh_secure_fail(dev, apdev):
    """Secure mesh network connectivity failure"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0], pmf=True)
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1], pmf=True)

    with fail_test(dev[0], 1, "wpa_driver_nl80211_sta_add;mesh_mpm_auth_peer"):
        dev[1].mesh_group_add(id)

        check_mesh_group_added(dev[0])
        check_mesh_group_added(dev[1])

        check_mesh_peer_connected(dev[0])
        check_mesh_peer_connected(dev[1])

def test_wpas_mesh_ctrl(dev):
    """wpa_supplicant ctrl_iface mesh command error cases"""
    check_mesh_support(dev[0])
    if "FAIL" not in dev[0].request("MESH_GROUP_ADD 123"):
        raise Exception("Unexpected MESH_GROUP_ADD success")
    id = dev[0].add_network()
    if "FAIL" not in dev[0].request("MESH_GROUP_ADD %d" % id):
        raise Exception("Unexpected MESH_GROUP_ADD success")
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network(id, "key_mgmt", "WPA-PSK")
    if "FAIL" not in dev[0].request("MESH_GROUP_ADD %d" % id):
        raise Exception("Unexpected MESH_GROUP_ADD success")

    if "FAIL" not in dev[0].request("MESH_GROUP_REMOVE foo"):
        raise Exception("Unexpected MESH_GROUP_REMOVE success")

def test_wpas_mesh_dynamic_interface(dev):
    """wpa_supplicant mesh with dynamic interface"""
    check_mesh_support(dev[0])
    mesh0 = None
    mesh1 = None
    try:
        mesh0 = dev[0].request("MESH_INTERFACE_ADD ifname=mesh0")
        if "FAIL" in mesh0:
            raise Exception("MESH_INTERFACE_ADD failed")
        mesh1 = dev[1].request("MESH_INTERFACE_ADD")
        if "FAIL" in mesh1:
            raise Exception("MESH_INTERFACE_ADD failed")

        wpas0 = WpaSupplicant(ifname=mesh0)
        wpas1 = WpaSupplicant(ifname=mesh1)
        logger.info(mesh0 + " address " + wpas0.get_status_field("address"))
        logger.info(mesh1 + " address " + wpas1.get_status_field("address"))

        add_open_mesh_network(wpas0)
        add_open_mesh_network(wpas1)
        check_mesh_group_added(wpas0)
        check_mesh_group_added(wpas1)
        check_mesh_peer_connected(wpas0)
        check_mesh_peer_connected(wpas1)
        hwsim_utils.test_connectivity(wpas0, wpas1)

        # Must not allow MESH_GROUP_REMOVE on dynamic interface
        if "FAIL" not in wpas0.request("MESH_GROUP_REMOVE " + mesh0):
            raise Exception("Invalid MESH_GROUP_REMOVE accepted")
        if "FAIL" not in wpas1.request("MESH_GROUP_REMOVE " + mesh1):
            raise Exception("Invalid MESH_GROUP_REMOVE accepted")

        # Must not allow MESH_GROUP_REMOVE on another radio interface
        if "FAIL" not in wpas0.request("MESH_GROUP_REMOVE " + mesh1):
            raise Exception("Invalid MESH_GROUP_REMOVE accepted")
        if "FAIL" not in wpas1.request("MESH_GROUP_REMOVE " + mesh0):
            raise Exception("Invalid MESH_GROUP_REMOVE accepted")

        wpas0.remove_ifname()
        wpas1.remove_ifname()

        if "OK" not in dev[0].request("MESH_GROUP_REMOVE " + mesh0):
            raise Exception("MESH_GROUP_REMOVE failed")
        if "OK" not in dev[1].request("MESH_GROUP_REMOVE " + mesh1):
            raise Exception("MESH_GROUP_REMOVE failed")

        if "FAIL" not in dev[0].request("MESH_GROUP_REMOVE " + mesh0):
            raise Exception("Invalid MESH_GROUP_REMOVE accepted")
        if "FAIL" not in dev[1].request("MESH_GROUP_REMOVE " + mesh1):
            raise Exception("Invalid MESH_GROUP_REMOVE accepted")

        logger.info("Make sure another dynamic group can be added")
        mesh0 = dev[0].request("MESH_INTERFACE_ADD ifname=mesh0")
        if "FAIL" in mesh0:
            raise Exception("MESH_INTERFACE_ADD failed")
        mesh1 = dev[1].request("MESH_INTERFACE_ADD")
        if "FAIL" in mesh1:
            raise Exception("MESH_INTERFACE_ADD failed")

        wpas0 = WpaSupplicant(ifname=mesh0)
        wpas1 = WpaSupplicant(ifname=mesh1)
        logger.info(mesh0 + " address " + wpas0.get_status_field("address"))
        logger.info(mesh1 + " address " + wpas1.get_status_field("address"))

        add_open_mesh_network(wpas0)
        add_open_mesh_network(wpas1)
        check_mesh_group_added(wpas0)
        check_mesh_group_added(wpas1)
        check_mesh_peer_connected(wpas0)
        check_mesh_peer_connected(wpas1)
        hwsim_utils.test_connectivity(wpas0, wpas1)
    finally:
        if mesh0:
            dev[0].request("MESH_GROUP_REMOVE " + mesh0)
        if mesh1:
            dev[1].request("MESH_GROUP_REMOVE " + mesh1)

def test_wpas_mesh_max_peering(dev, apdev, params):
    """Mesh max peering limit"""
    check_mesh_support(dev[0])
    try:
        dev[0].request("SET max_peer_links 1")

        # first, connect dev[0] and dev[1]
        add_open_mesh_network(dev[0])
        add_open_mesh_network(dev[1])
        for i in range(2):
            ev = dev[i].wait_event(["MESH-PEER-CONNECTED"])
            if ev is None:
                raise Exception("dev%d did not connect with any peer" % i)

        # add dev[2] which will try to connect with both dev[0] and dev[1],
        # but can complete connection only with dev[1]
        add_open_mesh_network(dev[2])
        for i in range(1, 3):
            ev = dev[i].wait_event(["MESH-PEER-CONNECTED"])
            if ev is None:
                raise Exception("dev%d did not connect the second peer" % i)

        ev = dev[0].wait_event(["MESH-PEER-CONNECTED"], timeout=1)
        if ev is not None:
            raise Exception("dev0 connection beyond max peering limit")

        ev = dev[2].wait_event(["MESH-PEER-CONNECTED"], timeout=0.1)
        if ev is not None:
            raise Exception("dev2 reported unexpected peering: " + ev)

        for i in range(3):
            dev[i].mesh_group_remove()
            check_mesh_group_removed(dev[i])
    finally:
        dev[0].request("SET max_peer_links 99")

    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    addr2 = dev[2].own_addr()

    capfile = os.path.join(params['logdir'], "hwsim0.pcapng")
    filt = "wlan.fc.type_subtype == 8"
    out = run_tshark(capfile, filt, [ "wlan.sa", "wlan.mesh.config.cap" ])
    pkts = out.splitlines()
    one = [ 0, 0, 0 ]
    zero = [ 0, 0, 0 ]
    for pkt in pkts:
        addr, cap = pkt.split('\t')
        cap = int(cap, 16)
        if addr == addr0:
            idx = 0
        elif addr == addr1:
            idx = 1
        elif addr == addr2:
            idx = 2
        else:
            continue
        if cap & 0x01:
            one[idx] += 1
        else:
            zero[idx] += 1
    logger.info("one: " + str(one))
    logger.info("zero: " + str(zero))
    if zero[0] == 0:
        raise Exception("Accepting Additional Mesh Peerings not cleared")
    if one[0] == 0:
        raise Exception("Accepting Additional Mesh Peerings was not set in the first Beacon frame")
    if zero[1] > 0 or zero[2] > 0 or one[1] == 0 or one[2] == 0:
        raise Exception("Unexpected value in Accepting Additional Mesh Peerings from other STAs")

def test_wpas_mesh_open_5ghz(dev, apdev):
    """wpa_supplicant open MESH network on 5 GHz band"""
    try:
        _test_wpas_mesh_open_5ghz(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def _test_wpas_mesh_open_5ghz(dev, apdev):
    check_mesh_support(dev[0])
    subprocess.call(['iw', 'reg', 'set', 'US'])
    for i in range(2):
        for j in range(5):
            ev = dev[i].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=5)
            if ev is None:
                raise Exception("No regdom change event")
            if "alpha2=US" in ev:
                break
        add_open_mesh_network(dev[i], freq="5180")

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

def test_wpas_mesh_open_5ghz_coex(dev, apdev):
    """Mesh network on 5 GHz band and 20/40 coex change"""
    try:
        _test_wpas_mesh_open_5ghz_coex(dev, apdev)
    finally:
        set_world_reg(apdev0=apdev[0], dev0=dev[0])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def _test_wpas_mesh_open_5ghz_coex(dev, apdev):
    check_mesh_support(dev[0])
    subprocess.call(['iw', 'reg', 'set', 'US'])

    # Start a 20 MHz BSS on channel 40 that would be the secondary channel of
    # HT40+ mesh on channel 36.
    params = { "ssid": "test-ht40",
               "hw_mode": "a",
               "channel": "40",
               "country_code": "US" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = hapd.own_addr()

    for i in range(2):
        for j in range(5):
            ev = dev[i].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=5)
            if ev is None:
                raise Exception("No regdom change event")
            if "alpha2=US" in ev:
                break
        dev[i].scan_for_bss(bssid, freq=5200)
        add_open_mesh_network(dev[i], freq="5180")

    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    freq = dev[0].get_status_field("freq")
    if freq != "5200":
        raise Exception("Unexpected STATUS freq=" + freq)
    sig = dev[0].request("SIGNAL_POLL").splitlines()
    if "FREQUENCY=5200" not in sig:
        raise Exception("Unexpected SIGNAL_POLL output: " + str(sig))

    hapd.disable()

def test_wpas_mesh_open_vht_80p80(dev, apdev):
    """wpa_supplicant open MESH network on VHT 80+80 MHz channel"""
    try:
        _test_wpas_mesh_open_vht_80p80(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def _test_wpas_mesh_open_vht_80p80(dev, apdev):
    check_mesh_support(dev[0])
    subprocess.call(['iw', 'reg', 'set', 'US'])
    for i in range(2):
        for j in range(5):
            ev = dev[i].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=5)
            if ev is None:
                raise Exception("No regdom change event")
            if "alpha2=US" in ev:
                break
        add_open_mesh_network(dev[i], freq="5180", chwidth=3)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

    sig = dev[0].request("SIGNAL_POLL").splitlines()
    if "WIDTH=80+80 MHz" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
    if "CENTER_FRQ1=5210" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(3): " + str(sig))
    if "CENTER_FRQ2=5775" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(4): " + str(sig))

    sig = dev[1].request("SIGNAL_POLL").splitlines()
    if "WIDTH=80+80 MHz" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(2b): " + str(sig))
    if "CENTER_FRQ1=5210" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(3b): " + str(sig))
    if "CENTER_FRQ2=5775" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(4b): " + str(sig))

def test_mesh_open_vht_160(dev, apdev):
    """Open mesh network on VHT 160 MHz channel"""
    try:
        _test_mesh_open_vht_160(dev, apdev)
    finally:
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def _test_mesh_open_vht_160(dev, apdev):
    check_mesh_support(dev[0])
    subprocess.call(['iw', 'reg', 'set', 'ZA'])
    for i in range(2):
        for j in range(5):
            ev = dev[i].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=5)
            if ev is None:
                raise Exception("No regdom change event")
            if "alpha2=ZA" in ev:
                break

        cmd = subprocess.Popen(["iw", "reg", "get"], stdout=subprocess.PIPE)
        reg = cmd.stdout.read()
        if "@ 160)" not in reg:
            raise HwsimSkip("160 MHz channel not supported in regulatory information")

        add_open_mesh_network(dev[i], freq="5520", chwidth=2)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

    sig = dev[0].request("SIGNAL_POLL").splitlines()
    if "WIDTH=160 MHz" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
    if "FREQUENCY=5520" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(3): " + str(sig))

    sig = dev[1].request("SIGNAL_POLL").splitlines()
    if "WIDTH=160 MHz" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(2b): " + str(sig))
    if "FREQUENCY=5520" not in sig:
        raise Exception("Unexpected SIGNAL_POLL value(3b): " + str(sig))

def test_wpas_mesh_password_mismatch(dev, apdev):
    """Mesh network and one device with mismatching password"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    dev[2].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[2])
    dev[2].set_network_quoted(id, "psk", "wrong password")
    dev[2].mesh_group_add(id)

    # The two peers with matching password need to be able to connect
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    ev = dev[2].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=20)
    if ev is None:
        raise Exception("dev2 did not report auth failure (1)")
    ev = dev[2].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=20)
    if ev is None:
        raise Exception("dev2 did not report auth failure (2)")
    dev[2].dump_monitor()

    count = 0
    ev = dev[0].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=5)
    if ev is None:
        logger.info("dev0 did not report auth failure")
    else:
        if "addr=" + dev[2].own_addr() not in ev:
            raise Exception("Unexpected peer address in dev0 event: " + ev)
        count += 1
    dev[0].dump_monitor()

    ev = dev[1].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=5)
    if ev is None:
        logger.info("dev1 did not report auth failure")
    else:
        if "addr=" + dev[2].own_addr() not in ev:
            raise Exception("Unexpected peer address in dev1 event: " + ev)
        count += 1
    dev[1].dump_monitor()

    hwsim_utils.test_connectivity(dev[0], dev[1])

    for i in range(2):
        try:
            hwsim_utils.test_connectivity(dev[i], dev[2], timeout=1)
            raise Exception("Data connectivity test passed unexpectedly")
        except Exception, e:
            if "data delivery failed" not in str(e):
                raise

    if count == 0:
        raise Exception("Neither dev0 nor dev1 reported auth failure")

def test_wpas_mesh_password_mismatch_retry(dev, apdev, params):
    """Mesh password mismatch and retry [long]"""
    if not params['long']:
        raise HwsimSkip("Skip test case with long duration due to --long not specified")
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].set_network_quoted(id, "psk", "wrong password")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    for i in range(4):
        ev = dev[0].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=20)
        if ev is None:
            raise Exception("dev0 did not report auth failure (%d)" % i)
        ev = dev[1].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=20)
        if ev is None:
            raise Exception("dev1 did not report auth failure (%d)" % i)

    ev = dev[0].wait_event(["MESH-SAE-AUTH-BLOCKED"], timeout=10)
    if ev is None:
        raise Exception("dev0 did not report auth blocked")
    ev = dev[1].wait_event(["MESH-SAE-AUTH-BLOCKED"], timeout=10)
    if ev is None:
        raise Exception("dev1 did not report auth blocked")

def test_mesh_wpa_auth_init_oom(dev, apdev):
    """Secure mesh network setup failing due to wpa_init() OOM"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    with alloc_fail(dev[0], 1, "wpa_init"):
        id = add_mesh_secure_net(dev[0])
        dev[0].mesh_group_add(id)
        ev = dev[0].wait_event(["MESH-GROUP-STARTED"], timeout=0.2)
        if ev is not None:
            raise Exception("Unexpected mesh group start during OOM")

def test_mesh_wpa_init_fail(dev, apdev):
    """Secure mesh network setup local failure"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")

    with fail_test(dev[0], 1, "os_get_random;=__mesh_rsn_auth_init"):
        id = add_mesh_secure_net(dev[0])
        dev[0].mesh_group_add(id)
        wait_fail_trigger(dev[0], "GET_FAIL")

    dev[0].dump_monitor()
    with alloc_fail(dev[0], 1, "mesh_rsn_auth_init"):
        id = add_mesh_secure_net(dev[0])
        dev[0].mesh_group_add(id)
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")

    dev[0].dump_monitor()
    with fail_test(dev[0], 1, "os_get_random;mesh_rsn_init_ampe_sta"):
        id = add_mesh_secure_net(dev[0])
        dev[0].mesh_group_add(id)
        dev[1].request("SET sae_groups ")
        id = add_mesh_secure_net(dev[1])
        dev[1].mesh_group_add(id)
        wait_fail_trigger(dev[0], "GET_FAIL")

def test_wpas_mesh_reconnect(dev, apdev):
    """Secure mesh network plink counting during reconnection"""
    check_mesh_support(dev[0])
    try:
        _test_wpas_mesh_reconnect(dev)
    finally:
        dev[0].request("SET max_peer_links 99")

def _test_wpas_mesh_reconnect(dev):
    dev[0].request("SET max_peer_links 2")
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].set_network(id, "beacon_int", "100")
    dev[0].mesh_group_add(id)
    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    for i in range(3):
        # Drop incoming management frames to avoid handling link close
        dev[0].request("SET ext_mgmt_frame_handling 1")
        dev[1].mesh_group_remove()
        check_mesh_group_removed(dev[1])
        dev[1].request("FLUSH")
        dev[0].request("SET ext_mgmt_frame_handling 0")
        id = add_mesh_secure_net(dev[1])
        dev[1].mesh_group_add(id)
        check_mesh_group_added(dev[1])
        check_mesh_peer_connected(dev[1])
        dev[0].dump_monitor()
        dev[1].dump_monitor()

def test_wpas_mesh_gate_forwarding(dev, apdev, p):
    """Mesh forwards traffic to unknown sta to mesh gates"""
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    addr2 = dev[2].own_addr()
    external_sta = '02:11:22:33:44:55'

    # start 3 node connected mesh
    check_mesh_support(dev[0])
    for i in range(3):
        add_open_mesh_network(dev[i])
        check_mesh_group_added(dev[i])
    for i in range(3):
        check_mesh_peer_connected(dev[i])

    hwsim_utils.test_connectivity(dev[0], dev[1])
    hwsim_utils.test_connectivity(dev[1], dev[2])
    hwsim_utils.test_connectivity(dev[0], dev[2])

    # dev0 and dev1 are mesh gates
    subprocess.call(['iw', 'dev', dev[0].ifname, 'set', 'mesh_param',
                     'mesh_gate_announcements=1'])
    subprocess.call(['iw', 'dev', dev[1].ifname, 'set', 'mesh_param',
                     'mesh_gate_announcements=1'])

    # wait for gate announcement frames
    time.sleep(1)

    # data frame from dev2 -> external sta should be sent to both gates
    dev[2].request("DATA_TEST_CONFIG 1")
    dev[2].request("DATA_TEST_TX {} {} 0".format(external_sta, addr2))
    dev[2].request("DATA_TEST_CONFIG 0")

    capfile = os.path.join(p['logdir'], "hwsim0.pcapng")
    filt = "wlan.sa==%s && wlan_mgt.fixed.mesh_addr5==%s" % (addr2,
                                                             external_sta)
    for i in range(15):
        da = run_tshark(capfile, filt, [ "wlan.da" ])
        if addr0 in da and addr1 in da:
            logger.debug("Frames seen in tshark iteration %d" % i)
            break
        time.sleep(0.3)

    if addr0 not in da:
        raise Exception("Frame to gate %s not observed" % addr0)
    if addr1 not in da:
        raise Exception("Frame to gate %s not observed" % addr1)

def test_wpas_mesh_pmksa_caching(dev, apdev):
    """Secure mesh network and PMKSA caching"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    pmksa0 = dev[0].get_pmksa(addr1)
    pmksa1 = dev[1].get_pmksa(addr0)
    if pmksa0 is None or pmksa1 is None:
        raise Exception("No PMKSA cache entry created")
    if pmksa0['pmkid'] != pmksa1['pmkid']:
        raise Exception("PMKID mismatch in PMKSA cache entries")

    if "OK" not in dev[0].request("MESH_PEER_REMOVE " + addr1):
        raise Exception("Failed to remove peer")
    pmksa0b = dev[0].get_pmksa(addr1)
    if pmksa0b is None:
        raise Exception("PMKSA cache entry not maintained")
    time.sleep(0.1)

    if "FAIL" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD unexpectedly succeeded in no_auto_peer=0 case")

def test_wpas_mesh_pmksa_caching2(dev, apdev):
    """Secure mesh network and PMKSA caching with no_auto_peer=1"""
    check_mesh_support(dev[0], secure=True)
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].set_network(id, "no_auto_peer", "1")
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message")
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed")
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    pmksa0 = dev[0].get_pmksa(addr1)
    pmksa1 = dev[1].get_pmksa(addr0)
    if pmksa0 is None or pmksa1 is None:
        raise Exception("No PMKSA cache entry created")
    if pmksa0['pmkid'] != pmksa1['pmkid']:
        raise Exception("PMKID mismatch in PMKSA cache entries")

    if "OK" not in dev[0].request("MESH_PEER_REMOVE " + addr1):
        raise Exception("Failed to remove peer")
    pmksa0b = dev[0].get_pmksa(addr1)
    if pmksa0b is None:
        raise Exception("PMKSA cache entry not maintained")

    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message (2)")
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed (2)")
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    pmksa0c = dev[0].get_pmksa(addr1)
    pmksa1c = dev[1].get_pmksa(addr0)
    if pmksa0c is None or pmksa1c is None:
        raise Exception("No PMKSA cache entry created (2)")
    if pmksa0c['pmkid'] != pmksa1c['pmkid']:
        raise Exception("PMKID mismatch in PMKSA cache entries")
    if pmksa0['pmkid'] != pmksa0c['pmkid']:
        raise Exception("PMKID changed")

    hwsim_utils.test_connectivity(dev[0], dev[1])

def test_wpas_mesh_pmksa_caching_no_match(dev, apdev):
    """Secure mesh network and PMKSA caching with no PMKID match"""
    check_mesh_support(dev[0], secure=True)
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].set_network(id, "no_auto_peer", "1")
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message")
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed")
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    pmksa0 = dev[0].get_pmksa(addr1)
    pmksa1 = dev[1].get_pmksa(addr0)
    if pmksa0 is None or pmksa1 is None:
        raise Exception("No PMKSA cache entry created")
    if pmksa0['pmkid'] != pmksa1['pmkid']:
        raise Exception("PMKID mismatch in PMKSA cache entries")

    if "OK" not in dev[0].request("MESH_PEER_REMOVE " + addr1):
        raise Exception("Failed to remove peer")

    if "OK" not in dev[1].request("PMKSA_FLUSH"):
        raise Exception("Failed to flush PMKSA cache")

    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message (2)")
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed (2)")
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    pmksa0c = dev[0].get_pmksa(addr1)
    pmksa1c = dev[1].get_pmksa(addr0)
    if pmksa0c is None or pmksa1c is None:
        raise Exception("No PMKSA cache entry created (2)")
    if pmksa0c['pmkid'] != pmksa1c['pmkid']:
        raise Exception("PMKID mismatch in PMKSA cache entries")
    if pmksa0['pmkid'] == pmksa0c['pmkid']:
        raise Exception("PMKID did not change")

    hwsim_utils.test_connectivity(dev[0], dev[1])

def test_mesh_pmksa_caching_oom(dev, apdev):
    """Secure mesh network and PMKSA caching failing due to OOM"""
    check_mesh_support(dev[0], secure=True)
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].set_network(id, "no_auto_peer", "1")
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message")
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed")
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    if "OK" not in dev[0].request("MESH_PEER_REMOVE " + addr1):
        raise Exception("Failed to remove peer")
    pmksa0b = dev[0].get_pmksa(addr1)
    if pmksa0b is None:
        raise Exception("PMKSA cache entry not maintained")

    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message (2)")

    with alloc_fail(dev[0], 1, "wpa_auth_sta_init;mesh_rsn_auth_sae_sta"):
        if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
            raise Exception("MESH_PEER_ADD failed (2)")
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")

def test_mesh_oom(dev, apdev):
    """Mesh network setup failing due to OOM"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")

    with alloc_fail(dev[0], 1, "mesh_config_create"):
        add_open_mesh_network(dev[0])
        ev = dev[0].wait_event(["Failed to init mesh"])
        if ev is None:
            raise Exception("Init failure not reported")

    with alloc_fail(dev[0], 4, "=wpa_supplicant_mesh_init"):
        add_open_mesh_network(dev[0], basic_rates="60 120 240")
        ev = dev[0].wait_event(["Failed to init mesh"])
        if ev is None:
            raise Exception("Init failure not reported")

    for i in range(1, 66):
        dev[0].dump_monitor()
        logger.info("Test instance %d" % i)
        try:
            with alloc_fail(dev[0], i, "wpa_supplicant_mesh_init"):
                add_open_mesh_network(dev[0])
                wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
                ev = dev[0].wait_event(["Failed to init mesh",
                                        "MESH-GROUP-STARTED"])
                if ev is None:
                    raise Exception("Init failure not reported")
        except Exception, e:
            if i < 15:
                raise
            logger.info("Ignore no-oom for i=%d" % i)

    with alloc_fail(dev[0], 5, "=wpa_supplicant_mesh_init"):
        id = add_mesh_secure_net(dev[0])
        dev[0].mesh_group_add(id)
        ev = dev[0].wait_event(["Failed to init mesh"])
        if ev is None:
            raise Exception("Init failure not reported")

def test_mesh_add_interface_oom(dev):
    """wpa_supplicant mesh with dynamic interface addition failing"""
    check_mesh_support(dev[0])
    for i in range(1, 3):
        mesh = None
        try:
            with alloc_fail(dev[0], i, "wpas_mesh_add_interface"):
                mesh = dev[0].request("MESH_INTERFACE_ADD").strip()
        finally:
            if mesh and mesh != "FAIL":
                dev[0].request("MESH_GROUP_REMOVE " + mesh)

def test_mesh_scan_oom(dev):
    """wpa_supplicant mesh scan results and OOM"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    check_mesh_group_added(dev[0])
    for i in range(5):
        dev[1].scan(freq="2412")
        res = dev[1].request("SCAN_RESULTS")
        if "[MESH]" in res:
            break
    for r in res.splitlines():
        if "[MESH]" in r:
            break
    bssid = r.split('\t')[0]

    bss = dev[1].get_bss(bssid)
    if bss is None:
        raise Exception("Could not get BSS entry for mesh")

    for i in range(1, 3):
        with alloc_fail(dev[1], i, "mesh_attr_text"):
            bss = dev[1].get_bss(bssid)
            if bss and "mesh_id" in bss:
                raise Exception("Unexpected BSS result during OOM")

def test_mesh_drv_fail(dev, apdev):
    """Mesh network setup failing due to driver command failure"""
    check_mesh_support(dev[0], secure=True)
    dev[0].request("SET sae_groups ")

    with fail_test(dev[0], 1, "nl80211_join_mesh"):
        add_open_mesh_network(dev[0])
        ev = dev[0].wait_event(["mesh join error"])
        if ev is None:
            raise Exception("Join failure not reported")

    dev[0].dump_monitor()
    with fail_test(dev[0], 1, "wpa_driver_nl80211_if_add"):
        if "FAIL" not in dev[0].request("MESH_INTERFACE_ADD").strip():
            raise Exception("Interface added unexpectedly")

    dev[0].dump_monitor()
    with fail_test(dev[0], 1, "wpa_driver_nl80211_init_mesh"):
        add_open_mesh_network(dev[0])
        ev = dev[0].wait_event(["Could not join mesh"])
        if ev is None:
            raise Exception("Join failure not reported")

def test_mesh_sae_groups_invalid(dev, apdev):
    """Mesh with invalid SAE group configuration"""
    check_mesh_support(dev[0], secure=True)

    dev[0].request("SET sae_groups 25")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups 123 122 121")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    ev = dev[0].wait_event(["new peer notification"], timeout=10)
    if ev is None:
        raise Exception("dev[0] did not see peer")
    ev = dev[1].wait_event(["new peer notification"], timeout=10)
    if ev is None:
        raise Exception("dev[1] did not see peer")

    ev = dev[0].wait_event(["MESH-PEER-CONNECTED"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected connection(0)")

    ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.01)
    if ev is not None:
        raise Exception("Unexpected connection(1)")

    # Additional coverage in mesh_rsn_sae_group() with non-zero
    # wpa_s->mesh_rsn->sae_group_index.
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    id = add_mesh_secure_net(dev[2])
    dev[2].mesh_group_add(id)
    check_mesh_group_added(dev[2])
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[2])
    ev = dev[1].wait_event(["new peer notification"], timeout=10)
    if ev is None:
        raise Exception("dev[1] did not see peer(2)")
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    dev[2].dump_monitor()

    dev[0].request("SET sae_groups ")
    dev[1].request("SET sae_groups ")

def test_mesh_sae_failure(dev, apdev):
    """Mesh and local SAE failures"""
    check_mesh_support(dev[0], secure=True)

    dev[0].request("SET sae_groups ")
    dev[1].request("SET sae_groups ")

    funcs = [ (1, "=mesh_rsn_auth_sae_sta", True),
              (1, "mesh_rsn_build_sae_commit;mesh_rsn_auth_sae_sta", False),
              (1, "auth_sae_init_committed;mesh_rsn_auth_sae_sta", True),
              (1, "=mesh_rsn_protect_frame", True),
              (2, "=mesh_rsn_protect_frame", True),
              (1, "aes_siv_encrypt;mesh_rsn_protect_frame", True),
              (1, "=mesh_rsn_process_ampe", True),
              (1, "aes_siv_decrypt;mesh_rsn_process_ampe", True) ]
    for count, func, success in funcs:
        id = add_mesh_secure_net(dev[0])
        dev[0].mesh_group_add(id)

        with alloc_fail(dev[1], count, func):
            id = add_mesh_secure_net(dev[1])
            dev[1].mesh_group_add(id)
            check_mesh_group_added(dev[0])
            check_mesh_group_added(dev[1])
            if success:
                # retry is expected to work
                check_mesh_peer_connected(dev[0])
                check_mesh_peer_connected(dev[1])
            else:
                wait_fail_trigger(dev[1], "GET_ALLOC_FAIL")
        dev[0].mesh_group_remove()
        dev[1].mesh_group_remove()
        check_mesh_group_removed(dev[0])
        check_mesh_group_removed(dev[1])

def test_mesh_failure(dev, apdev):
    """Mesh and local failures"""
    check_mesh_support(dev[0])

    funcs = [ (1, "ap_sta_add;mesh_mpm_add_peer", True),
              (1, "wpabuf_alloc;mesh_mpm_send_plink_action", True) ]
    for count, func, success in funcs:
        add_open_mesh_network(dev[0])

        with alloc_fail(dev[1], count, func):
            add_open_mesh_network(dev[1])
            check_mesh_group_added(dev[0])
            check_mesh_group_added(dev[1])
            if success:
                # retry is expected to work
                check_mesh_peer_connected(dev[0])
                check_mesh_peer_connected(dev[1])
            else:
                wait_fail_trigger(dev[1], "GET_ALLOC_FAIL")
        dev[0].mesh_group_remove()
        dev[1].mesh_group_remove()
        check_mesh_group_removed(dev[0])
        check_mesh_group_removed(dev[1])

    funcs = [ (1, "mesh_mpm_init_link", True) ]
    for count, func, success in funcs:
        add_open_mesh_network(dev[0])

        with fail_test(dev[1], count, func):
            add_open_mesh_network(dev[1])
            check_mesh_group_added(dev[0])
            check_mesh_group_added(dev[1])
            if success:
                # retry is expected to work
                check_mesh_peer_connected(dev[0])
                check_mesh_peer_connected(dev[1])
            else:
                wait_fail_trigger(dev[1], "GET_FAIL")
        dev[0].mesh_group_remove()
        dev[1].mesh_group_remove()
        check_mesh_group_removed(dev[0])
        check_mesh_group_removed(dev[1])

def test_mesh_invalid_frequency(dev, apdev):
    """Mesh and invalid frequency configuration"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0], freq=None)
    ev = dev[0].wait_event(["MESH-GROUP-STARTED",
                            "Could not join mesh"])
    if ev is None or "Could not join mesh" not in ev:
        raise Exception("Mesh join failure not reported")
    dev[0].request("REMOVE_NETWORK all")

    add_open_mesh_network(dev[0], freq="2413")
    ev = dev[0].wait_event(["MESH-GROUP-STARTED",
                            "Could not join mesh"])
    if ev is None or "Could not join mesh" not in ev:
        raise Exception("Mesh join failure not reported")

def test_mesh_default_beacon_int(dev, apdev):
    """Mesh and default beacon interval"""
    check_mesh_support(dev[0])
    try:
        dev[0].request("SET beacon_int 200")
        add_open_mesh_network(dev[0])
        check_mesh_group_added(dev[0])
    finally:
        dev[0].request("SET beacon_int 0")

def test_mesh_scan_parse_error(dev, apdev):
    """Mesh scan element parse error"""
    check_mesh_support(dev[0])
    params = { "ssid": "open",
               "beacon_int": "2000" }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']
    hapd.set('vendor_elements', 'dd0201')
    for i in range(10):
        dev[0].scan(freq=2412)
        if bssid in dev[0].request("SCAN_RESULTS"):
            break
    # This will fail in IE parsing due to the truncated IE in the Probe
    # Response frame.
    bss = dev[0].request("BSS " + bssid)

def test_mesh_missing_mic(dev, apdev):
    """Secure mesh network and missing MIC"""
    check_mesh_support(dev[0], secure=True)

    dev[0].request("SET ext_mgmt_frame_handling 1")
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    count = 0
    remove_mic = True
    while True:
        count += 1
        if count > 15:
            raise Exception("Did not see Action frames")
        rx_msg = dev[0].mgmt_rx()
        if rx_msg is None:
            ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.01)
            if ev:
                break
            raise Exception("MGMT-RX timeout")
        if rx_msg['subtype'] == 13:
            payload = rx_msg['payload']
            frame = rx_msg['frame']
            (categ, action) = struct.unpack('BB', payload[0:2])
            if categ == 15 and action == 1 and remove_mic:
                # Mesh Peering Open
                pos = frame.find('\x8c\x10')
                if not pos:
                    raise Exception("Could not find MIC element")
                logger.info("Found MIC at %d" % pos)
                # Remove MIC
                rx_msg['frame'] = frame[0:pos]
                remove_mic = False
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(rx_msg['freq'], rx_msg['datarate'], rx_msg['ssi_signal'], rx_msg['frame'].encode('hex'))):
            raise Exception("MGMT_RX_PROCESS failed")
        ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.01)
        if ev:
            break

def test_mesh_pmkid_mismatch(dev, apdev):
    """Secure mesh network and PMKID mismatch"""
    check_mesh_support(dev[0], secure=True)
    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()
    dev[0].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[0])
    dev[0].set_network(id, "no_auto_peer", "1")
    dev[0].mesh_group_add(id)

    dev[1].request("SET sae_groups ")
    id = add_mesh_secure_net(dev[1])
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message")
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed")
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    if "OK" not in dev[0].request("MESH_PEER_REMOVE " + addr1):
        raise Exception("Failed to remove peer")

    ev = dev[0].wait_event(["will not initiate new peer link"], timeout=10)
    if ev is None:
        raise Exception("Missing no-initiate message (2)")
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    dev[0].request("SET ext_mgmt_frame_handling 1")
    if "OK" not in dev[0].request("MESH_PEER_ADD " + addr1):
        raise Exception("MESH_PEER_ADD failed (2)")

    count = 0
    break_pmkid = True
    while True:
        count += 1
        if count > 50:
            raise Exception("Did not see Action frames")
        rx_msg = dev[0].mgmt_rx()
        if rx_msg is None:
            ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.1)
            if ev:
                break
            raise Exception("MGMT-RX timeout")
        if rx_msg['subtype'] == 13:
            payload = rx_msg['payload']
            frame = rx_msg['frame']
            (categ, action) = struct.unpack('BB', payload[0:2])
            if categ == 15 and action == 1 and break_pmkid:
                # Mesh Peering Open
                pos = frame.find('\x75\x14')
                if not pos:
                    raise Exception("Could not find Mesh Peering Management element")
                logger.info("Found Mesh Peering Management element at %d" % pos)
                # Break PMKID to hit "Mesh RSN: Invalid PMKID (Chosen PMK did
                # not match calculated PMKID)"
                rx_msg['frame'] = frame[0:pos + 6] + '\x00\x00\x00\x00' + frame[pos + 10:]
                break_pmkid = False
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(rx_msg['freq'], rx_msg['datarate'], rx_msg['ssi_signal'], rx_msg['frame'].encode('hex'))):
            raise Exception("MGMT_RX_PROCESS failed")
        ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.01)
        if ev:
            break

def test_mesh_peering_proto(dev, apdev):
    """Mesh peering management protocol testing"""
    check_mesh_support(dev[0])

    dev[0].request("SET ext_mgmt_frame_handling 1")
    add_open_mesh_network(dev[0], beacon_int=160)
    add_open_mesh_network(dev[1], beacon_int=160)

    count = 0
    test = 1
    while True:
        count += 1
        if count > 50:
            raise Exception("Did not see Action frames")
        rx_msg = dev[0].mgmt_rx()
        if rx_msg is None:
            ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.01)
            if ev:
                break
            raise Exception("MGMT-RX timeout")
        if rx_msg['subtype'] == 13:
            payload = rx_msg['payload']
            frame = rx_msg['frame']
            (categ, action) = struct.unpack('BB', payload[0:2])
            if categ == 15 and action == 1 and test == 1:
                # Mesh Peering Open
                pos = frame.find('\x75\x04')
                if not pos:
                    raise Exception("Could not find Mesh Peering Management element")
                logger.info("Found Mesh Peering Management element at %d" % pos)
                # Remove the element to hit
                # "MPM: No Mesh Peering Management element"
                rx_msg['frame'] = frame[0:pos]
                test += 1
            elif categ == 15 and action == 1 and test == 2:
                # Mesh Peering Open
                pos = frame.find('\x72\x0e')
                if not pos:
                    raise Exception("Could not find Mesh ID element")
                logger.info("Found Mesh ID element at %d" % pos)
                # Remove the element to hit
                # "MPM: No Mesh ID or Mesh Configuration element"
                rx_msg['frame'] = frame[0:pos] + frame[pos + 16:]
                test += 1
            elif categ == 15 and action == 1 and test == 3:
                # Mesh Peering Open
                pos = frame.find('\x72\x0e')
                if not pos:
                    raise Exception("Could not find Mesh ID element")
                logger.info("Found Mesh ID element at %d" % pos)
                # Replace Mesh ID to hit "MPM: Mesh ID or Mesh Configuration
                # element do not match local MBSS"
                rx_msg['frame'] = frame[0:pos] + '\x72\x0etest-test-test' + frame[pos + 16:]
                test += 1
            elif categ == 15 and action == 1 and test == 4:
                # Mesh Peering Open
                # Remove IEs to hit
                # "MPM: Ignore too short action frame 1 ie_len 0"
                rx_msg['frame'] = frame[0:26]
                test += 1
            elif categ == 15 and action == 1 and test == 5:
                # Mesh Peering Open
                # Truncate IEs to hit
                # "MPM: Failed to parse PLINK IEs"
                rx_msg['frame'] = frame[0:30]
                test += 1
            elif categ == 15 and action == 1 and test == 6:
                # Mesh Peering Open
                pos = frame.find('\x75\x04')
                if not pos:
                    raise Exception("Could not find Mesh Peering Management element")
                logger.info("Found Mesh Peering Management element at %d" % pos)
                # Truncate the element to hit
                # "MPM: Invalid peer mgmt ie" and
                # "MPM: Mesh parsing rejected frame"
                rx_msg['frame'] = frame[0:pos] + '\x75\x00\x00\x00' + frame[pos + 6:]
                test += 1
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(rx_msg['freq'], rx_msg['datarate'], rx_msg['ssi_signal'], rx_msg['frame'].encode('hex'))):
            raise Exception("MGMT_RX_PROCESS failed")
        ev = dev[1].wait_event(["MESH-PEER-CONNECTED"], timeout=0.01)
        if ev:
            break

    if test != 7:
        raise Exception("Not all test frames completed")

def test_mesh_mpm_init_proto(dev, apdev):
    """Mesh peering management protocol testing for peer addition"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    check_mesh_group_added(dev[0])
    dev[0].dump_monitor()

    dev[0].request("SET ext_mgmt_frame_handling 1")

    addr = "020000000100"
    hdr = "d000ac00020000000000" + addr + addr + "1000"
    fixed = "0f010000"
    supp_rates = "010802040b168c129824"
    ext_supp_rates = "3204b048606c"
    mesh_id = "720e777061732d6d6573682d6f70656e"
    mesh_conf = "710701010001000009"
    mpm = "75040000079d"
    ht_capab = "2d1a7c001bffff000000000000000000000100000000000000000000"
    ht_oper = "3d160b000000000000000000000000000000000000000000"

    dev[0].request("NOTE no supported rates")
    frame = hdr + fixed + ext_supp_rates + mesh_id + mesh_conf + mpm + ht_capab + ht_oper
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
        raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("NOTE Invalid supported rates element length 33+0")
    long_supp_rates = "012100112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
    frame = hdr + fixed + long_supp_rates + mesh_id + mesh_conf + mpm + ht_capab + ht_oper
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
        raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("NOTE Too short mesh config")
    short_mesh_conf = "710401010001"
    frame = hdr + fixed + supp_rates + mesh_id + short_mesh_conf + mpm + ht_capab + ht_oper
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
        raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("NOTE Add STA failure")
    frame = hdr + fixed + supp_rates + ext_supp_rates + mesh_id + mesh_conf + mpm + ht_capab + ht_oper
    with fail_test(dev[0], 1, "wpa_driver_nl80211_sta_add"):
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
            raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("NOTE Send Action failure")
    with fail_test(dev[0], 1, "driver_nl80211_send_action"):
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
            raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("NOTE Set STA failure")
    addr = "020000000101"
    hdr = "d000ac00020000000000" + addr + addr + "1000"
    frame = hdr + fixed + supp_rates + ext_supp_rates + mesh_id + mesh_conf + mpm + ht_capab + ht_oper
    with fail_test(dev[0], 2, "wpa_driver_nl80211_sta_add"):
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
            raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("NOTE ap_sta_add OOM")
    addr = "020000000102"
    hdr = "d000ac00020000000000" + addr + addr + "1000"
    frame = hdr + fixed + supp_rates + ext_supp_rates + mesh_id + mesh_conf + mpm + ht_capab + ht_oper
    with alloc_fail(dev[0], 1, "ap_sta_add"):
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
            raise Exception("MGMT_RX_PROCESS failed")

    dev[0].request("NOTE hostapd_get_aid() failure")
    addr = "020000000103"
    hdr = "d000ac00020000000000" + addr + addr + "1000"
    frame = hdr + fixed + supp_rates + ext_supp_rates + mesh_id + mesh_conf + mpm + ht_capab + ht_oper
    with fail_test(dev[0], 1, "hostapd_get_aid"):
        if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
            raise Exception("MGMT_RX_PROCESS failed")

    if "OK" not in dev[0].request("MESH_PEER_REMOVE 02:00:00:00:01:00"):
        raise Exception("Failed to remove peer")
    if "FAIL" not in dev[0].request("MESH_PEER_REMOVE 02:00:00:00:01:02"):
        raise Exception("Unexpected MESH_PEER_REMOVE success")
    if "FAIL" not in dev[1].request("MESH_PEER_REMOVE 02:00:00:00:01:02"):
        raise Exception("Unexpected MESH_PEER_REMOVE success(2)")
    if "FAIL" not in dev[1].request("MESH_PEER_ADD 02:00:00:00:01:02"):
        raise Exception("Unexpected MESH_PEER_ADD success")

def test_mesh_holding(dev, apdev):
    """Mesh MPM FSM and HOLDING state event OPN_ACPT"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    add_open_mesh_network(dev[1])
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()

    dev[0].request("SET ext_mgmt_frame_handling 1")
    if "OK" not in dev[0].request("MESH_PEER_REMOVE " + addr1):
        raise Exception("Failed to remove peer")

    rx_msg = dev[0].mgmt_rx()
    if rx_msg is None:
        raise Exception("MGMT-RX timeout")
    if rx_msg['subtype'] != 13:
        raise Exception("Unexpected management frame")
    payload = rx_msg['payload']
    (categ, action) = struct.unpack('BB', payload[0:2])
    if categ != 0x0f or action != 0x03:
        raise Exception("Did not see Mesh Peering Close")

    peer_lid = payload[-6:-4].encode("hex")
    my_lid = payload[-4:-2].encode("hex")

    # Drop Mesh Peering Close and instead, process an unexpected Mesh Peering
    # Open to trigger transmission of another Mesh Peering Close in the HOLDING
    # state based on an OPN_ACPT event.

    dst = addr0.replace(':', '')
    src = addr1.replace(':', '')
    hdr = "d000ac00" + dst + src + src + "1000"
    fixed = "0f010000"
    supp_rates = "010802040b168c129824"
    ext_supp_rates = "3204b048606c"
    mesh_id = "720e777061732d6d6573682d6f70656e"
    mesh_conf = "710701010001000009"
    mpm = "7504" + my_lid + peer_lid
    ht_capab = "2d1a7c001bffff000000000000000000000100000000000000000000"
    ht_oper = "3d160b000000000000000000000000000000000000000000"

    frame = hdr + fixed + supp_rates + ext_supp_rates + mesh_id + mesh_conf + mpm + ht_capab + ht_oper
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % frame):
        raise Exception("MGMT_RX_PROCESS failed")
    time.sleep(0.1)

def test_mesh_cnf_rcvd_event_cls_acpt(dev, apdev):
    """Mesh peering management protocol testing - CLS_ACPT event in CNF_RCVD"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    check_mesh_group_added(dev[0])
    dev[0].dump_monitor()

    dev[0].request("SET ext_mgmt_frame_handling 1")
    add_open_mesh_network(dev[1])
    check_mesh_group_added(dev[1])

    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()

    rx_msg = dev[0].mgmt_rx()
    # Drop Mesh Peering Open

    rx_msg = dev[0].mgmt_rx()
    # Allow Mesh Peering Confirm to go through
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(rx_msg['freq'], rx_msg['datarate'], rx_msg['ssi_signal'], rx_msg['frame'].encode('hex'))):
        raise Exception("MGMT_RX_PROCESS failed")

    payload = rx_msg['payload']
    peer_lid = payload[51:53].encode("hex")
    my_lid = payload[53:55].encode("hex")

    dst = addr0.replace(':', '')
    src = addr1.replace(':', '')
    hdr = "d000ac00" + dst + src + src + "1000"
    fixed = "0f03"
    mesh_id = "720e777061732d6d6573682d6f70656e"
    mpm = "75080000" + peer_lid + my_lid + "3700"
    frame = hdr + fixed + mesh_id + mpm

    # Inject Mesh Peering Close to hit "state CNF_RCVD event CLS_ACPT" to
    # HOLDING transition.
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + frame):
        raise Exception("MGMT_RX_PROCESS failed")

def test_mesh_opn_snt_event_cls_acpt(dev, apdev):
    """Mesh peering management protocol testing - CLS_ACPT event in OPN_SNT"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0])
    check_mesh_group_added(dev[0])
    dev[0].dump_monitor()

    dev[0].request("SET ext_mgmt_frame_handling 1")
    add_open_mesh_network(dev[1])
    check_mesh_group_added(dev[1])

    addr0 = dev[0].own_addr()
    addr1 = dev[1].own_addr()

    rx_msg = dev[0].mgmt_rx()
    # Drop Mesh Peering Open

    rx_msg = dev[0].mgmt_rx()
    # Drop Mesh Peering Confirm

    payload = rx_msg['payload']
    peer_lid = "0000"
    my_lid = payload[53:55].encode("hex")

    dst = addr0.replace(':', '')
    src = addr1.replace(':', '')
    hdr = "d000ac00" + dst + src + src + "1000"
    fixed = "0f03"
    mesh_id = "720e777061732d6d6573682d6f70656e"
    mpm = "75080000" + peer_lid + my_lid + "3700"
    frame = hdr + fixed + mesh_id + mpm

    # Inject Mesh Peering Close to hit "state OPN_SNTevent CLS_ACPT" to
    # HOLDING transition.
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + frame):
        raise Exception("MGMT_RX_PROCESS failed")

def test_mesh_select_network(dev):
    """Mesh network and SELECT_NETWORK"""
    check_mesh_support(dev[0])
    id0 = add_open_mesh_network(dev[0], start=False)
    id1 = add_open_mesh_network(dev[1], start=False)
    dev[0].select_network(id0)
    dev[1].select_network(id1)
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])
    hwsim_utils.test_connectivity(dev[0], dev[1])
