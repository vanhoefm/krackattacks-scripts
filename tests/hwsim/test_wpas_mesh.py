#!/usr/bin/python
#
# wpa_supplicant mesh mode tests
# Copyright (c) 2014, cozybit Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess

import hwsim_utils
from wpasupplicant import WpaSupplicant
from utils import HwsimSkip

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

def add_open_mesh_network(dev, freq="2412", start=True, beacon_int=0):
    id = dev.add_network()
    dev.set_network(id, "mode", "5")
    dev.set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev.set_network(id, "key_mgmt", "NONE")
    dev.set_network(id, "frequency", freq)
    if beacon_int:
        dev.set_network(id, "beacon_int", str(beacon_int))
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
    check_mesh_scan(dev[0], "use_id=1", beacon_int=175)

def test_wpas_mesh_open(dev, apdev):
    """wpa_supplicant open MESH network connectivity"""
    check_mesh_support(dev[0])
    add_open_mesh_network(dev[0], freq="2462")
    add_open_mesh_network(dev[1], freq="2462")

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    hwsim_utils.test_connectivity(dev[0], dev[1])

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

def add_mesh_secure_net(dev, psk=True):
    id = dev.add_network()
    dev.set_network(id, "mode", "5")
    dev.set_network_quoted(id, "ssid", "wpas-mesh-sec")
    dev.set_network(id, "key_mgmt", "SAE")
    dev.set_network(id, "frequency", "2412")
    if psk:
        dev.set_network_quoted(id, "psk", "thisismypassphrase!")
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

def test_wpas_mesh_max_peering(dev, apdev):
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

    count = 0
    ev = dev[0].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=1)
    if ev is None:
        logger.info("dev0 did not report auth failure")
    else:
        if "addr=" + dev[2].own_addr() not in ev:
            raise Exception("Unexpected peer address in dev0 event: " + ev)
        count += 1

    ev = dev[1].wait_event(["MESH-SAE-AUTH-FAILURE"], timeout=1)
    if ev is None:
        logger.info("dev1 did not report auth failure")
    else:
        if "addr=" + dev[2].own_addr() not in ev:
            raise Exception("Unexpected peer address in dev1 event: " + ev)
        count += 1

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
