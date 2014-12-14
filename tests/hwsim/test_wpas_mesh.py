#!/usr/bin/python
#
# wpa_supplicant mesh mode tests
# Copyright (c) 2014, cozybit Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.


def check_mesh_scan(dev, params, other_started=False):
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

def check_mesh_group_added(dev):
    ev = dev.wait_event(["MESH-GROUP-STARTED"])
    if ev is None:
        raise Exception("Test exception: Couldn't join mesh")


def check_mesh_group_removed(dev):
    ev = dev.wait_event(["MESH-GROUP-REMOVED"])
    if ev is None:
        raise Exception("Test exception: Couldn't leave mesh")


def check_mesh_peer_connected(dev):
    ev = dev.wait_event(["MESH-PEER-CONNECTED"])
    if ev is None:
        raise Exception("Test exception: Remote peer did not connect.")


def check_mesh_peer_disconnected(dev):
    ev = dev.wait_event(["MESH-PEER-DISCONNECTED"])
    if ev is None:
        raise Exception("Test exception: Peer disconnect event not detected.")


def test_wpas_add_set_remove_support(dev):
    """wpa_supplicant MESH add/set/remove network support"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].remove_network(id)


def test_wpas_mesh_group_added(dev):
    """wpa_supplicant MESH group add"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].mesh_group_add(id)

    # Check for MESH-GROUP-STARTED event
    check_mesh_group_added(dev[0])


def test_wpas_mesh_group_remove(dev):
    """wpa_supplicant MESH group remove"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].mesh_group_add(id)
    # Check for MESH-GROUP-STARTED event
    check_mesh_group_added(dev[0])
    dev[0].mesh_group_remove()
    # Check for MESH-GROUP-REMOVED event
    check_mesh_group_removed(dev[0])


def test_wpas_mesh_peer_connected(dev):
    """wpa_supplicant MESH peer connected"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].mesh_group_add(id)

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])


def test_wpas_mesh_peer_disconnected(dev):
    """wpa_supplicant MESH peer disconnected"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].mesh_group_add(id)

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].mesh_group_add(id)

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
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].set_network(id, "mesh_ht_mode", "HT40+")
    dev[0].mesh_group_add(id)

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].set_network(id, "mesh_ht_mode", "HT40+")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for Mesh scan
    check_mesh_scan(dev[0], "use_id=1")


def wrap_wpas_mesh_test(test, dev, apdev):
    import hwsim_utils

    def _test_connectivity(dev1, dev2):
        return hwsim_utils.test_connectivity(dev1, dev2)

    return test(dev, apdev, _test_connectivity)


def _test_wpas_mesh_open(dev, apdev, test_connectivity):
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].set_network(id, "mesh_ht_mode", "HT40+")
    dev[0].mesh_group_add(id)

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].set_network(id, "mesh_ht_mode", "HT40+")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    test_connectivity(dev[0], dev[1])


def test_wpas_mesh_open(dev, apdev):
    """wpa_supplicant open MESH network connectivity"""
    return wrap_wpas_mesh_test(_test_wpas_mesh_open, dev, apdev)


def _test_wpas_mesh_open_no_auto(dev, apdev, test_connectivity):
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].set_network(id, "dot11MeshMaxRetries", "16")
    dev[0].set_network(id, "dot11MeshRetryTimeout", "255")
    dev[0].mesh_group_add(id)

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].set_network(id, "no_auto_peer", "1")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_group_added(dev[0])
    check_mesh_group_added(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    test_connectivity(dev[0], dev[1])


def test_wpas_mesh_open_no_auto(dev, apdev):
    """wpa_supplicant open MESH network connectivity"""
    return wrap_wpas_mesh_test(_test_wpas_mesh_open_no_auto, dev, apdev)

def add_mesh_secure_net(dev, psk=True):
    id = dev.add_network()
    dev.set_network(id, "mode", "5")
    dev.set_network_quoted(id, "ssid", "wpas-mesh-sec")
    dev.set_network(id, "key_mgmt", "SAE")
    dev.set_network(id, "frequency", "2412")
    if psk:
        dev.set_network_quoted(id, "psk", "thisismypassphrase!")
    return id

def _test_wpas_mesh_secure(dev, apdev, test_connectivity):
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
    test_connectivity(dev[0], dev[1])


def test_wpas_mesh_secure(dev, apdev):
    """wpa_supplicant secure MESH network connectivity"""
    return wrap_wpas_mesh_test(_test_wpas_mesh_secure, dev, apdev)

def test_wpas_mesh_secure_sae_group_mismatch(dev, apdev):
    """wpa_supplicant secure MESH and SAE group mismatch"""
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

def _test_wpas_mesh_secure_no_auto(dev, apdev, test_connectivity):
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
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])

    # Test connectivity 0->1 and 1->0
    test_connectivity(dev[0], dev[1])

    dev[0].request("SET sae_groups ")
    dev[1].request("SET sae_groups ")

def test_wpas_mesh_secure_no_auto(dev, apdev):
    """wpa_supplicant secure MESH network connectivity"""
    return wrap_wpas_mesh_test(_test_wpas_mesh_secure_no_auto, dev, apdev)

def test_wpas_mesh_ctrl(dev):
    """wpa_supplicant ctrl_iface mesh command error cases"""
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
