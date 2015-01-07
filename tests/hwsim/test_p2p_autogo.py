# P2P autonomous GO test cases
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()

import hwsim_utils
import utils
from utils import HwsimSkip
from wlantest import Wlantest
from wpasupplicant import WpaSupplicant

def autogo(go, freq=None, persistent=None):
    logger.info("Start autonomous GO " + go.ifname)
    res = go.p2p_start_go(freq=freq, persistent=persistent)
    logger.debug("res: " + str(res))
    return res

def connect_cli(go, client, social=False, freq=None):
    logger.info("Try to connect the client to the GO")
    pin = client.wps_read_pin()
    go.p2p_go_authorize_client(pin)
    res = client.p2p_connect_group(go.p2p_dev_addr(), pin, timeout=60,
                                   social=social, freq=freq)
    logger.info("Client connected")
    hwsim_utils.test_connectivity_p2p(go, client)
    return res

def test_autogo(dev):
    """P2P autonomous GO and client joining group"""
    addr0 = dev[0].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()
    res = autogo(dev[0])
    if "p2p-wlan" in res['ifname']:
        raise Exception("Unexpected group interface name on GO")
    res = connect_cli(dev[0], dev[1])
    if "p2p-wlan" in res['ifname']:
        raise Exception("Unexpected group interface name on client")
    bss = dev[1].get_bss("p2p_dev_addr=" + addr0)
    if bss['bssid'] != dev[0].p2p_interface_addr():
        raise Exception("Unexpected BSSID in the BSS entry for the GO")
    id = bss['id']
    bss = dev[1].get_bss("ID-" + id)
    if bss['id'] != id:
        raise Exception("Could not find BSS entry based on id")
    res = dev[1].request("BSS RANGE=" + id + "- MASK=0x1")
    if "id=" + id not in res:
        raise Exception("Could not find BSS entry based on id range")

    res = dev[1].request("SCAN_RESULTS")
    if "[P2P]" not in res:
        raise Exception("P2P flag missing from scan results: " + res)

    # Presence request to increase testing coverage
    if "FAIL" not in dev[1].group_request("P2P_PRESENCE_REQ 30000"):
        raise Exception("Invald P2P_PRESENCE_REQ accepted")
    if "FAIL" not in dev[1].group_request("P2P_PRESENCE_REQ 30000 102400 30001"):
        raise Exception("Invald P2P_PRESENCE_REQ accepted")
    if "FAIL" in dev[1].group_request("P2P_PRESENCE_REQ 30000 102400"):
        raise Exception("Could not send presence request")
    ev = dev[1].wait_event(["P2P-PRESENCE-RESPONSE"])
    if ev is None:
        raise Exception("Timeout while waiting for Presence Response")
    if "FAIL" in dev[1].group_request("P2P_PRESENCE_REQ 30000 102400 20000 102400"):
        raise Exception("Could not send presence request")
    ev = dev[1].wait_event(["P2P-PRESENCE-RESPONSE"])
    if ev is None:
        raise Exception("Timeout while waiting for Presence Response")
    if "FAIL" in dev[1].group_request("P2P_PRESENCE_REQ"):
        raise Exception("Could not send presence request")
    ev = dev[1].wait_event(["P2P-PRESENCE-RESPONSE"])
    if ev is None:
        raise Exception("Timeout while waiting for Presence Response")

    if not dev[2].discover_peer(addr0):
        raise Exception("Could not discover GO")
    dev[0].dump_monitor()
    dev[2].global_request("P2P_PROV_DISC " + addr0 + " display join")
    ev = dev[0].wait_global_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=10)
    if ev is None:
        raise Exception("GO did not report P2P-PROV-DISC-SHOW-PIN")
    if "p2p_dev_addr=" + addr2 not in ev:
        raise Exception("Unexpected P2P Device Address in event: " + ev)
    if "group=" + dev[0].group_ifname not in ev:
        raise Exception("Unexpected group interface in event: " + ev)
    ev = dev[2].wait_global_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=10)
    if ev is None:
        raise Exception("P2P-PROV-DISC-ENTER-PIN not reported")

    dev[0].remove_group()
    dev[1].wait_go_ending_session()

def test_autogo2(dev):
    """P2P autonomous GO with a separate group interface and client joining group"""
    dev[0].request("SET p2p_no_group_iface 0")
    res = autogo(dev[0], freq=2437)
    if "p2p-wlan" not in res['ifname']:
        raise Exception("Unexpected group interface name on GO")
    if res['ifname'] not in utils.get_ifnames():
        raise Exception("Could not find group interface netdev")
    connect_cli(dev[0], dev[1], social=True, freq=2437)
    dev[0].remove_group()
    dev[1].wait_go_ending_session()
    if res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")

def test_autogo3(dev):
    """P2P autonomous GO and client with a separate group interface joining group"""
    dev[1].request("SET p2p_no_group_iface 0")
    autogo(dev[0], freq=2462)
    res = connect_cli(dev[0], dev[1], social=True, freq=2462)
    if "p2p-wlan" not in res['ifname']:
        raise Exception("Unexpected group interface name on client")
    if res['ifname'] not in utils.get_ifnames():
        raise Exception("Could not find group interface netdev")
    dev[0].remove_group()
    dev[1].wait_go_ending_session()
    dev[1].ping()
    if res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")

def test_autogo4(dev):
    """P2P autonomous GO and client joining group (both with a separate group interface)"""
    dev[0].request("SET p2p_no_group_iface 0")
    dev[1].request("SET p2p_no_group_iface 0")
    res1 = autogo(dev[0], freq=2412)
    res2 = connect_cli(dev[0], dev[1], social=True, freq=2412)
    if "p2p-wlan" not in res1['ifname']:
        raise Exception("Unexpected group interface name on GO")
    if "p2p-wlan" not in res2['ifname']:
        raise Exception("Unexpected group interface name on client")
    ifnames = utils.get_ifnames()
    if res1['ifname'] not in ifnames:
        raise Exception("Could not find GO group interface netdev")
    if res2['ifname'] not in ifnames:
        raise Exception("Could not find client group interface netdev")
    dev[0].remove_group()
    dev[1].wait_go_ending_session()
    dev[1].ping()
    ifnames = utils.get_ifnames()
    if res1['ifname'] in ifnames:
        raise Exception("GO group interface netdev was not removed")
    if res2['ifname'] in ifnames:
        raise Exception("Client group interface netdev was not removed")

def test_autogo_m2d(dev):
    """P2P autonomous GO and clients not authorized"""
    autogo(dev[0], freq=2412)
    go_addr = dev[0].p2p_dev_addr()

    dev[1].request("SET p2p_no_group_iface 0")
    if not dev[1].discover_peer(go_addr, social=True):
        raise Exception("GO " + go_addr + " not found")
    dev[1].dump_monitor()

    if not dev[2].discover_peer(go_addr, social=True):
        raise Exception("GO " + go_addr + " not found")
    dev[2].dump_monitor()

    logger.info("Trying to join the group when GO has not authorized the client")
    pin = dev[1].wps_read_pin()
    cmd = "P2P_CONNECT " + go_addr + " " + pin + " join"
    if "OK" not in dev[1].global_request(cmd):
        raise Exception("P2P_CONNECT join failed")

    pin = dev[2].wps_read_pin()
    cmd = "P2P_CONNECT " + go_addr + " " + pin + " join"
    if "OK" not in dev[2].global_request(cmd):
        raise Exception("P2P_CONNECT join failed")

    ev = dev[1].wait_global_event(["WPS-M2D"], timeout=10)
    if ev is None:
        raise Exception("No global M2D event")
    ifaces = dev[1].request("INTERFACES").splitlines()
    iface = ifaces[0] if "p2p-wlan" in ifaces[0] else ifaces[1]
    wpas = WpaSupplicant(ifname=iface)
    ev = wpas.wait_event(["WPS-M2D"], timeout=10)
    if ev is None:
        raise Exception("No M2D event on group interface")

    ev = dev[2].wait_global_event(["WPS-M2D"], timeout=10)
    if ev is None:
        raise Exception("No global M2D event (2)")
    ev = dev[2].wait_event(["WPS-M2D"], timeout=10)
    if ev is None:
        raise Exception("No M2D event on group interface (2)")

def test_autogo_fail(dev):
    """P2P autonomous GO and incorrect PIN"""
    autogo(dev[0], freq=2412)
    go_addr = dev[0].p2p_dev_addr()
    dev[0].p2p_go_authorize_client("00000000")

    dev[1].request("SET p2p_no_group_iface 0")
    if not dev[1].discover_peer(go_addr, social=True):
        raise Exception("GO " + go_addr + " not found")
    dev[1].dump_monitor()

    logger.info("Trying to join the group when GO has not authorized the client")
    pin = dev[1].wps_read_pin()
    cmd = "P2P_CONNECT " + go_addr + " " + pin + " join"
    if "OK" not in dev[1].global_request(cmd):
        raise Exception("P2P_CONNECT join failed")

    ev = dev[1].wait_global_event(["WPS-FAIL"], timeout=10)
    if ev is None:
        raise Exception("No global WPS-FAIL event")

def test_autogo_2cli(dev):
    """P2P autonomous GO and two clients joining group"""
    autogo(dev[0], freq=2412)
    connect_cli(dev[0], dev[1], social=True, freq=2412)
    connect_cli(dev[0], dev[2], social=True, freq=2412)
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    dev[0].global_request("P2P_REMOVE_CLIENT " + dev[1].p2p_dev_addr())
    dev[1].wait_go_ending_session()
    dev[0].global_request("P2P_REMOVE_CLIENT iface=" + dev[2].p2p_interface_addr())
    dev[2].wait_go_ending_session()
    if "FAIL" not in dev[0].global_request("P2P_REMOVE_CLIENT foo"):
        raise Exception("Invalid P2P_REMOVE_CLIENT command accepted")
    dev[0].remove_group()

def test_autogo_pbc(dev):
    """P2P autonomous GO and PBC"""
    dev[1].request("SET p2p_no_group_iface 0")
    autogo(dev[0], freq=2412)
    if "FAIL" not in dev[0].group_request("WPS_PBC p2p_dev_addr=00:11:22:33:44"):
        raise Exception("Invalid WPS_PBC succeeded")
    if "OK" not in dev[0].group_request("WPS_PBC p2p_dev_addr=" + dev[1].p2p_dev_addr()):
        raise Exception("WPS_PBC failed")
    dev[2].p2p_connect_group(dev[0].p2p_dev_addr(), "pbc", timeout=0,
                             social=True)
    ev = dev[2].wait_event(["WPS-M2D"], timeout=15)
    if ev is None:
        raise Exception("WPS-M2D not reported")
    if "config_error=12" not in ev:
        raise Exception("Unexpected config_error: " + ev)
    dev[1].p2p_connect_group(dev[0].p2p_dev_addr(), "pbc", timeout=15,
                             social=True)

def test_autogo_tdls(dev):
    """P2P autonomous GO and two clients using TDLS"""
    wt = Wlantest()
    go = dev[0]
    logger.info("Start autonomous GO with fixed parameters " + go.ifname)
    id = go.add_network()
    go.set_network_quoted(id, "ssid", "DIRECT-tdls")
    go.set_network_quoted(id, "psk", "12345678")
    go.set_network(id, "mode", "3")
    go.set_network(id, "disabled", "2")
    res = go.p2p_start_go(persistent=id, freq="2462")
    logger.debug("res: " + str(res))
    wt.flush()
    wt.add_passphrase("12345678")
    connect_cli(go, dev[1], social=True, freq=2462)
    connect_cli(go, dev[2], social=True, freq=2462)
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    bssid = dev[0].p2p_interface_addr()
    addr1 = dev[1].p2p_interface_addr()
    addr2 = dev[2].p2p_interface_addr()
    dev[1].tdls_setup(addr2)
    time.sleep(1)
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    conf = wt.get_tdls_counter("setup_conf_ok", bssid, addr1, addr2);
    if conf == 0:
        raise Exception("No TDLS Setup Confirm (success) seen")
    dl = wt.get_tdls_counter("valid_direct_link", bssid, addr1, addr2);
    if dl == 0:
        raise Exception("No valid frames through direct link")
    wt.tdls_clear(bssid, addr1, addr2);
    dev[1].tdls_teardown(addr2)
    time.sleep(1)
    teardown = wt.get_tdls_counter("teardown", bssid, addr1, addr2);
    if teardown == 0:
        raise Exception("No TDLS Setup Teardown seen")
    wt.tdls_clear(bssid, addr1, addr2);
    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])
    ap_path = wt.get_tdls_counter("valid_ap_path", bssid, addr1, addr2);
    if ap_path == 0:
        raise Exception("No valid frames via AP path")
    direct_link = wt.get_tdls_counter("valid_direct_link", bssid, addr1, addr2);
    if direct_link > 0:
        raise Exception("Unexpected frames through direct link")
    idirect_link = wt.get_tdls_counter("invalid_direct_link", bssid, addr1,
                                       addr2);
    if idirect_link > 0:
        raise Exception("Unexpected frames through direct link (invalid)")
    dev[2].remove_group()
    dev[1].remove_group()
    dev[0].remove_group()

def test_autogo_legacy(dev):
    """P2P autonomous GO and legacy clients"""
    res = autogo(dev[0], freq=2462)
    if dev[0].get_group_status_field("passphrase", extra="WPS") != res['passphrase']:
        raise Exception("passphrase mismatch")
    if dev[0].request("P2P_GET_PASSPHRASE") != res['passphrase']:
        raise Exception("passphrase mismatch(2)")

    logger.info("Connect P2P client")
    connect_cli(dev[0], dev[1], social=True, freq=2462)

    if "FAIL" not in dev[1].request("P2P_GET_PASSPHRASE"):
        raise Exception("P2P_GET_PASSPHRASE succeeded on P2P Client")

    logger.info("Connect legacy WPS client")
    pin = dev[2].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    dev[2].request("P2P_SET disabled 1")
    dev[2].dump_monitor()
    dev[2].request("WPS_PIN any " + pin)
    dev[2].wait_connected(timeout=30)
    status = dev[2].get_status()
    if status['wpa_state'] != 'COMPLETED':
        raise Exception("Not fully connected")
    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])
    dev[2].request("DISCONNECT")

    logger.info("Connect legacy non-WPS client")
    dev[2].request("FLUSH")
    dev[2].request("P2P_SET disabled 1")
    dev[2].connect(ssid=res['ssid'], psk=res['passphrase'], proto='RSN',
                   key_mgmt='WPA-PSK', pairwise='CCMP', group='CCMP',
                   scan_freq=res['freq'])
    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])
    dev[2].request("DISCONNECT")

    dev[0].remove_group()
    dev[1].wait_go_ending_session()

def test_autogo_chan_switch(dev):
    """P2P autonomous GO switching channels"""
    autogo(dev[0], freq=2417)
    connect_cli(dev[0], dev[1])
    res = dev[0].request("CHAN_SWITCH 5 2422")
    if "FAIL" in res:
        # for now, skip test since mac80211_hwsim support is not yet widely
        # deployed
        raise HwsimSkip("Assume mac80211_hwsim did not support channel switching")
    ev = dev[0].wait_event(["AP-CSA-FINISHED"], timeout=10)
    if ev is None:
        raise Exception("CSA finished event timed out")
    if "freq=2422" not in ev:
        raise Exception("Unexpected cahnnel in CSA finished event")
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    time.sleep(0.1)
    hwsim_utils.test_connectivity_p2p(dev[0], dev[1])

def test_autogo_extra_cred(dev):
    """P2P autonomous GO sending two WPS credentials"""
    if "FAIL" in dev[0].request("SET wps_testing_dummy_cred 1"):
        raise Exception("Failed to enable test mode")
    autogo(dev[0], freq=2412)
    connect_cli(dev[0], dev[1], social=True, freq=2412)
    dev[0].remove_group()
    dev[1].wait_go_ending_session()

def test_autogo_ifdown(dev):
    """P2P autonomous GO and external ifdown"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    res = autogo(wpas)
    wpas.dump_monitor()
    wpas.interface_remove("wlan5")
    wpas.interface_add("wlan5")
    res = autogo(wpas)
    wpas.dump_monitor()
    subprocess.call(['sudo', 'ifconfig', res['ifname'], 'down'])
    ev = wpas.wait_global_event(["P2P-GROUP-REMOVED"], timeout=10)
    if ev is None:
        raise Exception("Group removal not reported")
    if res['ifname'] not in ev:
        raise Exception("Unexpected group removal event: " + ev)

def test_autogo_start_during_scan(dev):
    """P2P autonomous GO started during ongoing manual scan"""
    try:
        # use autoscan to set scan_req = MANUAL_SCAN_REQ
        if "OK" not in dev[0].request("AUTOSCAN periodic:1"):
            raise Exception("Failed to set autoscan")
        autogo(dev[0], freq=2462)
        connect_cli(dev[0], dev[1], social=True, freq=2462)
        dev[0].remove_group()
        dev[1].wait_go_ending_session()
    finally:
        dev[0].request("AUTOSCAN ")

def test_autogo_passphrase_len(dev):
    """P2P autonomous GO and longer passphrase"""
    try:
        if "OK" not in dev[0].request("SET p2p_passphrase_len 13"):
            raise Exception("Failed to set passphrase length")
        res = autogo(dev[0], freq=2412)
        if len(res['passphrase']) != 13:
            raise Exception("Unexpected passphrase length")
        if dev[0].get_group_status_field("passphrase", extra="WPS") != res['passphrase']:
            raise Exception("passphrase mismatch")

        logger.info("Connect P2P client")
        connect_cli(dev[0], dev[1], social=True, freq=2412)

        logger.info("Connect legacy WPS client")
        pin = dev[2].wps_read_pin()
        dev[0].p2p_go_authorize_client(pin)
        dev[2].request("P2P_SET disabled 1")
        dev[2].dump_monitor()
        dev[2].request("WPS_PIN any " + pin)
        dev[2].wait_connected(timeout=30)
        status = dev[2].get_status()
        if status['wpa_state'] != 'COMPLETED':
            raise Exception("Not fully connected")
        dev[2].request("DISCONNECT")

        logger.info("Connect legacy non-WPS client")
        dev[2].request("FLUSH")
        dev[2].request("P2P_SET disabled 1")
        dev[2].connect(ssid=res['ssid'], psk=res['passphrase'], proto='RSN',
                       key_mgmt='WPA-PSK', pairwise='CCMP', group='CCMP',
                       scan_freq=res['freq'])
        hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])
        dev[2].request("DISCONNECT")

        dev[0].remove_group()
        dev[1].wait_go_ending_session()
    finally:
        dev[0].request("SET p2p_passphrase_len 8")

def test_autogo_bridge(dev):
    """P2P autonomous GO in a bridge"""
    try:
        # use autoscan to set scan_req = MANUAL_SCAN_REQ
        if "OK" not in dev[0].request("AUTOSCAN periodic:1"):
            raise Exception("Failed to set autoscan")
        autogo(dev[0])
        subprocess.call(['sudo', 'brctl', 'addbr', 'p2p-br0'])
        subprocess.call(['sudo', 'brctl', 'setfd', 'p2p-br0', '0'])
        subprocess.call(['sudo', 'brctl', 'addif', 'p2p-br0', dev[0].ifname])
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', 'p2p-br0', 'up'])
        time.sleep(0.1)
        subprocess.call(['sudo', 'brctl', 'delif', 'p2p-br0', dev[0].ifname])
        time.sleep(0.1)
        subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', 'p2p-br0', 'down'])
        time.sleep(0.1)
        subprocess.call(['sudo', 'brctl', 'delbr', 'p2p-br0'])
        ev = dev[0].wait_global_event(["P2P-GROUP-REMOVED"], timeout=1)
        if ev is not None:
            raise Exception("P2P group removed unexpectedly")
        if dev[0].get_status_field('wpa_state') != "COMPLETED":
            raise Exception("Unexpected wpa_state")
        dev[0].remove_group()
    finally:
        dev[0].request("AUTOSCAN ")
        subprocess.Popen(['sudo', 'brctl', 'delif', 'p2p-br0', dev[0].ifname],
                         stderr=open('/dev/null', 'w'))
        subprocess.Popen(['sudo', 'ip', 'link', 'set', 'dev', 'p2p-br0', 'down'],
                         stderr=open('/dev/null', 'w'))
        subprocess.Popen(['sudo', 'brctl', 'delbr', 'p2p-br0'],
                         stderr=open('/dev/null', 'w'))

def test_presence_req_on_group_interface(dev):
    """P2P_PRESENCE_REQ on group interface"""
    dev[1].request("SET p2p_no_group_iface 0")
    res = autogo(dev[0], freq=2437)
    res = connect_cli(dev[0], dev[1], social=True, freq=2437)
    if "FAIL" in dev[1].group_request("P2P_PRESENCE_REQ 30000 102400"):
        raise Exception("Could not send presence request")
    ev = dev[1].wait_group_event(["P2P-PRESENCE-RESPONSE"])
    if ev is None:
        raise Exception("Timeout while waiting for Presence Response")
    dev[0].remove_group()
    dev[1].wait_go_ending_session()
