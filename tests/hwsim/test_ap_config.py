# hostapd configuration tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import signal
import time

from remotehost import remote_compatible
import hostapd

@remote_compatible
def test_ap_config_errors(dev, apdev):
    """Various hostapd configuration errors"""

    # IEEE 802.11d without country code
    params = { "ssid": "foo", "ieee80211d": "1" }
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (ieee80211d without country_code)")
    hostapd.remove_bss(apdev[0])

    # IEEE 802.11h without IEEE 802.11d
    params = { "ssid": "foo", "ieee80211h": "1" }
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (ieee80211h without ieee80211d")
    hostapd.remove_bss(apdev[0])

    # Power Constraint without IEEE 802.11d
    params = { "ssid": "foo", "local_pwr_constraint": "1" }
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (local_pwr_constraint without ieee80211d)")
    hostapd.remove_bss(apdev[0])

    # Spectrum management without Power Constraint
    params = { "ssid": "foo", "spectrum_mgmt_required": "1" }
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (spectrum_mgmt_required without local_pwr_constraint)")
    hostapd.remove_bss(apdev[0])

    # IEEE 802.1X without authentication server
    params = { "ssid": "foo", "ieee8021x": "1" }
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (ieee8021x)")
    hostapd.remove_bss(apdev[0])

    # RADIUS-PSK without macaddr_acl=2
    params = hostapd.wpa2_params(ssid="foo", passphrase="12345678")
    params["wpa_psk_radius"] = "1"
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (wpa_psk_radius)")
    hostapd.remove_bss(apdev[0])

    # FT without NAS-Identifier
    params = { "wpa": "2",
               "wpa_key_mgmt": "FT-PSK",
               "rsn_pairwise": "CCMP",
               "wpa_passphrase": "12345678" }
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (FT without nas_identifier)")
    hostapd.remove_bss(apdev[0])

    # Hotspot 2.0 without WPA2/CCMP
    params = hostapd.wpa2_params(ssid="foo")
    params['wpa_key_mgmt'] = "WPA-EAP"
    params['ieee8021x'] = "1"
    params['auth_server_addr'] = "127.0.0.1"
    params['auth_server_port'] = "1812"
    params['auth_server_shared_secret'] = "radius"
    params['interworking'] = "1"
    params['hs20'] = "1"
    params['wpa'] = "1"
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (HS 2.0 without WPA2/CCMP)")
    hostapd.remove_bss(apdev[0])

def test_ap_config_reload(dev, apdev, params):
    """hostapd configuration reload"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "foo" })
    hapd.set("ssid", "foobar")
    with open(os.path.join(params['logdir'], 'hostapd-test.pid'), "r") as f:
        pid = int(f.read())
    os.kill(pid, signal.SIGHUP)
    time.sleep(0.1)
    dev[0].connect("foobar", key_mgmt="NONE", scan_freq="2412")
    hapd.set("ssid", "foo")
    os.kill(pid, signal.SIGHUP)
    dev[0].wait_disconnected()
    dev[0].request("DISCONNECT")

def test_ap_config_reload_file(dev, apdev, params):
    """hostapd configuration reload from file"""
    hapd = hostapd.add_iface(apdev[0], "bss-1.conf")
    hapd.enable()
    hapd.set("ssid", "foobar")
    with open(os.path.join(params['logdir'], 'hostapd-test.pid'), "r") as f:
        pid = int(f.read())
    os.kill(pid, signal.SIGHUP)
    time.sleep(0.1)
    dev[0].connect("foobar", key_mgmt="NONE", scan_freq="2412")
    hapd.set("ssid", "foo")
    os.kill(pid, signal.SIGHUP)
    dev[0].wait_disconnected()
    dev[0].request("DISCONNECT")

def test_ap_config_reload_before_enable(dev, apdev, params):
    """hostapd configuration reload before enable"""
    hapd = hostapd.add_iface(apdev[0], "bss-1.conf")
    with open(os.path.join(params['logdir'], 'hostapd-test.pid'), "r") as f:
        pid = int(f.read())
    os.kill(pid, signal.SIGHUP)
    hapd.ping()

def test_ap_config_sigusr1(dev, apdev, params):
    """hostapd SIGUSR1"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "foobar" })
    with open(os.path.join(params['logdir'], 'hostapd-test.pid'), "r") as f:
        pid = int(f.read())
    os.kill(pid, signal.SIGUSR1)
    dev[0].connect("foobar", key_mgmt="NONE", scan_freq="2412")
    os.kill(pid, signal.SIGUSR1)

def test_ap_config_invalid_value(dev, apdev, params):
    """Ignoring invalid hostapd configuration parameter updates"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "test" }, no_enable=True)
    not_exist = "/tmp/hostapd-test/does-not-exist"
    tests = [ ("driver", "foobar"),
              ("ssid2", "Q"),
              ("macaddr_acl", "255"),
              ("accept_mac_file", not_exist),
              ("deny_mac_file", not_exist),
              ("eapol_version", "255"),
              ("eap_user_file", not_exist),
              ("wep_key_len_broadcast", "-1"),
              ("wep_key_len_unicast", "-1"),
              ("wep_rekey_period", "-1"),
              ("eap_rekey_period", "-1"),
              ("radius_client_addr", "foo"),
              ("acs_chan_bias", "-1:0.8"),
              ("acs_chan_bias", "1"),
              ("acs_chan_bias", "1:p"),
              ("acs_chan_bias", "1:-0.8"),
              ("acs_chan_bias", "1:0.8p"),
              ("dtim_period", "0"),
              ("bss_load_update_period", "-1"),
              ("send_probe_response", "255"),
              ("beacon_rate", "ht:-1"),
              ("beacon_rate", "ht:32"),
              ("beacon_rate", "vht:-1"),
              ("beacon_rate", "vht:10"),
              ("beacon_rate", "9"),
              ("beacon_rate", "10001"),
              ("vlan_file", not_exist),
              ("bss", ""),
              ("bssid", "foo"),
              ("extra_cred", not_exist),
              ("anqp_elem", "265"),
              ("anqp_elem", "265"),
              ("anqp_elem", "265:1"),
              ("anqp_elem", "265:1q"),
              ("fst_priority", ""),
              ("fils_cache_id", "q"),
              ("unknown-item", "foo") ]
    for field, val in tests:
        if "FAIL" not in hapd.request("SET %s %s" % (field, val)):
            raise Exception("Invalid %s accepted" % field)
    hapd.enable()
    dev[0].connect("test", key_mgmt="NONE", scan_freq="2412")
