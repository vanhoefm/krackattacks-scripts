# hostapd configuration tests
# Copyright (c) 2014-2016, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import signal
import time
import logging
logger = logging.getLogger(__name__)
import subprocess

from remotehost import remote_compatible
import hostapd
from utils import alloc_fail, fail_test

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

def write_hostapd_config(conffile, ifname, ssid):
    with open(conffile, "w") as f:
        f.write("driver=nl80211\n")
        f.write("hw_mode=g\n")
        f.write("channel=1\n")
        f.write("ieee80211n=1\n")
        f.write("interface=" + ifname + "\n")
        f.write("ssid=" + ssid + "\n")

def test_ap_config_reload_on_sighup(dev, apdev, params):
    """hostapd configuration reload modification from file on SIGHUP"""
    pidfile = os.path.join(params['logdir'],
                           "ap_config_reload_on_sighup-hostapd.pid")
    logfile = os.path.join(params['logdir'],
                           "ap_config_reload_on_sighup-hostapd-log")
    conffile = os.path.join(os.getcwd(), params['logdir'],
                            "ap_config_reload_on_sighup-hostapd.conf")
    prg = os.path.join(params['logdir'], 'alt-hostapd/hostapd/hostapd')
    if not os.path.exists(prg):
        prg = '../../hostapd/hostapd'
    write_hostapd_config(conffile, apdev[0]['ifname'], "test-1")
    cmd = [ prg, '-B', '-dddt', '-P', pidfile, '-f', logfile, conffile ]
    res = subprocess.check_call(cmd)
    if res != 0:
        raise Exception("Could not start hostapd: %s" % str(res))

    dev[0].connect("test-1", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected()

    write_hostapd_config(conffile, apdev[0]['ifname'], "test-2")
    with open(pidfile, "r") as f:
        pid = int(f.read())
    os.kill(pid, signal.SIGHUP)

    dev[0].connect("test-2", key_mgmt="NONE", scan_freq="2412")
    dev[0].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected()

    os.kill(pid, signal.SIGTERM)
    removed = False
    for i in range(20):
        time.sleep(0.1)
        if not os.path.exists(pidfile):
            removed = True
            break
    if not removed:
        raise Exception("hostapd PID file not removed on SIGTERM")

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

def test_ap_config_eap_user_file_parsing(dev, apdev, params):
    """hostapd eap_user_file parsing"""
    tmp = os.path.join(params['logdir'], 'ap_vlan_file_parsing.tmp')
    hapd = hostapd.add_ap(apdev[0], { "ssid": "foobar" })

    for i in range(2):
        if "OK" not in hapd.request("SET eap_user_file auth_serv/eap_user.conf"):
            raise Exception("eap_user_file rejected")

    tests = [ "#\n\n*\tTLS\nradius_accept_attr=:",
              "foo\n",
              "\"foo\n",
              "\"foo\"\n",
              "\"foo\" FOOBAR\n",
              "\"foo\" " + 10*"TLS," + "TLS \"\n",
              "\"foo\" TLS \nfoo\n",
              "\"foo\" PEAP hash:foo\n",
              "\"foo\" PEAP hash:8846f7eaee8fb117ad06bdd830b7586q\n",
              "\"foo\" PEAP 01020\n",
              "\"foo\" PEAP 010q\n",
              "\"foo\" TLS\nradius_accept_attr=123:x:012\n",
              "\"foo\" TLS\nradius_accept_attr=123:x:012q\n",
              "\"foo\" TLS\nradius_accept_attr=123:Q:01\n",
              "\"foo\" TLS\nradius_accept_attr=123\nfoo\n" ]
    for t in tests:
        with open(tmp, "w") as f:
            f.write(t)
        if "FAIL" not in hapd.request("SET eap_user_file " + tmp):
            raise Exception("Invalid eap_user_file accepted")

    tests = [ ("\"foo\" TLS\n", 2, "hostapd_config_read_eap_user"),
              ("\"foo\" PEAP \"foo\"\n", 3, "hostapd_config_read_eap_user"),
              ("\"foo\" PEAP hash:8846f7eaee8fb117ad06bdd830b75861\n", 3,
               "hostapd_config_read_eap_user"),
              ("\"foo\" PEAP 0102\n", 3, "hostapd_config_read_eap_user"),
              ("\"foo\" TLS\nradius_accept_attr=123\n", 1,
               "=hostapd_parse_radius_attr"),
              ("\"foo\" TLS\nradius_accept_attr=123\n", 1,
               "wpabuf_alloc;hostapd_parse_radius_attr"),
              ("\"foo\" TLS\nradius_accept_attr=123:s:foo\n", 2,
               "hostapd_parse_radius_attr"),
              ("\"foo\" TLS\nradius_accept_attr=123:x:0102\n", 2,
               "hostapd_parse_radius_attr"),
              ("\"foo\" TLS\nradius_accept_attr=123:d:1\n", 2,
               "hostapd_parse_radius_attr"),
              ("* TLS\n", 1, "hostapd_config_read_eap_user") ]
    for t, count, func in tests:
        with alloc_fail(hapd, count, func):
            with open(tmp, "w") as f:
                f.write(t)
            if "FAIL" not in hapd.request("SET eap_user_file " + tmp):
                raise Exception("eap_user_file accepted during OOM")

def test_ap_config_set_oom(dev, apdev):
    """hostapd configuration parsing OOM"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "foobar" })

    tests = [ (1, "hostapd_parse_das_client",
               "SET radius_das_client 192.168.1.123 pw"),
              (1, "hostapd_config_read_wep", "SET wep_key0 \"hello\""),
              (1, "hostapd_config_read_wep", "SET wep_key0 0102030405"),
              (1, "hostapd_parse_chanlist", "SET chanlist 1 6 11-13"),
              (1, "hostapd_config_bss", "SET bss foo"),
              (2, "hostapd_config_bss", "SET bss foo"),
              (3, "hostapd_config_bss", "SET bss foo"),
              (1, "add_r0kh",
               "SET r0kh 02:01:02:03:04:05 r0kh-1.example.com 000102030405060708090a0b0c0d0e0f"),
              (1, "add_r1kh",
               "SET r1kh 02:01:02:03:04:05 02:11:22:33:44:55 000102030405060708090a0b0c0d0e0f"),
              (1, "parse_roaming_consortium", "SET roaming_consortium 021122"),
              (1, "parse_lang_string", "SET venue_name eng:Example venue"),
              (1, "parse_3gpp_cell_net",
               "SET anqp_3gpp_cell_net 244,91;310,026;234,56"),
              (1, "parse_nai_realm", "SET nai_realm 0,example.com;example.net"),
              (2, "parse_nai_realm", "SET nai_realm 0,example.com;example.net"),
              (1, "parse_anqp_elem", "SET anqp_elem 265:0000"),
              (2, "parse_anqp_elem", "SET anqp_elem 266:000000"),
              (1, "hs20_parse_conn_capab", "SET hs20_conn_capab 1:0:2"),
              (1, "hs20_parse_wan_metrics",
               "SET hs20_wan_metrics 01:8000:1000:80:240:3000"),
              (1, "hs20_parse_icon",
               "SET hs20_icon 32:32:eng:image/png:icon32:/tmp/icon32.png"),
              (1, "hs20_parse_osu_server_uri",
               "SET osu_server_uri https://example.com/osu/"),
              (1, "hostapd_config_parse_acs_chan_bias",
               "SET acs_chan_bias 1:0.8 6:0.8 11:0.8"),
              (2, "hostapd_config_parse_acs_chan_bias",
               "SET acs_chan_bias 1:0.8 6:0.8 11:0.8"),
              (1, "parse_wpabuf_hex", "SET vendor_elements 01020304"),
              (1, "parse_fils_realm", "SET fils_realm example.com"),
              (1, "hostapd_config_fill",
               "SET pac_opaque_encr_key 000102030405060708090a0b0c0d0e0f"),
              (1, "hostapd_config_fill", "SET eap_message hello"),
              (1, "hostapd_config_fill",
               "SET wpa_psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
              (1, "hostapd_config_fill", "SET time_zone EST5"),
              (1, "hostapd_config_fill",
               "SET network_auth_type 02http://www.example.com/redirect/"),
              (1, "hostapd_config_fill", "SET domain_name example.com"),
              (1, "hostapd_config_fill", "SET hs20_operating_class 5173"),
              (1, "hostapd_config_fill", "SET own_ie_override 11223344"),
              (1, "hostapd_parse_intlist", "SET sae_groups 19 25"),
              (1, "hostapd_parse_intlist", "SET basic_rates 10 20 55 110"),
              (1, "hostapd_parse_intlist", "SET supported_rates 10 20 55 110") ]
    for count, func, cmd in tests:
        with alloc_fail(hapd, count, func):
            if "FAIL" not in hapd.request(cmd):
                raise Exception("Command accepted during OOM: " + cmd)

    hapd.set("hs20_icon", "32:32:eng:image/png:icon32:/tmp/icon32.png")
    hapd.set("hs20_conn_capab", "1:0:2")
    hapd.set("nai_realm", "0,example.com;example.net")
    hapd.set("venue_name", "eng:Example venue")
    hapd.set("roaming_consortium", "021122")
    hapd.set("osu_server_uri", "https://example.com/osu/")
    hapd.set("vendor_elements", "01020304")
    hapd.set("vendor_elements", "01020304")
    hapd.set("vendor_elements", "")
    hapd.set("lci", "11223344")
    hapd.set("civic", "11223344")
    hapd.set("lci", "")
    hapd.set("civic", "")

    tests = [ (1, "hs20_parse_icon",
               "SET hs20_icon 32:32:eng:image/png:icon32:/tmp/icon32.png"),
              (1, "parse_roaming_consortium", "SET roaming_consortium 021122"),
              (2, "parse_nai_realm", "SET nai_realm 0,example.com;example.net"),
              (1, "parse_lang_string", "SET venue_name eng:Example venue"),
              (1, "hs20_parse_osu_server_uri",
               "SET osu_server_uri https://example.com/osu/"),
              (1, "hs20_parse_osu_nai", "SET osu_nai anonymous@example.com"),
              (1, "hostapd_parse_intlist", "SET osu_method_list 1 0"),
              (1, "hs20_parse_osu_icon", "SET osu_icon icon32"),
              (2, "hs20_parse_osu_icon", "SET osu_icon icon32"),
              (2, "hs20_parse_osu_icon", "SET osu_icon icon32"),
              (1, "hs20_parse_conn_capab", "SET hs20_conn_capab 1:0:2") ]
    for count, func, cmd in tests:
        with alloc_fail(hapd, count, func):
            if "FAIL" not in hapd.request(cmd):
                raise Exception("Command accepted during OOM (2): " + cmd)

    tests = [ (1, "parse_fils_realm", "SET fils_realm example.com") ]
    for count, func, cmd in tests:
        with fail_test(hapd, count, func):
            if "FAIL" not in hapd.request(cmd):
                raise Exception("Command accepted during FAIL_TEST: " + cmd)

def test_ap_config_set_errors(dev, apdev):
    """hostapd configuration parsing errors"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "foobar" })
    hapd.set("wep_key0", '"hello"')
    hapd.set("wep_key1", '"hello"')
    hapd.set("wep_key0", '')
    hapd.set("wep_key0", '"hello"')
    if "FAIL" not in hapd.request("SET wep_key1 \"hello\""):
        raise Exception("SET wep_key1 allowed to override existing key")
    hapd.set("wep_key1", '')
    hapd.set("wep_key1", '"hello"')

    hapd.set("auth_server_addr", "127.0.0.1")
    hapd.set("acct_server_addr", "127.0.0.1")

    tests = [ "SET eap_reauth_period -1",
              "SET fst_llt ",
              "SET auth_server_addr_replace foo",
              "SET acct_server_addr_replace foo" ]
    for t in tests:
        if "FAIL" not in hapd.request(t):
            raise Exception("Invalid command accepted: " + t)

    # Deprecated entries
    hapd.set("tx_queue_after_beacon_aifs", '2')
    hapd.set("tx_queue_beacon_aifs", '2')
    hapd.set("tx_queue_data9_aifs", '2')
    hapd.set("debug", '1')
    hapd.set("dump_file", '/tmp/hostapd-test-dump')
    hapd.set("eap_authenticator", '0')
    hapd.set("radio_measurements", '0')
    hapd.set("radio_measurements", '1')

    # Various extra coverage (not really errors)
    hapd.set("logger_syslog_level", '1')
    hapd.set("logger_syslog", '0')

    for i in range(50000):
        if "OK" not in hapd.request("SET hs20_conn_capab 17:5060:0"):
            logger.info("hs20_conn_capab limit at %d" % i)
            break
    if i < 1000 or i >= 49999:
        raise Exception("hs20_conn_capab limit not seen")
