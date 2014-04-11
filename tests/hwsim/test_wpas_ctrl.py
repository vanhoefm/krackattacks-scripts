# wpa_supplicant control interface
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

def test_wpas_ctrl_network(dev):
    """wpa_supplicant ctrl_iface network set/get"""
    id = dev[0].add_network()

    tests = (("key_mgmt", "WPA-PSK WPA-EAP IEEE8021X NONE WPA-NONE FT-PSK FT-EAP WPA-PSK-SHA256 WPA-EAP-SHA256"),
             ("pairwise", "CCMP-256 GCMP-256 CCMP GCMP TKIP"),
             ("group", "CCMP-256 GCMP-256 CCMP GCMP TKIP WEP104 WEP40"),
             ("auth_alg", "OPEN SHARED LEAP"),
             ("scan_freq", "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"),
             ("freq_list", "2412 2417"),
             ("scan_ssid", "1"),
             ("bssid", "00:11:22:33:44:55"),
             ("proto", "WPA RSN OSEN"),
             ("eap", "TLS"),
             ("go_p2p_dev_addr", "22:33:44:55:66:aa"),
             ("p2p_client_list", "22:33:44:55:66:bb 02:11:22:33:44:55"))

    dev[0].set_network_quoted(id, "ssid", "test")
    for field, value in tests:
        dev[0].set_network(id, field, value)
        res = dev[0].get_network(id, field)
        if res != value:
            raise Exception("Unexpected response for '" + field + "': '" + res + "'")

    q_tests = (("identity", "hello"),
               ("anonymous_identity", "foo@nowhere.com"))
    for field, value in q_tests:
        dev[0].set_network_quoted(id, field, value)
        res = dev[0].get_network(id, field)
        if res != '"' + value + '"':
            raise Exception("Unexpected quoted response for '" + field + "': '" + res + "'")

    get_tests = (("foo", None), ("ssid", '"test"'))
    for field, value in get_tests:
        res = dev[0].get_network(id, field)
        if res != value:
            raise Exception("Unexpected response for '" + field + "': '" + res + "'")

    if dev[0].get_network(id, "password"):
        raise Exception("Unexpected response for 'password'")
    dev[0].set_network_quoted(id, "password", "foo")
    if dev[0].get_network(id, "password") != '*':
        raise Exception("Unexpected response for 'password' (expected *)")
    dev[0].set_network(id, "password", "hash:12345678901234567890123456789012")
    if dev[0].get_network(id, "password") != '*':
        raise Exception("Unexpected response for 'password' (expected *)")
    dev[0].set_network(id, "password", "NULL")
    if dev[0].get_network(id, "password"):
        raise Exception("Unexpected response for 'password'")
    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + " password hash:12"):
        raise Exception("Unexpected success for invalid password hash")
    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + " password hash:123456789012345678x0123456789012"):
        raise Exception("Unexpected success for invalid password hash")

    dev[0].set_network(id, "identity", "414243")
    if dev[0].get_network(id, "identity") != '"ABC"':
        raise Exception("Unexpected identity hex->text response")

    dev[0].set_network(id, "identity", 'P"abc\ndef"')
    if dev[0].get_network(id, "identity") != "6162630a646566":
        raise Exception("Unexpected identity printf->hex response")

    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + ' identity P"foo'):
        raise Exception("Unexpected success for invalid identity string")

    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + ' identity 12x3'):
        raise Exception("Unexpected success for invalid identity string")

    for i in range(0, 4):
        if "FAIL" in dev[0].request("SET_NETWORK " + str(id) + ' wep_key' + str(i) + ' aabbccddee'):
            raise Exception("Unexpected wep_key set failure")
        if dev[0].get_network(id, "wep_key" + str(i)) != '*':
            raise Exception("Unexpected wep_key get failure")

    if "FAIL" in dev[0].request("SET_NETWORK " + str(id) + ' psk_list P2P-00:11:22:33:44:55-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'):
        raise Exception("Unexpected failure for psk_list string")

    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + ' psk_list 00:11:x2:33:44:55-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'):
        raise Exception("Unexpected success for invalid psk_list string")

    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + ' psk_list P2P-00:11:x2:33:44:55-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'):
        raise Exception("Unexpected success for invalid psk_list string")

    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + ' psk_list P2P-00:11:22:33:44:55+0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'):
        raise Exception("Unexpected success for invalid psk_list string")

    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + ' psk_list P2P-00:11:22:33:44:55-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde'):
        raise Exception("Unexpected success for invalid psk_list string")

    if "FAIL" not in dev[0].request("SET_NETWORK " + str(id) + ' psk_list P2P-00:11:22:33:44:55-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdex'):
        raise Exception("Unexpected success for invalid psk_list string")

    if dev[0].get_network(id, "psk_list"):
        raise Exception("Unexpected psk_list get response")

    if dev[0].list_networks()[0]['ssid'] != "test":
        raise Exception("Unexpected ssid in LIST_NETWORKS")
    dev[0].set_network(id, "ssid", "NULL")
    if dev[0].list_networks()[0]['ssid'] != "":
        raise Exception("Unexpected ssid in LIST_NETWORKS after clearing it")

    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' ssid "0123456789abcdef0123456789abcdef0"'):
        raise Exception("Too long SSID accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' scan_ssid qwerty'):
        raise Exception("Invalid integer accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' scan_ssid 2'):
        raise Exception("Too large integer accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' psk 12345678'):
        raise Exception("Invalid PSK accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' psk "1234567"'):
        raise Exception("Too short PSK accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' psk "1234567890123456789012345678901234567890123456789012345678901234"'):
        raise Exception("Too long PSK accepted")
    dev[0].set_network_quoted(id, "psk", "123456768");
    dev[0].set_network_quoted(id, "psk", "123456789012345678901234567890123456789012345678901234567890123");
    if dev[0].get_network(id, "psk") != '*':
        raise Exception("Unexpected psk read result");

    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' eap UNKNOWN'):
        raise Exception("Unknown EAP method accepted")

    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' password "foo'):
        raise Exception("Invalid password accepted")

    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' wep_key0 "foo'):
        raise Exception("Invalid WEP key accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' wep_key0 "12345678901234567"'):
        raise Exception("Too long WEP key accepted")
    # too short WEP key is ignored
    dev[0].set_network_quoted(id, "wep_key0", "1234")
    dev[0].set_network_quoted(id, "wep_key1", "12345")
    dev[0].set_network_quoted(id, "wep_key2", "1234567890123")
    dev[0].set_network_quoted(id, "wep_key3", "1234567890123456")

    dev[0].set_network(id, "go_p2p_dev_addr", "any")
    if dev[0].get_network(id, "go_p2p_dev_addr") is not None:
        raise Exception("Unexpected go_p2p_dev_addr value")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' go_p2p_dev_addr 00:11:22:33:44'):
        raise Exception("Invalid go_p2p_dev_addr accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' p2p_client_list 00:11:22:33:44'):
        raise Exception("Invalid p2p_client_list accepted")
    if "FAIL" in dev[0].request('SET_NETWORK ' + str(id) + ' p2p_client_list 00:11:22:33:44:55 00:1'):
        raise Exception("p2p_client_list truncation workaround failed")
    if dev[0].get_network(id, "p2p_client_list") != "00:11:22:33:44:55":
        raise Exception("p2p_client_list truncation workaround did not work")

    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' auth_alg '):
        raise Exception("Empty auth_alg accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' auth_alg FOO'):
        raise Exception("Invalid auth_alg accepted")

    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' proto '):
        raise Exception("Empty proto accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' proto FOO'):
        raise Exception("Invalid proto accepted")

    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' pairwise '):
        raise Exception("Empty pairwise accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' pairwise FOO'):
        raise Exception("Invalid pairwise accepted")
    if "FAIL" not in dev[0].request('SET_NETWORK ' + str(id) + ' pairwise WEP40'):
        raise Exception("Invalid pairwise accepted")

    if "OK" not in dev[0].request('BSSID ' + str(id) + ' 00:11:22:33:44:55'):
        raise Exception("Unexpected BSSID failure")
    if dev[0].request("GET_NETWORK 0 bssid") != '00:11:22:33:44:55':
        raise Exception("BSSID command did not set network bssid")
    if "OK" not in dev[0].request('BSSID ' + str(id) + ' 00:00:00:00:00:00'):
        raise Exception("Unexpected BSSID failure")
    if "FAIL" not in dev[0].request("GET_NETWORK 0 bssid"):
        raise Exception("bssid claimed configured after clearing")
    if "FAIL" not in dev[0].request('BSSID 123 00:11:22:33:44:55'):
        raise Exception("Unexpected BSSID success")
    if "FAIL" not in dev[0].request('BSSID ' + str(id) + ' 00:11:22:33:44'):
        raise Exception("Unexpected BSSID success")

def add_cred(dev):
    id = dev.add_cred()
    ev = dev.wait_event(["CRED-ADDED"])
    if ev is None:
        raise Exception("Missing CRED-ADDED event")
    if " " + str(id) not in ev:
        raise Exception("CRED-ADDED event without matching id")
    return id

def set_cred(dev, id, field, value):
    dev.set_cred(id, field, value)
    ev = dev.wait_event(["CRED-MODIFIED"])
    if ev is None:
        raise Exception("Missing CRED-MODIFIED event")
    if " " + str(id) + " " not in ev:
        raise Exception("CRED-MODIFIED event without matching id")
    if field not in ev:
        raise Exception("CRED-MODIFIED event without matching field")

def set_cred_quoted(dev, id, field, value):
    dev.set_cred_quoted(id, field, value)
    ev = dev.wait_event(["CRED-MODIFIED"])
    if ev is None:
        raise Exception("Missing CRED-MODIFIED event")
    if " " + str(id) + " " not in ev:
        raise Exception("CRED-MODIFIED event without matching id")
    if field not in ev:
        raise Exception("CRED-MODIFIED event without matching field")

def remove_cred(dev, id):
    dev.remove_cred(id)
    ev = dev.wait_event(["CRED-REMOVED"])
    if ev is None:
        raise Exception("Missing CRED-REMOVED event")
    if " " + str(id) not in ev:
        raise Exception("CRED-REMOVED event without matching id")

def test_wpas_ctrl_cred(dev):
    """wpa_supplicant ctrl_iface cred set"""
    id1 = add_cred(dev[0])
    id = add_cred(dev[0])
    id2 = add_cred(dev[0])
    set_cred(dev[0], id, "temporary", "1")
    set_cred(dev[0], id, "priority", "1")
    set_cred(dev[0], id, "pcsc", "1")
    set_cred_quoted(dev[0], id, "private_key_passwd", "test")
    set_cred_quoted(dev[0], id, "domain_suffix_match", "test")
    set_cred_quoted(dev[0], id, "phase1", "test")
    set_cred_quoted(dev[0], id, "phase2", "test")

    if "FAIL" not in dev[0].request("SET_CRED " + str(id) + " eap FOO"):
        raise Exception("Unexpected success on unknown EAP method")

    if "FAIL" not in dev[0].request("SET_CRED " + str(id) + " username 12xa"):
        raise Exception("Unexpected success on invalid string")

    for i in ("11", "1122", "112233445566778899aabbccddeeff00"):
        if "FAIL" not in dev[0].request("SET_CRED " + str(id) + " roaming_consortium " + i):
            raise Exception("Unexpected success on invalid roaming_consortium")

    dev[0].set_cred(id, "excluded_ssid", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    if "FAIL" not in dev[0].request("SET_CRED " + str(id) + " excluded_ssid 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"):
        raise Exception("Unexpected success on invalid excluded_ssid")

    if "FAIL" not in dev[0].request("SET_CRED " + str(id) + " foo 4142"):
        raise Exception("Unexpected success on unknown field")

    id3 = add_cred(dev[0])
    id4 = add_cred(dev[0])

    remove_cred(dev[0], id1)
    remove_cred(dev[0], id3)
    remove_cred(dev[0], id4)
    remove_cred(dev[0], id2)
    remove_cred(dev[0], id)
    if "FAIL" not in dev[0].request("REMOVE_CRED 1"):
        raise Exception("Unexpected success on invalid remove cred")

    id = add_cred(dev[0])
    values = [ ("temporary", "1", False),
               ("temporary", "0", False),
               ("pcsc", "1", False),
               ("realm", "example.com", True),
               ("username", "user@example.com", True),
               ("password", "foo", True, "*"),
               ("ca_cert", "ca.pem", True),
               ("client_cert", "user.pem", True),
               ("private_key", "key.pem", True),
               ("private_key_passwd", "foo", True, "*"),
               ("imsi", "310026-000000000", True),
               ("milenage", "foo", True, "*"),
               ("domain_suffix_match", "example.com", True),
               ("domain", "example.com", True),
               ("domain", "example.org", True, "example.com\nexample.org"),
               ("roaming_consortium", "0123456789", False),
               ("required_roaming_consortium", "456789", False),
               ("eap", "TTLS", False),
               ("phase1", "foo=bar1", True),
               ("phase2", "foo=bar2", True),
               ("excluded_ssid", "test", True),
               ("excluded_ssid", "foo", True, "test\nfoo"),
               ("roaming_partner", "example.com,0,4,*", True),
               ("roaming_partner", "example.org,1,2,US", True,
                "example.com,0,4,*\nexample.org,1,2,US"),
               ("update_identifier", "4", False),
               ("provisioning_sp", "sp.example.com", True),
               ("sp_priority", "7", False),
               ("min_dl_bandwidth_home", "100", False),
               ("min_ul_bandwidth_home", "101", False),
               ("min_dl_bandwidth_roaming", "102", False),
               ("min_ul_bandwidth_roaming", "103", False),
               ("max_bss_load", "57", False),
               ("req_conn_capab", "6:22,80,443", False),
               ("req_conn_capab", "17:500", False, "6:22,80,443\n17:500"),
               ("req_conn_capab", "50", False, "6:22,80,443\n17:500\n50"),
               ("ocsp", "1", False) ]
    for v in values:
        if v[2]:
            set_cred_quoted(dev[0], id, v[0], v[1])
        else:
            set_cred(dev[0], id, v[0], v[1])
        val = dev[0].get_cred(id, v[0])
        if len(v) == 4:
            expect = v[3]
        else:
            expect = v[1]
        if val != expect:
            raise Exception("Unexpected GET_CRED value for {}: {} != {}".format(v[0], val, expect))
    remove_cred(dev[0], id)

def test_wpas_ctrl_pno(dev):
    """wpa_supplicant ctrl_iface pno"""
    if "FAIL" not in dev[0].request("SET pno 1"):
        raise Exception("Unexpected success in enabling PNO without enabled network blocks")
    id = dev[0].add_network()
    dev[0].set_network_quoted(id, "ssid", "test")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].request("ENABLE_NETWORK " + str(id) + " no-connect")
    #mac80211_hwsim does not yet support PNO, so this fails
    if "FAIL" not in dev[0].request("SET pno 1"):
        raise Exception("Unexpected success in enabling PNO")
    if "FAIL" not in dev[0].request("SET pno 1 freq=2000-3000,5180"):
        raise Exception("Unexpected success in enabling PNO")
    if "FAIL" not in dev[0].request("SET pno 1 freq=0-6000"):
        raise Exception("Unexpected success in enabling PNO")
    if "FAIL" in dev[0].request("SET pno 0"):
        raise Exception("Unexpected failure in disabling PNO")

def test_wpas_ctrl_get(dev):
    """wpa_supplicant ctrl_iface get"""
    if "FAIL" in dev[0].request("GET version"):
        raise Exception("Unexpected get failure for version")
    if "FAIL" in dev[0].request("GET wifi_display"):
        raise Exception("Unexpected get failure for wifi_display")
    if "FAIL" not in dev[0].request("GET foo"):
        raise Exception("Unexpected success on get command")

def test_wpas_ctrl_preauth(dev):
    """wpa_supplicant ctrl_iface preauth"""
    if "FAIL" not in dev[0].request("PREAUTH "):
        raise Exception("Unexpected success on invalid PREAUTH")
    if "FAIL" in dev[0].request("PREAUTH 00:11:22:33:44:55"):
        raise Exception("Unexpected failure on PREAUTH")

def test_wpas_ctrl_stkstart(dev):
    """wpa_supplicant ctrl_iface strkstart"""
    if "FAIL" not in dev[0].request("STKSTART "):
        raise Exception("Unexpected success on invalid STKSTART")
    if "FAIL" not in dev[0].request("STKSTART 00:11:22:33:44:55"):
        raise Exception("Unexpected success on STKSTART")

def test_wpas_ctrl_tdls_discover(dev):
    """wpa_supplicant ctrl_iface tdls_discover"""
    if "FAIL" not in dev[0].request("TDLS_DISCOVER "):
        raise Exception("Unexpected success on invalid TDLS_DISCOVER")
    if "FAIL" not in dev[0].request("TDLS_DISCOVER 00:11:22:33:44:55"):
        raise Exception("Unexpected success on TDLS_DISCOVER")

def test_wpas_ctrl_addr(dev):
    """wpa_supplicant ctrl_iface invalid address"""
    if "FAIL" not in dev[0].request("TDLS_SETUP "):
        raise Exception("Unexpected success on invalid TDLS_SETUP")
    if "FAIL" not in dev[0].request("TDLS_TEARDOWN "):
        raise Exception("Unexpected success on invalid TDLS_TEARDOWN")
    if "FAIL" not in dev[0].request("FT_DS "):
        raise Exception("Unexpected success on invalid FT_DS")
    if "FAIL" not in dev[0].request("WPS_PBC 00:11:22:33:44"):
        raise Exception("Unexpected success on invalid WPS_PBC")
    if "FAIL" not in dev[0].request("WPS_PIN 00:11:22:33:44"):
        raise Exception("Unexpected success on invalid WPS_PIN")
    if "FAIL" not in dev[0].request("WPS_NFC 00:11:22:33:44"):
        raise Exception("Unexpected success on invalid WPS_NFC")
    if "FAIL" not in dev[0].request("WPS_REG 12345670 00:11:22:33:44"):
        raise Exception("Unexpected success on invalid WPS_REG")
    if "FAIL" not in dev[0].request("IBSS_RSN 00:11:22:33:44"):
        raise Exception("Unexpected success on invalid IBSS_RSN")

def test_wpas_ctrl_config_parser(dev):
    """wpa_supplicant ctrl_iface SET config parser"""
    if "FAIL" not in dev[0].request("SET pbc_in_m1 qwerty"):
        raise Exception("Non-number accepted as integer")
    if "FAIL" not in dev[0].request("SET eapol_version 0"):
        raise Exception("Out-of-range value accepted")
    if "FAIL" not in dev[0].request("SET eapol_version 10"):
        raise Exception("Out-of-range value accepted")

    if "FAIL" not in dev[0].request("SET serial_number 0123456789abcdef0123456789abcdef0"):
        raise Exception("Too long string accepted")

def test_wpas_ctrl_mib(dev):
    """wpa_supplicant ctrl_iface MIB"""
    mib = dev[0].get_mib()
    if "dot11RSNAOptionImplemented" not in mib:
        raise Exception("Missing MIB entry")
    if mib["dot11RSNAOptionImplemented"] != "TRUE":
        raise Exception("Unexpected dot11RSNAOptionImplemented value")

def test_wpas_ctrl_set_wps_params(dev):
    """wpa_supplicant ctrl_iface SET config_methods"""
    ts = [ "config_methods label virtual_display virtual_push_button keypad",
           "device_type 1-0050F204-1",
           "os_version 01020300",
           "uuid 12345678-9abc-def0-1234-56789abcdef0" ]
    for t in ts:
        if "OK" not in dev[2].request("SET " + t):
            raise Exception("SET failed for: " + t)

def test_wpas_ctrl_level(dev):
    """wpa_supplicant ctrl_iface LEVEL"""
    try:
        if "FAIL" not in dev[2].request("LEVEL 3"):
            raise Exception("Unexpected LEVEL success")
        if "OK" not in dev[2].mon.request("LEVEL 2"):
            raise Exception("Unexpected LEVEL failure")
        dev[2].request("SCAN freq=2412")
        ev = dev[2].wait_event(["State:"], timeout=5)
        if ev is None:
            raise Exception("No debug message received")
        dev[2].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=5)
    finally:
        dev[2].mon.request("LEVEL 3")

def test_wpas_ctrl_bssid_filter(dev, apdev):
    """wpa_supplicant bssid_filter"""
    try:
        if "OK" not in dev[2].request("SET bssid_filter " + apdev[0]['bssid']):
            raise Exception("Failed to set bssid_filter")
        params = { "ssid": "test" }
        hostapd.add_ap(apdev[0]['ifname'], params)
        hostapd.add_ap(apdev[1]['ifname'], params)
        dev[2].scan(freq="2412")
        bss = dev[2].get_bss(apdev[0]['bssid'])
        if len(bss) == 0:
            raise Exception("Missing BSS data")
        bss = dev[2].get_bss(apdev[1]['bssid'])
        if len(bss) != 0:
            raise Exception("Unexpected BSS data")
        dev[2].request("SET bssid_filter ")
        dev[2].scan(freq="2412")
        bss = dev[2].get_bss(apdev[0]['bssid'])
        if len(bss) == 0:
            raise Exception("Missing BSS data")
        bss = dev[2].get_bss(apdev[1]['bssid'])
        if len(bss) == 0:
            raise Exception("Missing BSS data(2)")

        if "FAIL" not in dev[2].request("SET bssid_filter 00:11:22:33:44:55 00:11:22:33:44"):
            raise Exception("Unexpected success for invalid SET bssid_filter")
    finally:
        dev[2].request("SET bssid_filter ")

def test_wpas_ctrl_disallow_aps(dev, apdev):
    """wpa_supplicant ctrl_iface disallow_aps"""
    params = { "ssid": "test" }
    hostapd.add_ap(apdev[0]['ifname'], params)

    if "FAIL" not in dev[0].request("SET disallow_aps bssid "):
        raise Exception("Unexpected success on invalid disallow_aps")
    if "FAIL" not in dev[0].request("SET disallow_aps bssid 00:11:22:33:44"):
        raise Exception("Unexpected success on invalid disallow_aps")
    if "FAIL" not in dev[0].request("SET disallow_aps ssid 0"):
        raise Exception("Unexpected success on invalid disallow_aps")
    if "FAIL" not in dev[0].request("SET disallow_aps ssid 4q"):
        raise Exception("Unexpected success on invalid disallow_aps")
    if "FAIL" not in dev[0].request("SET disallow_aps bssid 00:11:22:33:44:55 ssid 112233 ssid 123"):
        raise Exception("Unexpected success on invalid disallow_aps")
    if "FAIL" not in dev[0].request("SET disallow_aps ssid 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00"):
        raise Exception("Unexpected success on invalid disallow_aps")
    if "FAIL" not in dev[0].request("SET disallow_aps foo 112233445566"):
        raise Exception("Unexpected success on invalid disallow_aps")

    dev[0].connect("test", key_mgmt="NONE", scan_freq="2412")
    hostapd.add_ap(apdev[1]['ifname'], params)
    dev[0].dump_monitor()
    if "OK" not in dev[0].request("SET disallow_aps bssid 00:11:22:33:44:55 bssid 00:22:33:44:55:66"):
        raise Exception("Failed to set disallow_aps")
    if "OK" not in dev[0].request("SET disallow_aps bssid " + apdev[0]['bssid']):
        raise Exception("Failed to set disallow_aps")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=15)
    if ev is None:
        raise Exception("Reassociation timed out")
    if apdev[1]['bssid'] not in ev:
        raise Exception("Unexpected BSSID")

    dev[0].dump_monitor()
    if "OK" not in dev[0].request("SET disallow_aps ssid " + "test".encode("hex")):
        raise Exception("Failed to set disallow_aps")
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception("Disconnection not seen")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected reassociation")

def test_wpas_ctrl_blob(dev):
    """wpa_supplicant ctrl_iface SET blob"""
    if "FAIL" not in dev[0].request("SET blob foo"):
        raise Exception("Unexpected SET success")
    if "FAIL" not in dev[0].request("SET blob foo 0"):
        raise Exception("Unexpected SET success")
    if "FAIL" not in dev[0].request("SET blob foo 0q"):
        raise Exception("Unexpected SET success")
    if "OK" not in dev[0].request("SET blob foo 00"):
        raise Exception("Unexpected SET failure")
    if "OK" not in dev[0].request("SET blob foo 0011"):
        raise Exception("Unexpected SET failure")

def test_wpas_ctrl_set_uapsd(dev):
    """wpa_supplicant ctrl_iface SET uapsd"""
    if "FAIL" not in dev[0].request("SET uapsd foo"):
        raise Exception("Unexpected SET success")
    if "FAIL" not in dev[0].request("SET uapsd 0,0,0"):
        raise Exception("Unexpected SET success")
    if "FAIL" not in dev[0].request("SET uapsd 0,0"):
        raise Exception("Unexpected SET success")
    if "FAIL" not in dev[0].request("SET uapsd 0"):
        raise Exception("Unexpected SET success")
    if "OK" not in dev[0].request("SET uapsd 1,1,1,1;1"):
        raise Exception("Unexpected SET failure")
    if "OK" not in dev[0].request("SET uapsd 0,0,0,0;0"):
        raise Exception("Unexpected SET failure")
    if "OK" not in dev[0].request("SET uapsd disable"):
        raise Exception("Unexpected SET failure")

def test_wpas_ctrl_set(dev):
    """wpa_supplicant ctrl_iface SET"""
    vals = [ "foo",
             "dot11RSNAConfigPMKLifetime 0",
             "dot11RSNAConfigPMKReauthThreshold 101",
             "dot11RSNAConfigSATimeout 0",
             "wps_version_number -1",
             "wps_version_number 256" ]
    for val in vals:
        if "FAIL" not in dev[0].request("SET " + val):
            raise Exception("Unexpected SET success for " + val)

    vals = [ "EAPOL::heldPeriod 60",
             "EAPOL::authPeriod 30",
             "EAPOL::startPeriod 30",
             "EAPOL::maxStart 3",
             "dot11RSNAConfigSATimeout 60",
             "tdls_disabled 1",
             "tdls_disabled 0" ]
    for val in vals:
        if "OK" not in dev[0].request("SET " + val):
            raise Exception("Unexpected SET failure for " + val)

def test_wpas_ctrl_get_capability(dev):
    """wpa_supplicant ctrl_iface GET_CAPABILITY"""
    res = dev[0].get_capability("eap")
    if "TTLS" not in res:
        raise Exception("Unexpected GET_CAPABILITY eap response: " + str(res))

    res = dev[0].get_capability("pairwise")
    if "CCMP" not in res:
        raise Exception("Unexpected GET_CAPABILITY pairwise response: " + str(res))

    res = dev[0].get_capability("group")
    if "CCMP" not in res:
        raise Exception("Unexpected GET_CAPABILITY group response: " + str(res))

    res = dev[0].get_capability("key_mgmt")
    if "WPA-PSK" not in res or "WPA-EAP" not in res:
        raise Exception("Unexpected GET_CAPABILITY key_mgmt response: " + str(res))

    res = dev[0].get_capability("proto")
    if "WPA" not in res or "RSN" not in res:
        raise Exception("Unexpected GET_CAPABILITY proto response: " + str(res))

    res = dev[0].get_capability("auth_alg")
    if "OPEN" not in res or "SHARED" not in res:
        raise Exception("Unexpected GET_CAPABILITY auth_alg response: " + str(res))

    res = dev[0].get_capability("modes")
    if "IBSS" not in res or "AP" not in res:
        raise Exception("Unexpected GET_CAPABILITY modes response: " + str(res))

    res = dev[0].get_capability("channels")
    if "8" not in res or "36" not in res:
        raise Exception("Unexpected GET_CAPABILITY channels response: " + str(res))

    res = dev[0].get_capability("freq")
    if "2457" not in res or "5180" not in res:
        raise Exception("Unexpected GET_CAPABILITY freq response: " + str(res))

    res = dev[0].get_capability("tdls")
    if "EXTERNAL" not in res[0]:
        raise Exception("Unexpected GET_CAPABILITY tdls response: " + str(res))

    if dev[0].get_capability("foo") is not None:
        raise Exception("Unexpected GET_CAPABILITY foo response: " + str(res))

def test_wpas_ctrl_nfc_report_handover(dev):
    """wpa_supplicant ctrl_iface NFC_REPORT_HANDOVER"""
    vals = [ "FOO",
             "ROLE freq=12345",
             "ROLE TYPE",
             "ROLE TYPE REQ",
             "ROLE TYPE REQ SEL",
             "ROLE TYPE 0Q SEL",
             "ROLE TYPE 00 SEL",
             "ROLE TYPE 00 0Q",
             "ROLE TYPE 00 00" ]
    for v in vals:
        if "FAIL" not in dev[0].request("NFC_REPORT_HANDOVER " + v):
            raise Exception("Unexpected NFC_REPORT_HANDOVER success for " + v)

def get_blacklist(dev):
    return dev.request("BLACKLIST").splitlines()

def test_wpas_ctrl_blacklist(dev):
    """wpa_supplicant ctrl_iface BLACKLIST"""
    if "OK" not in dev[0].request("BLACKLIST clear"):
        raise Exception("BLACKLIST clear failed")
    b = get_blacklist(dev[0])
    if len(b) != 0:
        raise Exception("Unexpected blacklist contents: " + str(b))
    if "OK" not in dev[0].request("BLACKLIST 00:11:22:33:44:55"):
        raise Exception("BLACKLIST add failed")
    b = get_blacklist(dev[0])
    if "00:11:22:33:44:55" not in b:
        raise Exception("Unexpected blacklist contents: " + str(b))
    if "OK" not in dev[0].request("BLACKLIST 00:11:22:33:44:56"):
        raise Exception("BLACKLIST add failed")
    b = get_blacklist(dev[0])
    if "00:11:22:33:44:55" not in b or "00:11:22:33:44:56" not in b:
        raise Exception("Unexpected blacklist contents: " + str(b))
    if "OK" not in dev[0].request("BLACKLIST 00:11:22:33:44:56"):
        raise Exception("BLACKLIST add failed")
    b = get_blacklist(dev[0])
    if "00:11:22:33:44:55" not in b or "00:11:22:33:44:56" not in b or len(b) != 2:
        raise Exception("Unexpected blacklist contents: " + str(b))

    if "OK" not in dev[0].request("BLACKLIST clear"):
        raise Exception("BLACKLIST clear failed")
    if dev[0].request("BLACKLIST") != "":
        raise Exception("Unexpected blacklist contents")
