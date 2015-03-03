# hostapd control interface
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

def test_hapd_ctrl_status(dev, apdev):
    """hostapd ctrl_iface STATUS commands"""
    ssid = "hapd-ctrl"
    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    status = hapd.get_status()
    driver = hapd.get_driver_status()

    if status['bss[0]'] != apdev[0]['ifname']:
        raise Exception("Unexpected bss[0]")
    if status['ssid[0]'] != ssid:
        raise Exception("Unexpected ssid[0]")
    if status['bssid[0]'] != bssid:
        raise Exception("Unexpected bssid[0]")
    if status['freq'] != "2412":
        raise Exception("Unexpected freq")

    if driver['beacon_set'] != "1":
        raise Exception("Unexpected beacon_set")
    if driver['addr'] != bssid:
        raise Exception("Unexpected addr")

def test_hapd_ctrl_p2p_manager(dev, apdev):
    """hostapd as P2P Device manager"""
    ssid = "hapd-p2p-mgr"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params['manage_p2p'] = '1'
    params['allow_cross_connection'] = '0'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    addr = dev[0].own_addr()
    if "OK" not in hapd.request("DEAUTHENTICATE " + addr + " p2p=2"):
        raise Exception("DEAUTHENTICATE command failed")
    dev[0].wait_disconnected(timeout=5)
    dev[0].wait_connected(timeout=10, error="Re-connection timed out")

    if "OK" not in hapd.request("DISASSOCIATE " + addr + " p2p=2"):
        raise Exception("DISASSOCIATE command failed")
    dev[0].wait_disconnected(timeout=5)
    dev[0].wait_connected(timeout=10, error="Re-connection timed out")

def test_hapd_ctrl_sta(dev, apdev):
    """hostapd and STA ctrl_iface commands"""
    ssid = "hapd-ctrl-sta"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    addr = dev[0].own_addr()
    if "FAIL" in hapd.request("STA " + addr):
        raise Exception("Unexpected STA failure")
    if "FAIL" not in hapd.request("STA " + addr + " eapol"):
        raise Exception("Unexpected STA-eapol success")
    if "FAIL" not in hapd.request("STA 00:11:22:33:44"):
        raise Exception("Unexpected STA success")
    if "FAIL" not in hapd.request("STA 00:11:22:33:44:55"):
        raise Exception("Unexpected STA success")

    if len(hapd.request("STA-NEXT " + addr).splitlines()) > 0:
        raise Exception("Unexpected STA-NEXT result")
    if "FAIL" not in hapd.request("STA-NEXT 00:11:22:33:44"):
        raise Exception("Unexpected STA-NEXT success")

def test_hapd_ctrl_disconnect(dev, apdev):
    """hostapd and disconnection ctrl_iface commands"""
    ssid = "hapd-ctrl"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, psk=passphrase, scan_freq="2412")
    addr = dev[0].p2p_dev_addr()

    if "FAIL" not in hapd.request("DEAUTHENTICATE 00:11:22:33:44"):
        raise Exception("Unexpected DEAUTHENTICATE success")

    if "OK" not in hapd.request("DEAUTHENTICATE ff:ff:ff:ff:ff:ff"):
        raise Exception("Unexpected DEAUTHENTICATE failure")
    dev[0].wait_disconnected(timeout=5)
    dev[0].wait_connected(timeout=10, error="Re-connection timed out")

    if "FAIL" not in hapd.request("DISASSOCIATE 00:11:22:33:44"):
        raise Exception("Unexpected DISASSOCIATE success")

    if "OK" not in hapd.request("DISASSOCIATE ff:ff:ff:ff:ff:ff"):
        raise Exception("Unexpected DISASSOCIATE failure")
    dev[0].wait_disconnected(timeout=5)
    dev[0].wait_connected(timeout=10, error="Re-connection timed out")

def test_hapd_ctrl_chan_switch(dev, apdev):
    """hostapd and CHAN_SWITCH ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("CHAN_SWITCH "):
        raise Exception("Unexpected CHAN_SWITCH success")
    if "FAIL" not in hapd.request("CHAN_SWITCH qwerty 2422"):
        raise Exception("Unexpected CHAN_SWITCH success")
    if "FAIL" not in hapd.request("CHAN_SWITCH 5 qwerty"):
        raise Exception("Unexpected CHAN_SWITCH success")
    if "FAIL" not in hapd.request("CHAN_SWITCH 0 2432 center_freq1=123 center_freq2=234 bandwidth=1000 sec_channel_offset=20 ht vht"):
        raise Exception("Unexpected CHAN_SWITCH success")

def test_hapd_ctrl_level(dev, apdev):
    """hostapd and LEVEL ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("LEVEL 0"):
        raise Exception("Unexpected LEVEL success on non-monitor interface")

def test_hapd_ctrl_new_sta(dev, apdev):
    """hostapd and NEW_STA ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("NEW_STA 00:11:22:33:44"):
        raise Exception("Unexpected NEW_STA success")
    if "OK" not in hapd.request("NEW_STA 00:11:22:33:44:55"):
        raise Exception("Unexpected NEW_STA failure")
    if "AUTHORIZED" not in hapd.request("STA 00:11:22:33:44:55"):
        raise Exception("Unexpected NEW_STA STA status")

def test_hapd_ctrl_get(dev, apdev):
    """hostapd and GET ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("GET foo"):
        raise Exception("Unexpected GET success")
    if "FAIL" in hapd.request("GET version"):
        raise Exception("Unexpected GET version failure")

def test_hapd_ctrl_unknown(dev, apdev):
    """hostapd and unknown ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "UNKNOWN COMMAND" not in hapd.request("FOO"):
        raise Exception("Unexpected response")

def test_hapd_ctrl_hs20_wnm_notif(dev, apdev):
    """hostapd and HS20_WNM_NOTIF ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("HS20_WNM_NOTIF 00:11:22:33:44 http://example.com/"):
        raise Exception("Unexpected HS20_WNM_NOTIF success")
    if "FAIL" not in hapd.request("HS20_WNM_NOTIF 00:11:22:33:44:55http://example.com/"):
        raise Exception("Unexpected HS20_WNM_NOTIF success")

def test_hapd_ctrl_hs20_deauth_req(dev, apdev):
    """hostapd and HS20_DEAUTH_REQ ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("HS20_DEAUTH_REQ 00:11:22:33:44 1 120 http://example.com/"):
        raise Exception("Unexpected HS20_DEAUTH_REQ success")
    if "FAIL" not in hapd.request("HS20_DEAUTH_REQ 00:11:22:33:44:55"):
        raise Exception("Unexpected HS20_DEAUTH_REQ success")
    if "FAIL" not in hapd.request("HS20_DEAUTH_REQ 00:11:22:33:44:55 1"):
        raise Exception("Unexpected HS20_DEAUTH_REQ success")

def test_hapd_ctrl_disassoc_imminent(dev, apdev):
    """hostapd and DISASSOC_IMMINENT ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("DISASSOC_IMMINENT 00:11:22:33:44"):
        raise Exception("Unexpected DISASSOC_IMMINENT success")
    if "FAIL" not in hapd.request("DISASSOC_IMMINENT 00:11:22:33:44:55"):
        raise Exception("Unexpected DISASSOC_IMMINENT success")
    if "FAIL" not in hapd.request("DISASSOC_IMMINENT 00:11:22:33:44:55 2"):
        raise Exception("Unexpected DISASSOC_IMMINENT success")
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].p2p_interface_addr()
    if "OK" not in hapd.request("DISASSOC_IMMINENT " + addr + " 2"):
        raise Exception("Unexpected DISASSOC_IMMINENT failure")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 15)
    if ev is None:
        raise Exception("Scan timed out")

def test_hapd_ctrl_ess_disassoc(dev, apdev):
    """hostapd and ESS_DISASSOC ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    if "FAIL" not in hapd.request("ESS_DISASSOC 00:11:22:33:44"):
        raise Exception("Unexpected ESS_DISASSOCT success")
    if "FAIL" not in hapd.request("ESS_DISASSOC 00:11:22:33:44:55"):
        raise Exception("Unexpected ESS_DISASSOC success")
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    addr = dev[0].p2p_interface_addr()
    if "FAIL" not in hapd.request("ESS_DISASSOC " + addr):
        raise Exception("Unexpected ESS_DISASSOC success")
    if "FAIL" not in hapd.request("ESS_DISASSOC " + addr + " -1"):
        raise Exception("Unexpected ESS_DISASSOC success")
    if "FAIL" not in hapd.request("ESS_DISASSOC " + addr + " 1"):
        raise Exception("Unexpected ESS_DISASSOC success")
    if "OK" not in hapd.request("ESS_DISASSOC " + addr + " 20 http://example.com/"):
        raise Exception("Unexpected ESS_DISASSOC failure")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 15)
    if ev is None:
        raise Exception("Scan timed out")

def test_hapd_ctrl_set_deny_mac_file(dev, apdev):
    """hostapd and SET deny_mac_file ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    dev[1].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    if "OK" not in hapd.request("SET deny_mac_file hostapd.macaddr"):
        raise Exception("Unexpected SET failure")
    dev[0].wait_disconnected(timeout=15)
    ev = dev[1].wait_event(["CTRL-EVENT-DISCONNECTED"], 1)
    if ev is not None:
        raise Exception("Unexpected disconnection")

def test_hapd_ctrl_set_accept_mac_file(dev, apdev):
    """hostapd and SET accept_mac_file ctrl_iface command"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    dev[1].connect(ssid, key_mgmt="NONE", scan_freq="2412")
    hapd.request("SET macaddr_acl 1")
    if "OK" not in hapd.request("SET accept_mac_file hostapd.macaddr"):
        raise Exception("Unexpected SET failure")
    dev[1].wait_disconnected(timeout=15)
    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], 1)
    if ev is not None:
        raise Exception("Unexpected disconnection")

def test_hapd_ctrl_set_error_cases(dev, apdev):
    """hostapd and SET error cases"""
    ssid = "hapd-ctrl"
    params = { "ssid": ssid }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    errors = [ "wpa_key_mgmt FOO",
               "wpa_key_mgmt WPA-PSK   \t  FOO",
               "wpa_key_mgmt    \t  ",
               "wpa_pairwise FOO",
               "wpa_pairwise   \t   ",
               'wep_key0 "',
               'wep_key0 "abcde',
               "wep_key0 1",
               "wep_key0 12q3456789",
               "wep_key_len_broadcast 20",
               "wep_rekey_period -1",
               "wep_default_key 4",
               "r0kh 02:00:00:00:03:0q nas1.w1.fi 100102030405060708090a0b0c0d0e0f",
               "r0kh 02:00:00:00:03:00 12345678901234567890123456789012345678901234567890.nas1.w1.fi 100102030405060708090a0b0c0d0e0f",
               "r0kh 02:00:00:00:03:00 nas1.w1.fi 100q02030405060708090a0b0c0d0e0f",
               "r1kh 02:00:00:00:04:q0 00:01:02:03:04:06 200102030405060708090a0b0c0d0e0f",
               "r1kh 02:00:00:00:04:00 00:01:02:03:04:q6 200102030405060708090a0b0c0d0e0f",
               "r1kh 02:00:00:00:04:00 00:01:02:03:04:06 2q0102030405060708090a0b0c0d0e0f",
               "roaming_consortium 1",
               "roaming_consortium 12",
               "roaming_consortium 112233445566778899aabbccddeeff00",
               'venue_name P"engExample venue"',
               'venue_name P"engExample venue',
               "venue_name engExample venue",
               "venue_name e:Example venue",
               "venue_name eng1:Example venue",
               "venue_name eng:Example venue 1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
               "anqp_3gpp_cell_net abc",
               "anqp_3gpp_cell_net ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;",
               "anqp_3gpp_cell_net 244",
               "anqp_3gpp_cell_net 24,123",
               "anqp_3gpp_cell_net 244,1",
               "anqp_3gpp_cell_net 244,1234",
               "nai_realm 0",
               "nai_realm 0,1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.nas1.w1.fi",
               "nai_realm 0,example.org,1,2,3,4,5,6,7,8",
               "nai_realm 0,example.org,1[1:1][2:2][3:3][4:4][5:5]",
               "nai_realm 0,example.org,1[1]",
               "nai_realm 0,example.org,1[1:1",
               "nai_realm 0,a.example.org;b.example.org;c.example.org;d.example.org;e.example.org;f.example.org;g.example.org;h.example.org;i.example.org;j.example.org;k.example.org",
               "qos_map_set 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60",
               "qos_map_set 53,2,22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,255,300",
               "qos_map_set 53,2,22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,255,-1",
               "qos_map_set 53,2,22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,255,255,1",
               "qos_map_set 1",
               "qos_map_set 1,2",
               "hs20_conn_capab 1",
               "hs20_conn_capab 6:22",
               "hs20_wan_metrics 0q:8000:1000:80:240:3000",
               "hs20_wan_metrics 01",
               "hs20_wan_metrics 01:8000",
               "hs20_wan_metrics 01:8000:1000",
               "hs20_wan_metrics 01:8000:1000:80",
               "hs20_wan_metrics 01:8000:1000:80:240",
               "hs20_oper_friendly_name eng1:Example",
               "hs20_icon 32",
               "hs20_icon 32:32",
               "hs20_icon 32:32:eng",
               "hs20_icon 32:32:eng:image/png",
               "hs20_icon 32:32:eng:image/png:icon32",
               "hs20_icon 32:32:eng:image/png:123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890:/tmp/icon32.png",
               "hs20_icon 32:32:eng:image/png:name:/tmp/123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.png",
               "osu_ssid ",
               "osu_ssid P",
               'osu_ssid P"abc',
               'osu_ssid "1234567890123456789012345678901234567890"',
               "osu_friendly_name eng:Example",
               "osu_nai anonymous@example.com",
               "osu_method_list 1 0",
               "osu_icon foo",
               "osu_service_desc eng:Example services",
               "ssid 1234567890123456789012345678901234567890",
               "pac_opaque_encr_key 123456",
               "eap_fast_a_id 12345",
               "eap_fast_a_id 12345q",
               "own_ip_addr foo",
               "auth_server_addr foo2",
               "auth_server_shared_secret ",
               "acct_server_addr foo3",
               "acct_server_shared_secret ",
               "radius_auth_req_attr 123::",
               "radius_acct_req_attr 123::",
               "radius_das_client 192.168.1.123",
               "radius_das_client 192.168.1.1a foo",
               "auth_algs 0",
               "max_num_sta -1",
               "max_num_sta 1000000",
               "wpa_passphrase 1234567",
               "wpa_passphrase 1234567890123456789012345678901234567890123456789012345678901234",
               "wpa_psk 1234567890123456789012345678901234567890123456789012345678901234a",
               "wpa_psk 12345678901234567890123456789012345678901234567890123456789012",
               "wpa_psk_radius 123",
               "wpa_pairwise NONE",
               "wpa_pairwise WEP40",
               "wpa_pairwise WEP104",
               "rsn_pairwise NONE",
               "rsn_pairwise WEP40",
               "rsn_pairwise WEP104",
               "mobility_domain 01",
               "r1_key_holder 0011223344",
               "ctrl_interface_group nosuchgrouphere",
               "hw_mode foo",
               "wps_rf_bands foo",
               "beacon_int 0",
               "beacon_int 65536",
               "acs_num_scans 0",
               "acs_num_scans 101",
               "rts_threshold -1",
               "rts_threshold 2348",
               "fragm_threshold -1",
               "fragm_threshold 2347",
               "send_probe_response -1",
               "send_probe_response 2",
               "vlan_naming -1",
               "vlan_naming 10000000",
               "group_mgmt_cipher FOO",
               "assoc_sa_query_max_timeout 0",
               "assoc_sa_query_retry_timeout 0",
               "wps_state -1",
               "wps_state 3",
               "uuid FOO",
               "device_name 1234567890123456789012345678901234567890",
               "manufacturer 1234567890123456789012345678901234567890123456789012345678901234567890",
               "model_name 1234567890123456789012345678901234567890",
               "model_number 1234567890123456789012345678901234567890",
               "serial_number 1234567890123456789012345678901234567890",
               "device_type FOO",
               "os_version 1",
               "ap_settings /tmp/does/not/exist/ap-settings.foo",
               "wps_nfc_dev_pw_id 4",
               "wps_nfc_dev_pw_id 100000",
               "time_zone A",
               "access_network_type -1",
               "access_network_type 16",
               "hessid 00:11:22:33:44",
               "network_auth_type 0q",
               "ipaddr_type_availability 1q",
               "hs20_operating_class 0",
               "hs20_operating_class 0q",
               "bss_load_test ",
               "bss_load_test 12",
               "bss_load_test 12:80",
               "vendor_elements 0",
               "vendor_elements 0q",
               "local_pwr_constraint -1",
               "local_pwr_constraint 256",
               "wmm_ac_bk_cwmin -1",
               "wmm_ac_be_cwmin 13",
               "wmm_ac_vi_cwmax -1",
               "wmm_ac_vo_cwmax 13",
               "wmm_ac_foo_cwmax 6",
               "wmm_ac_bk_aifs 0",
               "wmm_ac_bk_aifs 256",
               "wmm_ac_bk_txop_limit -1",
               "wmm_ac_bk_txop_limit 65536",
               "wmm_ac_bk_acm -1",
               "wmm_ac_bk_acm 2",
               "wmm_ac_bk_foo 2",
               "tx_queue_foo_aifs 3",
               "tx_queue_data3_cwmin 4",
               "tx_queue_data3_cwmax 4",
               "tx_queue_data3_aifs -4",
               "tx_queue_data3_foo 1" ]
    for e in errors:
        if "FAIL" not in hapd.request("SET " + e):
            raise Exception("Unexpected SET success: '%s'" % e)

    if "OK" not in hapd.request("SET osu_server_uri https://example.com/"):
        raise Exception("Unexpected SET osu_server_uri failure")
    if "OK" not in hapd.request("SET osu_friendly_name eng:Example"):
        raise Exception("Unexpected SET osu_friendly_name failure")

    errors = [ "osu_friendly_name eng1:Example",
               "osu_service_desc eng1:Example services" ]
    for e in errors:
        if "FAIL" not in hapd.request("SET " + e):
            raise Exception("Unexpected SET success: '%s'" % e)

    no_err = [ "wps_nfc_dh_pubkey 0",
               "wps_nfc_dh_privkey 0q",
               "wps_nfc_dev_pw 012",
               "manage_p2p 0",
               "disassoc_low_ack 0",
               "network_auth_type 01",
               "tdls_prohibit 0",
               "tdls_prohibit_chan_switch 0" ]
    for e in no_err:
        if "OK" not in hapd.request("SET " + e):
            raise Exception("Unexpected SET failure: '%s'" % e)
