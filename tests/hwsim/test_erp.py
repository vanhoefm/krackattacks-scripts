# EAP Re-authentication Protocol (ERP) tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd
from test_ap_eap import int_eap_server_params

def test_erp_initiate_reauth_start(dev, apdev):
    """Authenticator sending EAP-Initiate/Re-auth-Start, but ERP disabled on peer"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("ERP_FLUSH")
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                   eap="PAX", identity="pax.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")

def test_erp_enabled_on_server(dev, apdev):
    """ERP enabled on internal EAP server, but disabled on peer"""
    params = int_eap_server_params()
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['eap_server_erp'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("ERP_FLUSH")
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                   eap="PAX", identity="pax.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412")

def test_erp(dev, apdev):
    """ERP enabled on server and peer"""
    capab = dev[0].get_capability("erp")
    if not capab or 'ERP' not in capab:
        return "skip"
    params = int_eap_server_params()
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['eap_server_erp'] = '1'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("ERP_FLUSH")
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                   eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   erp="1", scan_freq="2412")
    for i in range(3):
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=15)
        dev[0].request("RECONNECT")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
        if ev is None:
            raise Exception("EAP success timed out")
        if "EAP re-authentication completed successfully" not in ev:
            raise Exception("Did not use ERP")
        dev[0].wait_connected(timeout=15, error="Reconnection timed out")

def test_erp_server_no_match(dev, apdev):
    """ERP enabled on server and peer, but server has no key match"""
    capab = dev[0].get_capability("erp")
    if not capab or 'ERP' not in capab:
        return "skip"
    params = int_eap_server_params()
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['eap_server_erp'] = '1'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("ERP_FLUSH")
    id = dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=15)
    hapd.request("ERP_FLUSH")
    dev[0].request("RECONNECT")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS",
                            "CTRL-EVENT-EAP-FAILURE"], timeout=15)
    if ev is None:
        raise Exception("EAP result timed out")
    if "CTRL-EVENT-EAP-SUCCESS" in ev:
        raise Exception("Unexpected EAP success")
    dev[0].request("DISCONNECT")
    dev[0].select_network(id)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("EAP success timed out")
    if "EAP re-authentication completed successfully" in ev:
        raise Exception("Unexpected use of ERP")
    dev[0].wait_connected(timeout=15, error="Reconnection timed out")

def start_erp_as(apdev):
    params = { "ssid": "as", "beacon_int": "2000",
               "radius_server_clients": "auth_serv/radius_clients.conf",
               "radius_server_auth_port": '18128',
               "eap_server": "1",
               "eap_user_file": "auth_serv/eap_user.conf",
               "ca_cert": "auth_serv/ca.pem",
               "server_cert": "auth_serv/server.pem",
               "private_key": "auth_serv/server.key",
               "eap_sim_db": "unix:/tmp/hlr_auc_gw.sock",
               "dh_file": "auth_serv/dh.conf",
               "pac_opaque_encr_key": "000102030405060708090a0b0c0d0e0f",
               "eap_fast_a_id": "101112131415161718191a1b1c1d1e1f",
               "eap_fast_a_id_info": "test server",
               "eap_server_erp": "1",
               "erp_domain": "example.com" }
    hostapd.add_ap(apdev['ifname'], params)

def test_erp_radius(dev, apdev):
    """ERP enabled on RADIUS server and peer"""
    capab = dev[0].get_capability("erp")
    if not capab or 'ERP' not in capab:
        return "skip"
    start_erp_as(apdev[1])
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['auth_server_port'] = "18128"
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].request("ERP_FLUSH")
    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP",
                   eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   erp="1", scan_freq="2412")
    for i in range(3):
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=15)
        dev[0].request("RECONNECT")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
        if ev is None:
            raise Exception("EAP success timed out")
        if "EAP re-authentication completed successfully" not in ev:
            raise Exception("Did not use ERP")
        dev[0].wait_connected(timeout=15, error="Reconnection timed out")

def erp_test(dev, hapd, **kwargs):
    hapd.dump_monitor()
    dev.dump_monitor()
    dev.request("ERP_FLUSH")
    id = dev.connect("test-wpa2-eap", key_mgmt="WPA-EAP", erp="1",
                     scan_freq="2412", **kwargs)
    dev.request("DISCONNECT")
    dev.wait_disconnected(timeout=15)
    hapd.dump_monitor()
    dev.request("RECONNECT")
    ev = dev.wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("EAP success timed out")
    if "EAP re-authentication completed successfully" not in ev:
        raise Exception("Did not use ERP")
    dev.wait_connected(timeout=15, error="Reconnection timed out")
    ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
    if ev is None:
        raise Exception("No connection event received from hostapd")
    dev.request("DISCONNECT")

def test_erp_radius_eap_methods(dev, apdev):
    """ERP enabled on RADIUS server and peer"""
    capab = dev[0].get_capability("erp")
    if not capab or 'ERP' not in capab:
        return "skip"
    start_erp_as(apdev[1])
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['auth_server_port'] = "18128"
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    erp_test(dev[0], hapd, eap="AKA", identity="0232010000000000@example.com",
             password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")
    erp_test(dev[0], hapd, eap="AKA'", identity="6555444333222111@example.com",
             password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")
    # TODO: EKE getSession
    #erp_test(dev[0], hapd, eap="EKE", identity="erp-eke@example.com",
    #         password="hello")
    erp_test(dev[0], hapd, eap="FAST", identity="erp-fast@example.com",
             password="password", ca_cert="auth_serv/ca.pem", phase2="auth=GTC",
             phase1="fast_provisioning=2", pac_file="blob://fast_pac_auth_erp")
    erp_test(dev[0], hapd, eap="GPSK", identity="erp-gpsk@example.com",
             password="abcdefghijklmnop0123456789abcdef")
    erp_test(dev[0], hapd, eap="PAX", identity="erp-pax@example.com",
             password_hex="0123456789abcdef0123456789abcdef")
    # TODO: PEAP (EMSK)
    #erp_test(dev[0], hapd, eap="PEAP", identity="erp-peap@example.com",
    #         password="password", ca_cert="auth_serv/ca.pem",
    #         phase2="auth=MSCHAPV2")
    erp_test(dev[0], hapd, eap="PSK", identity="erp-psk@example.com",
             password_hex="0123456789abcdef0123456789abcdef")
    erp_test(dev[0], hapd, eap="PWD", identity="erp-pwd@example.com",
             password="secret password")
    erp_test(dev[0], hapd, eap="SAKE", identity="erp-sake@example.com",
             password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    erp_test(dev[0], hapd, eap="SIM", identity="1232010000000000@example.com",
             password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    erp_test(dev[0], hapd, eap="TLS", identity="erp-tls@example.com",
             ca_cert="auth_serv/ca.pem", client_cert="auth_serv/user.pem",
             private_key="auth_serv/user.key")
    erp_test(dev[0], hapd, eap="TTLS", identity="erp-ttls@example.com",
             password="password", ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
