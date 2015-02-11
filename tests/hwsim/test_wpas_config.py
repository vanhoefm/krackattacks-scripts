# wpa_supplicant config file
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os

from wpasupplicant import WpaSupplicant

def check_config(config):
    with open(config, "r") as f:
        data = f.read()
    if "update_config=1\n" not in data:
        raise Exception("Missing update_config")
    if "device_name=name\n" not in data:
        raise Exception("Missing device_name")
    if "eapol_version=2\n" not in data:
        raise Exception("Missing eapol_version")
    if "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=" not in data:
        raise Exception("Missing ctrl_interface")
    if "blob-base64-foo={" not in data:
        raise Exception("Missing blob")
    if "cred={" not in data:
        raise Exception("Missing cred")
    if "network={" not in data:
        raise Exception("Missing network")
    return data

def test_wpas_config_file(dev):
    """wpa_supplicant config file parsing/writing"""
    config = "/tmp/test_wpas_config_file.conf"
    if os.path.exists(config):
        os.remove(config)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    try:
        wpas.interface_add("wlan5", config=config)
        initialized = True
    except:
        initialized = False
    if initialized:
        raise Exception("Missing config file did not result in an error")

    try:
        with open(config, "w") as f:
            f.write("update_config=1 \t\r\n")
            f.write("# foo\n")
            f.write("\n")
            f.write(" \t\reapol_version=2")
            for i in range(0, 100):
                f.write("                    ")
            f.write("foo\n")
            f.write("device_name=name#foo\n")

        wpas.interface_add("wlan5", config=config)

        id = wpas.add_network()
        wpas.set_network_quoted(id, "ssid", "foo")
        wpas.set_network_quoted(id, "psk", "12345678")
        wpas.set_network(id, "bssid", "00:11:22:33:44:55")
        wpas.set_network(id, "proto", "RSN")
        wpas.set_network(id, "key_mgmt", "WPA-PSK-SHA256")
        wpas.set_network(id, "pairwise", "CCMP")
        wpas.set_network(id, "group", "CCMP")
        wpas.set_network(id, "auth_alg", "OPEN")

        id = wpas.add_cred()
        wpas.set_cred(id, "priority", "3")
        wpas.set_cred(id, "sp_priority", "6")
        wpas.set_cred(id, "update_identifier", "4")
        wpas.set_cred(id, "ocsp", "1")
        wpas.set_cred(id, "eap", "TTLS")
        wpas.set_cred(id, "req_conn_capab", "6:1234")
        wpas.set_cred_quoted(id, "realm", "example.com")
        wpas.set_cred_quoted(id, "provisioning_sp", "example.com")
        wpas.set_cred_quoted(id, "domain", "example.com")
        wpas.set_cred_quoted(id, "domain_suffix_match", "example.com")
        wpas.set_cred(id, "roaming_consortium", "112233")
        wpas.set_cred(id, "required_roaming_consortium", "112233")
        wpas.set_cred_quoted(id, "roaming_partner",
                             "roaming.example.net,1,127,*")
        wpas.set_cred_quoted(id, "ca_cert", "/tmp/ca.pem")
        wpas.set_cred_quoted(id, "username", "user")
        wpas.set_cred_quoted(id, "password", "secret")
        ev = wpas.wait_event(["CRED-MODIFIED 0 password"])

        wpas.request("SET blob foo 12345678")

        if "OK" not in wpas.request("SAVE_CONFIG"):
            raise Exception("Failed to save configuration file")
        if "OK" not in wpas.global_request("SAVE_CONFIG"):
            raise Exception("Failed to save configuration file")

        wpas.interface_remove("wlan5")
        data1 = check_config(config)

        wpas.interface_add("wlan5", config=config)
        if len(wpas.list_networks()) != 1:
            raise Exception("Unexpected number of networks")
        if len(wpas.request("LIST_CREDS").splitlines()) != 2:
            raise Exception("Unexpected number of credentials")

        if "OK" not in wpas.request("SAVE_CONFIG"):
            raise Exception("Failed to save configuration file")
        data2 = check_config(config)

        if data1 != data2:
            logger.debug(data1)
            logger.debug(data2)
            raise Exception("Unexpected configuration change")

        wpas.request("SET update_config 0")
        if "OK" in wpas.request("SAVE_CONFIG"):
            raise Exception("SAVE_CONFIG succeeded unexpectedly")
        if "OK" in wpas.global_request("SAVE_CONFIG"):
            raise Exception("SAVE_CONFIG (global) succeeded unexpectedly")

        # replace the config file with a directory to break writing/renaming
        os.remove(config)
        os.mkdir(config)
        wpas.request("SET update_config 1")
        if "OK" in wpas.request("SAVE_CONFIG"):
            raise Exception("SAVE_CONFIG succeeded unexpectedly")
        if "OK" in wpas.global_request("SAVE_CONFIG"):
            raise Exception("SAVE_CONFIG (global) succeeded unexpectedly")

    finally:
        try:
            os.remove(config)
        except:
            pass
        try:
            os.remove(config + ".tmp")
        except:
            pass
        try:
            os.rmdir(config)
        except:
            pass
