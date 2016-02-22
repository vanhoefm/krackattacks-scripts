# MBO tests
# Copyright (c) 2016, Intel Deutschland GmbH
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd
import os
import time

from tshark import run_tshark

def test_mbo_assoc_disallow(dev, apdev, params):
    hapd1 = hostapd.add_ap(apdev[0]['ifname'], { "ssid": "MBO", "mbo": "1" })
    hapd2 = hostapd.add_ap(apdev[1]['ifname'], { "ssid": "MBO", "mbo": "1" })

    logger.debug("Set mbo_assoc_disallow with invalid value")
    if "FAIL" not in hapd1.request("SET mbo_assoc_disallow 2"):
	raise Exception("Set mbo_assoc_disallow for AP1 succeeded unexpectedly with value 2")

    logger.debug("Disallow associations to AP1 and allow association to AP2")
    if "OK" not in hapd1.request("SET mbo_assoc_disallow 1"):
	raise Exception("Failed to set mbo_assoc_disallow for AP1")
    if "OK" not in hapd2.request("SET mbo_assoc_disallow 0"):
	raise Exception("Failed to set mbo_assoc_disallow for AP2")

    dev[0].connect("MBO", key_mgmt="NONE", scan_freq="2412")

    out = run_tshark(os.path.join(params['logdir'], "hwsim0.pcapng"),
		     "wlan.fc.type == 0 && wlan.fc.type_subtype == 0x00",
                     wait=False)
    if "Destination address: " + hapd1.own_addr() in out:
	raise Exception("Association request sent to disallowed AP")

    timestamp = run_tshark(os.path.join(params['logdir'], "hwsim0.pcapng"),
                           "wlan.fc.type_subtype == 0x00",
                           display=['frame.time'], wait=False)

    logger.debug("Allow associations to AP1 and disallow assications to AP2")
    if "OK" not in hapd1.request("SET mbo_assoc_disallow 0"):
	raise Exception("Failed to set mbo_assoc_disallow for AP1")
    if "OK" not in hapd2.request("SET mbo_assoc_disallow 1"):
	raise Exception("Failed to set mbo_assoc_disallow for AP2")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    # Force new scan, so the assoc_disallowed indication is updated */
    dev[0].request("FLUSH")

    dev[0].connect("MBO", key_mgmt="NONE", scan_freq="2412")

    filter = 'wlan.fc.type == 0 && wlan.fc.type_subtype == 0x00 && frame.time > "' + timestamp.rstrip() + '"'
    out = run_tshark(os.path.join(params['logdir'], "hwsim0.pcapng"),
                     filter, wait=False)
    if "Destination address: " + hapd2.own_addr() in out:
	raise Exception("Association request sent to disallowed AP 2")

def test_mbo_cell_capa_update(dev, apdev):
    """MBO cellular data capability update"""
    ssid = "test-wnm-mbo"
    params = { 'ssid': ssid, 'mbo': '1' }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    if "OK" not in dev[0].request("SET mbo_cell_capa 1"):
	raise Exception("Failed to set STA as cellular data capable")

    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")

    addr = dev[0].own_addr()
    sta = hapd.get_sta(addr)
    if 'mbo_cell_capa' not in sta or sta['mbo_cell_capa'] != '1':
        raise Exception("mbo_cell_capa missing after association")

    if "OK" not in dev[0].request("SET mbo_cell_capa 3"):
	raise Exception("Failed to set STA as cellular data not-capable")

    time.sleep(0.2)
    sta = hapd.get_sta(addr)
    if 'mbo_cell_capa' not in sta:
        raise Exception("mbo_cell_capa missing after update")
    if sta['mbo_cell_capa'] != '3':
        raise Exception("mbo_cell_capa not updated properly")

def test_mbo_cell_capa_update_pmf(dev, apdev):
    """MBO cellular data capability update with PMF required"""
    ssid = "test-wnm-mbo"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256";
    params["ieee80211w"] = "2";
    params['mbo'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    bssid = apdev[0]['bssid']
    if "OK" not in dev[0].request("SET mbo_cell_capa 1"):
	raise Exception("Failed to set STA as cellular data capable")

    dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK-SHA256",
                   proto="WPA2", ieee80211w="2", scan_freq="2412")

    addr = dev[0].own_addr()
    sta = hapd.get_sta(addr)
    if 'mbo_cell_capa' not in sta or sta['mbo_cell_capa'] != '1':
        raise Exception("mbo_cell_capa missing after association")

    if "OK" not in dev[0].request("SET mbo_cell_capa 3"):
	raise Exception("Failed to set STA as cellular data not-capable")

    time.sleep(0.2)
    sta = hapd.get_sta(addr)
    if 'mbo_cell_capa' not in sta:
        raise Exception("mbo_cell_capa missing after update")
    if sta['mbo_cell_capa'] != '3':
        raise Exception("mbo_cell_capa not updated properly")
