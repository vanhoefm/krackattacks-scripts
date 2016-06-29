# MBO tests
# Copyright (c) 2016, Intel Deutschland GmbH
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import logging
logger = logging.getLogger()

import hostapd
import os
import time

from tshark import run_tshark

def test_mbo_assoc_disallow(dev, apdev, params):
    hapd1 = hostapd.add_ap(apdev[0], { "ssid": "MBO", "mbo": "1" })
    hapd2 = hostapd.add_ap(apdev[1], { "ssid": "MBO", "mbo": "1" })

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

@remote_compatible
def test_mbo_cell_capa_update(dev, apdev):
    """MBO cellular data capability update"""
    ssid = "test-wnm-mbo"
    params = { 'ssid': ssid, 'mbo': '1' }
    hapd = hostapd.add_ap(apdev[0], params)
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
    # Duplicate update for additional code coverage
    if "OK" not in dev[0].request("SET mbo_cell_capa 3"):
        raise Exception("Failed to set STA as cellular data not-capable")

    time.sleep(0.2)
    sta = hapd.get_sta(addr)
    if 'mbo_cell_capa' not in sta:
        raise Exception("mbo_cell_capa missing after update")
    if sta['mbo_cell_capa'] != '3':
        raise Exception("mbo_cell_capa not updated properly")

@remote_compatible
def test_mbo_cell_capa_update_pmf(dev, apdev):
    """MBO cellular data capability update with PMF required"""
    ssid = "test-wnm-mbo"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256";
    params["ieee80211w"] = "2";
    params['mbo'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)
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

@remote_compatible
def test_mbo_non_pref_chan(dev, apdev):
    """MBO non-preferred channel list"""
    ssid = "test-wnm-mbo"
    params = { 'ssid': ssid, 'mbo': '1' }
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']
    if "FAIL" not in dev[0].request("SET non_pref_chan 81:7:200:99"):
        raise Exception("Invalid non_pref_chan value accepted")
    if "FAIL" not in dev[0].request("SET non_pref_chan 81:15:200:3"):
        raise Exception("Invalid non_pref_chan value accepted")
    if "FAIL" not in dev[0].request("SET non_pref_chan 81:7:200:3 81:7:201:3"):
        raise Exception("Invalid non_pref_chan value accepted")
    if "OK" not in dev[0].request("SET non_pref_chan 81:7:200:3"):
        raise Exception("Failed to set non-preferred channel list")
    if "OK" not in dev[0].request("SET non_pref_chan 81:7:200:1:123 81:9:100:2"):
        raise Exception("Failed to set non-preferred channel list")

    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")

    addr = dev[0].own_addr()
    sta = hapd.get_sta(addr)
    logger.debug("STA: " + str(sta))
    if 'non_pref_chan[0]' not in sta:
        raise Exception("Missing non_pref_chan[0] value (assoc)")
    if sta['non_pref_chan[0]'] != '81:200:1:123:7':
        raise Exception("Unexpected non_pref_chan[0] value (assoc)")
    if 'non_pref_chan[1]' not in sta:
        raise Exception("Missing non_pref_chan[1] value (assoc)")
    if sta['non_pref_chan[1]'] != '81:100:2:0:9':
        raise Exception("Unexpected non_pref_chan[1] value (assoc)")
    if 'non_pref_chan[2]' in sta:
        raise Exception("Unexpected non_pref_chan[2] value (assoc)")

    if "OK" not in dev[0].request("SET non_pref_chan 81:9:100:2"):
        raise Exception("Failed to update non-preferred channel list")
    time.sleep(0.1)
    sta = hapd.get_sta(addr)
    logger.debug("STA: " + str(sta))
    if 'non_pref_chan[0]' not in sta:
        raise Exception("Missing non_pref_chan[0] value (update 1)")
    if sta['non_pref_chan[0]'] != '81:100:2:0:9':
        raise Exception("Unexpected non_pref_chan[0] value (update 1)")
    if 'non_pref_chan[1]' in sta:
        raise Exception("Unexpected non_pref_chan[2] value (update 1)")

    if "OK" not in dev[0].request("SET non_pref_chan 81:9:100:2 81:10:100:2 81:8:100:2 81:7:100:1:123 81:5:100:1:124"):
        raise Exception("Failed to update non-preferred channel list")
    time.sleep(0.1)
    sta = hapd.get_sta(addr)
    logger.debug("STA: " + str(sta))
    if 'non_pref_chan[0]' not in sta:
        raise Exception("Missing non_pref_chan[0] value (update 2)")
    if sta['non_pref_chan[0]'] != '81:100:1:123:7':
        raise Exception("Unexpected non_pref_chan[0] value (update 2)")
    if 'non_pref_chan[1]' not in sta:
        raise Exception("Missing non_pref_chan[1] value (update 2)")
    if sta['non_pref_chan[1]'] != '81:100:1:124:5':
        raise Exception("Unexpected non_pref_chan[1] value (update 2)")
    if 'non_pref_chan[2]' not in sta:
        raise Exception("Missing non_pref_chan[2] value (update 2)")
    if sta['non_pref_chan[2]'] != '81:100:2:0:9,10,8':
        raise Exception("Unexpected non_pref_chan[2] value (update 2)")
    if 'non_pref_chan[3]' in sta:
        raise Exception("Unexpected non_pref_chan[3] value (update 2)")

    if "OK" not in dev[0].request("SET non_pref_chan 81:5:90:2 82:14:91:2"):
        raise Exception("Failed to update non-preferred channel list")
    time.sleep(0.1)
    sta = hapd.get_sta(addr)
    logger.debug("STA: " + str(sta))
    if 'non_pref_chan[0]' not in sta:
        raise Exception("Missing non_pref_chan[0] value (update 3)")
    if sta['non_pref_chan[0]'] != '81:90:2:0:5':
        raise Exception("Unexpected non_pref_chan[0] value (update 3)")
    if 'non_pref_chan[1]' not in sta:
        raise Exception("Missing non_pref_chan[1] value (update 3)")
    if sta['non_pref_chan[1]'] != '82:91:2:0:14':
        raise Exception("Unexpected non_pref_chan[1] value (update 3)")
    if 'non_pref_chan[2]' in sta:
        raise Exception("Unexpected non_pref_chan[2] value (update 3)")

    if "OK" not in dev[0].request("SET non_pref_chan "):
        raise Exception("Failed to update non-preferred channel list")
    time.sleep(0.1)
    sta = hapd.get_sta(addr)
    logger.debug("STA: " + str(sta))
    if 'non_pref_chan[0]' in sta:
        raise Exception("Unexpected non_pref_chan[0] value (update 4)")

@remote_compatible
def test_mbo_sta_supp_op_classes(dev, apdev):
    """MBO STA supported operating classes"""
    ssid = "test-wnm-mbo"
    params = { 'ssid': ssid, 'mbo': '1' }
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, key_mgmt="NONE", scan_freq="2412")

    addr = dev[0].own_addr()
    sta = hapd.get_sta(addr)
    logger.debug("STA: " + str(sta))
    if 'supp_op_classes' not in sta:
        raise Exception("No supp_op_classes")
    supp = bytearray(sta['supp_op_classes'].decode("hex"))
    if supp[0] != 81:
        raise Exception("Unexpected current operating class %d" % supp[0])
    if 115 not in supp:
        raise Exception("Operating class 115 missing")
