# Test cases for sigma_dut
# Copyright (c) 2017, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import socket
import subprocess
import time

import hostapd
from utils import HwsimSkip
from hwsim import HWSimRadio

def check_sigma_dut():
    if not os.path.exists("./sigma_dut"):
        raise HwsimSkip("sigma_dut not available")

def sigma_dut_cmd(cmd, port=9000):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                         socket.IPPROTO_TCP)
    sock.settimeout(2)
    addr = ('127.0.0.1', port)
    sock.connect(addr)
    sock.send(cmd + "\r\n")
    try:
        res = sock.recv(1000)
        running = False
        done = False
        for line in res.splitlines():
            if line.startswith("status,RUNNING"):
                running = True
            elif line.startswith("status,INVALID"):
                done = True
            elif line.startswith("status,ERROR"):
                done = True
            elif line.startswith("status,COMPLETE"):
                done = True
        if running and not done:
            # Read the actual response
            res = sock.recv(1000)
    except:
        res = ''
        pass
    sock.close()
    res = res.rstrip()
    logger.debug("sigma_dut: '%s' --> '%s'" % (cmd, res))
    return res

def sigma_dut_cmd_check(cmd):
    res = sigma_dut_cmd(cmd)
    if "COMPLETE" not in res:
        raise Exception("sigma_dut command failed: " + cmd)
    return res

def start_sigma_dut(ifname, debug=False):
    check_sigma_dut()
    cmd = [ './sigma_dut',
            '-M', ifname,
            '-S', ifname,
            '-F', '../../hostapd/hostapd',
            '-G',
            '-j', ifname ]
    if debug:
        cmd += [ '-d' ]
    sigma = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    for i in range(20):
        try:
            res = sigma_dut_cmd("HELLO")
            break
        except:
            time.sleep(0.05)
    return sigma

def stop_sigma_dut(sigma):
    sigma.terminate()
    sigma.wait()
    out, err = sigma.communicate()
    logger.debug("sigma_dut stdout: " + str(out))
    logger.debug("sigma_dut stderr: " + str(err))

def sigma_dut_wait_connected(ifname):
    for i in range(50):
        res = sigma_dut_cmd("sta_is_connected,interface," + ifname)
        if "connected,1" in res:
            break
        time.sleep(0.2)
        if i == 49:
            raise Exception("Connection did not complete")

def test_sigma_dut_basic(dev, apdev):
    """sigma_dut basic functionality"""
    sigma = start_sigma_dut(dev[0].ifname)

    res = sigma_dut_cmd("UNKNOWN")
    if "status,INVALID,errorCode,Unknown command" not in res:
        raise Exception("Unexpected sigma_dut response to unknown command")

    tests = [ ("ca_get_version", "status,COMPLETE,version,1.0"),
              ("device_get_info", "status,COMPLETE,vendor"),
              ("device_list_interfaces,interfaceType,foo", "status,ERROR"),
              ("device_list_interfaces,interfaceType,802.11",
               "status,COMPLETE,interfaceType,802.11,interfaceID," + dev[0].ifname) ]
    for cmd, response in tests:
        res = sigma_dut_cmd(cmd)
        if response not in res:
            raise Exception("Unexpected %s response: %s" % (cmd, res))

    stop_sigma_dut(sigma)

def test_sigma_dut_open(dev, apdev):
    """sigma_dut controlled open network association"""
    try:
        run_sigma_dut_open(dev, apdev)
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def run_sigma_dut_open(dev, apdev):
    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })

    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
    sigma_dut_cmd_check("sta_set_encryption,interface,%s,ssid,%s,encpType,none" % (ifname, "open"))
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s" % (ifname, "open"))
    sigma_dut_wait_connected(ifname)
    sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
    sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    stop_sigma_dut(sigma)

def test_sigma_dut_psk_pmf(dev, apdev):
    """sigma_dut controlled PSK+PMF association"""
    try:
        run_sigma_dut_psk_pmf(dev, apdev)
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def run_sigma_dut_psk_pmf(dev, apdev):
    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    ssid = "test-pmf-required"
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    hapd = hostapd.add_ap(apdev[0], params)

    sigma_dut_cmd_check("sta_reset_default,interface,%s,prog,PMF" % ifname)
    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
    sigma_dut_cmd_check("sta_set_psk,interface,%s,ssid,%s,passphrase,%s,encpType,aes-ccmp,keymgmttype,wpa2,PMF,Required" % (ifname, "test-pmf-required", "12345678"))
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-pmf-required"))
    sigma_dut_wait_connected(ifname)
    sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
    sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    stop_sigma_dut(sigma)

def test_sigma_dut_sae(dev, apdev):
    """sigma_dut controlled SAE association"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")

    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    ssid = "test-sae"
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE'
    hapd = hostapd.add_ap(apdev[0], params)

    sigma_dut_cmd_check("sta_reset_default,interface,%s" % ifname)
    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
    sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,%s,passphrase,%s,type,SAE,encpType,aes-ccmp,keymgmttype,wpa2" % (ifname, "test-sae", "12345678"))
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-sae"))
    sigma_dut_wait_connected(ifname)
    sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
    if dev[0].get_status_field('sae_group') != '19':
            raise Exception("Expected default SAE group not used")
    sigma_dut_cmd_check("sta_disconnect,interface," + ifname)

    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
    sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,%s,passphrase,%s,type,SAE,encpType,aes-ccmp,keymgmttype,wpa2,ECGroupID,20" % (ifname, "test-sae", "12345678"))
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-sae"))
    sigma_dut_wait_connected(ifname)
    sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
    if dev[0].get_status_field('sae_group') != '20':
            raise Exception("Expected SAE group not used")
    sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    stop_sigma_dut(sigma)

def test_sigma_dut_sta_override_rsne(dev, apdev):
    """sigma_dut and RSNE override on STA"""
    try:
        run_sigma_dut_sta_override_rsne(dev, apdev)
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def run_sigma_dut_sta_override_rsne(dev, apdev):
    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    ssid = "test-psk"
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0], params)

    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)

    tests = [ "30120100000fac040100000fac040100000fac02",
              "30140100000fac040100000fac040100000fac02ffff" ]
    for test in tests:
        sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,%s,type,PSK,passphrase,%s,EncpType,aes-ccmp,KeyMgmtType,wpa2" % (ifname, "test-psk", "12345678"))
        sigma_dut_cmd_check("dev_configure_ie,interface,%s,IE_Name,RSNE,Contents,%s" % (ifname, test))
        sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-psk"))
        sigma_dut_wait_connected(ifname)
        sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
        dev[0].dump_monitor()

    sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,%s,type,PSK,passphrase,%s,EncpType,aes-ccmp,KeyMgmtType,wpa2" % (ifname, "test-psk", "12345678"))
    sigma_dut_cmd_check("dev_configure_ie,interface,%s,IE_Name,RSNE,Contents,300101" % ifname)
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-psk"))

    ev = dev[0].wait_event(["CTRL-EVENT-ASSOC-REJECT"])
    if ev is None:
        raise Exception("Association rejection not reported")
    if "status_code=40" not in ev:
        raise Exception("Unexpected status code: " + ev)

    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    stop_sigma_dut(sigma)

def test_sigma_dut_ap_psk(dev, apdev):
    """sigma_dut controlled AP"""
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-psk,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-PSK,PSK,12345678")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].connect("test-psk", psk="12345678", scan_freq="2412")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_override_rsne(dev, apdev):
    """sigma_dut controlled AP overriding RSNE"""
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-psk,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-PSK,PSK,12345678")
            sigma_dut_cmd_check("dev_configure_ie,NAME,AP,interface,%s,IE_Name,RSNE,Contents,30180100000fac040200ffffffff000fac040100000fac020c00" % iface)
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].connect("test-psk", psk="12345678", scan_freq="2412")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_sae(dev, apdev):
    """sigma_dut controlled AP with SAE"""
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-sae,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-SAE,PSK,12345678")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].request("SET sae_groups ")
            dev[0].connect("test-sae", key_mgmt="SAE", psk="12345678",
                           scan_freq="2412")
            if dev[0].get_status_field('sae_group') != '19':
                raise Exception("Expected default SAE group not used")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_sae_group(dev, apdev):
    """sigma_dut controlled AP with SAE and specific group"""
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-sae,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-SAE,PSK,12345678,ECGroupID,20")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].request("SET sae_groups ")
            dev[0].connect("test-sae", key_mgmt="SAE", psk="12345678",
                           scan_freq="2412")
            if dev[0].get_status_field('sae_group') != '20':
                raise Exception("Expected SAE group not used")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_psk_sae(dev, apdev):
    """sigma_dut controlled AP with PSK+SAE"""
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-sae,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-PSK-SAE,PSK,12345678")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].request("SET sae_groups ")
            dev[0].connect("test-sae", key_mgmt="SAE", psk="12345678",
                           scan_freq="2412")
            dev[1].connect("test-sae", psk="12345678", scan_freq="2412")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)
