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
import threading
import time

import hostapd
from utils import HwsimSkip
from hwsim import HWSimRadio
from test_dpp import check_dpp_capab, update_hapd_config
from test_suite_b import check_suite_b_192_capa, suite_b_as_params, suite_b_192_rsa_ap_params

def check_sigma_dut():
    if not os.path.exists("./sigma_dut"):
        raise HwsimSkip("sigma_dut not available")

def sigma_dut_cmd(cmd, port=9000, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                         socket.IPPROTO_TCP)
    sock.settimeout(timeout)
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

def sigma_dut_cmd_check(cmd, port=9000, timeout=2):
    res = sigma_dut_cmd(cmd, port=port, timeout=timeout)
    if "COMPLETE" not in res:
        raise Exception("sigma_dut command failed: " + cmd)
    return res

def start_sigma_dut(ifname, debug=False, hostapd_logdir=None, cert_path=None):
    check_sigma_dut()
    cmd = [ './sigma_dut',
            '-M', ifname,
            '-S', ifname,
            '-F', '../../hostapd/hostapd',
            '-G',
            '-w', '/var/run/wpa_supplicant/',
            '-j', ifname ]
    if debug:
        cmd += [ '-d' ]
    if hostapd_logdir:
        cmd += [ '-H', hostapd_logdir ]
    if cert_path:
        cmd += [ '-C', cert_path ]
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

def test_sigma_dut_psk_pmf_bip_cmac_128(dev, apdev):
    """sigma_dut controlled PSK+PMF association with BIP-CMAC-128"""
    try:
        run_sigma_dut_psk_pmf_cipher(dev, apdev, "BIP-CMAC-128", "AES-128-CMAC")
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def test_sigma_dut_psk_pmf_bip_cmac_256(dev, apdev):
    """sigma_dut controlled PSK+PMF association with BIP-CMAC-256"""
    try:
        run_sigma_dut_psk_pmf_cipher(dev, apdev, "BIP-CMAC-256", "BIP-CMAC-256")
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def test_sigma_dut_psk_pmf_bip_gmac_128(dev, apdev):
    """sigma_dut controlled PSK+PMF association with BIP-GMAC-128"""
    try:
        run_sigma_dut_psk_pmf_cipher(dev, apdev, "BIP-GMAC-128", "BIP-GMAC-128")
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def test_sigma_dut_psk_pmf_bip_gmac_256(dev, apdev):
    """sigma_dut controlled PSK+PMF association with BIP-GMAC-256"""
    try:
        run_sigma_dut_psk_pmf_cipher(dev, apdev, "BIP-GMAC-256", "BIP-GMAC-256")
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def test_sigma_dut_psk_pmf_bip_gmac_256_mismatch(dev, apdev):
    """sigma_dut controlled PSK+PMF association with BIP-GMAC-256 mismatch"""
    try:
        run_sigma_dut_psk_pmf_cipher(dev, apdev, "BIP-GMAC-256", "AES-128-CMAC",
                                     failure=True)
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def run_sigma_dut_psk_pmf_cipher(dev, apdev, sigma_cipher, hostapd_cipher,
                                 failure=False):
    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    ssid = "test-pmf-required"
    params = hostapd.wpa2_params(ssid=ssid, passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    params["group_mgmt_cipher"] = hostapd_cipher
    hapd = hostapd.add_ap(apdev[0], params)

    sigma_dut_cmd_check("sta_reset_default,interface,%s,prog,PMF" % ifname)
    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
    sigma_dut_cmd_check("sta_set_psk,interface,%s,ssid,%s,passphrase,%s,encpType,aes-ccmp,keymgmttype,wpa2,PMF,Required,GroupMgntCipher,%s" % (ifname, "test-pmf-required", "12345678", sigma_cipher))
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-pmf-required"))
    if failure:
        ev = dev[0].wait_event(["CTRL-EVENT-NETWORK-NOT-FOUND",
                                "CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Network selection result not indicated")
        if "CTRL-EVENT-CONNECTED" in ev:
            raise Exception("Unexpected connection")
        res = sigma_dut_cmd("sta_is_connected,interface," + ifname)
        if "connected,1" in res:
            raise Exception("Connection reported")
    else:
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
    params["ieee80211w"] = "2"
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

def test_sigma_dut_sae_password(dev, apdev):
    """sigma_dut controlled SAE association and long password"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")

    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    try:
        ssid = "test-sae"
        params = hostapd.wpa2_params(ssid=ssid)
        params['sae_password'] = 100*'B'
        params['wpa_key_mgmt'] = 'SAE'
        params["ieee80211w"] = "2"
        hapd = hostapd.add_ap(apdev[0], params)

        sigma_dut_cmd_check("sta_reset_default,interface,%s" % ifname)
        sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
        sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,%s,passphrase,%s,type,SAE,encpType,aes-ccmp,keymgmttype,wpa2" % (ifname, "test-sae", 100*'B'))
        sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-sae"))
        sigma_dut_wait_connected(ifname)
        sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
        sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
        sigma_dut_cmd_check("sta_reset_default,interface," + ifname)
    finally:
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

def test_sigma_dut_ap_pskhex(dev, apdev, params):
    """sigma_dut controlled AP and PSKHEX"""
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_pskhex.sigma-hostapd")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-psk,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-PSK,PSKHEX," + psk)
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].connect("test-psk", raw_psk=psk, scan_freq="2412")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_suite_b(dev, apdev, params):
    """sigma_dut controlled STA Suite B"""
    check_suite_b_192_capa(dev)
    logdir = params['logdir']

    with open("auth_serv/ec2-ca.pem", "r") as f:
        with open(os.path.join(logdir, "suite_b_ca.pem"), "w") as f2:
            f2.write(f.read())

    with open("auth_serv/ec2-user.pem", "r") as f:
        with open("auth_serv/ec2-user.key", "r") as f2:
            with open(os.path.join(logdir, "suite_b.pem"), "w") as f3:
                f3.write(f.read())
                f3.write(f2.read())

    dev[0].flush_scan_cache()
    params = suite_b_as_params()
    params['ca_cert'] = 'auth_serv/ec2-ca.pem'
    params['server_cert'] = 'auth_serv/ec2-server.pem'
    params['private_key'] = 'auth_serv/ec2-server.key'
    params['openssl_ciphers'] = 'SUITEB192'
    hostapd.add_ap(apdev[1], params)

    params = { "ssid": "test-suite-b",
               "wpa": "2",
               "wpa_key_mgmt": "WPA-EAP-SUITE-B-192",
               "rsn_pairwise": "GCMP-256",
               "group_mgmt_cipher": "BIP-GMAC-256",
               "ieee80211w": "2",
               "ieee8021x": "1",
               'auth_server_addr': "127.0.0.1",
               'auth_server_port': "18129",
               'auth_server_shared_secret': "radius",
               'nas_identifier': "nas.w1.fi" }
    hapd = hostapd.add_ap(apdev[0], params)

    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname, cert_path=logdir)

    sigma_dut_cmd_check("sta_reset_default,interface,%s,prog,PMF" % ifname)
    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
    sigma_dut_cmd_check("sta_set_security,type,eaptls,interface,%s,ssid,%s,PairwiseCipher,AES-GCMP-256,GroupCipher,AES-GCMP-256,GroupMgntCipher,BIP-GMAC-256,keymgmttype,SuiteB,clientCertificate,suite_b.pem,trustedRootCA,suite_b_ca.pem,CertType,ECC" % (ifname, "test-suite-b"))
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-suite-b"))
    sigma_dut_wait_connected(ifname)
    sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
    sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    stop_sigma_dut(sigma)

def test_sigma_dut_suite_b_rsa(dev, apdev, params):
    """sigma_dut controlled STA Suite B (RSA)"""
    check_suite_b_192_capa(dev)
    logdir = params['logdir']

    with open("auth_serv/rsa3072-ca.pem", "r") as f:
        with open(os.path.join(logdir, "suite_b_ca_rsa.pem"), "w") as f2:
            f2.write(f.read())

    with open("auth_serv/rsa3072-user.pem", "r") as f:
        with open("auth_serv/rsa3072-user.key", "r") as f2:
            with open(os.path.join(logdir, "suite_b_rsa.pem"), "w") as f3:
                f3.write(f.read())
                f3.write(f2.read())

    dev[0].flush_scan_cache()
    params = suite_b_192_rsa_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)

    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname, cert_path=logdir)

    cmd = "sta_set_security,type,eaptls,interface,%s,ssid,%s,PairwiseCipher,AES-GCMP-256,GroupCipher,AES-GCMP-256,GroupMgntCipher,BIP-GMAC-256,keymgmttype,SuiteB,clientCertificate,suite_b_rsa.pem,trustedRootCA,suite_b_ca_rsa.pem,CertType,RSA" % (ifname, "test-suite-b")

    tests = [ "",
              ",TLSCipher,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
              ",TLSCipher,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" ]
    for extra in tests:
        sigma_dut_cmd_check("sta_reset_default,interface,%s,prog,PMF" % ifname)
        sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
        sigma_dut_cmd_check(cmd + extra)
        sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s,channel,1" % (ifname, "test-suite-b"))
        sigma_dut_wait_connected(ifname)
        sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
        sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
        sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    stop_sigma_dut(sigma)

def test_sigma_dut_ap_suite_b(dev, apdev, params):
    """sigma_dut controlled AP Suite B"""
    check_suite_b_192_capa(dev)
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_suite_b.sigma-hostapd")
    params = suite_b_as_params()
    params['ca_cert'] = 'auth_serv/ec2-ca.pem'
    params['server_cert'] = 'auth_serv/ec2-server.pem'
    params['private_key'] = 'auth_serv/ec2-server.key'
    params['openssl_ciphers'] = 'SUITEB192'
    hostapd.add_ap(apdev[1], params)
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-suite-b,MODE,11ng")
            sigma_dut_cmd_check("ap_set_radius,NAME,AP,IPADDR,127.0.0.1,PORT,18129,PASSWORD,radius")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,SuiteB")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                           ieee80211w="2",
                           openssl_ciphers="SUITEB192",
                           eap="TLS", identity="tls user",
                           ca_cert="auth_serv/ec2-ca.pem",
                           client_cert="auth_serv/ec2-user.pem",
                           private_key="auth_serv/ec2-user.key",
                           pairwise="GCMP-256", group="GCMP-256",
                           scan_freq="2412")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_cipher_gcmp_128(dev, apdev, params):
    """sigma_dut controlled AP with GCMP-128/BIP-GMAC-128 cipher"""
    run_sigma_dut_ap_cipher(dev, apdev, params, "AES-GCMP-128", "BIP-GMAC-128",
                            "GCMP")

def test_sigma_dut_ap_cipher_gcmp_256(dev, apdev, params):
    """sigma_dut controlled AP with GCMP-256/BIP-GMAC-256 cipher"""
    run_sigma_dut_ap_cipher(dev, apdev, params, "AES-GCMP-256", "BIP-GMAC-256",
                            "GCMP-256")

def test_sigma_dut_ap_cipher_ccmp_128(dev, apdev, params):
    """sigma_dut controlled AP with CCMP-128/BIP-CMAC-128 cipher"""
    run_sigma_dut_ap_cipher(dev, apdev, params, "AES-CCMP-128", "BIP-CMAC-128",
                            "CCMP")

def test_sigma_dut_ap_cipher_ccmp_256(dev, apdev, params):
    """sigma_dut controlled AP with CCMP-256/BIP-CMAC-256 cipher"""
    run_sigma_dut_ap_cipher(dev, apdev, params, "AES-CCMP-256", "BIP-CMAC-256",
                            "CCMP-256")

def test_sigma_dut_ap_cipher_ccmp_gcmp_1(dev, apdev, params):
    """sigma_dut controlled AP with CCMP-128+GCMP-256 ciphers (1)"""
    run_sigma_dut_ap_cipher(dev, apdev, params, "AES-CCMP-128 AES-GCMP-256",
                            "BIP-GMAC-256", "CCMP")

def test_sigma_dut_ap_cipher_ccmp_gcmp_2(dev, apdev, params):
    """sigma_dut controlled AP with CCMP-128+GCMP-256 ciphers (2)"""
    run_sigma_dut_ap_cipher(dev, apdev, params, "AES-CCMP-128 AES-GCMP-256",
                            "BIP-GMAC-256", "GCMP-256", "CCMP")

def test_sigma_dut_ap_cipher_gcmp_256_group_ccmp(dev, apdev, params):
    """sigma_dut controlled AP with GCMP-256/CCMP/BIP-GMAC-256 cipher"""
    run_sigma_dut_ap_cipher(dev, apdev, params, "AES-GCMP-256", "BIP-GMAC-256",
                            "GCMP-256", "CCMP", "AES-CCMP-128")

def run_sigma_dut_ap_cipher(dev, apdev, params, ap_pairwise, ap_group_mgmt,
                            sta_cipher, sta_cipher_group=None, ap_group=None):
    check_suite_b_192_capa(dev)
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_cipher.sigma-hostapd")
    params = suite_b_as_params()
    params['ca_cert'] = 'auth_serv/ec2-ca.pem'
    params['server_cert'] = 'auth_serv/ec2-server.pem'
    params['private_key'] = 'auth_serv/ec2-server.key'
    params['openssl_ciphers'] = 'SUITEB192'
    hostapd.add_ap(apdev[1], params)
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-suite-b,MODE,11ng")
            sigma_dut_cmd_check("ap_set_radius,NAME,AP,IPADDR,127.0.0.1,PORT,18129,PASSWORD,radius")
            cmd = "ap_set_security,NAME,AP,KEYMGNT,SuiteB,PMF,Required,PairwiseCipher,%s,GroupMgntCipher,%s" % (ap_pairwise, ap_group_mgmt)
            if ap_group:
                cmd += ",GroupCipher,%s" % ap_group
            sigma_dut_cmd_check(cmd)
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            if sta_cipher_group is None:
                sta_cipher_group = sta_cipher
            dev[0].connect("test-suite-b", key_mgmt="WPA-EAP-SUITE-B-192",
                           ieee80211w="2",
                           openssl_ciphers="SUITEB192",
                           eap="TLS", identity="tls user",
                           ca_cert="auth_serv/ec2-ca.pem",
                           client_cert="auth_serv/ec2-user.pem",
                           private_key="auth_serv/ec2-user.key",
                           pairwise=sta_cipher, group=sta_cipher_group,
                           scan_freq="2412")

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

def test_sigma_dut_ap_sae(dev, apdev, params):
    """sigma_dut controlled AP with SAE"""
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_sae.sigma-hostapd")
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-sae,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-SAE,PSK,12345678")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].request("SET sae_groups ")
            dev[0].connect("test-sae", key_mgmt="SAE", psk="12345678",
                           ieee80211w="2", scan_freq="2412")
            if dev[0].get_status_field('sae_group') != '19':
                raise Exception("Expected default SAE group not used")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_sae_password(dev, apdev, params):
    """sigma_dut controlled AP with SAE and long password"""
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_sae_password.sigma-hostapd")
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-sae,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-SAE,PSK," + 100*'C')
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].request("SET sae_groups ")
            dev[0].connect("test-sae", key_mgmt="SAE", sae_password=100*'C',
                           ieee80211w="2", scan_freq="2412")
            if dev[0].get_status_field('sae_group') != '19':
                raise Exception("Expected default SAE group not used")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_sae_group(dev, apdev, params):
    """sigma_dut controlled AP with SAE and specific group"""
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_sae_group.sigma-hostapd")
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-sae,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-SAE,PSK,12345678,ECGroupID,20")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].request("SET sae_groups ")
            dev[0].connect("test-sae", key_mgmt="SAE", psk="12345678",
                           ieee80211w="2", scan_freq="2412")
            if dev[0].get_status_field('sae_group') != '20':
                raise Exception("Expected SAE group not used")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_psk_sae(dev, apdev, params):
    """sigma_dut controlled AP with PSK+SAE"""
    if "SAE" not in dev[0].get_capability("auth_alg"):
        raise HwsimSkip("SAE not supported")
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_psk_sae.sigma-hostapd")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,test-sae,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,WPA2-PSK-SAE,PSK,12345678")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[2].request("SET sae_groups ")
            dev[2].connect("test-sae", key_mgmt="SAE", psk="12345678",
                           scan_freq="2412", ieee80211w="0", wait_connect=False)
            dev[0].request("SET sae_groups ")
            dev[0].connect("test-sae", key_mgmt="SAE", psk="12345678",
                           scan_freq="2412", ieee80211w="2")
            dev[1].connect("test-sae", psk="12345678", scan_freq="2412")

            ev = dev[2].wait_event(["CTRL-EVENT-CONNECTED"], timeout=0.1)
            dev[2].request("DISCONNECT")
            if ev is not None:
                raise Exception("Unexpected connection without PMF")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_owe(dev, apdev):
    """sigma_dut controlled OWE station"""
    try:
        run_sigma_dut_owe(dev, apdev)
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def run_sigma_dut_owe(dev, apdev):
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")

    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    try:
        params = { "ssid": "owe",
                   "wpa": "2",
                   "wpa_key_mgmt": "OWE",
                   "ieee80211w": "2",
                   "rsn_pairwise": "CCMP" }
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = hapd.own_addr()

        sigma_dut_cmd_check("sta_reset_default,interface,%s,prog,WPA3" % ifname)
        sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
        sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,owe,Type,OWE" % ifname)
        sigma_dut_cmd_check("sta_associate,interface,%s,ssid,owe,channel,1" % ifname)
        sigma_dut_wait_connected(ifname)
        sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)

        dev[0].dump_monitor()
        sigma_dut_cmd("sta_reassoc,interface,%s,Channel,1,bssid,%s" % (ifname, bssid))
        dev[0].wait_connected()
        sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
        dev[0].wait_disconnected()
        dev[0].dump_monitor()

        sigma_dut_cmd_check("sta_reset_default,interface,%s,prog,WPA3" % ifname)
        sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
        sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,owe,Type,OWE,ECGroupID,20" % ifname)
        sigma_dut_cmd_check("sta_associate,interface,%s,ssid,owe,channel,1" % ifname)
        sigma_dut_wait_connected(ifname)
        sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
        sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
        dev[0].wait_disconnected()
        dev[0].dump_monitor()

        sigma_dut_cmd_check("sta_reset_default,interface,%s,prog,WPA3" % ifname)
        sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
        sigma_dut_cmd_check("sta_set_security,interface,%s,ssid,owe,Type,OWE,ECGroupID,0" % ifname)
        sigma_dut_cmd_check("sta_associate,interface,%s,ssid,owe,channel,1" % ifname)
        ev = dev[0].wait_event(["CTRL-EVENT-ASSOC-REJECT"], timeout=10)
        sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
        if ev is None:
            raise Exception("Association not rejected")
        if "status_code=77" not in ev:
            raise Exception("Unexpected rejection reason: " + ev)

        sigma_dut_cmd_check("sta_reset_default,interface," + ifname)
    finally:
        stop_sigma_dut(sigma)

def test_sigma_dut_ap_owe(dev, apdev, params):
    """sigma_dut controlled AP with OWE"""
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_owe.sigma-hostapd")
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default,NAME,AP,Program,WPA3")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,owe,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,OWE")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].connect("owe", key_mgmt="OWE", ieee80211w="2",
                           scan_freq="2412")

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_owe_ecgroupid(dev, apdev):
    """sigma_dut controlled AP with OWE and ECGroupID"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface)
        try:
            sigma_dut_cmd_check("ap_reset_default,NAME,AP,Program,WPA3")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,CHANNEL,1,SSID,owe,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,KEYMGNT,OWE,ECGroupID,20 21,PMF,Required")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            dev[0].connect("owe", key_mgmt="OWE", ieee80211w="2",
                           owe_group="20", scan_freq="2412")
            dev[0].request("REMOVE_NETWORK all")
            dev[0].wait_disconnected()

            dev[0].connect("owe", key_mgmt="OWE", ieee80211w="2",
                           owe_group="21", scan_freq="2412")
            dev[0].request("REMOVE_NETWORK all")
            dev[0].wait_disconnected()

            dev[0].connect("owe", key_mgmt="OWE", ieee80211w="2",
                           owe_group="19", scan_freq="2412", wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-ASSOC-REJECT"], timeout=10)
            dev[0].request("DISCONNECT")
            if ev is None:
                raise Exception("Association not rejected")
            if "status_code=77" not in ev:
                raise Exception("Unexpected rejection reason: " + ev)
            dev[0].dump_monitor()

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_owe_transition_mode(dev, apdev, params):
    """sigma_dut controlled AP with OWE and transition mode"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_owe_transition_mode.sigma-hostapd")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default,NAME,AP,Program,WPA3")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,WLAN_TAG,1,CHANNEL,1,SSID,owe,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,WLAN_TAG,1,KEYMGNT,OWE")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,WLAN_TAG,2,CHANNEL,1,SSID,owe,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,WLAN_TAG,2,KEYMGNT,NONE")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            res1 = sigma_dut_cmd_check("ap_get_mac_address,NAME,AP,WLAN_TAG,1,Interface,24G")
            res2 = sigma_dut_cmd_check("ap_get_mac_address,NAME,AP,WLAN_TAG,2,Interface,24G")

            dev[0].connect("owe", key_mgmt="OWE", ieee80211w="2",
                           scan_freq="2412")
            dev[1].connect("owe", key_mgmt="NONE", scan_freq="2412")
            if dev[0].get_status_field('bssid') not in res1:
                raise Exception("Unexpected ap_get_mac_address WLAN_TAG,1: " + res1)
            if dev[1].get_status_field('bssid') not in res2:
                raise Exception("Unexpected ap_get_mac_address WLAN_TAG,2: " + res2)

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_owe_transition_mode_2(dev, apdev, params):
    """sigma_dut controlled AP with OWE and transition mode (2)"""
    if "OWE" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("OWE not supported")
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_owe_transition_mode_2.sigma-hostapd")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default,NAME,AP,Program,WPA3")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,WLAN_TAG,1,CHANNEL,1,SSID,owe,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,WLAN_TAG,1,KEYMGNT,NONE")
            sigma_dut_cmd_check("ap_set_wireless,NAME,AP,WLAN_TAG,2,CHANNEL,1,MODE,11ng")
            sigma_dut_cmd_check("ap_set_security,NAME,AP,WLAN_TAG,2,KEYMGNT,OWE")
            sigma_dut_cmd_check("ap_config_commit,NAME,AP")

            res1 = sigma_dut_cmd_check("ap_get_mac_address,NAME,AP,WLAN_TAG,1,Interface,24G")
            res2 = sigma_dut_cmd_check("ap_get_mac_address,NAME,AP,WLAN_TAG,2,Interface,24G")

            dev[0].connect("owe", key_mgmt="OWE", ieee80211w="2",
                           scan_freq="2412")
            dev[1].connect("owe", key_mgmt="NONE", scan_freq="2412")
            if dev[0].get_status_field('bssid') not in res2:
                raise Exception("Unexpected ap_get_mac_address WLAN_TAG,2: " + res1)
            if dev[1].get_status_field('bssid') not in res1:
                raise Exception("Unexpected ap_get_mac_address WLAN_TAG,1: " + res2)

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            stop_sigma_dut(sigma)

def dpp_init_enrollee(dev, id1):
    logger.info("Starting DPP initiator/enrollee in a thread")
    time.sleep(1)
    cmd = "DPP_AUTH_INIT peer=%d role=enrollee" % id1
    if "OK" not in dev.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev.wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    logger.info("DPP initiator/enrollee done")

def test_sigma_dut_dpp_qr_resp_1(dev, apdev):
    """sigma_dut DPP/QR responder (conf index 1)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 1)

def test_sigma_dut_dpp_qr_resp_2(dev, apdev):
    """sigma_dut DPP/QR responder (conf index 2)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 2)

def test_sigma_dut_dpp_qr_resp_3(dev, apdev):
    """sigma_dut DPP/QR responder (conf index 3)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 3)

def test_sigma_dut_dpp_qr_resp_4(dev, apdev):
    """sigma_dut DPP/QR responder (conf index 4)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 4)

def test_sigma_dut_dpp_qr_resp_5(dev, apdev):
    """sigma_dut DPP/QR responder (conf index 5)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 5)

def test_sigma_dut_dpp_qr_resp_6(dev, apdev):
    """sigma_dut DPP/QR responder (conf index 6)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 6)

def test_sigma_dut_dpp_qr_resp_7(dev, apdev):
    """sigma_dut DPP/QR responder (conf index 7)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 7)

def test_sigma_dut_dpp_qr_resp_chan_list(dev, apdev):
    """sigma_dut DPP/QR responder (channel list override)"""
    run_sigma_dut_dpp_qr_resp(dev, apdev, 1, chan_list='81/2 81/6 81/1',
                              listen_chan=2)

def run_sigma_dut_dpp_qr_resp(dev, apdev, conf_idx, chan_list=None,
                              listen_chan=None):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        cmd = "dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR"
        if chan_list:
            cmd += ",DPPChannelList," + chan_list
        res = sigma_dut_cmd(cmd)
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)
        hex = res.split(',')[3]
        uri = hex.decode('hex')
        logger.info("URI from sigma_dut: " + uri)

        res = dev[1].request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
        id1 = int(res)

        t = threading.Thread(target=dpp_init_enrollee, args=(dev[1], id1))
        t.start()
        cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPConfIndex,%d,DPPAuthDirection,Single,DPPProvisioningRole,Configurator,DPPConfEnrolleeRole,STA,DPPSigningKeyECC,P-256,DPPBS,QR,DPPTimeout,6" % conf_idx
        if listen_chan:
            cmd += ",DPPListenChannel," + str(listen_chan)
        res = sigma_dut_cmd(cmd, timeout=10)
        t.join()
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        stop_sigma_dut(sigma)

def test_sigma_dut_dpp_qr_init_enrollee(dev, apdev):
    """sigma_dut DPP/QR initiator as Enrollee"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "30770201010420768240a3fc89d6662d9782f120527fe7fb9edc6366ab0b9c7dde96125cfd250fa00a06082a8648ce3d030107a144034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    csign_pub = "3059301306072a8648ce3d020106082a8648ce3d030107034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJwYWtZbXVzd1dCdWpSYTl5OEsweDViaTVrT3VNT3dzZHRlaml2UG55ZHZzIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIybU5vNXZuRkI5bEw3d1VWb1hJbGVPYzBNSEE1QXZKbnpwZXZULVVTYzVNIiwieSI6IlhzS3dqVHJlLTg5WWdpU3pKaG9CN1haeUttTU05OTl3V2ZaSVl0bi01Q3MifX0.XhjFpZgcSa7G2lHy0OCYTvaZFRo5Hyx6b7g7oYyusLC7C_73AJ4_BxEZQVYJXAtDuGvb3dXSkHEKxREP9Q6Qeg"
    ap_netaccesskey = "30770201010420ceba752db2ad5200fa7bc565b9c05c69b7eb006751b0b329b0279de1c19ca67ca00a06082a8648ce3d030107a14403420004da6368e6f9c507d94bef0515a1722578e73430703902f267ce97af4fe51273935ec2b08d3adefbcf588224b3261a01ed76722a630cf7df7059f64862d9fee42b"

    params = { "ssid": "DPPNET01",
               "wpa": "2",
               "ieee80211w": "2",
               "wpa_key_mgmt": "DPP",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign_pub,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    sigma = start_sigma_dut(dev[0].ifname)
    try:
        dev[0].set("dpp_config_processing", "2")

        cmd = "DPP_CONFIGURATOR_ADD key=" + csign
        res = dev[1].request(cmd);
        if "FAIL" in res:
            raise Exception("Failed to add configurator")
        conf_id = int(res)

        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        dev[1].set("dpp_configurator_params",
                   " conf=sta-dpp ssid=%s configurator=%d" % ("DPPNET01".encode("hex"), conf_id));
        cmd = "DPP_LISTEN 2437 role=configurator"
        if "OK" not in dev[1].request(cmd):
            raise Exception("Failed to start listen operation")

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,6,DPPWaitForConnect,Yes", timeout=10)
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,OK,NetworkConnectResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        dev[0].set("dpp_config_processing", "0")
        stop_sigma_dut(sigma)

def test_sigma_dut_dpp_qr_mutual_init_enrollee(dev, apdev):
    """sigma_dut DPP/QR (mutual) initiator as Enrollee"""
    run_sigma_dut_dpp_qr_mutual_init_enrollee_check(dev, apdev)

def test_sigma_dut_dpp_qr_mutual_init_enrollee_check(dev, apdev):
    """sigma_dut DPP/QR (mutual) initiator as Enrollee (extra check)"""
    run_sigma_dut_dpp_qr_mutual_init_enrollee_check(dev, apdev,
                                                    extra="DPPAuthDirection,Mutual,")

def run_sigma_dut_dpp_qr_mutual_init_enrollee_check(dev, apdev, extra=''):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "30770201010420768240a3fc89d6662d9782f120527fe7fb9edc6366ab0b9c7dde96125cfd250fa00a06082a8648ce3d030107a144034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    csign_pub = "3059301306072a8648ce3d020106082a8648ce3d030107034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJwYWtZbXVzd1dCdWpSYTl5OEsweDViaTVrT3VNT3dzZHRlaml2UG55ZHZzIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIybU5vNXZuRkI5bEw3d1VWb1hJbGVPYzBNSEE1QXZKbnpwZXZULVVTYzVNIiwieSI6IlhzS3dqVHJlLTg5WWdpU3pKaG9CN1haeUttTU05OTl3V2ZaSVl0bi01Q3MifX0.XhjFpZgcSa7G2lHy0OCYTvaZFRo5Hyx6b7g7oYyusLC7C_73AJ4_BxEZQVYJXAtDuGvb3dXSkHEKxREP9Q6Qeg"
    ap_netaccesskey = "30770201010420ceba752db2ad5200fa7bc565b9c05c69b7eb006751b0b329b0279de1c19ca67ca00a06082a8648ce3d030107a14403420004da6368e6f9c507d94bef0515a1722578e73430703902f267ce97af4fe51273935ec2b08d3adefbcf588224b3261a01ed76722a630cf7df7059f64862d9fee42b"

    params = { "ssid": "DPPNET01",
               "wpa": "2",
               "ieee80211w": "2",
               "wpa_key_mgmt": "DPP",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign_pub,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    sigma = start_sigma_dut(dev[0].ifname)
    try:
        dev[0].set("dpp_config_processing", "2")

        cmd = "DPP_CONFIGURATOR_ADD key=" + csign
        res = dev[1].request(cmd);
        if "FAIL" in res:
            raise Exception("Failed to add configurator")
        conf_id = int(res)

        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        dev[1].set("dpp_configurator_params",
                   " conf=sta-dpp ssid=%s configurator=%d" % ("DPPNET01".encode("hex"), conf_id));
        cmd = "DPP_LISTEN 2437 role=configurator qr=mutual"
        if "OK" not in dev[1].request(cmd):
            raise Exception("Failed to start listen operation")

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR")
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)
        hex = res.split(',')[3]
        uri = hex.decode('hex')
        logger.info("URI from sigma_dut: " + uri)

        res = dev[1].request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
        id1 = int(res)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,%sDPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,6,DPPWaitForConnect,Yes" % extra, timeout=10)
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,OK,NetworkConnectResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        dev[0].set("dpp_config_processing", "0")
        stop_sigma_dut(sigma)

def dpp_init_conf_mutual(dev, id1, conf_id, own_id=None):
    time.sleep(1)
    logger.info("Starting DPP initiator/configurator in a thread")
    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp ssid=%s configurator=%d" % (id1, "DPPNET01".encode("hex"), conf_id)
    if own_id is not None:
        cmd += " own=%d" % own_id
    if "OK" not in dev.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev.wait_event(["DPP-CONF-SENT"], timeout=10)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    logger.info("DPP initiator/configurator done")

def test_sigma_dut_dpp_qr_mutual_resp_enrollee(dev, apdev):
    """sigma_dut DPP/QR (mutual) responder as Enrollee"""
    run_sigma_dut_dpp_qr_mutual_resp_enrollee(dev, apdev)

def test_sigma_dut_dpp_qr_mutual_resp_enrollee_pending(dev, apdev):
    """sigma_dut DPP/QR (mutual) responder as Enrollee (response pending)"""
    run_sigma_dut_dpp_qr_mutual_resp_enrollee(dev, apdev, ',DPPDelayQRResponse,1')

def run_sigma_dut_dpp_qr_mutual_resp_enrollee(dev, apdev, extra=None):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "30770201010420768240a3fc89d6662d9782f120527fe7fb9edc6366ab0b9c7dde96125cfd250fa00a06082a8648ce3d030107a144034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    csign_pub = "3059301306072a8648ce3d020106082a8648ce3d030107034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJwYWtZbXVzd1dCdWpSYTl5OEsweDViaTVrT3VNT3dzZHRlaml2UG55ZHZzIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIybU5vNXZuRkI5bEw3d1VWb1hJbGVPYzBNSEE1QXZKbnpwZXZULVVTYzVNIiwieSI6IlhzS3dqVHJlLTg5WWdpU3pKaG9CN1haeUttTU05OTl3V2ZaSVl0bi01Q3MifX0.XhjFpZgcSa7G2lHy0OCYTvaZFRo5Hyx6b7g7oYyusLC7C_73AJ4_BxEZQVYJXAtDuGvb3dXSkHEKxREP9Q6Qeg"
    ap_netaccesskey = "30770201010420ceba752db2ad5200fa7bc565b9c05c69b7eb006751b0b329b0279de1c19ca67ca00a06082a8648ce3d030107a14403420004da6368e6f9c507d94bef0515a1722578e73430703902f267ce97af4fe51273935ec2b08d3adefbcf588224b3261a01ed76722a630cf7df7059f64862d9fee42b"

    params = { "ssid": "DPPNET01",
               "wpa": "2",
               "ieee80211w": "2",
               "wpa_key_mgmt": "DPP",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign_pub,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    sigma = start_sigma_dut(dev[0].ifname)
    try:
        dev[0].set("dpp_config_processing", "2")

        cmd = "DPP_CONFIGURATOR_ADD key=" + csign
        res = dev[1].request(cmd);
        if "FAIL" in res:
            raise Exception("Failed to add configurator")
        conf_id = int(res)

        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR")
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)
        hex = res.split(',')[3]
        uri = hex.decode('hex')
        logger.info("URI from sigma_dut: " + uri)

        res = dev[1].request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
        id1 = int(res)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        t = threading.Thread(target=dpp_init_conf_mutual,
                             args=(dev[1], id1, conf_id, id0))
        t.start()

        cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPAuthDirection,Mutual,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,20,DPPWaitForConnect,Yes"
        if extra:
            cmd += extra
        res = sigma_dut_cmd(cmd, timeout=25)
        t.join()
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,OK,NetworkConnectResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        dev[0].set("dpp_config_processing", "0")
        stop_sigma_dut(sigma)

def dpp_resp_conf_mutual(dev, conf_id, uri):
    logger.info("Starting DPP responder/configurator in a thread")
    dev.set("dpp_configurator_params",
            " conf=sta-dpp ssid=%s configurator=%d" % ("DPPNET01".encode("hex"), conf_id));
    cmd = "DPP_LISTEN 2437 role=configurator qr=mutual"
    if "OK" not in dev.request(cmd):
        raise Exception("Failed to initiate DPP listen")
    if uri:
        ev = dev.wait_event(["DPP-SCAN-PEER-QR-CODE"], timeout=10)
        if ev is None:
            raise Exception("QR Code scan for mutual authentication not requested")
        res = dev.request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
    ev = dev.wait_event(["DPP-CONF-SENT"], timeout=10)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    logger.info("DPP responder/configurator done")

def test_sigma_dut_dpp_qr_mutual_init_enrollee(dev, apdev):
    """sigma_dut DPP/QR (mutual) initiator as Enrollee"""
    run_sigma_dut_dpp_qr_mutual_init_enrollee(dev, apdev, False)

def test_sigma_dut_dpp_qr_mutual_init_enrollee_pending(dev, apdev):
    """sigma_dut DPP/QR (mutual) initiator as Enrollee (response pending)"""
    run_sigma_dut_dpp_qr_mutual_init_enrollee(dev, apdev, True)

def run_sigma_dut_dpp_qr_mutual_init_enrollee(dev, apdev, resp_pending):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "30770201010420768240a3fc89d6662d9782f120527fe7fb9edc6366ab0b9c7dde96125cfd250fa00a06082a8648ce3d030107a144034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    csign_pub = "3059301306072a8648ce3d020106082a8648ce3d030107034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJwYWtZbXVzd1dCdWpSYTl5OEsweDViaTVrT3VNT3dzZHRlaml2UG55ZHZzIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIybU5vNXZuRkI5bEw3d1VWb1hJbGVPYzBNSEE1QXZKbnpwZXZULVVTYzVNIiwieSI6IlhzS3dqVHJlLTg5WWdpU3pKaG9CN1haeUttTU05OTl3V2ZaSVl0bi01Q3MifX0.XhjFpZgcSa7G2lHy0OCYTvaZFRo5Hyx6b7g7oYyusLC7C_73AJ4_BxEZQVYJXAtDuGvb3dXSkHEKxREP9Q6Qeg"
    ap_netaccesskey = "30770201010420ceba752db2ad5200fa7bc565b9c05c69b7eb006751b0b329b0279de1c19ca67ca00a06082a8648ce3d030107a14403420004da6368e6f9c507d94bef0515a1722578e73430703902f267ce97af4fe51273935ec2b08d3adefbcf588224b3261a01ed76722a630cf7df7059f64862d9fee42b"

    params = { "ssid": "DPPNET01",
               "wpa": "2",
               "ieee80211w": "2",
               "wpa_key_mgmt": "DPP",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign_pub,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    sigma = start_sigma_dut(dev[0].ifname)
    try:
        dev[0].set("dpp_config_processing", "2")

        cmd = "DPP_CONFIGURATOR_ADD key=" + csign
        res = dev[1].request(cmd);
        if "FAIL" in res:
            raise Exception("Failed to add configurator")
        conf_id = int(res)

        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR")
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)
        hex = res.split(',')[3]
        uri = hex.decode('hex')
        logger.info("URI from sigma_dut: " + uri)

        if not resp_pending:
            res = dev[1].request("DPP_QR_CODE " + uri)
            if "FAIL" in res:
                raise Exception("Failed to parse QR Code URI")
            uri = None

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        t = threading.Thread(target=dpp_resp_conf_mutual,
                             args=(dev[1], conf_id, uri))
        t.start()

        time.sleep(1)
        cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,10,DPPWaitForConnect,Yes"
        res = sigma_dut_cmd(cmd, timeout=15)
        t.join()
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,OK,NetworkConnectResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        dev[0].set("dpp_config_processing", "0")
        stop_sigma_dut(sigma)

def test_sigma_dut_dpp_qr_init_enrollee_psk(dev, apdev):
    """sigma_dut DPP/QR initiator as Enrollee (PSK)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    params = hostapd.wpa2_params(ssid="DPPNET01",
                                 passphrase="ThisIsDppPassphrase")
    hapd = hostapd.add_ap(apdev[0], params)

    sigma = start_sigma_dut(dev[0].ifname)
    try:
        dev[0].set("dpp_config_processing", "2")

        cmd = "DPP_CONFIGURATOR_ADD"
        res = dev[1].request(cmd);
        if "FAIL" in res:
            raise Exception("Failed to add configurator")
        conf_id = int(res)

        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        dev[1].set("dpp_configurator_params",
                   " conf=sta-psk ssid=%s pass=%s configurator=%d" % ("DPPNET01".encode("hex"), "ThisIsDppPassphrase".encode("hex"), conf_id));
        cmd = "DPP_LISTEN 2437 role=configurator"
        if "OK" not in dev[1].request(cmd):
            raise Exception("Failed to start listen operation")

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,6,DPPWaitForConnect,Yes", timeout=10)
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkConnectResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        dev[0].set("dpp_config_processing", "0")
        stop_sigma_dut(sigma)

def test_sigma_dut_dpp_qr_init_configurator_1(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (conf index 1)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 1)

def test_sigma_dut_dpp_qr_init_configurator_2(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (conf index 2)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 2)

def test_sigma_dut_dpp_qr_init_configurator_3(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (conf index 3)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 3)

def test_sigma_dut_dpp_qr_init_configurator_4(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (conf index 4)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 4)

def test_sigma_dut_dpp_qr_init_configurator_5(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (conf index 5)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 5)

def test_sigma_dut_dpp_qr_init_configurator_6(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (conf index 6)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 6)

def test_sigma_dut_dpp_qr_init_configurator_7(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (conf index 7)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 7)

def test_sigma_dut_dpp_qr_init_configurator_both(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator or Enrollee (conf index 1)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 1, "Both")

def test_sigma_dut_dpp_qr_init_configurator_neg_freq(dev, apdev):
    """sigma_dut DPP/QR initiator as Configurator (neg_freq)"""
    run_sigma_dut_dpp_qr_init_configurator(dev, apdev, 1, extra='DPPSubsequentChannel,81/11')

def run_sigma_dut_dpp_qr_init_configurator(dev, apdev, conf_idx,
                                           prov_role="Configurator",
                                           extra=None):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        cmd = "DPP_LISTEN 2437 role=enrollee"
        if "OK" not in dev[1].request(cmd):
            raise Exception("Failed to start listen operation")

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,%s,DPPConfIndex,%d,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,QR,DPPTimeout,6" % (prov_role, conf_idx)
        if extra:
            cmd += "," + extra
        res = sigma_dut_cmd(cmd)
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        stop_sigma_dut(sigma)

def test_sigma_dut_dpp_incompatible_roles_init(dev, apdev):
    """sigma_dut DPP roles incompatible (Initiator)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR")
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)
        hex = res.split(',')[3]
        uri = hex.decode('hex')
        logger.info("URI from sigma_dut: " + uri)

        res = dev[1].request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
        id1 = int(res)

        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        cmd = "DPP_LISTEN 2437 role=enrollee"
        if "OK" not in dev[1].request(cmd):
            raise Exception("Failed to start listen operation")

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Mutual,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,6"
        res = sigma_dut_cmd(cmd)
        if "BootstrapResult,OK,AuthResult,ROLES_NOT_COMPATIBLE" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        stop_sigma_dut(sigma)

def dpp_init_enrollee_mutual(dev, id1, own_id):
    logger.info("Starting DPP initiator/enrollee in a thread")
    time.sleep(1)
    cmd = "DPP_AUTH_INIT peer=%d own=%d role=enrollee" % (id1, own_id)
    if "OK" not in dev.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev.wait_event(["DPP-CONF-RECEIVED",
                         "DPP-NOT-COMPATIBLE"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    logger.info("DPP initiator/enrollee done")

def test_sigma_dut_dpp_incompatible_roles_resp(dev, apdev):
    """sigma_dut DPP roles incompatible (Responder)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        cmd = "dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR"
        res = sigma_dut_cmd(cmd)
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)
        hex = res.split(',')[3]
        uri = hex.decode('hex')
        logger.info("URI from sigma_dut: " + uri)

        res = dev[1].request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
        id1 = int(res)

        addr = dev[1].own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id0 = int(res)
        uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        t = threading.Thread(target=dpp_init_enrollee_mutual, args=(dev[1], id1, id0))
        t.start()
        cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPAuthDirection,Mutual,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,6"
        res = sigma_dut_cmd(cmd, timeout=10)
        t.join()
        if "BootstrapResult,OK,AuthResult,ROLES_NOT_COMPATIBLE" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        stop_sigma_dut(sigma)

def test_sigma_dut_dpp_pkex_init_configurator(dev, apdev):
    """sigma_dut DPP/PKEX initiator as Configurator"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        cmd = "DPP_BOOTSTRAP_GEN type=pkex"
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id1 = int(res)
        cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id1)
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to set PKEX data (responder)")
        cmd = "DPP_LISTEN 2437 role=enrollee"
        if "OK" not in dev[1].request(cmd):
            raise Exception("Failed to start listen operation")

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPProvisioningRole,Configurator,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,PKEX,DPPPKEXCodeIdentifier,test,DPPPKEXCode,secret,DPPTimeout,6")
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        stop_sigma_dut(sigma)

def dpp_init_conf(dev, id1, conf, conf_id, extra):
    logger.info("Starting DPP initiator/configurator in a thread")
    cmd = "DPP_AUTH_INIT peer=%d conf=%s %s configurator=%d" % (id1, conf, extra, conf_id)
    if "OK" not in dev.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev.wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    logger.info("DPP initiator/configurator done")

def test_sigma_dut_ap_dpp_qr(dev, apdev, params):
    """sigma_dut controlled AP (DPP)"""
    run_sigma_dut_ap_dpp_qr(dev, apdev, params, "ap-dpp", "sta-dpp")

def test_sigma_dut_ap_dpp_qr_legacy(dev, apdev, params):
    """sigma_dut controlled AP (legacy)"""
    run_sigma_dut_ap_dpp_qr(dev, apdev, params, "ap-psk", "sta-psk",
                            extra="pass=%s" % "qwertyuiop".encode("hex"))

def test_sigma_dut_ap_dpp_qr_legacy_psk(dev, apdev, params):
    """sigma_dut controlled AP (legacy)"""
    run_sigma_dut_ap_dpp_qr(dev, apdev, params, "ap-psk", "sta-psk",
                            extra="psk=%s" % (32*"12"))

def run_sigma_dut_ap_dpp_qr(dev, apdev, params, ap_conf, sta_conf, extra=""):
    check_dpp_capab(dev[0])
    logdir = os.path.join(params['logdir'], "sigma_dut_ap_dpp_qr.sigma-hostapd")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            sigma_dut_cmd_check("ap_reset_default,program,DPP")
            res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR")
            if "status,COMPLETE" not in res:
                raise Exception("dev_exec_action did not succeed: " + res)
            hex = res.split(',')[3]
            uri = hex.decode('hex')
            logger.info("URI from sigma_dut: " + uri)

            cmd = "DPP_CONFIGURATOR_ADD"
            res = dev[0].request(cmd);
            if "FAIL" in res:
                raise Exception("Failed to add configurator")
            conf_id = int(res)

            res = dev[0].request("DPP_QR_CODE " + uri)
            if "FAIL" in res:
                raise Exception("Failed to parse QR Code URI")
            id1 = int(res)

            t = threading.Thread(target=dpp_init_conf,
                                 args=(dev[0], id1, ap_conf, conf_id, extra))
            t.start()
            res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPAuthDirection,Single,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,6")
            t.join()
            if "ConfResult,OK" not in res:
                raise Exception("Unexpected result: " + res)

            addr = dev[1].own_addr().replace(':', '')
            cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
            res = dev[1].request(cmd)
            if "FAIL" in res:
                raise Exception("Failed to generate bootstrapping info")
            id1 = int(res)
            uri1 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1)

            res = dev[0].request("DPP_QR_CODE " + uri1)
            if "FAIL" in res:
                raise Exception("Failed to parse QR Code URI")
            id0b = int(res)

            dev[1].set("dpp_config_processing", "2")
            cmd = "DPP_LISTEN 2412"
            if "OK" not in dev[1].request(cmd):
                raise Exception("Failed to start listen operation")
            cmd = "DPP_AUTH_INIT peer=%d conf=%s %s configurator=%d" % (id0b, sta_conf, extra, conf_id)
            if "OK" not in dev[0].request(cmd):
                raise Exception("Failed to initiate DPP Authentication")
            dev[1].wait_connected()

            sigma_dut_cmd_check("ap_reset_default")
        finally:
            dev[1].set("dpp_config_processing", "0")
            stop_sigma_dut(sigma)

def test_sigma_dut_ap_dpp_pkex_responder(dev, apdev, params):
    """sigma_dut controlled AP as DPP PKEX responder"""
    check_dpp_capab(dev[0])
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_dpp_pkex_responder.sigma-hostapd")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            run_sigma_dut_ap_dpp_pkex_responder(dev, apdev)
        finally:
            stop_sigma_dut(sigma)

def dpp_init_conf_pkex(dev, conf_id, check_config=True):
    logger.info("Starting DPP PKEX initiator/configurator in a thread")
    time.sleep(1.5)
    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id = int(res)
    cmd = "DPP_PKEX_ADD own=%d init=1 conf=ap-dpp configurator=%d code=password" % (id, conf_id)
    res = dev.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to initiate DPP PKEX")
    if not check_config:
        return
    ev = dev.wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    logger.info("DPP initiator/configurator done")

def run_sigma_dut_ap_dpp_pkex_responder(dev, apdev):
    sigma_dut_cmd_check("ap_reset_default,program,DPP")

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    t = threading.Thread(target=dpp_init_conf_pkex, args=(dev[0], conf_id))
    t.start()
    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPAuthDirection,Mutual,DPPProvisioningRole,Enrollee,DPPBS,PKEX,DPPPKEXCode,password,DPPTimeout,6,DPPWaitForConnect,No", timeout=10)
    t.join()
    if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK" not in res:
        raise Exception("Unexpected result: " + res)

    sigma_dut_cmd_check("ap_reset_default")

def test_sigma_dut_dpp_pkex_responder_proto(dev, apdev):
    """sigma_dut controlled STA as DPP PKEX responder and error case"""
    check_dpp_capab(dev[0])
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        run_sigma_dut_dpp_pkex_responder_proto(dev, apdev)
    finally:
        stop_sigma_dut(sigma)

def run_sigma_dut_dpp_pkex_responder_proto(dev, apdev):
    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[1].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    dev[1].set("dpp_test", "44")

    t = threading.Thread(target=dpp_init_conf_pkex, args=(dev[1], conf_id,
                                                          False))
    t.start()
    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPProvisioningRole,Enrollee,DPPBS,PKEX,DPPPKEXCode,password,DPPTimeout,6", timeout=10)
    t.join()
    if "BootstrapResult,Timeout" not in res:
        raise Exception("Unexpected result: " + res)

def dpp_proto_init(dev, id1):
    time.sleep(1)
    logger.info("Starting DPP initiator/configurator in a thread")
    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev.request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp configurator=%d" % (id1, conf_id)
    if "OK" not in dev.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")

def test_sigma_dut_dpp_proto_initiator(dev, apdev):
    """sigma_dut DPP protocol testing - Initiator"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    tests = [ ("InvalidValue", "AuthenticationRequest", "WrappedData",
               "BootstrapResult,OK,AuthResult,Errorsent",
               None),
              ("InvalidValue", "AuthenticationConfirm", "WrappedData",
               "BootstrapResult,OK,AuthResult,Errorsent",
               None),
              ("MissingAttribute", "AuthenticationRequest", "InitCapabilities",
               "BootstrapResult,OK,AuthResult,Errorsent",
               "Missing or invalid I-capabilities"),
              ("InvalidValue", "AuthenticationConfirm", "InitAuthTag",
               "BootstrapResult,OK,AuthResult,Errorsent",
               "Mismatching Initiator Authenticating Tag"),
              ("MissingAttribute", "ConfigurationResponse", "EnrolleeNonce",
               "BootstrapResult,OK,AuthResult,OK,ConfResult,Errorsent",
               "Missing or invalid Enrollee Nonce attribute") ]
    for step, frame, attr, result, fail in tests:
        dev[0].request("FLUSH")
        dev[1].request("FLUSH")
        sigma = start_sigma_dut(dev[0].ifname)
        try:
            run_sigma_dut_dpp_proto_initiator(dev, step, frame, attr, result,
                                              fail)
        finally:
            stop_sigma_dut(sigma)

def run_sigma_dut_dpp_proto_initiator(dev, step, frame, attr, result, fail):
    addr = dev[1].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    cmd = "DPP_LISTEN 2437 role=enrollee"
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to start listen operation")

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
    if "status,COMPLETE" not in res:
        raise Exception("dev_exec_action did not succeed: " + res)

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Configurator,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,QR,DPPTimeout,6,DPPStep,%s,DPPFrameType,%s,DPPIEAttribute,%s" % (step, frame, attr),
                        timeout=10)
    if result not in res:
        raise Exception("Unexpected result: " + res)
    if fail:
        ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
        if ev is None or fail not in ev:
            raise Exception("Failure not reported correctly: " + str(ev))

    dev[1].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_sigma_dut_dpp_proto_responder(dev, apdev):
    """sigma_dut DPP protocol testing - Responder"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    tests = [ ("MissingAttribute", "AuthenticationResponse", "DPPStatus",
               "BootstrapResult,OK,AuthResult,Errorsent",
               "Missing or invalid required DPP Status attribute"),
              ("MissingAttribute", "ConfigurationRequest", "EnrolleeNonce",
               "BootstrapResult,OK,AuthResult,OK,ConfResult,Errorsent",
               "Missing or invalid Enrollee Nonce attribute") ]
    for step, frame, attr, result, fail in tests:
        dev[0].request("FLUSH")
        dev[1].request("FLUSH")
        sigma = start_sigma_dut(dev[0].ifname)
        try:
            run_sigma_dut_dpp_proto_responder(dev, step, frame, attr, result,
                                              fail)
        finally:
            stop_sigma_dut(sigma)

def run_sigma_dut_dpp_proto_responder(dev, step, frame, attr, result, fail):
    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR")
    if "status,COMPLETE" not in res:
        raise Exception("dev_exec_action did not succeed: " + res)
    hex = res.split(',')[3]
    uri = hex.decode('hex')
    logger.info("URI from sigma_dut: " + uri)

    res = dev[1].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    t = threading.Thread(target=dpp_proto_init, args=(dev[1], id1))
    t.start()
    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPAuthDirection,Single,DPPProvisioningRole,Enrollee,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,QR,DPPTimeout,6,DPPStep,%s,DPPFrameType,%s,DPPIEAttribute,%s" % (step, frame, attr), timeout=10)
    t.join()
    if result not in res:
        raise Exception("Unexpected result: " + res)
    if fail:
        ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
        if ev is None or fail not in ev:
            raise Exception("Failure not reported correctly:" + str(ev))

    dev[1].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_sigma_dut_dpp_proto_stop_at_initiator(dev, apdev):
    """sigma_dut DPP protocol testing - Stop at RX on Initiator"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    tests = [ ("AuthenticationResponse",
               "BootstrapResult,OK,AuthResult,Errorsent",
               None),
              ("ConfigurationRequest",
               "BootstrapResult,OK,AuthResult,OK,ConfResult,Errorsent",
               None)]
    for frame, result, fail in tests:
        dev[0].request("FLUSH")
        dev[1].request("FLUSH")
        sigma = start_sigma_dut(dev[0].ifname)
        try:
            run_sigma_dut_dpp_proto_stop_at_initiator(dev, frame, result, fail)
        finally:
            stop_sigma_dut(sigma)

def run_sigma_dut_dpp_proto_stop_at_initiator(dev, frame, result, fail):
    addr = dev[1].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    cmd = "DPP_LISTEN 2437 role=enrollee"
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to start listen operation")

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
    if "status,COMPLETE" not in res:
        raise Exception("dev_exec_action did not succeed: " + res)

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Configurator,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,QR,DPPTimeout,6,DPPStep,Timeout,DPPFrameType,%s" % (frame))
    if result not in res:
        raise Exception("Unexpected result: " + res)
    if fail:
        ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
        if ev is None or fail not in ev:
            raise Exception("Failure not reported correctly: " + str(ev))

    dev[1].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_sigma_dut_dpp_proto_stop_at_responder(dev, apdev):
    """sigma_dut DPP protocol testing - Stop at RX on Responder"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    tests = [ ("AuthenticationRequest",
               "BootstrapResult,OK,AuthResult,Errorsent",
               None),
              ("AuthenticationConfirm",
               "BootstrapResult,OK,AuthResult,Errorsent",
               None) ]
    for frame, result, fail in tests:
        dev[0].request("FLUSH")
        dev[1].request("FLUSH")
        sigma = start_sigma_dut(dev[0].ifname)
        try:
            run_sigma_dut_dpp_proto_stop_at_responder(dev, frame, result, fail)
        finally:
            stop_sigma_dut(sigma)

def run_sigma_dut_dpp_proto_stop_at_responder(dev, frame, result, fail):
    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,GetLocalBootstrap,DPPCryptoIdentifier,P-256,DPPBS,QR")
    if "status,COMPLETE" not in res:
        raise Exception("dev_exec_action did not succeed: " + res)
    hex = res.split(',')[3]
    uri = hex.decode('hex')
    logger.info("URI from sigma_dut: " + uri)

    res = dev[1].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    t = threading.Thread(target=dpp_proto_init, args=(dev[1], id1))
    t.start()
    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPAuthDirection,Single,DPPProvisioningRole,Enrollee,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,QR,DPPTimeout,6,DPPStep,Timeout,DPPFrameType,%s" % (frame), timeout=10)
    t.join()
    if result not in res:
        raise Exception("Unexpected result: " + res)
    if fail:
        ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
        if ev is None or fail not in ev:
            raise Exception("Failure not reported correctly:" + str(ev))

    dev[1].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def dpp_proto_init_pkex(dev):
    time.sleep(1)
    logger.info("Starting DPP PKEX initiator/configurator in a thread")
    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev.request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id = int(res)

    cmd = "DPP_PKEX_ADD own=%d init=1 conf=sta-dpp configurator=%d code=secret" % (id, conf_id)
    if "FAIL" in dev.request(cmd):
        raise Exception("Failed to initiate DPP PKEX")

def test_sigma_dut_dpp_proto_initiator_pkex(dev, apdev):
    """sigma_dut DPP protocol testing - Initiator (PKEX)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    tests = [ ("InvalidValue", "PKEXCRRequest", "WrappedData",
               "BootstrapResult,Errorsent",
               None),
              ("MissingAttribute", "PKEXExchangeRequest", "FiniteCyclicGroup",
               "BootstrapResult,Errorsent",
               "Missing or invalid Finite Cyclic Group attribute"),
              ("MissingAttribute", "PKEXCRRequest", "BSKey",
               "BootstrapResult,Errorsent",
               "No valid peer bootstrapping key found") ]
    for step, frame, attr, result, fail in tests:
        dev[0].request("FLUSH")
        dev[1].request("FLUSH")
        sigma = start_sigma_dut(dev[0].ifname)
        try:
            run_sigma_dut_dpp_proto_initiator_pkex(dev, step, frame, attr,
                                                   result, fail)
        finally:
            stop_sigma_dut(sigma)

def run_sigma_dut_dpp_proto_initiator_pkex(dev, step, frame, attr, result, fail):
    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d code=secret" % (id1)
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")

    cmd = "DPP_LISTEN 2437 role=enrollee"
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to start listen operation")

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Configurator,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,PKEX,DPPPKEXCode,secret,DPPTimeout,6,DPPStep,%s,DPPFrameType,%s,DPPIEAttribute,%s" % (step, frame, attr))
    if result not in res:
        raise Exception("Unexpected result: " + res)
    if fail:
        ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
        if ev is None or fail not in ev:
            raise Exception("Failure not reported correctly: " + str(ev))

    dev[1].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_sigma_dut_dpp_proto_responder_pkex(dev, apdev):
    """sigma_dut DPP protocol testing - Responder (PKEX)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    tests = [ ("InvalidValue", "PKEXCRResponse", "WrappedData",
               "BootstrapResult,Errorsent",
               None),
              ("MissingAttribute", "PKEXExchangeResponse", "DPPStatus",
               "BootstrapResult,Errorsent",
               "No DPP Status attribute"),
              ("MissingAttribute", "PKEXCRResponse", "BSKey",
               "BootstrapResult,Errorsent",
               "No valid peer bootstrapping key found") ]
    for step, frame, attr, result, fail in tests:
        dev[0].request("FLUSH")
        dev[1].request("FLUSH")
        sigma = start_sigma_dut(dev[0].ifname)
        try:
            run_sigma_dut_dpp_proto_responder_pkex(dev, step, frame, attr,
                                                   result, fail)
        finally:
            stop_sigma_dut(sigma)

def run_sigma_dut_dpp_proto_responder_pkex(dev, step, frame, attr, result, fail):
    t = threading.Thread(target=dpp_proto_init_pkex, args=(dev[1],))
    t.start()
    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Responder,DPPAuthDirection,Single,DPPProvisioningRole,Enrollee,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,PKEX,DPPPKEXCode,secret,DPPTimeout,6,DPPStep,%s,DPPFrameType,%s,DPPIEAttribute,%s" % (step, frame, attr), timeout=10)
    t.join()
    if result not in res:
        raise Exception("Unexpected result: " + res)
    if fail:
        ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
        if ev is None or fail not in ev:
            raise Exception("Failure not reported correctly:" + str(ev))

    dev[1].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def init_sigma_dut_dpp_proto_peer_disc_req(dev, apdev):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "30770201010420768240a3fc89d6662d9782f120527fe7fb9edc6366ab0b9c7dde96125cfd250fa00a06082a8648ce3d030107a144034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    csign_pub = "3059301306072a8648ce3d020106082a8648ce3d030107034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJwYWtZbXVzd1dCdWpSYTl5OEsweDViaTVrT3VNT3dzZHRlaml2UG55ZHZzIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIybU5vNXZuRkI5bEw3d1VWb1hJbGVPYzBNSEE1QXZKbnpwZXZULVVTYzVNIiwieSI6IlhzS3dqVHJlLTg5WWdpU3pKaG9CN1haeUttTU05OTl3V2ZaSVl0bi01Q3MifX0.XhjFpZgcSa7G2lHy0OCYTvaZFRo5Hyx6b7g7oYyusLC7C_73AJ4_BxEZQVYJXAtDuGvb3dXSkHEKxREP9Q6Qeg"
    ap_netaccesskey = "30770201010420ceba752db2ad5200fa7bc565b9c05c69b7eb006751b0b329b0279de1c19ca67ca00a06082a8648ce3d030107a14403420004da6368e6f9c507d94bef0515a1722578e73430703902f267ce97af4fe51273935ec2b08d3adefbcf588224b3261a01ed76722a630cf7df7059f64862d9fee42b"

    params = { "ssid": "DPPNET01",
               "wpa": "2",
               "ieee80211w": "2",
               "wpa_key_mgmt": "DPP",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign_pub,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    dev[0].set("dpp_config_processing", "2")

    cmd = "DPP_CONFIGURATOR_ADD key=" + csign
    res = dev[1].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    addr = dev[1].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    dev[1].set("dpp_configurator_params",
               " conf=sta-dpp ssid=%s configurator=%d" % ("DPPNET01".encode("hex"), conf_id));
    cmd = "DPP_LISTEN 2437 role=configurator"
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to start listen operation")

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri0.encode('hex'))
    if "status,COMPLETE" not in res:
        raise Exception("dev_exec_action did not succeed: " + res)

def test_sigma_dut_dpp_proto_peer_disc_req(dev, apdev):
    """sigma_dut DPP protocol testing - Peer Discovery Request"""
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        init_sigma_dut_dpp_proto_peer_disc_req(dev, apdev)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Enrollee,DPPBS,QR,DPPTimeout,6,DPPWaitForConnect,Yes,DPPStep,MissingAttribute,DPPFrameType,PeerDiscoveryRequest,DPPIEAttribute,TransactionID", timeout=10)
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,Errorsent" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        dev[0].set("dpp_config_processing", "0")
        stop_sigma_dut(sigma)

def test_sigma_dut_dpp_self_config(dev, apdev):
    """sigma_dut DPP Configurator enrolling an AP and using self-configuration"""
    check_dpp_capab(dev[0])

    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured" })
    check_dpp_capab(hapd)

    sigma = start_sigma_dut(dev[0].ifname)
    try:
        dev[0].set("dpp_config_processing", "2")
        addr = hapd.own_addr().replace(':', '')
        cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
        res = hapd.request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id = int(res)
        uri = hapd.request("DPP_BOOTSTRAP_GET_URI %d" % id)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri.encode('hex'))
        if "status,COMPLETE" not in res:
            raise Exception("dev_exec_action did not succeed: " + res)

        res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Configurator,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,AP,DPPBS,QR,DPPTimeout,6")
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
        update_hapd_config(hapd)

        cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPCryptoIdentifier,P-256,DPPBS,QR,DPPAuthRole,Initiator,DPPProvisioningRole,Configurator,DPPAuthDirection,Single,DPPConfIndex,1,DPPTimeout,6,DPPWaitForConnect,Yes,DPPSelfConfigure,Yes"
        res = sigma_dut_cmd(cmd, timeout=10)
        if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,OK,NetworkConnectResult,OK" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        stop_sigma_dut(sigma)
        dev[0].set("dpp_config_processing", "0")

def test_sigma_dut_ap_dpp_self_config(dev, apdev, params):
    """sigma_dut DPP AP Configurator using self-configuration"""
    logdir = os.path.join(params['logdir'],
                          "sigma_dut_ap_dpp_self_config.sigma-hostapd")
    with HWSimRadio() as (radio, iface):
        sigma = start_sigma_dut(iface, hostapd_logdir=logdir)
        try:
            run_sigma_dut_ap_dpp_self_config(dev, apdev)
        finally:
            stop_sigma_dut(sigma)
            dev[0].set("dpp_config_processing", "0")

def run_sigma_dut_ap_dpp_self_config(dev, apdev):
    check_dpp_capab(dev[0])

    sigma_dut_cmd_check("ap_reset_default,program,DPP")

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Configurator,DPPConfEnrolleeRole,AP,DPPBS,QR,DPPConfIndex,1,DPPSelfConfigure,Yes,DPPTimeout,6", timeout=10)
    if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK" not in res:
            raise Exception("Unexpected result: " + res)

    dev[0].set("dpp_config_processing", "2")

    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/11 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id = int(res)
    uri = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id)
    cmd = "DPP_LISTEN 2462 role=enrollee"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    res = sigma_dut_cmd("dev_exec_action,program,DPP,DPPActionType,SetPeerBootstrap,DPPBootstrappingdata,%s,DPPBS,QR" % uri.encode('hex'))
    if "status,COMPLETE" not in res:
        raise Exception("dev_exec_action did not succeed: " + res)
    cmd = "dev_exec_action,program,DPP,DPPActionType,AutomaticDPP,DPPAuthRole,Initiator,DPPAuthDirection,Single,DPPProvisioningRole,Configurator,DPPConfIndex,1,DPPSigningKeyECC,P-256,DPPConfEnrolleeRole,STA,DPPBS,QR,DPPTimeout,6"
    res = sigma_dut_cmd(cmd)
    if "BootstrapResult,OK,AuthResult,OK,ConfResult,OK" not in res:
        raise Exception("Unexpected result: " + res)
    dev[0].wait_connected()
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    sigma_dut_cmd_check("ap_reset_default")

def test_sigma_dut_preconfigured_profile(dev, apdev):
    """sigma_dut controlled connection using preconfigured profile"""
    try:
        run_sigma_dut_preconfigured_profile(dev, apdev)
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def run_sigma_dut_preconfigured_profile(dev, apdev):
    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    params = hostapd.wpa2_params(ssid="test-psk", passphrase="12345678")
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].connect("test-psk", psk="12345678", scan_freq="2412",
                   only_add_network=True)

    sigma_dut_cmd_check("sta_set_ip_config,interface,%s,dhcp,0,ip,127.0.0.11,mask,255.255.255.0" % ifname)
    sigma_dut_cmd_check("sta_associate,interface,%s,ssid,%s" % (ifname, "test-psk"))
    sigma_dut_wait_connected(ifname)
    sigma_dut_cmd_check("sta_get_ip_config,interface," + ifname)
    sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)

    stop_sigma_dut(sigma)

def test_sigma_dut_wps_pbc(dev, apdev):
    """sigma_dut and WPS PBC Enrollee"""
    try:
        run_sigma_dut_wps_pbc(dev, apdev)
    finally:
        dev[0].set("ignore_old_scan_res", "0")

def run_sigma_dut_wps_pbc(dev, apdev):
    ssid = "test-wps-conf"
    hapd = hostapd.add_ap(apdev[0],
                          { "ssid": "wps", "eap_server": "1", "wps_state": "2",
                            "wpa_passphrase": "12345678", "wpa": "2",
                            "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP" })
    hapd.request("WPS_PBC")

    ifname = dev[0].ifname
    sigma = start_sigma_dut(ifname)

    cmd = "start_wps_registration,interface,%s" % ifname
    cmd += ",WpsRole,Enrollee"
    cmd += ",WpsConfigMethod,PBC"
    sigma_dut_cmd_check(cmd, timeout=15)

    sigma_dut_cmd_check("sta_disconnect,interface," + ifname)
    hapd.disable()
    sigma_dut_cmd_check("sta_reset_default,interface," + ifname)
    stop_sigma_dut(sigma)
    dev[0].flush_scan_cache()

def test_sigma_dut_sta_scan_bss(dev, apdev):
    """sigma_dut sta_scan_bss"""
    hapd = hostapd.add_ap(apdev[0], { "ssid": "test" })
    sigma = start_sigma_dut(dev[0].ifname)
    try:
        cmd = "sta_scan_bss,Interface,%s,BSSID,%s" % (dev[0].ifname, \
                                                      hapd.own_addr())
        res = sigma_dut_cmd(cmd, timeout=10)
        if "ssid,test,bsschannel,1" not in res:
            raise Exception("Unexpected result: " + res)
    finally:
        stop_sigma_dut(sigma)
