# Test cases for FILS
# Copyright (c) 2015-2017, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import hashlib
import logging
logger = logging.getLogger()
import os
import socket
import struct
import time

import hostapd
from wpasupplicant import WpaSupplicant
import hwsim_utils
from utils import HwsimSkip, alloc_fail
from test_erp import check_erp_capa, start_erp_as
from test_ap_hs20 import ip_checksum

def check_fils_capa(dev):
    capa = dev.get_capability("fils")
    if capa is None or "FILS" not in capa:
        raise HwsimSkip("FILS not supported")

def test_fils_sk_full_auth(dev, apdev):
    """FILS SK full authentication"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    bss = dev[0].get_bss(bssid)
    logger.debug("BSS: " + str(bss))
    if "[FILS]" not in bss['flags']:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA256-CCMP]" not in bss['flags']:
        raise Exception("[WPA2-FILS-SHA256-CCMP] flag not indicated")

    res = dev[0].request("SCAN_RESULTS")
    logger.debug("SCAN_RESULTS: " + res)
    if "[FILS]" not in res:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA256-CCMP]" not in res:
        raise Exception("[WPA2-FILS-SHA256-CCMP] flag not indicated")

    dev[0].request("ERP_FLUSH")
    dev[0].connect("fils", key_mgmt="FILS-SHA256",
                   eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   erp="1", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

    conf = hapd.get_config()
    if conf['key_mgmt'] != 'FILS-SHA256':
        raise Exception("Unexpected config key_mgmt: " + conf['key_mgmt'])

def test_fils_sk_sha384_full_auth(dev, apdev):
    """FILS SK full authentication (SHA384)"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA384"
    params['auth_server_port'] = "18128"
    params['erp_send_reauth_start'] = '1'
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    bss = dev[0].get_bss(bssid)
    logger.debug("BSS: " + str(bss))
    if "[FILS]" not in bss['flags']:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA384-CCMP]" not in bss['flags']:
        raise Exception("[WPA2-FILS-SHA384-CCMP] flag not indicated")

    res = dev[0].request("SCAN_RESULTS")
    logger.debug("SCAN_RESULTS: " + res)
    if "[FILS]" not in res:
        raise Exception("[FILS] flag not indicated")
    if "[WPA2-FILS-SHA384-CCMP]" not in res:
        raise Exception("[WPA2-FILS-SHA384-CCMP] flag not indicated")

    dev[0].request("ERP_FLUSH")
    dev[0].connect("fils", key_mgmt="FILS-SHA384",
                   eap="PSK", identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   erp="1", scan_freq="2412")
    hwsim_utils.test_connectivity(dev[0], hapd)

    ev = dev[0].wait_event(["WPA: Group rekeying completed"], timeout=2)
    if ev is None:
        raise Exception("GTK rekey timed out")
    hwsim_utils.test_connectivity(dev[0], hapd)

    conf = hapd.get_config()
    if conf['key_mgmt'] != 'FILS-SHA384':
        raise Exception("Unexpected config key_mgmt: " + conf['key_mgmt'])

def test_fils_sk_pmksa_caching(dev, apdev):
    """FILS SK and PMKSA caching"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection using PMKSA caching timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    hwsim_utils.test_connectivity(dev[0], hapd)
    pmksa2 = dev[0].get_pmksa(bssid)
    if pmksa2 is None:
        raise Exception("No PMKSA cache entry found")
    if pmksa['pmkid'] != pmksa2['pmkid']:
        raise Exception("Unexpected PMKID change")

    # Verify EAPOL reauthentication after FILS authentication
    hapd.request("EAPOL_REAUTH " + dev[0].own_addr())
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=5)
    if ev is None:
        raise Exception("EAP authentication did not start")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("EAP authentication did not succeed")
    time.sleep(0.1)
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_fils_sk_erp(dev, apdev):
    """FILS SK using ERP"""
    run_fils_sk_erp(dev, apdev, "FILS-SHA256")

def test_fils_sk_erp_sha384(dev, apdev):
    """FILS SK using ERP and SHA384"""
    run_fils_sk_erp(dev, apdev, "FILS-SHA384")

def run_fils_sk_erp(dev, apdev, key_mgmt):
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = key_mgmt
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    id = dev[0].connect("fils", key_mgmt=key_mgmt,
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "EVENT-ASSOC-REJECT",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection using FILS/ERP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    if "EVENT-ASSOC-REJECT" in ev:
        raise Exception("Association failed")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_fils_sk_erp_another_ssid(dev, apdev):
    """FILS SK using ERP and roam to another SSID"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    hapd.disable()
    dev[0].flush_scan_cache()
    if "FAIL" in dev[0].request("PMKSA_FLUSH"):
        raise Exception("PMKSA_FLUSH failed")

    params = hostapd.wpa2_eap_params(ssid="fils2")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].dump_monitor()
    id = dev[0].connect("fils2", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412", wait_connect=False)

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "EVENT-ASSOC-REJECT",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection using FILS/ERP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    if "EVENT-ASSOC-REJECT" in ev:
        raise Exception("Association failed")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_fils_sk_multiple_realms(dev, apdev):
    """FILS SK and multiple realms"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    fils_realms = [ 'r1.example.org', 'r2.EXAMPLE.org', 'r3.example.org',
                    'r4.example.org', 'r5.example.org', 'r6.example.org',
                    'r7.example.org', 'r8.example.org',
                    'example.com',
                    'r9.example.org', 'r10.example.org', 'r11.example.org',
                    'r12.example.org', 'r13.example.org', 'r14.example.org',
                    'r15.example.org', 'r16.example.org' ]
    params['fils_realm'] = fils_realms
    params['fils_cache_id'] = "1234"
    params['hessid'] = bssid
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)

    if "OK" not in dev[0].request("ANQP_GET " + bssid + " 275"):
        raise Exception("ANQP_GET command failed")
    ev = dev[0].wait_event(["GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("GAS query timed out")
    bss = dev[0].get_bss(bssid)

    if 'fils_info' not in bss:
        raise Exception("FILS Indication element information missing")
    if bss['fils_info'] != '02b8':
        raise Exception("Unexpected FILS Information: " + bss['fils_info'])

    if 'fils_cache_id' not in bss:
        raise Exception("FILS Cache Identifier missing")
    if bss['fils_cache_id'] != '1234':
        raise Exception("Unexpected FILS Cache Identifier: " + bss['fils_cache_id'])

    if 'fils_realms' not in bss:
        raise Exception("FILS Realm Identifiers missing")
    expected = ''
    count = 0
    for realm in fils_realms:
        hash = hashlib.sha256(realm.lower()).digest()
        expected += binascii.hexlify(hash[0:2])
        count += 1
        if count == 7:
            break
    if bss['fils_realms'] != expected:
        raise Exception("Unexpected FILS Realm Identifiers: " + bss['fils_realms'])

    if 'anqp_fils_realm_info' not in bss:
        raise Exception("FILS Realm Information ANQP-element not seen")
    info = bss['anqp_fils_realm_info'];
    expected = ''
    for realm in fils_realms:
        hash = hashlib.sha256(realm.lower()).digest()
        expected += binascii.hexlify(hash[0:2])
    if info != expected:
        raise Exception("Unexpected FILS Realm Info ANQP-element: " + info)

    dev[0].request("ERP_FLUSH")
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                            "EVENT-ASSOC-REJECT",
                            "CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Connection using FILS/ERP timed out")
    if "CTRL-EVENT-EAP-STARTED" in ev:
        raise Exception("Unexpected EAP exchange")
    if "EVENT-ASSOC-REJECT" in ev:
        raise Exception("Association failed")
    hwsim_utils.test_connectivity(dev[0], hapd)

# DHCP message op codes
BOOTREQUEST=1
BOOTREPLY=2

OPT_PAD=0
OPT_DHCP_MESSAGE_TYPE=53
OPT_RAPID_COMMIT=80
OPT_END=255

DHCPDISCOVER=1
DHCPOFFER=2
DHCPREQUEST=3
DHCPDECLINE=4
DHCPACK=5
DHCPNAK=6
DHCPRELEASE=7
DHCPINFORM=8

def build_dhcp(req, dhcp_msg, chaddr, giaddr="0.0.0.0",
               ip_src="0.0.0.0", ip_dst="255.255.255.255",
               rapid_commit=True):
    proto = '\x08\x00' # IPv4
    _ip_src = socket.inet_pton(socket.AF_INET, ip_src)
    _ip_dst = socket.inet_pton(socket.AF_INET, ip_dst)

    _ciaddr = '\x00\x00\x00\x00'
    _yiaddr = '\x00\x00\x00\x00'
    _siaddr = '\x00\x00\x00\x00'
    _giaddr = socket.inet_pton(socket.AF_INET, giaddr)
    _chaddr = binascii.unhexlify(chaddr.replace(':','')) + 10*'\x00'
    htype = 1 # Hardware address type; 1 = Ethernet
    hlen = 6 # Hardware address length
    hops = 0
    xid = 123456
    secs = 0
    flags = 0
    if req:
        op = BOOTREQUEST
        src_port = 68
        dst_port = 67
    else:
        op = BOOTREPLY
        src_port = 67
        dst_port = 68
    payload = struct.pack('>BBBBLHH', op, htype, hlen, hops, xid, secs, flags)
    sname = 64*'\x00'
    file = 128*'\x00'
    payload += _ciaddr + _yiaddr + _siaddr + _giaddr + _chaddr + sname + file
    # magic - DHCP
    payload += '\x63\x82\x53\x63'
    # Option: DHCP Message Type
    payload += struct.pack('BBB', OPT_DHCP_MESSAGE_TYPE, 1, dhcp_msg)
    if rapid_commit:
        # Option: Rapid Commit
        payload += struct.pack('BB', OPT_RAPID_COMMIT, 0)
    # End Option
    payload += struct.pack('B', OPT_END)

    udp = struct.pack('>HHHH', src_port, dst_port,
                      8 + len(payload), 0) + payload

    tot_len = 20 + len(udp)
    start = struct.pack('>BBHHBBBB', 0x45, 0, tot_len, 0, 0, 0, 128, 17)
    ipv4 = start + '\x00\x00' + _ip_src + _ip_dst
    csum = ip_checksum(ipv4)
    ipv4 = start + csum + _ip_src + _ip_dst

    return proto + ipv4 + udp

def fils_hlp_config(fils_hlp_wait_time=10000):
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = "FILS-SHA256"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    params['disable_pmksa_caching'] = '1'
    params['own_ip_addr'] = '127.0.0.3'
    params['dhcp_server'] = '127.0.0.2'
    params['fils_hlp_wait_time'] = str(fils_hlp_wait_time)
    return params

def test_fils_sk_hlp(dev, apdev):
    """FILS SK HLP (rapid commit server)"""
    run_fils_sk_hlp(dev, apdev, True)

def test_fils_sk_hlp_no_rapid_commit(dev, apdev):
    """FILS SK HLP (no rapid commit server)"""
    run_fils_sk_hlp(dev, apdev, False)

def run_fils_sk_hlp(dev, apdev, rapid_commit_server):
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(5)
    sock.bind(("127.0.0.2", 67))

    bssid = apdev[0]['bssid']
    params = fils_hlp_config()
    params['fils_hlp_wait_time'] = '10000'
    if not rapid_commit_server:
        params['dhcp_rapid_commit_proxy'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    if "OK" not in dev[0].request("FILS_HLP_REQ_FLUSH"):
        raise Exception("Failed to flush pending FILS HLP requests")
    tests = [ "",
              "q",
              "ff:ff:ff:ff:ff:ff",
              "ff:ff:ff:ff:ff:ff q" ]
    for t in tests:
        if "FAIL" not in dev[0].request("FILS_HLP_REQ_ADD " + t):
            raise Exception("Invalid FILS_HLP_REQ_ADD accepted: " + t)
    dhcpdisc = build_dhcp(req=True, dhcp_msg=DHCPDISCOVER,
                          chaddr=dev[0].own_addr())
    tests = [ "ff:ff:ff:ff:ff:ff aabb",
              "ff:ff:ff:ff:ff:ff " + 255*'cc',
              hapd.own_addr() + " ddee010203040506070809",
              "ff:ff:ff:ff:ff:ff " + binascii.hexlify(dhcpdisc) ]
    for t in tests:
        if "OK" not in dev[0].request("FILS_HLP_REQ_ADD " + t):
            raise Exception("FILS_HLP_REQ_ADD failed: " + t)
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)

    (msg,addr) = sock.recvfrom(1000)
    logger.debug("Received DHCP message from %s" % str(addr))
    if rapid_commit_server:
        # TODO: Proper rapid commit response
        dhcpdisc = build_dhcp(req=False, dhcp_msg=DHCPACK,
                              chaddr=dev[0].own_addr(), giaddr="127.0.0.3")
        sock.sendto(dhcpdisc[2+20+8:], addr)
    else:
        dhcpdisc = build_dhcp(req=False, dhcp_msg=DHCPOFFER, rapid_commit=False,
                              chaddr=dev[0].own_addr(), giaddr="127.0.0.3")
        sock.sendto(dhcpdisc[2+20+8:], addr)
        (msg,addr) = sock.recvfrom(1000)
        logger.debug("Received DHCP message from %s" % str(addr))
        dhcpdisc = build_dhcp(req=False, dhcp_msg=DHCPACK, rapid_commit=False,
                              chaddr=dev[0].own_addr(), giaddr="127.0.0.3")
        sock.sendto(dhcpdisc[2+20+8:], addr)
    ev = dev[0].wait_event(["FILS-HLP-RX"], timeout=10)
    if ev is None:
        raise Exception("FILS HLP response not reported")
    vals = ev.split(' ')
    frame = binascii.unhexlify(vals[3].split('=')[1])
    proto, = struct.unpack('>H', frame[0:2])
    if proto != 0x0800:
        raise Exception("Unexpected ethertype in HLP response: %d" % proto)
    frame = frame[2:]
    ip = frame[0:20]
    if ip_checksum(ip) != '\x00\x00':
        raise Exception("IP header checksum mismatch in HLP response")
    frame = frame[20:]
    udp = frame[0:8]
    frame = frame[8:]
    sport, dport, ulen, ucheck = struct.unpack('>HHHH', udp)
    if sport != 67 or dport != 68:
        raise Exception("Unexpected UDP port in HLP response")
    dhcp = frame[0:28]
    frame = frame[28:]
    op,htype,hlen,hops,xid,secs,flags,ciaddr,yiaddr,siaddr,giaddr = struct.unpack('>4BL2H4L', dhcp)
    chaddr = frame[0:16]
    frame = frame[16:]
    sname = frame[0:64]
    frame = frame[64:]
    file = frame[0:128]
    frame = frame[128:]
    options = frame
    if options[0:4] != '\x63\x82\x53\x63':
        raise Exception("No DHCP magic seen in HLP response")
    options = options[4:]
    # TODO: fully parse and validate DHCPACK options
    if struct.pack('BBB', OPT_DHCP_MESSAGE_TYPE, 1, DHCPACK) not in options:
        raise Exception("DHCPACK not in HLP response")

    dev[0].wait_connected()

    dev[0].request("FILS_HLP_REQ_FLUSH")

def test_fils_sk_hlp_timeout(dev, apdev):
    """FILS SK HLP (rapid commit server timeout)"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(5)
    sock.bind(("127.0.0.2", 67))

    bssid = apdev[0]['bssid']
    params = fils_hlp_config(fils_hlp_wait_time=30)
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    if "OK" not in dev[0].request("FILS_HLP_REQ_FLUSH"):
        raise Exception("Failed to flush pending FILS HLP requests")
    dhcpdisc = build_dhcp(req=True, dhcp_msg=DHCPDISCOVER,
                          chaddr=dev[0].own_addr())
    if "OK" not in dev[0].request("FILS_HLP_REQ_ADD " + "ff:ff:ff:ff:ff:ff " + binascii.hexlify(dhcpdisc)):
        raise Exception("FILS_HLP_REQ_ADD failed")
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)

    (msg,addr) = sock.recvfrom(1000)
    logger.debug("Received DHCP message from %s" % str(addr))
    # Wait for HLP wait timeout to hit
    # FILS: HLP response timeout - continue with association response
    dev[0].wait_connected()

    dev[0].request("FILS_HLP_REQ_FLUSH")

def test_fils_sk_hlp_oom(dev, apdev):
    """FILS SK HLP and hostapd OOM"""
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])

    start_erp_as(apdev[1])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(5)
    sock.bind(("127.0.0.2", 67))

    bssid = apdev[0]['bssid']
    params = fils_hlp_config(fils_hlp_wait_time=500)
    params['dhcp_rapid_commit_proxy'] = '1'
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")
    if "OK" not in dev[0].request("FILS_HLP_REQ_FLUSH"):
        raise Exception("Failed to flush pending FILS HLP requests")
    dhcpdisc = build_dhcp(req=True, dhcp_msg=DHCPDISCOVER,
                          chaddr=dev[0].own_addr())
    if "OK" not in dev[0].request("FILS_HLP_REQ_ADD " + "ff:ff:ff:ff:ff:ff " + binascii.hexlify(dhcpdisc)):
        raise Exception("FILS_HLP_REQ_ADD failed")
    id = dev[0].connect("fils", key_mgmt="FILS-SHA256",
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    with alloc_fail(hapd, 1, "fils_process_hlp"):
        dev[0].select_network(id, freq=2412)
        dev[0].wait_connected()
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    with alloc_fail(hapd, 1, "fils_process_hlp_dhcp"):
        dev[0].select_network(id, freq=2412)
        dev[0].wait_connected()
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    with alloc_fail(hapd, 1, "wpabuf_alloc;fils_process_hlp_dhcp"):
        dev[0].select_network(id, freq=2412)
        dev[0].wait_connected()
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    with alloc_fail(hapd, 1, "wpabuf_alloc;fils_dhcp_handler"):
        dev[0].select_network(id, freq=2412)
        (msg,addr) = sock.recvfrom(1000)
        logger.debug("Received DHCP message from %s" % str(addr))
        dhcpdisc = build_dhcp(req=False, dhcp_msg=DHCPACK,
                              chaddr=dev[0].own_addr(), giaddr="127.0.0.3")
        sock.sendto(dhcpdisc[2+20+8:], addr)
        dev[0].wait_connected()
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    with alloc_fail(hapd, 1, "wpabuf_resize;fils_dhcp_handler"):
        dev[0].select_network(id, freq=2412)
        (msg,addr) = sock.recvfrom(1000)
        logger.debug("Received DHCP message from %s" % str(addr))
        dhcpdisc = build_dhcp(req=False, dhcp_msg=DHCPACK,
                              chaddr=dev[0].own_addr(), giaddr="127.0.0.3")
        sock.sendto(dhcpdisc[2+20+8:], addr)
        dev[0].wait_connected()
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    dev[0].dump_monitor()
    dev[0].select_network(id, freq=2412)
    (msg,addr) = sock.recvfrom(1000)
    logger.debug("Received DHCP message from %s" % str(addr))
    dhcpoffer = build_dhcp(req=False, dhcp_msg=DHCPOFFER, rapid_commit=False,
                           chaddr=dev[0].own_addr(), giaddr="127.0.0.3")
    with alloc_fail(hapd, 1, "wpabuf_resize;fils_dhcp_request"):
        sock.sendto(dhcpoffer[2+20+8:], addr)
        dev[0].wait_connected()
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()

    dev[0].request("FILS_HLP_REQ_FLUSH")
