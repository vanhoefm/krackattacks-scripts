# RADIUS tests
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess
import time

import hostapd

def connect(dev, ssid, wait_connect=True):
    dev.connect(ssid, key_mgmt="WPA-EAP", scan_freq="2412",
                eap="PSK", identity="psk.user@example.com",
                password_hex="0123456789abcdef0123456789abcdef",
                wait_connect=wait_connect)

def test_radius_auth_unreachable(dev, apdev):
    """RADIUS Authentication server unreachable"""
    params = hostapd.wpa2_eap_params(ssid="radius-auth")
    params['auth_server_port'] = "18139"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    connect(dev[0], "radius-auth", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"])
    if ev is None:
        raise Exception("Timeout on EAP start")
    logger.info("Checking for RADIUS retries")
    time.sleep(4)
    mib = hapd.get_mib()
    if "radiusAuthClientAccessRequests" not in mib:
        raise Exception("Missing MIB fields")
    if int(mib["radiusAuthClientAccessRetransmissions"]) < 1:
        raise Exception("Missing RADIUS Authentication retransmission")
    if int(mib["radiusAuthClientPendingRequests"]) < 1:
        raise Exception("Missing pending RADIUS Authentication request")

def test_radius_auth_unreachable2(dev, apdev):
    """RADIUS Authentication server unreachable (2)"""
    subprocess.call(['sudo', 'ip', 'ro', 'replace', '192.168.213.17', 'dev',
                     'lo'])
    params = hostapd.wpa2_eap_params(ssid="radius-auth")
    params['auth_server_addr'] = "192.168.213.17"
    params['auth_server_port'] = "18139"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    subprocess.call(['sudo', 'ip', 'ro', 'del', '192.168.213.17', 'dev', 'lo'])
    connect(dev[0], "radius-auth", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED"])
    if ev is None:
        raise Exception("Timeout on EAP start")
    logger.info("Checking for RADIUS retries")
    time.sleep(4)
    mib = hapd.get_mib()
    if "radiusAuthClientAccessRequests" not in mib:
        raise Exception("Missing MIB fields")
    if int(mib["radiusAuthClientAccessRetransmissions"]) < 1:
        raise Exception("Missing RADIUS Authentication retransmission")

def test_radius_acct_unreachable(dev, apdev):
    """RADIUS Accounting server unreachable"""
    params = hostapd.wpa2_eap_params(ssid="radius-acct")
    params['acct_server_addr'] = "127.0.0.1"
    params['acct_server_port'] = "18139"
    params['acct_server_shared_secret'] = "radius"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    connect(dev[0], "radius-acct")
    logger.info("Checking for RADIUS retries")
    time.sleep(4)
    mib = hapd.get_mib()
    if "radiusAccClientRetransmissions" not in mib:
        raise Exception("Missing MIB fields")
    if int(mib["radiusAccClientRetransmissions"]) < 2:
        raise Exception("Missing RADIUS Accounting retransmissions")
    if int(mib["radiusAccClientPendingRequests"]) < 2:
        raise Exception("Missing pending RADIUS Accounting requests")

def test_radius_acct_unreachable2(dev, apdev):
    """RADIUS Accounting server unreachable(2)"""
    subprocess.call(['sudo', 'ip', 'ro', 'replace', '192.168.213.17', 'dev',
                     'lo'])
    params = hostapd.wpa2_eap_params(ssid="radius-acct")
    params['acct_server_addr'] = "192.168.213.17"
    params['acct_server_port'] = "18139"
    params['acct_server_shared_secret'] = "radius"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    subprocess.call(['sudo', 'ip', 'ro', 'del', '192.168.213.17', 'dev', 'lo'])
    connect(dev[0], "radius-acct")
    logger.info("Checking for RADIUS retries")
    time.sleep(4)
    mib = hapd.get_mib()
    if "radiusAccClientRetransmissions" not in mib:
        raise Exception("Missing MIB fields")
    if int(mib["radiusAccClientRetransmissions"]) < 1 and int(mib["radiusAccClientPendingRequests"]) < 1:
        raise Exception("Missing pending or retransmitted RADIUS Accounting requests")

def test_radius_acct(dev, apdev):
    """RADIUS Accounting"""
    as_hapd = hostapd.Hostapd("as")
    as_mib_start = as_hapd.get_mib(param="radius_server")
    params = hostapd.wpa2_eap_params(ssid="radius-acct")
    params['acct_server_addr'] = "127.0.0.1"
    params['acct_server_port'] = "1813"
    params['acct_server_shared_secret'] = "radius"
    params['radius_auth_req_attr'] = [ "126:s:Operator", "77:s:testing" ]
    params['radius_acct_req_attr'] = [ "126:s:Operator", "77:s:testing" ]
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    connect(dev[0], "radius-acct")
    dev[1].connect("radius-acct", key_mgmt="WPA-EAP", scan_freq="2412",
                   eap="PAX", identity="test-class",
                   password_hex="0123456789abcdef0123456789abcdef")
    dev[2].connect("radius-acct", key_mgmt="WPA-EAP",
                   eap="GPSK", identity="gpsk-cui",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    logger.info("Checking for RADIUS counters")
    count = 0
    while True:
        mib = hapd.get_mib()
        if int(mib['radiusAccClientResponses']) >= 3:
            break
        time.sleep(0.1)
        count += 1
        if count > 10:
            raise Exception("Did not receive Accounting-Response packets")

    if int(mib['radiusAccClientRetransmissions']) > 0:
        raise Exception("Unexpected Accounting-Request retransmission")

    as_mib_end = as_hapd.get_mib(param="radius_server")

    req_s = int(as_mib_start['radiusAccServTotalRequests'])
    req_e = int(as_mib_end['radiusAccServTotalRequests'])
    if req_e < req_s + 2:
        raise Exception("Unexpected RADIUS server acct MIB value")

    acc_s = int(as_mib_start['radiusAuthServAccessAccepts'])
    acc_e = int(as_mib_end['radiusAuthServAccessAccepts'])
    if acc_e < acc_s + 1:
        raise Exception("Unexpected RADIUS server auth MIB value")

def test_radius_acct_interim(dev, apdev):
    """RADIUS Accounting interim update"""
    as_hapd = hostapd.Hostapd("as")
    params = hostapd.wpa2_eap_params(ssid="radius-acct")
    params['acct_server_addr'] = "127.0.0.1"
    params['acct_server_port'] = "1813"
    params['acct_server_shared_secret'] = "radius"
    params['radius_acct_interim_interval'] = "1"
    hostapd.add_ap(apdev[0]['ifname'], params)
    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    connect(dev[0], "radius-acct")
    logger.info("Checking for RADIUS counters")
    as_mib_start = as_hapd.get_mib(param="radius_server")
    time.sleep(3.1)
    as_mib_end = as_hapd.get_mib(param="radius_server")
    req_s = int(as_mib_start['radiusAccServTotalRequests'])
    req_e = int(as_mib_end['radiusAccServTotalRequests'])
    if req_e < req_s + 3:
        raise Exception("Unexpected RADIUS server acct MIB value")

def test_radius_das_disconnect(dev, apdev):
    """RADIUS Dynamic Authorization Extensions - Disconnect"""
    try:
        import pyrad.client
        import pyrad.packet
        import pyrad.dictionary
        import radius_das
    except ImportError:
        return "skip"

    params = hostapd.wpa2_eap_params(ssid="radius-das")
    params['radius_das_port'] = "3799"
    params['radius_das_client'] = "127.0.0.1 secret"
    params['radius_das_require_event_timestamp'] = "1"
    params['own_ip_addr'] = "127.0.0.1"
    params['nas_identifier'] = "nas.example.com"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    connect(dev[0], "radius-das")
    addr = dev[0].p2p_interface_addr()
    sta = hapd.get_sta(addr)
    id = sta['dot1xAuthSessionId']

    dict = pyrad.dictionary.Dictionary("dictionary.radius")

    srv = pyrad.client.Client(server="127.0.0.1", acctport=3799,
                              secret="secret", dict=dict)
    srv.retries = 1
    srv.timeout = 1

    logger.info("Disconnect-Request with incorrect secret")
    req = radius_das.DisconnectPacket(dict=dict, secret="incorrect",
                                      User_Name="foo",
                                      NAS_Identifier="localhost",
                                      Event_Timestamp=int(time.time()))
    logger.debug(req)
    try:
        reply = srv.SendPacket(req)
        raise Exception("Unexpected response to Disconnect-Request")
    except pyrad.client.Timeout:
        logger.info("Disconnect-Request with incorrect secret properly ignored")

    logger.info("Disconnect-Request without Event-Timestamp")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      User_Name="psk.user@example.com")
    logger.debug(req)
    try:
        reply = srv.SendPacket(req)
        raise Exception("Unexpected response to Disconnect-Request")
    except pyrad.client.Timeout:
        logger.info("Disconnect-Request without Event-Timestamp properly ignored")

    logger.info("Disconnect-Request with non-matching Event-Timestamp")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      User_Name="psk.user@example.com",
                                      Event_Timestamp=123456789)
    logger.debug(req)
    try:
        reply = srv.SendPacket(req)
        raise Exception("Unexpected response to Disconnect-Request")
    except pyrad.client.Timeout:
        logger.info("Disconnect-Request with non-matching Event-Timestamp properly ignored")

    logger.info("Disconnect-Request with unsupported attribute")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      User_Name="foo",
                                      User_Password="foo",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectNAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 401:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

    logger.info("Disconnect-Request with invalid Calling-Station-Id")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      User_Name="foo",
                                      Calling_Station_Id="foo",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectNAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 407:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

    logger.info("Disconnect-Request with mismatching User-Name")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      User_Name="foo",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectNAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 503:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

    logger.info("Disconnect-Request with mismatching Calling-Station-Id")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      Calling_Station_Id="12:34:56:78:90:aa",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectNAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 503:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

    logger.info("Disconnect-Request with mismatching Acct-Session-Id")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      Acct_Session_Id="12345678-87654321",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectNAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 503:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")

    logger.info("Disconnect-Request with mismatching NAS-IP-Address")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      NAS_IP_Address="192.168.3.4",
                                      Acct_Session_Id=id,
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectNAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 403:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

    logger.info("Disconnect-Request with mismatching NAS-Identifier")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      NAS_Identifier="unknown.example.com",
                                      Acct_Session_Id=id,
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectNAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 403:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")

    logger.info("Disconnect-Request with matching Acct-Session-Id")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      NAS_IP_Address="127.0.0.1",
                                      NAS_Identifier="nas.example.com",
                                      Acct_Session_Id=id,
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectACK:
        raise Exception("Unexpected response code")

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for disconnection")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection")

    logger.info("Disconnect-Request with matching User-Name")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      NAS_Identifier="nas.example.com",
                                      User_Name="psk.user@example.com",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectACK:
        raise Exception("Unexpected response code")

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for disconnection")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection")

    logger.info("Disconnect-Request with matching Calling-Station-Id")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      NAS_IP_Address="127.0.0.1",
                                      Calling_Station_Id=addr,
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectACK:
        raise Exception("Unexpected response code")

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for disconnection")
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED", "CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection")
    if "CTRL-EVENT-EAP-STARTED" not in ev:
        raise Exception("Unexpected skipping of EAP authentication in reconnection")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection to complete")

    logger.info("Disconnect-Request with matching Calling-Station-Id and non-matching CUI")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      Calling_Station_Id=addr,
                                      Chargeable_User_Identity="foo@example.com",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectACK:
        raise Exception("Unexpected response code")

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for disconnection")
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection")

    logger.info("Disconnect-Request with matching CUI")
    dev[1].connect("radius-das", key_mgmt="WPA-EAP",
                   eap="GPSK", identity="gpsk-cui",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    req = radius_das.DisconnectPacket(dict=dict, secret="secret",
                                      Chargeable_User_Identity="gpsk-chargeable-user-identity",
                                      Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.DisconnectACK:
        raise Exception("Unexpected response code")

    ev = dev[1].wait_event(["CTRL-EVENT-DISCONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for disconnection")
    ev = dev[1].wait_event(["CTRL-EVENT-CONNECTED"])
    if ev is None:
        raise Exception("Timeout while waiting for re-connection")

    ev = dev[0].wait_event(["CTRL-EVENT-DISCONNECTED"], timeout=1)
    if ev is not None:
        raise Exception("Unexpected disconnection")

def test_radius_das_coa(dev, apdev):
    """RADIUS Dynamic Authorization Extensions - CoA"""
    try:
        import pyrad.client
        import pyrad.packet
        import pyrad.dictionary
        import radius_das
    except ImportError:
        return "skip"

    params = hostapd.wpa2_eap_params(ssid="radius-das")
    params['radius_das_port'] = "3799"
    params['radius_das_client'] = "127.0.0.1 secret"
    params['radius_das_require_event_timestamp'] = "1"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    connect(dev[0], "radius-das")
    addr = dev[0].p2p_interface_addr()
    sta = hapd.get_sta(addr)
    id = sta['dot1xAuthSessionId']

    dict = pyrad.dictionary.Dictionary("dictionary.radius")

    srv = pyrad.client.Client(server="127.0.0.1", acctport=3799,
                              secret="secret", dict=dict)
    srv.retries = 1
    srv.timeout = 1

    # hostapd does not currently support CoA-Request, so NAK is expected
    logger.info("CoA-Request with matching Acct-Session-Id")
    req = radius_das.CoAPacket(dict=dict, secret="secret",
                               Acct_Session_Id=id,
                               Event_Timestamp=int(time.time()))
    reply = srv.SendPacket(req)
    logger.debug("RADIUS response from hostapd")
    for i in reply.keys():
        logger.debug("%s: %s" % (i, reply[i]))
    if reply.code != pyrad.packet.CoANAK:
        raise Exception("Unexpected response code")
    if 'Error-Cause' not in reply:
        raise Exception("Missing Error-Cause")
    if reply['Error-Cause'][0] != 405:
        raise Exception("Unexpected Error-Cause: {}".format(reply['Error-Cause']))

def test_radius_ipv6(dev, apdev):
    """RADIUS connection over IPv6"""
    params = {}
    params['ssid'] = 'as'
    params['beacon_int'] = '2000'
    params['radius_server_clients'] = 'auth_serv/radius_clients_ipv6.conf'
    params['radius_server_ipv6'] = '1'
    params['radius_server_auth_port'] = '18129'
    params['radius_server_acct_port'] = '18139'
    params['eap_server'] = '1'
    params['eap_user_file'] = 'auth_serv/eap_user.conf'
    params['ca_cert'] = 'auth_serv/ca.pem'
    params['server_cert'] = 'auth_serv/server.pem'
    params['private_key'] = 'auth_serv/server.key'
    hostapd.add_ap(apdev[1]['ifname'], params)

    params = hostapd.wpa2_eap_params(ssid="radius-ipv6")
    params['auth_server_addr'] = "::0"
    params['auth_server_port'] = "18129"
    params['acct_server_addr'] = "::0"
    params['acct_server_port'] = "18139"
    params['acct_server_shared_secret'] = "radius"
    params['own_ip_addr'] = "::0"
    hostapd.add_ap(apdev[0]['ifname'], params)
    connect(dev[0], "radius-ipv6")

def test_radius_macacl(dev, apdev):
    """RADIUS MAC ACL"""
    params = hostapd.radius_params()
    params["ssid"] = "radius"
    params["macaddr_acl"] = "2"
    hostapd.add_ap(apdev[0]['ifname'], params)
    dev[0].connect("radius", key_mgmt="NONE", scan_freq="2412")

def test_radius_failover(dev, apdev):
    """RADIUS Authentication and Accounting server failover"""
    subprocess.call(['sudo', 'ip', 'ro', 'replace', '192.168.213.17', 'dev',
                     'lo'])
    as_hapd = hostapd.Hostapd("as")
    as_mib_start = as_hapd.get_mib(param="radius_server")
    params = hostapd.wpa2_eap_params(ssid="radius-failover")
    params["auth_server_addr"] = "192.168.213.17"
    params["auth_server_port"] = "1812"
    params["auth_server_shared_secret"] = "testing"
    params['acct_server_addr'] = "192.168.213.17"
    params['acct_server_port'] = "1813"
    params['acct_server_shared_secret'] = "testing"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params, no_enable=True)
    hapd.set("auth_server_addr", "127.0.0.1")
    hapd.set("auth_server_port", "1812")
    hapd.set("auth_server_shared_secret", "radius")
    hapd.set('acct_server_addr', "127.0.0.1")
    hapd.set('acct_server_port', "1813")
    hapd.set('acct_server_shared_secret', "radius")
    hapd.enable()
    ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=30)
    if ev is None:
        raise Exception("AP startup timed out")
        if "AP-ENABLED" not in ev:
            raise Exception("AP startup failed")

    try:
        subprocess.call(['sudo', 'ip', 'ro', 'replace', 'prohibit',
                         '192.168.213.17'])
        dev[0].request("SET EAPOL::authPeriod 5")
        connect(dev[0], "radius-failover", wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=60)
        if ev is None:
            raise Exception("Connection with the AP timed out")
    finally:
        dev[0].request("SET EAPOL::authPeriod 30")
        subprocess.call(['sudo', 'ip', 'ro', 'del', '192.168.213.17'])

    as_mib_end = as_hapd.get_mib(param="radius_server")
    req_s = int(as_mib_start['radiusAccServTotalRequests'])
    req_e = int(as_mib_end['radiusAccServTotalRequests'])
    if req_e <= req_s:
        raise Exception("Unexpected RADIUS server acct MIB value")
