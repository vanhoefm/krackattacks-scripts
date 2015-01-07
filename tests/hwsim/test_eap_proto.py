# EAP protocol tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hmac
import logging
logger = logging.getLogger()
import select
import struct
import threading
import time

import hostapd
from utils import HwsimSkip

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4

EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
EAP_TYPE_MD5 = 4
EAP_TYPE_OTP = 5
EAP_TYPE_GTC = 6
EAP_TYPE_TLS = 13
EAP_TYPE_LEAP = 17
EAP_TYPE_SIM = 18
EAP_TYPE_TTLS = 21
EAP_TYPE_AKA = 23
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAPV2 = 26
EAP_TYPE_TLV = 33
EAP_TYPE_TNC = 38
EAP_TYPE_FAST = 43
EAP_TYPE_PAX = 46
EAP_TYPE_PSK = 47
EAP_TYPE_SAKE = 48
EAP_TYPE_IKEV2 = 49
EAP_TYPE_AKA_PRIME = 50
EAP_TYPE_GPSK = 51
EAP_TYPE_PWD = 52
EAP_TYPE_EKE = 53

def run_pyrad_server(srv, t_stop, eap_handler):
    srv.RunWithStop(t_stop, eap_handler)

def start_radius_server(eap_handler):
    try:
        import pyrad.server
        import pyrad.packet
        import pyrad.dictionary
    except ImportError:
        raise HwsimSkip("No pyrad modules available")

    class TestServer(pyrad.server.Server):
        def _HandleAuthPacket(self, pkt):
            pyrad.server.Server._HandleAuthPacket(self, pkt)
            if len(pkt[79]) > 1:
                logger.info("Multiple EAP-Message attributes")
                # TODO: reassemble
            eap = pkt[79][0]
            eap_req = self.eap_handler(self.ctx, eap)
            reply = self.CreateReplyPacket(pkt)
            if eap_req:
                while True:
                    if len(eap_req) > 253:
                        reply.AddAttribute("EAP-Message", eap_req[0:253])
                        eap_req = eap_req[253:]
                    else:
                        reply.AddAttribute("EAP-Message", eap_req)
                        break
            else:
                logger.info("No EAP request available")
            reply.code = pyrad.packet.AccessChallenge

            hmac_obj = hmac.new(reply.secret)
            hmac_obj.update(struct.pack("B", reply.code))
            hmac_obj.update(struct.pack("B", reply.id))

            # reply attributes
            reply.AddAttribute("Message-Authenticator",
                               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            attrs = reply._PktEncodeAttributes()

            # Length
            flen = 4 + 16 + len(attrs)
            hmac_obj.update(struct.pack(">H", flen))
            hmac_obj.update(pkt.authenticator)
            hmac_obj.update(attrs)
            del reply[80]
            reply.AddAttribute("Message-Authenticator", hmac_obj.digest())

            self.SendReplyPacket(pkt.fd, reply)

        def RunWithStop(self, t_stop, eap_handler):
            self._poll = select.poll()
            self._fdmap = {}
            self._PrepareSockets()
            self.t_stop = t_stop
            self.eap_handler = eap_handler
            self.ctx = {}

            while not t_stop.is_set():
                for (fd, event) in self._poll.poll(1000):
                    if event == select.POLLIN:
                        try:
                            fdo = self._fdmap[fd]
                            self._ProcessInput(fdo)
                        except pyrad.server.ServerPacketError as err:
                            logger.info("pyrad server dropping packet: " + str(err))
                        except pyrad.packet.PacketError as err:
                            logger.info("pyrad server received invalid packet: " + str(err))
                    else:
                        logger.error("Unexpected event in pyrad server main loop")

    srv = TestServer(dict=pyrad.dictionary.Dictionary("dictionary.radius"),
                     authport=18138, acctport=18139)
    srv.hosts["127.0.0.1"] = pyrad.server.RemoteHost("127.0.0.1",
                                                     "radius",
                                                     "localhost")
    srv.BindToAddress("")
    t_stop = threading.Event()
    t = threading.Thread(target=run_pyrad_server, args=(srv, t_stop, eap_handler))
    t.start()

    return { 'srv': srv, 'stop': t_stop, 'thread': t }

def stop_radius_server(srv):
    srv['stop'].set()
    srv['thread'].join()

def start_ap(ifname):
    params = hostapd.wpa2_eap_params(ssid="eap-test")
    params['auth_server_port'] = "18138"
    hapd = hostapd.add_ap(ifname, params)
    return hapd

def test_eap_proto(dev, apdev):
    """EAP protocol tests"""
    def eap_handler(ctx, req):
        logger.info("eap_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256
        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: MD5 challenge")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_MD5,
                               1, 0xaa, ord('n'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Success - id off by 2")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'] + 1, 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: MD5 challenge")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_MD5,
                               1, 0xaa, ord('n'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Success - id off by 3")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'] + 2, 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: MD5 challenge")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_MD5,
                               1, 0xaa, ord('n'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Notification/Request")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_NOTIFICATION,
                               ord('A'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'] - 1, 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Notification/Request")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_NOTIFICATION,
                               ord('B'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: MD5 challenge")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_MD5,
                               1, 0xaa, ord('n'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'] - 1, 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Notification/Request")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_NOTIFICATION,
                               ord('C'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: MD5 challenge")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_MD5,
                               1, 0xaa, ord('n'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Notification/Request")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_NOTIFICATION,
                               ord('D'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'] - 1, 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Notification/Request")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_NOTIFICATION,
                               ord('E'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Notification/Request (same id)")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'] - 1,
                               4 + 1 + 1,
                               EAP_TYPE_NOTIFICATION,
                               ord('F'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected EAP-Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'] - 2, 4)

        return None

    srv = start_radius_server(eap_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="MD5", identity="user", password="password",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP success")
        dev[0].request("REMOVE_NETWORK all")

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="MD5", identity="user", password="password",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=1)
        if ev is not None:
            raise Exception("Unexpected EAP success")
        dev[0].request("REMOVE_NETWORK all")

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="MD5", identity="user", password="password",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-NOTIFICATION"], timeout=10)
        if ev is None:
            raise Exception("Timeout on EAP notification")
        if ev != "<3>CTRL-EVENT-EAP-NOTIFICATION A":
            raise Exception("Unexpected notification contents: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP success")
        dev[0].request("REMOVE_NETWORK all")

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="MD5", identity="user", password="password",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-NOTIFICATION"], timeout=10)
        if ev is None:
            raise Exception("Timeout on EAP notification")
        if ev != "<3>CTRL-EVENT-EAP-NOTIFICATION B":
            raise Exception("Unexpected notification contents: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP success")
        dev[0].request("REMOVE_NETWORK all")

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="MD5", identity="user", password="password",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-NOTIFICATION"], timeout=10)
        if ev is None:
            raise Exception("Timeout on EAP notification")
        if ev != "<3>CTRL-EVENT-EAP-NOTIFICATION C":
            raise Exception("Unexpected notification contents: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-NOTIFICATION"], timeout=10)
        if ev is None:
            raise Exception("Timeout on EAP notification")
        if ev != "<3>CTRL-EVENT-EAP-NOTIFICATION D":
            raise Exception("Unexpected notification contents: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP success")
        dev[0].request("REMOVE_NETWORK all")

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="MD5", identity="user", password="password",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-NOTIFICATION"], timeout=10)
        if ev is None:
            raise Exception("Timeout on EAP notification")
        if ev != "<3>CTRL-EVENT-EAP-NOTIFICATION E":
            raise Exception("Unexpected notification contents: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-NOTIFICATION"], timeout=10)
        if ev is None:
            raise Exception("Timeout on EAP notification")
        if ev != "<3>CTRL-EVENT-EAP-NOTIFICATION F":
            raise Exception("Unexpected notification contents: " + ev)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP failure")
        dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

EAP_SAKE_VERSION = 2

EAP_SAKE_SUBTYPE_CHALLENGE = 1
EAP_SAKE_SUBTYPE_CONFIRM = 2
EAP_SAKE_SUBTYPE_AUTH_REJECT = 3
EAP_SAKE_SUBTYPE_IDENTITY = 4

EAP_SAKE_AT_RAND_S = 1
EAP_SAKE_AT_RAND_P = 2
EAP_SAKE_AT_MIC_S = 3
EAP_SAKE_AT_MIC_P = 4
EAP_SAKE_AT_SERVERID = 5
EAP_SAKE_AT_PEERID = 6
EAP_SAKE_AT_SPI_S = 7
EAP_SAKE_AT_SPI_P = 8
EAP_SAKE_AT_ANY_ID_REQ = 9
EAP_SAKE_AT_PERM_ID_REQ = 10
EAP_SAKE_AT_ENCR_DATA = 128
EAP_SAKE_AT_IV = 129
EAP_SAKE_AT_PADDING = 130
EAP_SAKE_AT_NEXT_TMPID = 131
EAP_SAKE_AT_MSK_LIFE = 132

def test_eap_proto_sake(dev, apdev):
    """EAP-SAKE protocol tests"""
    def sake_challenge(ctx):
        logger.info("Test: Challenge subtype")
        return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                           4 + 1 + 3 + 18,
                           EAP_TYPE_SAKE,
                           EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE,
                           EAP_SAKE_AT_RAND_S, 18, 0, 0, 0, 0)

    def sake_handler(ctx, req):
        logger.info("sake_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'], 4 + 1,
                               EAP_TYPE_SAKE)

        if ctx['num'] == 2:
            logger.info("Test: Identity subtype without any attributes")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY)

        if ctx['num'] == 3:
            logger.info("Test: Identity subtype")
            return struct.pack(">BBHBBBBBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 4, 0)
        if ctx['num'] == 4:
            logger.info("Test: Identity subtype (different session id)")
            return struct.pack(">BBHBBBBBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 1, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_PERM_ID_REQ, 4, 0)

        if ctx['num'] == 5:
            logger.info("Test: Identity subtype with too short attribute")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 2)

        if ctx['num'] == 6:
            logger.info("Test: Identity subtype with truncated attribute")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 4)

        if ctx['num'] == 7:
            logger.info("Test: Unknown subtype")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, 123)

        if ctx['num'] == 8:
            logger.info("Test: Challenge subtype without any attributes")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE)

        if ctx['num'] == 9:
            logger.info("Test: Challenge subtype with too short AT_RAND_S")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE,
                               EAP_SAKE_AT_RAND_S, 2)

        if ctx['num'] == 10:
            return sake_challenge(ctx)
        if ctx['num'] == 11:
            logger.info("Test: Unexpected Identity subtype")
            return struct.pack(">BBHBBBBBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 4, 0)

        if ctx['num'] == 12:
            return sake_challenge(ctx)
        if ctx['num'] == 13:
            logger.info("Test: Unexpected Challenge subtype")
            return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 18,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE,
                               EAP_SAKE_AT_RAND_S, 18, 0, 0, 0, 0)

        if ctx['num'] == 14:
            return sake_challenge(ctx)
        if ctx['num'] == 15:
            logger.info("Test: Confirm subtype without any attributes")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM)

        if ctx['num'] == 16:
            return sake_challenge(ctx)
        if ctx['num'] == 17:
            logger.info("Test: Confirm subtype with too short AT_MIC_S")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM,
                               EAP_SAKE_AT_MIC_S, 2)

        if ctx['num'] == 18:
            logger.info("Test: Unexpected Confirm subtype")
            return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 18,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM,
                               EAP_SAKE_AT_MIC_S, 18, 0, 0, 0, 0)

        if ctx['num'] == 19:
            return sake_challenge(ctx)
        if ctx['num'] == 20:
            logger.info("Test: Confirm subtype with incorrect AT_MIC_S")
            return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 18,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM,
                               EAP_SAKE_AT_MIC_S, 18, 0, 0, 0, 0)

        return sake_challenge(ctx)

    srv = start_radius_server(sake_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 14):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="SAKE", identity="sake user",
                           password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            dev[0].request("REMOVE_NETWORK all")

        logger.info("Too short password")
        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="SAKE", identity="sake user",
                       password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        time.sleep(0.1)
    finally:
        stop_radius_server(srv)

def test_eap_proto_leap(dev, apdev):
    """EAP-LEAP protocol tests"""
    def leap_handler(ctx, req):
        logger.info("leap_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)

        if ctx['num'] == 2:
            logger.info("Test: Unexpected version")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               0, 0, 0)

        if ctx['num'] == 3:
            logger.info("Test: Invalid challenge length")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 0)

        if ctx['num'] == 4:
            logger.info("Test: Truncated challenge")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 8)

        if ctx['num'] == 5:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 6:
            logger.info("Test: Missing payload in Response")
            return struct.pack(">BBHB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)

        if ctx['num'] == 7:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 8:
            logger.info("Test: Unexpected version in Response")
            return struct.pack(">BBHBBBB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               0, 0, 8)

        if ctx['num'] == 9:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 10:
            logger.info("Test: Invalid challenge length in Response")
            return struct.pack(">BBHBBBB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 0)

        if ctx['num'] == 11:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 12:
            logger.info("Test: Truncated challenge in Response")
            return struct.pack(">BBHBBBB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 24)

        if ctx['num'] == 13:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 14:
            logger.info("Test: Invalid challange value in Response")
            return struct.pack(">BBHBBBB6L", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_LEAP,
                               1, 0, 24,
                               0, 0, 0, 0, 0, 0)

        if ctx['num'] == 15:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 16:
            logger.info("Test: Valid challange value in Response")
            return struct.pack(">BBHBBBB24B", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_LEAP,
                               1, 0, 24,
                               0x48, 0x4e, 0x46, 0xe3, 0x88, 0x49, 0x46, 0xbd,
                               0x28, 0x48, 0xf8, 0x53, 0x82, 0x50, 0x00, 0x04,
                               0x93, 0x50, 0x30, 0xd7, 0x25, 0xea, 0x5f, 0x66)

        if ctx['num'] == 17:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 18:
            logger.info("Test: Success")
            return struct.pack(">BBHB", EAP_CODE_SUCCESS, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)
        # hostapd will drop the next frame in the sequence

        if ctx['num'] == 19:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 20:
            logger.info("Test: Failure")
            return struct.pack(">BBHB", EAP_CODE_FAILURE, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)

        return None

    srv = start_radius_server(leap_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 12):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="LEAP", identity="user", password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            if i == 10:
                logger.info("Wait for additional roundtrip")
                time.sleep(1)
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

def test_eap_proto_md5(dev, apdev):
    """EAP-MD5 protocol tests"""
    def md5_handler(ctx, req):
        logger.info("md5_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_MD5)

        if ctx['num'] == 2:
            logger.info("Test: Zero-length challenge")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_MD5,
                               0)

        if ctx['num'] == 3:
            logger.info("Test: Truncated challenge")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_MD5,
                               1)

        if ctx['num'] == 4:
            logger.info("Test: Shortest possible challenge and name")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_MD5,
                               1, 0xaa, ord('n'))

        return None

    srv = start_radius_server(md5_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 4):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="MD5", identity="user", password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

def test_eap_proto_otp(dev, apdev):
    """EAP-OTP protocol tests"""
    def otp_handler(ctx, req):
        logger.info("otp_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Empty payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_OTP)
        if ctx['num'] == 2:
            logger.info("Test: Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'],
                               4)

        if ctx['num'] == 3:
            logger.info("Test: Challenge included")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_OTP,
                               ord('A'))
        if ctx['num'] == 4:
            logger.info("Test: Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'],
                               4)

        return None

    srv = start_radius_server(otp_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 1):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="OTP", identity="user", password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            dev[0].request("REMOVE_NETWORK all")

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="OTP", identity="user", wait_connect=False)
        ev = dev[0].wait_event(["CTRL-REQ-OTP"])
        if ev is None:
            raise Exception("Request for password timed out")
        id = ev.split(':')[0].split('-')[-1]
        dev[0].request("CTRL-RSP-OTP-" + id + ":password")
        ev = dev[0].wait_event("CTRL-EVENT-EAP-SUCCESS")
        if ev is None:
            raise Exception("Success not reported")
    finally:
        stop_radius_server(srv)

EAP_GPSK_OPCODE_GPSK_1 = 1
EAP_GPSK_OPCODE_GPSK_2 = 2
EAP_GPSK_OPCODE_GPSK_3 = 3
EAP_GPSK_OPCODE_GPSK_4 = 4
EAP_GPSK_OPCODE_FAIL = 5
EAP_GPSK_OPCODE_PROTECTED_FAIL = 6

def test_eap_proto_gpsk(dev, apdev):
    """EAP-GPSK protocol tests"""
    def gpsk_handler(ctx, req):
        logger.info("gpsk_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_GPSK)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unknown opcode")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               255)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected GPSK-3")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_3)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Too short GPSK-1")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Truncated ID_Server")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Missing RAND_Server")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Missing CSuite_List")
            return struct.pack(">BBHBBH8L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Truncated CSuite_List")
            return struct.pack(">BBHBBH8LH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Empty CSuite_List")
            return struct.pack(">BBHBBH8LH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Invalid CSuite_List")
            return struct.pack(">BBHBBH8LHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               1, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 No supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected GPSK-1")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite but too short key")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short GPSK-3")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_3)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in RAND_Peer")
            return struct.pack(">BBHBB8L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 32,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_3,
                               0, 0, 0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing RAND_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in RAND_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8L", 1, 1, 1, 1, 1, 1, 1, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing ID_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8L", 0, 0, 0, 0, 0, 0, 0, 0)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Truncated ID_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LH", 0, 0, 0, 0, 0, 0, 0, 0, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in ID_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 3,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHB", 0, 0, 0, 0, 0, 0, 0, 0, 1, ord('B'))
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBHB8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 3 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 1, ord('A'),
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in ID_Server (same length)")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 3,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[15:47]
            msg += struct.pack(">8LHB", 0, 0, 0, 0, 0, 0, 0, 0, 1, ord('B'))
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing CSuite_Sel")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LH", 0, 0, 0, 0, 0, 0, 0, 0, 0)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in CSuite_Sel")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLH", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing len(PD_Payload_Block)")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLH", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Truncated PD_Payload_Block")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6 + 2,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLHH", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing MAC")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6 + 3,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLHHB",
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 123)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Incorrect MAC")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6 + 3 + 16,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLHHB4L",
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 123,
                               0, 0, 0, 0)
            return msg

        return None

    srv = start_radius_server(gpsk_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 27):
            if i == 12:
                pw = "short"
            else:
                pw = "abcdefghijklmnop0123456789abcdef"
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="GPSK", identity="user", password=pw,
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.05)
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

EAP_EKE_ID = 1
EAP_EKE_COMMIT = 2
EAP_EKE_CONFIRM = 3
EAP_EKE_FAILURE = 4

def test_eap_proto_eke(dev, apdev):
    """EAP-EKE protocol tests"""
    def eke_handler(ctx, req):
        logger.info("eke_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_EKE)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unknown exchange")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_EKE,
                               255)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No NumProposals in EAP-EKE-ID/Request")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: NumProposals=0 in EAP-EKE-ID/Request")
            return struct.pack(">BBHBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated Proposals list in EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               2, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unsupported proposals in EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4B4B4B4B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4 * 4,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               4, 0,
                               0, 0, 0, 0,
                               3, 0, 0, 0,
                               3, 1, 0, 0,
                               3, 1, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing IDType/Identity in EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4B4B4B4B4B",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 5 * 4,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               5, 0,
                               0, 0, 0, 0,
                               3, 0, 0, 0,
                               3, 1, 0, 0,
                               3, 1, 1, 0,
                               3, 1, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4BB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               1, 0,
                               3, 1, 1, 1,
                               255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4BB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               1, 0,
                               3, 1, 1, 1,
                               255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4BB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               1, 0,
                               3, 1, 1, 1,
                               255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected EAP-EKE-Confirm/Request")
            return struct.pack(">BBHBB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_CONFIRM)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short EAP-EKE-Failure/Request")
            return struct.pack(">BBHBB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_FAILURE)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected EAP-EKE-Commit/Request")
            return struct.pack(">BBHBB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_COMMIT)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4BB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               1, 0,
                               3, 1, 1, 1,
                               255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short EAP-EKE-Commit/Request")
            return struct.pack(">BBHBB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_COMMIT)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4BB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               1, 0,
                               1, 1, 1, 1,
                               255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: All zeroes DHComponent_S and empty CBvalue in EAP-EKE-Commit/Request")
            return struct.pack(">BBHBB4L32L",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16 + 128,
                               EAP_TYPE_EKE,
                               EAP_EKE_COMMIT,
                               0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short EAP-EKE-Confirm/Request")
            return struct.pack(">BBHBB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_CONFIRM)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid EAP-EKE-ID/Request")
            return struct.pack(">BBHBBBB4BB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 4 + 1,
                               EAP_TYPE_EKE,
                               EAP_EKE_ID,
                               1, 0,
                               1, 1, 1, 1,
                               255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: All zeroes DHComponent_S and empty CBvalue in EAP-EKE-Commit/Request")
            return struct.pack(">BBHBB4L32L",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16 + 128,
                               EAP_TYPE_EKE,
                               EAP_EKE_COMMIT,
                               0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid PNonce_PS and Auth_S values in EAP-EKE-Confirm/Request")
            return struct.pack(">BBHBB4L8L5L5L",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16 + 2 * 16 + 20 + 20,
                               EAP_TYPE_EKE,
                               EAP_EKE_CONFIRM,
                               0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        return None

    srv = start_radius_server(eke_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 14):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="EKE", identity="user", password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            if i in [ 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 ]:
                ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"],
                                       timeout=10)
                if ev is None:
                    raise Exception("Timeout on EAP failure")
            else:
                time.sleep(0.05)
            dev[0].request("REMOVE_NETWORK all")
            dev[0].dump_monitor()
    finally:
        stop_radius_server(srv)

EAP_PAX_OP_STD_1 = 0x01
EAP_PAX_OP_STD_2 = 0x02
EAP_PAX_OP_STD_3 = 0x03
EAP_PAX_OP_SEC_1 = 0x11
EAP_PAX_OP_SEC_2 = 0x12
EAP_PAX_OP_SEC_3 = 0x13
EAP_PAX_OP_SEC_4 = 0x14
EAP_PAX_OP_SEC_5 = 0x15
EAP_PAX_OP_ACK = 0x21

EAP_PAX_FLAGS_MF = 0x01
EAP_PAX_FLAGS_CE = 0x02
EAP_PAX_FLAGS_AI = 0x04

EAP_PAX_MAC_HMAC_SHA1_128 = 0x01
EAP_PAX_HMAC_SHA256_128 = 0x02

EAP_PAX_DH_GROUP_NONE = 0x00
EAP_PAX_DH_GROUP_2048_MODP = 0x01
EAP_PAX_DH_GROUP_3072_MODP = 0x02
EAP_PAX_DH_GROUP_NIST_ECC_P_256 = 0x03

EAP_PAX_PUBLIC_KEY_NONE = 0x00
EAP_PAX_PUBLIC_KEY_RSAES_OAEP = 0x01
EAP_PAX_PUBLIC_KEY_RSA_PKCS1_V1_5 = 0x02
EAP_PAX_PUBLIC_KEY_EL_GAMAL_NIST_ECC = 0x03

EAP_PAX_ADE_VENDOR_SPECIFIC = 0x01
EAP_PAX_ADE_CLIENT_CHANNEL_BINDING = 0x02
EAP_PAX_ADE_SERVER_CHANNEL_BINDING = 0x03

def test_eap_proto_pax(dev, apdev):
    """EAP-PAX protocol tests"""
    def pax_std_1(ctx):
            logger.info("Test: STD-1")
            ctx['id'] = 10
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               0x16, 0xc9, 0x08, 0x9d, 0x98, 0xa5, 0x6e, 0x1f,
                               0xf0, 0xac, 0xcf, 0xc4, 0x66, 0xcd, 0x2d, 0xbf)

    def pax_handler(ctx, req):
        logger.info("pax_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_PAX)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Minimum length payload")
            return struct.pack(">BBHB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 16,
                               EAP_TYPE_PAX,
                               0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unsupported MAC ID")
            return struct.pack(">BBHBBBBBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, 255, EAP_PAX_DH_GROUP_NONE,
                               EAP_PAX_PUBLIC_KEY_NONE,
                               0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unsupported DH Group ID")
            return struct.pack(">BBHBBBBBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               255, EAP_PAX_PUBLIC_KEY_NONE,
                               0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unsupported Public Key ID")
            return struct.pack(">BBHBBBBBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, 255,
                               0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: More fragments")
            return struct.pack(">BBHBBBBBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, EAP_PAX_FLAGS_MF,
                               EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid ICV")
            return struct.pack(">BBHBBBBBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid ICV in short frame")
            return struct.pack(">BBHBBBBBB3L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 12,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Correct ICV - unsupported op_code")
            ctx['id'] = 10
            return struct.pack(">BBHBBBBBB16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               255, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               0x90, 0x78, 0x97, 0x38, 0x29, 0x94, 0x32, 0xd4,
                               0x81, 0x27, 0xe0, 0xf6, 0x3b, 0x0d, 0xb2, 0xb2)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Correct ICV - CE flag in STD-1")
            ctx['id'] = 10
            return struct.pack(">BBHBBBBBB16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, EAP_PAX_FLAGS_CE,
                               EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               0x9c, 0x98, 0xb4, 0x0b, 0x94, 0x90, 0xde, 0x88,
                               0xb7, 0x72, 0x63, 0x44, 0x1d, 0xe3, 0x7c, 0x5c)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Correct ICV - too short STD-1 payload")
            ctx['id'] = 10
            return struct.pack(">BBHBBBBBB16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               0xda, 0xab, 0x2c, 0xe7, 0x84, 0x41, 0xb5, 0x5c,
                               0xee, 0xcf, 0x62, 0x03, 0xc5, 0x69, 0xcb, 0xf4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Correct ICV - incorrect A length in STD-1")
            ctx['id'] = 10
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0xc4, 0xb0, 0x81, 0xe4, 0x6c, 0x8c, 0x20, 0x23,
                               0x60, 0x46, 0x89, 0xea, 0x94, 0x60, 0xf3, 0x2a)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Correct ICV - extra data in STD-1")
            ctx['id'] = 10
            return struct.pack(">BBHBBBBBBH8LB16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 1 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               1,
                               0x61, 0x49, 0x65, 0x37, 0x21, 0xe8, 0xd8, 0xbf,
                               0xf3, 0x02, 0x01, 0xe5, 0x42, 0x51, 0xd3, 0x34)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected STD-1")
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               0xe5, 0x1d, 0xbf, 0xb8, 0x70, 0x20, 0x5c, 0xba,
                               0x41, 0xbb, 0x34, 0xda, 0x1a, 0x08, 0xe6, 0x8d)

        idx += 1
        if ctx['num'] == idx:
            return pax_std_1(ctx)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: MAC ID changed during session")
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_HMAC_SHA256_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               0xee, 0x00, 0xbf, 0xb8, 0x70, 0x20, 0x5c, 0xba,
                               0x41, 0xbb, 0x34, 0xda, 0x1a, 0x08, 0xe6, 0x8d)

        idx += 1
        if ctx['num'] == idx:
            return pax_std_1(ctx)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: DH Group ID changed during session")
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_2048_MODP,
                               EAP_PAX_PUBLIC_KEY_NONE,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               0xee, 0x01, 0xbf, 0xb8, 0x70, 0x20, 0x5c, 0xba,
                               0x41, 0xbb, 0x34, 0xda, 0x1a, 0x08, 0xe6, 0x8d)

        idx += 1
        if ctx['num'] == idx:
            return pax_std_1(ctx)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Public Key ID changed during session")
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_1, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE,
                               EAP_PAX_PUBLIC_KEY_RSAES_OAEP,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               0xee, 0x02, 0xbf, 0xb8, 0x70, 0x20, 0x5c, 0xba,
                               0x41, 0xbb, 0x34, 0xda, 0x1a, 0x08, 0xe6, 0x8d)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected STD-3")
            ctx['id'] = 10
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_3, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               0x47, 0xbb, 0xc0, 0xf9, 0xb9, 0x69, 0xf5, 0xcb,
                               0x3a, 0xe8, 0xe7, 0xd6, 0x80, 0x28, 0xf2, 0x59)

        idx += 1
        if ctx['num'] == idx:
            return pax_std_1(ctx)
        idx += 1
        if ctx['num'] == idx:
            # TODO: MAC calculation; for now, this gets dropped due to incorrect
            # ICV
            logger.info("Test: STD-3 with CE flag")
            return struct.pack(">BBHBBBBBBH8L16B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 5 + 2 + 32 + 16,
                               EAP_TYPE_PAX,
                               EAP_PAX_OP_STD_3, EAP_PAX_FLAGS_CE,
                               EAP_PAX_MAC_HMAC_SHA1_128,
                               EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE,
                               32, 0, 0, 0, 0, 0, 0, 0, 0,
                               0x8a, 0xc2, 0xf9, 0xf4, 0x8b, 0x75, 0x72, 0xa2,
                               0x4d, 0xd3, 0x1e, 0x54, 0x77, 0x04, 0x05, 0xe2)

        idx += 1
        if ctx['num'] & 0x1 == idx & 0x1:
            logger.info("Test: Default request")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_PAX)
        else:
            logger.info("Test: Default EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

    srv = start_radius_server(pax_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 18):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="PAX", identity="user",
                           password_hex="0123456789abcdef0123456789abcdef",
                           wait_connect=False)
            logger.info("Waiting for EAP method to start")
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.05)
            dev[0].request("REMOVE_NETWORK all")
            dev[0].dump_monitor()

        logger.info("Too short password")
        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="PAX", identity="user",
                       password_hex="0123456789abcdef0123456789abcd",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        time.sleep(0.1)
        dev[0].request("REMOVE_NETWORK all")
        dev[0].dump_monitor()

        logger.info("No password")
        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="PAX", identity="user",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        time.sleep(0.1)
        dev[0].request("REMOVE_NETWORK all")
        dev[0].dump_monitor()
    finally:
        stop_radius_server(srv)

def test_eap_proto_psk(dev, apdev):
    """EAP-PSK protocol tests"""
    def psk_handler(ctx, req):
        logger.info("psk_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_PSK)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Non-zero T in first message")
            return struct.pack(">BBHBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16,
                               EAP_TYPE_PSK, 0xc0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid first message")
            return struct.pack(">BBHBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16,
                               EAP_TYPE_PSK, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short third message")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_PSK)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid first message")
            return struct.pack(">BBHBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16,
                               EAP_TYPE_PSK, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Incorrect T in third message")
            return struct.pack(">BBHBB4L4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16 + 16,
                               EAP_TYPE_PSK, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid first message")
            return struct.pack(">BBHBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16,
                               EAP_TYPE_PSK, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing PCHANNEL in third message")
            return struct.pack(">BBHBB4L4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16 + 16,
                               EAP_TYPE_PSK, 0x80, 0, 0, 0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid first message")
            return struct.pack(">BBHBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16,
                               EAP_TYPE_PSK, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalic MAC_S in third message")
            return struct.pack(">BBHBB4L4L5LB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16 + 16 + 21,
                               EAP_TYPE_PSK, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid first message")
            return struct.pack(">BBHBB4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 16,
                               EAP_TYPE_PSK, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        return None

    srv = start_radius_server(psk_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 6):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="PSK", identity="user",
                           password_hex="0123456789abcdef0123456789abcdef",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            dev[0].request("REMOVE_NETWORK all")

        logger.info("Test: Invalid PSK length")
        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="PSK", identity="user",
                       password_hex="0123456789abcdef0123456789abcd",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                               timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        time.sleep(0.1)
        dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

EAP_SIM_SUBTYPE_START = 10
EAP_SIM_SUBTYPE_CHALLENGE = 11
EAP_SIM_SUBTYPE_NOTIFICATION = 12
EAP_SIM_SUBTYPE_REAUTHENTICATION = 13
EAP_SIM_SUBTYPE_CLIENT_ERROR = 14

EAP_AKA_SUBTYPE_CHALLENGE = 1
EAP_AKA_SUBTYPE_AUTHENTICATION_REJECT = 2
EAP_AKA_SUBTYPE_SYNCHRONIZATION_FAILURE = 4
EAP_AKA_SUBTYPE_IDENTITY = 5
EAP_AKA_SUBTYPE_NOTIFICATION = 12
EAP_AKA_SUBTYPE_REAUTHENTICATION = 13
EAP_AKA_SUBTYPE_CLIENT_ERROR = 14

EAP_SIM_AT_RAND = 1
EAP_SIM_AT_AUTN = 2
EAP_SIM_AT_RES = 3
EAP_SIM_AT_AUTS = 4
EAP_SIM_AT_PADDING = 6
EAP_SIM_AT_NONCE_MT = 7
EAP_SIM_AT_PERMANENT_ID_REQ = 10
EAP_SIM_AT_MAC = 11
EAP_SIM_AT_NOTIFICATION = 12
EAP_SIM_AT_ANY_ID_REQ = 13
EAP_SIM_AT_IDENTITY = 14
EAP_SIM_AT_VERSION_LIST = 15
EAP_SIM_AT_SELECTED_VERSION = 16
EAP_SIM_AT_FULLAUTH_ID_REQ = 17
EAP_SIM_AT_COUNTER = 19
EAP_SIM_AT_COUNTER_TOO_SMALL = 20
EAP_SIM_AT_NONCE_S = 21
EAP_SIM_AT_CLIENT_ERROR_CODE = 22
EAP_SIM_AT_KDF_INPUT = 23
EAP_SIM_AT_KDF = 24
EAP_SIM_AT_IV = 129
EAP_SIM_AT_ENCR_DATA = 130
EAP_SIM_AT_NEXT_PSEUDONYM = 132
EAP_SIM_AT_NEXT_REAUTH_ID = 133
EAP_SIM_AT_CHECKCODE = 134
EAP_SIM_AT_RESULT_IND = 135
EAP_SIM_AT_BIDDING = 136

def test_eap_proto_aka(dev, apdev):
    """EAP-AKA protocol tests"""
    def aka_handler(ctx, req):
        logger.info("aka_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_AKA)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unknown subtype")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_AKA, 255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Client Error")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_CLIENT_ERROR)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short attribute header")
            return struct.pack(">BBHBBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 3,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0, 255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated attribute")
            return struct.pack(">BBHBBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0, 255,
                               255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short attribute data")
            return struct.pack(">BBHBBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0, 255,
                               0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Skippable/non-skippable unrecognzized attribute")
            return struct.pack(">BBHBBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 10,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               255, 1, 0, 127, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request without ID type")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID (duplicate)")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request FULLAUTH_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_FULLAUTH_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request FULLAUTH_ID (duplicate)")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_FULLAUTH_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request FULLAUTH_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_FULLAUTH_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request PERMANENT_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_PERMANENT_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request PERMANENT_ID (duplicate)")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_PERMANENT_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with no attributes")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_CHALLENGE, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: AKA Challenge with BIDDING")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_BIDDING, 1, 0x8000)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification with no attributes")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification indicating success, but no MAC")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 32768)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification indicating success, but invalid MAC value")
            return struct.pack(">BBHBBHBBHBBH4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4 + 20,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 32768,
                               EAP_SIM_AT_MAC, 5, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification indicating success with zero-key MAC")
            return struct.pack(">BBHBBHBBHBBH16B", EAP_CODE_REQUEST,
                               ctx['id'] - 2,
                               4 + 1 + 3 + 4 + 20,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 32768,
                               EAP_SIM_AT_MAC, 5, 0,
                               0xbe, 0x2e, 0xbb, 0xa9, 0xfa, 0x2e, 0x82, 0x36,
                               0x37, 0x8c, 0x32, 0x41, 0xb7, 0xc7, 0x58, 0xa3)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification before auth")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 16384)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification before auth")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 16385)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification with unrecognized non-failure")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 0xc000)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification before auth (duplicate)")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 0xc000)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Re-authentication (unexpected) with no attributes")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_REAUTHENTICATION,
                               0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: AKA Challenge with Checkcode claiming identity round was used")
            return struct.pack(">BBHBBHBBH5L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_CHECKCODE, 6, 0, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: AKA Challenge with Checkcode claiming no identity round was used")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_CHECKCODE, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: AKA Challenge with mismatching Checkcode value")
            return struct.pack(">BBHBBHBBH5L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_CHECKCODE, 6, 0, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Re-authentication (unexpected) with Checkcode claimin identity round was used")
            return struct.pack(">BBHBBHBBH5L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_REAUTHENTICATION,
                               0,
                               EAP_SIM_AT_CHECKCODE, 6, 0, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_RAND length")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_RAND, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_AUTN length")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_AUTN, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unencrypted AT_PADDING")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_PADDING, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_NONCE_MT length")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_NONCE_MT, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_MAC length")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_MAC, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_NOTIFICATION length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_NOTIFICATION, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: AT_IDENTITY overflow")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_IDENTITY, 1, 0xffff)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected AT_VERSION_LIST")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_VERSION_LIST, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_SELECTED_VERSION length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_SELECTED_VERSION, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unencrypted AT_COUNTER")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_COUNTER, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unencrypted AT_COUNTER_TOO_SMALL")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_COUNTER_TOO_SMALL, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unencrypted AT_NONCE_S")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_NONCE_S, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_CLIENT_ERROR_CODE length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_CLIENT_ERROR_CODE, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_IV length")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_IV, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_ENCR_DATA length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_ENCR_DATA, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unencrypted AT_NEXT_PSEUDONYM")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_NEXT_PSEUDONYM, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unencrypted AT_NEXT_REAUTH_ID")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_NEXT_REAUTH_ID, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_RES length")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_RES, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_RES length")
            return struct.pack(">BBHBBHBBH5L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_RES, 6, 0xffff, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_AUTS length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_AUTS, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_CHECKCODE length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_CHECKCODE, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_RESULT_IND length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_RESULT_IND, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected AT_KDF_INPUT")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected AT_KDF")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_KDF, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_BIDDING length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_BIDDING, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        return None

    srv = start_radius_server(aka_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 49):
            eap = "AKA AKA'" if i == 11 else "AKA"
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap=eap, identity="0232010000000000",
                           password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            if i in [ 0, 15 ]:
                time.sleep(0.1)
            else:
                ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"],
                                       timeout=10)
                if ev is None:
                    raise Exception("Timeout on EAP failure")
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

def test_eap_proto_aka_prime(dev, apdev):
    """EAP-AKA' protocol tests"""
    def aka_prime_handler(ctx, req):
        logger.info("aka_prime_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_AKA_PRIME)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with no attributes")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with empty AT_KDF_INPUT")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with AT_KDF_INPUT")
            return struct.pack(">BBHBBHBBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'))
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with duplicated KDF")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 3 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_KDF, 1, 2,
                               EAP_SIM_AT_KDF, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with multiple KDF proposals")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 3 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with incorrect KDF selected")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with multiple KDF proposals")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 3 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with selected KDF not duplicated")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 3 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with multiple KDF proposals")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 3 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with selected KDF duplicated (missing MAC, RAND, AUTN)")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with multiple unsupported KDF proposals")
            return struct.pack(">BBHBBHBBHBBBBBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 2 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with multiple KDF proposals")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 3 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with invalid MAC, RAND, AUTN values)")
            return struct.pack(">BBHBBHBBHBBBBBBHBBHBBHBBHBBH4LBBH4LBBH4L",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4 * 4 + 20 + 20 + 20,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_MAC, 5, 0, 0, 0, 0, 0,
                               EAP_SIM_AT_RAND, 5, 0, 0, 0, 0, 0,
                               EAP_SIM_AT_AUTN, 5, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge - AMF separation bit not set)")
            return struct.pack(">BBHBBHBBHBBBBBBHBBH4LBBH4LBBH4L",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4 + 20 + 20 + 20,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_MAC, 5, 0, 1, 2, 3, 4,
                               EAP_SIM_AT_RAND, 5, 0, 5, 6, 7, 8,
                               EAP_SIM_AT_AUTN, 5, 0, 9, 10,
                               0x2fda8ef7, 0xbba518cc)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge - Invalid MAC")
            return struct.pack(">BBHBBHBBHBBBBBBHBBH4LBBH4LBBH4L",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4 + 20 + 20 + 20,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_MAC, 5, 0, 1, 2, 3, 4,
                               EAP_SIM_AT_RAND, 5, 0, 5, 6, 7, 8,
                               EAP_SIM_AT_AUTN, 5, 0, 0xffffffff, 0xffffffff,
                               0xd1f90322, 0x40514cb4)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge - Valid MAC")
            return struct.pack(">BBHBBHBBHBBBBBBHBBH4LBBH4LBBH4L",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4 + 20 + 20 + 20,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 1, ord('a'), ord('b'),
                               ord('c'), ord('d'),
                               EAP_SIM_AT_KDF, 1, 1,
                               EAP_SIM_AT_MAC, 5, 0,
                               0xf4a3c1d3, 0x7c901401, 0x34bd8b01, 0x6f7fa32f,
                               EAP_SIM_AT_RAND, 5, 0, 5, 6, 7, 8,
                               EAP_SIM_AT_AUTN, 5, 0, 0xffffffff, 0xffffffff,
                               0xd1f90322, 0x40514cb4)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_KDF_INPUT length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_KDF_INPUT, 2, 0xffff, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid AT_KDF length")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_IDENTITY, 0,
                               EAP_SIM_AT_KDF, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Challenge with large number of KDF proposals")
            return struct.pack(">BBHBBHBBHBBHBBHBBHBBHBBHBBHBBHBBHBBHBBHBBH",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 12 * 4,
                               EAP_TYPE_AKA_PRIME, EAP_AKA_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_KDF, 1, 255,
                               EAP_SIM_AT_KDF, 1, 254,
                               EAP_SIM_AT_KDF, 1, 253,
                               EAP_SIM_AT_KDF, 1, 252,
                               EAP_SIM_AT_KDF, 1, 251,
                               EAP_SIM_AT_KDF, 1, 250,
                               EAP_SIM_AT_KDF, 1, 249,
                               EAP_SIM_AT_KDF, 1, 248,
                               EAP_SIM_AT_KDF, 1, 247,
                               EAP_SIM_AT_KDF, 1, 246,
                               EAP_SIM_AT_KDF, 1, 245,
                               EAP_SIM_AT_KDF, 1, 244)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        return None

    srv = start_radius_server(aka_prime_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 16):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="AKA'", identity="6555444333222111",
                           password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            if i in [ 0 ]:
                time.sleep(0.1)
            else:
                ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"],
                                       timeout=10)
                if ev is None:
                    raise Exception("Timeout on EAP failure")
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

def test_eap_proto_sim(dev, apdev):
    """EAP-SIM protocol tests"""
    def sim_handler(ctx, req):
        logger.info("sim_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_SIM)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected AT_AUTN")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_AUTN, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short AT_VERSION_LIST")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: AT_VERSION_LIST overflow")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 1, 0xffff)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected AT_AUTS")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_AUTS, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected AT_CHECKCODE")
            return struct.pack(">BBHBBHBBHL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_CHECKCODE, 2, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No AT_VERSION_LIST in Start")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No support version in AT_VERSION_LIST")
            return struct.pack(">BBHBBHBBH4B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 3, 2, 3, 4, 5)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)


        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request without ID type")
            return struct.pack(">BBHBBHBBH2H", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID (duplicate)")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request FULLAUTH_ID")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_FULLAUTH_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request FULLAUTH_ID (duplicate)")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_FULLAUTH_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request ANY_ID")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_ANY_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request FULLAUTH_ID")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_FULLAUTH_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request PERMANENT_ID")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_PERMANENT_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Identity request PERMANENT_ID (duplicate)")
            return struct.pack(">BBHBBHBBH2HBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_START, 0,
                               EAP_SIM_AT_VERSION_LIST, 2, 2, 1, 0,
                               EAP_SIM_AT_PERMANENT_ID_REQ, 1, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No AT_MAC and AT_RAND in Challenge")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_CHALLENGE, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No AT_RAND in Challenge")
            return struct.pack(">BBHBBHBBH4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 20,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_MAC, 5, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Insufficient number of challenges in Challenge")
            return struct.pack(">BBHBBHBBH4LBBH4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 20 + 20,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_RAND, 5, 0, 0, 0, 0, 0,
                               EAP_SIM_AT_MAC, 5, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too many challenges in Challenge")
            return struct.pack(">BBHBBHBBH4L4L4L4LBBH4L", EAP_CODE_REQUEST,
                               ctx['id'],
                               4 + 1 + 3 + 4 + 4 * 16 + 20,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_RAND, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               EAP_SIM_AT_MAC, 5, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Same RAND multiple times in Challenge")
            return struct.pack(">BBHBBHBBH4L4L4LBBH4L", EAP_CODE_REQUEST,
                               ctx['id'],
                               4 + 1 + 3 + 4 + 3 * 16 + 20,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_CHALLENGE, 0,
                               EAP_SIM_AT_RAND, 13, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                               0, 0, 0, 0,
                               EAP_SIM_AT_MAC, 5, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification with no attributes")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_NOTIFICATION, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification indicating success, but no MAC")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 32768)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification indicating success, but invalid MAC value")
            return struct.pack(">BBHBBHBBHBBH4L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4 + 20,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 32768,
                               EAP_SIM_AT_MAC, 5, 0, 0, 0, 0, 0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification before auth")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 16384)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification before auth")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 16385)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification with unrecognized non-failure")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 0xc000)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Notification before auth (duplicate)")
            return struct.pack(">BBHBBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_NOTIFICATION, 0,
                               EAP_SIM_AT_NOTIFICATION, 1, 0xc000)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Re-authentication (unexpected) with no attributes")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_REAUTHENTICATION,
                               0)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Client Error")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_SIM, EAP_SIM_SUBTYPE_CLIENT_ERROR)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unknown subtype")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_SIM, 255)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        return None

    srv = start_radius_server(sim_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 25):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="SIM", identity="1232010000000000",
                           password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            if i in [ 0 ]:
                time.sleep(0.1)
            else:
                ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"],
                                       timeout=10)
                if ev is None:
                    raise Exception("Timeout on EAP failure")
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

def test_eap_proto_ikev2(dev, apdev):
    """EAP-IKEv2 protocol tests"""
    def ikev2_handler(ctx, req):
        logger.info("ikev2_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_IKEV2)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated Message Length field")
            return struct.pack(">BBHBB3B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 3,
                               EAP_TYPE_IKEV2, 0x80, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short Message Length value")
            return struct.pack(">BBHBBLB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4 + 1,
                               EAP_TYPE_IKEV2, 0x80, 0, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated message")
            return struct.pack(">BBHBBL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4,
                               EAP_TYPE_IKEV2, 0x80, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated message(2)")
            return struct.pack(">BBHBBL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4,
                               EAP_TYPE_IKEV2, 0x80, 0xffffffff)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated message(3)")
            return struct.pack(">BBHBBL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4,
                               EAP_TYPE_IKEV2, 0xc0, 0xffffffff)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated message(4)")
            return struct.pack(">BBHBBL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4,
                               EAP_TYPE_IKEV2, 0xc0, 10000000)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too long fragments (first fragment)")
            return struct.pack(">BBHBBLB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 4 + 1,
                               EAP_TYPE_IKEV2, 0xc0, 2, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too long fragments (second fragment)")
            return struct.pack(">BBHBB2B", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2,
                               EAP_TYPE_IKEV2, 0x00, 2, 3)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No Message Length field in first fragment")
            return struct.pack(">BBHBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 1,
                               EAP_TYPE_IKEV2, 0x40, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: ICV before keys")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_IKEV2, 0x20)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unsupported IKEv2 header version")
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 28,
                               EAP_TYPE_IKEV2, 0x00,
                               0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Incorrect IKEv2 header Length")
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 28,
                               EAP_TYPE_IKEV2, 0x00,
                               0, 0, 0, 0,
                               0, 0x20, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected IKEv2 Exchange Type in SA_INIT state")
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 28,
                               EAP_TYPE_IKEV2, 0x00,
                               0, 0, 0, 0,
                               0, 0x20, 0, 0, 0, 28)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected IKEv2 Message ID in SA_INIT state")
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 28,
                               EAP_TYPE_IKEV2, 0x00,
                               0, 0, 0, 0,
                               0, 0x20, 34, 0, 1, 28)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected IKEv2 Flags value")
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 28,
                               EAP_TYPE_IKEV2, 0x00,
                               0, 0, 0, 0,
                               0, 0x20, 34, 0, 0, 28)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected IKEv2 Flags value(2)")
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 28,
                               EAP_TYPE_IKEV2, 0x00,
                               0, 0, 0, 0,
                               0, 0x20, 34, 0x20, 0, 28)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No SAi1 in SA_INIT")
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 28,
                               EAP_TYPE_IKEV2, 0x00,
                               0, 0, 0, 0,
                               0, 0x20, 34, 0x08, 0, 28)

        def build_ike(id, next=0, exch_type=34, flags=0x00, ike=''):
            return struct.pack(">BBHBB2L2LBBBBLL", EAP_CODE_REQUEST, id,
                               4 + 1 + 1 + 28 + len(ike),
                               EAP_TYPE_IKEV2, flags,
                               0, 0, 0, 0,
                               next, 0x20, exch_type, 0x08, 0,
                               28 + len(ike)) + ike

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected extra data after payloads")
            return build_ike(ctx['id'], ike=struct.pack(">B", 1))

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated payload header")
            return build_ike(ctx['id'], next=128, ike=struct.pack(">B", 1))

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too small payload header length")
            ike = struct.pack(">BBH", 0, 0, 3)
            return build_ike(ctx['id'], next=128, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too large payload header length")
            ike = struct.pack(">BBH", 0, 0, 5)
            return build_ike(ctx['id'], next=128, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unsupported payload (non-critical and critical)")
            ike = struct.pack(">BBHBBH", 129, 0, 4, 0, 0x01, 4)
            return build_ike(ctx['id'], next=128, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Certificate and empty SAi1")
            ike = struct.pack(">BBHBBH", 33, 0, 4, 0, 0, 4)
            return build_ike(ctx['id'], next=37, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short proposal")
            ike = struct.pack(">BBHBBHBBB", 0, 0, 4 + 7,
                              0, 0, 7, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too small proposal length in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              0, 0, 7, 0, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too large proposal length in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              0, 0, 9, 0, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected proposal type in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              1, 0, 8, 0, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected Protocol ID in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              0, 0, 8, 0, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected proposal number in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              0, 0, 8, 0, 1, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Not enough room for SPI in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              0, 0, 8, 1, 1, 1, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected SPI in SAi1")
            ike = struct.pack(">BBHBBHBBBBB", 0, 0, 4 + 9,
                              0, 0, 9, 1, 1, 1, 0, 1)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No transforms in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              0, 0, 8, 1, 1, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short transform in SAi1")
            ike = struct.pack(">BBHBBHBBBB", 0, 0, 4 + 8,
                              0, 0, 8, 1, 1, 0, 1)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too small transform length in SAi1")
            ike = struct.pack(">BBHBBHBBBBBBHBBH", 0, 0, 4 + 8 + 8,
                              0, 0, 8 + 8, 1, 1, 0, 1,
                              0, 0, 7, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too large transform length in SAi1")
            ike = struct.pack(">BBHBBHBBBBBBHBBH", 0, 0, 4 + 8 + 8,
                              0, 0, 8 + 8, 1, 1, 0, 1,
                              0, 0, 9, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected Transform type in SAi1")
            ike = struct.pack(">BBHBBHBBBBBBHBBH", 0, 0, 4 + 8 + 8,
                              0, 0, 8 + 8, 1, 1, 0, 1,
                              1, 0, 8, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No transform attributes in SAi1")
            ike = struct.pack(">BBHBBHBBBBBBHBBH", 0, 0, 4 + 8 + 8,
                              0, 0, 8 + 8, 1, 1, 0, 1,
                              0, 0, 8, 0, 0, 0)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No transform attr for AES and unexpected data after transforms in SAi1")
            tlen1 = 8 + 3
            tlen2 = 8 + 4
            tlen3 = 8 + 4
            tlen = tlen1 + tlen2 + tlen3
            ike = struct.pack(">BBHBBHBBBBBBHBBH3BBBHBBHHHBBHBBHHHB",
                              0, 0, 4 + 8 + tlen + 1,
                              0, 0, 8 + tlen + 1, 1, 1, 0, 3,
                              3, 0, tlen1, 1, 0, 12, 1, 2, 3,
                              3, 0, tlen2, 1, 0, 12, 0, 128,
                              0, 0, tlen3, 1, 0, 12, 0x8000 | 14, 127,
                              1)
            return build_ike(ctx['id'], next=33, ike=ike)

        def build_sa(next=0):
            tlen = 5 * 8
            return struct.pack(">BBHBBHBBBBBBHBBHBBHBBHBBHBBHBBHBBHBBHBBH",
                               next, 0, 4 + 8 + tlen,
                               0, 0, 8 + tlen, 1, 1, 0, 5,
                               3, 0, 8, 1, 0, 3,
                               3, 0, 8, 2, 0, 1,
                               3, 0, 8, 3, 0, 1,
                               3, 0, 8, 4, 0, 5,
                               0, 0, 8, 241, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid proposal, but no KEi in SAi1")
            ike = build_sa()
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Empty KEi in SAi1")
            ike = build_sa(next=34) + struct.pack(">BBH", 0, 0, 4)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Mismatch in DH Group in SAi1")
            ike = build_sa(next=34)
            ike += struct.pack(">BBHHH", 0, 0, 4 + 4 + 96, 12345, 0)
            ike += 96*'\x00'
            return build_ike(ctx['id'], next=33, ike=ike)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid DH public value length in SAi1")
            ike = build_sa(next=34)
            ike += struct.pack(">BBHHH", 0, 0, 4 + 4 + 96, 5, 0)
            ike += 96*'\x00'
            return build_ike(ctx['id'], next=33, ike=ike)

        def build_ke(next=0):
            ke = struct.pack(">BBHHH", next, 0, 4 + 4 + 192, 5, 0)
            ke += 192*'\x00'
            return ke

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid proposal and KEi, but no Ni in SAi1")
            ike = build_sa(next=34)
            ike += build_ke()
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short Ni in SAi1")
            ike = build_sa(next=34)
            ike += build_ke(next=40)
            ike += struct.pack(">BBH", 0, 0, 4)
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too long Ni in SAi1")
            ike = build_sa(next=34)
            ike += build_ke(next=40)
            ike += struct.pack(">BBH", 0, 0, 4 + 257) + 257*'\x00'
            return build_ike(ctx['id'], next=33, ike=ike)

        def build_ni(next=0):
            return struct.pack(">BBH", next, 0, 4 + 256) + 256*'\x00'

        def build_sai1(id):
            ike = build_sa(next=34)
            ike += build_ke(next=40)
            ike += build_ni()
            return build_ike(ctx['id'], next=33, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid proposal, KEi, and Ni in SAi1")
            return build_sai1(ctx['id'])
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: EAP-Failure")
            return struct.pack(">BBH", EAP_CODE_FAILURE, ctx['id'], 4)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid proposal, KEi, and Ni in SAi1")
            return build_sai1(ctx['id'])
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: No integrity checksum")
            ike = ''
            return build_ike(ctx['id'], next=37, ike=ike)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid proposal, KEi, and Ni in SAi1")
            return build_sai1(ctx['id'])
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Truncated integrity checksum")
            return struct.pack(">BBHBB",
                               EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_IKEV2, 0x20)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Valid proposal, KEi, and Ni in SAi1")
            return build_sai1(ctx['id'])
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Invalid integrity checksum")
            ike = ''
            return build_ike(ctx['id'], next=37, flags=0x20, ike=ike)

        return None

    srv = start_radius_server(ikev2_handler)

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(49):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="IKEV2", identity="user",
                           password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            if i in [ 40, 45 ]:
                ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE"],
                                       timeout=10)
                if ev is None:
                    raise Exception("Timeout on EAP failure")
            else:
                time.sleep(0.05)
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)
