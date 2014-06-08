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
        return None

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
                if len(eap_req) > 253:
                    logger.info("Need to fragment EAP-Message")
                    # TODO: fragment
                reply.AddAttribute("EAP-Message", eap_req)
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
    if srv is None:
        return "skip"

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
