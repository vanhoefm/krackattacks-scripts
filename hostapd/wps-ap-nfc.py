#!/usr/bin/python
#
# Example nfcpy to hostapd wrapper for WPS NFC operations
# Copyright (c) 2012-2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import sys
import time

import nfc
import nfc.ndef
import nfc.llcp
import nfc.handover

import logging
logging.basicConfig()

import wpaspy

wpas_ctrl = '/var/run/hostapd'

def wpas_connect():
    ifaces = []
    if os.path.isdir(wpas_ctrl):
        try:
            ifaces = [os.path.join(wpas_ctrl, i) for i in os.listdir(wpas_ctrl)]
        except OSError, error:
            print "Could not find hostapd: ", error
            return None

    if len(ifaces) < 1:
        print "No hostapd control interface found"
        return None

    for ctrl in ifaces:
        try:
            wpas = wpaspy.Ctrl(ctrl)
            return wpas
        except Exception, e:
            pass
    return None


def wpas_tag_read(message):
    wpas = wpas_connect()
    if (wpas == None):
        return
    print wpas.request("WPS_NFC_TAG_READ " + message.encode("hex"))


def wpas_get_config_token():
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("WPS_NFC_CONFIG_TOKEN NDEF").rstrip().decode("hex")


def wpas_get_password_token():
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("WPS_NFC_TOKEN NDEF").rstrip().decode("hex")


def wpas_get_handover_sel():
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("NFC_GET_HANDOVER_SEL NDEF WPS-CR").rstrip().decode("hex")


def wpas_report_handover(req, sel):
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("NFC_REPORT_HANDOVER RESP WPS " +
                        str(req).encode("hex") + " " +
                        str(sel).encode("hex"))


class HandoverServer(nfc.handover.HandoverServer):
    def __init__(self):
        super(HandoverServer, self).__init__()

    def process_request(self, request):
        print "HandoverServer - request received"
        print "Parsed handover request: " + request.pretty()

        sel = nfc.ndef.HandoverSelectMessage(version="1.2")

        for carrier in request.carriers:
            print "Remote carrier type: " + carrier.type
            if carrier.type == "application/vnd.wfa.wsc":
                print "WPS carrier type match - add WPS carrier record"
                self.received_carrier = carrier.record
                data = wpas_get_handover_sel()
                if data is None:
                    print "Could not get handover select carrier record from hostapd"
                    continue
                print "Handover select carrier record from hostapd:"
                print data.encode("hex")
                self.sent_carrier = data

                message = nfc.ndef.Message(data);
                sel.add_carrier(message[0], "active", message[1:])

        print "Handover select:"
        print sel.pretty()
        print str(sel).encode("hex")

        print "Sending handover select"
        return sel


def wps_handover_resp(peer):
    print "Trying to handle WPS handover"

    srv = HandoverServer()
    srv.sent_carrier = None

    nfc.llcp.activate(peer);

    try:
        print "Trying handover";
        srv.start()
        print "Wait for disconnect"
        while nfc.llcp.connected():
            time.sleep(0.1)
        print "Disconnected after handover"
    except nfc.llcp.ConnectRefused:
        print "Handover connection refused"
        nfc.llcp.shutdown()
        return

    if srv.sent_carrier:
        wpas_report_handover(srv.received_carrier, srv.sent_carrier)

    print "Remove peer"
    nfc.llcp.shutdown()
    print "Done with handover"


def wps_tag_read(tag):
    if len(tag.ndef.message):
        message = nfc.ndef.Message(tag.ndef.message)
        print "message type " + message.type

        for record in message:
            print "record type " + record.type
            if record.type == "application/vnd.wfa.wsc":
                print "WPS tag - send to hostapd"
                wpas_tag_read(tag.ndef.message)
                break
    else:
        print "Empty tag"

    print "Remove tag"
    while tag.is_present:
        time.sleep(0.1)


def wps_write_config_tag(clf):
    print "Write WPS config token"
    data = wpas_get_config_token()
    if (data == None):
        print "Could not get WPS config token from hostapd"
        return

    print "Touch an NFC tag"
    while True:
        tag = clf.poll()
        if tag == None:
            time.sleep(0.1)
            continue
        break

    print "Tag found - writing"
    tag.ndef.message = data
    print "Done - remove tag"
    while tag.is_present:
        time.sleep(0.1)


def wps_write_password_tag(clf):
    print "Write WPS password token"
    data = wpas_get_password_token()
    if (data == None):
        print "Could not get WPS password token from hostapd"
        return

    print "Touch an NFC tag"
    while True:
        tag = clf.poll()
        if tag == None:
            time.sleep(0.1)
            continue
        break

    print "Tag found - writing"
    tag.ndef.message = data
    print "Done - remove tag"
    while tag.is_present:
        time.sleep(0.1)


def find_peer(clf):
    while True:
        if nfc.llcp.connected():
            print "LLCP connected"
        general_bytes = nfc.llcp.startup({})
        peer = clf.listen(ord(os.urandom(1)) + 250, general_bytes)
        if isinstance(peer, nfc.DEP):
            print "listen -> DEP";
            if peer.general_bytes.startswith("Ffm"):
                print "Found DEP"
                return peer
            print "mismatch in general_bytes"
            print peer.general_bytes

        peer = clf.poll(general_bytes)
        if isinstance(peer, nfc.DEP):
            print "poll -> DEP";
            if peer.general_bytes.startswith("Ffm"):
                print "Found DEP"
                return peer
            print "mismatch in general_bytes"
            print peer.general_bytes

        if peer:
            print "Found tag"
            return peer


def main():
    clf = nfc.ContactlessFrontend()

    try:
        if len(sys.argv) > 1 and sys.argv[1] == "write-config":
            wps_write_config_tag(clf)
            raise SystemExit

        if len(sys.argv) > 1 and sys.argv[1] == "write-password":
            wps_write_password_tag(clf)
            raise SystemExit

        while True:
            print "Waiting for a tag or peer to be touched"

            tag = find_peer(clf)
            if isinstance(tag, nfc.DEP):
                wps_handover_resp(tag)
                continue

            if tag.ndef:
                wps_tag_read(tag)
                continue

            print "Not an NDEF tag - remove tag"
            while tag.is_present:
                time.sleep(0.1)

    except KeyboardInterrupt:
        raise SystemExit
    finally:
        clf.close()

    raise SystemExit

if __name__ == '__main__':
    main()
