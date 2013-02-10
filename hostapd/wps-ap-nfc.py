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

import wpactrl

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
            wpas = wpactrl.WPACtrl(ctrl)
            return wpas
        except wpactrl.error, error:
            print "Error: ", error
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


def wpas_get_handover_req():
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("NFC_GET_HANDOVER_REQ NDEF WPS").rstrip().decode("hex")


def wpas_put_handover_sel(message):
    wpas = wpas_connect()
    if (wpas == None):
        return
    print wpas.request("NFC_RX_HANDOVER_SEL " + str(message).encode("hex"))


def wps_handover_init(peer):
    print "Trying to initiate WPS handover"

    data = wpas_get_handover_req()
    if (data == None):
        print "Could not get handover request message from hostapd"
        return
    print "Handover request from hostapd: " + data.encode("hex")
    message = nfc.ndef.Message(data)
    print "Parsed handover request: " + message.pretty()

    nfc.llcp.activate(peer);
    time.sleep(0.5)

    client = nfc.handover.HandoverClient()
    try:
        print "Trying handover";
        client.connect()
        print "Connected for handover"
    except nfc.llcp.ConnectRefused:
        print "Handover connection refused"
        nfc.llcp.shutdown()
        client.close()
        return

    print "Sending handover request"

    if not client.send(message):
        print "Failed to send handover request"

    print "Receiving handover response"
    message = client._recv()
    print "Handover select received"
    print message.pretty()
    wpas_put_handover_sel(message)

    print "Remove peer"
    nfc.llcp.shutdown()
    client.close()
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
        peer = clf.listen(ord(os.urandom(1)) + 200, general_bytes)
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
                wps_handover_init(tag)
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
