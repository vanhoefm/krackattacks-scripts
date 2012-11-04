#!/usr/bin/python
#
# Example nfcpy to wpa_supplicant wrapper for WPS NFC operations
# Copyright (c) 2012, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import sys
import time

import nfc
import nfc.ndef

import wpactrl

wpas_ctrl = '/var/run/wpa_supplicant'

def wpas_connect():
    ifaces = []
    if os.path.isdir(wpas_ctrl):
        try:
            ifaces = [os.path.join(wpas_ctrl, i) for i in os.listdir(wpas_ctrl)]
        except OSError, error:
            print "Could not find wpa_supplicant: ", error
            return None

    if len(ifaces) < 1:
        print "No wpa_supplicant control interface found"
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

def main():
    clf = nfc.ContactlessFrontend()

    try:
        while True:
            print "Waiting for a tag to be touched"

            while True:
                tag = clf.poll()
                if tag and tag.ndef:
                    break
                if tag:
                    print "Not an NDEF tag"
                    while tag.is_present:
                        time.sleep(0.2)

            if len(tag.ndef.message):
                message = nfc.ndef.Message(tag.ndef.message)
                print "message type " + message.type

                for record in message:
                    print "record type " + record.type
                    if record.type == "application/vnd.wfa.wsc":
                        print "WPS tag - send to wpa_supplicant"
                        wpas_tag_read(tag.ndef.message)
                        break
            else:
                print "Empty tag"

            print "Remove tag"
            while tag.is_present:
                time.sleep(0.2)

            print "Ok"

    except KeyboardInterrupt:
        raise SystemExit
    finally:
        clf.close()

    raise SystemExit

if __name__ == '__main__':
    main()
