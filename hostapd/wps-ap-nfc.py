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
import argparse

import nfc
import nfc.ndef
import nfc.llcp
import nfc.handover

import logging

import wpaspy

wpas_ctrl = '/var/run/hostapd'
continue_loop = True

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
    if "FAIL" in wpas.request("WPS_NFC_TAG_READ " + str(message).encode("hex")):
        return False
    return True


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
    def __init__(self, llc):
        super(HandoverServer, self).__init__(llc)
        self.ho_server_processing = False
        self.success = False

    def process_request(self, request):
        print "HandoverServer - request received"
        try:
            print "Parsed handover request: " + request.pretty()
        except Exception, e:
            print e
        print str(request).encode("hex")

        sel = nfc.ndef.HandoverSelectMessage(version="1.2")

        for carrier in request.carriers:
            print "Remote carrier type: " + carrier.type
            if carrier.type == "application/vnd.wfa.wsc":
                print "WPS carrier type match - add WPS carrier record"
                data = wpas_get_handover_sel()
                if data is None:
                    print "Could not get handover select carrier record from hostapd"
                    continue
                print "Handover select carrier record from hostapd:"
                print data.encode("hex")
                wpas_report_handover(carrier.record, data)

                message = nfc.ndef.Message(data);
                sel.add_carrier(message[0], "active", message[1:])

        print "Handover select:"
        try:
            print sel.pretty()
        except Exception, e:
            print e
        print str(sel).encode("hex")

        print "Sending handover select"
        self.success = True
        return sel


def wps_tag_read(tag):
    success = False
    if len(tag.ndef.message):
        for record in tag.ndef.message:
            print "record type " + record.type
            if record.type == "application/vnd.wfa.wsc":
                print "WPS tag - send to hostapd"
                success = wpas_tag_read(tag.ndef.message)
                break
    else:
        print "Empty tag"

    return success


def rdwr_connected_write(tag):
    print "Tag found - writing"
    global write_data
    tag.ndef.message = str(write_data)
    print "Done - remove tag"
    global only_one
    if only_one:
        global continue_loop
        continue_loop = False
    global write_wait_remove
    while write_wait_remove and tag.is_present:
        time.sleep(0.1)

def wps_write_config_tag(clf, wait_remove=True):
    print "Write WPS config token"
    global write_data, write_wait_remove
    write_wait_remove = wait_remove
    write_data = wpas_get_config_token()
    if write_data == None:
        print "Could not get WPS config token from hostapd"
        return

    print "Touch an NFC tag"
    clf.connect(rdwr={'on-connect': rdwr_connected_write})


def wps_write_password_tag(clf, wait_remove=True):
    print "Write WPS password token"
    global write_data, write_wait_remove
    write_wait_remove = wait_remove
    write_data = wpas_get_password_token()
    if write_data == None:
        print "Could not get WPS password token from hostapd"
        return

    print "Touch an NFC tag"
    clf.connect(rdwr={'on-connect': rdwr_connected_write})


def rdwr_connected(tag):
    global only_one, no_wait
    print "Tag connected: " + str(tag)

    if tag.ndef:
        print "NDEF tag: " + tag.type
        try:
            print tag.ndef.message.pretty()
        except Exception, e:
            print e
        success = wps_tag_read(tag)
        if only_one and success:
            global continue_loop
            continue_loop = False
    else:
        print "Not an NDEF tag - remove tag"

    return not no_wait


def llcp_startup(clf, llc):
    print "Start LLCP server"
    global srv
    srv = HandoverServer(llc)
    return llc

def llcp_connected(llc):
    print "P2P LLCP connected"
    global wait_connection
    wait_connection = False
    global srv
    srv.start()
    return True


def main():
    clf = nfc.ContactlessFrontend()

    parser = argparse.ArgumentParser(description='nfcpy to hostapd integration for WPS NFC operations')
    parser.add_argument('-d', const=logging.DEBUG, default=logging.INFO,
                        action='store_const', dest='loglevel',
                        help='verbose debug output')
    parser.add_argument('-q', const=logging.WARNING, action='store_const',
                        dest='loglevel', help='be quiet')
    parser.add_argument('--only-one', '-1', action='store_true',
                        help='run only one operation and exit')
    parser.add_argument('--no-wait', action='store_true',
                        help='do not wait for tag to be removed before exiting')
    parser.add_argument('command', choices=['write-config',
                                            'write-password'],
                        nargs='?')
    args = parser.parse_args()

    global only_one
    only_one = args.only_one

    global no_wait
    no_wait = args.no_wait

    logging.basicConfig(level=args.loglevel)

    try:
        if not clf.open("usb"):
            print "Could not open connection with an NFC device"
            raise SystemExit

        if args.command == "write-config":
            wps_write_config_tag(clf, wait_remove=not args.no_wait)
            raise SystemExit

        if args.command == "write-password":
            wps_write_password_tag(clf, wait_remove=not args.no_wait)
            raise SystemExit

        global continue_loop
        while continue_loop:
            print "Waiting for a tag or peer to be touched"
            wait_connection = True
            try:
                if not clf.connect(rdwr={'on-connect': rdwr_connected},
                                   llcp={'on-startup': llcp_startup,
                                         'on-connect': llcp_connected}):
                    break
            except Exception, e:
                print "clf.connect failed"

            global srv
            if only_one and srv and srv.success:
                raise SystemExit

    except KeyboardInterrupt:
        raise SystemExit
    finally:
        clf.close()

    raise SystemExit

if __name__ == '__main__':
    main()
