#!/usr/bin/python
#
# Example nfcpy to wpa_supplicant wrapper for WPS NFC operations
# Copyright (c) 2012-2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import sys
import time
import random
import threading
import argparse

import nfc
import nfc.ndef
import nfc.llcp
import nfc.handover

import logging

import wpaspy

wpas_ctrl = '/var/run/wpa_supplicant'
srv = None
continue_loop = True
terminate_now = False

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
            wpas = wpaspy.Ctrl(ctrl)
            return wpas
        except Exception, e:
            pass
    return None


def wpas_tag_read(message):
    wpas = wpas_connect()
    if (wpas == None):
        return False
    if "FAIL" in wpas.request("WPS_NFC_TAG_READ " + str(message).encode("hex")):
        return False
    return True

def wpas_get_config_token(id=None):
    wpas = wpas_connect()
    if (wpas == None):
        return None
    if id:
        ret = wpas.request("WPS_NFC_CONFIG_TOKEN NDEF " + id)
    else:
        ret = wpas.request("WPS_NFC_CONFIG_TOKEN NDEF")
    if "FAIL" in ret:
        return None
    return ret.rstrip().decode("hex")


def wpas_get_er_config_token(uuid):
    wpas = wpas_connect()
    if (wpas == None):
        return None
    ret = wpas.request("WPS_ER_NFC_CONFIG_TOKEN NDEF " + uuid)
    if "FAIL" in ret:
        return None
    return ret.rstrip().decode("hex")


def wpas_get_password_token():
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("WPS_NFC_TOKEN NDEF").rstrip().decode("hex")


def wpas_get_handover_req():
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("NFC_GET_HANDOVER_REQ NDEF WPS-CR").rstrip().decode("hex")


def wpas_get_handover_sel(uuid):
    wpas = wpas_connect()
    if (wpas == None):
        return None
    if uuid is None:
        res = wpas.request("NFC_GET_HANDOVER_SEL NDEF WPS-CR").rstrip()
    else:
	res = wpas.request("NFC_GET_HANDOVER_SEL NDEF WPS-CR " + uuid).rstrip()
    if "FAIL" in res:
	return None
    return res.decode("hex")


def wpas_report_handover(req, sel, type):
    wpas = wpas_connect()
    if (wpas == None):
        return None
    return wpas.request("NFC_REPORT_HANDOVER " + type + " WPS " +
                        str(req).encode("hex") + " " +
                        str(sel).encode("hex"))


class HandoverServer(nfc.handover.HandoverServer):
    def __init__(self, llc):
        super(HandoverServer, self).__init__(llc)
        self.sent_carrier = None
        self.ho_server_processing = False
        self.success = False

    def process_request(self, request):
        self.ho_server_processing = True
        print "HandoverServer - request received"
        try:
            print "Parsed handover request: " + request.pretty()
        except Exception, e:
            print e

        sel = nfc.ndef.HandoverSelectMessage(version="1.2")

        for carrier in request.carriers:
            print "Remote carrier type: " + carrier.type
            if carrier.type == "application/vnd.wfa.wsc":
                print "WPS carrier type match - add WPS carrier record"
                data = wpas_get_handover_sel(self.uuid)
                if data is None:
                    print "Could not get handover select carrier record from wpa_supplicant"
                    continue
                print "Handover select carrier record from wpa_supplicant:"
                print data.encode("hex")
                self.sent_carrier = data
                wpas_report_handover(carrier.record, self.sent_carrier, "RESP")

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


def wps_handover_init(llc):
    print "Trying to initiate WPS handover"

    data = wpas_get_handover_req()
    if (data == None):
        print "Could not get handover request carrier record from wpa_supplicant"
        return
    print "Handover request carrier record from wpa_supplicant: " + data.encode("hex")

    message = nfc.ndef.HandoverRequestMessage(version="1.2")
    message.nonce = random.randint(0, 0xffff)
    datamsg = nfc.ndef.Message(data)
    message.add_carrier(datamsg[0], "active", datamsg[1:])

    print "Handover request:"
    try:
        print message.pretty()
    except Exception, e:
        print e
    print str(message).encode("hex")

    client = nfc.handover.HandoverClient(llc)
    try:
        print "Trying handover";
        client.connect()
        print "Connected for handover"
    except nfc.llcp.ConnectRefused:
        print "Handover connection refused"
        client.close()
        return

    print "Sending handover request"

    if not client.send(message):
        print "Failed to send handover request"

    print "Receiving handover response"
    message = client._recv()
    if message is None:
        print "No response received"
        client.close()
        return
    if message.type != "urn:nfc:wkt:Hs":
        print "Response was not Hs - received: " + message.type
        client.close()
        return

    print "Received message"
    try:
        print message.pretty()
    except Exception, e:
        print e
    print str(message).encode("hex")
    message = nfc.ndef.HandoverSelectMessage(message)
    print "Handover select received"
    try:
        print message.pretty()
    except Exception, e:
        print e

    for carrier in message.carriers:
        print "Remote carrier type: " + carrier.type
        if carrier.type == "application/vnd.wfa.wsc":
            print "WPS carrier type match - send to wpa_supplicant"
            wpas_report_handover(data, carrier.record, "INIT")
            # nfcpy does not support the new format..
            #wifi = nfc.ndef.WifiConfigRecord(carrier.record)
            #print wifi.pretty()

    print "Remove peer"
    client.close()
    print "Done with handover"
    global only_one
    if only_one:
        global continue_loop
        continue_loop = False

    global no_wait
    if no_wait:
        print "Trying to exit.."
        global terminate_now
        terminate_now = True

def wps_tag_read(tag, wait_remove=True):
    success = False
    if len(tag.ndef.message):
        for record in tag.ndef.message:
            print "record type " + record.type
            if record.type == "application/vnd.wfa.wsc":
                print "WPS tag - send to wpa_supplicant"
                success = wpas_tag_read(tag.ndef.message)
                break
    else:
        print "Empty tag"

    if wait_remove:
        print "Remove tag"
        while tag.is_present:
            time.sleep(0.1)

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

def wps_write_config_tag(clf, id=None, wait_remove=True):
    print "Write WPS config token"
    global write_data, write_wait_remove
    write_wait_remove = wait_remove
    write_data = wpas_get_config_token(id)
    if write_data == None:
        print "Could not get WPS config token from wpa_supplicant"
        sys.exit(1)
        return
    print "Touch an NFC tag"
    clf.connect(rdwr={'on-connect': rdwr_connected_write})


def wps_write_er_config_tag(clf, uuid, wait_remove=True):
    print "Write WPS ER config token"
    global write_data, write_wait_remove
    write_wait_remove = wait_remove
    write_data = wpas_get_er_config_token(uuid)
    if write_data == None:
        print "Could not get WPS config token from wpa_supplicant"
        return

    print "Touch an NFC tag"
    clf.connect(rdwr={'on-connect': rdwr_connected_write})


def wps_write_password_tag(clf, wait_remove=True):
    print "Write WPS password token"
    global write_data, write_wait_remove
    write_wait_remove = wait_remove
    write_data = wpas_get_password_token()
    if write_data == None:
        print "Could not get WPS password token from wpa_supplicant"
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
        success = wps_tag_read(tag, not only_one)
        if only_one and success:
            global continue_loop
            continue_loop = False
    else:
        print "Not an NDEF tag - remove tag"

    return not no_wait


def llcp_worker(llc):
    global arg_uuid
    if arg_uuid is None:
        wps_handover_init(llc)
        print "Exiting llcp_worker thread"
        return

    global srv
    global wait_connection
    while not wait_connection and srv.sent_carrier is None:
        if srv.ho_server_processing:
            time.sleep(0.025)

def llcp_startup(clf, llc):
    global arg_uuid
    if arg_uuid:
        print "Start LLCP server"
        global srv
        srv = HandoverServer(llc)
        if arg_uuid is "ap":
            print "Trying to handle WPS handover"
            srv.uuid = None
        else:
            print "Trying to handle WPS handover with AP " + arg_uuid
            srv.uuid = arg_uuid
    return llc

def llcp_connected(llc):
    print "P2P LLCP connected"
    global wait_connection
    wait_connection = False
    global arg_uuid
    if arg_uuid:
        global srv
        srv.start()
    else:
        threading.Thread(target=llcp_worker, args=(llc,)).start()
    print "llcp_connected returning"
    return True


def terminate_loop():
    global terminate_now
    return terminate_now

def main():
    clf = nfc.ContactlessFrontend()

    parser = argparse.ArgumentParser(description='nfcpy to wpa_supplicant integration for WPS NFC operations')
    parser.add_argument('-d', const=logging.DEBUG, default=logging.INFO,
                        action='store_const', dest='loglevel',
                        help='verbose debug output')
    parser.add_argument('-q', const=logging.WARNING, action='store_const',
                        dest='loglevel', help='be quiet')
    parser.add_argument('--only-one', '-1', action='store_true',
                        help='run only one operation and exit')
    parser.add_argument('--no-wait', action='store_true',
                        help='do not wait for tag to be removed before exiting')
    parser.add_argument('--uuid',
                        help='UUID of an AP (used for WPS ER operations)')
    parser.add_argument('--id',
                        help='network id (used for WPS ER operations)')
    parser.add_argument('command', choices=['write-config',
                                            'write-er-config',
                                            'write-password'],
                        nargs='?')
    args = parser.parse_args()

    global arg_uuid
    arg_uuid = args.uuid

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
            wps_write_config_tag(clf, id=args.id, wait_remove=not args.no_wait)
            raise SystemExit

        if args.command == "write-er-config":
            wps_write_er_config_tag(clf, args.uuid, wait_remove=not args.no_wait)
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
                                         'on-connect': llcp_connected},
                                   terminate=terminate_loop):
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
