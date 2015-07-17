# FST functionality tests
# Copyright (c) 2015, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import struct
import subprocess
import time
import os

import hwsim_utils
from hwsim import HWSimRadio
import hostapd
import fst_test_common
import fst_module_aux
from utils import alloc_fail

#enum - bad parameter types
bad_param_none = 0
bad_param_session_add_no_params = 1
bad_param_group_id = 2
bad_param_session_set_no_params = 3
bad_param_session_set_unknown_param = 4
bad_param_session_id = 5
bad_param_old_iface = 6
bad_param_new_iface = 7
bad_param_negative_llt = 8
bad_param_zero_llt = 9
bad_param_llt_too_big = 10
bad_param_llt_nan = 11
bad_param_peer_addr = 12
bad_param_session_initiate_no_params = 13
bad_param_session_initiate_bad_session_id = 14
bad_param_session_initiate_with_no_new_iface_set = 15
bad_param_session_initiate_with_bad_peer_addr_set = 16
bad_param_session_initiate_request_with_bad_stie = 17
bad_param_session_initiate_response_with_reject = 18
bad_param_session_initiate_response_with_bad_stie = 19
bad_param_session_initiate_response_with_zero_llt = 20
bad_param_session_initiate_stt_no_response = 21
bad_param_session_initiate_concurrent_setup_request = 22
bad_param_session_transfer_no_params = 23
bad_param_session_transfer_bad_session_id = 24
bad_param_session_transfer_setup_skipped = 25
bad_param_session_teardown_no_params = 26
bad_param_session_teardown_bad_session_id = 27
bad_param_session_teardown_setup_skipped = 28
bad_param_session_teardown_bad_fsts_id = 29

bad_param_names = ("None",
                   "No params passed to session add",
                   "Group ID",
                   "No params passed to session set",
                   "Unknown param passed to session set",
                   "Session ID",
                   "Old interface name",
                   "New interface name",
                   "Negative LLT",
                   "Zero LLT",
                   "LLT too big",
                   "LLT is not a number",
                   "Peer address",
                   "No params passed to session initiate",
                   "Session ID",
                   "No new_iface was set",
                   "Peer address",
                   "Request with bad st ie",
                   "Response with reject",
                   "Response with bad st ie",
                   "Response with zero llt",
                   "No response, STT",
                   "Concurrent setup request",
                   "No params passed to session transfer",
                   "Session ID",
                   "Session setup skipped",
                   "No params passed to session teardown",
                   "Bad session",
                   "Session setup skipped",
                   "Bad fsts_id")

def fst_start_session(apdev, test_params, bad_param_type, start_on_ap,
                      peer_addr = None):
    """This function makes the necessary preparations and the adds and sets a
    session using either correct or incorrect parameters depending on the value
    of bad_param_type. If the call ends as expected (with session being
    successfully added and set in case of correct parameters or with the
    expected exception in case of incorrect parameters), the function silently
    exits. Otherwise, it throws an exception thus failing the test."""

    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    bad_parameter_detected = False
    exception_already_raised = False
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if start_on_ap:
            initiator = ap1
            responder = sta1
            new_iface = ap2.ifname()
            new_peer_addr = ap2.get_actual_peer_addr()
        else:
            initiator = sta1
            responder = ap1
            new_iface = sta2.ifname()
            new_peer_addr = sta2.get_actual_peer_addr()
        initiator.add_peer(responder, peer_addr, new_peer_addr)
        group_id = None
        if bad_param_type == bad_param_group_id:
            group_id = '-1'
        elif bad_param_type == bad_param_session_add_no_params:
            group_id = ''
        initiator.set_fst_parameters(group_id=group_id)
        sid = initiator.add_session()
        if bad_param_type == bad_param_session_set_no_params:
            res = initiator.set_session_param(None)
            if not res.startswith("OK"):
                raise Exception("Session set operation failed")
        elif bad_param_type == bad_param_session_set_unknown_param:
            res = initiator.set_session_param("bad_param=1")
            if not res.startswith("OK"):
                raise Exception("Session set operation failed")
        else:
            if bad_param_type == bad_param_session_initiate_with_no_new_iface_set:
                new_iface = None
            elif bad_param_type == bad_param_new_iface:
                new_iface = 'wlan12'
            old_iface = None if bad_param_type != bad_param_old_iface else 'wlan12'
            llt = None
            if bad_param_type == bad_param_negative_llt:
                llt = '-1'
            elif bad_param_type == bad_param_zero_llt:
                llt = '0'
            elif bad_param_type == bad_param_llt_too_big:
                llt = '4294967296'    #0x100000000
            elif bad_param_type == bad_param_llt_nan:
                llt = 'nan'
            elif bad_param_type == bad_param_session_id:
                sid = '-1'
            initiator.set_fst_parameters(llt=llt)
            initiator.configure_session(sid, new_iface, old_iface)
    except Exception, e:
        if e.args[0].startswith("Cannot add FST session with groupid"):
            if bad_param_type == bad_param_group_id or bad_param_type == bad_param_session_add_no_params:
                bad_parameter_detected = True
        elif e.args[0].startswith("Cannot set FST session new_ifname:"):
            if bad_param_type == bad_param_new_iface:
                bad_parameter_detected = True
        elif e.args[0].startswith("Session set operation failed"):
            if (bad_param_type == bad_param_session_set_no_params or
                bad_param_type == bad_param_session_set_unknown_param):
                bad_parameter_detected = True
        elif e.args[0].startswith("Cannot set FST session old_ifname:"):
            if (bad_param_type == bad_param_old_iface or
                bad_param_type == bad_param_session_id or
                bad_param_type == bad_param_session_set_no_params):
                bad_parameter_detected = True
        elif e.args[0].startswith("Cannot set FST session llt:"):
            if (bad_param_type == bad_param_negative_llt or
                bad_param_type == bad_param_llt_too_big or
                bad_param_type == bad_param_llt_nan):
                bad_parameter_detected = True
        elif e.args[0].startswith("Cannot set FST session peer address:"):
            if bad_param_type == bad_param_peer_addr:
                bad_parameter_detected = True
        if not bad_parameter_detected:
            # The exception was unexpected
            logger.info(e)
            exception_already_raised = True
            raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if not exception_already_raised:
            if bad_parameter_detected:
                logger.info("Success. Bad parameter was detected (%s)" % bad_param_names[bad_param_type])
            else:
                if bad_param_type == bad_param_none or bad_param_type == bad_param_zero_llt:
                    logger.info("Success. Session added and set")
                else:
                    exception_text = ""
                    if bad_param_type == bad_param_peer_addr:
                        exception_text = "Failure. Bad parameter was not detected (Peer address == %s)" % ap1.get_new_peer_addr()
                    else:
                        exception_text = "Failure. Bad parameter was not detected (%s)" % bad_param_names[bad_param_type]
                    raise Exception(exception_text)
        else:
            print "Failure. Unexpected exception"

def fst_initiate_session(apdev, test_params, bad_param_type, init_on_ap):
    """This function makes the necessary preparations and then adds, sets and
    initiates a session using either correct or incorrect parameters at each
    stage depending on the value of bad_param_type. If the call ends as expected
    (with session being successfully added, set and initiated in case of correct
    parameters or with the expected exception in case of incorrect parameters),
    the function silently exits. Otherwise it throws an exception thus failing
    the test."""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    bad_parameter_detected = False
    exception_already_raised = False
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        # This call makes sure FstHostapd singleton object is created and, as a
        # result, the global control interface is registered (this is done from
        # the constructor).
        ap1.get_global_instance()
        if init_on_ap:
            initiator = ap1
            responder = sta1
            new_iface = ap2.ifname() if bad_param_type != bad_param_session_initiate_with_no_new_iface_set else None
            new_peer_addr = ap2.get_actual_peer_addr()
            resp_newif = sta2.ifname()
        else:
            initiator = sta1
            responder = ap1
            new_iface = sta2.ifname() if bad_param_type != bad_param_session_initiate_with_no_new_iface_set else None
            new_peer_addr = sta2.get_actual_peer_addr()
            resp_newif = ap2.ifname()
        peeraddr = None if bad_param_type != bad_param_session_initiate_with_bad_peer_addr_set else '10:DE:AD:DE:AD:11'
        initiator.add_peer(responder, peeraddr, new_peer_addr)
        if bad_param_type == bad_param_session_initiate_response_with_zero_llt:
            initiator.set_fst_parameters(llt='0')
        sid = initiator.add_session()
        initiator.configure_session(sid, new_iface)
        if bad_param_type == bad_param_session_initiate_no_params:
            sid = ''
        elif bad_param_type == bad_param_session_initiate_bad_session_id:
            sid = '-1'
        if bad_param_type == bad_param_session_initiate_request_with_bad_stie:
            actual_fsts_id = initiator.get_fsts_id_by_sid(sid)
            initiator.send_test_session_setup_request(str(actual_fsts_id), "bad_new_band")
            responder.wait_for_session_event(5)
        elif bad_param_type == bad_param_session_initiate_response_with_reject:
            initiator.send_session_setup_request(sid)
            initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            setup_event = responder.wait_for_session_event(5, [],
                                                           ['EVENT_FST_SETUP'])
            if not 'id' in setup_event:
                raise Exception("No session id in FST setup event")
            responder.send_session_setup_response(str(setup_event['id']),
                                                  "reject")
            event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            if event['new_state'] != "INITIAL" or event['reason'] != "REASON_REJECT":
                raise Exception("Response with reject not handled as expected")
            bad_parameter_detected = True
        elif bad_param_type == bad_param_session_initiate_response_with_bad_stie:
            initiator.send_session_setup_request(sid)
            initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            responder.wait_for_session_event(5, [], ['EVENT_FST_SETUP'])
            actual_fsts_id = initiator.get_fsts_id_by_sid(sid)
            responder.send_test_session_setup_response(str(actual_fsts_id),
                                                       "accept", "bad_new_band")
            event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            if event['new_state'] != "INITIAL" or event['reason'] != "REASON_ERROR_PARAMS":
                raise Exception("Response with bad STIE not handled as expected")
            bad_parameter_detected = True
        elif bad_param_type == bad_param_session_initiate_response_with_zero_llt:
            initiator.initiate_session(sid, "accept")
            event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            if event['new_state'] != "TRANSITION_DONE":
                raise Exception("Response reception for a session with llt=0 not handled as expected")
            bad_parameter_detected = True
        elif bad_param_type == bad_param_session_initiate_stt_no_response:
            initiator.send_session_setup_request(sid)
            initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            responder.wait_for_session_event(5, [], ['EVENT_FST_SETUP'])
            event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            if event['new_state'] != "INITIAL" or event['reason'] != "REASON_STT":
                raise Exception("No response scenario not handled as expected")
            bad_parameter_detected = True
        elif bad_param_type == bad_param_session_initiate_concurrent_setup_request:
            responder.add_peer(initiator)
            resp_sid = responder.add_session()
            responder.configure_session(resp_sid, resp_newif)
            initiator.send_session_setup_request(sid)
            actual_fsts_id = initiator.get_fsts_id_by_sid(sid)
            responder.send_test_session_setup_request(str(actual_fsts_id))
            event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
            initiator_addr = initiator.get_own_mac_address()
            responder_addr = responder.get_own_mac_address()
            if initiator_addr < responder_addr:
                event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
                if event['new_state'] != "INITIAL" or event['reason'] != "REASON_SETUP":
                    raise Exception("Concurrent setup scenario not handled as expected")
                event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SETUP"])
                # The incoming setup request received by the initiator has
                # priority over the one sent previously by the initiator itself
                # because the initiator's MAC address is numerically lower than
                # the one of the responder. Thus, the initiator should generate
                # an FST_SETUP event.
            else:
                event = initiator.wait_for_session_event(5, [], ["EVENT_FST_SESSION_STATE"])
                if event['new_state'] != "INITIAL" or event['reason'] != "REASON_STT":
                    raise Exception("Concurrent setup scenario not handled as expected")
                # The incoming setup request was dropped at the initiator
                # because its MAC address is numerically bigger than the one of
                # the responder. Thus, the initiator continue to wait for a
                # setup response until the STT event fires.
            bad_parameter_detected = True
        else:
            initiator.initiate_session(sid, "accept")
    except Exception, e:
        if e.args[0].startswith("Cannot initiate fst session"):
            if bad_param_type != bad_param_none:
                bad_parameter_detected = True
        elif e.args[0].startswith("No FST-EVENT-SESSION received"):
            if bad_param_type == bad_param_session_initiate_request_with_bad_stie:
                bad_parameter_detected = True
        if not bad_parameter_detected:
            #The exception was unexpected
            logger.info(e)
            exception_already_raised = True
            raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if not exception_already_raised:
            if bad_parameter_detected:
                logger.info("Success. Bad parameter was detected (%s)" % bad_param_names[bad_param_type])
            else:
                if bad_param_type == bad_param_none:
                    logger.info("Success. Session initiated")
                else:
                    raise Exception("Failure. Bad parameter was not detected (%s)" % bad_param_names[bad_param_type])
        else:
            print "Failure. Unexpected exception"

def fst_transfer_session(apdev, test_params, bad_param_type, init_on_ap,
                         rsn=False):
    """This function makes the necessary preparations and then adds, sets,
    initiates and attempts to transfer a session using either correct or
    incorrect parameters at each stage depending on the value of bad_param_type.
    If the call ends as expected the function silently exits. Otherwise, it
    throws an exception thus failing the test."""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev, rsn=rsn)
    bad_parameter_detected = False
    exception_already_raised = False
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2, rsn=rsn)
        # This call makes sure FstHostapd singleton object is created and, as a
        # result, the global control interface is registered (this is done from
        # the constructor).
        ap1.get_global_instance()
        if init_on_ap:
            initiator = ap1
            responder = sta1
            new_iface = ap2.ifname()
            new_peer_addr = ap2.get_actual_peer_addr()
        else:
            initiator = sta1
            responder = ap1
            new_iface = sta2.ifname()
            new_peer_addr = sta2.get_actual_peer_addr()
        initiator.add_peer(responder, new_peer_addr = new_peer_addr)
        sid = initiator.add_session()
        initiator.configure_session(sid, new_iface)
        if bad_param_type != bad_param_session_transfer_setup_skipped:
            initiator.initiate_session(sid, "accept")
        if bad_param_type == bad_param_session_transfer_no_params:
            sid = ''
        elif bad_param_type == bad_param_session_transfer_bad_session_id:
            sid = '-1'
        initiator.transfer_session(sid)
    except Exception, e:
        if e.args[0].startswith("Cannot transfer fst session"):
            if bad_param_type != bad_param_none:
                bad_parameter_detected = True
        if not bad_parameter_detected:
            # The exception was unexpected
            logger.info(e)
            exception_already_raised = True
            raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if not exception_already_raised:
            if bad_parameter_detected:
                logger.info("Success. Bad parameter was detected (%s)" % bad_param_names[bad_param_type])
            else:
                if bad_param_type == bad_param_none:
                    logger.info("Success. Session transferred")
                else:
                    raise Exception("Failure. Bad parameter was not detected (%s)" % bad_param_names[bad_param_type])
        else:
            print "Failure. Unexpected exception"


def fst_tear_down_session(apdev, test_params, bad_param_type, init_on_ap):
    """This function makes the necessary preparations and then adds, sets, and
    initiates a session. It then issues a tear down command using either
    correct or incorrect parameters at each stage. If the call ends as expected,
    the function silently exits. Otherwise, it throws an exception thus failing
    the test."""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    bad_parameter_detected = False
    exception_already_raised = False
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        # This call makes sure FstHostapd singleton object is created and, as a
        # result, the global control interface is registered (this is done from
        # the constructor).
        ap1.get_global_instance()
        if init_on_ap:
            initiator = ap1
            responder = sta1
            new_iface = ap2.ifname()
            new_peer_addr = ap2.get_actual_peer_addr()
        else:
            initiator = sta1
            responder = ap1
            new_iface = sta2.ifname()
            new_peer_addr = sta2.get_actual_peer_addr()
        initiator.add_peer(responder, new_peer_addr = new_peer_addr)
        sid = initiator.add_session()
        initiator.configure_session(sid, new_iface)
        if bad_param_type != bad_param_session_teardown_setup_skipped:
            initiator.initiate_session(sid, "accept")
        if bad_param_type == bad_param_session_teardown_bad_fsts_id:
            initiator.send_test_tear_down('-1')
            responder.wait_for_session_event(5)
        else:
            if bad_param_type == bad_param_session_teardown_no_params:
                sid = ''
            elif bad_param_type == bad_param_session_teardown_bad_session_id:
                sid = '-1'
            initiator.teardown_session(sid)
    except Exception, e:
        if e.args[0].startswith("Cannot tear down fst session"):
            if (bad_param_type == bad_param_session_teardown_no_params or
                bad_param_type == bad_param_session_teardown_bad_session_id or
                bad_param_type == bad_param_session_teardown_setup_skipped):
                bad_parameter_detected = True
        elif e.args[0].startswith("No FST-EVENT-SESSION received"):
            if bad_param_type == bad_param_session_teardown_bad_fsts_id:
                bad_parameter_detected = True
        if not bad_parameter_detected:
            # The exception was unexpected
            logger.info(e)
            exception_already_raised = True
            raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if not exception_already_raised:
            if bad_parameter_detected:
                logger.info("Success. Bad parameter was detected (%s)" % bad_param_names[bad_param_type])
            else:
                if bad_param_type == bad_param_none:
                    logger.info("Success. Session torn down")
                else:
                    raise Exception("Failure. Bad parameter was not detected (%s)" % bad_param_names[bad_param_type])
        else:
            print "Failure. Unexpected exception"


#enum - remove session scenarios
remove_scenario_no_params = 0
remove_scenario_bad_session_id = 1
remove_scenario_non_established_session = 2
remove_scenario_established_session = 3

remove_scenario_names = ("No params",
                         "Bad session id",
                         "Remove non-established session",
                         "Remove established session")


def fst_remove_session(apdev, test_params, remove_session_scenario, init_on_ap):
    """This function attempts to remove a session at various stages of its
    formation, depending on the value of remove_session_scenario. If the call
    ends as expected, the function silently exits. Otherwise, it throws an
    exception thus failing the test."""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    bad_parameter_detected = False
    exception_already_raised = False
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        # This call makes sure FstHostapd singleton object is created and, as a
        # result, the global control interface is registered (this is done from
        # the constructor).
        ap1.get_global_instance()
        if init_on_ap:
            initiator = ap1
            responder = sta1
            new_iface = ap2.ifname()
            new_peer_addr = ap2.get_actual_peer_addr()
        else:
            initiator = sta1
            responder = ap1
            new_iface = sta2.ifname()
            new_peer_addr = sta2.get_actual_peer_addr()
        initiator.add_peer(responder, new_peer_addr = new_peer_addr)
        sid = initiator.add_session()
        initiator.configure_session(sid, new_iface)
        if remove_session_scenario != remove_scenario_no_params:
            if remove_session_scenario != remove_scenario_non_established_session:
                initiator.initiate_session(sid, "accept")
        if remove_session_scenario == remove_scenario_no_params:
            sid = ''
        elif remove_session_scenario == remove_scenario_bad_session_id:
            sid = '-1'
        initiator.remove_session(sid)
    except Exception, e:
        if e.args[0].startswith("Cannot remove fst session"):
            if (remove_session_scenario == remove_scenario_no_params or
                remove_session_scenario == remove_scenario_bad_session_id):
                bad_parameter_detected = True
        elif e.args[0].startswith("No FST-EVENT-SESSION received"):
            if remove_session_scenario == remove_scenario_non_established_session:
                bad_parameter_detected = True
        if not bad_parameter_detected:
            #The exception was unexpected
            logger.info(e)
            exception_already_raised = True
            raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if not exception_already_raised:
            if bad_parameter_detected:
                logger.info("Success. Remove scenario ended as expected (%s)" % remove_scenario_names[remove_session_scenario])
            else:
                if remove_session_scenario == remove_scenario_established_session:
                    logger.info("Success. Session removed")
                else:
                    raise Exception("Failure. Remove scenario ended in an unexpected way (%s)" % remove_scenario_names[remove_session_scenario])
        else:
            print "Failure. Unexpected exception"


#enum - frame types
frame_type_session_request = 0
frame_type_session_response = 1
frame_type_ack_request = 2
frame_type_ack_response = 3
frame_type_tear_down = 4

frame_type_names = ("Session request",
                    "Session Response",
                    "Ack request",
                    "Ack response",
                    "Tear down")

def fst_send_unexpected_frame(apdev, test_params, frame_type, send_from_ap, additional_param = ''):
    """This function creates two pairs of APs and stations, makes them connect
    and then causes one side to send an unexpected FST frame of the specified
    type to the other. The other side should then identify and ignore the
    frame."""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    exception_already_raised = False
    frame_receive_timeout = False
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        # This call makes sure FstHostapd singleton object is created and, as a
        # result, the global control interface is registered (this is done from
        # the constructor).
        ap1.get_global_instance()
        if send_from_ap:
            sender = ap1
            receiver = sta1
            new_iface = ap2.ifname()
            new_peer_addr = ap2.get_actual_peer_addr()
        else:
            sender = sta1
            receiver = ap1
            new_iface = sta2.ifname()
            new_peer_addr = sta2.get_actual_peer_addr()
        sender.add_peer(receiver, new_peer_addr = new_peer_addr)
        sid=sender.add_session()
        sender.configure_session(sid, new_iface)
        if frame_type == frame_type_session_request:
            sender.send_session_setup_request(sid)
            event = receiver.wait_for_session_event(5)
            if event['type'] != 'EVENT_FST_SETUP':
                raise Exception("Unexpected indication: " + event['type'])
        elif frame_type == frame_type_session_response:
            #fsts_id doesn't matter, no actual session exists
            sender.send_test_session_setup_response('0', additional_param)
            receiver.wait_for_session_event(5)
        elif frame_type == frame_type_ack_request:
            #fsts_id doesn't matter, no actual session exists
            sender.send_test_ack_request('0')
            receiver.wait_for_session_event(5)
        elif frame_type == frame_type_ack_response:
            #fsts_id doesn't matter, no actual session exists
            sender.send_test_ack_response('0')
            receiver.wait_for_session_event(5)
        elif frame_type == frame_type_tear_down:
            #fsts_id doesn't matter, no actual session exists
            sender.send_test_tear_down('0')
            receiver.wait_for_session_event(5)
    except Exception, e:
        if e.args[0].startswith("No FST-EVENT-SESSION received"):
            if frame_type != frame_type_session_request:
                frame_receive_timeout = True
        else:
            logger.info(e)
            exception_already_raised = True
            raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if not exception_already_raised:
            if frame_receive_timeout:
                logger.info("Success. Frame was ignored (%s)" % frame_type_names[frame_type])
            else:
                if frame_type == frame_type_session_request:
                    logger.info("Success. Frame received, session created")
                else:
                    raise Exception("Failure. Frame was not ignored (%s)" % frame_type_names[frame_type])
        else:
            print "Failure. Unexpected exception"


#enum - bad session transfer scenarios
bad_scenario_none = 0
bad_scenario_ack_req_session_not_set_up = 1
bad_scenario_ack_req_session_not_established_init_side = 2
bad_scenario_ack_req_session_not_established_resp_side = 3
bad_scenario_ack_req_bad_fsts_id = 4
bad_scenario_ack_resp_session_not_set_up = 5
bad_scenario_ack_resp_session_not_established_init_side = 6
bad_scenario_ack_resp_session_not_established_resp_side = 7
bad_scenario_ack_resp_no_ack_req = 8
bad_scenario_ack_resp_bad_fsts_id = 9

bad_scenario_names = ("None",
                      "Ack request received before the session was set up",
                      "Ack request received on the initiator side before session was established",
                      "Ack request received on the responder side before session was established",
                      "Ack request received with bad fsts_id",
                      "Ack response received before the session was set up",
                      "Ack response received on the initiator side before session was established",
                      "Ack response received on the responder side before session was established",
                      "Ack response received before ack request was sent",
                      "Ack response received with bad fsts_id")

def fst_bad_transfer(apdev, test_params, bad_scenario_type, init_on_ap):
    """This function makes the necessary preparations and then adds and sets a
    session. It then initiates and it unless instructed otherwise) and attempts
    to send one of the frames involved in the session transfer protocol,
    skipping or distorting one of the stages according to the value of
    bad_scenario_type parameter."""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    bad_parameter_detected = False
    exception_already_raised = False
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        # This call makes sure FstHostapd singleton object is created and, as a
        # result, the global control interface is registered (this is done from
        # the constructor).
        ap1.get_global_instance()
        if init_on_ap:
            initiator = ap1
            responder = sta1
            new_iface = ap2.ifname()
            new_peer_addr = ap2.get_actual_peer_addr()
        else:
            initiator = sta1
            responder = ap1
            new_iface = sta2.ifname()
            new_peer_addr = sta2.get_actual_peer_addr()
        initiator.add_peer(responder, new_peer_addr = new_peer_addr)
        sid = initiator.add_session()
        initiator.configure_session(sid, new_iface)
        if (bad_scenario_type != bad_scenario_ack_req_session_not_set_up and
            bad_scenario_type != bad_scenario_ack_resp_session_not_set_up):
            if (bad_scenario_type != bad_scenario_ack_req_session_not_established_init_side and
                bad_scenario_type != bad_scenario_ack_resp_session_not_established_init_side and
                bad_scenario_type != bad_scenario_ack_req_session_not_established_resp_side and
                bad_scenario_type != bad_scenario_ack_resp_session_not_established_resp_side):
                response =  "accept"
            else:
                response = ''
            initiator.initiate_session(sid, response)
        if bad_scenario_type == bad_scenario_ack_req_session_not_set_up:
            #fsts_id doesn't matter, no actual session exists
            responder.send_test_ack_request('0')
            initiator.wait_for_session_event(5)
            # We want to send the unexpected frame to the side that already has
            # a session created
        elif bad_scenario_type == bad_scenario_ack_resp_session_not_set_up:
            #fsts_id doesn't matter, no actual session exists
            responder.send_test_ack_response('0')
            initiator.wait_for_session_event(5)
            # We want to send the unexpected frame to the side that already has
            # a session created
        elif bad_scenario_type == bad_scenario_ack_req_session_not_established_init_side:
            #fsts_id doesn't matter, no actual session exists
            initiator.send_test_ack_request('0')
            responder.wait_for_session_event(5, ["EVENT_FST_SESSION_STATE"])
        elif bad_scenario_type == bad_scenario_ack_req_session_not_established_resp_side:
            #fsts_id doesn't matter, no actual session exists
            responder.send_test_ack_request('0')
            initiator.wait_for_session_event(5, ["EVENT_FST_SESSION_STATE"])
        elif bad_scenario_type == bad_scenario_ack_resp_session_not_established_init_side:
            #fsts_id doesn't matter, no actual session exists
            initiator.send_test_ack_response('0')
            responder.wait_for_session_event(5, ["EVENT_FST_SESSION_STATE"])
        elif bad_scenario_type == bad_scenario_ack_resp_session_not_established_resp_side:
            #fsts_id doesn't matter, no actual session exists
            responder.send_test_ack_response('0')
            initiator.wait_for_session_event(5, ["EVENT_FST_SESSION_STATE"])
        elif bad_scenario_type == bad_scenario_ack_req_bad_fsts_id:
            initiator.send_test_ack_request('-1')
            responder.wait_for_session_event(5, ["EVENT_FST_SESSION_STATE"])
        elif bad_scenario_type == bad_scenario_ack_resp_bad_fsts_id:
            initiator.send_test_ack_response('-1')
            responder.wait_for_session_event(5, ["EVENT_FST_SESSION_STATE"])
        elif bad_scenario_type == bad_scenario_ack_resp_no_ack_req:
            actual_fsts_id = initiator.get_fsts_id_by_sid(sid)
            initiator.send_test_ack_response(str(actual_fsts_id))
            responder.wait_for_session_event(5, ["EVENT_FST_SESSION_STATE"])
        else:
            raise Exception("Unknown bad scenario identifier")
    except Exception, e:
        if e.args[0].startswith("No FST-EVENT-SESSION received"):
            bad_parameter_detected = True
        if not bad_parameter_detected:
            # The exception was unexpected
            logger.info(e)
            exception_already_raised = True
            raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        if not exception_already_raised:
            if bad_parameter_detected:
                logger.info("Success. Bad scenario was handled correctly (%s)" % bad_scenario_names[bad_scenario_type])
            else:
                raise Exception("Failure. Bad scenario was handled incorrectly (%s)" % bad_scenario_names[bad_scenario_type])
        else:
            print "Failure. Unexpected exception"

def test_fst_sta_connect_to_non_fst_ap(dev, apdev, test_params):
    """FST STA connecting to non-FST AP"""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    with HWSimRadio() as (radio, iface):
        non_fst_ap = hostapd.add_ap(iface, { "ssid": "non_fst_11g" })
        try:
            orig_sta1_mbies = sta1.get_local_mbies()
            orig_sta2_mbies = sta2.get_local_mbies()
            vals = sta2.scan()
            freq = vals['freq']
            sta2.connect_to_external_ap(non_fst_ap, ssid="non_fst_11g",
                                        key_mgmt="NONE", scan_freq=freq)
            time.sleep(2)
            res_sta1_mbies = sta1.get_local_mbies()
            res_sta2_mbies = sta2.get_local_mbies()
            if (orig_sta1_mbies.startswith("FAIL") or
                orig_sta2_mbies.startswith("FAIL") or
                not res_sta1_mbies.startswith("FAIL") or
                not res_sta2_mbies.startswith("FAIL")):
                raise Exception("Failure. MB IEs have not been removed on the stations")
        except Exception, e:
            logger.info(e)
            raise
        finally:
            sta2.disconnect_from_external_ap()
            fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)

def test_fst_sta_connect_to_fst_ap(dev, apdev, test_params):
    """FST STA connecting to FST AP"""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    try:
        orig_sta2_mbies = sta2.get_local_mbies()
        vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
        sta1.connect(ap1, key_mgmt="NONE",
                     scan_freq=fst_test_common.fst_test_def_freq_a)
        time.sleep(2)
        res_sta2_mbies = sta2.get_local_mbies()
        if res_sta2_mbies == orig_sta2_mbies:
            raise Exception("Failure. MB IEs have not been updated")
    except Exception, e:
        logger.info(e)
        raise
    finally:
        sta1.disconnect()
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)

def test_fst_ap_connect_to_fst_sta(dev, apdev, test_params):
    """FST AP connecting to FST STA"""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    try:
        orig_ap_mbies = ap1.get_local_mbies()
        vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
        sta1.connect(ap1, key_mgmt="NONE",
                     scan_freq=fst_test_common.fst_test_def_freq_a)
        time.sleep(2)
        res_ap_mbies = ap1.get_local_mbies()
        if res_ap_mbies != orig_ap_mbies:
            raise Exception("Failure. MB IEs have been unexpectedly updated on the AP")
    except Exception, e:
        logger.info(e)
        raise
    finally:
        sta1.disconnect()
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)

def test_fst_ap_connect_to_non_fst_sta(dev, apdev, test_params):
    """FST AP connecting to non-FST STA"""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    try:
        orig_ap_mbies = ap2.get_local_mbies()
        vals = dev[0].scan(None, fst_test_common.fst_test_def_freq_g)
        fst_module_aux.external_sta_connect(dev[0], ap2, key_mgmt="NONE",
                                            scan_freq=fst_test_common.fst_test_def_freq_g)
        time.sleep(2)
        res_ap_mbies = ap2.get_local_mbies()
        if res_ap_mbies != orig_ap_mbies:
            raise Exception("Failure. MB IEs have been unexpectedly updated on the AP")
    except Exception, e:
        logger.info(e)
        raise
    finally:
        fst_module_aux.disconnect_external_sta(dev[0], ap2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)

def test_fst_second_sta_connect_to_non_fst_ap(dev, apdev, test_params):
    """FST STA 2nd connecting to non-FST AP"""
    fst_ap1, fst_ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    with HWSimRadio() as (radio, iface):
        non_fst_ap = hostapd.add_ap(iface, { "ssid": "non_fst_11g" })
        try:
            vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
            sta1.connect(fst_ap1, key_mgmt="NONE", scan_freq=fst_test_common.fst_test_def_freq_a)
            time.sleep(2)
            orig_sta1_mbies = sta1.get_local_mbies()
            orig_sta2_mbies = sta2.get_local_mbies()
            vals = sta2.scan()
            freq = vals['freq']
            sta2.connect_to_external_ap(non_fst_ap, ssid="non_fst_11g", key_mgmt="NONE", scan_freq=freq)
            time.sleep(2)
            res_sta1_mbies = sta1.get_local_mbies()
            res_sta2_mbies = sta2.get_local_mbies()
            if (orig_sta1_mbies.startswith("FAIL") or
                orig_sta2_mbies.startswith("FAIL") or
                not res_sta1_mbies.startswith("FAIL") or
                not res_sta2_mbies.startswith("FAIL")):
                raise Exception("Failure. MB IEs have not been removed on the stations")
        except Exception, e:
            logger.info(e)
            raise
        finally:
            sta1.disconnect()
            sta2.disconnect_from_external_ap()
            fst_module_aux.stop_two_ap_sta_pairs(fst_ap1, fst_ap2, sta1, sta2)


def test_fst_second_sta_connect_to_fst_ap(dev, apdev, test_params):
    """FST STA 2nd connecting to FST AP"""
    fst_ap1, fst_ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    with HWSimRadio() as (radio, iface):
        non_fst_ap = hostapd.add_ap(iface, { "ssid": "non_fst_11g" })
        try:
            vals = sta2.scan()
            freq = vals['freq']
            sta2.connect_to_external_ap(non_fst_ap, ssid="non_fst_11g", key_mgmt="NONE", scan_freq=freq)
            time.sleep(2)
            orig_sta1_mbies = sta1.get_local_mbies()
            orig_sta2_mbies = sta2.get_local_mbies()
            vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
            sta1.connect(fst_ap1, key_mgmt="NONE", scan_freq=fst_test_common.fst_test_def_freq_a)
            time.sleep(2)
            res_sta1_mbies = sta1.get_local_mbies()
            res_sta2_mbies = sta2.get_local_mbies()
            if (not orig_sta1_mbies.startswith("FAIL") or
                not orig_sta2_mbies.startswith("FAIL") or
                not res_sta1_mbies.startswith("FAIL") or
                not res_sta2_mbies.startswith("FAIL")):
                raise Exception("Failure. MB IEs should have stayed non-present on the stations")
        except Exception, e:
            logger.info(e)
            raise
        finally:
            sta1.disconnect()
            sta2.disconnect_from_external_ap()
            fst_module_aux.stop_two_ap_sta_pairs(fst_ap1, fst_ap2, sta1, sta2)

def test_fst_disconnect_1_of_2_stas_from_non_fst_ap(dev, apdev, test_params):
    """FST disconnect 1 of 2 STAs from non-FST AP"""
    fst_ap1, fst_ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    with HWSimRadio() as (radio, iface):
        non_fst_ap = hostapd.add_ap(iface, { "ssid": "non_fst_11g" })
        try:
            vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
            sta1.connect(fst_ap1, key_mgmt="NONE", scan_freq=fst_test_common.fst_test_def_freq_a)
            vals = sta2.scan()
            freq = vals['freq']
            sta2.connect_to_external_ap(non_fst_ap, ssid="non_fst_11g", key_mgmt="NONE", scan_freq=freq)
            time.sleep(2)
            orig_sta1_mbies = sta1.get_local_mbies()
            orig_sta2_mbies = sta2.get_local_mbies()
            sta2.disconnect_from_external_ap()
            time.sleep(2)
            res_sta1_mbies = sta1.get_local_mbies()
            res_sta2_mbies = sta2.get_local_mbies()
            if (not orig_sta1_mbies.startswith("FAIL") or
                not orig_sta2_mbies.startswith("FAIL") or
                res_sta1_mbies.startswith("FAIL") or
                res_sta2_mbies.startswith("FAIL")):
                raise Exception("Failure. MB IEs haven't reappeared on the stations")
        except Exception, e:
            logger.info(e)
            raise
        finally:
            sta1.disconnect()
            sta2.disconnect_from_external_ap()
            fst_module_aux.stop_two_ap_sta_pairs(fst_ap1, fst_ap2, sta1, sta2)


def test_fst_disconnect_1_of_2_stas_from_fst_ap(dev, apdev, test_params):
    """FST disconnect 1 of 2 STAs from FST AP"""
    fst_ap1, fst_ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    with HWSimRadio() as (radio, iface):
        non_fst_ap = hostapd.add_ap(iface, { "ssid": "non_fst_11g" })
        try:
            vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
            sta1.connect(fst_ap1, key_mgmt="NONE", scan_freq=fst_test_common.fst_test_def_freq_a)
            vals = sta2.scan()
            freq = vals['freq']
            sta2.connect_to_external_ap(non_fst_ap, ssid="non_fst_11g", key_mgmt="NONE", scan_freq=freq)
            time.sleep(2)
            orig_sta1_mbies = sta1.get_local_mbies()
            orig_sta2_mbies = sta2.get_local_mbies()
            sta1.disconnect()
            time.sleep(2)
            res_sta1_mbies = sta1.get_local_mbies()
            res_sta2_mbies = sta2.get_local_mbies()
            if (not orig_sta1_mbies.startswith("FAIL") or
                not orig_sta2_mbies.startswith("FAIL") or
                not res_sta1_mbies.startswith("FAIL") or
                not res_sta2_mbies.startswith("FAIL")):
                raise Exception("Failure. MB IEs should have stayed non-present on the stations")
        except Exception, e:
            logger.info(e)
            raise
        finally:
            sta1.disconnect()
            sta2.disconnect_from_external_ap()
            fst_module_aux.stop_two_ap_sta_pairs(fst_ap1, fst_ap2, sta1, sta2)

def test_fst_disconnect_2_of_2_stas_from_non_fst_ap(dev, apdev, test_params):
    """FST disconnect 2 of 2 STAs from non-FST AP"""
    fst_ap1, fst_ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    with HWSimRadio() as (radio, iface):
        non_fst_ap = hostapd.add_ap(iface, { "ssid": "non_fst_11g" })
        try:
            vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
            sta1.connect(fst_ap1, key_mgmt="NONE", scan_freq=fst_test_common.fst_test_def_freq_a)
            vals = sta2.scan()
            freq = vals['freq']
            sta2.connect_to_external_ap(non_fst_ap, ssid="non_fst_11g", key_mgmt="NONE", scan_freq=freq)
            time.sleep(2)
            sta1.disconnect()
            time.sleep(2)
            orig_sta1_mbies = sta1.get_local_mbies()
            orig_sta2_mbies = sta2.get_local_mbies()
            sta2.disconnect_from_external_ap()
            time.sleep(2)
            res_sta1_mbies = sta1.get_local_mbies()
            res_sta2_mbies = sta2.get_local_mbies()
            if (not orig_sta1_mbies.startswith("FAIL") or
                not orig_sta2_mbies.startswith("FAIL") or
                res_sta1_mbies.startswith("FAIL") or
                res_sta2_mbies.startswith("FAIL")):
                raise Exception("Failure. MB IEs haven't reappeared on the stations")
        except Exception, e:
            logger.info(e)
            raise
        finally:
            sta1.disconnect()
            sta2.disconnect_from_external_ap()
            fst_module_aux.stop_two_ap_sta_pairs(fst_ap1, fst_ap2, sta1, sta2)

def test_fst_disconnect_2_of_2_stas_from_fst_ap(dev, apdev, test_params):
    """FST disconnect 2 of 2 STAs from FST AP"""
    fst_ap1, fst_ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    with HWSimRadio() as (radio, iface):
        non_fst_ap = hostapd.add_ap(iface, { "ssid": "non_fst_11g"})
        try:
            vals = sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
            sta1.connect(fst_ap1, key_mgmt="NONE", scan_freq=fst_test_common.fst_test_def_freq_a)
            vals = sta2.scan()
            freq = vals['freq']
            sta2.connect_to_external_ap(non_fst_ap, ssid="non_fst_11g", key_mgmt="NONE", scan_freq=freq)
            time.sleep(2)
            sta2.disconnect_from_external_ap()
            time.sleep(2)
            orig_sta1_mbies = sta1.get_local_mbies()
            orig_sta2_mbies = sta2.get_local_mbies()
            sta1.disconnect()
            time.sleep(2)
            res_sta1_mbies = sta1.get_local_mbies()
            res_sta2_mbies = sta2.get_local_mbies()
            if (orig_sta1_mbies.startswith("FAIL") or
                orig_sta2_mbies.startswith("FAIL") or
                res_sta1_mbies.startswith("FAIL") or
                res_sta2_mbies.startswith("FAIL")):
                raise Exception("Failure. MB IEs should have stayed present on both stations")
            # Mandatory part of 8.4.2.140 Multi-band element is 24 bytes = 48 hex chars
            basic_sta1_mbies = res_sta1_mbies[0:48] + res_sta1_mbies[60:108]
            basic_sta2_mbies = res_sta2_mbies[0:48] + res_sta2_mbies[60:108]
            if (basic_sta1_mbies != basic_sta2_mbies):
                raise Exception("Failure. Basic MB IEs should have become identical on both stations")
            addr_sta1_str = sta1.get_own_mac_address().replace(":", "")
            addr_sta2_str = sta2.get_own_mac_address().replace(":", "")
            # Mandatory part of 8.4.2.140 Multi-band element is followed by STA MAC Address field (6 bytes = 12 hex chars)
            addr_sta1_mbie1 = res_sta1_mbies[48:60]
            addr_sta1_mbie2 = res_sta1_mbies[108:120]
            addr_sta2_mbie1 = res_sta2_mbies[48:60]
            addr_sta2_mbie2 = res_sta2_mbies[108:120]
            if (addr_sta1_mbie1 != addr_sta1_mbie2 or
                addr_sta1_mbie1 != addr_sta2_str or
                addr_sta2_mbie1 != addr_sta2_mbie2 or
                addr_sta2_mbie1 != addr_sta1_str):
                raise Exception("Failure. STA Address in MB IEs should have been same as the other STA's")
        except Exception, e:
            logger.info(e)
            raise
        finally:
            sta1.disconnect()
            sta2.disconnect_from_external_ap()
            fst_module_aux.stop_two_ap_sta_pairs(fst_ap1, fst_ap2, sta1, sta2)

def test_fst_disconnect_non_fst_sta(dev, apdev, test_params):
    """FST disconnect non-FST STA"""
    ap1, ap2, fst_sta1, fst_sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    external_sta_connected = False
    try:
        vals = fst_sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
        fst_sta1.connect(ap1, key_mgmt="NONE",
                         scan_freq=fst_test_common.fst_test_def_freq_a)
        vals = dev[0].scan(None, fst_test_common.fst_test_def_freq_g)
        fst_module_aux.external_sta_connect(dev[0], ap2, key_mgmt="NONE",
                                            scan_freq=fst_test_common.fst_test_def_freq_g)
        external_sta_connected = True
        time.sleep(2)
        fst_sta1.disconnect()
        time.sleep(2)
        orig_ap_mbies = ap2.get_local_mbies()
        fst_module_aux.disconnect_external_sta(dev[0], ap2)
        external_sta_connected = False
        time.sleep(2)
        res_ap_mbies = ap2.get_local_mbies()
        if res_ap_mbies != orig_ap_mbies:
            raise Exception("Failure. MB IEs have been unexpectedly updated on the AP")
    except Exception, e:
        logger.info(e)
        raise
    finally:
        fst_sta1.disconnect()
        if external_sta_connected:
            fst_module_aux.disconnect_external_sta(dev[0], ap2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, fst_sta1, fst_sta2)

def test_fst_disconnect_fst_sta(dev, apdev, test_params):
    """FST disconnect FST STA"""
    ap1, ap2, fst_sta1, fst_sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    external_sta_connected = False;
    try:
        vals = fst_sta1.scan(freq=fst_test_common.fst_test_def_freq_a)
        fst_sta1.connect(ap1, key_mgmt="NONE",
                         scan_freq=fst_test_common.fst_test_def_freq_a)
        vals = dev[0].scan(None, fst_test_common.fst_test_def_freq_g)
        fst_module_aux.external_sta_connect(dev[0], ap2, key_mgmt="NONE",
                                            scan_freq=fst_test_common.fst_test_def_freq_g)
        external_sta_connected = True
        time.sleep(2)
        fst_module_aux.disconnect_external_sta(dev[0], ap2)
        external_sta_connected = False
        time.sleep(2)
        orig_ap_mbies = ap2.get_local_mbies()
        fst_sta1.disconnect()
        time.sleep(2)
        res_ap_mbies = ap2.get_local_mbies()
        if res_ap_mbies != orig_ap_mbies:
            raise Exception("Failure. MB IEs have been unexpectedly updated on the AP")
    except Exception, e:
        logger.info(e)
        raise
    finally:
        fst_sta1.disconnect()
        if external_sta_connected:
            fst_module_aux.disconnect_external_sta(dev[0], ap2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, fst_sta1, fst_sta2)

def test_fst_dynamic_iface_attach(dev, apdev, test_params):
    """FST dynamic interface attach"""
    ap1 = fst_module_aux.FstAP(apdev[0]['ifname'], 'fst_11a', 'a',
                               fst_test_common.fst_test_def_chan_a,
                               fst_test_common.fst_test_def_group,
                               fst_test_common.fst_test_def_prio_low,
                               fst_test_common.fst_test_def_llt)
    ap1.start()
    ap2 = fst_module_aux.FstAP(apdev[1]['ifname'], 'fst_11g', 'b',
                               fst_test_common.fst_test_def_chan_g,
                               '', '', '')
    ap2.start()

    sta1 = fst_module_aux.FstSTA('wlan5',
                                 fst_module_aux.fst_test_common.fst_test_def_group,
                                 fst_test_common.fst_test_def_prio_low,
                                 fst_test_common.fst_test_def_llt)
    sta1.start()
    sta2 = fst_module_aux.FstSTA('wlan6', '', '', '')
    sta2.start()

    try:
        orig_sta2_mbies = sta2.get_local_mbies()
        orig_ap2_mbies = ap2.get_local_mbies()
        sta2.send_iface_attach_request(sta2.ifname(),
                                       fst_module_aux.fst_test_common.fst_test_def_group,
                                       '52', '27')
        event = sta2.wait_for_iface_event(5)
        if event['event_type'] != 'attached':
            raise Exception("Failure. Iface was not properly attached")
        ap2.send_iface_attach_request(ap2.ifname(),
                                      fst_module_aux.fst_test_common.fst_test_def_group,
                                      '102', '77')
        event = ap2.wait_for_iface_event(5)
        if event['event_type'] != 'attached':
            raise Exception("Failure. Iface was not properly attached")
        time.sleep(2)
        res_sta2_mbies = sta2.get_local_mbies()
        res_ap2_mbies = ap2.get_local_mbies()
        sta2.send_iface_detach_request(sta2.ifname())
        event = sta2.wait_for_iface_event(5)
        if event['event_type'] != 'detached':
            raise Exception("Failure. Iface was not properly detached")
        ap2.send_iface_detach_request(ap2.ifname())
        event = ap2.wait_for_iface_event(5)
        if event['event_type'] != 'detached':
            raise Exception("Failure. Iface was not properly detached")
        if (not orig_sta2_mbies.startswith("FAIL") or
            not orig_ap2_mbies.startswith("FAIL") or
            res_sta2_mbies.startswith("FAIL") or
            res_ap2_mbies.startswith("FAIL")):
            raise Exception("Failure. MB IEs should have appeared on the station and on the AP")
    except Exception, e:
        logger.info(e)
        raise
    finally:
        ap1.stop()
        ap2.stop()
        sta1.stop()
        sta2.stop()

# AP side FST module tests

def test_fst_ap_start_session(dev, apdev, test_params):
    """FST AP start session"""
    fst_start_session(apdev, test_params, bad_param_none, True)

def test_fst_ap_start_session_no_add_params(dev, apdev, test_params):
    """FST AP start session - no add params"""
    fst_start_session(apdev, test_params, bad_param_session_add_no_params, True)

def test_fst_ap_start_session_bad_group_id(dev, apdev, test_params):
    """FST AP start session - bad group id"""
    fst_start_session(apdev, test_params, bad_param_group_id, True)

def test_fst_ap_start_session_no_set_params(dev, apdev, test_params):
    """FST AP start session - no set params"""
    fst_start_session(apdev, test_params, bad_param_session_set_no_params, True)

def test_fst_ap_start_session_set_unknown_param(dev, apdev, test_params):
    """FST AP start session - set unknown param"""
    fst_start_session(apdev, test_params, bad_param_session_set_unknown_param,
                      True)

def test_fst_ap_start_session_bad_session_id(dev, apdev, test_params):
    """FST AP start session - bad session id"""
    fst_start_session(apdev, test_params, bad_param_session_id, True)

def test_fst_ap_start_session_bad_new_iface(dev, apdev, test_params):
    """FST AP start session - bad new iface"""
    fst_start_session(apdev, test_params, bad_param_new_iface, True)

def test_fst_ap_start_session_bad_old_iface(dev, apdev, test_params):
    """FST AP start session - bad old iface"""
    fst_start_session(apdev, test_params, bad_param_old_iface, True)

def test_fst_ap_start_session_negative_llt(dev, apdev, test_params):
    """FST AP start session - negative llt"""
    fst_start_session(apdev, test_params, bad_param_negative_llt, True)

def test_fst_ap_start_session_zero_llt(dev, apdev, test_params):
    """FST AP start session - zero llt"""
    fst_start_session(apdev, test_params, bad_param_zero_llt, True)

def test_fst_ap_start_session_llt_too_big(dev, apdev, test_params):
    """FST AP start session - llt too large"""
    fst_start_session(apdev, test_params, bad_param_llt_too_big, True)

def test_fst_ap_start_session_invalid_peer_addr(dev, apdev, test_params):
    """FST AP start session - invalid peer address"""
    fst_start_session(apdev, test_params, bad_param_peer_addr, True,
                      'GG:GG:GG:GG:GG:GG')

def test_fst_ap_start_session_multicast_peer_addr(dev, apdev, test_params):
    """FST AP start session - multicast peer address"""
    fst_start_session(apdev, test_params, bad_param_peer_addr, True,
                      '01:00:11:22:33:44')

def test_fst_ap_start_session_broadcast_peer_addr(dev, apdev, test_params):
    """FST AP start session - broadcast peer address"""
    fst_start_session(apdev, test_params, bad_param_peer_addr, True,
                      'FF:FF:FF:FF:FF:FF')

def test_fst_ap_initiate_session(dev, apdev, test_params):
    """FST AP initiate session"""
    fst_initiate_session(apdev, test_params, bad_param_none, True)

def test_fst_ap_initiate_session_no_params(dev, apdev, test_params):
    """FST AP initiate session - no params"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_no_params, True)

def test_fst_ap_initiate_session_invalid_session_id(dev, apdev, test_params):
    """FST AP initiate session - invalid session id"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_bad_session_id, True)

def test_fst_ap_initiate_session_no_new_iface(dev, apdev, test_params):
    """FST AP initiate session - no new iface"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_with_no_new_iface_set, True)

def test_fst_ap_initiate_session_bad_peer_addr(dev, apdev, test_params):
    """FST AP initiate session - bad peer address"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_with_bad_peer_addr_set,
                         True)

def test_fst_ap_initiate_session_request_with_bad_stie(dev, apdev, test_params):
    """FST AP initiate session - request with bad stie"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_request_with_bad_stie, True)

def test_fst_ap_initiate_session_response_with_reject(dev, apdev, test_params):
    """FST AP initiate session - response with reject"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_response_with_reject, True)

def test_fst_ap_initiate_session_response_with_bad_stie(dev, apdev,
                                                        test_params):
    """FST AP initiate session - response with bad stie"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_response_with_bad_stie,
                         True)

def test_fst_ap_initiate_session_response_with_zero_llt(dev, apdev,
                                                        test_params):
    """FST AP initiate session - zero llt"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_response_with_zero_llt,
                         True)

def test_fst_ap_initiate_session_stt_no_response(dev, apdev, test_params):
    """FST AP initiate session - stt no response"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_stt_no_response, True)

def test_fst_ap_initiate_session_concurrent_setup_request(dev, apdev,
                                                          test_params):
    """FST AP initiate session - concurrent setup request"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_concurrent_setup_request,
                         True)

def test_fst_ap_session_request_with_no_session(dev, apdev, test_params):
    """FST AP session request with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_session_request,
                              True)

def test_fst_ap_session_response_accept_with_no_session(dev, apdev,
                                                        test_params):
    """FST AP session response accept with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_session_response,
                              True, "accept")

def test_fst_ap_session_response_reject_with_no_session(dev, apdev,
                                                        test_params):
    """FST AP session response reject with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_session_response,
                              True, "reject")

def test_fst_ap_ack_request_with_no_session(dev, apdev, test_params):
    """FST AP ack request with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_ack_request, True)

def test_fst_ap_ack_response_with_no_session(dev, apdev, test_params):
    """FST AP ack response with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_ack_response, True)

def test_fst_ap_tear_down_response_with_no_session(dev, apdev, test_params):
    """FST AP tear down response with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_tear_down, True)

def test_fst_ap_transfer_session(dev, apdev, test_params):
    """FST AP transfer session"""
    fst_transfer_session(apdev, test_params, bad_param_none, True)

def test_fst_ap_transfer_session_no_params(dev, apdev, test_params):
    """FST AP transfer session - no params"""
    fst_transfer_session(apdev, test_params,
                         bad_param_session_transfer_no_params, True)

def test_fst_ap_transfer_session_bad_session_id(dev, apdev, test_params):
    """FST AP transfer session - bad session id"""
    fst_transfer_session(apdev, test_params,
                         bad_param_session_transfer_bad_session_id, True)

def test_fst_ap_transfer_session_setup_skipped(dev, apdev, test_params):
    """FST AP transfer session - setup skipped"""
    fst_transfer_session(apdev, test_params,
                         bad_param_session_transfer_setup_skipped, True)

def test_fst_ap_ack_request_with_session_not_set_up(dev, apdev, test_params):
    """FST AP ack request with session not set up"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_req_session_not_set_up, True)

def test_fst_ap_ack_request_with_session_not_established_init_side(dev, apdev,
                                                                   test_params):
    """FST AP ack request with session not established init side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_req_session_not_established_init_side,
                     True)

def test_fst_ap_ack_request_with_session_not_established_resp_side(dev, apdev,
                                                                   test_params):
    """FST AP ack request with session not established resp side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_req_session_not_established_resp_side,
                     True)

def test_fst_ap_ack_request_with_bad_fsts_id(dev, apdev, test_params):
    """FST AP ack request with bad fsts id"""
    fst_bad_transfer(apdev, test_params, bad_scenario_ack_req_bad_fsts_id, True)

def test_fst_ap_ack_response_with_session_not_set_up(dev, apdev, test_params):
    """FST AP ack response with session not set up"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_resp_session_not_set_up, True)

def test_fst_ap_ack_response_with_session_not_established_init_side(dev, apdev, test_params):
    """FST AP ack response with session not established init side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_resp_session_not_established_init_side,
                     True)

def test_fst_ap_ack_response_with_session_not_established_resp_side(dev, apdev, test_params):
    """FST AP ack response with session not established resp side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_resp_session_not_established_resp_side,
                     True)

def test_fst_ap_ack_response_with_no_ack_request(dev, apdev, test_params):
    """FST AP ack response with no ack request"""
    fst_bad_transfer(apdev, test_params, bad_scenario_ack_resp_no_ack_req, True)

def test_fst_ap_tear_down_session(dev, apdev, test_params):
    """FST AP tear down session"""
    fst_tear_down_session(apdev, test_params, bad_param_none, True)

def test_fst_ap_tear_down_session_no_params(dev, apdev, test_params):
    """FST AP tear down session - no params"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_no_params, True)

def test_fst_ap_tear_down_session_bad_session_id(dev, apdev, test_params):
    """FST AP tear down session - bad session id"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_bad_session_id, True)

def test_fst_ap_tear_down_session_setup_skipped(dev, apdev, test_params):
    """FST AP tear down session - setup skipped"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_setup_skipped, True)

def test_fst_ap_tear_down_session_bad_fsts_id(dev, apdev, test_params):
    """FST AP tear down session - bad fsts id"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_bad_fsts_id, True)

def test_fst_ap_remove_session_not_established(dev, apdev, test_params):
    """FST AP remove session - not established"""
    fst_remove_session(apdev, test_params,
                       remove_scenario_non_established_session, True)

def test_fst_ap_remove_session_established(dev, apdev, test_params):
    """FST AP remove session - established"""
    fst_remove_session(apdev, test_params,
                       remove_scenario_established_session, True)

def test_fst_ap_remove_session_no_params(dev, apdev, test_params):
    """FST AP remove session - no params"""
    fst_remove_session(apdev, test_params, remove_scenario_no_params, True)

def test_fst_ap_remove_session_bad_session_id(dev, apdev, test_params):
    """FST AP remove session - bad session id"""
    fst_remove_session(apdev, test_params, remove_scenario_bad_session_id, True)

def test_fst_ap_ctrl_iface(dev, apdev, test_params):
    """FST control interface behavior"""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        initiator = ap1
        responder = sta1
        initiator.add_peer(responder, None)
        initiator.set_fst_parameters(group_id=None)
        sid = initiator.add_session()
        res = initiator.get_session_params(sid)
        logger.info("Initial session params:\n" + str(res))
        if res['state'] != 'INITIAL':
            raise Exception("Unexpected state: " + res['state'])
        initiator.set_fst_parameters(llt=None)
        initiator.configure_session(sid, ap2.ifname(), None)
        res = initiator.get_session_params(sid)
        logger.info("Session params after configuration:\n" + str(res))
        res = initiator.iface_peers(initiator.ifname())
        logger.info("Interface peers: " + str(res))
        if len(res) != 1:
            raise Exception("Unexpected number of peers")
        res = initiator.get_peer_mbies(initiator.ifname(),
                                       initiator.get_new_peer_addr())
        logger.info("Peer MB IEs: " + str(res))
        res = initiator.list_ifaces()
        logger.info("Interfaces: " + str(res))
        if len(res) != 2:
            raise Exception("Unexpected number of interfaces")
        res = initiator.list_groups()
        logger.info("Groups: " + str(res))
        if len(res) != 1:
            raise Exception("Unexpected number of groups")

        tests = [ "LIST_IFACES unknown",
                  "LIST_IFACES     unknown2",
                  "SESSION_GET 12345678",
                  "SESSION_SET " + sid + " unknown=foo",
                  "SESSION_RESPOND 12345678 foo",
                  "SESSION_RESPOND " + sid,
                  "SESSION_RESPOND " + sid + " foo",
                  "TEST_REQUEST foo",
                  "GET_PEER_MBIES",
                  "GET_PEER_MBIES ",
                  "GET_PEER_MBIES unknown",
                  "GET_PEER_MBIES unknown unknown",
                  "GET_PEER_MBIES unknown  " + initiator.get_new_peer_addr(),
                  "GET_PEER_MBIES " + initiator.ifname() + " 01:ff:ff:ff:ff:ff",
                  "IFACE_PEERS",
                  "IFACE_PEERS ",
                  "IFACE_PEERS unknown",
                  "IFACE_PEERS unknown unknown",
                  "IFACE_PEERS " + initiator.fst_group,
                  "IFACE_PEERS " + initiator.fst_group + " unknown" ]
        for t in tests:
            if "FAIL" not in initiator.grequest("FST-MANAGER " + t):
                raise Exception("Unexpected response for invalid FST-MANAGER command " + t)
        if "UNKNOWN FST COMMAND" not in initiator.grequest("FST-MANAGER unknown"):
            raise Exception("Unexpected response for unknown FST-MANAGER command")

        tests = [ "FST-DETACH", "FST-DETACH ", "FST-DETACH unknown",
                  "FST-ATTACH", "FST-ATTACH ", "FST-ATTACH unknown",
                  "FST-ATTACH unknown unknown" ]
        for t in tests:
            if "FAIL" not in initiator.grequest(t):
                raise Exception("Unexpected response for invalid command " + t)

        try:
            # Trying to add same interface again needs to fail.
            ap1.send_iface_attach_request(ap1.iface, ap1.fst_group,
                                          ap1.fst_llt, ap1.fst_pri)
            raise Exception("Duplicate FST-ATTACH succeeded")
        except Exception, e:
            if not str(e).startswith("Cannot attach"):
                raise
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)

def test_fst_ap_start_session_oom(dev, apdev, test_params):
    """FST AP setup failing due to OOM"""
    ap1 = fst_module_aux.FstAP(apdev[0]['ifname'], 'fst_11a', 'a',
                               fst_test_common.fst_test_def_chan_a,
                               fst_test_common.fst_test_def_group,
                               fst_test_common.fst_test_def_prio_low,
                               fst_test_common.fst_test_def_llt)
    ap1.start()
    with alloc_fail(ap1, 1, "fst_iface_create"):
        ap2_started = False
        try:
            ap2 = fst_module_aux.FstAP(apdev[1]['ifname'], 'fst_11g', 'b',
                                       fst_test_common.fst_test_def_chan_g,
                                       fst_test_common.fst_test_def_group,
                                       fst_test_common.fst_test_def_prio_high,
                                       fst_test_common.fst_test_def_llt)
            try:
                # This will fail in fst_iface_create() OOM
                ap2.start()
            except:
                pass
        finally:
            ap1.stop()
            try:
                ap2.stop()
            except:
                pass

# STA side FST module tests

def test_fst_sta_start_session(dev, apdev, test_params):
    """FST STA start session"""
    fst_start_session(apdev, test_params, bad_param_none, False)

def test_fst_sta_start_session_no_add_params(dev, apdev, test_params):
    """FST STA start session - no add params"""
    fst_start_session(apdev, test_params, bad_param_session_add_no_params,
                      False)

def test_fst_sta_start_session_bad_group_id(dev, apdev, test_params):
    """FST STA start session - bad group id"""
    fst_start_session(apdev, test_params, bad_param_group_id, False)

def test_fst_sta_start_session_no_set_params(dev, apdev, test_params):
    """FST STA start session - no set params"""
    fst_start_session(apdev, test_params, bad_param_session_set_no_params,
                      False)

def test_fst_sta_start_session_set_unknown_param(dev, apdev, test_params):
    """FST STA start session - set unknown param"""
    fst_start_session(apdev, test_params, bad_param_session_set_unknown_param,
                      False)

def test_fst_sta_start_session_bad_session_id(dev, apdev, test_params):
    """FST STA start session - bad session id"""
    fst_start_session(apdev, test_params, bad_param_session_id, False)

def test_fst_sta_start_session_bad_new_iface(dev, apdev, test_params):
    """FST STA start session - bad new iface"""
    fst_start_session(apdev, test_params, bad_param_new_iface, False)

def test_fst_sta_start_session_bad_old_iface(dev, apdev, test_params):
    """FST STA start session - bad old iface"""
    fst_start_session(apdev, test_params, bad_param_old_iface, False)

def test_fst_sta_start_session_negative_llt(dev, apdev, test_params):
    """FST STA start session - negative llt"""
    fst_start_session(apdev, test_params, bad_param_negative_llt, False)

def test_fst_sta_start_session_zero_llt(dev, apdev, test_params):
    """FST STA start session - zero llt"""
    fst_start_session(apdev, test_params, bad_param_zero_llt, False)

def test_fst_sta_start_session_llt_too_big(dev, apdev, test_params):
    """FST STA start session - llt too large"""
    fst_start_session(apdev, test_params, bad_param_llt_too_big, False)

def test_fst_sta_start_session_invalid_peer_addr(dev, apdev, test_params):
    """FST STA start session - invalid peer address"""
    fst_start_session(apdev, test_params, bad_param_peer_addr, False,
                      'GG:GG:GG:GG:GG:GG')

def test_fst_sta_start_session_multicast_peer_addr(dev, apdev, test_params):
    """FST STA start session - multicast peer address"""
    fst_start_session(apdev, test_params, bad_param_peer_addr, False,
                      '11:00:11:22:33:44')

def test_fst_sta_start_session_broadcast_peer_addr(dev, apdev, test_params):
    """FST STA start session - broadcast peer addr"""
    fst_start_session(apdev, test_params, bad_param_peer_addr, False,
                      'FF:FF:FF:FF:FF:FF')

def test_fst_sta_initiate_session(dev, apdev, test_params):
    """FST STA initiate session"""
    fst_initiate_session(apdev, test_params, bad_param_none, False)

def test_fst_sta_initiate_session_no_params(dev, apdev, test_params):
    """FST STA initiate session - no params"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_no_params, False)

def test_fst_sta_initiate_session_invalid_session_id(dev, apdev, test_params):
    """FST STA initiate session - invalid session id"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_bad_session_id, False)

def test_fst_sta_initiate_session_no_new_iface(dev, apdev, test_params):
    """FST STA initiate session - no new iface"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_with_no_new_iface_set,
                         False)

def test_fst_sta_initiate_session_bad_peer_addr(dev, apdev, test_params):
    """FST STA initiate session - bad peer address"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_with_bad_peer_addr_set,
                         False)

def test_fst_sta_initiate_session_request_with_bad_stie(dev, apdev,
                                                        test_params):
    """FST STA initiate session - request with bad stie"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_request_with_bad_stie,
                         False)

def test_fst_sta_initiate_session_response_with_reject(dev, apdev, test_params):
    """FST STA initiate session - response with reject"""
    fst_initiate_session(apdev, test_params, bad_param_session_initiate_response_with_reject, False)

def test_fst_sta_initiate_session_response_with_bad_stie(dev, apdev, test_params):
    """FST STA initiate session - response with bad stie"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_response_with_bad_stie,
                         False)

def test_fst_sta_initiate_session_response_with_zero_llt(dev, apdev,
                                                         test_params):
    """FST STA initiate session - response with zero llt"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_response_with_zero_llt,
                         False)

def test_fst_sta_initiate_session_stt_no_response(dev, apdev, test_params):
    """FST STA initiate session - stt no response"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_stt_no_response, False)

def test_fst_sta_initiate_session_concurrent_setup_request(dev, apdev,
                                                           test_params):
    """FST STA initiate session - concurrent setup request"""
    fst_initiate_session(apdev, test_params,
                         bad_param_session_initiate_concurrent_setup_request,
                         False)

def test_fst_sta_session_request_with_no_session(dev, apdev, test_params):
    """FST STA session request with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_session_request,
                              False)

def test_fst_sta_session_response_accept_with_no_session(dev, apdev,
                                                         test_params):
    """FST STA session response accept with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_session_response,
                              False, "accept")

def test_fst_sta_session_response_reject_with_no_session(dev, apdev,
                                                         test_params):
    """FST STA session response reject with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_session_response,
                              False, "reject")

def test_fst_sta_ack_request_with_no_session(dev, apdev, test_params):
    """FST STA ack request with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_ack_request, False)

def test_fst_sta_ack_response_with_no_session(dev, apdev, test_params):
    """FST STA ack response with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_ack_response,
                              False)

def test_fst_sta_tear_down_response_with_no_session(dev, apdev, test_params):
    """FST STA tear down response with no session"""
    fst_send_unexpected_frame(apdev, test_params, frame_type_tear_down, False)

def test_fst_sta_transfer_session(dev, apdev, test_params):
    """FST STA transfer session"""
    fst_transfer_session(apdev, test_params, bad_param_none, False)

def test_fst_sta_transfer_session_no_params(dev, apdev, test_params):
    """FST STA transfer session - no params"""
    fst_transfer_session(apdev, test_params,
                         bad_param_session_transfer_no_params, False)

def test_fst_sta_transfer_session_bad_session_id(dev, apdev, test_params):
    """FST STA transfer session - bad session id"""
    fst_transfer_session(apdev, test_params,
                         bad_param_session_transfer_bad_session_id, False)

def test_fst_sta_transfer_session_setup_skipped(dev, apdev, test_params):
    """FST STA transfer session - setup skipped"""
    fst_transfer_session(apdev, test_params,
                         bad_param_session_transfer_setup_skipped, False)

def test_fst_sta_ack_request_with_session_not_set_up(dev, apdev, test_params):
    """FST STA ack request with session not set up"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_req_session_not_set_up, False)

def test_fst_sta_ack_request_with_session_not_established_init_side(dev, apdev, test_params):
    """FST STA ack request with session not established init side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_req_session_not_established_init_side,
                     False)

def test_fst_sta_ack_request_with_session_not_established_resp_side(dev, apdev, test_params):
    """FST STA ack request with session not established resp side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_req_session_not_established_resp_side,
                     False)

def test_fst_sta_ack_request_with_bad_fsts_id(dev, apdev, test_params):
    """FST STA ack request with bad fsts id"""
    fst_bad_transfer(apdev, test_params, bad_scenario_ack_req_bad_fsts_id,
                     False)

def test_fst_sta_ack_response_with_session_not_set_up(dev, apdev, test_params):
    """FST STA ack response with session not set up"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_resp_session_not_set_up, False)

def test_fst_sta_ack_response_with_session_not_established_init_side(dev, apdev, test_params):
    """FST STA ack response with session not established init side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_resp_session_not_established_init_side,
                     False)

def test_fst_sta_ack_response_with_session_not_established_resp_side(dev, apdev, test_params):
    """FST STA ack response with session not established resp side"""
    fst_bad_transfer(apdev, test_params,
                     bad_scenario_ack_resp_session_not_established_resp_side,
                     False)

def test_fst_sta_ack_response_with_no_ack_request(dev, apdev, test_params):
    """FST STA ack response with no ack request"""
    fst_bad_transfer(apdev, test_params, bad_scenario_ack_resp_no_ack_req,
                     False)

def test_fst_sta_tear_down_session(dev, apdev, test_params):
    """FST STA tear down session"""
    fst_tear_down_session(apdev, test_params, bad_param_none, False)

def test_fst_sta_tear_down_session_no_params(dev, apdev, test_params):
    """FST STA tear down session - no params"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_no_params, False)

def test_fst_sta_tear_down_session_bad_session_id(dev, apdev, test_params):
    """FST STA tear down session - bad session id"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_bad_session_id, False)

def test_fst_sta_tear_down_session_setup_skipped(dev, apdev, test_params):
    """FST STA tear down session - setup skipped"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_setup_skipped, False)

def test_fst_sta_tear_down_session_bad_fsts_id(dev, apdev, test_params):
    """FST STA tear down session - bad fsts id"""
    fst_tear_down_session(apdev, test_params,
                          bad_param_session_teardown_bad_fsts_id, False)

def test_fst_sta_remove_session_not_established(dev, apdev, test_params):
    """FST STA tear down session - not established"""
    fst_remove_session(apdev, test_params,
                       remove_scenario_non_established_session, False)

def test_fst_sta_remove_session_established(dev, apdev, test_params):
    """FST STA remove session - established"""
    fst_remove_session(apdev, test_params,
                       remove_scenario_established_session, False)

def test_fst_sta_remove_session_no_params(dev, apdev, test_params):
    """FST STA remove session - no params"""
    fst_remove_session(apdev, test_params, remove_scenario_no_params, False)

def test_fst_sta_remove_session_bad_session_id(dev, apdev, test_params):
    """FST STA remove session - bad session id"""
    fst_remove_session(apdev, test_params, remove_scenario_bad_session_id,
                       False)

def test_fst_rsn_ap_transfer_session(dev, apdev, test_params):
    """FST RSN AP transfer session"""
    fst_transfer_session(apdev, test_params, bad_param_none, True, rsn=True)

MGMT_SUBTYPE_ACTION = 13
ACTION_CATEG_FST = 18
FST_ACTION_SETUP_REQUEST = 0
FST_ACTION_SETUP_RESPONSE = 1
FST_ACTION_TEAR_DOWN = 2
FST_ACTION_ACK_REQUEST = 3
FST_ACTION_ACK_RESPONSE = 4
FST_ACTION_ON_CHANNEL_TUNNEL = 5

def test_fst_proto(dev, apdev, test_params):
    """FST protocol testing"""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        hapd = ap1.get_instance()
        sta = sta1.get_instance()
        dst = sta.own_addr()
        src = apdev[0]['bssid']

        msg = {}
        msg['fc'] = MGMT_SUBTYPE_ACTION << 4
        msg['da'] = dst
        msg['sa'] = src
        msg['bssid'] = src

        # unknown FST Action (255) received!
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST, 255)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # FST Request dropped: too short
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                     FST_ACTION_SETUP_REQUEST)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # FST Request dropped: new and old band IDs are the same
        msg['payload'] = struct.pack("<BBBLBBLBBBBBBB", ACTION_CATEG_FST,
                                     FST_ACTION_SETUP_REQUEST, 0, 0,
                                     164, 11, 0, 0, 0, 0, 0, 0, 0, 0)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        ifaces = sta1.list_ifaces()
        id = int(ifaces[0]['name'].split('|')[1])
        # FST Request dropped: new iface not found (new_band_id mismatch)
        msg['payload'] = struct.pack("<BBBLBBLBBBBBBB", ACTION_CATEG_FST,
                                     FST_ACTION_SETUP_REQUEST, 0, 0,
                                     164, 11, 0, 0, id + 1, 0, 0, 0, 0, 0)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # FST Action 'Setup Response' dropped: no session in progress found
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                     FST_ACTION_SETUP_RESPONSE)
        hapd.mgmt_tx(msg)

        # Create session
        initiator = ap1
        responder = sta1
        new_iface = ap2.ifname()
        new_peer_addr = ap2.get_actual_peer_addr()
        resp_newif = sta2.ifname()
        peeraddr = None
        initiator.add_peer(responder, peeraddr, new_peer_addr)
        sid = initiator.add_session()
        initiator.configure_session(sid, new_iface)
        initiator.initiate_session(sid, "accept")

        # FST Response dropped due to wrong state: SETUP_COMPLETION
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                     FST_ACTION_SETUP_RESPONSE)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # Too short FST Tear Down dropped
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                     FST_ACTION_TEAR_DOWN)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # tear down for wrong FST Setup ID (0)
        msg['payload'] = struct.pack("<BBL", ACTION_CATEG_FST,
                                     FST_ACTION_TEAR_DOWN, 0)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # Ack received on wrong interface
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                     FST_ACTION_ACK_REQUEST)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # Ack Response in inappropriate session state (SETUP_COMPLETION)
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                     FST_ACTION_ACK_RESPONSE)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # Unsupported FST Action frame (On channel tunnel)
        msg['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                     FST_ACTION_ON_CHANNEL_TUNNEL)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        # FST Request dropped: new iface not found (new_band_id match)
        # FST Request dropped due to MAC comparison
        msg['payload'] = struct.pack("<BBBLBBLBBBBBBB", ACTION_CATEG_FST,
                                     FST_ACTION_SETUP_REQUEST, 0, 0,
                                     164, 11, 0, 0, id, 0, 0, 0, 0, 0)
        hapd.mgmt_tx(msg)
        time.sleep(0.1)

        hapd2 = ap2.get_instance()
        dst2 = sta2.get_instance().own_addr()
        src2 = apdev[1]['bssid']

        msg2 = {}
        msg2['fc'] = MGMT_SUBTYPE_ACTION << 4
        msg2['da'] = dst2
        msg2['sa'] = src2
        msg2['bssid'] = src2
        # FST Response dropped: wlan6 is not the old iface
        msg2['payload'] = struct.pack("<BB", ACTION_CATEG_FST,
                                      FST_ACTION_SETUP_RESPONSE)
        hapd2.mgmt_tx(msg2)
        time.sleep(0.1)

        sta.dump_monitor()

        group = ap1.fst_group
        ap1.send_iface_detach_request(ap1.iface)

        sta.flush_scan_cache()
        sta.request("REASSOCIATE")
        sta.wait_connected()

        # FST Request dropped due to no interface connection
        msg['payload'] = struct.pack("<BBBLBBLBBBBBBB", ACTION_CATEG_FST,
                                     FST_ACTION_SETUP_REQUEST, 0, 0,
                                     164, 11, 0, 0, id, 0, 0, 0, 0, 0)
        hapd.mgmt_tx(msg)
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        try:
            fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        except:
            pass

def test_fst_ap_config_oom(dev, apdev, test_params):
    """FST AP configuration and OOM"""
    ap1 = fst_module_aux.FstAP(apdev[0]['ifname'], 'fst_11a', 'a',
                               fst_test_common.fst_test_def_chan_a,
                               fst_test_common.fst_test_def_group,
                               fst_test_common.fst_test_def_prio_low)
    hapd = ap1.start(return_early=True)
    with alloc_fail(hapd, 1, "fst_group_create"):
        res = ap1.grequest("FST-ATTACH %s %s" % (ap1.iface, ap1.fst_group))
        if not res.startswith("FAIL"):
            raise Exception("FST-ATTACH succeeded unexpectedly")

    with alloc_fail(hapd, 1, "fst_group_create_mb_ie"):
        res = ap1.grequest("FST-ATTACH %s %s" % (ap1.iface, ap1.fst_group))
        # This is allowed to complete currently

    ap1.stop()

def test_fst_send_oom(dev, apdev, test_params):
    """FST send action OOM"""
    ap1, ap2, sta1, sta2 = fst_module_aux.start_two_ap_sta_pairs(apdev)
    try:
        fst_module_aux.connect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        hapd = ap1.get_instance()
        sta = sta1.get_instance()
        dst = sta.own_addr()
        src = apdev[0]['bssid']

        # Create session
        initiator = ap1
        responder = sta1
        new_iface = ap2.ifname()
        new_peer_addr = ap2.get_actual_peer_addr()
        resp_newif = sta2.ifname()
        peeraddr = None
        initiator.add_peer(responder, peeraddr, new_peer_addr)
        sid = initiator.add_session()
        initiator.configure_session(sid, new_iface)
        with alloc_fail(hapd, 1, "fst_session_send_action"):
            res = initiator.grequest("FST-MANAGER SESSION_INITIATE " + sid)
            if not res.startswith("FAIL"):
                raise Exception("Unexpected SESSION_INITIATE result")

        res = initiator.grequest("FST-MANAGER SESSION_INITIATE " + sid)
        if not res.startswith("OK"):
            raise Exception("SESSION_INITIATE failed")

        with alloc_fail(hapd, 1, "fst_session_send_action"):
            res = initiator.grequest("FST-MANAGER SESSION_TEARDOWN " + sid)
            if not res.startswith("FAIL"):
                raise Exception("Unexpected SESSION_TEARDOWN result")
    finally:
        fst_module_aux.disconnect_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
        fst_module_aux.stop_two_ap_sta_pairs(ap1, ap2, sta1, sta2)
