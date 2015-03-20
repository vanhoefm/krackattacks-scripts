# P2P services
# Copyright (c) 2014-2015, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time
import random

import hwsim_utils
from wpasupplicant import WpaSupplicant
from test_p2p_grpform import check_grpform_results
from test_p2p_grpform import remove_group
from test_p2p_persistent import go_neg_pin_authorized_persistent

# Dev[0] -> Advertiser
# Dev[1] -> Seeker
# ev0 -> Event generated at advertiser side
# ev1 -> Event generated at Seeker side

def p2ps_advertise(r_dev, r_role, svc_name, srv_info, rsp_info=None):
    """P2PS Advertise function"""
    adv_id = random.randrange(1, 0xFFFFFFFF)
    advid = hex(adv_id)[2:]

    if rsp_info is not None and srv_info is not None:
        if "OK" not in r_dev.global_request("P2P_SERVICE_ADD asp " + str(r_role) + " " + str(advid) + " 1 1108 " + svc_name + " svc_info='" + srv_info + "'" + " rsp_info=" + rsp_info + "'"):
            raise Exception("P2P_SERVICE_ADD with response info and service info failed")

    if rsp_info is None and srv_info is not None:
        if "OK" not in r_dev.global_request("P2P_SERVICE_ADD asp " + str(r_role) + " " + str(advid) + " 1 1108 " + svc_name + " svc_info='" + srv_info + "'"):
            raise Exception("P2P_SERVICE_ADD with service info failed")

    if rsp_info is None and srv_info is None:
        if "OK" not in r_dev.global_request("P2P_SERVICE_ADD asp " + str(r_role) + " " + str(advid) + " 1 1108 " + svc_name + " "):
            raise Exception("P2P_SERVICE_ADD without service info and without response info failed")

    if rsp_info is not None and srv_info is None:
        if "OK" not in r_dev.global_request("P2P_SERVICE_ADD asp " + str(r_role) + " " + str(adv_id) + " 1 1108 " + svc_name + " svc_info='" + " rsp_info=" + rsp_info + "'"):
            raise Exception("P2P_SERVICE_ADD with response info failed")

    r_dev.p2p_listen()
    return advid

def p2ps_exact_seek(i_dev, r_dev, svc_name, srv_info=None):
    """P2PS exact service seek request"""
    if srv_info is not None:
        ev1 = i_dev.global_request("P2P_SERV_DISC_REQ 00:00:00:00:00:00 asp 1 " + svc_name + " '" + srv_info + "'")
        if ev1 is None:
            raise Exception("Failed to add Service Discovery request for exact seek request")

    if "OK" not in i_dev.global_request("P2P_FIND 10 type=social seek=" + svc_name):
        raise Exception("Failed to initiate seek operation")

    ev1 = i_dev.wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
    if ev1 is None:
        raise Exception("P2P-DEVICE-FOUND timeout on seeker side")
    if r_dev.p2p_dev_addr() not in ev1:
        raise Exception("Unexpected peer")

    if srv_info is None:
        adv_id = ev1.split("adv_id=")[1].split(" ")[0]
        rcvd_svc_name = ev1.split("asp_svc=")[1].split(" ")[0]
        if rcvd_svc_name != svc_name:
            raise Exception("service name not matching")
    else:
        ev1 = i_dev.wait_global_event(["P2P-SERV-ASP-RESP"], timeout=10)
        if ev1 is None:
            raise Exception("Failed to receive Service Discovery Response")
        if r_dev.p2p_dev_addr() not in ev1:
            raise Exception("Service Discovery response from Unknown Peer")
        if srv_info is not None and srv_info not in ev1:
            raise Exception("service info not available in Service Discovery response")
        adv_id = ev1.split(" ")[3]
        rcvd_svc_name = ev1.split(" ")[6]
        if rcvd_svc_name != svc_name:
            raise Exception("service name not matching")

    return [adv_id, rcvd_svc_name]

def p2ps_nonexact_seek(i_dev, r_dev, svc_name, srv_info=None, adv_num=None):
    """P2PS nonexact service seek request"""
    if adv_num is None:
       adv_num = 1
    if srv_info is not None:
        ev1 = i_dev.global_request("P2P_SERV_DISC_REQ 00:00:00:00:00:00 asp 1 " + svc_name + " '" + srv_info + "'")
    else:
        ev1 = i_dev.global_request("P2P_SERV_DISC_REQ 00:00:00:00:00:00 asp 1 " + svc_name + " '")
    if ev1 is None:
        raise Exception("Failed to add Service Discovery request for nonexact seek request")
    if "OK" not in i_dev.global_request("P2P_FIND 10 type=social seek="):
        raise Exception("Failed to initiate seek")
    ev1 = i_dev.wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
    if ev1 is None:
        raise Exception("P2P-DEVICE-FOUND timeout on seeker side")
    if r_dev.p2p_dev_addr() not in ev1:
        raise Exception("Unexpected peer")
    ev_list = []
    for i in range (0, adv_num):
        ev1 = i_dev.wait_global_event(["P2P-SERV-ASP-RESP"], timeout=10)
        if ev1 is None:
            raise Exception("Failed to receive Service Discovery Response")
        if r_dev.p2p_dev_addr() not in ev1:
            raise Exception("Service Discovery response from Unknown Peer")
        if srv_info is not None and srv_info not in ev1:
            raise Exception("service info not available in Service Discovery response")
        adv_id = ev1.split(" ")[3]
        rcvd_svc_name = ev1.split(" ")[6]
        ev_list.append(''.join([adv_id, ' ', rcvd_svc_name]))
    return ev_list

def p2p_connect_p2ps_method(i_dev, r_dev, autoaccept):
    """P2PS connect function with p2ps method"""
    if autoaccept == False:
        if "OK" not in i_dev.global_request("P2P_CONNECT " + r_dev.p2p_dev_addr() + " 12345670 p2ps persistent auth"):
            raise Exception("P2P_CONNECT fails on seeker side")
        ev0 = r_dev.wait_global_event(["P2PS-PROV-DONE"], timeout=10)
        if ev0 is None:
            raise Exception("P2PS-PROV-DONE timeout on Advertiser side")

        if "OK" not in r_dev.global_request("P2P_CONNECT " + i_dev.p2p_dev_addr() + " 12345670 p2ps persistent"):
            raise Exception("P2P_CONNECT fails on Advertiser side")

    else:
        if "OK" not in r_dev.global_request("P2P_CONNECT " + i_dev.p2p_dev_addr() + " 12345670 p2ps persistent auth"):
            raise Exception("P2P_CONNECT fails on Advertiser side")
        ev1 = i_dev.wait_global_event(["P2PS-PROV-DONE"], timeout=5)
        if ev1 is None:
            raise Exception("Failed to receive deferred acceptance at seeker")

        if "OK" not in i_dev.global_request("P2P_CONNECT " + r_dev.p2p_dev_addr() + " 12345670 p2ps persistent"):
            raise Exception("P2P_CONNECT fails on seeker side")
    ev0 = r_dev.wait_global_event(["P2P-GO-NEG-SUCCESS"], timeout=10)
    if ev0 is None:
        raise Exception("GO Neg did not succeed")
    ev0 = r_dev.wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev0 is None:
        raise Exception("P2P-GROUP-STARTED timeout on advertiser side")
    ev1 = i_dev.wait_global_event(["P2P-GROUP-STARTED"], timeout=5)
    if ev1 is None:
        raise Exception("P2P-GROUP-STARTED timeout on seeker side")

def p2ps_provision_keypad_method(i_dev, r_dev, autoaccept,
                                 initiator_or_responder):
    """P2PS keypad method provisioning function"""
    if autoaccept == False and initiator_or_responder == 'initiator':
        ev = i_dev.wait_global_event(["P2P-PROV-DISC-FAILURE"], timeout=10)
        if ev is None:
            raise Exception("Provisioning deferred on seeker side")
        ev1 = i_dev.wait_global_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=10)
        if ev1 is None:
            raise Exception("P2P-PROV-DISC-ENTER-PIN timeout on seeker side")
        if r_dev.p2p_dev_addr() not in ev1:
            raise Exception("Unknown peer ")
        ev = r_dev.wait_global_event(["P2PS-PROV-START"], timeout=10)
        if ev is None:
            raise Exception("P2PS-PROV-START timeout on Advertiser side")

    if autoaccept == False and initiator_or_responder == 'responder':
        ev0 = r_dev.wait_global_event(["P2PS-PROV-DONE"], timeout=10)
        if ev0 is None:
            raise Exception("P2PS-PROV-DONE timeout on seeker side")
        ev0 = r_dev.wait_global_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=5)
        if ev0 is None:
            raise Exception("P2P-PROV-DISC-ENTER-PIN timeout on advertiser side")

    if autoaccept == True and initiator_or_responder == 'initiator':
        ev1 = i_dev.wait_global_event(["P2PS-PROV-DONE"], timeout=10)
        if ev1 is None:
            raise Exception("P2PS-PROV-DONE timeout on seeker side")
        ev1 = i_dev.wait_global_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=10)
        if ev1 is None:
            raise Exception("P2P-PROV-DISC-ENTER-PIN failed on seeker side")
        if r_dev.p2p_dev_addr() not in ev1:
            raise Exception("Unknown peer ")
        return ev1

def p2ps_provision_display_method(i_dev, r_dev, autoaccept,
                                  initiator_or_responder):
    """P2PS display method provisioning function"""
    if initiator_or_responder == 'initiator':
        ev0 = r_dev.wait_global_event(["P2PS-PROV-START"], timeout=10)
        if ev0 is None:
            raise Exception("P2PS-PROV-START timeout on Advertiser side")
        if autoaccept == False:
            ev = i_dev.wait_global_event(["P2P-PROV-DISC-FAILURE"], timeout=10)
            if ev is None:
                raise Exception("Provisioning deferred on seeker side")
        ev1 = i_dev.wait_global_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=10)
        if ev1 is None:
            raise Exception("P2P-PROV-DISC-SHOW-PIN timeout on Seeker side")
        if r_dev.p2p_dev_addr() not in ev1:
            raise Exception("Unknown peer ")
        pin = ev1.split(" ")[2]
    else:
        ev0 = r_dev.wait_global_event(["P2PS-PROV-DONE"], timeout=10)
        if ev0 is None:
            raise Exception("P2PS-PROV-DONE timeout on advertiser")
        ev0 = r_dev.wait_global_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=5)
        if ev0 is None:
            raise Exception("PIN Display on advertiser side")
        pin = ev0.split(" ")[2]
    return pin

def p2ps_connect_pin(pin, i_dev, r_dev, initiator_method):
    """P2PS function to perform connection using PIN method"""
    if initiator_method=="display":
        if "OK" not in i_dev.global_request("P2P_CONNECT " + r_dev.p2p_dev_addr() + " " + pin + " display persistent "):
            raise Exception("P2P_CONNECT fails on seeker side")
        ev0 = r_dev.wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=10)
        if ev0 is None:
            raise Exception("Failed to receive P2P_GO-NEG-REQUEST on responder side")
        if "OK" not in r_dev.global_request("P2P_CONNECT " + i_dev.p2p_dev_addr() + " " + pin + " keypad persistent "):
            raise Exception("P2P_CONNECT fails on Advertiser side")
    else:
        if "OK" not in i_dev.global_request("P2P_CONNECT " + r_dev.p2p_dev_addr() + " " + pin + " keypad persistent "):
            raise Exception("P2P_CONNECT fails on seeker side")
        ev0 = r_dev.wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=10)
        if ev0 is None:
            raise Exception("Failed to receive P2P_GO-NEG-REQUEST on responder side")
        if "OK" not in r_dev.global_request("P2P_CONNECT " + i_dev.p2p_dev_addr() + " " + pin + " display persistent "):
            raise Exception("P2P_CONNECT fails on Advertiser side")

    ev0 = r_dev.wait_global_event(["P2P-GO-NEG-SUCCESS"], timeout=10)
    if ev0 is None:
        raise Exception("GO Neg did not succeed on advertiser side")
    peer_mac = ev0.split("peer_dev=")[1].split(" ")[0]

    ev1 = i_dev.wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev1 is None:
        raise Exception("P2P-GROUP-STARTED timeout on seeker side")

    ev_grpfrm = r_dev.wait_global_event(["P2P-GROUP-FORMATION-SUCCESS"],
                                        timeout=10)
    if ev_grpfrm is None:
        raise Exception("Group Formation failed on advertiser side")

    ev = r_dev.wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("P2P-GROUP-STARTED timeout on advertiser side")
    Role = ev.split(" ")[2]
    if Role == "GO":
        ev_grpfrm = r_dev.wait_global_event(["AP-STA-CONNECTED"], timeout=10)
        if ev_grpfrm is None:
            raise Exception("AP-STA-CONNECTED timeout on advertiser side")
        if i_dev.p2p_dev_addr() not in ev_grpfrm:
            raise Exception("Group formed with unknown Peer")
    else:
        ev1 = i_dev.wait_global_event(["AP-STA-CONNECTED"], timeout=5)
        if ev1 is None:
            raise Exception("AP-STA-CONNECTED timeout on Seeker side")
    if r_dev.p2p_dev_addr() not in ev1:
        raise Exception("Group formed with unknown Peer")

def test_p2ps_exact_search(dev):
    """P2PS exact service request"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='1', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx')

    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")

def test_p2ps_exact_search_srvinfo(dev):
    """P2PS exact service request with service info"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='0', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')

    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")

def test_p2ps_nonexact_search(dev):
    """P2PS nonexact seek request"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='0', svc_name='org.wi-fi.wfds.play.rx',
                   srv_info='I support Miracast Mode ')
    ev_list = p2ps_nonexact_seek(i_dev=dev[1], r_dev=dev[0],
                                 svc_name='org.wi-fi.wfds.play*')
    adv_id = ev_list[0].split(" ")[0]

    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")

def test_p2ps_nonexact_search_srvinfo(dev):
    """P2PS nonexact seek request with service info"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='0', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    ev_list = p2ps_nonexact_seek(i_dev=dev[1], r_dev=dev[0],
                                 svc_name='org.wi-fi.wfds.send*',
                                 srv_info='2 GB')
    adv_id = ev_list[0].split(" ")[0]
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")

def test_p2ps_connect_p2ps_method_nonautoaccept(dev):
    """P2PS connect for non-auto-accept and P2PS config method"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='0', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    ev_list = p2ps_nonexact_seek(i_dev=dev[1], r_dev=dev[0],
                                 svc_name='org.wi-fi.wfds.send*',
                                 srv_info='2 GB')
    adv_id = ev_list[0].split(" ")[0]
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=1000"):
        raise Exception("Failed to request provisioning on seeker")
    ev0 = dev[0].wait_global_event(["P2PS-PROV-START"], timeout=10)
    if ev0 is None:
        raise Exception("P2PS-PROV-START timeout on advertiser side")
    ev1 = dev[1].wait_global_event(["P2P-PROV-DISC-FAILURE"], timeout=15)
    if ev1 is None:
        raise Exception("Provisioning deferred timeout on seeker side")
    dev[1].p2p_listen()
    if "OK" not in dev[0].global_request("P2P_ASP_PROVISION_RESP " + addr1 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " status=12"):
        raise Exception("Failed to send deferred acceptance from advertizer")
    ev1 = dev[1].wait_global_event(["P2PS-PROV-DONE"], timeout=15)
    if ev1 is None:
        raise Exception("Failed to receive deferred acceptance at seeker")

    p2p_connect_p2ps_method(i_dev=dev[1], r_dev=dev[0], autoaccept=False)
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_p2ps_method_autoaccept(dev):
    """P2PS connection with P2PS default config method and auto-accept"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='1', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=1000"):
        raise Exception("P2P_ASP_PROVISION failed on seeker side")

    ev0 = dev[0].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev0 is None:
        raise Exception("P2PS-PROV-DONE timeout on advertiser side")

    p2p_connect_p2ps_method(i_dev=dev[1], r_dev=dev[0], autoaccept=True)

    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_keypad_method_nonautoaccept(dev):
    """P2PS Connection with non-auto-accept and seeker having keypad method"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='0', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    ev_list = p2ps_nonexact_seek(i_dev=dev[1], r_dev=dev[0],
                                 svc_name='org.wi-fi.wfds.send*',
                                 srv_info='2 GB')
    adv_id = ev_list[0].split(" ")[0]
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=8"):     # keypad method on seeker side
        raise Exception("Failed to request provisioning on seeker")
    p2ps_provision_keypad_method(i_dev=dev[1], r_dev=dev[0], autoaccept=False,
                                 initiator_or_responder='initiator')
    dev[1].p2p_listen()

    if "OK" not in dev[0].global_request("P2P_ASP_PROVISION_RESP " + addr1 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " status=12"):
        raise Exception("Failed to send deferred acceptance from advertizer")

    pin = p2ps_provision_display_method(i_dev=dev[1], r_dev=dev[0],
                                        autoaccept=False,
                                        initiator_or_responder='responder')
    p2ps_connect_pin(pin, i_dev=dev[0], r_dev=dev[1],
                     initiator_method="display")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_display_method_nonautoaccept(dev):
    """P2PS connection with non-auto-accept and seeker having display method"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='0', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    ev_list = p2ps_nonexact_seek(i_dev=dev[1], r_dev=dev[0],
                                 svc_name='org.wi-fi.wfds*', srv_info='2 GB')
    adv_id = ev_list[0].split(" ")[0]
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=100"):     # keypad method on seeker side
        raise Exception("Failed to request provisioning on seeker")
    pin = p2ps_provision_display_method(i_dev=dev[1], r_dev=dev[0],
                                        autoaccept=False,
                                        initiator_or_responder='initiator')
    dev[1].p2p_listen()

    if "OK" not in dev[0].global_request("P2P_ASP_PROVISION_RESP " + addr1 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " status=12"):
        raise Exception("Failed to send deferred acceptance from advertiser")
    p2ps_provision_keypad_method(i_dev=dev[1], r_dev=dev[0], autoaccept=False,
                                 initiator_or_responder='responder')
    p2ps_connect_pin(pin, i_dev=dev[0], r_dev=dev[1], initiator_method="keypad")

    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_keypad_method_autoaccept(dev):
    """P2PS connection with auto-accept and keypad method on seeker side"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='1', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=8"):     # keypad method on seeker side
        raise Exception("Failed to request provisioning on seeker")

    p2ps_provision_keypad_method(i_dev=dev[1], r_dev=dev[0], autoaccept=True,
                                 initiator_or_responder='initiator')
    pin = p2ps_provision_display_method(i_dev=dev[1], r_dev=dev[0],
                                        autoaccept=True,
                                        initiator_or_responder='responder')
    p2ps_connect_pin(pin, i_dev=dev[1], r_dev=dev[0], initiator_method="Keypad")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_display_method_autoaccept(dev):
    """P2PS connection with auto-accept and display method on seeker side"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='1', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=100"):     # display method on seeker side
        raise Exception("Failed to request provisioning on seeker")

    pin = p2ps_provision_display_method(i_dev=dev[1], r_dev=dev[0],
                                        autoaccept=True,
                                        initiator_or_responder='initiator')
    dev[1].p2p_listen()

    p2ps_connect_pin(pin, i_dev=dev[1], r_dev=dev[0], initiator_method="display")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_adv_go_p2ps_method(dev):
    """P2PS auto-accept connection with advertisement as GO and P2PS method"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='4', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=1000"):
        raise Exception("Failed to request provisioning on seeker")

    ev0 = dev[0].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev0 is None:
        raise Exception("Timed out while waiting for prov done on advertizer")
    if "go=" not in ev0:
        raise Exception("Advertiser failed to become GO")

    adv_conncap = ev0.split("conncap=")[1].split(" ")[0]
    if adv_conncap == "4":
        logger.info("Advertiser is GO")
    ev0 = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev0 is None:
        raise Exception("P2P-GROUP-STARTED timeout on advertiser side")

    ev1 = dev[1].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev1 is None:
        raise Exception("P2PS-PROV-DONE timeout on seeker side")

    seeker_conncap = ev1.split("conncap=")[1].split(" ")[0]

    if "join=" in ev1:
        if "OK" not in dev[1].global_request("P2P_CONNECT " + addr0 + " 12345670 p2ps persistent join"):
            raise Exception("P2P_CONNECT failed on seeker side")
        ev1 = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
        if ev1 is None:
            raise Exception("P2P-GROUP-STARTED timeout on seeker side")

    ev0 = dev[0].wait_global_event(["AP-STA-CONNECTED"], timeout=5)
    if ev0 is None:
        raise Exception("AP-STA-CONNECTED timeout on advertiser side")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_adv_client_p2ps_method(dev):
    """P2PS auto-accept connection with advertisement as Client and P2PS method"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='2', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=1000"):
        raise Exception("Failed to request provisioning on seeker")

    ev0 = dev[0].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev0 is None:
        raise Exception("P2PS-PROV-DONE timeout on advertiser side")
    if "join=" not in ev0:
        raise Exception("Advertiser failed to become Client")

    adv_conncap = ev0.split("conncap=")[1].split(" ")[0]
    if adv_conncap == "2":
        logger.info("Advertiser is Client")

    ev1 = dev[1].wait_global_event(["P2PS-PROV-DONE"], timeout=5)
    if ev1 is None:
        raise Exception("Provisioning failed on seeker side")

    seeker_conncap = ev1.split("conncap=")[1].split(" ")[0]
    ev1 = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev1 is None:
        raise Exception("P2P-GROUP-STARTED timeout on seeker side")

    if "join=" in ev0:
        if "OK" not in dev[0].global_request("P2P_CONNECT " + addr1 + " 12345670 p2ps persistent join"):
            raise Exception("P2P_CONNECT failed on seeker side")

    ev0 = dev[0].wait_global_event(["P2P-GROUP-FORMATION-SUCCESS"], timeout=15)
    if ev0 is None:
        raise Exception("P2P Group Formation failed on advertiser side")

    ev0 = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev0 is None:
        raise Exception("P2P-GROUP-STARTED timeout on advertiser side")

    ev1 = dev[1].wait_global_event(["AP-STA-CONNECTED"], timeout=5)
    if ev1 is None:
        raise Exception("Group formation failed")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_adv_go_pin_method(dev):
    """P2PS advertiser as GO with keypad config method on seeker side and auto-accept"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    p2ps_advertise(r_dev=dev[0], r_role='4', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=8"):     # keypad method on seeker side
        raise Exception("Failed to request provisioning on seeker")

    seek_prov_ev = p2ps_provision_keypad_method(i_dev=dev[1], r_dev=dev[0],
                                                autoaccept=True,
                                                initiator_or_responder='initiator')

    ev0 = dev[0].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev0 is None:
        raise Exception("P2PS-PROV-DONE timeout on advertier side")
    adv_conncap = ev0.split("conncap=")[1].split(" ")[0]
    if adv_conncap == "4":
        logger.info("Advertiser is GO")
    ev0 = dev[0].wait_global_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=5)
    if ev0 is None:
        raise Exception("PIN Display on advertiser side")
    pin = ev0.split(" ")[2]

    ev0 = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev0 is None:
        raise Exception("P2P-GROUP-STARTED timeout on advertiser side")
    ev0 = dev[0].group_request("WPS_PIN any " + pin)
    if ev0 is None:
        raise Exception("Failed to initiate Pin authorization on registrar side")
    if "join=" in seek_prov_ev:
        if "OK" not in dev[1].global_request("P2P_CONNECT " + addr0 + " " + pin + " keypad persistent join"):
            raise Exception("P2P_CONNECT failed on seeker side")
        ev1 = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
        if ev1 is None:
            raise Exception("P2P-GROUP-STARTED timeout on seeker side")

        ev0 = dev[0].wait_global_event(["AP-STA-CONNECTED"], timeout=10)
        if ev0 is None:
            raise Exception("AP-STA-CONNECTED timeout on advertiser side")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_connect_adv_client_pin_method(dev):
    """P2PS advertiser as client with keypad config method on seeker side and auto-accept"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[0].flush_scan_cache()
    p2ps_advertise(r_dev=dev[0], r_role='2', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=8"):     # keypad method on seeker side
        raise Exception("Failed to request provisioning on seeker")

    seek_prov_ev = p2ps_provision_keypad_method(i_dev=dev[1], r_dev=dev[0],
                                                autoaccept=True,
                                                initiator_or_responder='initiator')

    adv_prov = dev[0].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if adv_prov is None:
        raise Exception("Prov failed on advertiser")
    adv_conncap = adv_prov.split("conncap=")[1].split(" ")[0]
    if adv_conncap == "2":
        logger.info("Advertiser is Client")
    adv_pin_show_event = dev[0].wait_global_event(["P2P-PROV-DISC-SHOW-PIN"],
                                                  timeout=5)
    if adv_pin_show_event is None:
        raise Exception("PIN Display on advertiser side")
    pin = adv_pin_show_event.split(" ")[2]

    ev1 = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev1 is None:
        raise Exception("P2P-GROUP-STARTED timeout on seeker side")

    ev1 = dev[1].group_request("WPS_PIN any " + pin)
    if ev1 is None:
        raise Exception("Failed to initiate Pin authorization on registrar side")

    if "join=" in adv_prov:
        if "OK" not in dev[0].global_request("P2P_CONNECT " + addr1 + " " + pin + " display persistent join"):
            raise Exception("P2P_CONNECT failed on advertiser side")
    ev0 = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev0 is None:
        raise Exception("Group formation failed to start on seeker side")

    ev1 = dev[1].wait_global_event(["AP-STA-CONNECTED"], timeout=10)
    if ev1 is None:
        raise Exception("AP-STA-CONNECTED timeout on advertiser side")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])

def test_p2ps_service_discovery_multiple_queries(dev):
    """P2P service discovery with multiple queries"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    adv_id1 = p2ps_advertise(r_dev=dev[0], r_role='0',
                             svc_name='org.wi-fi.wfds.send.tx',
                             srv_info='I can transfer files upto size of 2 GB')
    adv_id2 = p2ps_advertise(r_dev=dev[0], r_role='0',
                             svc_name='org.wi-fi.wfds.send.rx',
                             srv_info='I can receive files upto size of 2 GB')
    adv_id3 = p2ps_advertise(r_dev=dev[0], r_role='1',
                             svc_name='org.wi-fi.wfds.display.tx',
                             srv_info='Miracast Mode')
    adv_id4 = p2ps_advertise(r_dev=dev[0], r_role='1',
                             svc_name='org.wi-fi.wfds.display.rx',
                             srv_info='Miracast Mode')

    dev[1].global_request("P2P_SERV_DISC_REQ " + addr0 + " asp 1 org.wi-fi.wfds.display.tx 'Miracast Mode'")
    dev[1].global_request("P2P_FIND 10 type=social seek=org.wi-fi.wfds.display.tx")
    dev[1].global_request("P2P_SERV_DISC_REQ " + addr0 + " asp 2 org.wi-fi.wfds.send* 'size of 2 GB'")
    dev[1].p2p_stop_find()
    dev[1].global_request("P2P_FIND 10 type=social seek=")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
    if ev is None:
        raise Exception("P2P Device Found timed out")
    if addr0 not in ev:
        raise Exception("Unexpected service discovery request source")
    ev_list = []
    for i in range(0, 3):
        ev = dev[1].wait_global_event(["P2P-SERV-ASP-RESP"], timeout=10)
        if ev is None:
            raise Exception("P2P Service discovery timed out")
        if addr0 in ev:
            ev_list.append(ev)
            if len(ev_list) == 3:
                break
    dev[1].p2p_stop_find()

    for test in [ ("seek=org.wi-fi.wfds.display.TX",
                   "asp_svc=org.wi-fi.wfds.display.tx"),
                  ("seek=foo seek=org.wi-fi.wfds.display.tx seek=bar",
                   "asp_svc=org.wi-fi.wfds.display.tx"),
                  ("seek=1 seek=2 seek=3 seek=org.wi-fi.wfds.display.tx seek=4 seek=5 seek=6",
                   "asp_svc=org.wi-fi.wfds.display.tx"),
                  ("seek=not-found", None),
                  ("seek=org.wi-fi.wfds", "asp_svc=org.wi-fi.wfds")]:
        dev[2].global_request("P2P_FIND 10 type=social " + test[0])
        if test[1] is None:
            ev = dev[2].wait_global_event(["P2P-DEVICE-FOUND"], timeout=1)
            if ev is not None:
                raise Exception("Unexpected device found: " + ev)
            continue
        ev = dev[2].wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
        if ev is None:
            raise Exception("P2P device discovery timed out (dev2)")
            if test[1] not in ev:
                raise Exception("Expected asp_svc not reported: " + ev)
        dev[2].p2p_stop_find()
        dev[2].request("P2P_FLUSH")

    dev[0].p2p_stop_find()

    ev1 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id1))
    if ev1 is None:
        raise Exception("Unable to remove the advertisement instance")
    ev2 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id2))
    if ev2 is None:
        raise Exception("Unable to remove the advertisement instance")
    ev3 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id3))
    if ev3 is None:
        raise Exception("Unable to remove the advertisement instance")
    ev4 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id4))
    if ev4 is None:
        raise Exception("Unable to remove the advertisement instance")

    if "OK" not in dev[0].global_request("P2P_SERVICE_ADD asp 1 12345678 1 1108 org.wi-fi.wfds.foobar svc_info='Test'"):
        raise Exception("P2P_SERVICE_ADD failed")
    if "OK" not in dev[0].global_request("P2P_SERVICE_DEL asp all"):
        raise Exception("P2P_SERVICE_DEL asp all failed")
    if "OK" not in dev[0].global_request("P2P_SERVICE_ADD asp 1 12345678 1 1108 org.wi-fi.wfds.foobar svc_info='Test'"):
        raise Exception("P2P_SERVICE_ADD failed")
    if "OK" not in dev[0].global_request("P2P_SERVICE_REP asp 1 12345678 1 1108 org.wi-fi.wfds.foobar svc_info='Test'"):
        raise Exception("P2P_SERVICE_REP failed")
    if "FAIL" not in dev[0].global_request("P2P_SERVICE_REP asp 1 12345678 1 1108 org.wi-fi.wfds.Foo svc_info='Test'"):
        raise Exception("Invalid P2P_SERVICE_REP accepted")
    if "OK" not in dev[0].global_request("P2P_SERVICE_ADD asp 1 a2345678 1 1108 org.wi-fi.wfds.something svc_info='Test'"):
        raise Exception("P2P_SERVICE_ADD failed")
    if "OK" not in dev[0].global_request("P2P_SERVICE_ADD asp 1 a2345679 1 1108 org.wi-fi.wfds.Foo svc_info='Test'"):
        raise Exception("P2P_SERVICE_ADD failed")

def get_ifnames():
    with open('/proc/net/dev', 'r') as f:
        data = f.read()
    ifnames = []
    for line in data.splitlines():
        ifname = line.strip().split(' ')[0]
        if ':' not in ifname:
            continue
        ifname = ifname.split(':')[0]
        ifnames.append(ifname)
    return ifnames

def p2ps_connect_p2ps_method(dev):
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[0].flush_scan_cache()
    dev[1].flush_scan_cache()
    p2ps_advertise(r_dev=dev[0], r_role='2', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='test-session-info-data' method=1000"):
        raise Exception("Failed to request provisioning on seeker")

    ev0 = dev[0].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev0 is None:
        raise Exception("P2PS-PROV-DONE timeout on advertiser side")
    if "join=" not in ev0:
        raise Exception("join parameter missing from P2PS-PROV-DONE")

    ev1 = dev[1].wait_global_event(["P2PS-PROV-DONE"], timeout=5)
    if ev1 is None:
        raise Exception("Provisioning failed on seeker side")

    ev1 = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev1 is None:
        raise Exception("P2P-GROUP-STARTED timeout on seeker side")
    res1 = dev[1].group_form_result(ev1)
    ifnames1 = get_ifnames()

    if "OK" not in dev[0].global_request("P2P_CONNECT " + addr1 + " 12345670 p2ps persistent join"):
        raise Exception("P2P_CONNECT failed on seeker side")

    ev0 = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev0 is None:
        raise Exception("P2P-GROUP-STARTED timeout on advertiser side")
    res0 = dev[0].group_form_result(ev0)

    ev1 = dev[1].wait_global_event(["AP-STA-CONNECTED"], timeout=5)
    if ev1 is None:
        raise Exception("Group formation failed")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    ifnames2 = get_ifnames()
    remove_group(dev[0], dev[1])
    ifnames3 = get_ifnames()
    return (res0, res1, ifnames1 + ifnames2 + ifnames3)

def has_string_prefix(vals, prefix):
    for val in vals:
        if val.startswith(prefix):
            return True
    return False

def test_p2ps_connect_p2ps_method_1(dev):
    """P2PS connection with P2PS method - no group interface"""
    (res0, res1, ifnames) = p2ps_connect_p2ps_method(dev)
    if res0['ifname'] != dev[0].ifname:
        raise Exception("unexpected dev0 group ifname: " + res0['ifname'])
    if res1['ifname'] != dev[1].ifname:
        raise Exception("unexpected dev1 group ifname: " + res1['ifname'])
    if has_string_prefix(ifnames, 'p2p-' + res0['ifname']):
        raise Exception("dev0 group interface unexpectedly present")
    if has_string_prefix(ifnames, 'p2p-' + res1['ifname']):
        raise Exception("dev1 group interface unexpectedly present")

def test_p2ps_connect_p2ps_method_2(dev):
    """P2PS connection with P2PS method - group interface on dev0"""
    dev[0].request("SET p2p_no_group_iface 0")
    (res0, res1, ifnames) = p2ps_connect_p2ps_method(dev)
    if not res0['ifname'].startswith('p2p-' + dev[0].ifname + '-'):
        raise Exception("unexpected dev0 group ifname: " + res0['ifname'])
    if res1['ifname'] != dev[1].ifname:
        raise Exception("unexpected dev1 group ifname: " + res1['ifname'])
    if has_string_prefix(ifnames, 'p2p-' + res0['ifname']):
        raise Exception("dev0 group interface unexpectedly present")

def test_p2ps_connect_p2ps_method_3(dev):
    """P2PS connection with P2PS method - group interface on dev1"""
    dev[1].request("SET p2p_no_group_iface 0")
    (res0, res1, ifnames) = p2ps_connect_p2ps_method(dev)
    if res0['ifname'] != dev[0].ifname:
        raise Exception("unexpected dev0 group ifname: " + res0['ifname'])
    if not res1['ifname'].startswith('p2p-' + dev[1].ifname + '-'):
        raise Exception("unexpected dev1 group ifname: " + res1['ifname'])
    if has_string_prefix(ifnames, 'p2p-' + res0['ifname']):
        raise Exception("dev0 group interface unexpectedly present")

def test_p2ps_connect_p2ps_method_4(dev):
    """P2PS connection with P2PS method - group interface on both"""
    dev[0].request("SET p2p_no_group_iface 0")
    dev[1].request("SET p2p_no_group_iface 0")
    (res0, res1, ifnames) = p2ps_connect_p2ps_method(dev)
    if not res0['ifname'].startswith('p2p-' + dev[0].ifname + '-'):
        raise Exception("unexpected dev0 group ifname: " + res0['ifname'])
    if not res1['ifname'].startswith('p2p-' + dev[1].ifname + '-'):
        raise Exception("unexpected dev1 group ifname: " + res1['ifname'])

def test_p2ps_connect_adv_go_persistent(dev):
    """P2PS auto-accept connection with advertisement as GO and having persistent group"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()

    go_neg_pin_authorized_persistent(i_dev=dev[0], i_intent=15,
                                     r_dev=dev[1], r_intent=0)
    dev[0].remove_group()
    dev[1].wait_go_ending_session()

    p2ps_advertise(r_dev=dev[0], r_role='4', svc_name='org.wi-fi.wfds.send.rx',
                   srv_info='I can receive files upto size 2 GB')
    [adv_id, rcvd_svc_name] = p2ps_exact_seek(i_dev=dev[1], r_dev=dev[0],
                                              svc_name='org.wi-fi.wfds.send.rx',
                                              srv_info='2 GB')
    if "OK" not in dev[1].global_request("P2P_ASP_PROVISION " + addr0 + " adv_id=" + str(adv_id) + " adv_mac=" + addr0 + " session=1 session_mac=" + addr1 + " info='' method=1000"):
        raise Exception("Failed to request provisioning on seeker")

    ev0 = dev[0].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev0 is None:
        raise Exception("Timed out while waiting for prov done on advertizer")
    if "persist=" not in ev0:
        raise Exception("Advertiser did not indicate persistent group")
    id0 = ev0.split("persist=")[1].split(" ")[0]
    if "OK" not in dev[0].global_request("P2P_GROUP_ADD persistent=" + id0 + " freq=2412"):
        raise Exception("Could not re-start persistent group")

    ev0 = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev0 is None:
        raise Exception("P2P-GROUP-STARTED timeout on advertiser side")

    ev1 = dev[1].wait_global_event(["P2PS-PROV-DONE"], timeout=10)
    if ev1 is None:
        raise Exception("P2PS-PROV-DONE timeout on seeker side")

    if "persist=" not in ev1:
        raise Exception("Seeker did not indicate persistent group")
    id1 = ev1.split("persist=")[1].split(" ")[0]
    if "OK" not in dev[1].global_request("P2P_GROUP_ADD persistent=" + id1 + " freq=2412"):
        raise Exception("Could not re-start persistent group")

    ev1 = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev1 is None:
        raise Exception("P2P-GROUP-STARTED timeout on seeker side")

    ev0 = dev[0].wait_global_event(["AP-STA-CONNECTED"], timeout=15)
    if ev0 is None:
        raise Exception("AP-STA-CONNECTED timeout on advertiser side")
    ev0 = dev[0].global_request("P2P_SERVICE_DEL asp " + str(adv_id))
    if ev0 is None:
        raise Exception("Unable to remove the advertisement instance")
    remove_group(dev[0], dev[1])
