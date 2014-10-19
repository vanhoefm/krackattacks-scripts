# hwsim testing utilities
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import subprocess
import time
import logging
logger = logging.getLogger()

def test_connectivity_run(ifname1, ifname2, dscp=None, tos=None, max_tries=1):
    if os.path.isfile("../../mac80211_hwsim/tools/hwsim_test"):
        hwsim_test = "../../mac80211_hwsim/tools/hwsim_test"
    else:
        hwsim_test = "hwsim_test"
    cmd = ["sudo",
           hwsim_test,
           ifname1,
           ifname2]
    if dscp:
        cmd.append('-D')
        cmd.append(str(dscp))
    elif tos:
        cmd.append('-t')
        cmd.append(str(tos))
    success = False
    for i in range(0, max_tries):
        try:
            s = subprocess.check_output(cmd)
            logger.debug(s)
            success = True
            break
        except subprocess.CalledProcessError, e:
            logger.info("hwsim failed: " + str(e.returncode))
            logger.info(e.output)
            if i + 1 < max_tries:
                time.sleep(1)
    if not success:
        raise Exception("hwsim_test failed")

def test_connectivity(dev1, dev2, dscp=None, tos=None, max_tries=1):
    test_connectivity_run(dev1.ifname, dev2.ifname, dscp=dscp, tos=tos,
                          max_tries=max_tries)

def test_connectivity_iface(dev1, ifname, dscp=None, tos=None, max_tries=1):
    test_connectivity_run(dev1.ifname, ifname, dscp=dscp, tos=tos,
                          max_tries=max_tries)

def test_connectivity_p2p(dev1, dev2, dscp=None, tos=None):
    ifname1 = dev1.group_ifname if dev1.group_ifname else dev1.ifname
    ifname2 = dev2.group_ifname if dev2.group_ifname else dev2.ifname
    test_connectivity_run(ifname1, ifname2, dscp, tos)

def test_connectivity_p2p_sta(dev1, dev2, dscp=None, tos=None):
    ifname1 = dev1.group_ifname if dev1.group_ifname else dev1.ifname
    ifname2 = dev2.ifname
    test_connectivity_run(ifname1, ifname2, dscp, tos)

def test_connectivity_sta(dev1, dev2, dscp=None, tos=None):
    ifname1 = dev1.ifname
    ifname2 = dev2.ifname
    test_connectivity_run(ifname1, ifname2, dscp, tos)
