# wmediumd sanity checks
# Copyright (c) 2015, Intel Deutschland GmbH
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import tempfile, os, subprocess, errno, hwsim_utils
from utils import HwsimSkip
from test_ap_open import _test_ap_open
from test_wpas_mesh import check_mesh_support, check_mesh_group_added
from test_wpas_mesh import check_mesh_peer_connected, add_open_mesh_network
from test_wpas_mesh import check_mesh_group_removed

CFG = """
ifaces :
{
    ids = ["%s", "%s" ];
    links = (
        (0, 1, 30)
    );
};
"""

CFG2 = """
ifaces :
{
    ids = ["%s", "%s", "%s"];

    links = (
        (0, 1, 50),
        (0, 2, 50),
        (1, 2, -10)
    );
};
"""

def output_wmediumd_log(p, params, data):
    log_file = open(os.path.abspath(os.path.join(params['logdir'],
                                                 'wmediumd.log')), 'a')
    log_file.write(data)
    log_file.close()

def start_wmediumd(fn, params):
    try:
        p = subprocess.Popen(['wmediumd', '-c', fn],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    except OSError, e:
        if e.errno == errno.ENOENT:
            raise HwsimSkip('wmediumd not available')
        raise

    logs = ''
    while True:
        line = p.stdout.readline()
        if not line:
            output_wmediumd_log(p, params, logs)
            raise Exception('wmediumd was terminated unexpectedly')
        if line.find('REGISTER SENT!') > -1:
            break
        logs += line
    return p

def stop_wmediumd(p, params):
    p.terminate()
    p.wait()
    stdoutdata, stderrdata = p.communicate()
    output_wmediumd_log(p, params, stdoutdata)

def test_wmediumd_simple(dev, apdev, params):
    """test a simple wmediumd configuration"""
    fd, fn = tempfile.mkstemp()
    try:
        f = os.fdopen(fd, 'w')
        f.write(CFG % (apdev[0]['bssid'], dev[0].own_addr()))
        f.close()
        p = start_wmediumd(fn, params)
        try:
            _test_ap_open(dev, apdev)
        finally:
            stop_wmediumd(p, params)
        # test that releasing hwsim works correctly
        _test_ap_open(dev, apdev)
    finally:
        os.unlink(fn)

def test_wmediumd_path_simple(dev, apdev, params):
    """test a mesh path"""
    # 0 and 1 is connected
    # 0 and 2 is connected
    # 1 and 2 is not connected
    # 1 --- 0 --- 2
    # |           |
    # +-----X-----+
    # This tests if 1 and 2 can communicate each other via 0.
    fd, fn = tempfile.mkstemp()
    try:
        f = os.fdopen(fd, 'w')
        f.write(CFG2 % (dev[0].own_addr(), dev[1].own_addr(),
                        dev[2].own_addr()))
        f.close()
        p = start_wmediumd(fn, params)
        try:
            _test_wmediumd_path_simple(dev, apdev)
        finally:
            stop_wmediumd(p, params)
    finally:
        os.unlink(fn)

def _test_wmediumd_path_simple(dev, apdev):
    for i in range(0, 3):
        check_mesh_support(dev[i])
        add_open_mesh_network(dev[i], freq="2462", basic_rates="60 120 240")

    # Check for mesh joined
    for i in range(0, 3):
        check_mesh_group_added(dev[i])

        state = dev[i].get_status_field("wpa_state")
        if state != "COMPLETED":
            raise Exception("Unexpected wpa_state on dev" + str(i) + ": " + state)

        mode = dev[i].get_status_field("mode")
        if mode != "mesh":
            raise Exception("Unexpected mode: " + mode)

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])
    check_mesh_peer_connected(dev[2])

    # Test connectivity 1->2 and 2->1
    hwsim_utils.test_connectivity(dev[1], dev[2])

    # Check mpath table on 0
    res, data = dev[0].cmd_execute(['iw', dev[0].ifname, 'mpath', 'dump'])
    if res != 0:
        raise Exception("iw command failed on dev0")
    if data.find(dev[1].own_addr() + ' ' +  dev[1].own_addr()) == -1 or \
       data.find(dev[2].own_addr() + ' ' +  dev[2].own_addr()) == -1:
        raise Exception("mpath not found on dev0:\n" + data)
    if data.find(dev[0].own_addr()) > -1:
        raise Exception("invalid mpath found on dev0:\n" + data)

    # Check mpath table on 1
    res, data = dev[1].cmd_execute(['iw', dev[1].ifname, 'mpath', 'dump'])
    if res != 0:
        raise Exception("iw command failed on dev1")
    if data.find(dev[0].own_addr() + ' ' +  dev[0].own_addr()) == -1 or \
       data.find(dev[2].own_addr() + ' ' +  dev[0].own_addr()) == -1:
        raise Exception("mpath not found on dev1:\n" + data)
    if data.find(dev[2].own_addr() + ' ' +  dev[2].own_addr()) > -1 or \
       data.find(dev[1].own_addr()) > -1:
        raise Exception("invalid mpath found on dev1:\n" + data)

    # Check mpath table on 2
    res, data = dev[2].cmd_execute(['iw', dev[2].ifname, 'mpath', 'dump'])
    if res != 0:
        raise Exception("iw command failed on dev2")
    if data.find(dev[0].own_addr() + ' ' +  dev[0].own_addr()) == -1 or \
       data.find(dev[1].own_addr() + ' ' +  dev[0].own_addr()) == -1:
        raise Exception("mpath not found on dev2:\n" + data)
    if data.find(dev[1].own_addr() + ' ' +  dev[1].own_addr()) > -1 or \
       data.find(dev[2].own_addr()) > -1:
        raise Exception("invalid mpath found on dev2:\n" + data)

    # remove mesh groups
    for i in range(0, 3):
        dev[i].mesh_group_remove()
        check_mesh_group_removed(dev[i])
        dev[i].dump_monitor()
