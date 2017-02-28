# wmediumd sanity checks
# Copyright (c) 2015, Intel Deutschland GmbH
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import tempfile, os, subprocess, errno
from utils import HwsimSkip
from test_ap_open import _test_ap_open

CFG = """
ifaces :
{
    ids = ["%s", "%s" ];
    links = (
        (0, 1, 30)
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
