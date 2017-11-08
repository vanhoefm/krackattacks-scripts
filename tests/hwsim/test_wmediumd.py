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

def test_wmediumd_simple(dev, apdev):
    """test a simple wmediumd configuration"""
    fd, fn = tempfile.mkstemp()
    try:
        f = os.fdopen(fd, 'w')
        f.write(CFG % (apdev[0]['bssid'], dev[0].own_addr()))
        f.close()
        try:
            p = subprocess.Popen(['wmediumd', '-c', fn],
                                 stdout=open('/dev/null', 'a'),
                                 stderr=subprocess.STDOUT)
        except OSError, e:
            if e.errno == errno.ENOENT:
                raise HwsimSkip("wmediumd not available")
            raise
        try:
            _test_ap_open(dev, apdev)
        finally:
            p.terminate()
            p.wait()
        # test that releasing hwsim works correctly
        _test_ap_open(dev, apdev)
    finally:
        os.unlink(fn)
