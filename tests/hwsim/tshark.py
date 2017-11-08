#
# tshark module - refactored from test_scan.py
#
# Copyright (c) 2014, Qualcomm Atheros, Inc.
# Copyright (c) 2015, Intel Mobile Communications GmbH
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger()


_tshark_filter_arg = '-Y'

def run_tshark(filename, filter, display=None, wait=True):
    global _tshark_filter_arg

    if wait:
        # wait a bit to make it more likely for wlantest sniffer to have
        # captured and written the results into a file that we can process here
        time.sleep(0.1)

    try:
        arg = [ "tshark", "-r", filename,
                _tshark_filter_arg, filter ]
        if display:
            arg.append('-Tfields')
            for d in display:
                arg.append('-e')
                arg.append(d)
        else:
            arg.append('-V')
        cmd = subprocess.Popen(arg, stdout=subprocess.PIPE,
                               stderr=open('/dev/null', 'w'))
    except Exception, e:
        logger.info("Could run run tshark check: " + str(e))
        cmd = None
        return None

    out = cmd.communicate()[0]
    res = cmd.wait()
    if res == 1:
        # remember this for efficiency
        _tshark_filter_arg = '-R'
        arg[3] = '-R'
        cmd = subprocess.Popen(arg, stdout=subprocess.PIPE,
                               stderr=open('/dev/null', 'w'))
        out = cmd.communicate()[0]
        cmd.wait()

    return out
