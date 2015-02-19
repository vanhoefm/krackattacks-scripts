# Python class for controlling wlantest
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time
import subprocess
import logging
import wpaspy

logger = logging.getLogger()

class Wlantest:
    def __init__(self):
        if os.path.isfile('../../wlantest/wlantest_cli'):
            self.wlantest_cli = '../../wlantest/wlantest_cli'
        else:
            self.wlantest_cli = 'wlantest_cli'

    def flush(self):
        res = subprocess.check_output([self.wlantest_cli, "flush"])
        if "FAIL" in res:
            raise Exception("wlantest_cli flush failed")

    def relog(self):
        res = subprocess.check_output([self.wlantest_cli, "relog"])
        if "FAIL" in res:
            raise Exception("wlantest_cli relog failed")

    def add_passphrase(self, passphrase):
        res = subprocess.check_output([self.wlantest_cli, "add_passphrase",
                                       passphrase])
        if "FAIL" in res:
            raise Exception("wlantest_cli add_passphrase failed")

    def add_wepkey(self, key):
        res = subprocess.check_output([self.wlantest_cli, "add_wepkey", key])
        if "FAIL" in res:
            raise Exception("wlantest_cli add_key failed")

    def info_bss(self, field, bssid):
        res = subprocess.check_output([self.wlantest_cli, "info_bss",
                                       field, bssid])
        if "FAIL" in res:
            raise Exception("Could not get BSS info from wlantest for " + bssid)
        return res

    def get_bss_counter(self, field, bssid):
        try:
            res = subprocess.check_output([self.wlantest_cli, "get_bss_counter",
                                           field, bssid]);
        except Exception, e:
            return 0
        if "FAIL" in res:
            return 0
        return int(res)

    def clear_bss_counters(self, bssid):
        subprocess.call([self.wlantest_cli, "clear_bss_counters", bssid],
                        stdout=open('/dev/null', 'w'));

    def info_sta(self, field, bssid, addr):
        res = subprocess.check_output([self.wlantest_cli, "info_sta",
                                       field, bssid, addr])
        if "FAIL" in res:
            raise Exception("Could not get STA info from wlantest for " + addr)
        return res

    def get_sta_counter(self, field, bssid, addr):
        res = subprocess.check_output([self.wlantest_cli, "get_sta_counter",
                                       field, bssid, addr]);
        if "FAIL" in res:
            raise Exception("wlantest_cli command failed")
        return int(res)

    def clear_sta_counters(self, bssid, addr):
        res = subprocess.check_output([self.wlantest_cli, "clear_sta_counters",
                                       bssid, addr]);
        if "FAIL" in res:
            raise Exception("wlantest_cli command failed")

    def tdls_clear(self, bssid, addr1, addr2):
        res = subprocess.check_output([self.wlantest_cli, "clear_tdls_counters",
                                       bssid, addr1, addr2]);

    def get_tdls_counter(self, field, bssid, addr1, addr2):
        res = subprocess.check_output([self.wlantest_cli, "get_tdls_counter",
                                       field, bssid, addr1, addr2]);
        if "FAIL" in res:
            raise Exception("wlantest_cli command failed")
        return int(res)

    def require_ap_pmf_mandatory(self, bssid):
        res = self.info_bss("rsn_capab", bssid)
        if "MFPR" not in res:
            raise Exception("AP did not require PMF")
        if "MFPC" not in res:
            raise Exception("AP did not enable PMF")
        res = self.info_bss("key_mgmt", bssid)
        if "PSK-SHA256" not in res:
            raise Exception("AP did not enable SHA256-based AKM for PMF")

    def require_ap_pmf_optional(self, bssid):
        res = self.info_bss("rsn_capab", bssid)
        if "MFPR" in res:
            raise Exception("AP required PMF")
        if "MFPC" not in res:
            raise Exception("AP did not enable PMF")

    def require_ap_no_pmf(self, bssid):
        res = self.info_bss("rsn_capab", bssid)
        if "MFPR" in res:
            raise Exception("AP required PMF")
        if "MFPC" in res:
            raise Exception("AP enabled PMF")

    def require_sta_pmf_mandatory(self, bssid, addr):
        res = self.info_sta("rsn_capab", bssid, addr)
        if "MFPR" not in res:
            raise Exception("STA did not require PMF")
        if "MFPC" not in res:
            raise Exception("STA did not enable PMF")

    def require_sta_pmf(self, bssid, addr):
        res = self.info_sta("rsn_capab", bssid, addr)
        if "MFPC" not in res:
            raise Exception("STA did not enable PMF")

    def require_sta_no_pmf(self, bssid, addr):
        res = self.info_sta("rsn_capab", bssid, addr)
        if "MFPC" in res:
            raise Exception("STA enabled PMF")

    def require_sta_key_mgmt(self, bssid, addr, key_mgmt):
        res = self.info_sta("key_mgmt", bssid, addr)
        if key_mgmt not in res:
            raise Exception("Unexpected STA key_mgmt")

    def get_tx_tid(self, bssid, addr, tid):
        res = subprocess.check_output([self.wlantest_cli, "get_tx_tid",
                                       bssid, addr, str(tid)]);
        if "FAIL" in res:
            raise Exception("wlantest_cli command failed")
        return int(res)

    def get_rx_tid(self, bssid, addr, tid):
        res = subprocess.check_output([self.wlantest_cli, "get_rx_tid",
                                       bssid, addr, str(tid)]);
        if "FAIL" in res:
            raise Exception("wlantest_cli command failed")
        return int(res)

    def get_tid_counters(self, bssid, addr):
        tx = {}
        rx = {}
        for tid in range(0, 17):
            tx[tid] = self.get_tx_tid(bssid, addr, tid)
            rx[tid] = self.get_rx_tid(bssid, addr, tid)
        return [ tx, rx ]
