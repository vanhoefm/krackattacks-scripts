#
# HWSIM generic netlink controller code
# Copyright (c) 2014	Intel Corporation
#
# Author: Johannes Berg <johannes.berg@intel.com>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import netlink

# constants
HWSIM_CMD_CREATE_RADIO		= 4
HWSIM_CMD_DESTROY_RADIO		= 5

HWSIM_ATTR_CHANNELS		= 9
HWSIM_ATTR_RADIO_ID		= 10

# the controller class
class HWSimController(object):
    def __init__(self):
        self._conn = netlink.Connection(netlink.NETLINK_GENERIC)
        self._fid = netlink.genl_controller.get_family_id('MAC80211_HWSIM')

    def create_radio(self, n_channels=None):
        attrs = []
        if n_channels:
            attrs.append(netlink.U32Attr(HWSIM_ATTR_CHANNELS, n_channels))
        msg = netlink.GenlMessage(self._fid, HWSIM_CMD_CREATE_RADIO,
                                  flags = netlink.NLM_F_REQUEST |
                                          netlink.NLM_F_ACK,
                                  attrs = attrs)
        return msg.send_and_recv(self._conn).ret

    def destroy_radio(self, radio_id):
        attrs = [netlink.U32Attr(HWSIM_ATTR_RADIO_ID, radio_id)]
        msg = netlink.GenlMessage(self._fid, HWSIM_CMD_DESTROY_RADIO,
                                  flags = netlink.NLM_F_REQUEST |
                                          netlink.NLM_F_ACK,
                                  attrs = attrs)
        msg.send_and_recv(self._conn)

if __name__ == '__main__':
    import sys
    c = HWSimController()
    if sys.argv[1] == 'create':
        if len(sys.argv) > 2:
            n_channels = int(sys.argv[2])
        else:
            n_channels = 0
        print 'Created radio %d' % c.create_radio(n_channels=n_channels)
    elif sys.argv[1] == 'destroy':
        print c.destroy_radio(int(sys.argv[2]))
