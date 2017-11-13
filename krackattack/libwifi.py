# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
from scapy.all import *
from Cryptodome.Cipher import AES
from datetime import datetime

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


#### Packet Processing Functions ####

class DHCP_sock(DHCP_am):
	def __init__(self, **kwargs):
		self.sock = kwargs.pop("sock")
		self.server_ip = kwargs["gw"]
		super(DHCP_sock, self).__init__(**kwargs)

	def make_reply(self, req):
		rep = super(DHCP_sock, self).make_reply(req)

		# Fix scapy bug: set broadcast IP if required
		if rep is not None and BOOTP in req and IP in rep:
			if req[BOOTP].flags & 0x8000 != 0 and req[BOOTP].giaddr == '0.0.0.0' and req[BOOTP].ciaddr == '0.0.0.0':
				rep[IP].dst = "255.255.255.255"

		# Explicitly set source IP if requested
		if not self.server_ip is None:
			rep[IP].src = self.server_ip

		return rep

	def send_reply(self, reply):
		self.sock.send(reply, **self.optsend)

	def print_reply(self, req, reply):
		log(STATUS, "%s: DHCP reply %s to %s" % (reply.getlayer(Ether).dst, reply.getlayer(BOOTP).yiaddr, reply.dst), color="green")

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


#### Packet Processing Functions ####

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
	if Dot11WEP not in p:
		log(ERROR, "INTERNAL ERROR: Requested IV of plaintext frame")
		return 0

	wep = p[Dot11WEP]
	if wep.keyid & 32:
		# FIXME: Only CCMP is supported (TKIP uses a different IV structure)
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
	else:
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (ord(wep.iv[2]) << 16)

def get_tlv_value(p, type):
	if not Dot11Elt in p: return None
	el = p[Dot11Elt]
	while isinstance(el, Dot11Elt):
		if el.ID == type:
			return el.info
		el = el.payload
	return None

def dot11_get_priority(p):
	if not Dot11QoS in p: return 0
	return ord(str(p[Dot11QoS])[0])


#### Crypto functions and util ####

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

class IvInfo():
	def __init__(self, p):
		self.iv = dot11_get_iv(p)
		self.seq = dot11_get_seqnum(p)
		self.time = p.time

	def is_reused(self, p):
		"""Return true if frame p reuses an IV and if p is not a retransmitted frame"""
		iv = dot11_get_iv(p)
		seq = dot11_get_seqnum(p)
		return self.iv == iv and self.seq != seq and p.time >= self.time + 1

class IvCollection():
	def __init__(self):
		self.ivs = dict() # maps IV values to IvInfo objects

	def reset(self):
		self.ivs = dict()

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



