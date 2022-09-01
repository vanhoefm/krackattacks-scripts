# Copyright (c) 2019-2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
from scapy.all import *
from Crypto.Cipher import AES
from datetime import datetime
import binascii

#### Constants ####

IEEE_TLV_TYPE_SSID    = 0
IEEE_TLV_TYPE_CHANNEL = 3
IEEE_TLV_TYPE_RSN     = 48
IEEE_TLV_TYPE_CSA     = 37
IEEE_TLV_TYPE_FT      = 55
IEEE_TLV_TYPE_VENDOR  = 221

WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4
WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6
WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7

#TODO: Not sure if really needed...
IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_CHANNEL = (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS = (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES = (1 << 17)

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
	msg = (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m"
	print(msg)

def change_log_level(delta):
	global global_log_level
	global_log_level += delta

#### Back-wards compatibility with older scapy

if not "Dot11FCS" in locals():
	class Dot11FCS():
		pass
if not "Dot11Encrypted" in locals():
	class Dot11Encrypted():
		pass
	class Dot11CCMP():
		pass
	class Dot11TKIP():
		pass

#### Linux ####

def get_device_driver(iface):
	path = "/sys/class/net/%s/device/driver" % iface
	try:
		output = subprocess.check_output(["readlink", "-f", path])
		return output.decode('utf-8').strip().split("/")[-1]
	except:
		return None

#### Utility ####

def get_mac_address(interface):
	return open("/sys/class/net/%s/address" % interface).read().strip()

def addr2bin(addr):
	return binascii.a2b_hex(addr.replace(':', ''))

def get_channel(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("channel (\d+)")
	m = p.search(output)
	if m == None: return None
	return int(m.group(1))

def get_channel(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("channel (\d+)")
	m = p.search(output)
	if m == None:
		return None
	return int(m.group(1))

def set_channel(iface, channel):
	subprocess.check_output(["iw", iface, "set", "channel", str(channel)])

def set_macaddress(iface, macaddr):
	# macchanger throws an error if the interface already has the given MAC address
	if get_macaddress(iface) != macaddr:
		subprocess.check_output(["ifconfig", iface, "down"])
		subprocess.check_output(["macchanger", "-m", macaddr, iface])

def get_macaddress(iface):
	"""This works even for interfaces in monitor mode."""
	s = get_if_raw_hwaddr(iface)[1]
	return ("%02x:" * 6)[:-1] % tuple(orb(x) for x in s)

def get_iface_type(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("type (\w+)")
	return str(p.search(output).group(1))

def set_monitor_mode(iface, up=True, mtu=1500):
	# Note: we let the user put the device in monitor mode, such that they can control optional
	#       parameters such as "iw wlan0 set monitor active" for devices that support it.
	if get_iface_type(iface) != "monitor":
		# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
		# sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
		subprocess.check_output(["ifconfig", iface, "down"])
		subprocess.check_output(["iw", iface, "set", "type", "monitor"])
		time.sleep(0.5)
		subprocess.check_output(["iw", iface, "set", "type", "monitor"])

	if up:
		subprocess.check_output(["ifconfig", iface, "up"])
	subprocess.check_output(["ifconfig", iface, "mtu", str(mtu)])

def rawmac(addr):
	return bytes.fromhex(addr.replace(':', ''))

def set_amsdu(p):
	if "A_MSDU_Present" in [field.name for field in Dot11QoS.fields_desc]:
		p.A_MSDU_Present = 1
	else:
		p.Reserved = 1

def is_amsdu(p):
	if "A_MSDU_Present" in [field.name for field in Dot11QoS.fields_desc]:
		return p.A_MSDU_Present == 1
	else:
		return p.Reserved == 1

#### Packet Processing Functions ####

class DHCP_sock(DHCP_am):
	def __init__(self, **kwargs):
		self.sock = kwargs.pop("sock")
		self.server_ip = kwargs["gw"]
		super(DHCP_sock, self).__init__(**kwargs)

	def prealloc_ip(self, clientmac, ip=None):
		"""Allocate an IP for the client before it send DHCP requests"""
		if clientmac not in self.leases:
			if ip == None:
				ip = self.pool.pop()
			self.leases[clientmac] = ip
		return self.leases[clientmac]

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

# Compatibility with older Scapy versions
if not "ORDER" in scapy.layers.dot11._rt_txflags:
	scapy.layers.dot11._rt_txflags.append("ORDER")

class MonitorSocket(L2Socket):
	def __init__(self, iface, dumpfile=None, detect_injected=False, **kwargs):
		super(MonitorSocket, self).__init__(iface, **kwargs)
		self.pcap = None
		if dumpfile:
			self.pcap = PcapWriter("%s.%s.pcap" % (dumpfile, self.iface), append=False, sync=True)
		self.detect_injected = detect_injected
		self.default_rate = None

	def set_channel(self, channel):
		subprocess.check_output(["iw", self.iface, "set", "channel", str(channel)])

	def attach_filter(self, bpf):
		log(DEBUG, "Attaching filter to %s: <%s>" % (self.iface, bpf))
		attach_filter(self.ins, bpf, self.iface)

	def set_default_rate(self, rate):
		self.default_rate = rate

	def send(self, p, rate=None):
		# Hack: set the More Data flag so we can detect injected frames (and so clients stay awake longer)
		if self.detect_injected:
			p.FCfield |= 0x20

		# Control data rate injected frames
		if rate is None and self.default_rate is None:
			rtap = RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")
		else:
			use_rate = rate if rate != None else self.default_rate
			rtap = RadioTap(present="TXFlags+Rate", Rate=use_rate, TXFlags="NOSEQ+ORDER")

		L2Socket.send(self, rtap/p)
		if self.pcap: self.pcap.write(RadioTap()/p)

	def _strip_fcs(self, p):
		"""
		Scapy may throw exceptions when handling malformed short frames,
		so we need to catch these exceptions and just ignore these frames.
		This in particular happened with short malformed beacons.
		"""
		try:
			return Dot11(raw(p[Dot11FCS])[:-4])
		except:
			return None

	def _detect_and_strip_fcs(self, p):
		# Older scapy can't handle the optional Frame Check Sequence (FCS) field automatically
		if p[RadioTap].present & 2 != 0 and not Dot11FCS in p:
			rawframe = raw(p[RadioTap])
			pos = 8
			while orb(rawframe[pos - 1]) & 0x80 != 0: pos += 4

			# If the TSFT field is present, it must be 8-bytes aligned
			if p[RadioTap].present & 1 != 0:
				pos += (8 - (pos % 8))
				pos += 8

			# Remove FCS if present
			if orb(rawframe[pos]) & 0x10 != 0:
				return self._strip_fcs(p)

		return p[Dot11]

	def recv(self, x=MTU, reflected=False):
		p = L2Socket.recv(self, x)
		if p == None or not (Dot11 in p or Dot11FCS in p):
			return None
		if self.pcap:
			self.pcap.write(p)

		# Hack: ignore frames that we just injected and are echoed back by the kernel
		if self.detect_injected and p.FCfield & 0x20 != 0:
			return None

		# Ignore reflection of injected frames. These have a small RadioTap header.
		if not reflected and p[RadioTap].len < 13:
			return None

		# Strip the FCS if present, and drop the RadioTap header
		if Dot11FCS in p:
			return self._strip_fcs(p)
		else:
			return self._detect_and_strip_fcs(p)

	def close(self):
		if self.pcap: self.pcap.close()
		super(MonitorSocket, self).close()

# For backwards compatibility
class MitmSocket(MonitorSocket):
	pass

def dot11_get_seqnum(p):
	return p.SC >> 4

def dot11_is_encrypted_data(p):
	# All these different cases are explicitly tested to handle older scapy versions
	return (p.FCfield & 0x40) or Dot11CCMP in p or Dot11TKIP in p or Dot11WEP in p or Dot11Encrypted in p

def payload_to_iv(payload):
	iv0 = payload[0]
	iv1 = payload[1]
	wepdata = payload[4:8]

	# FIXME: Only CCMP is supported (TKIP uses a different IV structure)
	return orb(iv0) + (orb(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)

def dot11_get_iv(p):
	"""
	Assume it's a CCMP frame. Old scapy can't handle Extended IVs.
	This code only works for CCMP frames.
	"""
	if Dot11CCMP in p:
		payload = raw(p[Dot11CCMP])
		return payload_to_iv(payload)

	elif Dot11TKIP in p:
		# Scapy uses a heuristic to differentiate CCMP/TKIP and this may be wrong.
		# So even when we get a Dot11TKIP frame, we should treat it like a Dot11CCMP frame.
		payload = raw(p[Dot11TKIP])
		return payload_to_iv(payload)

	if Dot11CCMP in p:
		payload = raw(p[Dot11CCMP])
		return payload_to_iv(payload)
	elif Dot11TKIP in p:
		payload = raw(p[Dot11TKIP])
		return payload_to_iv(payload)
	elif Dot11Encrypted in p:
		payload = raw(p[Dot11Encrypted])
		return payload_to_iv(payload)

	elif Dot11WEP in p:
		wep = p[Dot11WEP]
		if wep.keyid & 32:
			# FIXME: Only CCMP is supported (TKIP uses a different IV structure)
			return orb(wep.iv[0]) + (orb(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
		else:
			return orb(wep.iv[0]) + (orb(wep.iv[1]) << 8) + (orb(wep.iv[2]) << 16)

	elif p.FCfield & 0x40:
		return payload_to_iv(p[Raw].load)

	else:
		return None

def dot11_get_priority(p):
	if not Dot11QoS in p: return 0
	return p[Dot11QoS].TID


#### Crypto functions and util ####

def get_ccmp_keyid(p):
	if Dot11WEP in p:
		return p.keyid
	return p.key_id

def get_ccmp_payload(p):
	if Dot11WEP in p:
		# Extract encrypted payload:
		# - Skip extended IV (4 bytes in total)
		# - Exclude first 4 bytes of the CCMP MIC (note that last 4 are saved in the WEP ICV field)
		return raw(p.wepdata[4:-4])
	elif Dot11CCMP in p:
		return p[Dot11CCMP].data
	elif Dot11TKIP in p:
		return p[Dot11TKIP].data
	elif Dot11Encrypted in p:
		return p[Dot11Encrypted].data
	elif Raw in p:
		return p[Raw].load
	else:
		return None

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

def create_fragments(header, data, num_frags):
	# This special case is useful so scapy keeps the full "interpretation" of the frame
	# instead of afterwards treating/displaying the payload as just raw data.
	if num_frags == 1: return [header/data]

	data = raw(data)
	fragments = []
	fragsize = (len(data) + num_frags - 1) // num_frags
	for i in range(num_frags):
		frag = header.copy()
		frag.SC |= i
		if i < num_frags - 1:
			frag.FCfield |= Dot11(FCfield="MF").FCfield

		payload = data[fragsize * i : fragsize * (i + 1)]
		frag = frag/Raw(payload)
		fragments.append(frag)

	return fragments

def get_element(el, id):
	if not Dot11Elt in el: return None
	el = el[Dot11Elt]
	while not el is None:
		if el.ID == id:
			return el
		el = el.payload
	return None

def get_ssid(beacon):
	if not (Dot11 in beacon or Dot11FCS in beacon): return
	if Dot11Elt not in beacon: return
	if beacon[Dot11].type != 0 and beacon[Dot11].subtype != 8: return
	el = get_element(beacon, IEEE_TLV_TYPE_SSID)
	return el.info.decode()

def is_from_sta(p, macaddr):
	if not (Dot11 in p or Dot11FCS in p):
		return False
	if p.addr1 != macaddr and p.addr2 != macaddr:
		return False
	return True

def get_bss(iface, clientmac, timeout=20):
	ps = sniff(count=1, timeout=timeout, lfilter=lambda p: is_from_sta(p, clientmac), iface=iface)
	if len(ps) == 0:
		return None
	return ps[0].addr1 if ps[0].addr1 != clientmac else ps[0].addr2

def create_msdu_subframe(src, dst, payload, last=False):
	length = len(payload)
	p = Ether(dst=dst, src=src, type=length)

	payload = raw(payload)

	total_length = len(p) + len(payload)
	padding = ""
	if not last and total_length % 4 != 0:
		padding = b"\x00" * (4 - (total_length % 4))

	return p / payload / Raw(padding)

def find_network(iface, ssid):
	ps = sniff(count=1, timeout=0.3, lfilter=lambda p: get_ssid(p) == ssid, iface=iface)
	if ps is None or len(ps) < 1:
		log(STATUS, "Searching for target network on other channels")
		for chan in [1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9, 12, 13]:
			set_channel(iface, chan)
			log(DEBUG, "Listening on channel %d" % chan)
			ps = sniff(count=1, timeout=0.3, lfilter=lambda p: get_ssid(p) == ssid, iface=iface)
			if ps and len(ps) >= 1: break

	if ps and len(ps) >= 1:
		# Even though we capture the beacon we might still be on another channel,
		# so it's important to explicitly switch to the correct channel.
		actual_chan = orb(get_element(ps[0], IEEE_TLV_TYPE_CHANNEL).info)
		set_channel(iface, actual_chan)

		# Return the beacon that we captured
		return ps[0]

	return None

