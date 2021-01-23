#!/usr/bin/env python3
import struct, binascii
from .wifi import *
#from binascii import a2b_hex
#from struct import unpack,pack

from Crypto.Cipher import AES, ARC4
from scapy.layers.dot11 import Dot11, Dot11CCMP, Dot11QoS

import zlib

def pn2bytes(pn):
	pn_bytes = [0] * 6
	for i in range(6):
		pn_bytes[i] = pn & 0xFF
		pn >>= 8
	return pn_bytes

def pn2bin(pn):
	return struct.pack(">Q", pn)[2:]

def dot11ccmp_get_pn(p):
	pn = p.PN5
	pn = (pn << 8) | p.PN4
	pn = (pn << 8) | p.PN3
	pn = (pn << 8) | p.PN2
	pn = (pn << 8) | p.PN1
	pn = (pn << 8) | p.PN0
	return pn

def ccmp_get_nonce(priority, addr, pn):
	return struct.pack("B", priority) + addr2bin(addr) + pn2bin(pn)

def ccmp_get_aad(p, amsdu_spp=False):
	# FC field with masked values
	fc = raw(p)[:2]
	fc = struct.pack("<BB", fc[0] & 0x8f, fc[1] & 0xc7)

	# Sequence number is masked, but fragment number is included
	sc = struct.pack("<H", p.SC & 0xf)

	addr1 = addr2bin(p.addr1)
	addr2 = addr2bin(p.addr2)
	addr3 = addr2bin(p.addr3)
	aad = fc + addr1 + addr2 + addr3 + sc
	if Dot11QoS in p:
		if not amsdu_spp:
			# Everything except the TID is masked
			aad += struct.pack("<H", p[Dot11QoS].TID)
		else:
			# TODO: Mask unrelated fields
			aad += raw(p[Dot11QoS])[:2]

	return aad

def Raw(x):
	return x

def encrypt_ccmp(p, tk, pn, keyid=0, amsdu_spp=False):
	"""Takes a plaintext Dot11 frame, encrypts it, and adds all the necessairy headers"""

	# Update the FC field
	p = p.copy()
	p.FCfield |= Dot11(FCfield="protected").FCfield
	if Dot11QoS in p:
		payload = raw(p[Dot11QoS].payload)
		p[Dot11QoS].remove_payload()
		# Explicitly set TID so we can assume it's an integer
		if p[Dot11QoS].TID == None:
			p[Dot11QoS].TID = 0
		priority = p[Dot11QoS].TID
	else:
		payload = raw(p.payload)
		p.remove_payload()
		priority = 0

	# Add the CCMP header. res0 and res1 are by default set to zero.
	newp = p/Dot11CCMP()
	pn_bytes = pn2bytes(pn)
	newp.PN0, newp.PN1, newp.PN2, newp.PN3, newp.PN4, newp.PN5 = pn_bytes
	newp.key_id = keyid
	newp.ext_iv = 1

	# Generate the CCMP Header and AAD for encryption.
	ccm_nonce = ccmp_get_nonce(priority, newp.addr2, pn)
	ccm_aad = ccmp_get_aad(newp, amsdu_spp)
	#print("CCM Nonce:", ccm_nonce.hex())
	#print("CCM aad  :", ccm_aad.hex())

	# Encrypt the plaintext using AES in CCM Mode.
	#print("Payload:", payload.hex())
	cipher = AES.new(tk, AES.MODE_CCM, ccm_nonce, mac_len=8)
	cipher.update(ccm_aad)
	ciphertext = cipher.encrypt(payload)
	digest = cipher.digest()
	newp = newp/Raw(ciphertext)
	newp = newp/Raw(digest)

	#print("Ciphertext:", ciphertext.hex())
	#print(repr(newp))
	#print(raw(newp).hex())

	return newp

def decrypt_ccmp(p, tk, verify=True):
	"""Takes a Dot11CCMP frame and decrypts it"""

	p = p.copy()

	# Get used CCMP parameters
	keyid = p.key_id
	priority = dot11_get_priority(p)
	pn = dot11ccmp_get_pn(p)

	# TODO: Mask flags in p.FCfield that are not part of the AAD
	fc = p.FCfield
	payload = get_ccmp_payload(p)

	if Dot11QoS in p:
		p[Dot11QoS].remove_payload()
	else:
		p.remove_payload()

	# Prepare for CCMP decryption
	ccm_nonce = ccmp_get_nonce(priority, p.addr2, pn)
	ccm_aad = ccmp_get_aad(p)

	# Decrypt using AES in CCM Mode.
	cipher = AES.new(tk, AES.MODE_CCM, ccm_nonce, mac_len=8)
	cipher.update(ccm_aad)
	plaintext = cipher.decrypt(payload[:-8])

	try:
		if verify:
			cipher.verify(payload[-8:])
	except ValueError:
		return None

	return p/LLC(plaintext)

def encrypt_wep(p, key, pn, keyid=0):
	"""Takes a plaintext Dot11 frame, encrypts it, and adds all the necessairy headers"""

	# Update the FC field --- XXX share this with encrypt_ccmp
	p = p.copy()
	p.FCfield |= Dot11(FCfield="protected").FCfield
	if Dot11QoS in p:
		payload = raw(p[Dot11QoS].payload)
		p[Dot11QoS].remove_payload()
		# Explicitly set TID so we can assume it's an integer
		if p[Dot11QoS].TID == None:
			p[Dot11QoS].TID = 0
		priority = p[Dot11QoS].TID
	else:
		payload = raw(p.payload)
		p.remove_payload()
		priority = 0

	# Add the WEP ICV which will be encrypted
	payload += struct.pack("<I", zlib.crc32(payload) & 0xffffffff)
	iv = struct.pack(">I", pn)[1:]
	cipher = ARC4.new(iv + key)
	ciphertext = cipher.encrypt(payload)

	# Construct packet ourselves to avoid scapy bugs
	newp = p/iv/struct.pack("<B", keyid)/ciphertext

	return newp

