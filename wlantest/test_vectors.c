/*
 * test_vectors - IEEE 802.11 test vector generator
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "wlantest.h"


extern int wpa_debug_level;
extern int wpa_debug_show_keys;


static void test_vector_tkip(void)
{
	u8 tk[] = {
		0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
		0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12,
		0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
		0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34
	};
	u8 pn[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	u8 frame[] = {
		0x08, 0x42, 0x2c, 0x00, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x08, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xd0, 0x02,
		/* 0x00, 0x20, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, */
		0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0xa5, 0x55, 0xc0, 0xa8, 0x0a, 0x02,
		0xc0, 0xa8, 0x0a, 0x01, 0x08, 0x00, 0x3a, 0xb0,
		0x00, 0x00, 0x00, 0x00, 0xcd, 0x4c, 0x05, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
		0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37,
		/* 0x68, 0x81, 0xa3, 0xf3, 0xd6, 0x48, 0xd0, 0x3c */
	};
	u8 *enc, *plain;
	size_t enc_len, plain_len;

	wpa_printf(MSG_INFO, "\nIEEE Std 802.11-2012, M.6.3 TKIP test "
		   "vector\n");

	wpa_hexdump(MSG_INFO, "TK", tk, sizeof(tk));
	wpa_hexdump(MSG_INFO, "PN", pn, sizeof(pn));
	wpa_hexdump(MSG_INFO, "Plaintext MPDU", frame, sizeof(frame));

	enc = tkip_encrypt(tk, frame, sizeof(frame), 24, NULL, pn, 0, &enc_len);
	if (enc == NULL) {
		wpa_printf(MSG_ERROR, "Failed to encrypt TKIP frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Encrypted MPDU (without FCS)", enc, enc_len);

	wpa_debug_level = MSG_INFO;
	plain = tkip_decrypt(tk, (const struct ieee80211_hdr *) enc,
			     enc + 24, enc_len - 24, &plain_len);
	wpa_debug_level = MSG_EXCESSIVE;
	os_free(enc);

	if (plain == NULL) {
		wpa_printf(MSG_ERROR, "Failed to decrypt TKIP frame");
		return;
	}

	if (plain_len != sizeof(frame) - 24 ||
	    os_memcmp(plain, frame + 24, plain_len) != 0) {
		wpa_hexdump(MSG_ERROR, "Decryption result did not match",
			    plain, plain_len);
	}

	os_free(plain);
}


static void test_vector_ccmp(void)
{
	u8 tk[] = { 0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
		    0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f };
	u8 pn[] = { 0xB5, 0x03, 0x97, 0x76, 0xE7, 0x0C };
	u8 frame[] = {
		0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28,
		0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08,
		0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33,
		0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae,
		0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb,
		0x7e, 0x78, 0xa0, 0x50
	};
	u8 *enc, *plain;
	size_t enc_len, plain_len;
	u8 fcs[4];

	wpa_printf(MSG_INFO, "\nIEEE Std 802.11-2012, M.6.4 CCMP test "
		   "vector\n");

	wpa_hexdump(MSG_INFO, "TK", tk, sizeof(tk));
	wpa_hexdump(MSG_INFO, "PN", pn, sizeof(pn));
	wpa_hexdump(MSG_INFO, "802.11 Header", frame, 24);
	wpa_hexdump(MSG_INFO, "Plaintext Data", frame + 24, sizeof(frame) - 24);

	enc = ccmp_encrypt(tk, frame, sizeof(frame), 24, NULL, pn, 0, &enc_len);
	if (enc == NULL) {
		wpa_printf(MSG_ERROR, "Failed to encrypt CCMP frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Encrypted MPDU (without FCS)", enc, enc_len);
	WPA_PUT_LE32(fcs, crc32(enc, enc_len));
	wpa_hexdump(MSG_INFO, "FCS", fcs, sizeof(fcs));

	wpa_debug_level = MSG_INFO;
	plain = ccmp_decrypt(tk, (const struct ieee80211_hdr *) enc,
			     enc + 24, enc_len - 24, &plain_len);
	wpa_debug_level = MSG_EXCESSIVE;
	os_free(enc);

	if (plain == NULL) {
		wpa_printf(MSG_ERROR, "Failed to decrypt CCMP frame");
		return;
	}

	if (plain_len != sizeof(frame) - 24 ||
	    os_memcmp(plain, frame + 24, plain_len) != 0) {
		wpa_hexdump(MSG_ERROR, "Decryption result did not match",
			    plain, plain_len);
	}

	os_free(plain);
}


static void test_vector_bip(void)
{
	u8 igtk[] = {
		0x4e, 0xa9, 0x54, 0x3e, 0x09, 0xcf, 0x2b, 0x1e,
		0xca, 0x66, 0xff, 0xc5, 0x8b, 0xde, 0xcb, 0xcf
	};
	u8 ipn[] = { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u8 frame[] = {
		0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
		0x02, 0x00
	};
	u8 *prot;
	size_t prot_len;

	wpa_printf(MSG_INFO, "\nIEEE Std 802.11-2012, M.9.1 BIP with broadcast "
		   "Deauthentication frame\n");

	wpa_hexdump(MSG_INFO, "IGTK", igtk, sizeof(igtk));
	wpa_hexdump(MSG_INFO, "IPN", ipn, sizeof(ipn));
	wpa_hexdump(MSG_INFO, "Plaintext frame", frame, sizeof(frame));

	prot = bip_protect(igtk, frame, sizeof(frame), ipn, 4, &prot_len);
	if (prot == NULL) {
		wpa_printf(MSG_ERROR, "Failed to protect BIP frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Protected MPDU (without FCS)", prot, prot_len);
	os_free(prot);
}


static void test_vector_ccmp_mgmt(void)
{
	u8 tk[] = { 0x66, 0xed, 0x21, 0x04, 0x2f, 0x9f, 0x26, 0xd7,
		    0x11, 0x57, 0x06, 0xe4, 0x04, 0x14, 0xcf, 0x2e };
	u8 pn[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	u8 frame[] = {
		0xc0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
		0x02, 0x00
	};
	u8 *enc, *plain;
	size_t enc_len, plain_len;

	wpa_printf(MSG_INFO, "\nIEEE Std 802.11-2012, M.9.2 CCMP with unicast "
		   "Deauthentication frame\n");

	wpa_hexdump(MSG_INFO, "TK", tk, sizeof(tk));
	wpa_hexdump(MSG_INFO, "PN", pn, sizeof(pn));
	wpa_hexdump(MSG_INFO, "802.11 Header", frame, 24);
	wpa_hexdump(MSG_INFO, "Plaintext Data", frame + 24, sizeof(frame) - 24);

	enc = ccmp_encrypt(tk, frame, sizeof(frame), 24, NULL, pn, 0, &enc_len);
	if (enc == NULL) {
		wpa_printf(MSG_ERROR, "Failed to encrypt CCMP frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Encrypted MPDU (without FCS)", enc, enc_len);

	wpa_debug_level = MSG_INFO;
	plain = ccmp_decrypt(tk, (const struct ieee80211_hdr *) enc,
			     enc + 24, enc_len - 24, &plain_len);
	wpa_debug_level = MSG_EXCESSIVE;
	os_free(enc);

	if (plain == NULL) {
		wpa_printf(MSG_ERROR, "Failed to decrypt CCMP frame");
		return;
	}

	if (plain_len != sizeof(frame) - 24 ||
	    os_memcmp(plain, frame + 24, plain_len) != 0) {
		wpa_hexdump(MSG_ERROR, "Decryption result did not match",
			    plain, plain_len);
	}

	os_free(plain);
}


static void test_vector_gcmp(void)
{
	u8 tk[] = { 0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
		    0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f };
	u8 pn[] = {
		0x00, 0x89, 0x5F, 0x5F, 0x2B, 0x08
	};
	u8 frame[] = {
		0x88, 0x48, 0x0b, 0x00, 0x0f, 0xd2, 0xe1, 0x28,
		0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08,
		0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0x80, 0x33,
		0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
		0x26, 0x27
	};
	u8 *enc, *plain;
	size_t enc_len, plain_len;
	u8 fcs[4];

	wpa_printf(MSG_INFO, "\nIEEE P802.11ad/D9.0, M.11.1 GCMP test "
		   "vector #2\n");

	wpa_hexdump(MSG_INFO, "TK", tk, sizeof(tk));
	wpa_hexdump(MSG_INFO, "PN", pn, sizeof(pn));
	wpa_hexdump(MSG_INFO, "802.11 Header", frame, 26);
	wpa_hexdump(MSG_INFO, "Plaintext Data", frame + 26, sizeof(frame) - 26);

	enc = gcmp_encrypt(tk, sizeof(tk), frame, sizeof(frame), 26, frame + 24,
			   pn, 0, &enc_len);
	if (enc == NULL) {
		wpa_printf(MSG_ERROR, "Failed to encrypt GCMP frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Encrypted MPDU (without FCS)", enc, enc_len);
	WPA_PUT_LE32(fcs, crc32(enc, enc_len));
	wpa_hexdump(MSG_INFO, "FCS", fcs, sizeof(fcs));

	wpa_debug_level = MSG_INFO;
	plain = gcmp_decrypt(tk, sizeof(tk), (const struct ieee80211_hdr *) enc,
			     enc + 26, enc_len - 26, &plain_len);
	wpa_debug_level = MSG_EXCESSIVE;
	os_free(enc);

	if (plain == NULL) {
		wpa_printf(MSG_ERROR, "Failed to decrypt GCMP frame");
		return;
	}

	if (plain_len != sizeof(frame) - 26 ||
	    os_memcmp(plain, frame + 26, plain_len) != 0) {
		wpa_hexdump(MSG_ERROR, "Decryption result did not match",
			    plain, plain_len);
	}

	os_free(plain);
}


static void test_vector_gcmp_256(void)
{
	u8 tk[] = { 0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
		    0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f,
		    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	u8 pn[] = {
		0x00, 0x89, 0x5F, 0x5F, 0x2B, 0x08
	};
	u8 frame[] = {
		0x88, 0x48, 0x0b, 0x00, 0x0f, 0xd2, 0xe1, 0x28,
		0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08,
		0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0x80, 0x33,
		0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
		0x26, 0x27
	};
	u8 *enc, *plain;
	size_t enc_len, plain_len;
	u8 fcs[4];

	wpa_printf(MSG_INFO, "\nGCMP-256 test vector\n");

	wpa_hexdump(MSG_INFO, "TK", tk, sizeof(tk));
	wpa_hexdump(MSG_INFO, "PN", pn, sizeof(pn));
	wpa_hexdump(MSG_INFO, "802.11 Header", frame, 26);
	wpa_hexdump(MSG_INFO, "Plaintext Data", frame + 26, sizeof(frame) - 26);

	enc = gcmp_encrypt(tk, sizeof(tk), frame, sizeof(frame), 26, frame + 24,
			   pn, 0, &enc_len);
	if (enc == NULL) {
		wpa_printf(MSG_ERROR, "Failed to encrypt GCMP frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Encrypted MPDU (without FCS)", enc, enc_len);
	WPA_PUT_LE32(fcs, crc32(enc, enc_len));
	wpa_hexdump(MSG_INFO, "FCS", fcs, sizeof(fcs));

	wpa_debug_level = MSG_INFO;
	plain = gcmp_decrypt(tk, sizeof(tk), (const struct ieee80211_hdr *) enc,
			     enc + 26, enc_len - 26, &plain_len);
	wpa_debug_level = MSG_EXCESSIVE;
	os_free(enc);

	if (plain == NULL) {
		wpa_printf(MSG_ERROR, "Failed to decrypt GCMP frame");
		return;
	}

	if (plain_len != sizeof(frame) - 26 ||
	    os_memcmp(plain, frame + 26, plain_len) != 0) {
		wpa_hexdump(MSG_ERROR, "Decryption result did not match",
			    plain, plain_len);
	}

	os_free(plain);
}


static void test_vector_ccmp_256(void)
{
	u8 tk[] = { 0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
		    0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f,
		    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	u8 pn[] = { 0xB5, 0x03, 0x97, 0x76, 0xE7, 0x0C };
	u8 frame[] = {
		0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28,
		0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08,
		0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33,
		0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae,
		0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb,
		0x7e, 0x78, 0xa0, 0x50
	};
	u8 *enc, *plain;
	size_t enc_len, plain_len;
	u8 fcs[4];

	wpa_printf(MSG_INFO, "\nCCMP-256 test vector\n");

	wpa_hexdump(MSG_INFO, "TK", tk, sizeof(tk));
	wpa_hexdump(MSG_INFO, "PN", pn, sizeof(pn));
	wpa_hexdump(MSG_INFO, "802.11 Header", frame, 24);
	wpa_hexdump(MSG_INFO, "Plaintext Data", frame + 24, sizeof(frame) - 24);

	enc = ccmp_256_encrypt(tk, frame, sizeof(frame), 24, NULL, pn, 0,
			       &enc_len);
	if (enc == NULL) {
		wpa_printf(MSG_ERROR, "Failed to encrypt CCMP frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Encrypted MPDU (without FCS)", enc, enc_len);
	WPA_PUT_LE32(fcs, crc32(enc, enc_len));
	wpa_hexdump(MSG_INFO, "FCS", fcs, sizeof(fcs));

	wpa_debug_level = MSG_INFO;
	plain = ccmp_256_decrypt(tk, (const struct ieee80211_hdr *) enc,
				 enc + 24, enc_len - 24, &plain_len);
	wpa_debug_level = MSG_EXCESSIVE;
	os_free(enc);

	if (plain == NULL) {
		wpa_printf(MSG_ERROR, "Failed to decrypt CCMP-256 frame");
		return;
	}

	if (plain_len != sizeof(frame) - 24 ||
	    os_memcmp(plain, frame + 24, plain_len) != 0) {
		wpa_hexdump(MSG_ERROR, "Decryption result did not match",
			    plain, plain_len);
	}

	os_free(plain);
}


static void test_vector_bip_gmac_128(void)
{
	u8 igtk[] = {
		0x4e, 0xa9, 0x54, 0x3e, 0x09, 0xcf, 0x2b, 0x1e,
		0xca, 0x66, 0xff, 0xc5, 0x8b, 0xde, 0xcb, 0xcf
	};
	u8 ipn[] = { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u8 frame[] = {
		0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
		0x02, 0x00
	};
	u8 *prot;
	size_t prot_len;

	wpa_printf(MSG_INFO, "\nBIP-GMAC-128 with broadcast "
		   "Deauthentication frame\n");

	wpa_hexdump(MSG_INFO, "IGTK", igtk, sizeof(igtk));
	wpa_hexdump(MSG_INFO, "IPN", ipn, sizeof(ipn));
	wpa_hexdump(MSG_INFO, "Plaintext frame", frame, sizeof(frame));

	prot = bip_gmac_protect(igtk, sizeof(igtk), frame, sizeof(frame),
				ipn, 4, &prot_len);
	if (prot == NULL) {
		wpa_printf(MSG_ERROR, "Failed to protect BIP-GMAC-128 frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Protected MPDU (without FCS)", prot, prot_len);
	os_free(prot);
}


static void test_vector_bip_gmac_256(void)
{
	u8 igtk[] = {
		0x4e, 0xa9, 0x54, 0x3e, 0x09, 0xcf, 0x2b, 0x1e,
		0xca, 0x66, 0xff, 0xc5, 0x8b, 0xde, 0xcb, 0xcf,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	u8 ipn[] = { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u8 frame[] = {
		0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
		0x02, 0x00
	};
	u8 *prot;
	size_t prot_len;

	wpa_printf(MSG_INFO, "\nBIP-GMAC-256 with broadcast "
		   "Deauthentication frame\n");

	wpa_hexdump(MSG_INFO, "IGTK", igtk, sizeof(igtk));
	wpa_hexdump(MSG_INFO, "IPN", ipn, sizeof(ipn));
	wpa_hexdump(MSG_INFO, "Plaintext frame", frame, sizeof(frame));

	prot = bip_gmac_protect(igtk, sizeof(igtk), frame, sizeof(frame),
				ipn, 4, &prot_len);
	if (prot == NULL) {
		wpa_printf(MSG_ERROR, "Failed to protect BIP-GMAC-256 frame");
		return;
	}

	wpa_hexdump(MSG_INFO, "Protected MPDU (without FCS)", prot, prot_len);
	os_free(prot);
}


int main(int argc, char *argv[])
{
	wpa_debug_level = MSG_EXCESSIVE;
	wpa_debug_show_keys = 1;

	if (os_program_init())
		return -1;

	test_vector_tkip();
	test_vector_ccmp();
	test_vector_bip();
	test_vector_ccmp_mgmt();
	test_vector_gcmp();
	test_vector_gcmp_256();
	test_vector_ccmp_256();
	test_vector_bip_gmac_128();
	test_vector_bip_gmac_256();

	os_program_deinit();

	return 0;
}
