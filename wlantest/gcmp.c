/*
 * GCM with GMAC Protocol (GCMP)
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "crypto/aes.h"
#include "wlantest.h"


static void inc32(u8 *block)
{
	u32 val;
	val = WPA_GET_BE32(block + AES_BLOCK_SIZE - 4);
	val++;
	WPA_PUT_BE32(block + AES_BLOCK_SIZE - 4, val);
}


static void xor_block(u8 *dst, const u8 *src)
{
	u32 *d = (u32 *) dst;
	u32 *s = (u32 *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}


static void shift_right_block(u8 *v)
{
	u32 val;

	val = WPA_GET_BE32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 12, val);

	val = WPA_GET_BE32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 8, val);

	val = WPA_GET_BE32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 4, val);

	val = WPA_GET_BE32(v);
	val >>= 1;
	WPA_PUT_BE32(v, val);
}


/* Multiplication in GF(2^128) */
static void gf_mult(const u8 *x, const u8 *y, u8 *z)
{
	u8 v[16];
	int i, j;

	os_memset(z, 0, 16); /* Z_0 = 0^128 */
	os_memcpy(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}


static void ghash(const u8 *h, const u8 *x, size_t xlen, u8 *y)
{
	size_t m, i;
	const u8 *xpos = x;
	u8 tmp[16];

	m = xlen / 16;

	/* Y_0 = 0^128 */
	os_memset(y, 0, 16);
	for (i = 0; i < m; i++) {
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(y, xpos);
		xpos += 16;

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
		os_memcpy(y, tmp, 16);
	}

	/* Return Y_m */
}


static void aes_gctr(void *aes, const u8 *icb, const u8 *x, size_t xlen, u8 *y)
{
	size_t i, n, last;
	u8 cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	const u8 *xpos = x;
	u8 *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	os_memcpy(cb, icb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++) {
		aes_encrypt(aes, cb, ypos);
		xor_block(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		inc32(cb);
	}

	last = x + xlen - xpos;
	if (last) {
		/* Last, partial block */
		aes_encrypt(aes, cb, tmp);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}


static void gcmp_aad_nonce(const struct ieee80211_hdr *hdr, const u8 *data,
			   u8 *aad, size_t *aad_len, u8 *nonce)
{
	u16 fc, stype, seq;
	int qos = 0, addr4 = 0;
	u8 *pos;

	fc = le_to_host16(hdr->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);
	if ((fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)) ==
	    (WLAN_FC_TODS | WLAN_FC_FROMDS))
		addr4 = 1;

	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA) {
		fc &= ~0x0070; /* Mask subtype bits */
		if (stype & 0x08) {
			const u8 *qc;
			qos = 1;
			fc &= ~WLAN_FC_ORDER;
			qc = (const u8 *) (hdr + 1);
			if (addr4)
				qc += ETH_ALEN;
		}
	}

	fc &= ~(WLAN_FC_RETRY | WLAN_FC_PWRMGT | WLAN_FC_MOREDATA);
	fc |= WLAN_FC_ISWEP;
	WPA_PUT_LE16(aad, fc);
	pos = aad + 2;
	os_memcpy(pos, hdr->addr1, 3 * ETH_ALEN);
	pos += 3 * ETH_ALEN;
	seq = le_to_host16(hdr->seq_ctrl);
	seq &= ~0xfff0; /* Mask Seq#; do not modify Frag# */
	WPA_PUT_LE16(pos, seq);
	pos += 2;

	os_memcpy(pos, hdr + 1, addr4 * ETH_ALEN + qos * 2);
	pos += addr4 * ETH_ALEN;
	if (qos) {
		pos[0] &= ~0x70;
		if (1 /* FIX: either device has SPP A-MSDU Capab = 0 */)
			pos[0] &= ~0x80;
		pos++;
		*pos++ = 0x00;
	}

	*aad_len = pos - aad;

	os_memcpy(nonce, hdr->addr2, ETH_ALEN);
	nonce[6] = data[7]; /* PN5 */
	nonce[7] = data[6]; /* PN4 */
	nonce[8] = data[5]; /* PN3 */
	nonce[9] = data[4]; /* PN2 */
	nonce[10] = data[1]; /* PN1 */
	nonce[11] = data[0]; /* PN0 */
}


u8 * gcmp_decrypt(const u8 *tk, const struct ieee80211_hdr *hdr,
		  const u8 *data, size_t data_len, size_t *decrypted_len)
{
	u8 aad[2 + 30], nonce[12], *plain, *auth, *apos;
	u8 H[AES_BLOCK_SIZE];
	u8 J0[AES_BLOCK_SIZE];
	u8 S[16], T[16];
	size_t aad_len, padlen, mlen;
	void *aes;
	const u8 *m;

	if (data_len < 8 + 16)
		return NULL;

	plain = os_malloc(data_len + AES_BLOCK_SIZE);
	if (plain == NULL)
		return NULL;

	aes = aes_encrypt_init(tk, 16);
	if (aes == NULL) {
		os_free(plain);
		return NULL;
	}

	m = data + 8;
	mlen = data_len - 8 - 16;

	os_memset(aad, 0, sizeof(aad));
	gcmp_aad_nonce(hdr, data, &aad[2], &aad_len, nonce);
	WPA_PUT_BE16(aad, aad_len);
	wpa_hexdump(MSG_EXCESSIVE, "GCMP AAD", &aad[2], aad_len);
	wpa_hexdump(MSG_EXCESSIVE, "GCMP nonce", nonce, sizeof(nonce));

	/* GCM-AD_K(IV, C, A, T)
	 *
	 * IV = GCMP nonce
	 * A = AAD
	 * C | T = received frame
	 */

	/* 2. Generate hash subkey H = AES_K(0^128) */
	os_memset(H, 0, sizeof(H));
	aes_encrypt(aes, H, H);
	wpa_hexdump(MSG_EXCESSIVE, "Hash subkey H for GHASH", H, sizeof(H));

	/* 3. Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
	os_memcpy(J0, nonce, sizeof(nonce));
	os_memset(J0 + sizeof(nonce), 0, AES_BLOCK_SIZE - sizeof(nonce));
	J0[AES_BLOCK_SIZE - 1] = 0x01;

	/* 4. C = GCTR_K(inc_32(J_0), C) */
	inc32(J0);
	aes_gctr(aes, J0, m, mlen, plain);

	/*
	 * 5. u = 128 * ceil[len(C)/128] - len(C)
	 *    v = 128 * ceil[len(A)/128] - len(A)
	 * 6. S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	auth = os_malloc(32 + 16 + data_len - 16 + 8 + 8);
	if (auth == NULL) {
		os_free(plain);
		return NULL;
	}

	apos = auth;

	/* Zero-padded AAD */
	os_memcpy(apos, &aad[2], aad_len);
	apos += aad_len;
	padlen = (16 - aad_len % 16) % 16;
	os_memset(apos, 0, padlen);
	apos += padlen;

	/* Zero-padded C */
	os_memcpy(apos, m, mlen);
	apos += mlen;
	padlen = (16 - mlen % 16) % 16;
	os_memset(apos, 0, padlen);
	apos += padlen;

	/* Length of AAD and C in bits */
	WPA_PUT_BE64(apos, aad_len * 8);
	apos += 8;
	WPA_PUT_BE64(apos, mlen * 8);
	apos += 8;

	wpa_hexdump(MSG_EXCESSIVE, "GCMP GHASH_H input", auth, apos - auth);
	ghash(H, auth, apos - auth, S);
	wpa_hexdump(MSG_EXCESSIVE, "GCMP S = GHASH_H(...)", S, 16);
	os_free(auth);

	/* 7. T' = MSB_t(GCTR_K(J_0, S)) */
	J0[AES_BLOCK_SIZE - 1] = 0x01;
	aes_gctr(aes, J0, S, sizeof(S), T);

	aes_encrypt_deinit(aes);

	if (os_memcmp(data + data_len - 16, T, 16) != 0) {
		u16 seq_ctrl = le_to_host16(hdr->seq_ctrl);
		wpa_printf(MSG_INFO, "Invalid GCMP MIC in frame: A1=" MACSTR
			   " A2=" MACSTR " A3=" MACSTR " seq=%u frag=%u",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3),
			   WLAN_GET_SEQ_SEQ(seq_ctrl),
			   WLAN_GET_SEQ_FRAG(seq_ctrl));
		wpa_hexdump(MSG_DEBUG, "GCMP decrypted", plain, data_len - 16);
		os_free(plain);
		return NULL;
	}

	*decrypted_len = data_len - 8 - 16;
	return plain;
}


u8 * gcmp_encrypt(const u8 *tk, u8 *frame, size_t len, size_t hdrlen, u8 *qos,
		  u8 *pn, int keyid, size_t *encrypted_len)
{
	u8 aad[2 + 30], nonce[12], *crypt, *pos, *auth, *apos;
	u8 H[AES_BLOCK_SIZE];
	u8 J0[AES_BLOCK_SIZE];
	u8 S[16];
	size_t aad_len, plen, padlen;
	struct ieee80211_hdr *hdr;
	void *aes;

	if (len < hdrlen || hdrlen < 24)
		return NULL;
	plen = len - hdrlen;

	crypt = os_malloc(hdrlen + 8 + plen + 16 + AES_BLOCK_SIZE);
	if (crypt == NULL)
		return NULL;

	os_memcpy(crypt, frame, hdrlen);
	hdr = (struct ieee80211_hdr *) crypt;
	hdr->frame_control |= host_to_le16(WLAN_FC_ISWEP);
	pos = crypt + hdrlen;
	*pos++ = pn[5]; /* PN0 */
	*pos++ = pn[4]; /* PN1 */
	*pos++ = 0x00; /* Rsvd */
	*pos++ = 0x20 | (keyid << 6);
	*pos++ = pn[3]; /* PN2 */
	*pos++ = pn[2]; /* PN3 */
	*pos++ = pn[1]; /* PN4 */
	*pos++ = pn[0]; /* PN5 */

	aes = aes_encrypt_init(tk, 16);
	if (aes == NULL) {
		os_free(crypt);
		return NULL;
	}

	os_memset(aad, 0, sizeof(aad));
	gcmp_aad_nonce(hdr, crypt + hdrlen, &aad[2], &aad_len, nonce);
	WPA_PUT_BE16(aad, aad_len);
	wpa_hexdump(MSG_EXCESSIVE, "GCMP AAD", &aad[2], aad_len);
	wpa_hexdump(MSG_EXCESSIVE, "GCMP nonce", nonce, sizeof(nonce));

	/* GCM-AE_K(IV, P, A)
	 *
	 * IV = GCMP nonce
	 * A = AAD
	 */

	/* 1. Generate hash subkey H = AES_K(0^128) */
	os_memset(H, 0, sizeof(H));
	aes_encrypt(aes, H, H);
	wpa_hexdump(MSG_EXCESSIVE, "Hash subkey H for GHASH", H, sizeof(H));

	/* 2. Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
	os_memcpy(J0, nonce, sizeof(nonce));
	os_memset(J0 + sizeof(nonce), 0, AES_BLOCK_SIZE - sizeof(nonce));
	J0[AES_BLOCK_SIZE - 1] = 0x01;

	/* 3. C = GCTR_K(inc_32(J_0), P) */
	inc32(J0);
	aes_gctr(aes, J0, frame + hdrlen, len - hdrlen, pos);
	pos += len - hdrlen;

	/*
	 * 4. u = 128 * ceil[len(C)/128] - len(C)
	 *    v = 128 * ceil[len(A)/128] - len(A)
	 * 5. S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	auth = os_malloc(32 + 16 + len - hdrlen + 8 + 8);
	if (auth == NULL) {
		os_free(crypt);
		return NULL;
	}

	apos = auth;

	/* Zero-padded AAD */
	os_memcpy(apos, &aad[2], aad_len);
	apos += aad_len;
	padlen = (16 - aad_len % 16) % 16;
	os_memset(apos, 0, padlen);
	apos += padlen;

	/* Zero-padded C */
	os_memcpy(apos, crypt + hdrlen + 8, plen);
	apos += plen;
	padlen = (16 - plen % 16) % 16;
	os_memset(apos, 0, padlen);
	apos += padlen;

	/* Length of AAD and C in bits */
	WPA_PUT_BE64(apos, aad_len * 8);
	apos += 8;
	WPA_PUT_BE64(apos, plen * 8);
	apos += 8;

	wpa_hexdump(MSG_EXCESSIVE, "GCMP GHASH_H input", auth, apos - auth);
	ghash(H, auth, apos - auth, S);
	wpa_hexdump(MSG_EXCESSIVE, "GCMP S = GHASH_H(...)", S, 16);
	os_free(auth);

	/* 6. T = MSB_t(GCTR_K(J_0, S)) */
	J0[AES_BLOCK_SIZE - 1] = 0x01;
	aes_gctr(aes, J0, S, sizeof(S), pos);
	wpa_hexdump(MSG_EXCESSIVE, "GCMP MIC", pos, 16);

	/* 7. Return (C, T) */

	wpa_hexdump(MSG_EXCESSIVE, "GCMP encrypted", crypt + hdrlen + 8, plen);

	aes_encrypt_deinit(aes);

	*encrypted_len = hdrlen + 8 + plen + 16;

	return crypt;
}
