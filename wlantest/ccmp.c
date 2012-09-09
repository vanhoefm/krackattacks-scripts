/*
 * CTR with CBC-MAC Protocol (CCMP)
 * Copyright (c) 2010-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "crypto/aes.h"
#include "wlantest.h"


static void xor_aes_block(u8 *dst, const u8 *src)
{
	u32 *d = (u32 *) dst;
	u32 *s = (u32 *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}


static void aes_ccm_auth_start(void *aes, size_t M, size_t L, const u8 *nonce,
			       const u8 *aad, size_t aad_len, size_t plain_len,
			       u8 *x)
{
	u8 aad_buf[2 * AES_BLOCK_SIZE];
	u8 b[AES_BLOCK_SIZE];

	/* Authentication */
	/* B_0: Flags | Nonce N | l(m) */
	b[0] = aad_len ? 0x40 : 0 /* Adata */;
	b[0] |= (((M - 2) / 2) /* M' */ << 3);
	b[0] |= (L - 1) /* L' */;
	os_memcpy(&b[1], nonce, 15 - L);
	WPA_PUT_BE16(&b[AES_BLOCK_SIZE - L], plain_len);

	wpa_hexdump_key(MSG_EXCESSIVE, "CCM B_0", b, AES_BLOCK_SIZE);
	aes_encrypt(aes, b, x); /* X_1 = E(K, B_0) */

	if (!aad_len)
		return;

	WPA_PUT_BE16(aad_buf, aad_len);
	os_memcpy(aad_buf + 2, aad, aad_len);
	os_memset(aad_buf + 2 + aad_len, 0, sizeof(aad_buf) - 2 - aad_len);

	xor_aes_block(aad_buf, x);
	aes_encrypt(aes, aad_buf, x); /* X_2 = E(K, X_1 XOR B_1) */

	if (aad_len > AES_BLOCK_SIZE - 2) {
		xor_aes_block(&aad_buf[AES_BLOCK_SIZE], x);
		/* X_3 = E(K, X_2 XOR B_2) */
		aes_encrypt(aes, &aad_buf[AES_BLOCK_SIZE], x);
	}
}


static void aes_ccm_auth(void *aes, const u8 *data, size_t len, u8 *x)
{
	size_t last = len % AES_BLOCK_SIZE;
	size_t i;

	for (i = 0; i < len / AES_BLOCK_SIZE; i++) {
		/* X_i+1 = E(K, X_i XOR B_i) */
		xor_aes_block(x, data);
		data += AES_BLOCK_SIZE;
		aes_encrypt(aes, x, x);
	}
	if (last) {
		/* XOR zero-padded last block */
		for (i = 0; i < last; i++)
			x[i] ^= *data++;
		aes_encrypt(aes, x, x);
	}
}


static void aes_ccm_encr_start(size_t L, const u8 *nonce, u8 *a)
{
	/* A_i = Flags | Nonce N | Counter i */
	a[0] = L - 1; /* Flags = L' */
	os_memcpy(&a[1], nonce, 15 - L);
}


static void aes_ccm_encr(void *aes, size_t L, const u8 *in, size_t len, u8 *out,
			 u8 *a)
{
	size_t last = len % AES_BLOCK_SIZE;
	size_t i;

	/* crypt = msg XOR (S_1 | S_2 | ... | S_n) */
	for (i = 1; i <= len / AES_BLOCK_SIZE; i++) {
		WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], i);
		/* S_i = E(K, A_i) */
		aes_encrypt(aes, a, out);
		xor_aes_block(out, in);
		out += AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
	}
	if (last) {
		WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], i);
		aes_encrypt(aes, a, out);
		/* XOR zero-padded last block */
		for (i = 0; i < last; i++)
			*out++ ^= *in++;
	}
}


static void aes_ccm_encr_auth(void *aes, size_t M, u8 *x, u8 *a, u8 *auth)
{
	size_t i;
	u8 tmp[AES_BLOCK_SIZE];

	wpa_hexdump_key(MSG_EXCESSIVE, "CCM T", x, M);
	/* U = T XOR S_0; S_0 = E(K, A_0) */
	WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], 0);
	aes_encrypt(aes, a, tmp);
	for (i = 0; i < M; i++)
		auth[i] = x[i] ^ tmp[i];
	wpa_hexdump_key(MSG_EXCESSIVE, "CCM U", auth, M);
}


static void aes_ccm_decr_auth(void *aes, size_t M, u8 *a, const u8 *auth, u8 *t)
{
	size_t i;
	u8 tmp[AES_BLOCK_SIZE];

	wpa_hexdump_key(MSG_EXCESSIVE, "CCM U", auth, M);
	/* U = T XOR S_0; S_0 = E(K, A_0) */
	WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], 0);
	aes_encrypt(aes, a, tmp);
	for (i = 0; i < M; i++)
		t[i] = auth[i] ^ tmp[i];
	wpa_hexdump_key(MSG_EXCESSIVE, "CCM T", t, M);
}


/* AES-CCM with fixed L=2 and aad_len <= 30 assumption */
static int aes_ccm_ae(const u8 *key, size_t key_len, const u8 *nonce,
		      size_t M, const u8 *plain, size_t plain_len,
		      const u8 *aad, size_t aad_len, u8 *crypt, u8 *auth)
{
	const size_t L = 2;
	void *aes;
	u8 x[AES_BLOCK_SIZE], a[AES_BLOCK_SIZE];

	if (aad_len > 30 || M > AES_BLOCK_SIZE)
		return -1;

	aes = aes_encrypt_init(key, key_len);
	if (aes == NULL)
		return -1;

	aes_ccm_auth_start(aes, M, L, nonce, aad, aad_len, plain_len, x);
	aes_ccm_auth(aes, plain, plain_len, x);

	/* Encryption */
	aes_ccm_encr_start(L, nonce, a);
	aes_ccm_encr(aes, L, plain, plain_len, crypt, a);
	aes_ccm_encr_auth(aes, M, x, a, auth);

	aes_encrypt_deinit(aes);

	return 0;
}


/* AES-CCM with fixed L=2 and aad_len <= 30 assumption */
static int aes_ccm_ad(const u8 *key, size_t key_len, const u8 *nonce,
		      size_t M, const u8 *crypt, size_t crypt_len,
		      const u8 *aad, size_t aad_len, const u8 *auth, u8 *plain)
{
	const size_t L = 2;
	void *aes;
	u8 x[AES_BLOCK_SIZE], a[AES_BLOCK_SIZE];
	u8 t[AES_BLOCK_SIZE];

	if (aad_len > 30 || M > AES_BLOCK_SIZE)
		return -1;

	aes = aes_encrypt_init(key, key_len);
	if (aes == NULL)
		return -1;

	/* Decryption */
	aes_ccm_encr_start(L, nonce, a);
	aes_ccm_decr_auth(aes, M, a, auth, t);

	/* plaintext = msg XOR (S_1 | S_2 | ... | S_n) */
	aes_ccm_encr(aes, L, crypt, crypt_len, plain, a);

	aes_ccm_auth_start(aes, M, L, nonce, aad, aad_len, crypt_len, x);
	aes_ccm_auth(aes, plain, crypt_len, x);

	aes_encrypt_deinit(aes);

	if (os_memcmp(x, t, M) != 0) {
		wpa_printf(MSG_EXCESSIVE, "CCM: Auth mismatch");
		return -1;
	}

	return 0;
}


static void ccmp_aad_nonce(const struct ieee80211_hdr *hdr, const u8 *data,
			   u8 *aad, size_t *aad_len, u8 *nonce)
{
	u16 fc, stype, seq;
	int qos = 0, addr4 = 0;
	u8 *pos;

	nonce[0] = 0;

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
			nonce[0] = qc[0] & 0x0f;
		}
	} else if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT)
		nonce[0] |= 0x10; /* Management */

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

	os_memcpy(nonce + 1, hdr->addr2, ETH_ALEN);
	nonce[7] = data[7]; /* PN5 */
	nonce[8] = data[6]; /* PN4 */
	nonce[9] = data[5]; /* PN3 */
	nonce[10] = data[4]; /* PN2 */
	nonce[11] = data[1]; /* PN1 */
	nonce[12] = data[0]; /* PN0 */
}


u8 * ccmp_decrypt(const u8 *tk, const struct ieee80211_hdr *hdr,
		  const u8 *data, size_t data_len, size_t *decrypted_len)
{
	u8 aad[30], nonce[13];
	size_t aad_len;
	size_t mlen;
	u8 *plain;

	if (data_len < 8 + 8)
		return NULL;

	plain = os_malloc(data_len + AES_BLOCK_SIZE);
	if (plain == NULL)
		return NULL;

	mlen = data_len - 8 - 8;

	os_memset(aad, 0, sizeof(aad));
	ccmp_aad_nonce(hdr, data, aad, &aad_len, nonce);
	wpa_hexdump(MSG_EXCESSIVE, "CCMP AAD", aad, aad_len);
	wpa_hexdump(MSG_EXCESSIVE, "CCMP nonce", nonce, 13);

	if (aes_ccm_ad(tk, 16, nonce, 8, data + 8, mlen, aad, aad_len,
		       data + 8 + mlen, plain) < 0) {
		u16 seq_ctrl = le_to_host16(hdr->seq_ctrl);
		wpa_printf(MSG_INFO, "Invalid CCMP MIC in frame: A1=" MACSTR
			   " A2=" MACSTR " A3=" MACSTR " seq=%u frag=%u",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3),
			   WLAN_GET_SEQ_SEQ(seq_ctrl),
			   WLAN_GET_SEQ_FRAG(seq_ctrl));
		os_free(plain);
		return NULL;
	}
	wpa_hexdump(MSG_EXCESSIVE, "CCMP decrypted", plain, mlen);

	*decrypted_len = mlen;
	return plain;
}


void ccmp_get_pn(u8 *pn, const u8 *data)
{
	pn[0] = data[7]; /* PN5 */
	pn[1] = data[6]; /* PN4 */
	pn[2] = data[5]; /* PN3 */
	pn[3] = data[4]; /* PN2 */
	pn[4] = data[1]; /* PN1 */
	pn[5] = data[0]; /* PN0 */
}


u8 * ccmp_encrypt(const u8 *tk, u8 *frame, size_t len, size_t hdrlen, u8 *qos,
		  u8 *pn, int keyid, size_t *encrypted_len)
{
	u8 aad[30], nonce[13];
	size_t aad_len, plen;
	u8 *crypt, *pos;
	struct ieee80211_hdr *hdr;

	if (len < hdrlen || hdrlen < 24)
		return NULL;
	plen = len - hdrlen;

	crypt = os_malloc(hdrlen + 8 + plen + 8 + AES_BLOCK_SIZE);
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

	os_memset(aad, 0, sizeof(aad));
	ccmp_aad_nonce(hdr, crypt + hdrlen, aad, &aad_len, nonce);
	wpa_hexdump(MSG_EXCESSIVE, "CCMP AAD", aad, aad_len);
	wpa_hexdump(MSG_EXCESSIVE, "CCMP nonce", nonce, 13);

	if (aes_ccm_ae(tk, 16, nonce, 8, frame + hdrlen, plen, aad, aad_len,
		       pos, pos + plen) < 0) {
		os_free(crypt);
		return NULL;
	}

	wpa_hexdump(MSG_EXCESSIVE, "CCMP encrypted", crypt + hdrlen + 8, plen);

	*encrypted_len = hdrlen + 8 + plen + 8;

	return crypt;
}
