/*
 * EAP-FAST server (RFC 4851)
 * Copyright (c) 2004-2008, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "aes_wrap.h"
#include "sha1.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include "tls.h"
#include "eap_common/eap_tlv_common.h"
#include "eap_common/eap_fast_common.h"


static void eap_fast_reset(struct eap_sm *sm, void *priv);


/* Private PAC-Opaque TLV types */
#define PAC_OPAQUE_TYPE_PAD 0
#define PAC_OPAQUE_TYPE_KEY 1
#define PAC_OPAQUE_TYPE_LIFETIME 2

/* PAC-Key lifetime in seconds (hard limit) */
#define PAC_KEY_LIFETIME (7 * 24 * 60 * 60)

/*
 * PAC-Key refresh time in seconds (soft limit on remaining hard limit). The
 * server will generate a new PAC-Key when this number of seconds (or fewer)
 * of the lifetime.
 */
#define PAC_KEY_REFRESH_TIME (1 * 24 * 60 * 60)


struct eap_fast_data {
	struct eap_ssl_data ssl;
	enum {
		START, PHASE1, PHASE2_START, PHASE2_ID, PHASE2_METHOD,
		CRYPTO_BINDING, REQUEST_PAC, SUCCESS, FAILURE
	} state;

	int fast_version;
	const struct eap_method *phase2_method;
	void *phase2_priv;
	int force_version;
	int peer_version;

	u8 crypto_binding_nonce[32];
	int final_result;

	struct eap_fast_key_block_provisioning *key_block_p;

	u8 simck[EAP_FAST_SIMCK_LEN];
	u8 cmk[20];
	int simck_idx;

	u8 pac_opaque_encr[16];
	char *srv_id;

	int anon_provisioning;
	int send_new_pac; /* server triggered re-keying of Tunnel PAC */
	struct wpabuf *pending_phase2_resp;
};


static const char * eap_fast_state_txt(int state)
{
	switch (state) {
	case START:
		return "START";
	case PHASE1:
		return "PHASE1";
	case PHASE2_START:
		return "PHASE2_START";
	case PHASE2_ID:
		return "PHASE2_ID";
	case PHASE2_METHOD:
		return "PHASE2_METHOD";
	case CRYPTO_BINDING:
		return "CRYPTO_BINDING";
	case REQUEST_PAC:
		return "REQUEST_PAC";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "Unknown?!";
	}
}


static void eap_fast_state(struct eap_fast_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-FAST: %s -> %s",
		   eap_fast_state_txt(data->state),
		   eap_fast_state_txt(state));
	data->state = state;
}


static EapType eap_fast_req_failure(struct eap_sm *sm,
				    struct eap_fast_data *data)
{
	/* TODO: send Result TLV(FAILURE) */
	eap_fast_state(data, FAILURE);
	return EAP_TYPE_NONE;
}


static int eap_fast_session_ticket_cb(void *ctx, const u8 *ticket, size_t len,
				      const u8 *client_random,
				      const u8 *server_random,
				      u8 *master_secret)
{
	struct eap_fast_data *data = ctx;
#define TLS_RANDOM_LEN 32
#define TLS_MASTER_SECRET_LEN 48
	u8 seed[2 * TLS_RANDOM_LEN];
	const u8 *pac_opaque;
	size_t pac_opaque_len;
	u8 *buf, *pos, *end, *pac_key = NULL;
	os_time_t lifetime = 0;
	struct os_time now;

	wpa_printf(MSG_DEBUG, "EAP-FAST: SessionTicket callback");
	wpa_hexdump(MSG_DEBUG, "EAP-FAST: SessionTicket (PAC-Opaque)",
		    ticket, len);
	wpa_hexdump(MSG_DEBUG, "EAP-FAST: client_random",
		    client_random, TLS_RANDOM_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-FAST: server_random",
		    server_random, TLS_RANDOM_LEN);

	if (len < 4 || WPA_GET_BE16(ticket) != PAC_TYPE_PAC_OPAQUE) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Ignore invalid "
			   "SessionTicket");
		return 0;
	}

	pac_opaque_len = WPA_GET_BE16(ticket + 2);
	pac_opaque = ticket + 4;
	if (pac_opaque_len < 8 || pac_opaque_len % 8 ||
	    pac_opaque_len > len - 4) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Ignore invalid PAC-Opaque "
			   "(len=%lu left=%lu)",
			   (unsigned long) pac_opaque_len,
			   (unsigned long) len);
		return 0;
	}
	wpa_hexdump(MSG_DEBUG, "EAP-FAST: Received PAC-Opaque",
		    pac_opaque, pac_opaque_len);

	buf = os_malloc(pac_opaque_len - 8);
	if (buf == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Failed to allocate memory "
			   "for decrypting PAC-Opaque");
		return 0;
	}

	if (aes_unwrap(data->pac_opaque_encr, (pac_opaque_len - 8) / 8,
		       pac_opaque, buf) < 0) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Failed to decrypt "
			   "PAC-Opaque");
		os_free(buf);
		/*
		 * This may have been caused by server changing the PAC-Opaque
		 * encryption key, so just ignore this PAC-Opaque instead of
		 * failing the authentication completely. Provisioning can now
		 * be used to provision a new PAC.
		 */
		return 0;
	}

	end = buf + pac_opaque_len - 8;
	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: Decrypted PAC-Opaque",
			buf, end - buf);

	pos = buf;
	while (pos + 1 < end) {
		if (pos + 2 + pos[1] > end)
			break;

		switch (*pos) {
		case PAC_OPAQUE_TYPE_PAD:
			pos = end;
			break;
		case PAC_OPAQUE_TYPE_KEY:
			if (pos[1] != EAP_FAST_PAC_KEY_LEN) {
				wpa_printf(MSG_DEBUG, "EAP-FAST: Invalid "
					   "PAC-Key length %d", pos[1]);
				os_free(buf);
				return -1;
			}
			pac_key = pos + 2;
			wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: PAC-Key from "
					"decrypted PAC-Opaque",
					pac_key, EAP_FAST_PAC_KEY_LEN);
			break;
		case PAC_OPAQUE_TYPE_LIFETIME:
			if (pos[1] != 4) {
				wpa_printf(MSG_DEBUG, "EAP-FAST: Invalid "
					   "PAC-Key lifetime length %d",
					   pos[1]);
				os_free(buf);
				return -1;
			}
			lifetime = WPA_GET_BE32(pos + 2);
			break;
		}

		pos += 2 + pos[1];
	}

	if (pac_key == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: No PAC-Key included in "
			   "PAC-Opaque");
		os_free(buf);
		return -1;
	}

	if (os_get_time(&now) < 0 || lifetime <= 0 || now.sec > lifetime) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: PAC-Key not valid anymore "
			   "(lifetime=%ld now=%ld)", lifetime, now.sec);
		os_free(buf);
		return 0;
	}

	if (lifetime - now.sec < PAC_KEY_REFRESH_TIME)
		data->send_new_pac = 1;

	/*
	 * RFC 4851, Section 5.1:
	 * master_secret = T-PRF(PAC-Key, "PAC to master secret label hash", 
	 *                       server_random + client_random, 48)
	 */
	os_memcpy(seed, server_random, TLS_RANDOM_LEN);
	os_memcpy(seed + TLS_RANDOM_LEN, client_random, TLS_RANDOM_LEN);
	sha1_t_prf(pac_key, EAP_FAST_PAC_KEY_LEN,
		   "PAC to master secret label hash",
		   seed, sizeof(seed), master_secret, TLS_MASTER_SECRET_LEN);

	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: master_secret",
			master_secret, TLS_MASTER_SECRET_LEN);

	os_free(buf);

	return 1;
}


static u8 * eap_fast_derive_key(struct eap_sm *sm, struct eap_ssl_data *data,
				char *label, size_t len)
{
	struct tls_keys keys;
	u8 *rnd = NULL, *out;
	int block_size;

	block_size = tls_connection_get_keyblock_size(sm->ssl_ctx, data->conn);
	if (block_size < 0)
		return NULL;

	out = os_malloc(block_size + len);
	if (out == NULL)
		return NULL;

	if (tls_connection_prf(sm->ssl_ctx, data->conn, label, 1, out,
			       block_size + len) == 0) {
		os_memmove(out, out + block_size, len);
		return out;
	}

	if (tls_connection_get_keys(sm->ssl_ctx, data->conn, &keys))
		goto fail;

	rnd = os_malloc(keys.client_random_len + keys.server_random_len);
	if (rnd == NULL)
		goto fail;

	os_memcpy(rnd, keys.server_random, keys.server_random_len);
	os_memcpy(rnd + keys.server_random_len, keys.client_random,
		  keys.client_random_len);

	wpa_hexdump_key(MSG_MSGDUMP, "EAP-FAST: master_secret for key "
			"expansion", keys.master_key, keys.master_key_len);
	if (tls_prf(keys.master_key, keys.master_key_len,
		    label, rnd, keys.client_random_len +
		    keys.server_random_len, out, block_size + len))
		goto fail;
	os_free(rnd);
	os_memmove(out, out + block_size, len);
	return out;

fail:
	os_free(rnd);
	os_free(out);
	return NULL;
}


static void eap_fast_derive_key_auth(struct eap_sm *sm,
				     struct eap_fast_data *data)
{
	u8 *sks;

	/* RFC 4851, Section 5.1:
	 * Extra key material after TLS key_block: session_key_seed[40]
	 */

	sks = eap_fast_derive_key(sm, &data->ssl, "key expansion",
				  EAP_FAST_SKS_LEN);
	if (sks == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Failed to derive "
			   "session_key_seed");
		return;
	}

	/*
	 * RFC 4851, Section 5.2:
	 * S-IMCK[0] = session_key_seed
	 */
	wpa_hexdump_key(MSG_DEBUG,
			"EAP-FAST: session_key_seed (SKS = S-IMCK[0])",
			sks, EAP_FAST_SKS_LEN);
	data->simck_idx = 0;
	os_memcpy(data->simck, sks, EAP_FAST_SIMCK_LEN);
	os_free(sks);
}


static void eap_fast_derive_key_provisioning(struct eap_sm *sm,
					     struct eap_fast_data *data)
{
	os_free(data->key_block_p);
	data->key_block_p = (struct eap_fast_key_block_provisioning *)
		eap_fast_derive_key(sm, &data->ssl, "key expansion",
				    sizeof(*data->key_block_p));
	if (data->key_block_p == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Failed to derive key block");
		return;
	}
	/*
	 * RFC 4851, Section 5.2:
	 * S-IMCK[0] = session_key_seed
	 */
	wpa_hexdump_key(MSG_DEBUG,
			"EAP-FAST: session_key_seed (SKS = S-IMCK[0])",
			data->key_block_p->session_key_seed,
			sizeof(data->key_block_p->session_key_seed));
	data->simck_idx = 0;
	os_memcpy(data->simck, data->key_block_p->session_key_seed,
		  EAP_FAST_SIMCK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: server_challenge",
			data->key_block_p->server_challenge,
			sizeof(data->key_block_p->server_challenge));
	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: client_challenge",
			data->key_block_p->client_challenge,
			sizeof(data->key_block_p->client_challenge));
}


static int eap_fast_get_phase2_key(struct eap_sm *sm,
				   struct eap_fast_data *data,
				   u8 *isk, size_t isk_len)
{
	u8 *key;
	size_t key_len;

	os_memset(isk, 0, isk_len);

	if (data->phase2_method == NULL || data->phase2_priv == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Phase 2 method not "
			   "available");
		return -1;
	}

	if (data->phase2_method->getKey == NULL)
		return 0;

	if ((key = data->phase2_method->getKey(sm, data->phase2_priv,
					       &key_len)) == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Could not get key material "
			   "from Phase 2");
		return -1;
	}

	if (key_len > isk_len)
		key_len = isk_len;
	os_memcpy(isk, key, key_len);
	os_free(key);

	return 0;
}


static int eap_fast_update_icmk(struct eap_sm *sm, struct eap_fast_data *data)
{
	u8 isk[32], imck[60];

	wpa_printf(MSG_DEBUG, "EAP-FAST: Deriving ICMK[%d] (S-IMCK and CMK)",
		   data->simck_idx + 1);

	/*
	 * RFC 4851, Section 5.2:
	 * IMCK[j] = T-PRF(S-IMCK[j-1], "Inner Methods Compound Keys",
	 *                 MSK[j], 60)
	 * S-IMCK[j] = first 40 octets of IMCK[j]
	 * CMK[j] = last 20 octets of IMCK[j]
	 */

	if (eap_fast_get_phase2_key(sm, data, isk, sizeof(isk)) < 0)
		return -1;
	wpa_hexdump_key(MSG_MSGDUMP, "EAP-FAST: ISK[j]", isk, sizeof(isk));
	sha1_t_prf(data->simck, EAP_FAST_SIMCK_LEN,
		   "Inner Methods Compound Keys",
		   isk, sizeof(isk), imck, sizeof(imck));
	data->simck_idx++;
	os_memcpy(data->simck, imck, EAP_FAST_SIMCK_LEN);
	wpa_hexdump_key(MSG_MSGDUMP, "EAP-FAST: S-IMCK[j]",
			data->simck, EAP_FAST_SIMCK_LEN);
	os_memcpy(data->cmk, imck + EAP_FAST_SIMCK_LEN, 20);
	wpa_hexdump_key(MSG_MSGDUMP, "EAP-FAST: CMK[j]", data->cmk, 20);

	return 0;
}


static void * eap_fast_init(struct eap_sm *sm)
{
	struct eap_fast_data *data;
	u8 ciphers[5] = {
		TLS_CIPHER_ANON_DH_AES128_SHA,
		TLS_CIPHER_AES128_SHA,
		TLS_CIPHER_RSA_DHE_AES128_SHA,
		TLS_CIPHER_RC4_SHA,
		TLS_CIPHER_NONE
	};

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->fast_version = EAP_FAST_VERSION;
	data->force_version = -1;
	if (sm->user && sm->user->force_version >= 0) {
		data->force_version = sm->user->force_version;
		wpa_printf(MSG_DEBUG, "EAP-FAST: forcing version %d",
			   data->force_version);
		data->fast_version = data->force_version;
	}
	data->state = START;

	if (eap_server_tls_ssl_init(sm, &data->ssl, 0)) {
		wpa_printf(MSG_INFO, "EAP-FAST: Failed to initialize SSL.");
		eap_fast_reset(sm, data);
		return NULL;
	}

	if (tls_connection_set_cipher_list(sm->ssl_ctx, data->ssl.conn,
					   ciphers) < 0) {
		wpa_printf(MSG_INFO, "EAP-FAST: Failed to set TLS cipher "
			   "suites");
		eap_fast_reset(sm, data);
		return NULL;
	}

	if (tls_connection_set_session_ticket_cb(sm->ssl_ctx, data->ssl.conn,
						 eap_fast_session_ticket_cb,
						 data) < 0) {
		wpa_printf(MSG_INFO, "EAP-FAST: Failed to set SessionTicket "
			   "callback");
		eap_fast_reset(sm, data);
		return NULL;
	}

	if (sm->pac_opaque_encr_key == NULL) {
		wpa_printf(MSG_INFO, "EAP-FAST: No PAC-Opaque encryption key "
			   "configured");
		eap_fast_reset(sm, data);
		return NULL;
	}
	os_memcpy(data->pac_opaque_encr, sm->pac_opaque_encr_key,
		  sizeof(data->pac_opaque_encr));

	if (sm->eap_fast_a_id == NULL) {
		wpa_printf(MSG_INFO, "EAP-FAST: No A-ID configured");
		eap_fast_reset(sm, data);
		return NULL;
	}
	data->srv_id = os_strdup(sm->eap_fast_a_id);
	if (data->srv_id == NULL) {
		eap_fast_reset(sm, data);
		return NULL;
	}

	return data;
}


static void eap_fast_reset(struct eap_sm *sm, void *priv)
{
	struct eap_fast_data *data = priv;
	if (data == NULL)
		return;
	if (data->phase2_priv && data->phase2_method)
		data->phase2_method->reset(sm, data->phase2_priv);
	eap_server_tls_ssl_deinit(sm, &data->ssl);
	os_free(data->srv_id);
	os_free(data->key_block_p);
	wpabuf_free(data->pending_phase2_resp);
	os_free(data);
}


static struct wpabuf * eap_fast_build_start(struct eap_sm *sm,
					    struct eap_fast_data *data, u8 id)
{
	struct wpabuf *req;
	struct pac_tlv_hdr *a_id;
	size_t srv_id_len = os_strlen(data->srv_id);

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_FAST,
			    1 + sizeof(*a_id) + srv_id_len,
			    EAP_CODE_REQUEST, id);
	if (req == NULL) {
		wpa_printf(MSG_ERROR, "EAP-FAST: Failed to allocate memory for"
			   " request");
		eap_fast_state(data, FAILURE);
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TLS_FLAGS_START | data->fast_version);
	a_id = wpabuf_put(req, sizeof(*a_id));
	a_id->type = host_to_be16(PAC_TYPE_A_ID);
	a_id->len = host_to_be16(srv_id_len);
	wpabuf_put_data(req, data->srv_id, srv_id_len);

	eap_fast_state(data, PHASE1);

	return req;
}


static int eap_fast_phase1_done(struct eap_sm *sm, struct eap_fast_data *data)
{
	char cipher[64];

	wpa_printf(MSG_DEBUG, "EAP-FAST: Phase1 done, starting Phase2");

	if (tls_get_cipher(sm->ssl_ctx, data->ssl.conn, cipher, sizeof(cipher))
	    < 0) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Failed to get cipher "
			   "information");
		eap_fast_state(data, FAILURE);
		return -1;
	}
	data->anon_provisioning = os_strstr(cipher, "ADH") != NULL;
		    
	if (data->anon_provisioning) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Anonymous provisioning");
		eap_fast_derive_key_provisioning(sm, data);
	} else
		eap_fast_derive_key_auth(sm, data);

	eap_fast_state(data, PHASE2_START);

	return 0;
}


static struct wpabuf * eap_fast_build_req(struct eap_sm *sm,
					  struct eap_fast_data *data, u8 id)
{
	int res;
	struct wpabuf *req;

	res = eap_server_tls_buildReq_helper(sm, &data->ssl, EAP_TYPE_FAST,
					     data->fast_version, id, &req);

	if (tls_connection_established(sm->ssl_ctx, data->ssl.conn)) {
		if (eap_fast_phase1_done(sm, data) < 0) {
			os_free(req);
			return NULL;
		}
	}

	if (res == 1)
		return eap_server_tls_build_ack(id, EAP_TYPE_FAST,
						data->fast_version);
	return req;
}


static struct wpabuf * eap_fast_encrypt(struct eap_sm *sm,
					struct eap_fast_data *data,
					u8 id, u8 *plain, size_t plain_len)
{
	int res;
	struct wpabuf *buf;

	/* TODO: add support for fragmentation, if needed. This will need to
	 * add TLS Message Length field, if the frame is fragmented. */
	buf = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_FAST,
			    1 + data->ssl.tls_out_limit,
			    EAP_CODE_REQUEST, id);
	if (buf == NULL)
		return NULL;

	wpabuf_put_u8(buf, data->fast_version);

	res = tls_connection_encrypt(sm->ssl_ctx, data->ssl.conn,
				     plain, plain_len, wpabuf_put(buf, 0),
				     data->ssl.tls_out_limit);
	if (res < 0) {
		wpa_printf(MSG_INFO, "EAP-FAST: Failed to encrypt Phase 2 "
			   "data");
		wpabuf_free(buf);
		return NULL;
	}

	wpabuf_put(buf, res);
	eap_update_len(buf);

	return buf;
}


static struct wpabuf * eap_fast_tlv_eap_payload(struct wpabuf *buf)
{
	struct wpabuf *e;
	struct eap_tlv_hdr *tlv;

	if (buf == NULL)
		return NULL;

	/* Encapsulate EAP packet in EAP-Payload TLV */
	wpa_printf(MSG_DEBUG, "EAP-FAST: Add EAP-Payload TLV");
	e = wpabuf_alloc(sizeof(*tlv) + wpabuf_len(buf));
	if (e == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Failed to allocate memory "
			   "for TLV encapsulation");
		wpabuf_free(buf);
		return NULL;
	}
	tlv = wpabuf_put(e, sizeof(*tlv));
	tlv->tlv_type = host_to_be16(EAP_TLV_TYPE_MANDATORY |
				     EAP_TLV_EAP_PAYLOAD_TLV);
	tlv->length = host_to_be16(wpabuf_len(buf));
	wpabuf_put_buf(e, buf);
	wpabuf_free(buf);
	return e;
}


static struct wpabuf * eap_fast_build_phase2_req(struct eap_sm *sm,
						 struct eap_fast_data *data,
						 u8 id)
{
	struct wpabuf *req;

	if (data->phase2_priv == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Phase 2 method not "
			   "initialized");
		return NULL;
	}
	req = data->phase2_method->buildReq(sm, data->phase2_priv, id);
	if (req == NULL)
		return NULL;

	wpa_hexdump_buf_key(MSG_MSGDUMP, "EAP-FAST: Phase 2 EAP-Request", req);
	return eap_fast_tlv_eap_payload(req);
}


static struct wpabuf * eap_fast_build_crypto_binding(
	struct eap_sm *sm, struct eap_fast_data *data)
{
	struct wpabuf *buf;
	struct eap_tlv_result_tlv *result;
	struct eap_tlv_crypto_binding__tlv *binding;
	int type;

	buf = wpabuf_alloc(sizeof(*result) + sizeof(*binding));
	if (buf == NULL)
		return NULL;

	if (data->send_new_pac || data->anon_provisioning) {
		type = EAP_TLV_INTERMEDIATE_RESULT_TLV;
		data->final_result = 0;
	} else {
		type = EAP_TLV_RESULT_TLV;
		data->final_result = 1;
	}

	/* Result TLV */
	wpa_printf(MSG_DEBUG, "EAP-FAST: Add Result TLV (status=SUCCESS)");
	result = wpabuf_put(buf, sizeof(*result));
	result->tlv_type = host_to_be16(EAP_TLV_TYPE_MANDATORY | type);
	result->length = host_to_be16(2);
	result->status = host_to_be16(EAP_TLV_RESULT_SUCCESS);

	/* Crypto-Binding TLV */
	binding = wpabuf_put(buf, sizeof(*binding));
	binding->tlv_type = host_to_be16(EAP_TLV_TYPE_MANDATORY |
					 EAP_TLV_CRYPTO_BINDING_TLV);
	binding->length = host_to_be16(sizeof(*binding) -
				       sizeof(struct eap_tlv_hdr));
	binding->version = EAP_FAST_VERSION;
	binding->received_version = data->peer_version;
	binding->subtype = EAP_TLV_CRYPTO_BINDING_SUBTYPE_REQUEST;
	if (os_get_random(binding->nonce, sizeof(binding->nonce)) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	/*
	 * RFC 4851, Section 4.2.8:
	 * The nonce in a request MUST have its least significant bit set to 0.
	 */
	binding->nonce[sizeof(binding->nonce) - 1] &= ~0x01;

	os_memcpy(data->crypto_binding_nonce, binding->nonce,
		  sizeof(binding->nonce));

	/*
	 * RFC 4851, Section 5.3:
	 * CMK = CMK[j]
	 * Compound-MAC = HMAC-SHA1( CMK, Crypto-Binding TLV )
	 */

	hmac_sha1(data->cmk, 20, (u8 *) binding, sizeof(*binding),
		  binding->compound_mac);

	wpa_printf(MSG_DEBUG, "EAP-FAST: Add Crypto-Binding TLV: Version %d "
		   "Received Version %d SubType %d",
		   binding->version, binding->received_version,
		   binding->subtype);
	wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: NONCE",
		    binding->nonce, sizeof(binding->nonce));
	wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: Compound MAC",
		    binding->compound_mac, sizeof(binding->compound_mac));

	return buf;
}


static struct wpabuf * eap_fast_build_pac(struct eap_sm *sm,
					  struct eap_fast_data *data)
{
	u8 pac_key[2 + EAP_FAST_PAC_KEY_LEN + 6];
	u8 pac_opaque[8 + EAP_FAST_PAC_KEY_LEN + 8];
	struct wpabuf *buf;
	u8 *pos;
	size_t buf_len, srv_id_len;
	struct eap_tlv_hdr *pac_tlv;
	struct pac_tlv_hdr *hdr, *pac_info;
	struct eap_tlv_result_tlv *result;
	struct os_time now;

	srv_id_len = os_strlen(data->srv_id);

	pac_key[0] = PAC_OPAQUE_TYPE_KEY;
	pac_key[1] = EAP_FAST_PAC_KEY_LEN;
	if (os_get_random(pac_key + 2, EAP_FAST_PAC_KEY_LEN) < 0)
		return NULL;
	if (os_get_time(&now) < 0)
		return NULL;
	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: Generated PAC-Key",
			pac_key + 2, EAP_FAST_PAC_KEY_LEN);
	pos = pac_key + 2 + EAP_FAST_PAC_KEY_LEN;
	*pos++ = PAC_OPAQUE_TYPE_LIFETIME;
	*pos++ = 4;
	WPA_PUT_BE32(pos, now.sec + PAC_KEY_LIFETIME);

	if (aes_wrap(data->pac_opaque_encr, sizeof(pac_key) / 8, pac_key,
		     pac_opaque) < 0)
		return NULL;

	wpa_hexdump(MSG_DEBUG, "EAP-FAST: PAC-Opaque",
		    pac_opaque, sizeof(pac_opaque));

	buf_len = sizeof(*pac_tlv) +
		sizeof(*hdr) + EAP_FAST_PAC_KEY_LEN +
		sizeof(*hdr) + sizeof(pac_opaque) +
		2 * srv_id_len + 100 + sizeof(*result);
	buf = wpabuf_alloc(buf_len);
	if (buf == NULL)
		return NULL;

	/* PAC TLV */
	wpa_printf(MSG_DEBUG, "EAP-FAST: Add PAC TLV");
	pac_tlv = wpabuf_put(buf, sizeof(*pac_tlv));
	pac_tlv->tlv_type = host_to_be16(EAP_TLV_TYPE_MANDATORY |
					 EAP_TLV_PAC_TLV);

	/* PAC-Key */
	hdr = wpabuf_put(buf, sizeof(*hdr));
	hdr->type = host_to_be16(PAC_TYPE_PAC_KEY);
	hdr->len = host_to_be16(EAP_FAST_PAC_KEY_LEN);
	wpabuf_put_data(buf, pac_key + 2, EAP_FAST_PAC_KEY_LEN);

	/* PAC-Opaque */
	hdr = wpabuf_put(buf, sizeof(*hdr));
	hdr->type = host_to_be16(PAC_TYPE_PAC_OPAQUE);
	hdr->len = host_to_be16(sizeof(pac_opaque));
	wpabuf_put_data(buf, pac_opaque, sizeof(pac_opaque));

	/* PAC-Info */
	pac_info = wpabuf_put(buf, sizeof(*pac_info));
	pac_info->type = host_to_be16(PAC_TYPE_PAC_INFO);

	/* PAC-Lifetime (inside PAC-Info) */
	hdr = wpabuf_put(buf, sizeof(*hdr));
	hdr->type = host_to_be16(PAC_TYPE_CRED_LIFETIME);
	hdr->len = host_to_be16(4);
	wpabuf_put_be32(buf, now.sec + PAC_KEY_LIFETIME);

	/* A-ID (inside PAC-Info) */
	hdr = wpabuf_put(buf, sizeof(*hdr));
	hdr->type = host_to_be16(PAC_TYPE_A_ID);
	hdr->len = host_to_be16(srv_id_len);
	wpabuf_put_data(buf, data->srv_id, srv_id_len);
	
	/* Note: headers may be misaligned after A-ID */

	/* A-ID-Info (inside PAC-Info) */
	hdr = wpabuf_put(buf, sizeof(*hdr));
	WPA_PUT_BE16((u8 *) &hdr->type, PAC_TYPE_A_ID_INFO);
	WPA_PUT_BE16((u8 *) &hdr->len, srv_id_len);
	wpabuf_put_data(buf, data->srv_id, srv_id_len);

	/* PAC-Type (inside PAC-Info) */
	hdr = wpabuf_put(buf, sizeof(*hdr));
	WPA_PUT_BE16((u8 *) &hdr->type, PAC_TYPE_PAC_TYPE);
	WPA_PUT_BE16((u8 *) &hdr->len, 2);
	wpabuf_put_be16(buf, PAC_TYPE_TUNNEL_PAC);

	/* Update PAC-Info and PAC TLV Length fields */
	pos = wpabuf_put(buf, 0);
	pac_info->len = host_to_be16(pos - (u8 *) (pac_info + 1));
	pac_tlv->length = host_to_be16(pos - (u8 *) (pac_tlv + 1));

	/* Result TLV */
	wpa_printf(MSG_DEBUG, "EAP-FAST: Add Result TLV (status=SUCCESS)");
	result = wpabuf_put(buf, sizeof(*result));
	WPA_PUT_BE16((u8 *) &result->tlv_type,
		     EAP_TLV_TYPE_MANDATORY | EAP_TLV_RESULT_TLV);
	WPA_PUT_BE16((u8 *) &result->length, 2);
	WPA_PUT_BE16((u8 *) &result->status, EAP_TLV_RESULT_SUCCESS);

	return buf;
}


static struct wpabuf * eap_fast_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_fast_data *data = priv;
	struct wpabuf *req;
	struct wpabuf *encr;

	if (data->state == START)
		return eap_fast_build_start(sm, data, id);

	if (data->state == PHASE1)
		return eap_fast_build_req(sm, data, id);

	switch (data->state) {
	case PHASE2_ID:
	case PHASE2_METHOD:
		req = eap_fast_build_phase2_req(sm, data, id);
		break;
	case CRYPTO_BINDING:
		req = eap_fast_build_crypto_binding(sm, data);
		break;
	case REQUEST_PAC:
		req = eap_fast_build_pac(sm, data);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-FAST: %s - unexpected state %d",
			   __func__, data->state);
		return NULL;
	}

	if (req == NULL)
		return NULL;

	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-FAST: Encrypting Phase 2 TLVs",
			    req);
	encr = eap_fast_encrypt(sm, data, id, wpabuf_mhead(req),
				wpabuf_len(req));
	wpabuf_free(req);

	return encr;
}


static Boolean eap_fast_check(struct eap_sm *sm, void *priv,
			      struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_FAST, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-FAST: Invalid frame");
		return TRUE;
	}

	return FALSE;
}


static int eap_fast_phase2_init(struct eap_sm *sm, struct eap_fast_data *data,
				EapType eap_type)
{
	if (data->phase2_priv && data->phase2_method) {
		data->phase2_method->reset(sm, data->phase2_priv);
		data->phase2_method = NULL;
		data->phase2_priv = NULL;
	}
	data->phase2_method = eap_server_get_eap_method(EAP_VENDOR_IETF,
							eap_type);
	if (!data->phase2_method)
		return -1;

	if (data->key_block_p) {
		sm->auth_challenge = data->key_block_p->server_challenge;
		sm->peer_challenge = data->key_block_p->client_challenge;
	}
	sm->init_phase2 = 1;
	data->phase2_priv = data->phase2_method->init(sm);
	sm->init_phase2 = 0;
	sm->auth_challenge = NULL;
	sm->peer_challenge = NULL;

	return data->phase2_priv == NULL ? -1 : 0;
}


static void eap_fast_process_phase2_response(struct eap_sm *sm,
					     struct eap_fast_data *data,
					     u8 *in_data, size_t in_len)
{
	u8 next_type = EAP_TYPE_NONE;
	struct eap_hdr *hdr;
	u8 *pos;
	size_t left;
	struct wpabuf buf;
	const struct eap_method *m = data->phase2_method;
	void *priv = data->phase2_priv;

	if (priv == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: %s - Phase2 not "
			   "initialized?!", __func__);
		return;
	}

	hdr = (struct eap_hdr *) in_data;
	pos = (u8 *) (hdr + 1);

	if (in_len > sizeof(*hdr) && *pos == EAP_TYPE_NAK) {
		left = in_len - sizeof(*hdr);
		wpa_hexdump(MSG_DEBUG, "EAP-FAST: Phase2 type Nak'ed; "
			    "allowed types", pos + 1, left - 1);
		eap_sm_process_nak(sm, pos + 1, left - 1);
		if (sm->user && sm->user_eap_method_index < EAP_MAX_METHODS &&
		    sm->user->methods[sm->user_eap_method_index].method !=
		    EAP_TYPE_NONE) {
			next_type = sm->user->methods[
				sm->user_eap_method_index++].method;
			wpa_printf(MSG_DEBUG, "EAP-FAST: try EAP type %d",
				   next_type);
		} else {
			next_type = eap_fast_req_failure(sm, data);
		}
		eap_fast_phase2_init(sm, data, next_type);
		return;
	}

	wpabuf_set(&buf, in_data, in_len);

	if (m->check(sm, priv, &buf)) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Phase2 check() asked to "
			   "ignore the packet");
		next_type = eap_fast_req_failure(sm, data);
		return;
	}

	m->process(sm, priv, &buf);

	if (!m->isDone(sm, priv))
		return;

	if (!m->isSuccess(sm, priv)) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Phase2 method failed");
		next_type = eap_fast_req_failure(sm, data);
		eap_fast_phase2_init(sm, data, next_type);
		return;
	}

	switch (data->state) {
	case PHASE2_ID:
		if (eap_user_get(sm, sm->identity, sm->identity_len, 1) != 0) {
			wpa_hexdump_ascii(MSG_DEBUG, "EAP-FAST: Phase2 "
					  "Identity not found in the user "
					  "database",
					  sm->identity, sm->identity_len);
			next_type = eap_fast_req_failure(sm, data);
			break;
		}

		eap_fast_state(data, PHASE2_METHOD);
		if (data->anon_provisioning) {
			/*
			 * Only EAP-MSCHAPv2 is allowed for anonymous
			 * provisioning.
			 */
			next_type = EAP_TYPE_MSCHAPV2;
			sm->user_eap_method_index = 0;
		} else {
			next_type = sm->user->methods[0].method;
			sm->user_eap_method_index = 1;
		}
		wpa_printf(MSG_DEBUG, "EAP-FAST: try EAP type %d", next_type);
		break;
	case PHASE2_METHOD:
		eap_fast_update_icmk(sm, data);
		eap_fast_state(data, CRYPTO_BINDING);
		next_type = EAP_TYPE_NONE;
		break;
	case FAILURE:
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-FAST: %s - unexpected state %d",
			   __func__, data->state);
		break;
	}

	eap_fast_phase2_init(sm, data, next_type);
}


static void eap_fast_process_phase2_eap(struct eap_sm *sm,
					struct eap_fast_data *data,
					u8 *in_data, size_t in_len)
{
	struct eap_hdr *hdr;
	size_t len;

	hdr = (struct eap_hdr *) in_data;
	if (in_len < (int) sizeof(*hdr)) {
		wpa_printf(MSG_INFO, "EAP-FAST: Too short Phase 2 "
			   "EAP frame (len=%d)", in_len);
		eap_fast_req_failure(sm, data);
		return;
	}
	len = be_to_host16(hdr->length);
	if (len > in_len) {
		wpa_printf(MSG_INFO, "EAP-FAST: Length mismatch in "
			   "Phase 2 EAP frame (len=%d hdr->length=%d)",
			   in_len, len);
		eap_fast_req_failure(sm, data);
		return;
	}
	wpa_printf(MSG_DEBUG, "EAP-FAST: Received Phase 2: code=%d "
		   "identifier=%d length=%d", hdr->code, hdr->identifier, len);
	switch (hdr->code) {
	case EAP_CODE_RESPONSE:
		eap_fast_process_phase2_response(sm, data, (u8 *) hdr, len);
		break;
	default:
		wpa_printf(MSG_INFO, "EAP-FAST: Unexpected code=%d in "
			   "Phase 2 EAP header", hdr->code);
		break;
	}
}


struct eap_fast_tlv_parse {
	u8 *eap_payload_tlv;
	size_t eap_payload_tlv_len;
	struct eap_tlv_crypto_binding__tlv *crypto_binding;
	size_t crypto_binding_len;
	int iresult;
	int result;
	int request_action;
	u8 *pac;
	size_t pac_len;
};


static int eap_fast_parse_tlv(struct eap_fast_tlv_parse *tlv,
			      int tlv_type, u8 *pos, int len)
{
	switch (tlv_type) {
	case EAP_TLV_EAP_PAYLOAD_TLV:
		wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: EAP-Payload TLV",
			    pos, len);
		if (tlv->eap_payload_tlv) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: More than one "
				   "EAP-Payload TLV in the message");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			return -2;
		}
		tlv->eap_payload_tlv = pos;
		tlv->eap_payload_tlv_len = len;
		break;
	case EAP_TLV_RESULT_TLV:
		wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: Result TLV", pos, len);
		if (tlv->result) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: More than one "
				   "Result TLV in the message");
			tlv->result = EAP_TLV_RESULT_FAILURE;
			return -2;
		}
		if (len < 2) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Too short "
				   "Result TLV");
			tlv->result = EAP_TLV_RESULT_FAILURE;
			break;
		}
		tlv->result = WPA_GET_BE16(pos);
		if (tlv->result != EAP_TLV_RESULT_SUCCESS &&
		    tlv->result != EAP_TLV_RESULT_FAILURE) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Unknown Result %d",
				   tlv->result);
			tlv->result = EAP_TLV_RESULT_FAILURE;
		}
		wpa_printf(MSG_DEBUG, "EAP-FAST: Result: %s",
			   tlv->result == EAP_TLV_RESULT_SUCCESS ?
			   "Success" : "Failure");
		break;
	case EAP_TLV_INTERMEDIATE_RESULT_TLV:
		wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: Intermediate Result TLV",
			    pos, len);
		if (len < 2) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Too short "
				   "Intermediate-Result TLV");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			break;
		}
		if (tlv->iresult) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: More than one "
				   "Intermediate-Result TLV in the message");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			return -2;
		}
		tlv->iresult = WPA_GET_BE16(pos);
		if (tlv->iresult != EAP_TLV_RESULT_SUCCESS &&
		    tlv->iresult != EAP_TLV_RESULT_FAILURE) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Unknown Intermediate "
				   "Result %d", tlv->iresult);
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
		}
		wpa_printf(MSG_DEBUG, "EAP-FAST: Intermediate Result: %s",
			   tlv->iresult == EAP_TLV_RESULT_SUCCESS ?
			   "Success" : "Failure");
		break;
	case EAP_TLV_CRYPTO_BINDING_TLV:
		wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: Crypto-Binding TLV",
			    pos, len);
		if (tlv->crypto_binding) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: More than one "
				   "Crypto-Binding TLV in the message");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			return -2;
		}
		tlv->crypto_binding_len = sizeof(struct eap_tlv_hdr) + len;
		if (tlv->crypto_binding_len < sizeof(*tlv->crypto_binding)) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Too short "
				   "Crypto-Binding TLV");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			return -2;
		}
		tlv->crypto_binding = (struct eap_tlv_crypto_binding__tlv *)
			(pos - sizeof(struct eap_tlv_hdr));
		break;
	case EAP_TLV_REQUEST_ACTION_TLV:
		wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: Request-Action TLV",
			    pos, len);
		if (tlv->request_action) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: More than one "
				   "Request-Action TLV in the message");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			return -2;
		}
		if (len < 2) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Too short "
				   "Request-Action TLV");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			break;
		}
		tlv->request_action = WPA_GET_BE16(pos);
		wpa_printf(MSG_DEBUG, "EAP-FAST: Request-Action: %d",
			   tlv->request_action);
		break;
	case EAP_TLV_PAC_TLV:
		wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: PAC TLV", pos, len);
		if (tlv->pac) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: More than one "
				   "PAC TLV in the message");
			tlv->iresult = EAP_TLV_RESULT_FAILURE;
			return -2;
		}
		tlv->pac = pos;
		tlv->pac_len = len;
		break;
	default:
		/* Unknown TLV */
		return -1;
	}

	return 0;
}


static int eap_fast_parse_tlvs(u8 *data, size_t data_len,
			       struct eap_fast_tlv_parse *tlv)
{
	int mandatory, tlv_type, len, res;
	u8 *pos, *end;

	os_memset(tlv, 0, sizeof(*tlv));

	pos = data;
	end = data + data_len;
	while (pos + 4 < end) {
		mandatory = pos[0] & 0x80;
		tlv_type = WPA_GET_BE16(pos) & 0x3fff;
		pos += 2;
		len = WPA_GET_BE16(pos);
		pos += 2;
		if (pos + len > end) {
			wpa_printf(MSG_INFO, "EAP-FAST: TLV overflow");
			return -1;
		}
		wpa_printf(MSG_DEBUG, "EAP-FAST: Received Phase 2: "
			   "TLV type %d length %d%s",
			   tlv_type, len, mandatory ? " (mandatory)" : "");

		res = eap_fast_parse_tlv(tlv, tlv_type, pos, len);
		if (res == -2)
			break;
		if (res < 0) {
			if (mandatory) {
				wpa_printf(MSG_DEBUG, "EAP-FAST: Nak unknown "
					   "mandatory TLV type %d", tlv_type);
				/* TODO: generate Nak TLV */
				break;
			} else {
				wpa_printf(MSG_DEBUG, "EAP-FAST: Ignored "
					   "unknown optional TLV type %d",
					   tlv_type);
			}
		}

		pos += len;
	}

	return 0;
}


static int eap_fast_validate_crypto_binding(
	struct eap_fast_data *data, struct eap_tlv_crypto_binding__tlv *b,
	size_t bind_len)
{
	u8 cmac[20];

	wpa_printf(MSG_DEBUG, "EAP-FAST: Reply Crypto-Binding TLV: "
		   "Version %d Received Version %d SubType %d",
		   b->version, b->received_version, b->subtype);
	wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: NONCE",
		    b->nonce, sizeof(b->nonce));
	wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: Compound MAC",
		    b->compound_mac, sizeof(b->compound_mac));

	if (b->version != EAP_FAST_VERSION ||
	    b->received_version != EAP_FAST_VERSION) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Unexpected version "
			   "in Crypto-Binding: version %d "
			   "received_version %d", b->version,
			   b->received_version);
		return -1;
	}

	if (b->subtype != EAP_TLV_CRYPTO_BINDING_SUBTYPE_RESPONSE) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Unexpected subtype in "
			   "Crypto-Binding: %d", b->subtype);
		return -1;
	}

	if (os_memcmp(data->crypto_binding_nonce, b->nonce, 31) != 0 ||
	    (data->crypto_binding_nonce[31] | 1) != b->nonce[31]) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Invalid nonce in "
			   "Crypto-Binding");
		return -1;
	}

	os_memcpy(cmac, b->compound_mac, sizeof(cmac));
	os_memset(b->compound_mac, 0, sizeof(cmac));
	wpa_hexdump(MSG_MSGDUMP, "EAP-FAST: Crypto-Binding TLV for "
		    "Compound MAC calculation",
		    (u8 *) b, bind_len);
	hmac_sha1(data->cmk, 20, (u8 *) b, bind_len, b->compound_mac);
	if (os_memcmp(cmac, b->compound_mac, sizeof(cmac)) != 0) {
		wpa_hexdump(MSG_MSGDUMP,
			    "EAP-FAST: Calculated Compound MAC",
			    b->compound_mac, sizeof(cmac));
		wpa_printf(MSG_INFO, "EAP-FAST: Compound MAC did not "
			   "match");
		return -1;
	}

	return 0;
}


static int eap_fast_pac_type(u8 *pac, size_t len, u16 type)
{
	struct eap_tlv_pac_type_tlv *tlv;

	if (pac == NULL || len != sizeof(*tlv))
		return 0;

	tlv = (struct eap_tlv_pac_type_tlv *) pac;

	return be_to_host16(tlv->tlv_type) == PAC_TYPE_PAC_TYPE &&
		be_to_host16(tlv->length) == 2 &&
		be_to_host16(tlv->pac_type) == type;
}


static void eap_fast_process_phase2_tlvs(struct eap_sm *sm,
					 struct eap_fast_data *data,
					 u8 *in_data, size_t in_len)
{
	struct eap_fast_tlv_parse tlv;
	int check_crypto_binding = data->state == CRYPTO_BINDING;

	if (eap_fast_parse_tlvs(in_data, in_len, &tlv) < 0) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Failed to parse received "
			   "Phase 2 TLVs");
		return;
	}

	if (tlv.result == EAP_TLV_RESULT_FAILURE) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Result TLV indicated "
			   "failure");
		eap_fast_state(data, FAILURE);
		return;
	}

	if (data->state == REQUEST_PAC) {
		u16 type, len, res;
		if (tlv.pac == NULL || tlv.pac_len < 6) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: No PAC "
				   "Acknowledgement received");
			eap_fast_state(data, FAILURE);
			return;
		}

		type = WPA_GET_BE16(tlv.pac);
		len = WPA_GET_BE16(tlv.pac + 2);
		res = WPA_GET_BE16(tlv.pac + 4);

		if (type != PAC_TYPE_PAC_ACKNOWLEDGEMENT || len != 2 ||
		    res != EAP_TLV_RESULT_SUCCESS) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: PAC TLV did not "
				   "contain acknowledgement");
			eap_fast_state(data, FAILURE);
			return;
		}

		wpa_printf(MSG_DEBUG, "EAP-FAST: PAC-Acknowledgement received "
			   "- PAC provisioning succeeded");
		eap_fast_state(data, data->anon_provisioning ?
			       FAILURE : SUCCESS);
		return;
	}

	if (tlv.eap_payload_tlv) {
		eap_fast_process_phase2_eap(sm, data, tlv.eap_payload_tlv,
					    tlv.eap_payload_tlv_len);
	}

	if (check_crypto_binding) {
		if (tlv.crypto_binding == NULL) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: No Crypto-Binding "
				   "TLV received");
			eap_fast_state(data, FAILURE);
			return;
		}

		if (data->final_result &&
		    tlv.result != EAP_TLV_RESULT_SUCCESS) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Crypto-Binding TLV "
				   "without Success Result");
			eap_fast_state(data, FAILURE);
			return;
		}

		if (!data->final_result &&
		    tlv.iresult != EAP_TLV_RESULT_SUCCESS) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Crypto-Binding TLV "
				   "without intermediate Success Result");
			eap_fast_state(data, FAILURE);
			return;
		}

		if (eap_fast_validate_crypto_binding(data, tlv.crypto_binding,
						     tlv.crypto_binding_len)) {
			eap_fast_state(data, FAILURE);
			return;
		}

		wpa_printf(MSG_DEBUG, "EAP-FAST: Valid Crypto-Binding TLV "
			   "received - authentication completed successfully");

		if (data->anon_provisioning ||
		    (tlv.request_action == EAP_TLV_ACTION_PROCESS_TLV &&
		     eap_fast_pac_type(tlv.pac, tlv.pac_len,
				       PAC_TYPE_TUNNEL_PAC))) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Requested a new "
				   "Tunnel PAC");
			eap_fast_state(data, REQUEST_PAC);
		} else if (data->send_new_pac) {
			wpa_printf(MSG_DEBUG, "EAP-FAST: Server triggered "
				   "re-keying of Tunnel PAC");
			eap_fast_state(data, REQUEST_PAC);
		} else
			eap_fast_state(data, SUCCESS);
	}
}


static void eap_fast_process_phase2(struct eap_sm *sm,
				    struct eap_fast_data *data,
				    const u8 *in_data, size_t in_len)
{
	u8 *in_decrypted;
	int len_decrypted, res;
	size_t buf_len;

	wpa_printf(MSG_DEBUG, "EAP-FAST: Received %lu bytes encrypted data for"
		   " Phase 2", (unsigned long) in_len);

	if (data->pending_phase2_resp) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Pending Phase 2 response - "
			   "skip decryption and use old data");
		eap_fast_process_phase2_tlvs(
			sm, data, wpabuf_mhead(data->pending_phase2_resp),
			wpabuf_len(data->pending_phase2_resp));
		wpabuf_free(data->pending_phase2_resp);
		data->pending_phase2_resp = NULL;
		return;
	}

	/* FIX: get rid of const -> non-const typecast */
	res = eap_server_tls_data_reassemble(sm, &data->ssl, (u8 **) &in_data,
					     &in_len);
	if (res < 0 || res == 1)
		return;

	buf_len = in_len;
	if (data->ssl.tls_in_total > buf_len)
		buf_len = data->ssl.tls_in_total;
	in_decrypted = os_malloc(buf_len);
	if (in_decrypted == NULL) {
		os_free(data->ssl.tls_in);
		data->ssl.tls_in = NULL;
		data->ssl.tls_in_len = 0;
		wpa_printf(MSG_WARNING, "EAP-FAST: Failed to allocate memory "
			   "for decryption");
		return;
	}

	len_decrypted = tls_connection_decrypt(sm->ssl_ctx, data->ssl.conn,
					       in_data, in_len,
					       in_decrypted, buf_len);
	os_free(data->ssl.tls_in);
	data->ssl.tls_in = NULL;
	data->ssl.tls_in_len = 0;
	if (len_decrypted < 0) {
		wpa_printf(MSG_INFO, "EAP-FAST: Failed to decrypt Phase 2 "
			   "data");
		os_free(in_decrypted);
		eap_fast_state(data, FAILURE);
		return;
	}

	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: Decrypted Phase 2 TLVs",
			in_decrypted, len_decrypted);

	eap_fast_process_phase2_tlvs(sm, data, in_decrypted, len_decrypted);

	if (sm->method_pending == METHOD_PENDING_WAIT) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: Phase2 method is in "
			   "pending wait state - save decrypted response");
		wpabuf_free(data->pending_phase2_resp);
		data->pending_phase2_resp = wpabuf_alloc_copy(in_decrypted,
							      len_decrypted);
	}

	os_free(in_decrypted);
}


static void eap_fast_process(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	struct eap_fast_data *data = priv;
	const u8 *pos;
	u8 flags;
	size_t left;
	unsigned int tls_msg_len;
	int peer_version;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_FAST, respData,
			       &left);
	if (pos == NULL || left < 1)
		return;
	flags = *pos++;
	left--;
	wpa_printf(MSG_DEBUG, "EAP-FAST: Received packet(len=%lu) - "
		   "Flags 0x%02x", (unsigned long) wpabuf_len(respData),
		   flags);
	data->peer_version = peer_version = flags & EAP_PEAP_VERSION_MASK;
	if (data->force_version >= 0 && peer_version != data->force_version) {
		wpa_printf(MSG_INFO, "EAP-FAST: peer did not select the forced"
			   " version (forced=%d peer=%d) - reject",
			   data->force_version, peer_version);
		eap_fast_state(data, FAILURE);
		return;
	}
	if (peer_version < data->fast_version) {
		wpa_printf(MSG_DEBUG, "EAP-FAST: peer ver=%d, own ver=%d; "
			   "use version %d",
			   peer_version, data->fast_version, peer_version);
		data->fast_version = peer_version;
	}
	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		if (left < 4) {
			wpa_printf(MSG_INFO, "EAP-FAST: Short frame with TLS "
				   "length");
			eap_fast_state(data, FAILURE);
			return;
		}
		tls_msg_len = WPA_GET_BE32(pos);
		wpa_printf(MSG_DEBUG, "EAP-FAST: TLS Message Length: %d",
			   tls_msg_len);
		if (data->ssl.tls_in_left == 0) {
			data->ssl.tls_in_total = tls_msg_len;
			data->ssl.tls_in_left = tls_msg_len;
			os_free(data->ssl.tls_in);
			data->ssl.tls_in = NULL;
			data->ssl.tls_in_len = 0;
		}
		pos += 4;
		left -= 4;
	}

	switch (data->state) {
	case PHASE1:
		if (eap_server_tls_process_helper(sm, &data->ssl, pos, left) <
		    0) {
			wpa_printf(MSG_INFO, "EAP-FAST: TLS processing "
				   "failed");
			eap_fast_state(data, FAILURE);
		}

		if (!tls_connection_established(sm->ssl_ctx, data->ssl.conn) ||
		    data->ssl.tls_out_len > 0)
			break;

		/*
		 * Phase 1 was completed with the received message (e.g., when
		 * using abbreviated handshake), so Phase 2 can be started
		 * immediately without having to send through an empty message
		 * to the peer.
		 */

		if (eap_fast_phase1_done(sm, data) < 0)
			break;

		/* fall through to PHASE2_START */
	case PHASE2_START:
		eap_fast_state(data, PHASE2_ID);
		eap_fast_phase2_init(sm, data, EAP_TYPE_IDENTITY);
		break;
	case PHASE2_ID:
	case PHASE2_METHOD:
	case CRYPTO_BINDING:
	case REQUEST_PAC:
		eap_fast_process_phase2(sm, data, pos, left);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-FAST: Unexpected state %d in %s",
			   data->state, __func__);
		break;
	}

	if (tls_connection_get_write_alerts(sm->ssl_ctx, data->ssl.conn) > 1) {
		wpa_printf(MSG_INFO, "EAP-FAST: Locally detected fatal error "
			   "in TLS processing");
		eap_fast_state(data, FAILURE);
	}
}


static Boolean eap_fast_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_fast_data *data = priv;
	return data->state == SUCCESS || data->state == FAILURE;
}


static u8 * eap_fast_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_fast_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	/*
	 * RFC 4851, Section 5.4: EAP Master Session Key Genreration
	 * MSK = T-PRF(S-IMCK[j], "Session Key Generating Function", 64)
	 */

	eapKeyData = os_malloc(EAP_FAST_KEY_LEN);
	if (eapKeyData == NULL)
		return NULL;

	sha1_t_prf(data->simck, EAP_FAST_SIMCK_LEN,
		   "Session Key Generating Function", (u8 *) "", 0,
		   eapKeyData, EAP_FAST_KEY_LEN);
	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: Derived key (MSK)",
			eapKeyData, EAP_FAST_KEY_LEN);
	*len = EAP_FAST_KEY_LEN;

	return eapKeyData;
}


static u8 * eap_fast_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_fast_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	/*
	 * RFC 4851, Section 5.4: EAP Master Session Key Genreration
	 * EMSK = T-PRF(S-IMCK[j],
	 *        "Extended Session Key Generating Function", 64)
	 */

	eapKeyData = os_malloc(EAP_EMSK_LEN);
	if (eapKeyData == NULL)
		return NULL;

	sha1_t_prf(data->simck, EAP_FAST_SIMCK_LEN,
		   "Extended Session Key Generating Function",
		   (u8 *) "", 0, eapKeyData, EAP_EMSK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "EAP-FAST: Derived key (EMSK)",
			eapKeyData, EAP_EMSK_LEN);

	*len = EAP_EMSK_LEN;

	return eapKeyData;
}


static Boolean eap_fast_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_fast_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_fast_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_FAST, "FAST");
	if (eap == NULL)
		return -1;

	eap->init = eap_fast_init;
	eap->reset = eap_fast_reset;
	eap->buildReq = eap_fast_buildReq;
	eap->check = eap_fast_check;
	eap->process = eap_fast_process;
	eap->isDone = eap_fast_isDone;
	eap->getKey = eap_fast_getKey;
	eap->get_emsk = eap_fast_get_emsk;
	eap->isSuccess = eap_fast_isSuccess;

	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
	return ret;
}
