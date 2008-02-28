/*
 * hostapd / EAP-PEAP (draft-josefsson-pppext-eap-tls-eap-10.txt)
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
#include "eap_i.h"
#include "eap_tls_common.h"
#include "eap_common/eap_tlv_common.h"
#include "tls.h"


/* Maximum supported PEAP version
 * 0 = Microsoft's PEAP version 0; draft-kamath-pppext-peapv0-00.txt
 * 1 = draft-josefsson-ppext-eap-tls-eap-05.txt
 * 2 = draft-josefsson-ppext-eap-tls-eap-10.txt
 */
#define EAP_PEAP_VERSION 1


static void eap_peap_reset(struct eap_sm *sm, void *priv);


struct eap_peap_data {
	struct eap_ssl_data ssl;
	enum {
		START, PHASE1, PHASE1_ID2, PHASE2_START, PHASE2_ID,
		PHASE2_METHOD,
		PHASE2_TLV, SUCCESS_REQ, FAILURE_REQ, SUCCESS, FAILURE
	} state;

	int peap_version;
	const struct eap_method *phase2_method;
	void *phase2_priv;
	int force_version;
	struct wpabuf *pending_phase2_resp;
};


static const char * eap_peap_state_txt(int state)
{
	switch (state) {
	case START:
		return "START";
	case PHASE1:
		return "PHASE1";
	case PHASE1_ID2:
		return "PHASE1_ID2";
	case PHASE2_START:
		return "PHASE2_START";
	case PHASE2_ID:
		return "PHASE2_ID";
	case PHASE2_METHOD:
		return "PHASE2_METHOD";
	case PHASE2_TLV:
		return "PHASE2_TLV";
	case SUCCESS_REQ:
		return "SUCCESS_REQ";
	case FAILURE_REQ:
		return "FAILURE_REQ";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "Unknown?!";
	}
}


static void eap_peap_state(struct eap_peap_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-PEAP: %s -> %s",
		   eap_peap_state_txt(data->state),
		   eap_peap_state_txt(state));
	data->state = state;
}


static struct wpabuf * eap_peapv2_tlv_eap_payload(struct wpabuf *buf)
{
	struct wpabuf *e;
	struct eap_tlv_hdr *tlv;

	if (buf == NULL)
		return NULL;

	/* Encapsulate EAP packet in EAP-Payload TLV */
	wpa_printf(MSG_DEBUG, "EAP-PEAPv2: Add EAP-Payload TLV");
	e = wpabuf_alloc(sizeof(*tlv) + wpabuf_len(buf));
	if (e == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-PEAPv2: Failed to allocate memory "
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


static EapType eap_peap_req_success(struct eap_sm *sm,
				    struct eap_peap_data *data)
{
	if (data->state == FAILURE || data->state == FAILURE_REQ) {
		eap_peap_state(data, FAILURE);
		return EAP_TYPE_NONE;
	}

	if (data->peap_version == 0) {
		sm->tlv_request = TLV_REQ_SUCCESS;
		eap_peap_state(data, PHASE2_TLV);
		return EAP_TYPE_TLV;
	} else {
		eap_peap_state(data, SUCCESS_REQ);
		return EAP_TYPE_NONE;
	}
}


static EapType eap_peap_req_failure(struct eap_sm *sm,
				    struct eap_peap_data *data)
{
	if (data->state == FAILURE || data->state == FAILURE_REQ ||
	    data->state == SUCCESS_REQ ||
	    (data->phase2_method &&
	     data->phase2_method->method == EAP_TYPE_TLV)) {
		eap_peap_state(data, FAILURE);
		return EAP_TYPE_NONE;
	}

	if (data->peap_version == 0) {
		sm->tlv_request = TLV_REQ_FAILURE;
		eap_peap_state(data, PHASE2_TLV);
		return EAP_TYPE_TLV;
	} else {
		eap_peap_state(data, FAILURE_REQ);
		return EAP_TYPE_NONE;
	}
}


static void * eap_peap_init(struct eap_sm *sm)
{
	struct eap_peap_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->peap_version = EAP_PEAP_VERSION;
	data->force_version = -1;
	if (sm->user && sm->user->force_version >= 0) {
		data->force_version = sm->user->force_version;
		wpa_printf(MSG_DEBUG, "EAP-PEAP: forcing version %d",
			   data->force_version);
		data->peap_version = data->force_version;
	}
	data->state = START;

	if (eap_server_tls_ssl_init(sm, &data->ssl, 0)) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Failed to initialize SSL.");
		eap_peap_reset(sm, data);
		return NULL;
	}

	return data;
}


static void eap_peap_reset(struct eap_sm *sm, void *priv)
{
	struct eap_peap_data *data = priv;
	if (data == NULL)
		return;
	if (data->phase2_priv && data->phase2_method)
		data->phase2_method->reset(sm, data->phase2_priv);
	eap_server_tls_ssl_deinit(sm, &data->ssl);
	wpabuf_free(data->pending_phase2_resp);
	os_free(data);
}


static struct wpabuf * eap_peap_build_start(struct eap_sm *sm,
					    struct eap_peap_data *data, u8 id)
{
	struct wpabuf *req;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PEAP, 1,
			    EAP_CODE_REQUEST, id);
	if (req == NULL) {
		wpa_printf(MSG_ERROR, "EAP-PEAP: Failed to allocate memory for"
			   " request");
		eap_peap_state(data, FAILURE);
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TLS_FLAGS_START | data->peap_version);

	eap_peap_state(data, PHASE1);

	return req;
}


static struct wpabuf * eap_peap_build_req(struct eap_sm *sm,
					  struct eap_peap_data *data, u8 id)
{
	int res;
	struct wpabuf *req;

	res = eap_server_tls_buildReq_helper(sm, &data->ssl, EAP_TYPE_PEAP,
					     data->peap_version, id, &req);

	if (data->peap_version < 2 &&
	    tls_connection_established(sm->ssl_ctx, data->ssl.conn)) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase1 done, starting "
			   "Phase2");
		eap_peap_state(data, PHASE2_START);
	}

	if (res == 1)
		return eap_server_tls_build_ack(id, EAP_TYPE_PEAP,
						data->peap_version);
	return req;
}


static struct wpabuf * eap_peap_encrypt(struct eap_sm *sm,
					struct eap_peap_data *data,
					u8 id, const u8 *plain,
					size_t plain_len)
{
	int res;
	struct wpabuf *buf;

	/* TODO: add support for fragmentation, if needed. This will need to
	 * add TLS Message Length field, if the frame is fragmented. */
	buf = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PEAP,
			    1 + data->ssl.tls_out_limit,
			    EAP_CODE_REQUEST, id);
	if (buf == NULL)
		return NULL;

	wpabuf_put_u8(buf, data->peap_version);

	res = tls_connection_encrypt(sm->ssl_ctx, data->ssl.conn,
				     plain, plain_len, wpabuf_put(buf, 0),
				     data->ssl.tls_out_limit);
	if (res < 0) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Failed to encrypt Phase 2 "
			   "data");
		wpabuf_free(buf);
		return NULL;
	}

	wpabuf_put(buf, res);
	eap_update_len(buf);

	return buf;
}


static struct wpabuf * eap_peap_build_phase2_req(struct eap_sm *sm,
						 struct eap_peap_data *data,
						 u8 id)
{
	struct wpabuf *buf, *encr_req;
	const u8 *req;
	size_t req_len;

	buf = data->phase2_method->buildReq(sm, data->phase2_priv, id);
	if (data->peap_version >= 2 && buf)
		buf = eap_peapv2_tlv_eap_payload(buf);
	if (buf == NULL)
		return NULL;

	req = wpabuf_head(buf);
	req_len = wpabuf_len(buf);
	wpa_hexdump_key(MSG_DEBUG, "EAP-PEAP: Encrypting Phase 2 data",
			req, req_len);

	if (data->peap_version == 0 &&
	    data->phase2_method->method != EAP_TYPE_TLV) {
		req += sizeof(struct eap_hdr);
		req_len -= sizeof(struct eap_hdr);
	}

	encr_req = eap_peap_encrypt(sm, data, id, req, req_len);
	wpabuf_free(buf);

	return encr_req;
}


static struct wpabuf * eap_peap_build_phase2_term(struct eap_sm *sm,
						  struct eap_peap_data *data,
						  u8 id, int success)
{
	struct wpabuf *encr_req;
	size_t req_len;
	struct eap_hdr *hdr;

	req_len = sizeof(*hdr);
	hdr = os_zalloc(req_len);
	if (hdr == NULL)
		return NULL;

	hdr->code = success ? EAP_CODE_SUCCESS : EAP_CODE_FAILURE;
	hdr->identifier = id;
	hdr->length = host_to_be16(req_len);

	wpa_hexdump_key(MSG_DEBUG, "EAP-PEAP: Encrypting Phase 2 data",
			(u8 *) hdr, req_len);

	encr_req = eap_peap_encrypt(sm, data, id, (u8 *) hdr, req_len);
	os_free(hdr);

	return encr_req;
}


static struct wpabuf * eap_peap_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_peap_data *data = priv;

	switch (data->state) {
	case START:
		return eap_peap_build_start(sm, data, id);
	case PHASE1:
	case PHASE1_ID2:
		return eap_peap_build_req(sm, data, id);
	case PHASE2_ID:
	case PHASE2_METHOD:
	case PHASE2_TLV:
		return eap_peap_build_phase2_req(sm, data, id);
	case SUCCESS_REQ:
		return eap_peap_build_phase2_term(sm, data, id, 1);
	case FAILURE_REQ:
		return eap_peap_build_phase2_term(sm, data, id, 0);
	default:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: %s - unexpected state %d",
			   __func__, data->state);
		return NULL;
	}
}


static Boolean eap_peap_check(struct eap_sm *sm, void *priv,
			      struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PEAP, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Invalid frame");
		return TRUE;
	}

	return FALSE;
}


static int eap_peap_phase2_init(struct eap_sm *sm, struct eap_peap_data *data,
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

	sm->init_phase2 = 1;
	data->phase2_priv = data->phase2_method->init(sm);
	sm->init_phase2 = 0;
	return 0;
}


static void eap_peap_process_phase2_response(struct eap_sm *sm,
					     struct eap_peap_data *data,
					     struct wpabuf *in_data)
{
	u8 next_type = EAP_TYPE_NONE;
	const struct eap_hdr *hdr;
	const u8 *pos;
	size_t left;

	if (data->phase2_priv == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: %s - Phase2 not "
			   "initialized?!", __func__);
		return;
	}

	hdr = wpabuf_head(in_data);
	pos = (const u8 *) (hdr + 1);

	if (wpabuf_len(in_data) > sizeof(*hdr) && *pos == EAP_TYPE_NAK) {
		left = wpabuf_len(in_data) - sizeof(*hdr);
		wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Phase2 type Nak'ed; "
			    "allowed types", pos + 1, left - 1);
		eap_sm_process_nak(sm, pos + 1, left - 1);
		if (sm->user && sm->user_eap_method_index < EAP_MAX_METHODS &&
		    sm->user->methods[sm->user_eap_method_index].method !=
		    EAP_TYPE_NONE) {
			next_type = sm->user->methods[
				sm->user_eap_method_index++].method;
			wpa_printf(MSG_DEBUG, "EAP-PEAP: try EAP type %d",
				   next_type);
		} else {
			next_type = eap_peap_req_failure(sm, data);
		}
		eap_peap_phase2_init(sm, data, next_type);
		return;
	}

	if (data->phase2_method->check(sm, data->phase2_priv, in_data)) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase2 check() asked to "
			   "ignore the packet");
		return;
	}

	data->phase2_method->process(sm, data->phase2_priv, in_data);

	if (sm->method_pending == METHOD_PENDING_WAIT) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase2 method is in "
			   "pending wait state - save decrypted response");
		wpabuf_free(data->pending_phase2_resp);
		data->pending_phase2_resp = wpabuf_dup(in_data);
	}

	if (!data->phase2_method->isDone(sm, data->phase2_priv))
		return;

	if (!data->phase2_method->isSuccess(sm, data->phase2_priv)) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase2 method failed");
		next_type = eap_peap_req_failure(sm, data);
		eap_peap_phase2_init(sm, data, next_type);
		return;
	}

	switch (data->state) {
	case PHASE1_ID2:
	case PHASE2_ID:
		if (eap_user_get(sm, sm->identity, sm->identity_len, 1) != 0) {
			wpa_hexdump_ascii(MSG_DEBUG, "EAP_PEAP: Phase2 "
					  "Identity not found in the user "
					  "database",
					  sm->identity, sm->identity_len);
			next_type = eap_peap_req_failure(sm, data);
			break;
		}

		eap_peap_state(data, PHASE2_METHOD);
		next_type = sm->user->methods[0].method;
		sm->user_eap_method_index = 1;
		wpa_printf(MSG_DEBUG, "EAP-PEAP: try EAP type %d", next_type);
		break;
	case PHASE2_METHOD:
		next_type = eap_peap_req_success(sm, data);
		break;
	case PHASE2_TLV:
		if (sm->tlv_request == TLV_REQ_SUCCESS ||
		    data->state == SUCCESS_REQ) {
			eap_peap_state(data, SUCCESS);
		} else {
			eap_peap_state(data, FAILURE);
		}
		break;
	case FAILURE:
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: %s - unexpected state %d",
			   __func__, data->state);
		break;
	}

	eap_peap_phase2_init(sm, data, next_type);
}


static void eap_peap_process_phase2(struct eap_sm *sm,
				    struct eap_peap_data *data,
				    const struct wpabuf *respData,
				    const u8 *in_data, size_t in_len)
{
	struct wpabuf *in_decrypted;
	int len_decrypted, res;
	const struct eap_hdr *hdr;
	size_t buf_len, len;

	wpa_printf(MSG_DEBUG, "EAP-PEAP: received %lu bytes encrypted data for"
		   " Phase 2", (unsigned long) in_len);

	if (data->pending_phase2_resp) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Pending Phase 2 response - "
			   "skip decryption and use old data");
		eap_peap_process_phase2_response(sm, data,
						 data->pending_phase2_resp);
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
	in_decrypted = wpabuf_alloc(buf_len);
	if (in_decrypted == NULL) {
		os_free(data->ssl.tls_in);
		data->ssl.tls_in = NULL;
		data->ssl.tls_in_len = 0;
		wpa_printf(MSG_WARNING, "EAP-PEAP: failed to allocate memory "
			   "for decryption");
		return;
	}

	len_decrypted = tls_connection_decrypt(sm->ssl_ctx, data->ssl.conn,
					       in_data, in_len,
					       wpabuf_mhead(in_decrypted),
					       buf_len);
	os_free(data->ssl.tls_in);
	data->ssl.tls_in = NULL;
	data->ssl.tls_in_len = 0;
	if (len_decrypted < 0) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Failed to decrypt Phase 2 "
			   "data");
		wpabuf_free(in_decrypted);
		eap_peap_state(data, FAILURE);
		return;
	}
	wpabuf_put(in_decrypted, len_decrypted);

	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-PEAP: Decrypted Phase 2 EAP",
			    in_decrypted);

	hdr = wpabuf_head(in_decrypted);

	if (data->peap_version == 0 && data->state != PHASE2_TLV) {
		const struct eap_hdr *resp;
		struct eap_hdr *nhdr;
		struct wpabuf *nbuf =
			wpabuf_alloc(sizeof(struct eap_hdr) +
				     wpabuf_len(in_decrypted));
		if (nbuf == NULL) {
			wpabuf_free(in_decrypted);
			return;
		}

		resp = wpabuf_head(respData);
		nhdr = wpabuf_put(nbuf, sizeof(*nhdr));
		nhdr->code = resp->code;
		nhdr->identifier = resp->identifier;
		nhdr->length = host_to_be16(sizeof(struct eap_hdr) +
					    wpabuf_len(in_decrypted));
		wpabuf_put_buf(nbuf, in_decrypted);
		wpabuf_free(in_decrypted);

		in_decrypted = nbuf;
	} else if (data->peap_version >= 2) {
		struct eap_tlv_hdr *tlv;
		struct wpabuf *nmsg;

		if (wpabuf_len(in_decrypted) < sizeof(*tlv) + sizeof(*hdr)) {
			wpa_printf(MSG_INFO, "EAP-PEAPv2: Too short Phase 2 "
				   "EAP TLV");
			wpabuf_free(in_decrypted);
			return;
		}
		tlv = wpabuf_mhead(in_decrypted);
		if ((be_to_host16(tlv->tlv_type) & EAP_TLV_TYPE_MASK) !=
		    EAP_TLV_EAP_PAYLOAD_TLV) {
			wpa_printf(MSG_INFO, "EAP-PEAPv2: Not an EAP TLV");
			wpabuf_free(in_decrypted);
			return;
		}
		if (sizeof(*tlv) + be_to_host16(tlv->length) >
		    wpabuf_len(in_decrypted)) {
			wpa_printf(MSG_INFO, "EAP-PEAPv2: Invalid EAP TLV "
				   "length");
			wpabuf_free(in_decrypted);
			return;
		}
		hdr = (struct eap_hdr *) (tlv + 1);
		if (be_to_host16(hdr->length) > be_to_host16(tlv->length)) {
			wpa_printf(MSG_INFO, "EAP-PEAPv2: No room for full "
				   "EAP packet in EAP TLV");
			wpabuf_free(in_decrypted);
			return;
		}

		nmsg = wpabuf_alloc(be_to_host16(hdr->length));
		if (nmsg == NULL) {
			wpabuf_free(in_decrypted);
			return;
		}

		wpabuf_put_data(nmsg, hdr, be_to_host16(hdr->length));
		wpabuf_free(in_decrypted);
		in_decrypted = nmsg;
	}

	hdr = wpabuf_head(in_decrypted);
	if (wpabuf_len(in_decrypted) < (int) sizeof(*hdr)) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Too short Phase 2 "
			   "EAP frame (len=%lu)",
			   (unsigned long) wpabuf_len(in_decrypted));
		wpabuf_free(in_decrypted);
		eap_peap_req_failure(sm, data);
		return;
	}
	len = be_to_host16(hdr->length);
	if (len > wpabuf_len(in_decrypted)) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Length mismatch in "
			   "Phase 2 EAP frame (len=%lu hdr->length=%lu)",
			   (unsigned long) wpabuf_len(in_decrypted),
			   (unsigned long) len);
		wpabuf_free(in_decrypted);
		eap_peap_req_failure(sm, data);
		return;
	}
	wpa_printf(MSG_DEBUG, "EAP-PEAP: received Phase 2: code=%d "
		   "identifier=%d length=%lu", hdr->code, hdr->identifier,
		   (unsigned long) len);
	switch (hdr->code) {
	case EAP_CODE_RESPONSE:
		eap_peap_process_phase2_response(sm, data, in_decrypted);
		break;
	case EAP_CODE_SUCCESS:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase 2 Success");
		if (data->state == SUCCESS_REQ) {
			eap_peap_state(data, SUCCESS);
		}
		break;
	case EAP_CODE_FAILURE:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase 2 Failure");
		eap_peap_state(data, FAILURE);
		break;
	default:
		wpa_printf(MSG_INFO, "EAP-PEAP: Unexpected code=%d in "
			   "Phase 2 EAP header", hdr->code);
		break;
	}

	os_free(in_decrypted);
}


static int eap_peapv2_start_phase2(struct eap_sm *sm,
				   struct eap_peap_data *data)
{
	struct wpabuf *buf, *buf2;
	int res;
	u8 *tls_out;

	wpa_printf(MSG_DEBUG, "EAP-PEAPv2: Phase1 done, include first Phase2 "
		   "payload in the same message");
	eap_peap_state(data, PHASE1_ID2);
	if (eap_peap_phase2_init(sm, data, EAP_TYPE_IDENTITY))
		return -1;

	/* TODO: which Id to use here? */
	buf = data->phase2_method->buildReq(sm, data->phase2_priv, 6);
	if (buf == NULL)
		return -1;

	buf2 = eap_peapv2_tlv_eap_payload(buf);
	if (buf2 == NULL)
		return -1;

	wpa_hexdump_buf(MSG_DEBUG, "EAP-PEAPv2: Identity Request", buf2);

	buf = wpabuf_alloc(data->ssl.tls_out_limit);
	if (buf == NULL) {
		wpabuf_free(buf2);
		return -1;
	}

	res = tls_connection_encrypt(sm->ssl_ctx, data->ssl.conn,
				     wpabuf_head(buf2), wpabuf_len(buf2),
				     wpabuf_put(buf, 0),
				     data->ssl.tls_out_limit);
	wpabuf_free(buf2);

	if (res < 0) {
		wpa_printf(MSG_INFO, "EAP-PEAPv2: Failed to encrypt Phase 2 "
			   "data");
		wpabuf_free(buf);
		return -1;
	}

	wpabuf_put(buf, res);
	wpa_hexdump_buf(MSG_DEBUG, "EAP-PEAPv2: Encrypted Identity Request",
			buf);

	/* Append TLS data into the pending buffer after the Server Finished */
	tls_out = os_realloc(data->ssl.tls_out,
			     data->ssl.tls_out_len + wpabuf_len(buf));
	if (tls_out == NULL) {
		wpabuf_free(buf);
		return -1;
	}

	os_memcpy(tls_out + data->ssl.tls_out_len, wpabuf_head(buf),
		  wpabuf_len(buf));
	data->ssl.tls_out = tls_out;
	data->ssl.tls_out_len += wpabuf_len(buf);

	wpabuf_free(buf);

	return 0;
}


static void eap_peap_process(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	struct eap_peap_data *data = priv;
	const u8 *pos;
	u8 flags;
	size_t left;
	unsigned int tls_msg_len;
	int peer_version;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PEAP, respData,
			       &left);
	if (pos == NULL || left < 1)
		return;
	flags = *pos++;
	left--;
	wpa_printf(MSG_DEBUG, "EAP-PEAP: Received packet(len=%lu) - "
		   "Flags 0x%02x", (unsigned long) wpabuf_len(respData),
		   flags);
	peer_version = flags & EAP_PEAP_VERSION_MASK;
	if (data->force_version >= 0 && peer_version != data->force_version) {
		wpa_printf(MSG_INFO, "EAP-PEAP: peer did not select the forced"
			   " version (forced=%d peer=%d) - reject",
			   data->force_version, peer_version);
		eap_peap_state(data, FAILURE);
		return;
	}
	if (peer_version < data->peap_version) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: peer ver=%d, own ver=%d; "
			   "use version %d",
			   peer_version, data->peap_version, peer_version);
		data->peap_version = peer_version;
	}
	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		if (left < 4) {
			wpa_printf(MSG_INFO, "EAP-PEAP: Short frame with TLS "
				   "length");
			eap_peap_state(data, FAILURE);
			return;
		}
		tls_msg_len = WPA_GET_BE32(pos);
		wpa_printf(MSG_DEBUG, "EAP-PEAP: TLS Message Length: %d",
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
			wpa_printf(MSG_INFO, "EAP-PEAP: TLS processing "
				   "failed");
			eap_peap_state(data, FAILURE);
			break;
		}

		if (data->peap_version >= 2 &&
		    tls_connection_established(sm->ssl_ctx, data->ssl.conn)) {
			if (eap_peapv2_start_phase2(sm, data)) {
				eap_peap_state(data, FAILURE);
				break;
			}
		}
		break;
	case PHASE2_START:
		eap_peap_state(data, PHASE2_ID);
		eap_peap_phase2_init(sm, data, EAP_TYPE_IDENTITY);
		break;
	case PHASE1_ID2:
	case PHASE2_ID:
	case PHASE2_METHOD:
	case PHASE2_TLV:
		eap_peap_process_phase2(sm, data, respData, pos, left);
		break;
	case SUCCESS_REQ:
		eap_peap_state(data, SUCCESS);
		break;
	case FAILURE_REQ:
		eap_peap_state(data, FAILURE);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Unexpected state %d in %s",
			   data->state, __func__);
		break;
	}

	if (tls_connection_get_write_alerts(sm->ssl_ctx, data->ssl.conn) > 1) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Locally detected fatal error "
			   "in TLS processing");
		eap_peap_state(data, FAILURE);
	}
}


static Boolean eap_peap_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_peap_data *data = priv;
	return data->state == SUCCESS || data->state == FAILURE;
}


static u8 * eap_peap_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_peap_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	/* TODO: PEAPv1 - different label in some cases */
	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl,
					       "client EAP encryption",
					       EAP_TLS_KEY_LEN);
	if (eapKeyData) {
		*len = EAP_TLS_KEY_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Derived key",
			    eapKeyData, EAP_TLS_KEY_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Failed to derive key");
	}

	return eapKeyData;
}


static Boolean eap_peap_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_peap_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_peap_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_PEAP, "PEAP");
	if (eap == NULL)
		return -1;

	eap->init = eap_peap_init;
	eap->reset = eap_peap_reset;
	eap->buildReq = eap_peap_buildReq;
	eap->check = eap_peap_check;
	eap->process = eap_peap_process;
	eap->isDone = eap_peap_isDone;
	eap->getKey = eap_peap_getKey;
	eap->isSuccess = eap_peap_isSuccess;

	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
	return ret;
}
