/*
 * EAP server method: EAP-TNC (Trusted Network Connect)
 * Copyright (c) 2007-2008, Jouni Malinen <j@w1.fi>
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
#include "base64.h"
#include "eap_i.h"
#include "tncs.h"


struct eap_tnc_data {
	enum { START, CONTINUE, RECOMMENDATION, DONE, FAIL } state;
	enum { ALLOW, ISOLATE, NO_ACCESS, NO_RECOMMENDATION } recommendation;
	struct tncs_data *tncs;
};


/* EAP-TNC Flags */
#define EAP_TNC_FLAGS_LENGTH_INCLUDED 0x80
#define EAP_TNC_FLAGS_MORE_FRAGMENTS 0x40
#define EAP_TNC_FLAGS_START 0x20
#define EAP_TNC_VERSION_MASK 0x07

#define EAP_TNC_VERSION 1


static void * eap_tnc_init(struct eap_sm *sm)
{
	struct eap_tnc_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = START;
	data->tncs = tncs_init();
	if (data->tncs == NULL) {
		os_free(data);
		return NULL;
	}

	return data;
}


static void eap_tnc_reset(struct eap_sm *sm, void *priv)
{
	struct eap_tnc_data *data = priv;
	tncs_deinit(data->tncs);
	os_free(data);
}


static struct wpabuf * eap_tnc_build_start(struct eap_sm *sm,
					   struct eap_tnc_data *data, u8 id)
{
	struct wpabuf *req;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TNC, 1, EAP_CODE_REQUEST,
			    id);
	if (req == NULL) {
		wpa_printf(MSG_ERROR, "EAP-TNC: Failed to allocate memory for "
			   "request");
		data->state = FAIL;
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TNC_FLAGS_START | EAP_TNC_VERSION);

	data->state = CONTINUE;

	return req;
}


static struct wpabuf * eap_tnc_build(struct eap_sm *sm,
				     struct eap_tnc_data *data, u8 id)
{
	struct wpabuf *req;
	u8 *rpos, *rpos1, *start;
	size_t rlen;
	char *start_buf, *end_buf;
	size_t start_len, end_len;
	size_t imv_len;

	imv_len = tncs_total_send_len(data->tncs);

	start_buf = tncs_if_tnccs_start(data->tncs);
	if (start_buf == NULL)
		return NULL;
	start_len = os_strlen(start_buf);
	end_buf = tncs_if_tnccs_end();
	if (end_buf == NULL) {
		os_free(start_buf);
		return NULL;
	}
	end_len = os_strlen(end_buf);

	rlen = 1 + start_len + imv_len + end_len;
	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TNC, rlen,
			    EAP_CODE_REQUEST, id);
	if (req == NULL) {
		os_free(start_buf);
		os_free(end_buf);
		return NULL;
	}

	start = wpabuf_put(req, 0);
	wpabuf_put_u8(req, EAP_TNC_VERSION);
	wpabuf_put_data(req, start_buf, start_len);
	os_free(start_buf);

	rpos1 = wpabuf_put(req, 0);
	rpos = tncs_copy_send_buf(data->tncs, rpos1);
	wpabuf_put(req, rpos - rpos1);

	wpabuf_put_data(req, end_buf, end_len);
	os_free(end_buf);

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-TNC: Request", start, rlen);

	return req;
}


static struct wpabuf * eap_tnc_build_recommendation(struct eap_sm *sm,
						    struct eap_tnc_data *data,
						    u8 id)
{
	switch (data->recommendation) {
	case ALLOW:
		data->state = DONE;
		break;
	case ISOLATE:
		data->state = FAIL;
		/* TODO: support assignment to a different VLAN */
		break;
	case NO_ACCESS:
		data->state = FAIL;
		break;
	case NO_RECOMMENDATION:
		data->state = DONE;
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TNC: Unknown recommendation");
		return NULL;
	}

	return eap_tnc_build(sm, data, id);
}


static struct wpabuf * eap_tnc_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_tnc_data *data = priv;

	switch (data->state) {
	case START:
		tncs_init_connection(data->tncs);
		return eap_tnc_build_start(sm, data, id);
	case CONTINUE:
		return eap_tnc_build(sm, data, id);
	case RECOMMENDATION:
		return eap_tnc_build_recommendation(sm, data, id);
	case DONE:
	case FAIL:
		return NULL;
	}

	return NULL;
}


static Boolean eap_tnc_check(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TNC, respData,
			       &len);
	if (pos == NULL || len == 0) {
		wpa_printf(MSG_INFO, "EAP-TNC: Invalid frame");
		return TRUE;
	}

	if ((*pos & EAP_TNC_VERSION_MASK) != EAP_TNC_VERSION) {
		wpa_printf(MSG_DEBUG, "EAP-TNC: Unsupported version %d",
			   *pos & EAP_TNC_VERSION_MASK);
		return TRUE;
	}

	if (*pos & EAP_TNC_FLAGS_START) {
		wpa_printf(MSG_DEBUG, "EAP-TNC: Peer used Start flag");
		return TRUE;
	}

	return FALSE;
}


static void eap_tnc_process(struct eap_sm *sm, void *priv,
			    struct wpabuf *respData)
{
	struct eap_tnc_data *data = priv;
	const u8 *pos;
	size_t len;
	enum tncs_process_res res;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TNC, respData, &len);
	if (pos == NULL || len == 0)
		return; /* Should not happen; message already verified */

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-TNC: Received payload", pos, len);

	if (len == 1 && (data->state == DONE || data->state == FAIL)) {
		wpa_printf(MSG_DEBUG, "EAP-TNC: Peer acknowledged the last "
			   "message");
		return;
	}

	res = tncs_process_if_tnccs(data->tncs, pos + 1, len - 1);
	switch (res) {
	case TNCCS_RECOMMENDATION_ALLOW:
		wpa_printf(MSG_DEBUG, "EAP-TNC: TNCS allowed access");
		data->state = RECOMMENDATION;
		data->recommendation = ALLOW;
		break;
	case TNCCS_RECOMMENDATION_NO_RECOMMENDATION:
		wpa_printf(MSG_DEBUG, "EAP-TNC: TNCS has no recommendation");
		data->state = RECOMMENDATION;
		data->recommendation = NO_RECOMMENDATION;
		break;
	case TNCCS_RECOMMENDATION_ISOLATE:
		wpa_printf(MSG_DEBUG, "EAP-TNC: TNCS requested isolation");
		data->state = RECOMMENDATION;
		data->recommendation = ISOLATE;
		break;
	case TNCCS_RECOMMENDATION_NO_ACCESS:
		wpa_printf(MSG_DEBUG, "EAP-TNC: TNCS rejected access");
		data->state = RECOMMENDATION;
		data->recommendation = NO_ACCESS;
		break;
	case TNCCS_PROCESS_ERROR:
		wpa_printf(MSG_DEBUG, "EAP-TNC: TNCS processing error");
		data->state = FAIL;
		break;
	default:
		break;
	}
}


static Boolean eap_tnc_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_tnc_data *data = priv;
	return data->state == DONE;
}


static Boolean eap_tnc_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_tnc_data *data = priv;
	return data->state == DONE;
}


int eap_server_tnc_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_TNC, "TNC");
	if (eap == NULL)
		return -1;

	eap->init = eap_tnc_init;
	eap->reset = eap_tnc_reset;
	eap->buildReq = eap_tnc_buildReq;
	eap->check = eap_tnc_check;
	eap->process = eap_tnc_process;
	eap->isDone = eap_tnc_isDone;
	eap->isSuccess = eap_tnc_isSuccess;

	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
	return ret;
}
