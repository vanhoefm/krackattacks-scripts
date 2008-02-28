/*
 * EAP peer method: EAP-TNC (Trusted Network Connect)
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
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
#include "tncc.h"


struct eap_tnc_data {
	EapMethodState state;
	struct tncc_data *tncc;
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
	data->state = METHOD_INIT;
	data->tncc = tncc_init();
	if (data->tncc == NULL) {
		os_free(data);
		return NULL;
	}

	return data;
}


static void eap_tnc_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_tnc_data *data = priv;

	tncc_deinit(data->tncc);
	os_free(data);
}


static struct wpabuf * eap_tnc_process(struct eap_sm *sm, void *priv,
				       struct eap_method_ret *ret,
				       const struct wpabuf *reqData)
{
	struct eap_tnc_data *data = priv;
	struct wpabuf *resp;
	const u8 *pos;
	u8 *rpos, *rpos1, *start;
	size_t len, rlen;
	size_t imc_len;
	char *start_buf, *end_buf;
	size_t start_len, end_len;
	int tncs_done = 0;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TNC, reqData, &len);
	if (pos == NULL || len == 0) {
		wpa_printf(MSG_INFO, "EAP-TNC: Invalid frame (pos=%p len=%lu)",
			   pos, (unsigned long) len);
		ret->ignore = TRUE;
		return NULL;
	}

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-TNC: Received payload", pos, len);

	if ((*pos & EAP_TNC_VERSION_MASK) != EAP_TNC_VERSION) {
		wpa_printf(MSG_DEBUG, "EAP-TNC: Unsupported version %d",
			   *pos & EAP_TNC_VERSION_MASK);
		ret->ignore = TRUE;
		return NULL;
	}

	if (data->state == METHOD_INIT) {
		if (!(*pos & EAP_TNC_FLAGS_START)) {
			wpa_printf(MSG_DEBUG, "EAP-TNC: Server did not use "
				   "start flag in the first message");
			ret->ignore = TRUE;
			return NULL;
		}

		tncc_init_connection(data->tncc);

		data->state = METHOD_MAY_CONT;
	} else {
		enum tncc_process_res res;

		if (*pos & EAP_TNC_FLAGS_START) {
			wpa_printf(MSG_DEBUG, "EAP-TNC: Server used start "
				   "flag again");
			ret->ignore = TRUE;
			return NULL;
		}

		res = tncc_process_if_tnccs(data->tncc, pos + 1, len - 1);
		switch (res) {
		case TNCCS_PROCESS_ERROR:
			ret->ignore = TRUE;
			return NULL;
		case TNCCS_PROCESS_OK_NO_RECOMMENDATION:
		case TNCCS_RECOMMENDATION_ERROR:
			wpa_printf(MSG_DEBUG, "EAP-TNC: No "
				   "TNCCS-Recommendation received");
			break;
		case TNCCS_RECOMMENDATION_ALLOW:
			wpa_msg(sm->msg_ctx, MSG_INFO,
				"TNC: Recommendation = allow");
			tncs_done = 1;
			break;
		case TNCCS_RECOMMENDATION_NONE:
			wpa_msg(sm->msg_ctx, MSG_INFO,
				"TNC: Recommendation = none");
			tncs_done = 1;
			break;
		case TNCCS_RECOMMENDATION_ISOLATE:
			wpa_msg(sm->msg_ctx, MSG_INFO,
				"TNC: Recommendation = isolate");
			tncs_done = 1;
			break;
		}
	}

	ret->ignore = FALSE;
	ret->methodState = data->state;
	ret->decision = DECISION_UNCOND_SUCC;
	ret->allowNotifications = TRUE;

	if (tncs_done) {
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TNC, 1,
				     EAP_CODE_RESPONSE, eap_get_id(reqData));
		if (resp == NULL)
			return NULL;

		wpabuf_put_u8(resp, EAP_TNC_VERSION);
		wpa_printf(MSG_DEBUG, "EAP-TNC: TNCS done - reply with an "
			   "empty ACK message");
		return resp;
	}

	imc_len = tncc_total_send_len(data->tncc);

	start_buf = tncc_if_tnccs_start(data->tncc);
	if (start_buf == NULL)
		return NULL;
	start_len = os_strlen(start_buf);
	end_buf = tncc_if_tnccs_end();
	if (end_buf == NULL) {
		os_free(start_buf);
		return NULL;
	}
	end_len = os_strlen(end_buf);

	rlen = 1 + start_len + imc_len + end_len;
	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TNC, rlen,
			     EAP_CODE_RESPONSE, eap_get_id(reqData));
	if (resp == NULL) {
		os_free(start_buf);
		os_free(end_buf);
		return NULL;
	}

	start = wpabuf_put(resp, 0);
	wpabuf_put_u8(resp, EAP_TNC_VERSION);
	wpabuf_put_data(resp, start_buf, start_len);
	os_free(start_buf);

	rpos1 = wpabuf_put(resp, 0);
	rpos = tncc_copy_send_buf(data->tncc, rpos1);
	wpabuf_put(resp, rpos - rpos1);

	wpabuf_put_data(resp, end_buf, end_len);
	os_free(end_buf);

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-TNC: Response", start, rlen);

	return resp;
}


int eap_peer_tnc_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_TNC, "TNC");
	if (eap == NULL)
		return -1;

	eap->init = eap_tnc_init;
	eap->deinit = eap_tnc_deinit;
	eap->process = eap_tnc_process;

	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret;
}
