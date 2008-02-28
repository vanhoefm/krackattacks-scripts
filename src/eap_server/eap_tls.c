/*
 * hostapd / EAP-TLS (RFC 2716)
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
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
#include "tls.h"


static void eap_tls_reset(struct eap_sm *sm, void *priv);


struct eap_tls_data {
	struct eap_ssl_data ssl;
	enum { START, CONTINUE, SUCCESS, FAILURE } state;
};


static void * eap_tls_init(struct eap_sm *sm)
{
	struct eap_tls_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = START;

	if (eap_server_tls_ssl_init(sm, &data->ssl, 1)) {
		wpa_printf(MSG_INFO, "EAP-TLS: Failed to initialize SSL.");
		eap_tls_reset(sm, data);
		return NULL;
	}

	return data;
}


static void eap_tls_reset(struct eap_sm *sm, void *priv)
{
	struct eap_tls_data *data = priv;
	if (data == NULL)
		return;
	eap_server_tls_ssl_deinit(sm, &data->ssl);
	os_free(data);
}


static struct wpabuf * eap_tls_build_start(struct eap_sm *sm,
					   struct eap_tls_data *data, u8 id)
{
	struct wpabuf *req;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TLS, 1, EAP_CODE_REQUEST,
			    id);
	if (req == NULL) {
		wpa_printf(MSG_ERROR, "EAP-TLS: Failed to allocate memory for "
			   "request");
		data->state = FAILURE;
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TLS_FLAGS_START);

	data->state = CONTINUE;

	return req;
}


static struct wpabuf * eap_tls_build_req(struct eap_sm *sm,
					 struct eap_tls_data *data, u8 id)
{
	int res;
	struct wpabuf *req;

	res = eap_server_tls_buildReq_helper(sm, &data->ssl, EAP_TYPE_TLS, 0,
					     id, &req);

	if (tls_connection_established(sm->ssl_ctx, data->ssl.conn)) {
		wpa_printf(MSG_DEBUG, "EAP-TLS: Done");
		data->state = SUCCESS;
	}

	if (res == 1)
		return eap_server_tls_build_ack(id, EAP_TYPE_TLS, 0);
	return req;
}


static struct wpabuf * eap_tls_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_tls_data *data = priv;

	switch (data->state) {
	case START:
		return eap_tls_build_start(sm, data, id);
	case CONTINUE:
		return eap_tls_build_req(sm, data, id);
	default:
		wpa_printf(MSG_DEBUG, "EAP-TLS: %s - unexpected state %d",
			   __func__, data->state);
		return NULL;
	}
}


static Boolean eap_tls_check(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TLS, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-TLS: Invalid frame");
		return TRUE;
	}

	return FALSE;
}


static void eap_tls_process(struct eap_sm *sm, void *priv,
			    struct wpabuf *respData)
{
	struct eap_tls_data *data = priv;
	const u8 *pos;
	u8 flags;
	size_t left;
	unsigned int tls_msg_len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TLS, respData, &left);
	if (pos == NULL || left < 1)
		return; /* Should not happen - frame already validated */

	flags = *pos++;
	left--;
	wpa_printf(MSG_DEBUG, "EAP-TLS: Received packet(len=%lu) - "
		   "Flags 0x%02x", (unsigned long) wpabuf_len(respData),
		   flags);
	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		if (left < 4) {
			wpa_printf(MSG_INFO, "EAP-TLS: Short frame with TLS "
				   "length");
			data->state = FAILURE;
			return;
		}
		tls_msg_len = WPA_GET_BE32(pos);
		wpa_printf(MSG_DEBUG, "EAP-TLS: TLS Message Length: %d",
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

	if (eap_server_tls_process_helper(sm, &data->ssl, pos, left) < 0) {
		wpa_printf(MSG_INFO, "EAP-TLS: TLS processing failed");
		data->state = FAILURE;
		return;
	}

	if (tls_connection_get_write_alerts(sm->ssl_ctx, data->ssl.conn) > 1) {
		wpa_printf(MSG_INFO, "EAP-TLS: Locally detected fatal error "
			   "in TLS processing");
		data->state = FAILURE;
		return;
	}
}


static Boolean eap_tls_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_tls_data *data = priv;
	return data->state == SUCCESS || data->state == FAILURE;
}


static u8 * eap_tls_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_tls_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl,
					       "client EAP encryption",
					       EAP_TLS_KEY_LEN);
	if (eapKeyData) {
		*len = EAP_TLS_KEY_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-TLS: Derived key",
			    eapKeyData, EAP_TLS_KEY_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TLS: Failed to derive key");
	}

	return eapKeyData;
}


static u8 * eap_tls_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_tls_data *data = priv;
	u8 *eapKeyData, *emsk;

	if (data->state != SUCCESS)
		return NULL;

	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl,
					       "client EAP encryption",
					       EAP_TLS_KEY_LEN + EAP_EMSK_LEN);
	if (eapKeyData) {
		emsk = os_malloc(EAP_EMSK_LEN);
		if (emsk)
			os_memcpy(emsk, eapKeyData + EAP_TLS_KEY_LEN,
				  EAP_EMSK_LEN);
		os_free(eapKeyData);
	} else
		emsk = NULL;

	if (emsk) {
		*len = EAP_EMSK_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-TLS: Derived EMSK",
			    emsk, EAP_EMSK_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TLS: Failed to derive EMSK");
	}

	return emsk;
}


static Boolean eap_tls_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_tls_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_tls_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_TLS, "TLS");
	if (eap == NULL)
		return -1;

	eap->init = eap_tls_init;
	eap->reset = eap_tls_reset;
	eap->buildReq = eap_tls_buildReq;
	eap->check = eap_tls_check;
	eap->process = eap_tls_process;
	eap->isDone = eap_tls_isDone;
	eap->getKey = eap_tls_getKey;
	eap->isSuccess = eap_tls_isSuccess;
	eap->get_emsk = eap_tls_get_emsk;

	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
	return ret;
}
