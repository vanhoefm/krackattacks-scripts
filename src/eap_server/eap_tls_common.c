/*
 * hostapd / EAP-TLS/PEAP/TTLS/FAST common functions
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
#include "sha1.h"
#include "tls.h"


int eap_server_tls_ssl_init(struct eap_sm *sm, struct eap_ssl_data *data,
			    int verify_peer)
{
	data->eap = sm;
	data->phase2 = sm->init_phase2;

	data->conn = tls_connection_init(sm->ssl_ctx);
	if (data->conn == NULL) {
		wpa_printf(MSG_INFO, "SSL: Failed to initialize new TLS "
			   "connection");
		return -1;
	}

	if (tls_connection_set_verify(sm->ssl_ctx, data->conn, verify_peer)) {
		wpa_printf(MSG_INFO, "SSL: Failed to configure verification "
			   "of TLS peer certificate");
		tls_connection_deinit(sm->ssl_ctx, data->conn);
		data->conn = NULL;
		return -1;
	}

	/* TODO: make this configurable */
	data->tls_out_limit = 1398;
	if (data->phase2) {
		/* Limit the fragment size in the inner TLS authentication
		 * since the outer authentication with EAP-PEAP does not yet
		 * support fragmentation */
		if (data->tls_out_limit > 100)
			data->tls_out_limit -= 100;
	}
	return 0;
}


void eap_server_tls_ssl_deinit(struct eap_sm *sm, struct eap_ssl_data *data)
{
	tls_connection_deinit(sm->ssl_ctx, data->conn);
	os_free(data->tls_in);
	os_free(data->tls_out);
}


u8 * eap_server_tls_derive_key(struct eap_sm *sm, struct eap_ssl_data *data,
			       char *label, size_t len)
{
	struct tls_keys keys;
	u8 *rnd = NULL, *out;

	out = os_malloc(len);
	if (out == NULL)
		return NULL;

	if (tls_connection_prf(sm->ssl_ctx, data->conn, label, 0, out, len) ==
	    0)
		return out;

	if (tls_connection_get_keys(sm->ssl_ctx, data->conn, &keys))
		goto fail;

	if (keys.client_random == NULL || keys.server_random == NULL ||
	    keys.master_key == NULL)
		goto fail;

	rnd = os_malloc(keys.client_random_len + keys.server_random_len);
	if (rnd == NULL)
		goto fail;
	os_memcpy(rnd, keys.client_random, keys.client_random_len);
	os_memcpy(rnd + keys.client_random_len, keys.server_random,
		  keys.server_random_len);

	if (tls_prf(keys.master_key, keys.master_key_len,
		    label, rnd, keys.client_random_len +
		    keys.server_random_len, out, len))
		goto fail;

	os_free(rnd);
	return out;

fail:
	os_free(out);
	os_free(rnd);
	return NULL;
}


int eap_server_tls_data_reassemble(struct eap_sm *sm,
				   struct eap_ssl_data *data,
				   u8 **in_data, size_t *in_len)
{
	u8 *buf;

	if (data->tls_in_left > *in_len || data->tls_in) {
		if (*in_len == 0) {
			wpa_printf(MSG_INFO, "SSL: Empty fragment when trying "
				   "to reassemble");
			return -1;
		}
		if (data->tls_in_len + *in_len > 65536) {
			/* Limit length to avoid rogue peers from causing large
			 * memory allocations. */
			os_free(data->tls_in);
			data->tls_in = NULL;
			data->tls_in_len = 0;
			wpa_printf(MSG_INFO, "SSL: Too long TLS fragment (size"
				   " over 64 kB)");
			return -1;
		}
		buf = os_realloc(data->tls_in, data->tls_in_len + *in_len);
		if (buf == NULL) {
			os_free(data->tls_in);
			data->tls_in = NULL;
			data->tls_in_len = 0;
			wpa_printf(MSG_INFO, "SSL: Could not allocate memory "
				   "for TLS data");
			return -1;
		}
		os_memcpy(buf + data->tls_in_len, *in_data, *in_len);
		data->tls_in = buf;
		data->tls_in_len += *in_len;
		if (*in_len > data->tls_in_left) {
			wpa_printf(MSG_INFO, "SSL: more data than TLS message "
				   "length indicated");
			data->tls_in_left = 0;
			return -1;
		}
		data->tls_in_left -= *in_len;
		if (data->tls_in_left > 0) {
			wpa_printf(MSG_DEBUG, "SSL: Need %lu bytes more input "
				   "data", (unsigned long) data->tls_in_left);
			return 1;
		}

		*in_data = data->tls_in;
		*in_len = data->tls_in_len;
	} else
		data->tls_in_left = 0;

	return 0;
}


int eap_server_tls_process_helper(struct eap_sm *sm, struct eap_ssl_data *data,
				  const u8 *in_data, size_t in_len)
{
	WPA_ASSERT(data->tls_out_len == 0 || in_len == 0);

	if (data->tls_out_len == 0) {
		u8 *_in_data = (u8 *) in_data; /* FIX: get rid of the typecast
						*/
		/* No more data to send out - expect to receive more data from
		 * the peer. */
		int res = eap_server_tls_data_reassemble(sm, data, &_in_data,
							 &in_len);
		if (res < 0 || res == 1) {
			wpa_printf(MSG_DEBUG, "SSL: data reassembly failed");
			return res;
		}
		/* Full TLS message reassembled - continue handshake processing
		 */
		if (data->tls_out) {
			/* This should not happen.. */
			wpa_printf(MSG_INFO, "SSL: eap_tls_process_helper - "
				   "pending tls_out data even though "
				   "tls_out_len = 0");
			os_free(data->tls_out);
			WPA_ASSERT(data->tls_out == NULL);
		}
		data->tls_out = tls_connection_server_handshake(
			sm->ssl_ctx, data->conn, _in_data, in_len,
			&data->tls_out_len);

		/* Clear reassembled input data (if the buffer was needed). */
		data->tls_in_left = data->tls_in_total = data->tls_in_len = 0;
		os_free(data->tls_in);
		data->tls_in = NULL;
	}

	if (data->tls_out == NULL) {
		wpa_printf(MSG_DEBUG, "SSL: failed to generate output data");
		data->tls_out_len = 0;
		return -1;
	}
	if (data->tls_out_len == 0) {
		/* TLS negotiation should now be complete since all other cases
		 * needing more that should have been catched above based on
		 * the TLS Message Length field. */
		wpa_printf(MSG_DEBUG, "SSL: No data to be sent out");
		os_free(data->tls_out);
		data->tls_out = NULL;

		if (tls_connection_get_read_alerts(sm->ssl_ctx, data->conn)) {
			wpa_printf(MSG_DEBUG, "SSL: Remote end sent a fatal "
				   "alert - abort handshake");
			return -1;
		}

		return 1;
	}

	wpa_printf(MSG_DEBUG, "SSL: %lu bytes left to be sent out (of total "
		   "%lu bytes)",
		   (unsigned long) data->tls_out_len - data->tls_out_pos,
		   (unsigned long) data->tls_out_len);

	return 0;
}


int eap_server_tls_buildReq_helper(struct eap_sm *sm,
				   struct eap_ssl_data *data,
				   int eap_type, int peap_version, u8 id,
				   struct wpabuf **out_data)
{
	size_t len;
	u8 *flags;
	struct wpabuf *req;
	int incl_len;

	incl_len = data->tls_out_pos == 0 &&
		data->tls_out_len > data->tls_out_limit;
	req = eap_msg_alloc(EAP_VENDOR_IETF, eap_type,
			    1 + (incl_len ? 4 : 0) + data->tls_out_limit,
			    EAP_CODE_REQUEST, id);
	if (req == NULL) {
		*out_data = NULL;
		return -1;
	}
	flags = wpabuf_put(req, 1);
	*flags = peap_version;
	if (incl_len) {
		*flags |= EAP_TLS_FLAGS_LENGTH_INCLUDED;
		wpabuf_put_be32(req, data->tls_out_len);
	}

	len = data->tls_out_len - data->tls_out_pos;
	if (len > data->tls_out_limit) {
		*flags |= EAP_TLS_FLAGS_MORE_FRAGMENTS;
		len = data->tls_out_limit;
		wpa_printf(MSG_DEBUG, "SSL: sending %lu bytes, more fragments "
			   "will follow", (unsigned long) len);
	}
	wpabuf_put_data(req, &data->tls_out[data->tls_out_pos], len);
	data->tls_out_pos += len;

	eap_update_len(req);
	*out_data = req;

	if (!(*flags & EAP_TLS_FLAGS_MORE_FRAGMENTS)) {
		data->tls_out_len = 0;
		data->tls_out_pos = 0;
		os_free(data->tls_out);
		data->tls_out = NULL;
	}

	return 0;
}


struct wpabuf * eap_server_tls_build_ack(u8 id, int eap_type, int peap_version)
{
	struct wpabuf *req;

	req = eap_msg_alloc(EAP_VENDOR_IETF, eap_type, 1, EAP_CODE_REQUEST,
			    id);
	if (req == NULL)
		return NULL;
	wpa_printf(MSG_DEBUG, "SSL: Building ACK");
	wpabuf_put_u8(req, peap_version); /* Flags */
	return req;
}
