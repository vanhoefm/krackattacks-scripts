/*
 * EAP-WSC peer for Wi-Fi Protected Setup
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
#include "uuid.h"
#include "eap_i.h"
#include "eap_common/eap_wsc_common.h"
#include "wps/wps.h"
#include "wps/wps_defs.h"


struct eap_wsc_data {
	enum { WAIT_START, MSG, FRAG_ACK, WAIT_FRAG_ACK, DONE, FAIL } state;
	int registrar;
	struct wpabuf *in_buf;
	struct wpabuf *out_buf;
	u8 in_op_code, out_op_code;
	size_t out_used;
	size_t fragment_size;
	struct wps_data *wps;
	struct wps_context *wps_ctx;
};


static const char * eap_wsc_state_txt(int state)
{
	switch (state) {
	case WAIT_START:
		return "WAIT_START";
	case MSG:
		return "MSG";
	case FRAG_ACK:
		return "FRAG_ACK";
	case WAIT_FRAG_ACK:
		return "WAIT_FRAG_ACK";
	case DONE:
		return "DONE";
	case FAIL:
		return "FAIL";
	default:
		return "?";
	}
}


static void eap_wsc_state(struct eap_wsc_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-WSC: %s -> %s",
		   eap_wsc_state_txt(data->state),
		   eap_wsc_state_txt(state));
	data->state = state;
}


static int eap_wsc_new_psk_cb(void *ctx, const u8 *mac_addr, const u8 *psk,
			      size_t psk_len)
{
	/* struct eap_wsc_data *data = ctx; */

	wpa_printf(MSG_DEBUG, "EAP-SC: Received new WPA/WPA2-PSK from WPS for "
		   "STA " MACSTR, MAC2STR(mac_addr));
	wpa_hexdump_key(MSG_DEBUG, "Per-device PSK", psk, psk_len);

	/* TODO */

	return 0;
}


static void eap_wsc_pin_needed_cb(void *ctx, const u8 *uuid_e,
				  const struct wps_device_data *dev)
{
	/* struct eap_wsc_data *data = ctx; */
	char uuid[40], txt[400];
	int len;
	if (uuid_bin2str(uuid_e, uuid, sizeof(uuid)))
		return;
	wpa_printf(MSG_DEBUG, "EAP-WSC: PIN needed for E-UUID %s", uuid);
	len = os_snprintf(txt, sizeof(txt), "WPS-EVENT-PIN-NEEDED "
			  "%s " MACSTR " [%s|%s|%s|%s|%s|%d-%08X-%d]",
			  uuid, MAC2STR(dev->mac_addr), dev->device_name,
			  dev->manufacturer, dev->model_name,
			  dev->model_number, dev->serial_number,
			  dev->categ, dev->oui, dev->sub_categ);
	if (len > 0 && len < (int) sizeof(txt))
		wpa_printf(MSG_INFO, "%s", txt);
}


static void * eap_wsc_init(struct eap_sm *sm)
{
	struct eap_wsc_data *data;
	const u8 *identity;
	size_t identity_len;
	int registrar;
	struct wps_config cfg;
	u8 uuid[UUID_LEN];
	const char *pos;
	const char *phase1;
	struct wps_context *wps = NULL;

	identity = eap_get_config_identity(sm, &identity_len);

	if (identity && identity_len == WSC_ID_REGISTRAR_LEN &&
	    os_memcmp(identity, WSC_ID_REGISTRAR, WSC_ID_REGISTRAR_LEN) == 0)
		registrar = 1; /* Supplicant is Registrar */
	else if (identity && identity_len == WSC_ID_ENROLLEE_LEN &&
	    os_memcmp(identity, WSC_ID_ENROLLEE, WSC_ID_ENROLLEE_LEN) == 0)
		registrar = 0; /* Supplicant is Enrollee */
	else {
		wpa_hexdump_ascii(MSG_INFO, "EAP-WSC: Unexpected identity",
				  identity, identity_len);
		return NULL;
	}

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = registrar ? MSG : WAIT_START;
	data->registrar = registrar;

	if (registrar) {
		struct wps_registrar_config rcfg;

		wps = os_zalloc(sizeof(*wps));
		if (wps == NULL) {
			os_free(data);
			return NULL;
		}

		wps->cb_ctx = data;

		/* TODO: configure.. */
		wps->auth_types = WPS_AUTH_WPA2PSK;
		wps->encr_types = WPS_ENCR_AES;
		os_memcpy(wps->ssid, "test", 4);
		wps->ssid_len = 4;

		os_memset(&rcfg, 0, sizeof(rcfg));
		rcfg.new_psk_cb = eap_wsc_new_psk_cb;
		rcfg.pin_needed_cb = eap_wsc_pin_needed_cb;
		rcfg.cb_ctx = data;

		wps->registrar = wps_registrar_init(wps, &rcfg);
		if (wps->registrar == NULL) {
			wpa_printf(MSG_DEBUG, "EAP-WSC: Failed to initialize "
				   "WPS Registrar");
			os_free(wps->network_key);
			os_free(wps);
			os_free(data);
			return NULL;
		}

		data->wps_ctx = wps;
	}

	os_memset(&cfg, 0, sizeof(cfg));
	cfg.authenticator = 0;
	cfg.wps = wps;
	cfg.registrar = data->wps_ctx ? data->wps_ctx->registrar : NULL;
	cfg.enrollee_mac_addr = sm->mac_addr;

	phase1 = eap_get_config_phase1(sm);
	if (phase1 == NULL) {
		wpa_printf(MSG_INFO, "EAP-WSC: phase1 configuration data not "
			   "set");
		os_free(data);
		return NULL;
	}

	pos = os_strstr(phase1, "pin=");
	if (pos) {
		pos += 4;
		cfg.pin = (const u8 *) pos;
		while (*pos != '\0' && *pos != ' ')
			pos++;
		cfg.pin_len = pos - (const char *) cfg.pin;
	} else {
		pos = os_strstr(phase1, "pbc=1");
		if (pos)
			cfg.pbc = 1;
	}

	if (cfg.pin == NULL && !cfg.pbc) {
		wpa_printf(MSG_INFO, "EAP-WSC: PIN or PBC not set in phase1 "
			   "configuration data");
		os_free(data);
		return NULL;
	}

	pos = os_strstr(phase1, "uuid=");
	if (pos == NULL) {
		wpa_printf(MSG_INFO, "EAP-WSC: UUID not set in phase1 "
			   "configuration data");
		os_free(data);
		return NULL;
	}
	if (uuid_str2bin(pos + 5, uuid)) {
		wpa_printf(MSG_INFO, "EAP-WSC: Invalid UUID in phase1 "
			   "configuration data");
		os_free(data);
		return NULL;
	}
	if (registrar && wps)
		os_memcpy(wps->uuid, uuid, UUID_LEN);
	else
		cfg.uuid = uuid;
	cfg.wps_cred_cb = sm->eapol_cb->wps_cred;
	cfg.cb_ctx = sm->eapol_ctx;
	data->wps = wps_init(&cfg);
	if (data->wps == NULL) {
		os_free(data);
		return NULL;
	}
	data->fragment_size = WSC_FRAGMENT_SIZE;


	if (registrar) {
		/* Testing */
		wpa_printf(MSG_INFO, "EAP-WSC: Registrar functionality not "
			   "yet fully supported - using test values");
		u8 uuid_e[UUID_LEN];
		os_memset(uuid_e, 0, UUID_LEN);
		wps_registrar_add_pin(data->wps_ctx->registrar, uuid_e,
				      (const u8 *) "12345670", 8);
	}

	return data;
}


static void eap_wsc_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_wsc_data *data = priv;
	wpabuf_free(data->in_buf);
	wpabuf_free(data->out_buf);
	wps_deinit(data->wps);
	if (data->wps_ctx) {
		wps_registrar_deinit(data->wps_ctx->registrar);
		os_free(data->wps_ctx->network_key);
		os_free(data->wps_ctx);
	}
	os_free(data);
}


static struct wpabuf * eap_wsc_build_msg(struct eap_wsc_data *data,
					 struct eap_method_ret *ret, u8 id)
{
	struct wpabuf *resp;
	u8 flags;
	size_t send_len, plen;

	ret->ignore = FALSE;
	wpa_printf(MSG_DEBUG, "EAP-WSC: Generating Response");
	ret->allowNotifications = TRUE;

	flags = 0;
	send_len = wpabuf_len(data->out_buf) - data->out_used;
	if (2 + send_len > data->fragment_size) {
		send_len = data->fragment_size - 2;
		flags |= WSC_FLAGS_MF;
		if (data->out_used == 0) {
			flags |= WSC_FLAGS_LF;
			send_len -= 2;
		}
	}
	plen = 2 + send_len;
	if (flags & WSC_FLAGS_LF)
		plen += 2;
	resp = eap_msg_alloc(EAP_VENDOR_WFA, EAP_VENDOR_TYPE_WSC, plen,
			     EAP_CODE_RESPONSE, id);
	if (resp == NULL)
		return NULL;

	wpabuf_put_u8(resp, data->out_op_code); /* Op-Code */
	wpabuf_put_u8(resp, flags); /* Flags */
	if (flags & WSC_FLAGS_LF)
		wpabuf_put_be16(resp, wpabuf_len(data->out_buf));

	wpabuf_put_data(resp, wpabuf_head_u8(data->out_buf) + data->out_used,
			send_len);
	data->out_used += send_len;

	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_FAIL;

	if (data->out_used == wpabuf_len(data->out_buf)) {
		wpa_printf(MSG_DEBUG, "EAP-WSC: Sending out %lu bytes "
			   "(message sent completely)",
			   (unsigned long) send_len);
		wpabuf_free(data->out_buf);
		data->out_buf = NULL;
		data->out_used = 0;
		if ((data->state == FAIL && data->out_op_code == WSC_ACK) ||
		    data->out_op_code == WSC_NACK ||
		    data->out_op_code == WSC_Done) {
			eap_wsc_state(data, FAIL);
			ret->methodState = METHOD_DONE;
		} else
			eap_wsc_state(data, MSG);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-WSC: Sending out %lu bytes "
			   "(%lu more to send)", (unsigned long) send_len,
			   (unsigned long) wpabuf_len(data->out_buf) -
			   data->out_used);
		eap_wsc_state(data, WAIT_FRAG_ACK);
	}

	return resp;
}


static int eap_wsc_process_cont(struct eap_wsc_data *data,
				const u8 *buf, size_t len, u8 op_code)
{
	/* Process continuation of a pending message */
	if (op_code != data->in_op_code) {
		wpa_printf(MSG_DEBUG, "EAP-WSC: Unexpected Op-Code %d in "
			   "fragment (expected %d)",
			   op_code, data->in_op_code);
		return -1;
	}

	if (len > wpabuf_tailroom(data->in_buf)) {
		wpa_printf(MSG_DEBUG, "EAP-WSC: Fragment overflow");
		eap_wsc_state(data, FAIL);
		return -1;
	}

	wpabuf_put_data(data->in_buf, buf, len);
	wpa_printf(MSG_DEBUG, "EAP-WSC: Received %lu bytes, waiting "
		   "for %lu bytes more", (unsigned long) len,
		   (unsigned long) wpabuf_tailroom(data->in_buf));

	return 0;
}


static struct wpabuf * eap_wsc_process_fragment(struct eap_wsc_data *data,
						struct eap_method_ret *ret,
						u8 id, u8 flags, u8 op_code,
						u16 message_length,
						const u8 *buf, size_t len)
{
	/* Process a fragment that is not the last one of the message */
	if (data->in_buf == NULL && !(flags & WSC_FLAGS_LF)) {
		wpa_printf(MSG_DEBUG, "EAP-WSC: No Message Length field in a "
			   "fragmented packet");
		ret->ignore = TRUE;
		return NULL;
	}

	if (data->in_buf == NULL) {
		/* First fragment of the message */
		data->in_buf = wpabuf_alloc(message_length);
		if (data->in_buf == NULL) {
			wpa_printf(MSG_DEBUG, "EAP-WSC: No memory for "
				   "message");
			ret->ignore = TRUE;
			return NULL;
		}
		data->in_op_code = op_code;
		wpabuf_put_data(data->in_buf, buf, len);
		wpa_printf(MSG_DEBUG, "EAP-WSC: Received %lu bytes in first "
			   "fragment, waiting for %lu bytes more",
			   (unsigned long) len,
			   (unsigned long) wpabuf_tailroom(data->in_buf));
	}

	return eap_wsc_build_frag_ack(id, EAP_CODE_RESPONSE);
}


static struct wpabuf * eap_wsc_process(struct eap_sm *sm, void *priv,
				       struct eap_method_ret *ret,
				       const struct wpabuf *reqData)
{
	struct eap_wsc_data *data = priv;
	const u8 *start, *pos, *end;
	size_t len;
	u8 op_code, flags, id;
	u16 message_length = 0;
	enum wps_process_res res;
	struct wpabuf tmpbuf;

	pos = eap_hdr_validate(EAP_VENDOR_WFA, EAP_VENDOR_TYPE_WSC, reqData,
			       &len);
	if (pos == NULL || len < 2) {
		ret->ignore = TRUE;
		return NULL;
	}

	id = eap_get_id(reqData);

	start = pos;
	end = start + len;

	op_code = *pos++;
	flags = *pos++;
	if (flags & WSC_FLAGS_LF) {
		if (end - pos < 2) {
			wpa_printf(MSG_DEBUG, "EAP-WSC: Message underflow");
			ret->ignore = TRUE;
			return NULL;
		}
		message_length = WPA_GET_BE16(pos);
		pos += 2;

		if (message_length < end - pos) {
			wpa_printf(MSG_DEBUG, "EAP-WSC: Invalid Message "
				   "Length");
			ret->ignore = TRUE;
			return NULL;
		}
	}

	wpa_printf(MSG_DEBUG, "EAP-WSC: Received packet: Op-Code %d "
		   "Flags 0x%x Message Length %d",
		   op_code, flags, message_length);

	if (data->state == WAIT_FRAG_ACK) {
		if (op_code != WSC_FRAG_ACK) {
			wpa_printf(MSG_DEBUG, "EAP-WSC: Unexpected Op-Code %d "
				   "in WAIT_FRAG_ACK state", op_code);
			ret->ignore = TRUE;
			return NULL;
		}
		wpa_printf(MSG_DEBUG, "EAP-WSC: Fragment acknowledged");
		eap_wsc_state(data, MSG);
		return eap_wsc_build_msg(data, ret, id);
	}

	if (op_code != WSC_ACK && op_code != WSC_NACK && op_code != WSC_MSG &&
	    op_code != WSC_Done && op_code != WSC_Start) {
		wpa_printf(MSG_DEBUG, "EAP-WSC: Unexpected Op-Code %d",
			   op_code);
		ret->ignore = TRUE;
		return NULL;
	}

	if (data->state == WAIT_START) {
		if (op_code != WSC_Start) {
			wpa_printf(MSG_DEBUG, "EAP-WSC: Unexpected Op-Code %d "
				   "in WAIT_START state", op_code);
			ret->ignore = TRUE;
			return NULL;
		}
		wpa_printf(MSG_DEBUG, "EAP-WSC: Received start");
		eap_wsc_state(data, MSG);
		/* Start message has empty payload, skip processing */
		goto send_msg;
	} else if (op_code == WSC_Start) {
		wpa_printf(MSG_DEBUG, "EAP-WSC: Unexpected Op-Code %d",
			   op_code);
		ret->ignore = TRUE;
		return NULL;
	}

	if (data->in_buf &&
	    eap_wsc_process_cont(data, pos, end - pos, op_code) < 0) {
		ret->ignore = TRUE;
		return NULL;
	}

	if (flags & WSC_FLAGS_MF) {
		return eap_wsc_process_fragment(data, ret, id, flags, op_code,
						message_length, pos,
						end - pos);
	}

	if (data->in_buf == NULL) {
		/* Wrap unfragmented messages as wpabuf without extra copy */
		wpabuf_set(&tmpbuf, pos, end - pos);
		data->in_buf = &tmpbuf;
	}

	res = wps_process_msg(data->wps, op_code, data->in_buf);
	switch (res) {
	case WPS_DONE:
		wpa_printf(MSG_DEBUG, "EAP-WSC: WPS processing completed "
			   "successfully - wait for EAP failure");
		eap_wsc_state(data, FAIL);
		break;
	case WPS_CONTINUE:
		eap_wsc_state(data, MSG);
		break;
	case WPS_FAILURE:
		wpa_printf(MSG_DEBUG, "EAP-WSC: WPS processing failed");
		eap_wsc_state(data, FAIL);
		break;
	case WPS_PENDING:
		wpa_printf(MSG_DEBUG, "EAP-WSC: WPS processing pending");
		ret->ignore = TRUE;
		if (data->in_buf == &tmpbuf)
			data->in_buf = NULL;
		return NULL;
	}

	if (data->in_buf != &tmpbuf)
		wpabuf_free(data->in_buf);
	data->in_buf = NULL;

send_msg:
	if (data->out_buf == NULL) {
		data->out_buf = wps_get_msg(data->wps, &data->out_op_code);
		if (data->out_buf == NULL) {
			wpa_printf(MSG_DEBUG, "EAP-WSC: Failed to receive "
				   "message from WPS");
			return NULL;
		}
		data->out_used = 0;
	}

	eap_wsc_state(data, MSG);
	return eap_wsc_build_msg(data, ret, id);
}


int eap_peer_wsc_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_WFA, EAP_VENDOR_TYPE_WSC,
				    "WSC");
	if (eap == NULL)
		return -1;

	eap->init = eap_wsc_init;
	eap->deinit = eap_wsc_deinit;
	eap->process = eap_wsc_process;

	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret;
}
