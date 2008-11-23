/*
 * Wi-Fi Protected Setup
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
#include "wps_i.h"
#include "wps_dev_attr.h"


struct wps_data * wps_init(const struct wps_config *cfg)
{
	struct wps_data *data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->authenticator = cfg->authenticator;
	data->wps = cfg->wps;
	data->registrar = cfg->registrar;
	if (cfg->enrollee_mac_addr)
		os_memcpy(data->mac_addr_e, cfg->enrollee_mac_addr, ETH_ALEN);
	if (cfg->uuid) {
		os_memcpy(cfg->registrar ? data->uuid_r : data->uuid_e,
			  cfg->uuid, WPS_UUID_LEN);
	}
	if (cfg->pin) {
		data->dev_pw_id = DEV_PW_DEFAULT;
		data->dev_password = os_malloc(cfg->pin_len);
		if (data->dev_password == NULL) {
			os_free(data);
			return NULL;
		}
		os_memcpy(data->dev_password, cfg->pin, cfg->pin_len);
		data->dev_password_len = cfg->pin_len;
	}

	data->pbc = cfg->pbc;
	if (cfg->pbc) {
		/* Use special PIN '00000000' for PBC */
		data->dev_pw_id = DEV_PW_PUSHBUTTON;
		os_free(data->dev_password);
		data->dev_password = os_malloc(8);
		if (data->dev_password == NULL) {
			os_free(data);
			return NULL;
		}
		os_memset(data->dev_password, '0', 8);
		data->dev_password_len = 8;
	}

	data->wps_cred_cb = cfg->wps_cred_cb;
	data->cb_ctx = cfg->cb_ctx;

	data->state = data->registrar ? RECV_M1 : SEND_M1;

	return data;
}


void wps_deinit(struct wps_data *data)
{
	if (data->wps_pin_revealed) {
		wpa_printf(MSG_DEBUG, "WPS: Full PIN information revealed and "
			   "negotiation failed");
		if (data->registrar)
			wps_registrar_invalidate_pin(data->registrar,
						     data->uuid_e);
	} else if (data->registrar)
		wps_registrar_unlock_pin(data->registrar, data->uuid_e);

	wpabuf_free(data->dh_privkey);
	wpabuf_free(data->dh_pubkey_e);
	wpabuf_free(data->dh_pubkey_r);
	wpabuf_free(data->last_msg);
	os_free(data->dev_password);
	os_free(data->new_psk);
	wps_device_data_free(&data->peer_dev);
	os_free(data);
}


enum wps_process_res wps_process_msg(struct wps_data *wps, u8 op_code,
				     const struct wpabuf *msg)
{
	if (wps->registrar)
		return wps_registrar_process_msg(wps, op_code, msg);
	else
		return wps_enrollee_process_msg(wps, op_code, msg);
}


struct wpabuf * wps_get_msg(struct wps_data *wps, u8 *op_code)
{
	if (wps->registrar)
		return wps_registrar_get_msg(wps, op_code);
	else
		return wps_enrollee_get_msg(wps, op_code);
}


int wps_is_selected_pbc_registrar(const u8 *buf, size_t len)
{
	struct wps_parse_attr attr;
	struct wpabuf msg;

	wpabuf_set(&msg, buf, len);
	if (wps_parse_msg(&msg, &attr) < 0 ||
	    !attr.selected_registrar || *attr.selected_registrar == 0 ||
	    !attr.sel_reg_config_methods ||
	    !(WPA_GET_BE16(attr.sel_reg_config_methods) &
	      WPS_CONFIG_PUSHBUTTON) ||
	    !attr.dev_password_id ||
	    WPA_GET_BE16(attr.dev_password_id) != DEV_PW_PUSHBUTTON)
		return 0;

	return 1;
}


int wps_is_selected_pin_registrar(const u8 *buf, size_t len)
{
	struct wps_parse_attr attr;
	struct wpabuf msg;

	wpabuf_set(&msg, buf, len);
	if (wps_parse_msg(&msg, &attr) < 0 ||
	    !attr.selected_registrar || *attr.selected_registrar == 0 ||
	    !attr.sel_reg_config_methods ||
	    !(WPA_GET_BE16(attr.sel_reg_config_methods) &
	      (WPS_CONFIG_LABEL | WPS_CONFIG_DISPLAY | WPS_CONFIG_KEYPAD)) ||
	    !attr.dev_password_id ||
	    WPA_GET_BE16(attr.dev_password_id) == DEV_PW_PUSHBUTTON)
		return 0;

	return 1;
}


const u8 * wps_get_uuid_e(const u8 *buf, size_t len)
{
	struct wps_parse_attr attr;
	struct wpabuf msg;

	wpabuf_set(&msg, buf, len);
	if (wps_parse_msg(&msg, &attr) < 0)
		return NULL;
	return attr.uuid_e;
}
