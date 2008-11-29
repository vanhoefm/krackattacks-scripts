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
#include "ieee802_11_defs.h"


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

	data->state = data->registrar ? RECV_M1 : SEND_M1;

	if (cfg->assoc_wps_ie) {
		struct wps_parse_attr attr;
		wpa_hexdump_buf(MSG_DEBUG, "WPS: WPS IE from (Re)AssocReq",
				cfg->assoc_wps_ie);
		if (wps_parse_msg(cfg->assoc_wps_ie, &attr) < 0) {
			wpa_printf(MSG_DEBUG, "WPS: Failed to parse WPS IE "
				   "from (Re)AssocReq");
		} else if (attr.request_type == NULL) {
			wpa_printf(MSG_DEBUG, "WPS: No Request Type attribute "
				   "in (Re)AssocReq WPS IE");
		} else {
			wpa_printf(MSG_DEBUG, "WPS: Request Type (from WPS IE "
				   "in (Re)AssocReq WPS IE): %d",
				   *attr.request_type);
			data->request_type = *attr.request_type;
		}
	}

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


struct wpabuf * wps_build_assoc_req_ie(void)
{
	struct wpabuf *ie;
	u8 *len;

	wpa_printf(MSG_DEBUG, "WPS: Building WPS IE for (Re)Association "
		   "Request");
	ie = wpabuf_alloc(100);
	if (ie == NULL)
		return NULL;

	wpabuf_put_u8(ie, WLAN_EID_VENDOR_SPECIFIC);
	len = wpabuf_put(ie, 1);
	wpabuf_put_be32(ie, WPS_DEV_OUI_WFA);

	if (wps_build_version(ie) ||
	    wps_build_req_type(ie, WPS_REQ_ENROLLEE)) {
		wpabuf_free(ie);
		return NULL;
	}

	*len = wpabuf_len(ie) - 2;

	return ie;
}


struct wpabuf * wps_build_probe_req_ie(int pbc, struct wps_device_data *dev,
				       const u8 *uuid)
{
	struct wpabuf *ie;
	u8 *len;
	u16 methods;

	wpa_printf(MSG_DEBUG, "WPS: Building WPS IE for Probe Request");

	ie = wpabuf_alloc(200);
	if (ie == NULL)
		return NULL;

	wpabuf_put_u8(ie, WLAN_EID_VENDOR_SPECIFIC);
	len = wpabuf_put(ie, 1);
	wpabuf_put_be32(ie, WPS_DEV_OUI_WFA);

	if (pbc)
		methods = WPS_CONFIG_PUSHBUTTON;
	else
		methods = WPS_CONFIG_LABEL | WPS_CONFIG_DISPLAY |
			WPS_CONFIG_KEYPAD;

	if (wps_build_version(ie) ||
	    wps_build_req_type(ie, WPS_REQ_ENROLLEE) ||
	    wps_build_config_methods(ie, methods) ||
	    wps_build_uuid_e(ie, uuid) ||
	    wps_build_primary_dev_type(dev, ie) ||
	    wps_build_rf_bands(dev, ie) ||
	    wps_build_assoc_state(NULL, ie) ||
	    wps_build_config_error(ie, WPS_CFG_NO_ERROR) ||
	    wps_build_dev_password_id(ie, pbc ? DEV_PW_PUSHBUTTON :
				      DEV_PW_DEFAULT)) {
		wpabuf_free(ie);
		return NULL;
	}

	*len = wpabuf_len(ie) - 2;

	return ie;
}
