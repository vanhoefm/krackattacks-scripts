/*
 * Wi-Fi Protected Setup - Enrollee
 * Copyright (c) 2008, Jouni Malinen <j@w1.fi>
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
#include "sha256.h"
#include "ieee802_11_defs.h"
#include "wps_i.h"


static int wps_build_req_type(struct wpabuf *msg, enum wps_request_type type)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Request Type");
	wpabuf_put_be16(msg, ATTR_REQUEST_TYPE);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, type);
	return 0;
}


static int wps_build_uuid_e(struct wpabuf *msg, const u8 *uuid)
{
	wpa_printf(MSG_DEBUG, "WPS:  * UUID-E");
	wpabuf_put_be16(msg, ATTR_UUID_E);
	wpabuf_put_be16(msg, WPS_UUID_LEN);
	wpabuf_put_data(msg, uuid, WPS_UUID_LEN);
	return 0;
}


static int wps_build_mac_addr(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * MAC Address");
	wpabuf_put_be16(msg, ATTR_MAC_ADDR);
	wpabuf_put_be16(msg, ETH_ALEN);
	wpabuf_put_data(msg, wps->mac_addr_e, ETH_ALEN);
	return 0;
}


static int wps_build_config_methods(struct wpabuf *msg, u16 methods)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Config Methods");
	wpabuf_put_be16(msg, ATTR_CONFIG_METHODS);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, methods);
	return 0;
}


static int wps_build_wps_state(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Wi-Fi Protected Setup State");
	wpabuf_put_be16(msg, ATTR_WPS_STATE);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, WPS_STATE_CONFIGURED);
	return 0;
}


static int wps_build_manufacturer(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Manufacturer");
	wpabuf_put_be16(msg, ATTR_MANUFACTURER);
	wpabuf_put_be16(msg, 5);
	wpabuf_put_data(msg, "manuf", 5); /* FIX */
	return 0;
}


static int wps_build_model_name(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Model Name");
	wpabuf_put_be16(msg, ATTR_MODEL_NAME);
	wpabuf_put_be16(msg, 10);
	wpabuf_put_data(msg, "model name", 10); /* FIX */
	return 0;
}


static int wps_build_model_number(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Model Number");
	wpabuf_put_be16(msg, ATTR_MODEL_NUMBER);
	wpabuf_put_be16(msg, 12);
	wpabuf_put_data(msg, "model number", 12); /* FIX */
	return 0;
}


static int wps_build_serial_number(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Serial Number");
	wpabuf_put_be16(msg, ATTR_SERIAL_NUMBER);
	wpabuf_put_be16(msg, 5);
	wpabuf_put_data(msg, "12345", 5); /* FIX */
	return 0;
}


static int wps_build_primary_dev_type(struct wps_data *wps, struct wpabuf *msg)
{
	struct wps_dev_type *dev;
	wpa_printf(MSG_DEBUG, "WPS:  * Primary Device Type");
	wpabuf_put_be16(msg, ATTR_PRIMARY_DEV_TYPE);
	wpabuf_put_be16(msg, sizeof(*dev));
	dev = wpabuf_put(msg, sizeof(*dev));
	WPA_PUT_BE16(dev->categ_id, WPS_DEV_COMPUTER);
	WPA_PUT_BE32(dev->oui, WPS_DEV_OUI_WFA);
	WPA_PUT_BE16(dev->sub_categ_id, WPS_DEV_COMPUTER_PC);
	return 0;
}


static int wps_build_dev_name(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Device Name");
	wpabuf_put_be16(msg, ATTR_DEV_NAME);
	wpabuf_put_be16(msg, 8);
	wpabuf_put_data(msg, "dev name", 8); /* FIX */
	return 0;
}


static int wps_build_rf_bands(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * RF Bands");
	wpabuf_put_be16(msg, ATTR_RF_BANDS);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, WPS_RF_24GHZ | WPS_RF_50GHZ);
	return 0;
}


static int wps_build_dev_password_id(struct wpabuf *msg, u16 id)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Device Password ID");
	wpabuf_put_be16(msg, ATTR_DEV_PASSWORD_ID);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, id);
	return 0;
}


static int wps_build_config_error(struct wps_data *wps, struct wpabuf *msg)
{
	u16 err = WPS_CFG_NO_ERROR;
	wpabuf_put_be16(msg, ATTR_CONFIG_ERROR);
	wpabuf_put_be16(msg, 2);
	if (wps && wps->authenticator && wps->wps->ap_setup_locked)
		err = WPS_CFG_SETUP_LOCKED;
	wpa_printf(MSG_DEBUG, "WPS:  * Configuration Error (%d)", err);
	wpabuf_put_be16(msg, err);
	return 0;
}


static int wps_build_os_version(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * OS Version");
	wpabuf_put_be16(msg, ATTR_OS_VERSION);
	wpabuf_put_be16(msg, 4);
	wpabuf_put_be32(msg, 0x80000000); /* FIX */
	return 0;
}


static int wps_build_e_hash(struct wps_data *wps, struct wpabuf *msg)
{
	u8 *hash;
	const u8 *addr[4];
	size_t len[4];

	if (os_get_random(wps->snonce, 2 * WPS_SECRET_NONCE_LEN) < 0)
		return -1;
	wpa_hexdump(MSG_DEBUG, "WPS: E-S1", wps->snonce, WPS_SECRET_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: E-S2",
		    wps->snonce + WPS_SECRET_NONCE_LEN, WPS_SECRET_NONCE_LEN);

	if (wps->dh_pubkey_e == NULL || wps->dh_pubkey_r == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: DH public keys not available for "
			   "E-Hash derivation");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS:  * E-Hash1");
	wpabuf_put_be16(msg, ATTR_E_HASH1);
	wpabuf_put_be16(msg, SHA256_MAC_LEN);
	hash = wpabuf_put(msg, SHA256_MAC_LEN);
	/* E-Hash1 = HMAC_AuthKey(E-S1 || PSK1 || PK_E || PK_R) */
	addr[0] = wps->snonce;
	len[0] = WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk1;
	len[1] = WPS_PSK_LEN;
	addr[2] = wpabuf_head(wps->dh_pubkey_e);
	len[2] = wpabuf_len(wps->dh_pubkey_e);
	addr[3] = wpabuf_head(wps->dh_pubkey_r);
	len[3] = wpabuf_len(wps->dh_pubkey_r);
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);
	wpa_hexdump(MSG_DEBUG, "WPS: E-Hash1", hash, SHA256_MAC_LEN);

	wpa_printf(MSG_DEBUG, "WPS:  * E-Hash2");
	wpabuf_put_be16(msg, ATTR_E_HASH2);
	wpabuf_put_be16(msg, SHA256_MAC_LEN);
	hash = wpabuf_put(msg, SHA256_MAC_LEN);
	/* E-Hash2 = HMAC_AuthKey(E-S2 || PSK2 || PK_E || PK_R) */
	addr[0] = wps->snonce + WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk2;
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);
	wpa_hexdump(MSG_DEBUG, "WPS: E-Hash2", hash, SHA256_MAC_LEN);

	return 0;
}


static int wps_build_e_snonce1(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * E-SNonce1");
	wpabuf_put_be16(msg, ATTR_E_SNONCE1);
	wpabuf_put_be16(msg, WPS_SECRET_NONCE_LEN);
	wpabuf_put_data(msg, wps->snonce, WPS_SECRET_NONCE_LEN);
	return 0;
}


static int wps_build_e_snonce2(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * E-SNonce2");
	wpabuf_put_be16(msg, ATTR_E_SNONCE2);
	wpabuf_put_be16(msg, WPS_SECRET_NONCE_LEN);
	wpabuf_put_data(msg, wps->snonce + WPS_SECRET_NONCE_LEN,
			WPS_SECRET_NONCE_LEN);
	return 0;
}


static struct wpabuf * wps_build_m1(struct wps_data *wps)
{
	struct wpabuf *msg;
	u16 methods;

	if (os_get_random(wps->nonce_e, WPS_NONCE_LEN) < 0)
		return NULL;
	wpa_hexdump(MSG_DEBUG, "WPS: Enrollee Nonce",
		    wps->nonce_e, WPS_NONCE_LEN);

	wpa_printf(MSG_DEBUG, "WPS: Building Message M1");
	msg = wpabuf_alloc(1000);
	if (msg == NULL)
		return NULL;

	methods = WPS_CONFIG_LABEL | WPS_CONFIG_DISPLAY | WPS_CONFIG_KEYPAD;
	if (wps->pbc)
		methods |= WPS_CONFIG_PUSHBUTTON;

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M1) ||
	    wps_build_uuid_e(msg, wps->uuid_e) ||
	    wps_build_mac_addr(wps, msg) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_public_key(wps, msg) ||
	    wps_build_auth_type_flags(wps, msg) ||
	    wps_build_encr_type_flags(wps, msg) ||
	    wps_build_conn_type_flags(wps, msg) ||
	    wps_build_config_methods(msg, methods) ||
	    wps_build_wps_state(wps, msg) ||
	    wps_build_manufacturer(wps, msg) ||
	    wps_build_model_name(wps, msg) ||
	    wps_build_model_number(wps, msg) ||
	    wps_build_serial_number(wps, msg) ||
	    wps_build_primary_dev_type(wps, msg) ||
	    wps_build_dev_name(wps, msg) ||
	    wps_build_rf_bands(wps, msg) ||
	    wps_build_assoc_state(wps, msg) ||
	    wps_build_dev_password_id(msg, wps->dev_pw_id) ||
	    wps_build_config_error(wps, msg) ||
	    wps_build_os_version(wps, msg)) {
		wpabuf_free(msg);
		return NULL;
	}

	wps->state = RECV_M2;
	return msg;
}


static struct wpabuf * wps_build_m3(struct wps_data *wps)
{
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "WPS: Building Message M3");

	if (wps->dev_password == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Device Password available");
		return NULL;
	}
	wps_derive_psk(wps, wps->dev_password, wps->dev_password_len);

	msg = wpabuf_alloc(1000);
	if (msg == NULL)
		return NULL;

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M3) ||
	    wps_build_registrar_nonce(wps, msg) ||
	    wps_build_e_hash(wps, msg) ||
	    wps_build_authenticator(wps, msg)) {
		wpabuf_free(msg);
		return NULL;
	}

	wps->state = RECV_M4;
	return msg;
}


static struct wpabuf * wps_build_m5(struct wps_data *wps)
{
	struct wpabuf *msg, *plain;

	wpa_printf(MSG_DEBUG, "WPS: Building Message M5");

	plain = wpabuf_alloc(200);
	if (plain == NULL)
		return NULL;

	msg = wpabuf_alloc(1000);
	if (msg == NULL) {
		wpabuf_free(plain);
		return NULL;
	}

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M5) ||
	    wps_build_registrar_nonce(wps, msg) ||
	    wps_build_e_snonce1(wps, plain) ||
	    wps_build_key_wrap_auth(wps, plain) ||
	    wps_build_encr_settings(wps, msg, plain) ||
	    wps_build_authenticator(wps, msg)) {
		wpabuf_free(plain);
		wpabuf_free(msg);
		return NULL;
	}
	wpabuf_free(plain);

	wps->state = RECV_M6;
	return msg;
}


static int wps_build_cred_ssid(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * SSID");
	wpabuf_put_be16(msg, ATTR_SSID);
	wpabuf_put_be16(msg, wps->wps->ssid_len);
	wpabuf_put_data(msg, wps->wps->ssid, wps->wps->ssid_len);
	return 0;
}


static int wps_build_cred_auth_type(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Authentication Type");
	wpabuf_put_be16(msg, ATTR_AUTH_TYPE);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, wps->wps->auth_types);
	return 0;
}


static int wps_build_cred_encr_type(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Encryption Type");
	wpabuf_put_be16(msg, ATTR_ENCR_TYPE);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, wps->wps->encr_types);
	return 0;
}


static int wps_build_cred_network_key(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Network Key");
	wpabuf_put_be16(msg, ATTR_NETWORK_KEY);
	wpabuf_put_be16(msg, wps->wps->network_key_len);
	wpabuf_put_data(msg, wps->wps->network_key, wps->wps->network_key_len);
	return 0;
}


static int wps_build_cred_mac_addr(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * MAC Address (AP BSSID)");
	wpabuf_put_be16(msg, ATTR_MAC_ADDR);
	wpabuf_put_be16(msg, ETH_ALEN);
	wpabuf_put_data(msg, wps->wps->dev.mac_addr, ETH_ALEN);
	return 0;
}


static struct wpabuf * wps_build_m7(struct wps_data *wps)
{
	struct wpabuf *msg, *plain;

	wpa_printf(MSG_DEBUG, "WPS: Building Message M7");

	plain = wpabuf_alloc(500);
	if (plain == NULL)
		return NULL;

	msg = wpabuf_alloc(1000);
	if (msg == NULL) {
		wpabuf_free(plain);
		return NULL;
	}

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M7) ||
	    wps_build_registrar_nonce(wps, msg) ||
	    wps_build_e_snonce2(wps, plain) ||
	    (wps->authenticator &&
	     (wps_build_cred_ssid(wps, plain) ||
	      wps_build_cred_mac_addr(wps, plain) ||
	      wps_build_cred_auth_type(wps, plain) ||
	      wps_build_cred_encr_type(wps, plain) ||
	      wps_build_cred_network_key(wps, plain))) ||
	    wps_build_key_wrap_auth(wps, plain) ||
	    wps_build_encr_settings(wps, msg, plain) ||
	    wps_build_authenticator(wps, msg)) {
		wpabuf_free(plain);
		wpabuf_free(msg);
		return NULL;
	}
	wpabuf_free(plain);

	wps->state = RECV_M8;
	return msg;
}


static struct wpabuf * wps_build_wsc_done(struct wps_data *wps)
{
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "WPS: Building Message WSC_Done");

	msg = wpabuf_alloc(1000);
	if (msg == NULL)
		return NULL;

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_WSC_DONE) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_registrar_nonce(wps, msg)) {
		wpabuf_free(msg);
		return NULL;
	}

	wps->state = wps->authenticator ? RECV_ACK : WPS_FINISHED;
	return msg;
}


static struct wpabuf * wps_build_wsc_ack(struct wps_data *wps)
{
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "WPS: Building Message WSC_ACK");

	msg = wpabuf_alloc(1000);
	if (msg == NULL)
		return NULL;

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_WSC_ACK) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_registrar_nonce(wps, msg)) {
		wpabuf_free(msg);
		return NULL;
	}

	return msg;
}


static struct wpabuf * wps_build_wsc_nack(struct wps_data *wps)
{
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "WPS: Building Message WSC_NACK");

	msg = wpabuf_alloc(1000);
	if (msg == NULL)
		return NULL;

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_WSC_NACK) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_registrar_nonce(wps, msg) ||
	    wps_build_config_error(wps, msg)) {
		wpabuf_free(msg);
		return NULL;
	}

	return msg;
}


struct wpabuf * wps_enrollee_get_msg(struct wps_data *wps, u8 *op_code)
{
	struct wpabuf *msg;

	switch (wps->state) {
	case SEND_M1:
		msg = wps_build_m1(wps);
		*op_code = WSC_MSG;
		break;
	case SEND_M3:
		msg = wps_build_m3(wps);
		*op_code = WSC_MSG;
		break;
	case SEND_M5:
		msg = wps_build_m5(wps);
		*op_code = WSC_MSG;
		break;
	case SEND_M7:
		msg = wps_build_m7(wps);
		*op_code = WSC_MSG;
		break;
	case RECEIVED_M2D:
		msg = wps_build_wsc_ack(wps);
		*op_code = WSC_ACK;
		if (msg) {
			/* Another M2/M2D may be received */
			wps->state = RECV_M2;
		}
		break;
	case SEND_WSC_NACK:
		msg = wps_build_wsc_nack(wps);
		*op_code = WSC_NACK;
		break;
	case WPS_MSG_DONE:
		msg = wps_build_wsc_done(wps);
		*op_code = WSC_Done;
		break;
	default:
		wpa_printf(MSG_DEBUG, "WPS: Unsupported state %d for building "
			   "a message", wps->state);
		msg = NULL;
		break;
	}

	if (*op_code == WSC_MSG && msg) {
		/* Save a copy of the last message for Authenticator derivation
		 */
		wpabuf_free(wps->last_msg);
		wps->last_msg = wpabuf_dup(msg);
	}

	return msg;
}


static int wps_process_registrar_nonce(struct wps_data *wps, const u8 *r_nonce)
{
	if (r_nonce == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Registrar Nonce received");
		return -1;
	}

	os_memcpy(wps->nonce_r, r_nonce, WPS_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: Registrar Nonce",
		    wps->nonce_r, WPS_NONCE_LEN);

	return 0;
}


static int wps_process_enrollee_nonce(struct wps_data *wps, const u8 *e_nonce)
{
	if (e_nonce == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Enrollee Nonce received");
		return -1;
	}

	if (os_memcmp(wps->nonce_e, e_nonce, WPS_NONCE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: Invalid Enrollee Nonce received");
		return -1;
	}

	return 0;
}


static int wps_process_uuid_r(struct wps_data *wps, const u8 *uuid_r)
{
	if (uuid_r == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No UUID-R received");
		return -1;
	}

	os_memcpy(wps->uuid_r, uuid_r, WPS_UUID_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: UUID-R", wps->uuid_r, WPS_UUID_LEN);

	return 0;
}


static int wps_process_pubkey(struct wps_data *wps, const u8 *pk,
			      size_t pk_len)
{
	if (pk == NULL || pk_len == 0) {
		wpa_printf(MSG_DEBUG, "WPS: No Public Key received");
		return -1;
	}

	wpabuf_free(wps->dh_pubkey_r);
	wps->dh_pubkey_r = wpabuf_alloc_copy(pk, pk_len);
	if (wps->dh_pubkey_r == NULL)
		return -1;

	return wps_derive_keys(wps);
}


static int wps_process_r_hash1(struct wps_data *wps, const u8 *r_hash1)
{
	if (r_hash1 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No R-Hash1 received");
		return -1;
	}

	os_memcpy(wps->peer_hash1, r_hash1, WPS_HASH_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: R-Hash1", wps->peer_hash1, WPS_HASH_LEN);

	return 0;
}


static int wps_process_r_hash2(struct wps_data *wps, const u8 *r_hash2)
{
	if (r_hash2 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No R-Hash2 received");
		return -1;
	}

	os_memcpy(wps->peer_hash2, r_hash2, WPS_HASH_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: R-Hash2", wps->peer_hash2, WPS_HASH_LEN);

	return 0;
}


static int wps_process_r_snonce1(struct wps_data *wps, const u8 *r_snonce1)
{
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[4];
	size_t len[4];

	if (r_snonce1 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No R-SNonce1 received");
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "WPS: R-SNonce1", r_snonce1,
			WPS_SECRET_NONCE_LEN);

	/* R-Hash1 = HMAC_AuthKey(R-S1 || PSK1 || PK_E || PK_R) */
	addr[0] = r_snonce1;
	len[0] = WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk1;
	len[1] = WPS_PSK_LEN;
	addr[2] = wpabuf_head(wps->dh_pubkey_e);
	len[2] = wpabuf_len(wps->dh_pubkey_e);
	addr[3] = wpabuf_head(wps->dh_pubkey_r);
	len[3] = wpabuf_len(wps->dh_pubkey_r);
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);

	if (os_memcmp(wps->peer_hash1, hash, WPS_HASH_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: R-Hash1 derived from R-S1 does "
			   "not match with the pre-committed value");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Registrar proved knowledge of the first "
		   "half of the device password");

	return 0;
}


static int wps_process_r_snonce2(struct wps_data *wps, const u8 *r_snonce2)
{
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[4];
	size_t len[4];

	if (r_snonce2 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No R-SNonce2 received");
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "WPS: R-SNonce2", r_snonce2,
			WPS_SECRET_NONCE_LEN);

	/* R-Hash2 = HMAC_AuthKey(R-S2 || PSK2 || PK_E || PK_R) */
	addr[0] = r_snonce2;
	len[0] = WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk2;
	len[1] = WPS_PSK_LEN;
	addr[2] = wpabuf_head(wps->dh_pubkey_e);
	len[2] = wpabuf_len(wps->dh_pubkey_e);
	addr[3] = wpabuf_head(wps->dh_pubkey_r);
	len[3] = wpabuf_len(wps->dh_pubkey_r);
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);

	if (os_memcmp(wps->peer_hash2, hash, WPS_HASH_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: R-Hash2 derived from R-S2 does "
			   "not match with the pre-committed value");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Registrar proved knowledge of the second "
		   "half of the device password");

	return 0;
}


static int wps_process_cred_network_idx(struct wps_credential *cred,
					const u8 *idx)
{
	if (idx == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Credential did not include "
			   "Network Index");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Network Index: %d", *idx);

	return 0;
}


static int wps_process_cred_ssid(struct wps_credential *cred, const u8 *ssid,
				 size_t ssid_len)
{
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Credential did not include SSID");
		return -1;
	}

	/* Remove zero-padding since some Registrar implementations seem to use
	 * hardcoded 32-octet length for this attribute */
	while (ssid_len > 0 && ssid[ssid_len - 1] == 0)
		ssid_len--;

	wpa_hexdump_ascii(MSG_DEBUG, "WPS: SSID", ssid, ssid_len);
	if (ssid_len <= sizeof(cred->ssid)) {
		os_memcpy(cred->ssid, ssid, ssid_len);
		cred->ssid_len = ssid_len;
	}

	return 0;
}


static int wps_process_cred_auth_type(struct wps_credential *cred,
				      const u8 *auth_type)
{
	if (auth_type == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Credential did not include "
			   "Authentication Type");
		return -1;
	}

	cred->auth_type = WPA_GET_BE16(auth_type);
	wpa_printf(MSG_DEBUG, "WPS: Authentication Type: 0x%x",
		   cred->auth_type);

	return 0;
}


static int wps_process_cred_encr_type(struct wps_credential *cred,
				      const u8 *encr_type)
{
	if (encr_type == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Credential did not include "
			   "Encryption Type");
		return -1;
	}

	cred->encr_type = WPA_GET_BE16(encr_type);
	wpa_printf(MSG_DEBUG, "WPS: Encryption Type: 0x%x",
		   cred->encr_type);

	return 0;
}


static int wps_process_cred_network_key_idx(struct wps_credential *cred,
					    const u8 *key_idx)
{
	if (key_idx == NULL)
		return 0; /* optional attribute */

	wpa_printf(MSG_DEBUG, "WPS: Network Key Index: %d", *key_idx);
	cred->key_idx = *key_idx;

	return 0;
}


static int wps_process_cred_network_key(struct wps_credential *cred,
					const u8 *key, size_t key_len)
{
	if (key == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Credential did not include "
			   "Network Key");
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "WPS: Network Key", key, key_len);
	if (key_len <= sizeof(cred->key)) {
		os_memcpy(cred->key, key, key_len);
		cred->key_len = key_len;
	}

	return 0;
}


static int wps_process_cred_mac_addr(struct wps_credential *cred,
				     const u8 *mac_addr)
{
	if (mac_addr == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Credential did not include "
			   "MAC Address");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: MAC Address " MACSTR, MAC2STR(mac_addr));
	os_memcpy(cred->mac_addr, mac_addr, ETH_ALEN);

	return 0;
}


static int wps_process_cred_eap_type(struct wps_credential *cred,
				     const u8 *eap_type, size_t eap_type_len)
{
	if (eap_type == NULL)
		return 0; /* optional attribute */

	wpa_hexdump(MSG_DEBUG, "WPS: EAP Type", eap_type, eap_type_len);

	return 0;
}


static int wps_process_cred_eap_identity(struct wps_credential *cred,
					 const u8 *identity,
					 size_t identity_len)
{
	if (identity == NULL)
		return 0; /* optional attribute */

	wpa_hexdump_ascii(MSG_DEBUG, "WPS: EAP Identity",
			  identity, identity_len);

	return 0;
}


static int wps_process_cred_key_prov_auto(struct wps_credential *cred,
					  const u8 *key_prov_auto)
{
	if (key_prov_auto == NULL)
		return 0; /* optional attribute */

	wpa_printf(MSG_DEBUG, "WPS: Key Provided Automatically: %d",
		   *key_prov_auto);

	return 0;
}


static int wps_process_cred_802_1x_enabled(struct wps_credential *cred,
					   const u8 *dot1x_enabled)
{
	if (dot1x_enabled == NULL)
		return 0; /* optional attribute */

	wpa_printf(MSG_DEBUG, "WPS: 802.1X Enabled: %d", *dot1x_enabled);

	return 0;
}


static int wps_process_cred(struct wps_data *wps, const u8 *cred,
			    size_t cred_len)
{
	struct wps_parse_attr attr;
	struct wpabuf msg;

	wpa_printf(MSG_DEBUG, "WPS: Received Credential");
	os_memset(&wps->cred, 0, sizeof(wps->cred));
	wpabuf_set(&msg, cred, cred_len);
	/* TODO: support multiple Network Keys */
	if (wps_parse_msg(&msg, &attr) < 0 ||
	    wps_process_cred_network_idx(&wps->cred, attr.network_idx) ||
	    wps_process_cred_ssid(&wps->cred, attr.ssid, attr.ssid_len) ||
	    wps_process_cred_auth_type(&wps->cred, attr.auth_type) ||
	    wps_process_cred_encr_type(&wps->cred, attr.encr_type) ||
	    wps_process_cred_network_key_idx(&wps->cred, attr.network_key_idx)
	    ||
	    wps_process_cred_network_key(&wps->cred, attr.network_key,
					 attr.network_key_len) ||
	    wps_process_cred_mac_addr(&wps->cred, attr.mac_addr) ||
	    wps_process_cred_eap_type(&wps->cred, attr.eap_type,
				      attr.eap_type_len) ||
	    wps_process_cred_eap_identity(&wps->cred, attr.eap_identity,
					  attr.eap_identity_len) ||
	    wps_process_cred_key_prov_auto(&wps->cred, attr.key_prov_auto) ||
	    wps_process_cred_802_1x_enabled(&wps->cred, attr.dot1x_enabled))
		return -1;

	if (wps->wps_cred_cb)
		wps->wps_cred_cb(wps->cb_ctx, &wps->cred);

	return 0;
}


static int wps_process_creds(struct wps_data *wps, const u8 *cred[],
			     size_t cred_len[], size_t num_cred)
{
	size_t i;

	if (wps->authenticator)
		return 0;

	if (num_cred == 0) {
		wpa_printf(MSG_DEBUG, "WPS: No Credential attributes "
			   "received");
		return -1;
	}

	for (i = 0; i < num_cred; i++) {
		if (wps_process_cred(wps, cred[i], cred_len[i]))
			return -1;
	}

	return 0;
}


static int wps_process_ap_settings(struct wps_data *wps,
				   struct wps_parse_attr *attr)
{
	struct wps_credential cred;

	if (!wps->authenticator)
		return 0;

	wpa_printf(MSG_DEBUG, "WPS: Processing AP Settings");
	os_memset(&cred, 0, sizeof(cred));
	/* TODO: optional attributes New Password and Device Password ID */
	if (wps_process_cred_ssid(&cred, attr->ssid, attr->ssid_len) ||
	    wps_process_cred_auth_type(&cred, attr->auth_type) ||
	    wps_process_cred_encr_type(&cred, attr->encr_type) ||
	    wps_process_cred_network_key_idx(&cred, attr->network_key_idx) ||
	    wps_process_cred_network_key(&cred, attr->network_key,
					 attr->network_key_len) ||
	    wps_process_cred_mac_addr(&cred, attr->mac_addr))
		return -1;

	wpa_printf(MSG_INFO, "WPS: Received new AP configuration from "
		   "Registrar");

	if (wps->wps->cred_cb)
		wps->wps->cred_cb(wps->wps->cb_ctx, &cred);

	return 0;
}


static enum wps_process_res wps_process_m2(struct wps_data *wps,
					   const struct wpabuf *msg,
					   struct wps_parse_attr *attr)
{
	wpa_printf(MSG_DEBUG, "WPS: Received M2");

	if (wps->state != RECV_M2) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M2", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_registrar_nonce(wps, attr->registrar_nonce) ||
	    wps_process_enrollee_nonce(wps, attr->enrollee_nonce) ||
	    wps_process_uuid_r(wps, attr->uuid_r) ||
	    wps_process_pubkey(wps, attr->public_key, attr->public_key_len) ||
	    wps_process_authenticator(wps, attr->authenticator, msg))
		return WPS_FAILURE;

	if (wps->authenticator && wps->wps->ap_setup_locked) {
		wpa_printf(MSG_DEBUG, "WPS: AP Setup is locked - refuse "
			   "registration of a new Registrar");
		wps->state = SEND_WSC_NACK;
		return WPS_CONTINUE;
	}

	wps->state = SEND_M3;
	return WPS_CONTINUE;
}


static enum wps_process_res wps_process_m2d(struct wps_data *wps,
					    struct wps_parse_attr *attr)
{
	wpa_printf(MSG_DEBUG, "WPS: Received M2D");

	if (wps->state != RECV_M2) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M2D", wps->state);
		return WPS_FAILURE;
	}

	wpa_hexdump_ascii(MSG_DEBUG, "WPS: Manufacturer",
			  attr->manufacturer, attr->manufacturer_len);
	wpa_hexdump_ascii(MSG_DEBUG, "WPS: Model Name",
			  attr->model_name, attr->model_name_len);
	wpa_hexdump_ascii(MSG_DEBUG, "WPS: Model Number",
			  attr->model_number, attr->model_number_len);
	wpa_hexdump_ascii(MSG_DEBUG, "WPS: Serial Number",
			  attr->serial_number, attr->serial_number_len);
	wpa_hexdump_ascii(MSG_DEBUG, "WPS: Device Name",
			  attr->dev_name, attr->dev_name_len);

	/*
	 * TODO: notify monitor programs (cli/gui/etc.) of the M2D and provide
	 * user information about the registrar properties.
	 */

	wps->state = RECEIVED_M2D;
	return WPS_FAILURE;
}


static enum wps_process_res wps_process_m4(struct wps_data *wps,
					   const struct wpabuf *msg,
					   struct wps_parse_attr *attr)
{
	struct wpabuf *decrypted;
	struct wps_parse_attr eattr;

	wpa_printf(MSG_DEBUG, "WPS: Received M4");

	if (wps->state != RECV_M4) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M4", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_enrollee_nonce(wps, attr->enrollee_nonce) ||
	    wps_process_authenticator(wps, attr->authenticator, msg) ||
	    wps_process_r_hash1(wps, attr->r_hash1) ||
	    wps_process_r_hash2(wps, attr->r_hash2))
		return WPS_FAILURE;

	decrypted = wps_decrypt_encr_settings(wps, attr->encr_settings,
					      attr->encr_settings_len);
	if (decrypted == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Failed to decrypted Encrypted "
			   "Settings attribute");
		return WPS_FAILURE;
	}

	wpa_printf(MSG_DEBUG, "WPS: Processing decrypted Encrypted Settings "
		   "attribute");
	if (wps_parse_msg(decrypted, &eattr) < 0 ||
	    wps_process_key_wrap_auth(wps, decrypted, eattr.key_wrap_auth) ||
	    wps_process_r_snonce1(wps, eattr.r_snonce1)) {
		wpabuf_free(decrypted);
		return WPS_FAILURE;
	}
	wpabuf_free(decrypted);

	wps->state = SEND_M5;
	return WPS_CONTINUE;
}


static enum wps_process_res wps_process_m6(struct wps_data *wps,
					   const struct wpabuf *msg,
					   struct wps_parse_attr *attr)
{
	struct wpabuf *decrypted;
	struct wps_parse_attr eattr;

	wpa_printf(MSG_DEBUG, "WPS: Received M6");

	if (wps->state != RECV_M6) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M6", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_enrollee_nonce(wps, attr->enrollee_nonce) ||
	    wps_process_authenticator(wps, attr->authenticator, msg))
		return WPS_FAILURE;

	decrypted = wps_decrypt_encr_settings(wps, attr->encr_settings,
					      attr->encr_settings_len);
	if (decrypted == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Failed to decrypted Encrypted "
			   "Settings attribute");
		return WPS_FAILURE;
	}

	wpa_printf(MSG_DEBUG, "WPS: Processing decrypted Encrypted Settings "
		   "attribute");
	if (wps_parse_msg(decrypted, &eattr) < 0 ||
	    wps_process_key_wrap_auth(wps, decrypted, eattr.key_wrap_auth) ||
	    wps_process_r_snonce2(wps, eattr.r_snonce2)) {
		wpabuf_free(decrypted);
		return WPS_FAILURE;
	}
	wpabuf_free(decrypted);

	wps->state = SEND_M7;
	return WPS_CONTINUE;
}


static enum wps_process_res wps_process_m8(struct wps_data *wps,
					   const struct wpabuf *msg,
					   struct wps_parse_attr *attr)
{
	struct wpabuf *decrypted;
	struct wps_parse_attr eattr;

	wpa_printf(MSG_DEBUG, "WPS: Received M8");

	if (wps->state != RECV_M8) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M8", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_enrollee_nonce(wps, attr->enrollee_nonce) ||
	    wps_process_authenticator(wps, attr->authenticator, msg))
		return WPS_FAILURE;

	decrypted = wps_decrypt_encr_settings(wps, attr->encr_settings,
					      attr->encr_settings_len);
	if (decrypted == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Failed to decrypted Encrypted "
			   "Settings attribute");
		return WPS_FAILURE;
	}

	wpa_printf(MSG_DEBUG, "WPS: Processing decrypted Encrypted Settings "
		   "attribute");
	if (wps_parse_msg(decrypted, &eattr) < 0 ||
	    wps_process_key_wrap_auth(wps, decrypted, eattr.key_wrap_auth) ||
	    wps_process_creds(wps, eattr.cred, eattr.cred_len,
			      eattr.num_cred) ||
	    wps_process_ap_settings(wps, &eattr)) {
		wpabuf_free(decrypted);
		return WPS_FAILURE;
	}
	wpabuf_free(decrypted);

	wps->state = WPS_MSG_DONE;
	return WPS_CONTINUE;
}


static enum wps_process_res wps_process_wsc_msg(struct wps_data *wps,
						const struct wpabuf *msg)
{
	struct wps_parse_attr attr;
	enum wps_process_res ret = WPS_CONTINUE;

	wpa_printf(MSG_DEBUG, "WPS: Received WSC_MSG");

	if (wps_parse_msg(msg, &attr) < 0)
		return WPS_FAILURE;

	if (attr.version == NULL || *attr.version != WPS_VERSION) {
		wpa_printf(MSG_DEBUG, "WPS: Unsupported message version 0x%x",
			   attr.version ? *attr.version : 0);
		return WPS_FAILURE;
	}

	if (attr.enrollee_nonce == NULL ||
	    os_memcmp(wps->nonce_e, attr.enrollee_nonce, WPS_NONCE_LEN != 0)) {
		wpa_printf(MSG_DEBUG, "WPS: Mismatch in enrollee nonce");
		return WPS_FAILURE;
	}

	if (attr.msg_type == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Message Type attribute");
		return WPS_FAILURE;
	}

	switch (*attr.msg_type) {
	case WPS_M2:
		ret = wps_process_m2(wps, msg, &attr);
		break;
	case WPS_M2D:
		ret = wps_process_m2d(wps, &attr);
		break;
	case WPS_M4:
		ret = wps_process_m4(wps, msg, &attr);
		break;
	case WPS_M6:
		ret = wps_process_m6(wps, msg, &attr);
		break;
	case WPS_M8:
		ret = wps_process_m8(wps, msg, &attr);
		break;
	default:
		wpa_printf(MSG_DEBUG, "WPS: Unsupported Message Type %d",
			   *attr.msg_type);
		return WPS_FAILURE;
	}

	if (ret == WPS_CONTINUE) {
		/* Save a copy of the last message for Authenticator derivation
		 */
		wpabuf_free(wps->last_msg);
		wps->last_msg = wpabuf_dup(msg);
	}

	return ret;
}


static enum wps_process_res wps_process_wsc_ack(struct wps_data *wps,
						const struct wpabuf *msg)
{
	struct wps_parse_attr attr;

	wpa_printf(MSG_DEBUG, "WPS: Received WSC_ACK");

	if (wps_parse_msg(msg, &attr) < 0)
		return WPS_FAILURE;

	if (attr.version == NULL || *attr.version != WPS_VERSION) {
		wpa_printf(MSG_DEBUG, "WPS: Unsupported message version 0x%x",
			   attr.version ? *attr.version : 0);
		return WPS_FAILURE;
	}

	if (attr.msg_type == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Message Type attribute");
		return WPS_FAILURE;
	}

	if (*attr.msg_type != WPS_WSC_ACK) {
		wpa_printf(MSG_DEBUG, "WPS: Invalid Message Type %d",
			   *attr.msg_type);
		return WPS_FAILURE;
	}

	if (attr.registrar_nonce == NULL ||
	    os_memcmp(wps->nonce_r, attr.registrar_nonce, WPS_NONCE_LEN != 0))
	{
		wpa_printf(MSG_DEBUG, "WPS: Mismatch in registrar nonce");
		return WPS_FAILURE;
	}

	if (attr.enrollee_nonce == NULL ||
	    os_memcmp(wps->nonce_e, attr.enrollee_nonce, WPS_NONCE_LEN != 0)) {
		wpa_printf(MSG_DEBUG, "WPS: Mismatch in enrollee nonce");
		return WPS_FAILURE;
	}

	if (wps->state == RECV_ACK && wps->authenticator) {
		wpa_printf(MSG_DEBUG, "WPS: External Registrar registration "
			   "completed successfully");
		wps->state = WPS_FINISHED;
		return WPS_DONE;
	}

	return WPS_FAILURE;
}


static enum wps_process_res wps_process_wsc_nack(struct wps_data *wps,
						 const struct wpabuf *msg)
{
	struct wps_parse_attr attr;

	wpa_printf(MSG_DEBUG, "WPS: Received WSC_NACK");

	if (wps_parse_msg(msg, &attr) < 0)
		return WPS_FAILURE;

	if (attr.version == NULL || *attr.version != WPS_VERSION) {
		wpa_printf(MSG_DEBUG, "WPS: Unsupported message version 0x%x",
			   attr.version ? *attr.version : 0);
		return WPS_FAILURE;
	}

	if (attr.msg_type == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Message Type attribute");
		return WPS_FAILURE;
	}

	if (*attr.msg_type != WPS_WSC_NACK) {
		wpa_printf(MSG_DEBUG, "WPS: Invalid Message Type %d",
			   *attr.msg_type);
		return WPS_FAILURE;
	}

	if (attr.registrar_nonce == NULL ||
	    os_memcmp(wps->nonce_r, attr.registrar_nonce, WPS_NONCE_LEN != 0))
	{
		wpa_printf(MSG_DEBUG, "WPS: Mismatch in registrar nonce");
		wpa_hexdump(MSG_DEBUG, "WPS: Received Registrar Nonce",
			    attr.registrar_nonce, WPS_NONCE_LEN);
		wpa_hexdump(MSG_DEBUG, "WPS: Expected Registrar Nonce",
			    wps->nonce_r, WPS_NONCE_LEN);
		return WPS_FAILURE;
	}

	if (attr.enrollee_nonce == NULL ||
	    os_memcmp(wps->nonce_e, attr.enrollee_nonce, WPS_NONCE_LEN != 0)) {
		wpa_printf(MSG_DEBUG, "WPS: Mismatch in enrollee nonce");
		wpa_hexdump(MSG_DEBUG, "WPS: Received Enrollee Nonce",
			    attr.enrollee_nonce, WPS_NONCE_LEN);
		wpa_hexdump(MSG_DEBUG, "WPS: Expected Enrollee Nonce",
			    wps->nonce_e, WPS_NONCE_LEN);
		return WPS_FAILURE;
	}

	if (attr.config_error == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Configuration Error attribute "
			   "in WSC_NACK");
		return WPS_FAILURE;
	}

	wpa_printf(MSG_DEBUG, "WPS: Enrollee terminated negotiation with "
		   "Configuration Error %d", WPA_GET_BE16(attr.config_error));

	return WPS_FAILURE;
}


enum wps_process_res wps_enrollee_process_msg(struct wps_data *wps, u8 op_code,
					      const struct wpabuf *msg)
{

	wpa_printf(MSG_DEBUG, "WPS: Processing received message (len=%lu "
		   "op_code=%d)",
		   (unsigned long) wpabuf_len(msg), op_code);

	switch (op_code) {
	case WSC_MSG:
		return wps_process_wsc_msg(wps, msg);
	case WSC_ACK:
		return wps_process_wsc_ack(wps, msg);
	case WSC_NACK:
		return wps_process_wsc_nack(wps, msg);
	default:
		wpa_printf(MSG_DEBUG, "WPS: Unsupported op_code %d", op_code);
		return WPS_FAILURE;
	}
}


struct wpabuf * wps_enrollee_build_assoc_req_ie(void)
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


struct wpabuf * wps_enrollee_build_probe_req_ie(int pbc, const u8 *uuid)
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
	    wps_build_primary_dev_type(NULL, ie) ||
	    wps_build_rf_bands(NULL, ie) ||
	    wps_build_assoc_state(NULL, ie) ||
	    wps_build_config_error(NULL, ie) ||
	    wps_build_dev_password_id(ie, pbc ? DEV_PW_PUSHBUTTON :
				      DEV_PW_DEFAULT)) {
		wpabuf_free(ie);
		return NULL;
	}

	*len = wpabuf_len(ie) - 2;

	return ie;
}
