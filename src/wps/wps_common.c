/*
 * Wi-Fi Protected Setup - common functionality
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
#include "dh_groups.h"
#include "sha256.h"
#include "aes_wrap.h"
#include "crypto.h"
#include "ieee802_11_defs.h"
#include "wps_i.h"
#include "wps_dev_attr.h"


static int wps_set_attr(struct wps_parse_attr *attr, u16 type,
			const u8 *pos, u16 len)
{
	switch (type) {
	case ATTR_VERSION:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Version length %u",
				   len);
			return -1;
		}
		attr->version = pos;
		break;
	case ATTR_MSG_TYPE:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Message Type "
				   "length %u", len);
			return -1;
		}
		attr->msg_type = pos;
		break;
	case ATTR_ENROLLEE_NONCE:
		if (len != WPS_NONCE_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Enrollee Nonce "
				   "length %u", len);
			return -1;
		}
		attr->enrollee_nonce = pos;
		break;
	case ATTR_REGISTRAR_NONCE:
		if (len != WPS_NONCE_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Registrar Nonce "
				   "length %u", len);
			return -1;
		}
		attr->registrar_nonce = pos;
		break;
	case ATTR_UUID_E:
		if (len != WPS_UUID_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid UUID-E length %u",
				   len);
			return -1;
		}
		attr->uuid_e = pos;
		break;
	case ATTR_UUID_R:
		if (len != WPS_UUID_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid UUID-R length %u",
				   len);
			return -1;
		}
		attr->uuid_r = pos;
		break;
	case ATTR_AUTH_TYPE_FLAGS:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Authentication "
				   "Type Flags length %u", len);
			return -1;
		}
		attr->auth_type_flags = pos;
		break;
	case ATTR_ENCR_TYPE_FLAGS:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Encryption Type "
				   "Flags length %u", len);
			return -1;
		}
		attr->encr_type_flags = pos;
		break;
	case ATTR_CONN_TYPE_FLAGS:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Connection Type "
				   "Flags length %u", len);
			return -1;
		}
		attr->conn_type_flags = pos;
		break;
	case ATTR_CONFIG_METHODS:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Config Methods "
				   "length %u", len);
			return -1;
		}
		attr->config_methods = pos;
		break;
	case ATTR_SELECTED_REGISTRAR_CONFIG_METHODS:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Selected "
				   "Registrar Config Methods length %u", len);
			return -1;
		}
		attr->sel_reg_config_methods = pos;
		break;
	case ATTR_PRIMARY_DEV_TYPE:
		if (len != sizeof(struct wps_dev_type)) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Primary Device "
				   "Type length %u", len);
			return -1;
		}
		attr->primary_dev_type = pos;
		break;
	case ATTR_RF_BANDS:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid RF Bands length "
				   "%u", len);
			return -1;
		}
		attr->rf_bands = pos;
		break;
	case ATTR_ASSOC_STATE:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Association State "
				   "length %u", len);
			return -1;
		}
		attr->assoc_state = pos;
		break;
	case ATTR_CONFIG_ERROR:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Configuration "
				   "Error length %u", len);
			return -1;
		}
		attr->config_error = pos;
		break;
	case ATTR_DEV_PASSWORD_ID:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Device Password "
				   "ID length %u", len);
			return -1;
		}
		attr->dev_password_id = pos;
		break;
	case ATTR_OS_VERSION:
		if (len != 4) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid OS Version length "
				   "%u", len);
			return -1;
		}
		attr->os_version = pos;
		break;
	case ATTR_WPS_STATE:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Wi-Fi Protected "
				   "Setup State length %u", len);
			return -1;
		}
		attr->wps_state = pos;
		break;
	case ATTR_AUTHENTICATOR:
		if (len != WPS_AUTHENTICATOR_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Authenticator "
				   "length %u", len);
			return -1;
		}
		attr->authenticator = pos;
		break;
	case ATTR_R_HASH1:
		if (len != WPS_HASH_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid R-Hash1 length %u",
				   len);
			return -1;
		}
		attr->r_hash1 = pos;
		break;
	case ATTR_R_HASH2:
		if (len != WPS_HASH_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid R-Hash2 length %u",
				   len);
			return -1;
		}
		attr->r_hash2 = pos;
		break;
	case ATTR_E_HASH1:
		if (len != WPS_HASH_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid E-Hash1 length %u",
				   len);
			return -1;
		}
		attr->e_hash1 = pos;
		break;
	case ATTR_E_HASH2:
		if (len != WPS_HASH_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid E-Hash2 length %u",
				   len);
			return -1;
		}
		attr->e_hash2 = pos;
		break;
	case ATTR_R_SNONCE1:
		if (len != WPS_SECRET_NONCE_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid R-SNonce1 length "
				   "%u", len);
			return -1;
		}
		attr->r_snonce1 = pos;
		break;
	case ATTR_R_SNONCE2:
		if (len != WPS_SECRET_NONCE_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid R-SNonce2 length "
				   "%u", len);
			return -1;
		}
		attr->r_snonce2 = pos;
		break;
	case ATTR_E_SNONCE1:
		if (len != WPS_SECRET_NONCE_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid E-SNonce1 length "
				   "%u", len);
			return -1;
		}
		attr->e_snonce1 = pos;
		break;
	case ATTR_E_SNONCE2:
		if (len != WPS_SECRET_NONCE_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid E-SNonce2 length "
				   "%u", len);
			return -1;
		}
		attr->e_snonce2 = pos;
		break;
	case ATTR_KEY_WRAP_AUTH:
		if (len != WPS_KWA_LEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Key Wrap "
				   "Authenticator length %u", len);
			return -1;
		}
		attr->key_wrap_auth = pos;
		break;
	case ATTR_AUTH_TYPE:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Authentication "
				   "Type length %u", len);
			return -1;
		}
		attr->auth_type = pos;
		break;
	case ATTR_ENCR_TYPE:
		if (len != 2) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Encryption "
				   "Type length %u", len);
			return -1;
		}
		attr->encr_type = pos;
		break;
	case ATTR_NETWORK_INDEX:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Network Index "
				   "length %u", len);
			return -1;
		}
		attr->network_idx = pos;
		break;
	case ATTR_NETWORK_KEY_INDEX:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Network Key Index "
				   "length %u", len);
			return -1;
		}
		attr->network_key_idx = pos;
		break;
	case ATTR_MAC_ADDR:
		if (len != ETH_ALEN) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid MAC Address "
				   "length %u", len);
			return -1;
		}
		attr->mac_addr = pos;
		break;
	case ATTR_KEY_PROVIDED_AUTO:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Key Provided "
				   "Automatically length %u", len);
			return -1;
		}
		attr->key_prov_auto = pos;
		break;
	case ATTR_802_1X_ENABLED:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid 802.1X Enabled "
				   "length %u", len);
			return -1;
		}
		attr->dot1x_enabled = pos;
		break;
	case ATTR_SELECTED_REGISTRAR:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Selected Registrar"
				   " length %u", len);
			return -1;
		}
		attr->selected_registrar = pos;
		break;
	case ATTR_REQUEST_TYPE:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Request Type "
				   "length %u", len);
			return -1;
		}
		attr->request_type = pos;
		break;
	case ATTR_RESPONSE_TYPE:
		if (len != 1) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid Response Type "
				   "length %u", len);
			return -1;
		}
		attr->request_type = pos;
		break;
	case ATTR_MANUFACTURER:
		attr->manufacturer = pos;
		attr->manufacturer_len = len;
		break;
	case ATTR_MODEL_NAME:
		attr->model_name = pos;
		attr->model_name_len = len;
		break;
	case ATTR_MODEL_NUMBER:
		attr->model_number = pos;
		attr->model_number_len = len;
		break;
	case ATTR_SERIAL_NUMBER:
		attr->serial_number = pos;
		attr->serial_number_len = len;
		break;
	case ATTR_DEV_NAME:
		attr->dev_name = pos;
		attr->dev_name_len = len;
		break;
	case ATTR_PUBLIC_KEY:
		attr->public_key = pos;
		attr->public_key_len = len;
		break;
	case ATTR_ENCR_SETTINGS:
		attr->encr_settings = pos;
		attr->encr_settings_len = len;
		break;
	case ATTR_CRED:
		if (attr->num_cred >= MAX_CRED_COUNT) {
			wpa_printf(MSG_DEBUG, "WPS: Skipped Credential "
				   "attribute (max %d credentials)",
				   MAX_CRED_COUNT);
			break;
		}
		attr->cred[attr->num_cred] = pos;
		attr->cred_len[attr->num_cred] = len;
		attr->num_cred++;
		break;
	case ATTR_SSID:
		attr->ssid = pos;
		attr->ssid_len = len;
		break;
	case ATTR_NETWORK_KEY:
		attr->network_key = pos;
		attr->network_key_len = len;
		break;
	case ATTR_EAP_TYPE:
		attr->eap_type = pos;
		attr->eap_type_len = len;
		break;
	case ATTR_EAP_IDENTITY:
		attr->eap_identity = pos;
		attr->eap_identity_len = len;
		break;
	default:
		wpa_printf(MSG_DEBUG, "WPS: Unsupported attribute type 0x%x "
			   "len=%u", type, len);
		break;
	}

	return 0;
}


int wps_parse_msg(const struct wpabuf *msg, struct wps_parse_attr *attr)
{
	const u8 *pos, *end;
	u16 type, len;

	os_memset(attr, 0, sizeof(*attr));
	pos = wpabuf_head(msg);
	end = pos + wpabuf_len(msg);

	while (pos < end) {
		if (end - pos < 4) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid message - "
				   "%lu bytes remaining",
				   (unsigned long) (end - pos));
			return -1;
		}

		type = WPA_GET_BE16(pos);
		pos += 2;
		len = WPA_GET_BE16(pos);
		pos += 2;
		wpa_printf(MSG_MSGDUMP, "WPS: attr type=0x%x len=%u",
			   type, len);
		if (len > end - pos) {
			wpa_printf(MSG_DEBUG, "WPS: Attribute overflow");
			return -1;
		}

		if (wps_set_attr(attr, type, pos, len) < 0)
			return -1;

		pos += len;
	}

	return 0;
}


void wps_kdf(const u8 *key, const u8 *label_prefix, size_t label_prefix_len,
	     const char *label, u8 *res, size_t res_len)
{
	u8 i_buf[4], key_bits[4];
	const u8 *addr[4];
	size_t len[4];
	int i, iter;
	u8 hash[SHA256_MAC_LEN], *opos;
	size_t left;

	WPA_PUT_BE32(key_bits, res_len * 8);

	addr[0] = i_buf;
	len[0] = sizeof(i_buf);
	addr[1] = label_prefix;
	len[1] = label_prefix_len;
	addr[2] = (const u8 *) label;
	len[2] = os_strlen(label);
	addr[3] = key_bits;
	len[3] = sizeof(key_bits);

	iter = (res_len + SHA256_MAC_LEN - 1) / SHA256_MAC_LEN;
	opos = res;
	left = res_len;

	for (i = 1; i <= iter; i++) {
		WPA_PUT_BE32(i_buf, i);
		hmac_sha256_vector(key, SHA256_MAC_LEN, 4, addr, len, hash);
		if (i < iter) {
			os_memcpy(opos, hash, SHA256_MAC_LEN);
			opos += SHA256_MAC_LEN;
			left -= SHA256_MAC_LEN;
		} else
			os_memcpy(opos, hash, left);
	}
}


int wps_build_public_key(struct wps_data *wps, struct wpabuf *msg)
{
	struct wpabuf *pubkey;

	wpa_printf(MSG_DEBUG, "WPS:  * Public Key");
	pubkey = dh_init(dh_groups_get(WPS_DH_GROUP), &wps->dh_privkey);
	if (pubkey == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Failed to initialize "
			   "Diffie-Hellman handshake");
		return -1;
	}

	wpabuf_put_be16(msg, ATTR_PUBLIC_KEY);
	wpabuf_put_be16(msg, wpabuf_len(pubkey));
	wpabuf_put_buf(msg, pubkey);

	if (wps->registrar) {
		wpabuf_free(wps->dh_pubkey_r);
		wps->dh_pubkey_r = pubkey;
	} else {
		wpabuf_free(wps->dh_pubkey_e);
		wps->dh_pubkey_e = pubkey;
	}

	return 0;
}


static int wps_build_req_type(struct wpabuf *msg, enum wps_request_type type)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Request Type");
	wpabuf_put_be16(msg, ATTR_REQUEST_TYPE);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, type);
	return 0;
}


int wps_build_config_methods(struct wpabuf *msg, u16 methods)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Config Methods (%x)", methods);
	wpabuf_put_be16(msg, ATTR_CONFIG_METHODS);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, methods);
	return 0;
}


int wps_build_uuid_e(struct wpabuf *msg, const u8 *uuid)
{
	wpa_printf(MSG_DEBUG, "WPS:  * UUID-E");
	wpabuf_put_be16(msg, ATTR_UUID_E);
	wpabuf_put_be16(msg, WPS_UUID_LEN);
	wpabuf_put_data(msg, uuid, WPS_UUID_LEN);
	return 0;
}


int wps_build_dev_password_id(struct wpabuf *msg, u16 id)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Device Password ID (%d)", id);
	wpabuf_put_be16(msg, ATTR_DEV_PASSWORD_ID);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, id);
	return 0;
}


int wps_build_config_error(struct wpabuf *msg, u16 err)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Configuration Error (%d)", err);
	wpabuf_put_be16(msg, ATTR_CONFIG_ERROR);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, err);
	return 0;
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


int wps_derive_keys(struct wps_data *wps)
{
	struct wpabuf *pubkey, *dh_shared;
	u8 dhkey[SHA256_MAC_LEN], kdk[SHA256_MAC_LEN];
	const u8 *addr[3];
	size_t len[3];
	u8 keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];

	if (wps->dh_privkey == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Own DH private key not available");
		return -1;
	}

	pubkey = wps->registrar ? wps->dh_pubkey_e : wps->dh_pubkey_r;
	if (pubkey == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Peer DH public key not available");
		return -1;
	}

	dh_shared = dh_derive_shared(pubkey, wps->dh_privkey,
				     dh_groups_get(WPS_DH_GROUP));
	if (dh_shared == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Failed to derive DH shared key");
		return -1;
	}

	/* Own DH private key is not needed anymore */
	wpabuf_free(wps->dh_privkey);
	wps->dh_privkey = NULL;

	wpa_hexdump_buf_key(MSG_DEBUG, "WPS: DH shared key", dh_shared);

	/* DHKey = SHA-256(g^AB mod p) */
	addr[0] = wpabuf_head(dh_shared);
	len[0] = wpabuf_len(dh_shared);
	sha256_vector(1, addr, len, dhkey);
	wpa_hexdump_key(MSG_DEBUG, "WPS: DHKey", dhkey, sizeof(dhkey));
	wpabuf_free(dh_shared);

	/* KDK = HMAC-SHA-256_DHKey(N1 || EnrolleeMAC || N2) */
	addr[0] = wps->nonce_e;
	len[0] = WPS_NONCE_LEN;
	addr[1] = wps->mac_addr_e;
	len[1] = ETH_ALEN;
	addr[2] = wps->nonce_r;
	len[2] = WPS_NONCE_LEN;
	hmac_sha256_vector(dhkey, sizeof(dhkey), 3, addr, len, kdk);
	wpa_hexdump_key(MSG_DEBUG, "WPS: KDK", kdk, sizeof(kdk));

	wps_kdf(kdk, NULL, 0, "Wi-Fi Easy and Secure Key Derivation",
		keys, sizeof(keys));
	os_memcpy(wps->authkey, keys, WPS_AUTHKEY_LEN);
	os_memcpy(wps->keywrapkey, keys + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
	os_memcpy(wps->emsk, keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN,
		  WPS_EMSK_LEN);

	wpa_hexdump_key(MSG_DEBUG, "WPS: AuthKey",
			wps->authkey, WPS_AUTHKEY_LEN);
	wpa_hexdump_key(MSG_DEBUG, "WPS: KeyWrapKey",
			wps->keywrapkey, WPS_KEYWRAPKEY_LEN);
	wpa_hexdump_key(MSG_DEBUG, "WPS: EMSK", wps->emsk, WPS_EMSK_LEN);

	return 0;
}


int wps_derive_mgmt_keys(struct wps_data *wps)
{
	u8 nonces[2 * WPS_NONCE_LEN];
	u8 keys[WPS_MGMTAUTHKEY_LEN + WPS_MGMTENCKEY_LEN];
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[2];
	size_t len[2];
	const char *auth_label = "WFA-WLAN-Management-MgmtAuthKey";
	const char *enc_label = "WFA-WLAN-Management-MgmtEncKey";

	/* MgmtAuthKey || MgmtEncKey =
	 * kdf(EMSK, N1 || N2 || "WFA-WLAN-Management-Keys", 384) */
	os_memcpy(nonces, wps->nonce_e, WPS_NONCE_LEN);
	os_memcpy(nonces + WPS_NONCE_LEN, wps->nonce_r, WPS_NONCE_LEN);
	wps_kdf(wps->emsk, nonces, sizeof(nonces), "WFA-WLAN-Management-Keys",
		keys, sizeof(keys));
	os_memcpy(wps->mgmt_auth_key, keys, WPS_MGMTAUTHKEY_LEN);
	os_memcpy(wps->mgmt_enc_key, keys + WPS_MGMTAUTHKEY_LEN,
		  WPS_MGMTENCKEY_LEN);

	addr[0] = nonces;
	len[0] = sizeof(nonces);

	/* MgmtEncKeyID = first 128 bits of
	 * SHA-256(N1 || N2 || "WFA-WLAN-Management-MgmtAuthKey") */
	addr[1] = (const u8 *) auth_label;
	len[1] = os_strlen(auth_label);
	sha256_vector(2, addr, len, hash);
	os_memcpy(wps->mgmt_auth_key_id, hash, WPS_MGMT_KEY_ID_LEN);

	/* MgmtEncKeyID = first 128 bits of
	 * SHA-256(N1 || N2 || "WFA-WLAN-Management-MgmtEncKey") */
	addr[1] = (const u8 *) enc_label;
	len[1] = os_strlen(enc_label);
	sha256_vector(2, addr, len, hash);
	os_memcpy(wps->mgmt_enc_key_id, hash, WPS_MGMT_KEY_ID_LEN);

	wpa_hexdump_key(MSG_DEBUG, "WPS: MgmtAuthKey",
			wps->mgmt_auth_key, WPS_MGMTAUTHKEY_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: MgmtAuthKeyID",
		    wps->mgmt_auth_key_id, WPS_MGMT_KEY_ID_LEN);
	wpa_hexdump_key(MSG_DEBUG, "WPS: MgmtEncKey",
			wps->mgmt_enc_key, WPS_MGMTENCKEY_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: MgmtEncKeyID",
		    wps->mgmt_enc_key_id, WPS_MGMT_KEY_ID_LEN);

	return 0;
}


int wps_build_authenticator(struct wps_data *wps, struct wpabuf *msg)
{
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[2];
	size_t len[2];

	if (wps->last_msg == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Last message not available for "
			   "building authenticator");
		return -1;
	}

	/* Authenticator = HMAC-SHA256_AuthKey(M_prev || M_curr*)
	 * (M_curr* is M_curr without the Authenticator attribute)
	 */
	addr[0] = wpabuf_head(wps->last_msg);
	len[0] = wpabuf_len(wps->last_msg);
	addr[1] = wpabuf_head(msg);
	len[1] = wpabuf_len(msg);
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 2, addr, len, hash);

	wpa_printf(MSG_DEBUG, "WPS:  * Authenticator");
	wpabuf_put_be16(msg, ATTR_AUTHENTICATOR);
	wpabuf_put_be16(msg, WPS_AUTHENTICATOR_LEN);
	wpabuf_put_data(msg, hash, WPS_AUTHENTICATOR_LEN);

	return 0;
}


int wps_process_authenticator(struct wps_data *wps, const u8 *authenticator,
			      const struct wpabuf *msg)
{
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[2];
	size_t len[2];

	if (authenticator == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Authenticator attribute "
			   "included");
		return -1;
	}

	if (wps->last_msg == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Last message not available for "
			   "validating authenticator");
		return -1;
	}

	/* Authenticator = HMAC-SHA256_AuthKey(M_prev || M_curr*)
	 * (M_curr* is M_curr without the Authenticator attribute)
	 */
	addr[0] = wpabuf_head(wps->last_msg);
	len[0] = wpabuf_len(wps->last_msg);
	addr[1] = wpabuf_head(msg);
	len[1] = wpabuf_len(msg) - 4 - WPS_AUTHENTICATOR_LEN;
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 2, addr, len, hash);

	if (os_memcmp(hash, authenticator, WPS_AUTHENTICATOR_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: Incorrect Authenticator");
		return -1;
	}

	return 0;
}


void wps_derive_psk(struct wps_data *wps, const u8 *dev_passwd,
		    size_t dev_passwd_len)
{
	u8 hash[SHA256_MAC_LEN];

	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, dev_passwd,
		    (dev_passwd_len + 1) / 2, hash);
	os_memcpy(wps->psk1, hash, WPS_PSK_LEN);
	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN,
		    dev_passwd + (dev_passwd_len + 1) / 2,
		    dev_passwd_len / 2, hash);
	os_memcpy(wps->psk2, hash, WPS_PSK_LEN);

	wpa_hexdump_ascii_key(MSG_DEBUG, "WPS: Device Password",
			      dev_passwd, dev_passwd_len);
	wpa_hexdump_key(MSG_DEBUG, "WPS: PSK1", wps->psk1, WPS_PSK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "WPS: PSK2", wps->psk2, WPS_PSK_LEN);
}


struct wpabuf * wps_decrypt_encr_settings(struct wps_data *wps, const u8 *encr,
					  size_t encr_len)
{
	struct wpabuf *decrypted;
	const size_t block_size = 16;
	size_t i;
	u8 pad;
	const u8 *pos;

	/* AES-128-CBC */
	if (encr == NULL || encr_len < 2 * block_size || encr_len % block_size)
	{
		wpa_printf(MSG_DEBUG, "WPS: No Encrypted Settings received");
		return NULL;
	}

	decrypted = wpabuf_alloc(encr_len - block_size);
	if (decrypted == NULL)
		return NULL;

	wpa_hexdump(MSG_MSGDUMP, "WPS: Encrypted Settings", encr, encr_len);
	wpabuf_put_data(decrypted, encr + block_size, encr_len - block_size);
	if (aes_128_cbc_decrypt(wps->keywrapkey, encr, wpabuf_mhead(decrypted),
				wpabuf_len(decrypted))) {
		wpabuf_free(decrypted);
		return NULL;
	}

	wpa_hexdump_buf_key(MSG_MSGDUMP, "WPS: Decrypted Encrypted Settings",
			    decrypted);

	pos = wpabuf_head_u8(decrypted) + wpabuf_len(decrypted) - 1;
	pad = *pos;
	if (pad > wpabuf_len(decrypted)) {
		wpa_printf(MSG_DEBUG, "WPS: Invalid PKCS#5 v2.0 pad value");
		wpabuf_free(decrypted);
		return NULL;
	}
	for (i = 0; i < pad; i++) {
		if (*pos-- != pad) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid PKCS#5 v2.0 pad "
				   "string");
			wpabuf_free(decrypted);
			return NULL;
		}
	}
	decrypted->used -= pad;

	return decrypted;
}


int wps_process_key_wrap_auth(struct wps_data *wps, struct wpabuf *msg,
			      const u8 *key_wrap_auth)
{
	u8 hash[SHA256_MAC_LEN];
	const u8 *head;
	size_t len;

	if (key_wrap_auth == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No KWA in decrypted attribute");
		return -1;
	}

	head = wpabuf_head(msg);
	len = wpabuf_len(msg) - 4 - WPS_KWA_LEN;
	if (head + len != key_wrap_auth - 4) {
		wpa_printf(MSG_DEBUG, "WPS: KWA not in the end of the "
			   "decrypted attribute");
		return -1;
	}

	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, head, len, hash);
	if (os_memcmp(hash, key_wrap_auth, WPS_KWA_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: Invalid KWA");
		return -1;
	}

	return 0;
}


int wps_build_version(struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Version");
	wpabuf_put_be16(msg, ATTR_VERSION);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, WPS_VERSION);
	return 0;
}


int wps_build_msg_type(struct wpabuf *msg, enum wps_msg_type msg_type)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Message Type (%d)", msg_type);
	wpabuf_put_be16(msg, ATTR_MSG_TYPE);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, msg_type);
	return 0;
}


int wps_build_enrollee_nonce(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Enrollee Nonce");
	wpabuf_put_be16(msg, ATTR_ENROLLEE_NONCE);
	wpabuf_put_be16(msg, WPS_NONCE_LEN);
	wpabuf_put_data(msg, wps->nonce_e, WPS_NONCE_LEN);
	return 0;
}


int wps_build_registrar_nonce(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Registrar Nonce");
	wpabuf_put_be16(msg, ATTR_REGISTRAR_NONCE);
	wpabuf_put_be16(msg, WPS_NONCE_LEN);
	wpabuf_put_data(msg, wps->nonce_r, WPS_NONCE_LEN);
	return 0;
}


int wps_build_auth_type_flags(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Authentication Type Flags");
	wpabuf_put_be16(msg, ATTR_AUTH_TYPE_FLAGS);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, WPS_AUTH_TYPES);
	return 0;
}


int wps_build_encr_type_flags(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Encryption Type Flags");
	wpabuf_put_be16(msg, ATTR_ENCR_TYPE_FLAGS);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, WPS_ENCR_TYPES);
	return 0;
}


int wps_build_conn_type_flags(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Connection Type Flags");
	wpabuf_put_be16(msg, ATTR_CONN_TYPE_FLAGS);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, WPS_CONN_ESS);
	return 0;
}


int wps_build_assoc_state(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Association State");
	wpabuf_put_be16(msg, ATTR_ASSOC_STATE);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, WPS_ASSOC_NOT_ASSOC);
	return 0;
}


int wps_build_key_wrap_auth(struct wps_data *wps, struct wpabuf *msg)
{
	u8 hash[SHA256_MAC_LEN];

	wpa_printf(MSG_DEBUG, "WPS:  * Key Wrap Authenticator");
	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, wpabuf_head(msg),
		    wpabuf_len(msg), hash);

	wpabuf_put_be16(msg, ATTR_KEY_WRAP_AUTH);
	wpabuf_put_be16(msg, WPS_KWA_LEN);
	wpabuf_put_data(msg, hash, WPS_KWA_LEN);
	return 0;
}


int wps_build_encr_settings(struct wps_data *wps, struct wpabuf *msg,
			    struct wpabuf *plain)
{
	size_t pad_len;
	const size_t block_size = 16;
	u8 *iv, *data;

	wpa_printf(MSG_DEBUG, "WPS:  * Encrypted Settings");

	/* PKCS#5 v2.0 pad */
	pad_len = block_size - wpabuf_len(plain) % block_size;
	os_memset(wpabuf_put(plain, pad_len), pad_len, pad_len);

	wpabuf_put_be16(msg, ATTR_ENCR_SETTINGS);
	wpabuf_put_be16(msg, block_size + wpabuf_len(plain));

	iv = wpabuf_put(msg, block_size);
	if (os_get_random(iv, block_size) < 0)
		return -1;

	data = wpabuf_put(msg, 0);
	wpabuf_put_buf(msg, plain);
	if (aes_128_cbc_encrypt(wps->keywrapkey, iv, data, wpabuf_len(plain)))
		return -1;

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


int wps_process_cred(struct wps_parse_attr *attr,
		     struct wps_credential *cred)
{
	wpa_printf(MSG_DEBUG, "WPS: Process Credential");

	/* TODO: support multiple Network Keys */
	if (wps_process_cred_network_idx(cred, attr->network_idx) ||
	    wps_process_cred_ssid(cred, attr->ssid, attr->ssid_len) ||
	    wps_process_cred_auth_type(cred, attr->auth_type) ||
	    wps_process_cred_encr_type(cred, attr->encr_type) ||
	    wps_process_cred_network_key_idx(cred, attr->network_key_idx) ||
	    wps_process_cred_network_key(cred, attr->network_key,
					 attr->network_key_len) ||
	    wps_process_cred_mac_addr(cred, attr->mac_addr) ||
	    wps_process_cred_eap_type(cred, attr->eap_type,
				      attr->eap_type_len) ||
	    wps_process_cred_eap_identity(cred, attr->eap_identity,
					  attr->eap_identity_len) ||
	    wps_process_cred_key_prov_auto(cred, attr->key_prov_auto) ||
	    wps_process_cred_802_1x_enabled(cred, attr->dot1x_enabled))
		return -1;

	return 0;
}


int wps_process_ap_settings(struct wps_parse_attr *attr,
			    struct wps_credential *cred)
{
	wpa_printf(MSG_DEBUG, "WPS: Processing AP Settings");
	os_memset(cred, 0, sizeof(*cred));
	/* TODO: optional attributes New Password and Device Password ID */
	if (wps_process_cred_ssid(cred, attr->ssid, attr->ssid_len) ||
	    wps_process_cred_auth_type(cred, attr->auth_type) ||
	    wps_process_cred_encr_type(cred, attr->encr_type) ||
	    wps_process_cred_network_key_idx(cred, attr->network_key_idx) ||
	    wps_process_cred_network_key(cred, attr->network_key,
					 attr->network_key_len) ||
	    wps_process_cred_mac_addr(cred, attr->mac_addr))
		return -1;

	return 0;
}
