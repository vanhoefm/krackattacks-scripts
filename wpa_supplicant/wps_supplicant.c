/*
 * wpa_supplicant / WPS integration
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
#include "ieee802_11_defs.h"
#include "wpa_common.h"
#include "config.h"
#include "eap_peer/eap.h"
#include "wpa_supplicant_i.h"
#include "wps/wps.h"
#include "wps/wps_defs.h"
#include "wps_supplicant.h"


int wpas_wps_eapol_cb(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPS && wpa_s->current_ssid &&
	    !(wpa_s->current_ssid->key_mgmt & WPA_KEY_MGMT_WPS)) {
		wpa_printf(MSG_DEBUG, "WPS: Network configuration replaced - "
			   "try to associate with the received credential");
		wpa_supplicant_deauthenticate(wpa_s,
					      WLAN_REASON_DEAUTH_LEAVING);
		wpa_s->reassociate = 1;
		wpa_supplicant_req_scan(wpa_s, 0, 0);
		return 1;
	}

	return 0;
}


static int wpa_supplicant_wps_cred(void *ctx,
				   const struct wps_credential *cred)
{
	struct wpa_supplicant *wpa_s = ctx;
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	wpa_msg(wpa_s, MSG_INFO, "WPS: New credential received");

	if (ssid && (ssid->key_mgmt & WPA_KEY_MGMT_WPS)) {
		wpa_printf(MSG_DEBUG, "WPS: Replace WPS network block based "
			   "on the received credential");
		os_free(ssid->eap.identity);
		ssid->eap.identity = NULL;
		ssid->eap.identity_len = 0;
		os_free(ssid->eap.phase1);
		ssid->eap.phase1 = NULL;
		os_free(ssid->eap.eap_methods);
		ssid->eap.eap_methods = NULL;
	} else {
		wpa_printf(MSG_DEBUG, "WPS: Create a new network based on the "
			   "received credential");
		ssid = wpa_config_add_network(wpa_s->conf);
		if (ssid == NULL)
			return -1;
	}

	wpa_config_set_network_defaults(ssid);

	os_free(ssid->ssid);
	ssid->ssid = os_malloc(cred->ssid_len);
	if (ssid->ssid) {
		os_memcpy(ssid->ssid, cred->ssid, cred->ssid_len);
		ssid->ssid_len = cred->ssid_len;
	}

	switch (cred->encr_type) {
	case WPS_ENCR_NONE:
		ssid->pairwise_cipher = ssid->group_cipher = WPA_CIPHER_NONE;
		break;
	case WPS_ENCR_WEP:
		ssid->pairwise_cipher = ssid->group_cipher =
			WPA_CIPHER_WEP40 | WPA_CIPHER_WEP104;
		if (cred->key_len > 0 && cred->key_len <= MAX_WEP_KEY_LEN &&
		    cred->key_idx < NUM_WEP_KEYS) {
			os_memcpy(ssid->wep_key[cred->key_idx], cred->key,
				  cred->key_len);
			ssid->wep_key_len[cred->key_idx] = cred->key_len;
			ssid->wep_tx_keyidx = cred->key_idx;
		}
		break;
	case WPS_ENCR_TKIP:
		ssid->pairwise_cipher = WPA_CIPHER_TKIP;
		ssid->group_cipher = WPA_CIPHER_TKIP;
		break;
	case WPS_ENCR_AES:
		ssid->pairwise_cipher = WPA_CIPHER_CCMP;
		ssid->group_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
		break;
	}

	switch (cred->auth_type) {
	case WPS_AUTH_OPEN:
		ssid->auth_alg = WPA_AUTH_ALG_OPEN;
		ssid->key_mgmt = WPA_KEY_MGMT_NONE;
		ssid->proto = 0;
		break;
	case WPS_AUTH_SHARED:
		ssid->auth_alg = WPA_AUTH_ALG_SHARED;
		ssid->key_mgmt = WPA_KEY_MGMT_NONE;
		ssid->proto = 0;
		break;
	case WPS_AUTH_WPAPSK:
		ssid->auth_alg = WPA_AUTH_ALG_OPEN;
		ssid->key_mgmt = WPA_KEY_MGMT_PSK;
		ssid->proto = WPA_PROTO_WPA;
		break;
	case WPS_AUTH_WPA:
		ssid->auth_alg = WPA_AUTH_ALG_OPEN;
		ssid->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
		ssid->proto = WPA_PROTO_WPA;
		break;
	case WPS_AUTH_WPA2:
		ssid->auth_alg = WPA_AUTH_ALG_OPEN;
		ssid->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
		ssid->proto = WPA_PROTO_RSN;
		break;
	case WPS_AUTH_WPA2PSK:
		ssid->auth_alg = WPA_AUTH_ALG_OPEN;
		ssid->key_mgmt = WPA_KEY_MGMT_PSK;
		ssid->proto = WPA_PROTO_RSN;
		break;
	}

	if (ssid->key_mgmt == WPA_KEY_MGMT_PSK) {
		if (cred->key_len == 2 * PMK_LEN) {
			if (hexstr2bin((const char *) cred->key, ssid->psk,
				       PMK_LEN)) {
				wpa_printf(MSG_ERROR, "WPS: Invalid Network "
					   "Key");
				return -1;
			}
			ssid->psk_set = 1;
		} else if (cred->key_len >= 8 && cred->key_len < 2 * PMK_LEN) {
			os_free(ssid->passphrase);
			ssid->passphrase = os_malloc(cred->key_len + 1);
			if (ssid->passphrase == NULL)
				return -1;
			os_memcpy(ssid->passphrase, cred->key, cred->key_len);
			ssid->passphrase[cred->key_len] = '\0';
			wpa_config_update_psk(ssid);
		} else {
			wpa_printf(MSG_ERROR, "WPS: Invalid Network Key "
				   "length %lu",
				   (unsigned long) cred->key_len);
			return -1;
		}
	}

#ifndef CONFIG_NO_CONFIG_WRITE
	if (wpa_s->conf->update_config &&
	    wpa_config_write(wpa_s->confname, wpa_s->conf)) {
		wpa_printf(MSG_DEBUG, "WPS: Failed to update configuration");
		return -1;
	}
#endif /* CONFIG_NO_CONFIG_WRITE */

	return 0;
}


u8 wpas_wps_get_req_type(struct wpa_ssid *ssid)
{
	if (eap_is_wps_pbc_enrollee(&ssid->eap) ||
	    eap_is_wps_pin_enrollee(&ssid->eap))
		return WPS_REQ_ENROLLEE;
	else
		return WPS_REQ_REGISTRAR;
}


int wpas_wps_init(struct wpa_supplicant *wpa_s)
{
	struct wps_context *wps;

	wps = os_zalloc(sizeof(*wps));
	if (wps == NULL)
		return -1;

	wps->cred_cb = wpa_supplicant_wps_cred;
	wps->cb_ctx = wpa_s;

	/* TODO: make the device data configurable */
	wps->dev.device_name = "dev name";
	wps->dev.manufacturer = "manuf";
	wps->dev.model_name = "model name";
	wps->dev.model_number = "model number";
	wps->dev.serial_number = "12345";
	wps->dev.categ = WPS_DEV_COMPUTER;
	wps->dev.oui = WPS_DEV_OUI_WFA;
	wps->dev.sub_categ = WPS_DEV_COMPUTER_PC;
	wps->dev.os_version = 0;
	wps->dev.rf_bands = WPS_RF_24GHZ | WPS_RF_50GHZ;
	os_memcpy(wps->dev.mac_addr, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(wps->uuid, wpa_s->conf->uuid, 16);

	wpa_s->wps = wps;

	return 0;
}


void wpas_wps_deinit(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->wps == NULL)
		return;

	os_free(wpa_s->wps->network_key);
	os_free(wpa_s->wps);
	wpa_s->wps = NULL;
}
