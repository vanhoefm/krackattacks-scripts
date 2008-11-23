/*
 * Wi-Fi Protected Setup - Registrar
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
#include "base64.h"
#include "ieee802_11_defs.h"
#include "eloop.h"
#include "wps_i.h"
#include "wps_dev_attr.h"


struct wps_uuid_pin {
	struct wps_uuid_pin *next;
	u8 uuid[WPS_UUID_LEN];
	u8 *pin;
	size_t pin_len;
	int locked;
};


static void wps_free_pin(struct wps_uuid_pin *pin)
{
	os_free(pin->pin);
	os_free(pin);
}


static void wps_free_pins(struct wps_uuid_pin *pins)
{
	struct wps_uuid_pin *pin, *prev;

	pin = pins;
	while (pin) {
		prev = pin;
		pin = pin->next;
		wps_free_pin(prev);
	}
}


struct wps_pbc_session {
	struct wps_pbc_session *next;
	u8 addr[ETH_ALEN];
	u8 uuid_e[WPS_UUID_LEN];
	struct os_time timestamp;
};


static void wps_free_pbc_sessions(struct wps_pbc_session *pbc)
{
	struct wps_pbc_session *prev;

	while (pbc) {
		prev = pbc;
		pbc = pbc->next;
		os_free(prev);
	}
}


struct wps_registrar {
	struct wps_context *wps;

	int pbc;
	int selected_registrar;

	int (*new_psk_cb)(void *ctx, const u8 *mac_addr, const u8 *psk,
			  size_t psk_len);
	int (*set_ie_cb)(void *ctx, const u8 *beacon_ie, size_t beacon_ie_len,
			 const u8 *probe_resp_ie, size_t probe_resp_ie_len);
	void (*pin_needed_cb)(void *ctx, const u8 *uuid_e,
			      const struct wps_device_data *dev);
	void *cb_ctx;

	struct wps_uuid_pin *pins;
	struct wps_pbc_session *pbc_sessions;
};


static int wps_set_ie(struct wps_registrar *reg);
static void wps_registrar_pbc_timeout(void *eloop_ctx, void *timeout_ctx);


static void wps_registrar_add_pbc_session(struct wps_registrar *reg,
					  const u8 *addr, const u8 *uuid_e)
{
	struct wps_pbc_session *pbc, *prev = NULL;
	struct os_time now;

	os_get_time(&now);

	pbc = reg->pbc_sessions;
	while (pbc) {
		if (os_memcmp(pbc->addr, addr, ETH_ALEN) == 0 &&
		    os_memcmp(pbc->uuid_e, uuid_e, WPS_UUID_LEN) == 0) {
			if (prev)
				prev->next = pbc->next;
			else
				reg->pbc_sessions = pbc->next;
			break;
		}
		prev = pbc;
		pbc = pbc->next;
	}

	if (!pbc) {
		pbc = os_zalloc(sizeof(*pbc));
		if (pbc == NULL)
			return;
		os_memcpy(pbc->addr, addr, ETH_ALEN);
		if (uuid_e)
			os_memcpy(pbc->uuid_e, uuid_e, WPS_UUID_LEN);
	}

	pbc->next = reg->pbc_sessions;
	reg->pbc_sessions = pbc;
	pbc->timestamp = now;

	/* remove entries that have timed out */
	prev = pbc;
	pbc = pbc->next;

	while (pbc) {
		if (now.sec > pbc->timestamp.sec + WPS_PBC_WALK_TIME) {
			prev->next = NULL;
			wps_free_pbc_sessions(pbc);
			break;
		}
		prev = pbc;
		pbc = pbc->next;
	}
}


static void wps_registrar_remove_pbc_session(struct wps_registrar *reg,
					     const u8 *addr, const u8 *uuid_e)
{
	struct wps_pbc_session *pbc, *prev = NULL;

	pbc = reg->pbc_sessions;
	while (pbc) {
		if (os_memcmp(pbc->addr, addr, ETH_ALEN) == 0 &&
		    os_memcmp(pbc->uuid_e, uuid_e, WPS_UUID_LEN) == 0) {
			if (prev)
				prev->next = pbc->next;
			else
				reg->pbc_sessions = pbc->next;
			os_free(pbc);
			break;
		}
		prev = pbc;
		pbc = pbc->next;
	}
}


int wps_registrar_pbc_overlap(struct wps_registrar *reg,
			      const u8 *addr, const u8 *uuid_e)
{
	int count = 0;
	struct wps_pbc_session *pbc;
	struct os_time now;

	os_get_time(&now);

	for (pbc = reg->pbc_sessions; pbc; pbc = pbc->next) {
		if (now.sec > pbc->timestamp.sec + WPS_PBC_WALK_TIME)
			break;
		if (addr == NULL || os_memcmp(addr, pbc->addr, ETH_ALEN) ||
		    uuid_e == NULL ||
		    os_memcmp(uuid_e, pbc->uuid_e, WPS_UUID_LEN))
			count++;
	}

	if (addr || uuid_e)
		count++;

	return count > 1 ? 1 : 0;
}


static int wps_build_wps_state(struct wps_context *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Wi-Fi Protected Setup State (%d)",
		   wps->wps_state);
	wpabuf_put_be16(msg, ATTR_WPS_STATE);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, wps->wps_state);
	return 0;
}


static int wps_build_ap_setup_locked(struct wps_context *wps,
				     struct wpabuf *msg)
{
	if (wps->ap_setup_locked) {
		wpa_printf(MSG_DEBUG, "WPS:  * AP Setup Locked");
		wpabuf_put_be16(msg, ATTR_AP_SETUP_LOCKED);
		wpabuf_put_be16(msg, 1);
		wpabuf_put_u8(msg, 1);
	}
	return 0;
}


static int wps_build_selected_registrar(struct wps_registrar *reg,
					struct wpabuf *msg)
{
	if (!reg->selected_registrar)
		return 0;
	wpa_printf(MSG_DEBUG, "WPS:  * Selected Registrar");
	wpabuf_put_be16(msg, ATTR_SELECTED_REGISTRAR);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, 1);
	return 0;
}


static int wps_build_sel_reg_dev_password_id(struct wps_registrar *reg,
					     struct wpabuf *msg)
{
	u16 id = reg->pbc ? DEV_PW_PUSHBUTTON : DEV_PW_DEFAULT;
	if (!reg->selected_registrar)
		return 0;
	wpa_printf(MSG_DEBUG, "WPS:  * Device Password ID (%d)", id);
	wpabuf_put_be16(msg, ATTR_DEV_PASSWORD_ID);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, id);
	return 0;
}


static int wps_build_sel_reg_config_methods(struct wps_registrar *reg,
					    struct wpabuf *msg)
{
	u16 methods;
	if (!reg->selected_registrar)
		return 0;
	methods = reg->wps->config_methods & ~WPS_CONFIG_PUSHBUTTON;
	if (reg->pbc)
		methods |= WPS_CONFIG_PUSHBUTTON;
	wpa_printf(MSG_DEBUG, "WPS:  * Selected Registrar Config Methods (%x)",
		   methods);
	wpabuf_put_be16(msg, ATTR_SELECTED_REGISTRAR_CONFIG_METHODS);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, methods);
	return 0;
}


static int wps_build_probe_config_methods(struct wps_registrar *reg,
					  struct wpabuf *msg)
{
	u16 methods;
	methods = 0;
	wpa_printf(MSG_DEBUG, "WPS:  * Config Methods (%x)", methods);
	wpabuf_put_be16(msg, ATTR_CONFIG_METHODS);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, methods);
	return 0;
}


static int wps_build_config_methods(struct wps_registrar *reg,
				    struct wpabuf *msg)
{
	u16 methods;
	methods = reg->wps->config_methods & ~WPS_CONFIG_PUSHBUTTON;
	if (reg->pbc)
		methods |= WPS_CONFIG_PUSHBUTTON;
	wpa_printf(MSG_DEBUG, "WPS:  * Config Methods (%x)", methods);
	wpabuf_put_be16(msg, ATTR_CONFIG_METHODS);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, methods);
	return 0;
}


static int wps_build_rf_bands(struct wps_registrar *reg, struct wpabuf *msg)
{
	u8 bands = WPS_RF_24GHZ /* TODO: | WPS_RF_50GHZ */;
	wpa_printf(MSG_DEBUG, "WPS:  * RF Bands (%x)", bands);
	wpabuf_put_be16(msg, ATTR_RF_BANDS);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, bands);
	return 0;
}


static int wps_build_uuid_e(struct wps_registrar *reg, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * UUID-E");
	wpabuf_put_be16(msg, ATTR_UUID_E);
	wpabuf_put_be16(msg, WPS_UUID_LEN);
	wpabuf_put_data(msg, reg->wps->uuid, WPS_UUID_LEN);
	return 0;
}


static int wps_build_resp_type(struct wps_registrar *reg, struct wpabuf *msg)
{
	u8 resp = reg->wps->ap ? WPS_RESP_AP : WPS_RESP_REGISTRAR;
	wpa_printf(MSG_DEBUG, "WPS:  * Response Type (%d)", resp);
	wpabuf_put_be16(msg, ATTR_RESPONSE_TYPE);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, resp);
	return 0;
}


struct wps_registrar *
wps_registrar_init(struct wps_context *wps,
		   const struct wps_registrar_config *cfg)
{
	struct wps_registrar *reg = os_zalloc(sizeof(*reg));
	if (reg == NULL)
		return NULL;

	reg->wps = wps;
	reg->new_psk_cb = cfg->new_psk_cb;
	reg->set_ie_cb = cfg->set_ie_cb;
	reg->pin_needed_cb = cfg->pin_needed_cb;
	reg->cb_ctx = cfg->cb_ctx;

	if (wps_set_ie(reg)) {
		wps_registrar_deinit(reg);
		return NULL;
	}

	return reg;
}


void wps_registrar_deinit(struct wps_registrar *reg)
{
	if (reg == NULL)
		return;
	eloop_cancel_timeout(wps_registrar_pbc_timeout, reg, NULL);
	wps_free_pins(reg->pins);
	wps_free_pbc_sessions(reg->pbc_sessions);
	os_free(reg);
}


int wps_registrar_add_pin(struct wps_registrar *reg, const u8 *uuid,
			  const u8 *pin, size_t pin_len)
{
	struct wps_uuid_pin *p;

	p = os_zalloc(sizeof(*p));
	if (p == NULL)
		return -1;
	os_memcpy(p->uuid, uuid, WPS_UUID_LEN);
	p->pin = os_malloc(pin_len);
	if (p->pin == NULL) {
		os_free(p);
		return -1;
	}
	os_memcpy(p->pin, pin, pin_len);
	p->pin_len = pin_len;

	p->next = reg->pins;
	reg->pins = p;

	wpa_printf(MSG_DEBUG, "WPS: A new PIN configured");
	wpa_hexdump(MSG_DEBUG, "WPS: UUID", uuid, WPS_UUID_LEN);
	wpa_hexdump_ascii_key(MSG_DEBUG, "WPS: PIN", pin, pin_len);
	reg->selected_registrar = 1;
	reg->pbc = 0;
	wps_set_ie(reg);

	return 0;
}


int wps_registrar_invalidate_pin(struct wps_registrar *reg, const u8 *uuid)
{
	struct wps_uuid_pin *pin, *prev;

	prev = NULL;
	pin = reg->pins;
	while (pin) {
		if (os_memcmp(pin->uuid, uuid, WPS_UUID_LEN) == 0) {
			if (prev == NULL)
				reg->pins = pin->next;
			else
				prev->next = pin->next;
			wpa_hexdump(MSG_DEBUG, "WPS: Invalidated PIN for UUID",
				    pin->uuid, WPS_UUID_LEN);
			wps_free_pin(pin);
			return 0;
		}
		prev = pin;
		pin = pin->next;
	}

	return -1;
}


static const u8 * wps_registrar_get_pin(struct wps_registrar *reg,
					const u8 *uuid, size_t *pin_len)
{
	struct wps_uuid_pin *pin;

	pin = reg->pins;
	while (pin) {
		if (os_memcmp(pin->uuid, uuid, WPS_UUID_LEN) == 0) {
			/*
			 * Lock the PIN to avoid attacks based on concurrent
			 * re-use of the PIN that could otherwise avoid PIN
			 * invalidations.
			 */
			if (pin->locked) {
				wpa_printf(MSG_DEBUG, "WPS: Selected PIN "
					   "locked - do not allow concurrent "
					   "re-use");
				return NULL;
			}
			*pin_len = pin->pin_len;
			pin->locked = 1;
			return pin->pin;
		}
		pin = pin->next;
	}

	return NULL;
}


int wps_registrar_unlock_pin(struct wps_registrar *reg, const u8 *uuid)
{
	struct wps_uuid_pin *pin;

	pin = reg->pins;
	while (pin) {
		if (os_memcmp(pin->uuid, uuid, WPS_UUID_LEN) == 0) {
			pin->locked = 0;
			return 0;
		}
		pin = pin->next;
	}

	return -1;
}


static void wps_registrar_pbc_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wps_registrar *reg = eloop_ctx;

	wpa_printf(MSG_DEBUG, "WPS: PBC timed out - disable PBC mode");
	reg->selected_registrar = 0;
	reg->pbc = 0;
	wps_set_ie(reg);
}


int wps_registrar_button_pushed(struct wps_registrar *reg)
{
	if (wps_registrar_pbc_overlap(reg, NULL, NULL)) {
		wpa_printf(MSG_DEBUG, "WPS: PBC overlap - do not start PBC "
			   "mode");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "WPS: Button pushed - PBC mode started");
	reg->selected_registrar = 1;
	reg->pbc = 1;
	wps_set_ie(reg);

	eloop_cancel_timeout(wps_registrar_pbc_timeout, reg, NULL);
	eloop_register_timeout(WPS_PBC_WALK_TIME, 0, wps_registrar_pbc_timeout,
			       reg, NULL);
	return 0;
}


static void wps_registrar_pbc_completed(struct wps_registrar *reg)
{
	wpa_printf(MSG_DEBUG, "WPS: PBC completed - stopping PBC mode");
	eloop_cancel_timeout(wps_registrar_pbc_timeout, reg, NULL);
	reg->selected_registrar = 0;
	reg->pbc = 0;
	wps_set_ie(reg);
}


void wps_registrar_probe_req_rx(struct wps_registrar *reg, const u8 *addr,
				const struct wpabuf *wps_data)
{
	struct wps_parse_attr attr;
	u16 methods;

	wpa_hexdump_buf(MSG_MSGDUMP,
			"WPS: Probe Request with WPS data received",
			wps_data);

	if (wps_parse_msg(wps_data, &attr) < 0 ||
	    attr.version == NULL || *attr.version != WPS_VERSION) {
		wpa_printf(MSG_DEBUG, "WPS: Unsupported ProbeReq WPS IE "
			   "version 0x%x", attr.version ? *attr.version : 0);
		return;
	}

	if (attr.config_methods == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Config Methods attribute in "
			   "Probe Request");
		return;
	}

	methods = WPA_GET_BE16(attr.config_methods);
	if (!(methods & WPS_CONFIG_PUSHBUTTON))
		return; /* Not PBC */

	wpa_printf(MSG_DEBUG, "WPS: Probe Request for PBC received from "
		   MACSTR, MAC2STR(addr));

	wps_registrar_add_pbc_session(reg, addr, attr.uuid_e);
}


static int wps_cb_new_psk(struct wps_registrar *reg, const u8 *mac_addr,
			  const u8 *psk, size_t psk_len)
{
	if (reg->new_psk_cb == NULL)
		return 0;

	return reg->new_psk_cb(reg->cb_ctx, mac_addr, psk, psk_len);
}


static void wps_cb_pin_needed(struct wps_registrar *reg, const u8 *uuid_e,
			      const struct wps_device_data *dev)
{
	if (reg->pin_needed_cb == NULL)
		return;

	reg->pin_needed_cb(reg->cb_ctx, uuid_e, dev);
}


static int wps_cb_set_ie(struct wps_registrar *reg,
			 const struct wpabuf *beacon_ie,
			 const struct wpabuf *probe_resp_ie)
{
	if (reg->set_ie_cb == NULL)
		return 0;

	return reg->set_ie_cb(reg->cb_ctx, wpabuf_head(beacon_ie),
			      wpabuf_len(beacon_ie),
			      wpabuf_head(probe_resp_ie),
			      wpabuf_len(probe_resp_ie));
}


static int wps_set_ie(struct wps_registrar *reg)
{
	struct wpabuf *beacon;
	struct wpabuf *probe;
	int ret;
	u8 *blen, *plen;

	wpa_printf(MSG_DEBUG, "WPS: Build Beacon and Probe Response IEs");

	beacon = wpabuf_alloc(300);
	if (beacon == NULL)
		return -1;
	probe = wpabuf_alloc(300);
	if (probe == NULL) {
		wpabuf_free(beacon);
		return -1;
	}

	wpabuf_put_u8(beacon, WLAN_EID_VENDOR_SPECIFIC);
	blen = wpabuf_put(beacon, 1);
	wpabuf_put_be32(beacon, WPS_DEV_OUI_WFA);

	wpabuf_put_u8(probe, WLAN_EID_VENDOR_SPECIFIC);
	plen = wpabuf_put(probe, 1);
	wpabuf_put_be32(probe, WPS_DEV_OUI_WFA);

	if (wps_build_version(beacon) ||
	    wps_build_wps_state(reg->wps, beacon) ||
	    wps_build_ap_setup_locked(reg->wps, beacon) ||
	    wps_build_selected_registrar(reg, beacon) ||
	    wps_build_sel_reg_dev_password_id(reg, beacon) ||
	    wps_build_sel_reg_config_methods(reg, beacon) ||
	    wps_build_version(probe) ||
	    wps_build_wps_state(reg->wps, probe) ||
	    wps_build_ap_setup_locked(reg->wps, probe) ||
	    wps_build_selected_registrar(reg, probe) ||
	    wps_build_sel_reg_dev_password_id(reg, probe) ||
	    wps_build_sel_reg_config_methods(reg, probe) ||
	    wps_build_resp_type(reg, probe) ||
	    wps_build_uuid_e(reg, probe) ||
	    wps_build_device_attrs(&reg->wps->dev, probe) ||
	    wps_build_probe_config_methods(reg, probe) ||
	    wps_build_rf_bands(reg, probe)) {
		wpabuf_free(beacon);
		wpabuf_free(probe);
		return -1;
	}

	*blen = wpabuf_len(beacon) - 2;
	*plen = wpabuf_len(probe) - 2;

	ret = wps_cb_set_ie(reg, beacon, probe);
	wpabuf_free(beacon);
	wpabuf_free(probe);

	return ret;
}


static int wps_get_dev_password(struct wps_data *wps)
{
	const u8 *pin;
	size_t pin_len;

	os_free(wps->dev_password);
	wps->dev_password = NULL;

	if (wps->pbc) {
		wpa_printf(MSG_DEBUG, "WPS: Use default PIN for PBC");
		pin = (const u8 *) "00000000";
		pin_len = 8;
	} else {
		pin = wps_registrar_get_pin(wps->registrar, wps->uuid_e,
					    &pin_len);
	}
	if (pin == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Device Password available for "
			   "the Enrollee");
		wps_cb_pin_needed(wps->registrar, wps->uuid_e, &wps->peer_dev);
		return -1;
	}

	wps->dev_password = os_malloc(pin_len);
	if (wps->dev_password == NULL)
		return -1;
	os_memcpy(wps->dev_password, pin, pin_len);
	wps->dev_password_len = pin_len;

	return 0;
}


static int wps_build_uuid_r(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * UUID-R");
	wpabuf_put_be16(msg, ATTR_UUID_R);
	wpabuf_put_be16(msg, WPS_UUID_LEN);
	wpabuf_put_data(msg, wps->uuid_r, WPS_UUID_LEN);
	return 0;
}


static int wps_build_dev_password_id(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Device Password ID");
	wpabuf_put_be16(msg, ATTR_DEV_PASSWORD_ID);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, DEV_PW_DEFAULT);
	return 0;
}


static int wps_build_config_error(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Configuration Error");
	wpabuf_put_be16(msg, ATTR_CONFIG_ERROR);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, WPS_CFG_NO_ERROR);
	return 0;
}


static int wps_build_r_hash(struct wps_data *wps, struct wpabuf *msg)
{
	u8 *hash;
	const u8 *addr[4];
	size_t len[4];

	if (os_get_random(wps->snonce, 2 * WPS_SECRET_NONCE_LEN) < 0)
		return -1;
	wpa_hexdump(MSG_DEBUG, "WPS: R-S1", wps->snonce, WPS_SECRET_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: R-S2",
		    wps->snonce + WPS_SECRET_NONCE_LEN, WPS_SECRET_NONCE_LEN);

	if (wps->dh_pubkey_e == NULL || wps->dh_pubkey_r == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: DH public keys not available for "
			   "R-Hash derivation");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS:  * R-Hash1");
	wpabuf_put_be16(msg, ATTR_R_HASH1);
	wpabuf_put_be16(msg, SHA256_MAC_LEN);
	hash = wpabuf_put(msg, SHA256_MAC_LEN);
	/* R-Hash1 = HMAC_AuthKey(R-S1 || PSK1 || PK_E || PK_R) */
	addr[0] = wps->snonce;
	len[0] = WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk1;
	len[1] = WPS_PSK_LEN;
	addr[2] = wpabuf_head(wps->dh_pubkey_e);
	len[2] = wpabuf_len(wps->dh_pubkey_e);
	addr[3] = wpabuf_head(wps->dh_pubkey_r);
	len[3] = wpabuf_len(wps->dh_pubkey_r);
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);
	wpa_hexdump(MSG_DEBUG, "WPS: R-Hash1", hash, SHA256_MAC_LEN);

	wpa_printf(MSG_DEBUG, "WPS:  * R-Hash2");
	wpabuf_put_be16(msg, ATTR_R_HASH2);
	wpabuf_put_be16(msg, SHA256_MAC_LEN);
	hash = wpabuf_put(msg, SHA256_MAC_LEN);
	/* R-Hash2 = HMAC_AuthKey(R-S2 || PSK2 || PK_E || PK_R) */
	addr[0] = wps->snonce + WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk2;
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);
	wpa_hexdump(MSG_DEBUG, "WPS: R-Hash2", hash, SHA256_MAC_LEN);

	return 0;
}


static int wps_build_r_snonce1(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * R-SNonce1");
	wpabuf_put_be16(msg, ATTR_R_SNONCE1);
	wpabuf_put_be16(msg, WPS_SECRET_NONCE_LEN);
	wpabuf_put_data(msg, wps->snonce, WPS_SECRET_NONCE_LEN);
	return 0;
}


static int wps_build_r_snonce2(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * R-SNonce2");
	wpabuf_put_be16(msg, ATTR_R_SNONCE2);
	wpabuf_put_be16(msg, WPS_SECRET_NONCE_LEN);
	wpabuf_put_data(msg, wps->snonce + WPS_SECRET_NONCE_LEN,
			WPS_SECRET_NONCE_LEN);
	return 0;
}


static int wps_build_cred_network_idx(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Network Index");
	wpabuf_put_be16(msg, ATTR_NETWORK_INDEX);
	wpabuf_put_be16(msg, 1);
	wpabuf_put_u8(msg, 0);
	return 0;
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
	wpa_printf(MSG_DEBUG, "WPS:  * Authentication Type (0x%x)",
		   wps->auth_type);
	wpabuf_put_be16(msg, ATTR_AUTH_TYPE);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, wps->auth_type);
	return 0;
}


static int wps_build_cred_encr_type(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Encryption Type (0x%x)",
		   wps->encr_type);
	wpabuf_put_be16(msg, ATTR_ENCR_TYPE);
	wpabuf_put_be16(msg, 2);
	wpabuf_put_be16(msg, wps->encr_type);
	return 0;
}


static int wps_build_cred_network_key(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * Network Key");
	wpabuf_put_be16(msg, ATTR_NETWORK_KEY);
	if (wps->wps->wps_state == WPS_STATE_NOT_CONFIGURED && wps->wps->ap) {
		u8 r[16];
		/* Generate a random passphrase */
		if (os_get_random(r, sizeof(r)) < 0)
			return -1;
		os_free(wps->new_psk);
		wps->new_psk = base64_encode(r, sizeof(r), &wps->new_psk_len);
		if (wps->new_psk == NULL)
			return -1;
		wps->new_psk_len--; /* remove newline */
		while (wps->new_psk_len &&
		       wps->new_psk[wps->new_psk_len - 1] == '=')
			wps->new_psk_len--;
		wpa_hexdump_ascii_key(MSG_DEBUG, "WPS: Generated passphrase",
				      wps->new_psk, wps->new_psk_len);
		wpabuf_put_be16(msg, wps->new_psk_len);
		wpabuf_put_data(msg, wps->new_psk, wps->new_psk_len);
	} else if (wps->wps->network_key) {
		wpabuf_put_be16(msg, wps->wps->network_key_len);
		wpabuf_put_data(msg, wps->wps->network_key,
				wps->wps->network_key_len);
	} else if (wps->auth_type & (WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK)) {
		char hex[65];
		/* Generate a random per-device PSK */
		os_free(wps->new_psk);
		wps->new_psk_len = 32;
		wps->new_psk = os_malloc(wps->new_psk_len);
		if (wps->new_psk == NULL)
			return -1;
		if (os_get_random(wps->new_psk, wps->new_psk_len) < 0) {
			os_free(wps->new_psk);
			wps->new_psk = NULL;
			return -1;
		}
		wpa_hexdump_key(MSG_DEBUG, "WPS: Generated per-device PSK",
				wps->new_psk, wps->new_psk_len);
		wpa_snprintf_hex(hex, sizeof(hex), wps->new_psk,
				 wps->new_psk_len);
		wpabuf_put_be16(msg, wps->new_psk_len * 2);
		wpabuf_put_data(msg, hex, wps->new_psk_len * 2);
	} else {
		/* No Network Key */
		wpabuf_put_be16(msg, 0);
	}
	return 0;
}


static int wps_build_cred_mac_addr(struct wps_data *wps, struct wpabuf *msg)
{
	wpa_printf(MSG_DEBUG, "WPS:  * MAC Address");
	wpabuf_put_be16(msg, ATTR_MAC_ADDR);
	wpabuf_put_be16(msg, ETH_ALEN);
	wpabuf_put_data(msg, wps->mac_addr_e, ETH_ALEN);
	return 0;
}


static int wps_build_cred(struct wps_data *wps, struct wpabuf *msg)
{
	struct wpabuf *cred;
	int ap_settings;

	ap_settings = !wps->wps->ap;

	if (ap_settings)
		wpa_printf(MSG_DEBUG, "WPS:  * AP Settings");
	else
		wpa_printf(MSG_DEBUG, "WPS:  * Credential");

	/* Select the best authentication and encryption type */
	if (wps->auth_type & WPS_AUTH_WPA2PSK)
		wps->auth_type = WPS_AUTH_WPA2PSK;
	else if (wps->auth_type & WPS_AUTH_WPAPSK)
		wps->auth_type = WPS_AUTH_WPAPSK;
	else if (wps->auth_type & WPS_AUTH_OPEN)
		wps->auth_type = WPS_AUTH_OPEN;
	else if (wps->auth_type & WPS_AUTH_SHARED)
		wps->auth_type = WPS_AUTH_SHARED;
	else {
		wpa_printf(MSG_DEBUG, "WPS: Unsupported auth_type 0x%x",
			   wps->auth_type);
		return -1;
	}

	if (wps->auth_type == WPS_AUTH_WPA2PSK ||
	    wps->auth_type == WPS_AUTH_WPAPSK) {
		if (wps->encr_type & WPS_ENCR_AES)
			wps->encr_type = WPS_ENCR_AES;
		else if (wps->encr_type & WPS_ENCR_TKIP)
			wps->encr_type = WPS_ENCR_TKIP;
		else {
			wpa_printf(MSG_DEBUG, "WPS: No suitable encryption "
				   "type for WPA/WPA2");
			return -1;
		}
	} else {
		if (wps->encr_type & WPS_ENCR_WEP)
			wps->encr_type = WPS_ENCR_WEP;
		else if (wps->encr_type & WPS_ENCR_NONE)
			wps->encr_type = WPS_ENCR_NONE;
		else {
			wpa_printf(MSG_DEBUG, "WPS: No suitable encryption "
				   "type for non-WPA/WPA2 mode");
			return -1;
		}
	}

	cred = wpabuf_alloc(200);
	if (cred == NULL)
		return -1;

	if (wps_build_cred_network_idx(wps, cred) ||
	    wps_build_cred_ssid(wps, cred) ||
	    wps_build_cred_auth_type(wps, cred) ||
	    wps_build_cred_encr_type(wps, cred) ||
	    wps_build_cred_network_key(wps, cred) ||
	    wps_build_cred_mac_addr(wps, cred)) {
		wpabuf_free(cred);
		return -1;
	}

	if (ap_settings) {
		wpabuf_put_buf(msg, cred);
		wpabuf_free(cred);
	} else {
		wpabuf_put_be16(msg, ATTR_CRED);
		wpabuf_put_be16(msg, wpabuf_len(cred));
		wpabuf_put_buf(msg, cred);
		wpabuf_free(cred);
	}

	return 0;
}


static struct wpabuf * wps_build_m2(struct wps_data *wps)
{
	struct wpabuf *msg;

	if (os_get_random(wps->nonce_r, WPS_NONCE_LEN) < 0)
		return NULL;
	wpa_hexdump(MSG_DEBUG, "WPS: Registrar Nonce",
		    wps->nonce_r, WPS_NONCE_LEN);
	os_memcpy(wps->uuid_r, wps->wps->uuid, WPS_UUID_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: UUID-R", wps->uuid_r, WPS_UUID_LEN);

	wpa_printf(MSG_DEBUG, "WPS: Building Message M2");
	msg = wpabuf_alloc(1000);
	if (msg == NULL)
		return NULL;

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M2) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_registrar_nonce(wps, msg) ||
	    wps_build_uuid_r(wps, msg) ||
	    wps_build_public_key(wps, msg) ||
	    wps_derive_keys(wps) ||
	    wps_build_auth_type_flags(wps, msg) ||
	    wps_build_encr_type_flags(wps, msg) ||
	    wps_build_conn_type_flags(wps, msg) ||
	    wps_build_config_methods(wps->registrar, msg) ||
	    wps_build_device_attrs(&wps->wps->dev, msg) ||
	    wps_build_rf_bands(wps->registrar, msg) ||
	    wps_build_assoc_state(wps, msg) ||
	    wps_build_config_error(wps, msg) ||
	    wps_build_dev_password_id(wps, msg) ||
	    wps_build_os_version(&wps->wps->dev, msg) ||
	    wps_build_authenticator(wps, msg)) {
		wpabuf_free(msg);
		return NULL;
	}

	wps->state = RECV_M3;
	return msg;
}


static struct wpabuf * wps_build_m2d(struct wps_data *wps)
{
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "WPS: Building Message M2D");
	msg = wpabuf_alloc(1000);
	if (msg == NULL)
		return NULL;

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M2D) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_registrar_nonce(wps, msg) ||
	    wps_build_uuid_r(wps, msg) ||
	    wps_build_auth_type_flags(wps, msg) ||
	    wps_build_encr_type_flags(wps, msg) ||
	    wps_build_conn_type_flags(wps, msg) ||
	    wps_build_config_methods(wps->registrar, msg) ||
	    wps_build_device_attrs(&wps->wps->dev, msg) ||
	    wps_build_rf_bands(wps->registrar, msg) ||
	    wps_build_assoc_state(wps, msg) ||
	    wps_build_config_error(wps, msg) ||
	    wps_build_os_version(&wps->wps->dev, msg)) {
		wpabuf_free(msg);
		return NULL;
	}

	wps->state = RECV_M2D_ACK;
	return msg;
}


static struct wpabuf * wps_build_m4(struct wps_data *wps)
{
	struct wpabuf *msg, *plain;

	wpa_printf(MSG_DEBUG, "WPS: Building Message M4");

	wps_derive_psk(wps, wps->dev_password, wps->dev_password_len);

	plain = wpabuf_alloc(200);
	if (plain == NULL)
		return NULL;

	msg = wpabuf_alloc(1000);
	if (msg == NULL) {
		wpabuf_free(plain);
		return NULL;
	}

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M4) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_r_hash(wps, msg) ||
	    wps_build_r_snonce1(wps, plain) ||
	    wps_build_key_wrap_auth(wps, plain) ||
	    wps_build_encr_settings(wps, msg, plain) ||
	    wps_build_authenticator(wps, msg)) {
		wpabuf_free(plain);
		wpabuf_free(msg);
		return NULL;
	}
	wpabuf_free(plain);

	wps->state = RECV_M5;
	return msg;
}


static struct wpabuf * wps_build_m6(struct wps_data *wps)
{
	struct wpabuf *msg, *plain;

	wpa_printf(MSG_DEBUG, "WPS: Building Message M6");

	plain = wpabuf_alloc(200);
	if (plain == NULL)
		return NULL;

	msg = wpabuf_alloc(1000);
	if (msg == NULL) {
		wpabuf_free(plain);
		return NULL;
	}

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M6) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_r_snonce2(wps, plain) ||
	    wps_build_key_wrap_auth(wps, plain) ||
	    wps_build_encr_settings(wps, msg, plain) ||
	    wps_build_authenticator(wps, msg)) {
		wpabuf_free(plain);
		wpabuf_free(msg);
		return NULL;
	}
	wpabuf_free(plain);

	wps->wps_pin_revealed = 1;
	wps->state = RECV_M7;
	return msg;
}


static struct wpabuf * wps_build_m8(struct wps_data *wps)
{
	struct wpabuf *msg, *plain;

	wpa_printf(MSG_DEBUG, "WPS: Building Message M8");

	plain = wpabuf_alloc(500);
	if (plain == NULL)
		return NULL;

	msg = wpabuf_alloc(1000);
	if (msg == NULL) {
		wpabuf_free(plain);
		return NULL;
	}

	if (wps_build_version(msg) ||
	    wps_build_msg_type(msg, WPS_M8) ||
	    wps_build_enrollee_nonce(wps, msg) ||
	    wps_build_cred(wps, plain) ||
	    wps_build_key_wrap_auth(wps, plain) ||
	    wps_build_encr_settings(wps, msg, plain) ||
	    wps_build_authenticator(wps, msg)) {
		wpabuf_free(plain);
		wpabuf_free(msg);
		return NULL;
	}
	wpabuf_free(plain);

	wps->state = RECV_DONE;
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


struct wpabuf * wps_registrar_get_msg(struct wps_data *wps, u8 *op_code)
{
	struct wpabuf *msg;

	switch (wps->state) {
	case SEND_M2:
		if (wps_get_dev_password(wps) < 0)
			msg = wps_build_m2d(wps);
		else
			msg = wps_build_m2(wps);
		*op_code = WSC_MSG;
		break;
	case SEND_M2D:
		msg = wps_build_m2d(wps);
		*op_code = WSC_MSG;
		break;
	case SEND_M4:
		msg = wps_build_m4(wps);
		*op_code = WSC_MSG;
		break;
	case SEND_M6:
		msg = wps_build_m6(wps);
		*op_code = WSC_MSG;
		break;
	case SEND_M8:
		msg = wps_build_m8(wps);
		*op_code = WSC_MSG;
		break;
	case RECV_DONE:
		msg = wps_build_wsc_ack(wps);
		*op_code = WSC_ACK;
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


static int wps_process_enrollee_nonce(struct wps_data *wps, const u8 *e_nonce)
{
	if (e_nonce == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Enrollee Nonce received");
		return -1;
	}

	os_memcpy(wps->nonce_e, e_nonce, WPS_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: Enrollee Nonce",
		    wps->nonce_e, WPS_NONCE_LEN);

	return 0;
}


static int wps_process_registrar_nonce(struct wps_data *wps, const u8 *r_nonce)
{
	if (r_nonce == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Registrar Nonce received");
		return -1;
	}

	if (os_memcmp(wps->nonce_r, r_nonce, WPS_NONCE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: Invalid Registrar Nonce received");
		return -1;
	}

	return 0;
}


static int wps_process_uuid_e(struct wps_data *wps, const u8 *uuid_e)
{
	if (uuid_e == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No UUID-E received");
		return -1;
	}

	os_memcpy(wps->uuid_e, uuid_e, WPS_UUID_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: UUID-E", wps->uuid_e, WPS_UUID_LEN);

	return 0;
}


static int wps_process_dev_password_id(struct wps_data *wps, const u8 *pw_id)
{
	if (pw_id == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Device Password ID received");
		return -1;
	}

	wps->dev_pw_id = WPA_GET_BE16(pw_id);
	wpa_printf(MSG_DEBUG, "WPS: Device Password ID %d", wps->dev_pw_id);

	return 0;
}


static int wps_process_e_hash1(struct wps_data *wps, const u8 *e_hash1)
{
	if (e_hash1 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No E-Hash1 received");
		return -1;
	}

	os_memcpy(wps->peer_hash1, e_hash1, WPS_HASH_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: E-Hash1", wps->peer_hash1, WPS_HASH_LEN);

	return 0;
}


static int wps_process_e_hash2(struct wps_data *wps, const u8 *e_hash2)
{
	if (e_hash2 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No E-Hash2 received");
		return -1;
	}

	os_memcpy(wps->peer_hash2, e_hash2, WPS_HASH_LEN);
	wpa_hexdump(MSG_DEBUG, "WPS: E-Hash2", wps->peer_hash2, WPS_HASH_LEN);

	return 0;
}


static int wps_process_e_snonce1(struct wps_data *wps, const u8 *e_snonce1)
{
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[4];
	size_t len[4];

	if (e_snonce1 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No E-SNonce1 received");
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "WPS: E-SNonce1", e_snonce1,
			WPS_SECRET_NONCE_LEN);

	/* E-Hash1 = HMAC_AuthKey(E-S1 || PSK1 || PK_E || PK_R) */
	addr[0] = e_snonce1;
	len[0] = WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk1;
	len[1] = WPS_PSK_LEN;
	addr[2] = wpabuf_head(wps->dh_pubkey_e);
	len[2] = wpabuf_len(wps->dh_pubkey_e);
	addr[3] = wpabuf_head(wps->dh_pubkey_r);
	len[3] = wpabuf_len(wps->dh_pubkey_r);
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);

	if (os_memcmp(wps->peer_hash1, hash, WPS_HASH_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: E-Hash1 derived from E-S1 does "
			   "not match with the pre-committed value");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Enrollee proved knowledge of the first "
		   "half of the device password");

	return 0;
}


static int wps_process_e_snonce2(struct wps_data *wps, const u8 *e_snonce2)
{
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[4];
	size_t len[4];

	if (e_snonce2 == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No E-SNonce2 received");
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "WPS: E-SNonce2", e_snonce2,
			WPS_SECRET_NONCE_LEN);

	/* E-Hash2 = HMAC_AuthKey(E-S2 || PSK2 || PK_E || PK_R) */
	addr[0] = e_snonce2;
	len[0] = WPS_SECRET_NONCE_LEN;
	addr[1] = wps->psk2;
	len[1] = WPS_PSK_LEN;
	addr[2] = wpabuf_head(wps->dh_pubkey_e);
	len[2] = wpabuf_len(wps->dh_pubkey_e);
	addr[3] = wpabuf_head(wps->dh_pubkey_r);
	len[3] = wpabuf_len(wps->dh_pubkey_r);
	hmac_sha256_vector(wps->authkey, WPS_AUTHKEY_LEN, 4, addr, len, hash);

	if (os_memcmp(wps->peer_hash2, hash, WPS_HASH_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "WPS: E-Hash2 derived from E-S2 does "
			   "not match with the pre-committed value");
		wps_registrar_invalidate_pin(wps->registrar, wps->uuid_e);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Enrollee proved knowledge of the second "
		   "half of the device password");
	wps->wps_pin_revealed = 0;
	wps_registrar_unlock_pin(wps->registrar, wps->uuid_e);

	return 0;
}


static int wps_process_mac_addr(struct wps_data *wps, const u8 *mac_addr)
{
	if (mac_addr == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No MAC Address received");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Enrollee MAC Address " MACSTR,
		   MAC2STR(mac_addr));
	os_memcpy(wps->mac_addr_e, mac_addr, ETH_ALEN);
	os_memcpy(wps->peer_dev.mac_addr, mac_addr, ETH_ALEN);

	return 0;
}


static int wps_process_pubkey(struct wps_data *wps, const u8 *pk,
			      size_t pk_len)
{
	if (pk == NULL || pk_len == 0) {
		wpa_printf(MSG_DEBUG, "WPS: No Public Key received");
		return -1;
	}

	wpabuf_free(wps->dh_pubkey_e);
	wps->dh_pubkey_e = wpabuf_alloc_copy(pk, pk_len);
	if (wps->dh_pubkey_e == NULL)
		return -1;

	return 0;
}


static int wps_process_auth_type_flags(struct wps_data *wps, const u8 *auth)
{
	u16 auth_types;

	if (auth == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Authentication Type flags "
			   "received");
		return -1;
	}

	auth_types = WPA_GET_BE16(auth);

	wpa_printf(MSG_DEBUG, "WPS: Enrollee Authentication Type flags 0x%x",
		   auth_types);
	wps->auth_type = wps->wps->auth_types & auth_types;
	if (wps->auth_type == 0) {
		wpa_printf(MSG_DEBUG, "WPS: No match in supported "
			   "authentication types");
		return -1;
	}

	return 0;
}


static int wps_process_encr_type_flags(struct wps_data *wps, const u8 *encr)
{
	u16 encr_types;

	if (encr == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Encryption Type flags "
			   "received");
		return -1;
	}

	encr_types = WPA_GET_BE16(encr);

	wpa_printf(MSG_DEBUG, "WPS: Enrollee Encryption Type flags 0x%x",
		   encr_types);
	wps->encr_type = wps->wps->encr_types & encr_types;
	if (wps->encr_type == 0) {
		wpa_printf(MSG_DEBUG, "WPS: No match in supported "
			   "encryption types");
		return -1;
	}

	return 0;
}


static int wps_process_conn_type_flags(struct wps_data *wps, const u8 *conn)
{
	if (conn == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Connection Type flags "
			   "received");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Enrollee Connection Type flags 0x%x",
		   *conn);

	return 0;
}


static int wps_process_config_methods(struct wps_data *wps, const u8 *methods)
{
	u16 m;

	if (methods == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Config Methods received");
		return -1;
	}

	m = WPA_GET_BE16(methods);

	wpa_printf(MSG_DEBUG, "WPS: Enrollee Config Methods 0x%x", m);

	return 0;
}


static int wps_process_wps_state(struct wps_data *wps, const u8 *state)
{
	if (state == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Wi-Fi Protected Setup State "
			   "received");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Enrollee Wi-Fi Protected Setup State %d",
		   *state);

	return 0;
}


static int wps_process_rf_bands(struct wps_data *wps, const u8 *bands)
{
	if (bands == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No RF Bands received");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPS: Enrollee RF Bands 0x%x", *bands);

	return 0;
}


static int wps_process_assoc_state(struct wps_data *wps, const u8 *assoc)
{
	u16 a;

	if (assoc == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Association State received");
		return -1;
	}

	a = WPA_GET_BE16(assoc);
	wpa_printf(MSG_DEBUG, "WPS: Enrollee Association State %d", a);

	return 0;
}


static int wps_process_config_error(struct wps_data *wps, const u8 *err)
{
	u16 e;

	if (err == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Configuration Error received");
		return -1;
	}

	e = WPA_GET_BE16(err);
	wpa_printf(MSG_DEBUG, "WPS: Enrollee Configuration Error %d", e);

	return 0;
}


static enum wps_process_res wps_process_m1(struct wps_data *wps,
					   struct wps_parse_attr *attr)
{
	wpa_printf(MSG_DEBUG, "WPS: Received M1");

	if (wps->state != RECV_M1) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M1", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_uuid_e(wps, attr->uuid_e) ||
	    wps_process_mac_addr(wps, attr->mac_addr) ||
	    wps_process_enrollee_nonce(wps, attr->enrollee_nonce) ||
	    wps_process_pubkey(wps, attr->public_key, attr->public_key_len) ||
	    wps_process_auth_type_flags(wps, attr->auth_type_flags) ||
	    wps_process_encr_type_flags(wps, attr->encr_type_flags) ||
	    wps_process_conn_type_flags(wps, attr->conn_type_flags) ||
	    wps_process_config_methods(wps, attr->config_methods) ||
	    wps_process_wps_state(wps, attr->wps_state) ||
	    wps_process_device_attrs(&wps->peer_dev, attr) ||
	    wps_process_rf_bands(wps, attr->rf_bands) ||
	    wps_process_assoc_state(wps, attr->assoc_state) ||
	    wps_process_dev_password_id(wps, attr->dev_password_id) ||
	    wps_process_config_error(wps, attr->config_error) ||
	    wps_process_os_version(&wps->peer_dev, attr->os_version))
		return WPS_FAILURE;

	if (wps->dev_pw_id != DEV_PW_DEFAULT &&
	    wps->dev_pw_id != DEV_PW_USER_SPECIFIED &&
	    wps->dev_pw_id != DEV_PW_MACHINE_SPECIFIED &&
	    wps->dev_pw_id != DEV_PW_REGISTRAR_SPECIFIED &&
	    (wps->dev_pw_id != DEV_PW_PUSHBUTTON || !wps->registrar->pbc)) {
		wpa_printf(MSG_DEBUG, "WPS: Unsupported Device Password ID %d",
			   wps->dev_pw_id);
		wps->state = SEND_M2D;
		return WPS_CONTINUE;
	}

	if (wps->dev_pw_id == DEV_PW_PUSHBUTTON) {
		if (wps_registrar_pbc_overlap(wps->registrar, wps->mac_addr_e,
					      wps->uuid_e)) {
			wpa_printf(MSG_DEBUG, "WPS: PBC overlap - deny PBC "
				   "negotiation");
			wps->state = SEND_M2D;
			return WPS_CONTINUE;
		}
		wps_registrar_add_pbc_session(wps->registrar, wps->mac_addr_e,
					      wps->uuid_e);
		wps->pbc = 1;
	}

	wps->state = SEND_M2;
	return WPS_CONTINUE;
}


static enum wps_process_res wps_process_m3(struct wps_data *wps,
					   const struct wpabuf *msg,
					   struct wps_parse_attr *attr)
{
	wpa_printf(MSG_DEBUG, "WPS: Received M3");

	if (wps->state != RECV_M3) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M3", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_registrar_nonce(wps, attr->registrar_nonce) ||
	    wps_process_authenticator(wps, attr->authenticator, msg) ||
	    wps_process_e_hash1(wps, attr->e_hash1) ||
	    wps_process_e_hash2(wps, attr->e_hash2))
		return WPS_FAILURE;

	wps->state = SEND_M4;
	return WPS_CONTINUE;
}


static enum wps_process_res wps_process_m5(struct wps_data *wps,
					   const struct wpabuf *msg,
					   struct wps_parse_attr *attr)
{
	struct wpabuf *decrypted;
	struct wps_parse_attr eattr;

	wpa_printf(MSG_DEBUG, "WPS: Received M5");

	if (wps->state != RECV_M5) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M5", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_registrar_nonce(wps, attr->registrar_nonce) ||
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
	    wps_process_e_snonce1(wps, eattr.e_snonce1)) {
		wpabuf_free(decrypted);
		return WPS_FAILURE;
	}
	wpabuf_free(decrypted);

	wps->state = SEND_M6;
	return WPS_CONTINUE;
}


static enum wps_process_res wps_process_m7(struct wps_data *wps,
					   const struct wpabuf *msg,
					   struct wps_parse_attr *attr)
{
	struct wpabuf *decrypted;
	struct wps_parse_attr eattr;

	wpa_printf(MSG_DEBUG, "WPS: Received M7");

	if (wps->state != RECV_M7) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving M7", wps->state);
		return WPS_FAILURE;
	}

	if (wps_process_registrar_nonce(wps, attr->registrar_nonce) ||
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
	    wps_process_e_snonce2(wps, eattr.e_snonce2)) {
		wpabuf_free(decrypted);
		return WPS_FAILURE;
	}
	wpabuf_free(decrypted);

	wps->state = SEND_M8;
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

	if (attr.msg_type == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: No Message Type attribute");
		return WPS_FAILURE;
	}

	if (*attr.msg_type != WPS_M1 &&
	    (attr.registrar_nonce == NULL ||
	     os_memcmp(wps->nonce_r, attr.registrar_nonce,
		       WPS_NONCE_LEN != 0))) {
		wpa_printf(MSG_DEBUG, "WPS: Mismatch in registrar nonce");
		return WPS_FAILURE;
	}

	switch (*attr.msg_type) {
	case WPS_M1:
		ret = wps_process_m1(wps, &attr);
		break;
	case WPS_M3:
		ret = wps_process_m3(wps, msg, &attr);
		break;
	case WPS_M5:
		ret = wps_process_m5(wps, msg, &attr);
		break;
	case WPS_M7:
		ret = wps_process_m7(wps, msg, &attr);
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

	if (wps->state == RECV_M2D_ACK) {
		/* TODO: support for multiple registrars and sending of
		 * multiple M2/M2D messages */

		wpa_printf(MSG_DEBUG, "WPS: No more registrars available - "
			   "terminate negotiation");
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
		return WPS_FAILURE;
	}

	if (attr.enrollee_nonce == NULL ||
	    os_memcmp(wps->nonce_e, attr.enrollee_nonce, WPS_NONCE_LEN != 0)) {
		wpa_printf(MSG_DEBUG, "WPS: Mismatch in enrollee nonce");
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


static enum wps_process_res wps_process_wsc_done(struct wps_data *wps,
						 const struct wpabuf *msg)
{
	struct wps_parse_attr attr;

	wpa_printf(MSG_DEBUG, "WPS: Received WSC_Done");

	if (wps->state != RECV_DONE) {
		wpa_printf(MSG_DEBUG, "WPS: Unexpected state (%d) for "
			   "receiving WSC_Done", wps->state);
		return WPS_FAILURE;
	}

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

	if (*attr.msg_type != WPS_WSC_DONE) {
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

	wpa_printf(MSG_DEBUG, "WPS: Negotiation completed successfully");

	if (wps->wps->wps_state == WPS_STATE_NOT_CONFIGURED && wps->new_psk &&
	    wps->wps->ap) {
		struct wps_credential cred;

		wpa_printf(MSG_DEBUG, "WPS: Moving to Configured state based "
			   "on first Enrollee connection");

		os_memset(&cred, 0, sizeof(cred));
		os_memcpy(cred.ssid, wps->wps->ssid, wps->wps->ssid_len);
		cred.ssid_len = wps->wps->ssid_len;
		cred.auth_type = WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK;
		cred.encr_type = WPS_ENCR_TKIP | WPS_ENCR_AES;
		os_memcpy(cred.key, wps->new_psk, wps->new_psk_len);
		cred.key_len = wps->new_psk_len;

		wps->wps->wps_state = WPS_STATE_CONFIGURED;
		wpa_hexdump_ascii_key(MSG_DEBUG,
				      "WPS: Generated random passphrase",
				      wps->new_psk, wps->new_psk_len);
		if (wps->wps->cred_cb)
			wps->wps->cred_cb(wps->wps->cb_ctx, &cred);

		os_free(wps->new_psk);
		wps->new_psk = NULL;
	}

	if (wps->new_psk) {
		if (wps_cb_new_psk(wps->registrar, wps->mac_addr_e,
				   wps->new_psk, wps->new_psk_len)) {
			wpa_printf(MSG_DEBUG, "WPS: Failed to configure the "
				   "new PSK");
		}
		os_free(wps->new_psk);
		wps->new_psk = NULL;
	}

	if (wps->pbc) {
		wps_registrar_remove_pbc_session(wps->registrar,
						 wps->mac_addr_e, wps->uuid_e);
		wps_registrar_pbc_completed(wps->registrar);
	}

	return WPS_DONE;
}


enum wps_process_res wps_registrar_process_msg(struct wps_data *wps,
					       u8 op_code,
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
	case WSC_Done:
		return wps_process_wsc_done(wps, msg);
	default:
		wpa_printf(MSG_DEBUG, "WPS: Unsupported op_code %d", op_code);
		return WPS_FAILURE;
	}
}
