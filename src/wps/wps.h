/*
 * Wi-Fi Protected Setup
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

#ifndef WPS_H
#define WPS_H

enum wsc_op_code {
	WSC_Start = 0x01,
	WSC_ACK = 0x02,
	WSC_NACK = 0x03,
	WSC_MSG = 0x04,
	WSC_Done = 0x05,
	WSC_FRAG_ACK = 0x06
};

struct wps_registrar;

struct wps_credential {
	u8 ssid[32];
	size_t ssid_len;
	u16 auth_type;
	u16 encr_type;
	u8 key_idx;
	u8 key[64];
	size_t key_len;
	u8 mac_addr[ETH_ALEN];
};

struct wps_config {
	int authenticator;
	struct wps_context *wps;
	struct wps_registrar *registrar; /* NULL for Enrollee */
	const u8 *enrollee_mac_addr; /* NULL for Registrar */
	const u8 *pin; /* Enrollee Device Password (NULL for Registrar or PBC)
			*/
	size_t pin_len;
	const u8 *uuid; /* 128-bit Enrollee UUID (NULL for Registrar) */
	int pbc;

	int (*wps_cred_cb)(void *ctx, struct wps_credential *cred);
	void *cb_ctx;
};

struct wps_data * wps_init(const struct wps_config *cfg);

void wps_deinit(struct wps_data *data);

enum wps_process_res {
	WPS_DONE, WPS_CONTINUE, WPS_FAILURE, WPS_PENDING
};
enum wps_process_res wps_process_msg(struct wps_data *wps, u8 op_code,
				     const struct wpabuf *msg);

struct wpabuf * wps_get_msg(struct wps_data *wps, u8 *op_code);

int wps_is_selected_pbc_registrar(const u8 *buf, size_t len);
int wps_is_selected_pin_registrar(const u8 *buf, size_t len);
const u8 * wps_get_uuid_e(const u8 *buf, size_t len);


struct wps_device_data {
	u8 mac_addr[ETH_ALEN];
	char *device_name;
	char *manufacturer;
	char *model_name;
	char *model_number;
	char *serial_number;
	u16 categ;
	u32 oui;
	u16 sub_categ;
	u32 os_version;
};


struct wps_registrar_config {
	int (*new_psk_cb)(void *ctx, const u8 *mac_addr, const u8 *psk,
			  size_t psk_len);
	int (*set_ie_cb)(void *ctx, const u8 *beacon_ie, size_t beacon_ie_len,
			 const u8 *probe_resp_ie, size_t probe_resp_ie_len);
	void (*pin_needed_cb)(void *ctx, const u8 *uuid_e,
			      const struct wps_device_data *dev);
	void *cb_ctx;
};


struct wps_context {
	int ap;
	struct wps_registrar *registrar;
	int wps_state;
	int ap_setup_locked;
	u8 uuid[16];
	u8 ssid[32];
	size_t ssid_len;
	struct wps_device_data dev;
	u16 config_methods; /* bit field of WPS_CONFIG_* */
	u16 encr_types; /* bit field of WPS_ENCR_* */
	u16 auth_types; /* bit field of WPS_AUTH_* */
	u8 *network_key; /* or NULL to generate per-device PSK */
	size_t network_key_len;

	int (*cred_cb)(void *ctx, const struct wps_credential *cred);
	void *cb_ctx;
};


struct wps_registrar *
wps_registrar_init(struct wps_context *wps,
		   const struct wps_registrar_config *cfg);
void wps_registrar_deinit(struct wps_registrar *reg);
int wps_registrar_add_pin(struct wps_registrar *reg, const u8 *uuid,
			  const u8 *pin, size_t pin_len);
int wps_registrar_invalidate_pin(struct wps_registrar *reg, const u8 *uuid);
int wps_registrar_unlock_pin(struct wps_registrar *reg, const u8 *uuid);
int wps_registrar_button_pushed(struct wps_registrar *reg);
void wps_registrar_probe_req_rx(struct wps_registrar *reg, const u8 *addr,
				const struct wpabuf *wps_data);

struct wpabuf * wps_enrollee_build_assoc_req_ie(void);
struct wpabuf * wps_enrollee_build_probe_req_ie(int pbc, const u8 *uuid);

#endif /* WPS_H */
