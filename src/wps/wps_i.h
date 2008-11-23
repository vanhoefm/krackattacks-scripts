/*
 * Wi-Fi Protected Setup - internal definitions
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

#ifndef WPS_I_H
#define WPS_I_H

#include "wps.h"
#include "wps_defs.h"

struct wps_data {
	int authenticator;
	struct wps_context *wps;
	struct wps_registrar *registrar;
	enum {
		/* Enrollee states */
		SEND_M1, RECV_M2, SEND_M3, RECV_M4, SEND_M5, RECV_M6, SEND_M7,
		RECV_M8, RECEIVED_M2D, WPS_MSG_DONE, RECV_ACK, WPS_FINISHED,
		SEND_WSC_NACK,

		/* Registrar states */
		RECV_M1, SEND_M2, RECV_M3, SEND_M4, RECV_M5, SEND_M6,
		RECV_M7, SEND_M8, RECV_DONE, SEND_M2D, RECV_M2D_ACK
	} state;

	u8 uuid_e[WPS_UUID_LEN];
	u8 uuid_r[WPS_UUID_LEN];
	u8 mac_addr_e[ETH_ALEN];
	u8 nonce_e[WPS_NONCE_LEN];
	u8 nonce_r[WPS_NONCE_LEN];
	u8 psk1[WPS_PSK_LEN];
	u8 psk2[WPS_PSK_LEN];
	u8 snonce[2 * WPS_SECRET_NONCE_LEN];
	u8 peer_hash1[WPS_HASH_LEN];
	u8 peer_hash2[WPS_HASH_LEN];

	struct wpabuf *dh_privkey;
	struct wpabuf *dh_pubkey_e;
	struct wpabuf *dh_pubkey_r;
	u8 authkey[WPS_AUTHKEY_LEN];
	u8 keywrapkey[WPS_KEYWRAPKEY_LEN];
	u8 emsk[WPS_EMSK_LEN];

	struct wpabuf *last_msg;

	u8 *dev_password;
	size_t dev_password_len;
	u16 dev_pw_id;
	int pbc;

	u16 encr_type; /* available encryption types */
	u16 auth_type; /* available authentication types */

	u8 *new_psk;
	size_t new_psk_len;

	int wps_pin_revealed;
	struct wps_credential cred;

	int (*wps_cred_cb)(void *ctx, struct wps_credential *cred);
	void *cb_ctx;

	struct wps_device_data peer_dev;
};


struct wps_parse_attr {
	/* fixed length fields */
	const u8 *version; /* 1 octet */
	const u8 *msg_type; /* 1 octet */
	const u8 *enrollee_nonce; /* WPS_NONCE_LEN (16) octets */
	const u8 *registrar_nonce; /* WPS_NONCE_LEN (16) octets */
	const u8 *uuid_r; /* WPS_UUID_LEN (16) octets */
	const u8 *uuid_e; /* WPS_UUID_LEN (16) octets */
	const u8 *auth_type_flags; /* 2 octets */
	const u8 *encr_type_flags; /* 2 octets */
	const u8 *conn_type_flags; /* 1 octet */
	const u8 *config_methods; /* 2 octets */
	const u8 *sel_reg_config_methods; /* 2 octets */
	const u8 *primary_dev_type; /* 8 octets */
	const u8 *rf_bands; /* 1 octet */
	const u8 *assoc_state; /* 2 octets */
	const u8 *config_error; /* 2 octets */
	const u8 *dev_password_id; /* 2 octets */
	const u8 *os_version; /* 4 octets */
	const u8 *wps_state; /* 1 octet */
	const u8 *authenticator; /* WPS_AUTHENTICATOR_LEN (8) octets */
	const u8 *r_hash1; /* WPS_HASH_LEN (32) octets */
	const u8 *r_hash2; /* WPS_HASH_LEN (32) octets */
	const u8 *e_hash1; /* WPS_HASH_LEN (32) octets */
	const u8 *e_hash2; /* WPS_HASH_LEN (32) octets */
	const u8 *r_snonce1; /* WPS_SECRET_NONCE_LEN (16) octets */
	const u8 *r_snonce2; /* WPS_SECRET_NONCE_LEN (16) octets */
	const u8 *e_snonce1; /* WPS_SECRET_NONCE_LEN (16) octets */
	const u8 *e_snonce2; /* WPS_SECRET_NONCE_LEN (16) octets */
	const u8 *key_wrap_auth; /* WPS_KWA_LEN (8) octets */
	const u8 *auth_type; /* 2 octets */
	const u8 *encr_type; /* 2 octets */
	const u8 *network_idx; /* 1 octet */
	const u8 *network_key_idx; /* 1 octet */
	const u8 *mac_addr; /* ETH_ALEN (6) octets */
	const u8 *key_prov_auto; /* 1 octet (Bool) */
	const u8 *dot1x_enabled; /* 1 octet (Bool) */
	const u8 *selected_registrar; /* 1 octet (Bool) */

	/* variable length fields */
	const u8 *manufacturer;
	size_t manufacturer_len;
	const u8 *model_name;
	size_t model_name_len;
	const u8 *model_number;
	size_t model_number_len;
	const u8 *serial_number;
	size_t serial_number_len;
	const u8 *dev_name;
	size_t dev_name_len;
	const u8 *public_key;
	size_t public_key_len;
	const u8 *encr_settings;
	size_t encr_settings_len;
	const u8 *ssid; /* <= 32 octets */
	size_t ssid_len;
	const u8 *network_key; /* <= 64 octets */
	size_t network_key_len;
	const u8 *eap_type; /* <= 8 octets */
	size_t eap_type_len;
	const u8 *eap_identity; /* <= 64 octets */
	size_t eap_identity_len;

	/* attributes that can occur multiple times */
#define MAX_CRED_COUNT 10
	const u8 *cred[MAX_CRED_COUNT];
	size_t cred_len[MAX_CRED_COUNT];
	size_t num_cred;
};

/* wps_common.c */
int wps_parse_msg(const struct wpabuf *msg, struct wps_parse_attr *attr);
void wps_kdf(const u8 *key, const char *label, u8 *res, size_t res_len);
int wps_build_public_key(struct wps_data *wps, struct wpabuf *msg);
int wps_derive_keys(struct wps_data *wps);
int wps_build_authenticator(struct wps_data *wps, struct wpabuf *msg);
int wps_process_authenticator(struct wps_data *wps, const u8 *authenticator,
			      const struct wpabuf *msg);
void wps_derive_psk(struct wps_data *wps, const u8 *dev_passwd,
		    size_t dev_passwd_len);
struct wpabuf * wps_decrypt_encr_settings(struct wps_data *wps, const u8 *encr,
					  size_t encr_len);
int wps_process_key_wrap_auth(struct wps_data *wps, struct wpabuf *msg,
			      const u8 *key_wrap_auth);
int wps_build_key_wrap_auth(struct wps_data *wps, struct wpabuf *msg);
int wps_build_encr_settings(struct wps_data *wps, struct wpabuf *msg,
			    struct wpabuf *plain);
int wps_build_version(struct wpabuf *msg);
int wps_build_msg_type(struct wpabuf *msg, enum wps_msg_type msg_type);
int wps_build_enrollee_nonce(struct wps_data *wps, struct wpabuf *msg);
int wps_build_registrar_nonce(struct wps_data *wps, struct wpabuf *msg);
int wps_build_auth_type_flags(struct wps_data *wps, struct wpabuf *msg);
int wps_build_encr_type_flags(struct wps_data *wps, struct wpabuf *msg);
int wps_build_conn_type_flags(struct wps_data *wps, struct wpabuf *msg);
int wps_build_assoc_state(struct wps_data *wps, struct wpabuf *msg);

/* wps_enrollee.c */
struct wpabuf * wps_enrollee_get_msg(struct wps_data *wps, u8 *op_code);
enum wps_process_res wps_enrollee_process_msg(struct wps_data *wps, u8 op_code,
					      const struct wpabuf *msg);

/* wps_registrar.c */
struct wpabuf * wps_registrar_get_msg(struct wps_data *wps, u8 *op_code);
enum wps_process_res wps_registrar_process_msg(struct wps_data *wps,
					       u8 op_code,
					       const struct wpabuf *msg);

#endif /* WPS_I_H */
