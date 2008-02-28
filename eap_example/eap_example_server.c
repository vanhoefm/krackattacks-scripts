/*
 * Example application showing how EAP server code from hostapd can be used as
 * a library.
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

#include "includes.h"

#include "common.h"
#include "eap_server/eap.h"
#include "tls.h"
#include "wpabuf.h"

void eap_example_peer_rx(const u8 *data, size_t data_len);


struct eap_server_ctx {
	struct eap_eapol_interface *eap_if;
	struct eap_sm *eap;
	void *tls_ctx;
};

static struct eap_server_ctx eap_ctx;


static int server_get_eap_user(void *ctx, const u8 *identity,
			       size_t identity_len, int phase2,
			       struct eap_user *user)
{
	os_memset(user, 0, sizeof(*user));

	if (!phase2) {
		/* Only allow EAP-PEAP as the Phase 1 method */
		user->methods[0].vendor = EAP_VENDOR_IETF;
		user->methods[0].method = EAP_TYPE_PEAP;
		return 0;
	}

	if (identity_len != 4 || identity == NULL ||
	    os_memcmp(identity, "user", 4) != 0) {
		printf("Unknown user\n");
		return -1;
	}

	/* Only allow EAP-MSCHAPv2 as the Phase 2 method */
	user->methods[0].vendor = EAP_VENDOR_IETF;
	user->methods[0].method = EAP_TYPE_MSCHAPV2;
	user->password = (u8 *) os_strdup("password");
	user->password_len = 8;

	return 0;
}


static const char * server_get_eap_req_id_text(void *ctx, size_t *len)
{
	*len = 0;
	return NULL;
}


static struct eapol_callbacks eap_cb;
static struct eap_config eap_conf;

static int eap_example_server_init_tls(void)
{
	struct tls_config tconf;
	struct tls_connection_params tparams;

	os_memset(&tconf, 0, sizeof(tconf));
	eap_ctx.tls_ctx = tls_init(&tconf);
	if (eap_ctx.tls_ctx == NULL)
		return -1;

	os_memset(&tparams, 0, sizeof(tparams));
	tparams.ca_cert = "ca.pem";
	tparams.client_cert = "server.pem";
	tparams.private_key = "server.key";
	tparams.private_key_passwd = "whatever";

	if (tls_global_set_params(eap_ctx.tls_ctx, &tparams)) {
		printf("Failed to set TLS parameters\n");
		return -1;
	}

	if (tls_global_set_verify(eap_ctx.tls_ctx, 0)) {
		printf("Failed to set check_crl\n");
		return -1;
	}

	return 0;
}


int eap_example_server_init(void)
{
	if (eap_server_register_methods() < 0)
		return -1;

	os_memset(&eap_ctx, 0, sizeof(eap_ctx));

	if (eap_example_server_init_tls() < 0)
		return -1;

	os_memset(&eap_cb, 0, sizeof(eap_cb));
	eap_cb.get_eap_user = server_get_eap_user;
	eap_cb.get_eap_req_id_text = server_get_eap_req_id_text;

	os_memset(&eap_conf, 0, sizeof(eap_conf));
	eap_conf.eap_server = 1;
	eap_conf.ssl_ctx = eap_ctx.tls_ctx;

	eap_ctx.eap = eap_server_sm_init(&eap_ctx, &eap_cb, &eap_conf);
	if (eap_ctx.eap == NULL)
		return -1;

	eap_ctx.eap_if = eap_get_interface(eap_ctx.eap);

	/* Enable "port" and request EAP to start authentication. */
	eap_ctx.eap_if->portEnabled = TRUE;
	eap_ctx.eap_if->eapRestart = TRUE;

	return 0;
}


void eap_example_server_deinit(void)
{
	eap_server_sm_deinit(eap_ctx.eap);
	eap_server_unregister_methods();
	tls_deinit(eap_ctx.tls_ctx);
}


int eap_example_server_step(void)
{
	int res, process = 0;

	res = eap_server_sm_step(eap_ctx.eap);

	if (eap_ctx.eap_if->eapReq) {
		printf("==> Request\n");
		process = 1;
		eap_ctx.eap_if->eapReq = 0;
	}

	if (eap_ctx.eap_if->eapSuccess) {
		printf("==> Success\n");
		process = 1;
		res = 0;
		eap_ctx.eap_if->eapSuccess = 0;

		if (eap_ctx.eap_if->eapKeyAvailable) {
			wpa_hexdump(MSG_DEBUG, "EAP keying material",
				    eap_ctx.eap_if->eapKeyData,
				    eap_ctx.eap_if->eapKeyDataLen);
		}
	}

	if (eap_ctx.eap_if->eapFail) {
		printf("==> Fail\n");
		process = 1;
		eap_ctx.eap_if->eapFail = 0;
	}

	if (process && eap_ctx.eap_if->eapReqData) {
		/* Send EAP response to the server */
		eap_example_peer_rx(wpabuf_head(eap_ctx.eap_if->eapReqData),
				    wpabuf_len(eap_ctx.eap_if->eapReqData));
	}

	return res;
}


void eap_example_server_rx(const u8 *data, size_t data_len)
{
	/* Make received EAP message available to the EAP library */
	wpabuf_free(eap_ctx.eap_if->eapRespData);
	eap_ctx.eap_if->eapRespData = wpabuf_alloc_copy(data, data_len);
	if (eap_ctx.eap_if->eapRespData)
		eap_ctx.eap_if->eapResp = TRUE;
}
