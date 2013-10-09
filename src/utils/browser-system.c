/*
 * Hotspot 2.0 client - Web browser using system browser
 * Copyright (c) 2013, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "utils/eloop.h"
#include "wps/http_server.h"
#include "browser.h"


struct browser_data {
	int success;
};


static void browser_timeout(void *eloop_data, void *user_ctx)
{
	wpa_printf(MSG_INFO, "Timeout on waiting browser interaction to "
		   "complete");
	eloop_terminate();
}


static void http_req(void *ctx, struct http_request *req)
{
	struct browser_data *data = ctx;
	struct wpabuf *resp;
	const char *url;
	int done = 0;

	url = http_request_get_uri(req);
	wpa_printf(MSG_INFO, "Browser response received: %s", url);

	if (os_strcmp(url, "/") == 0) {
		data->success = 1;
		done = 1;
	} else if (os_strncmp(url, "/osu/", 5) == 0) {
		data->success = atoi(url + 5);
		done = 1;
	}

	resp = wpabuf_alloc(1);
	if (resp == NULL) {
		http_request_deinit(req);
		if (done)
			eloop_terminate();
		return;
	}

	if (done) {
		eloop_cancel_timeout(browser_timeout, NULL, NULL);
		eloop_register_timeout(0, 500000, browser_timeout, &data, NULL);
	}

	http_request_send_and_deinit(req, resp);
}


int hs20_web_browser(const char *url)
{
	char cmd[2000];
	int ret;
	struct http_server *http;
	struct in_addr addr;
	struct browser_data data;

	wpa_printf(MSG_INFO, "Launching Android browser to %s", url);

	os_memset(&data, 0, sizeof(data));

	ret = os_snprintf(cmd, sizeof(cmd), "x-www-browser '%s' &", url);
	if (ret < 0 || (size_t) ret >= sizeof(cmd)) {
		wpa_printf(MSG_ERROR, "Too long URL");
		return -1;
	}

	if (eloop_init() < 0) {
		wpa_printf(MSG_ERROR, "eloop_init failed");
		return -1;
	}
	addr.s_addr = htonl((127 << 24) | 1);
	http = http_server_init(&addr, 12345, http_req, &data);
	if (http == NULL) {
		wpa_printf(MSG_ERROR, "http_server_init failed");
		eloop_destroy();
		return -1;
	}

	if (system(cmd) != 0) {
		wpa_printf(MSG_INFO, "Failed to launch browser");
		eloop_cancel_timeout(browser_timeout, NULL, NULL);
		http_server_deinit(http);
		eloop_destroy();
		return -1;
	}

	eloop_register_timeout(120, 0, browser_timeout, &data, NULL);
	eloop_run();
	eloop_cancel_timeout(browser_timeout, &data, NULL);
	http_server_deinit(http);
	eloop_destroy();

	/* TODO: Close browser */

	return data.success;
}
