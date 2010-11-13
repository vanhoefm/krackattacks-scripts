/*
 * wlantest control interface
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
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

#include "utils/includes.h"
#include <sys/un.h>

#include "utils/common.h"
#include "utils/eloop.h"
#include "wlantest.h"
#include "wlantest_ctrl.h"


static void ctrl_disconnect(struct wlantest *wt, int sock)
{
	int i;
	wpa_printf(MSG_DEBUG, "Disconnect control interface connection %d",
		   sock);
	for (i = 0; i < MAX_CTRL_CONNECTIONS; i++) {
		if (wt->ctrl_socks[i] == sock) {
			close(wt->ctrl_socks[i]);
			eloop_unregister_read_sock(wt->ctrl_socks[i]);
			wt->ctrl_socks[i] = -1;
			break;
		}
	}
}


static void ctrl_send_simple(struct wlantest *wt, int sock,
			     enum wlantest_ctrl_cmd cmd)
{
	u8 buf[4];
	WPA_PUT_BE32(buf, cmd);
	if (send(sock, buf, sizeof(buf), 0) < 0) {
		wpa_printf(MSG_INFO, "send(ctrl): %s", strerror(errno));
		ctrl_disconnect(wt, sock);
	}
}


static void ctrl_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wlantest *wt = eloop_ctx;
	u8 buf[WLANTEST_CTRL_MAX_CMD_LEN];
	int len;
	enum wlantest_ctrl_cmd cmd;

	wpa_printf(MSG_EXCESSIVE, "New control interface message from %d",
		   sock);
	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_INFO, "recv(ctrl): %s", strerror(errno));
		ctrl_disconnect(wt, sock);
		return;
	}
	if (len == 0) {
		ctrl_disconnect(wt, sock);
		return;
	}

	if (len < 4) {
		wpa_printf(MSG_INFO, "Too short control interface command "
			   "from %d", sock);
		ctrl_disconnect(wt, sock);
		return;
	}
	cmd = WPA_GET_BE32(buf);
	wpa_printf(MSG_EXCESSIVE, "Control interface command %d from %d",
		   cmd, sock);

	switch (cmd) {
	case WLANTEST_CTRL_PING:
		ctrl_send_simple(wt, sock, WLANTEST_CTRL_SUCCESS);
		break;
	case WLANTEST_CTRL_TERMINATE:
		ctrl_send_simple(wt, sock, WLANTEST_CTRL_SUCCESS);
		eloop_terminate();
		break;
	default:
		ctrl_send_simple(wt, sock, WLANTEST_CTRL_UNKNOWN_CMD);
		break;
	}
}


static void ctrl_connect(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wlantest *wt = eloop_ctx;
	int conn, i;

	conn = accept(sock, NULL, NULL);
	if (conn < 0) {
		wpa_printf(MSG_INFO, "accept(ctrl): %s", strerror(errno));
		return;
	}
	wpa_printf(MSG_MSGDUMP, "New control interface connection %d", conn);

	for (i = 0; i < MAX_CTRL_CONNECTIONS; i++) {
		if (wt->ctrl_socks[i] < 0)
			break;
	}

	if (i == MAX_CTRL_CONNECTIONS) {
		wpa_printf(MSG_INFO, "No room for new control connection");
		close(conn);
		return;
	}

	wt->ctrl_socks[i] = conn;
	eloop_register_read_sock(conn, ctrl_read, wt, NULL);
}


int ctrl_init(struct wlantest *wt)
{
	struct sockaddr_un addr;

	wt->ctrl_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (wt->ctrl_sock < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path + 1, WLANTEST_SOCK_NAME,
		   sizeof(addr.sun_path) - 1);
	if (bind(wt->ctrl_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		wpa_printf(MSG_ERROR, "bind: %s", strerror(errno));
		close(wt->ctrl_sock);
		wt->ctrl_sock = -1;
		return -1;
	}

	if (listen(wt->ctrl_sock, 5) < 0) {
		wpa_printf(MSG_ERROR, "listen: %s", strerror(errno));
		close(wt->ctrl_sock);
		wt->ctrl_sock = -1;
		return -1;
	}

	if (eloop_register_read_sock(wt->ctrl_sock, ctrl_connect, wt, NULL)) {
		close(wt->ctrl_sock);
		wt->ctrl_sock = -1;
		return -1;
	}

	return 0;
}


void ctrl_deinit(struct wlantest *wt)
{
	int i;

	if (wt->ctrl_sock < 0)
		return;

	for (i = 0; i < MAX_CTRL_CONNECTIONS; i++) {
		if (wt->ctrl_socks[i] >= 0) {
			close(wt->ctrl_socks[i]);
			eloop_unregister_read_sock(wt->ctrl_socks[i]);
			wt->ctrl_socks[i] = -1;
		}
	}

	eloop_unregister_read_sock(wt->ctrl_sock);
	close(wt->ctrl_sock);
	wt->ctrl_sock = -1;
}
