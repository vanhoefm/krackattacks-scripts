/**
 * http_server - HTTP server
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
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
#include <fcntl.h>

#include "common.h"
#include "eloop.h"
#include "http_server.h"


struct http_server {
	void (*cb)(void *ctx, int fd, struct sockaddr_in *addr);
	void *cb_ctx;

	int fd;
	int port;
};


static void http_server_cb(int sd, void *eloop_ctx, void *sock_ctx)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	struct http_server *srv = eloop_ctx;
	int conn;

	conn = accept(srv->fd, (struct sockaddr *) &addr, &addr_len);
	if (conn < 0) {
		wpa_printf(MSG_DEBUG, "HTTP: Failed to accept new connection: "
			   "%s", strerror(errno));
		return;
	}
	wpa_printf(MSG_DEBUG, "HTTP: Connection from %s:%d",
		   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	srv->cb(srv->cb_ctx, conn, &addr);
}


struct http_server * http_server_init(struct in_addr *addr, int port,
				      void (*cb)(void *ctx, int fd,
						 struct sockaddr_in *addr),
				      void *cb_ctx)
{
	struct sockaddr_in sin;
	struct http_server *srv;

	srv = os_zalloc(sizeof(*srv));
	if (srv == NULL)
		return NULL;
	srv->cb = cb;
	srv->cb_ctx = cb_ctx;

	srv->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv->fd < 0)
		goto fail;
	if (fcntl(srv->fd, F_SETFL, O_NONBLOCK) < 0)
		goto fail;
	if (port < 0)
		srv->port = 49152;
	else
		srv->port = port;

	os_memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr->s_addr;

	for (;;) {
		sin.sin_port = htons(srv->port);
		if (bind(srv->fd, (struct sockaddr *) &sin, sizeof(sin)) == 0)
			break;
		if (errno == EADDRINUSE) {
			/* search for unused port */
			if (++srv->port == 65535 || port >= 0)
				goto fail;
			continue;
		}
		wpa_printf(MSG_DEBUG, "HTTP: Failed to bind server port %d: "
			   "%s", srv->port, strerror(errno));
		goto fail;
	}
	if (listen(srv->fd, 10 /* max backlog */) < 0)
		goto fail;
	if (fcntl(srv->fd, F_SETFL, O_NONBLOCK) < 0)
		goto fail;
	if (eloop_register_sock(srv->fd, EVENT_TYPE_READ, http_server_cb,
				srv, NULL))
		goto fail;

	wpa_printf(MSG_DEBUG, "HTTP: Started server on %s:%d",
		   inet_ntoa(*addr), srv->port);

	return srv;

fail:
	http_server_deinit(srv);
	return NULL;
}


void http_server_deinit(struct http_server *srv)
{
	if (srv == NULL)
		return;
	if (srv->fd >= 0) {
		eloop_unregister_sock(srv->fd, EVENT_TYPE_READ);
		close(srv->fd);
	}

	os_free(srv);
}


int http_server_get_port(struct http_server *srv)
{
	return srv->port;
}
