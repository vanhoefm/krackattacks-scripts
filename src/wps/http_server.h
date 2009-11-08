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

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

struct http_server;

struct http_server * http_server_init(struct in_addr *addr, int port,
				      void (*cb)(void *ctx, int fd,
						 struct sockaddr_in *addr),
				      void *cb_ctx);
void http_server_deinit(struct http_server *srv);
int http_server_get_port(struct http_server *srv);

#endif /* HTTP_SERVER_H */
