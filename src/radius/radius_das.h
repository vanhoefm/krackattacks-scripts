/*
 * RADIUS Dynamic Authorization Server (DAS)
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef RADIUS_DAS_H
#define RADIUS_DAS_H

struct radius_das_data;

struct radius_das_conf {
	int port;
	const u8 *shared_secret;
	size_t shared_secret_len;
	const struct hostapd_ip_addr *client_addr;
	unsigned int time_window;
	int require_event_timestamp;
};

struct radius_das_data *
radius_das_init(struct radius_das_conf *conf);

void radius_das_deinit(struct radius_das_data *data);

#endif /* RADIUS_DAS_H */
