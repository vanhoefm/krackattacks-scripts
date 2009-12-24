/*
 * AP mode helper functions
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

#include "common.h"
#include "hostapd.h"


int hostapd_register_probereq_cb(struct hostapd_data *hapd,
				 void (*cb)(void *ctx, const u8 *sa,
					    const u8 *ie, size_t ie_len),
				 void *ctx)
{
	struct hostapd_probereq_cb *n;

	n = os_realloc(hapd->probereq_cb, (hapd->num_probereq_cb + 1) *
		       sizeof(struct hostapd_probereq_cb));
	if (n == NULL)
		return -1;

	hapd->probereq_cb = n;
	n = &hapd->probereq_cb[hapd->num_probereq_cb];
	hapd->num_probereq_cb++;

	n->cb = cb;
	n->ctx = ctx;

	return 0;
}
