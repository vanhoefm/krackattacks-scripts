/*
 * Dynamic data buffer
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
#include "wpabuf.h"

static void wpabuf_overflow(const struct wpabuf *buf, size_t len)
{
	wpa_printf(MSG_ERROR, "wpabuf %p (size=%lu used=%lu) overflow len=%lu",
		   buf, (unsigned long) buf->size, (unsigned long) buf->used,
		   (unsigned long) len);
	abort();
}


int wpabuf_resize(struct wpabuf **_buf, size_t add_len)
{
	struct wpabuf *buf = *_buf;
	if (buf->used + add_len > buf->size) {
		unsigned char *nbuf;
		if (buf->ext_data) {
			nbuf = os_realloc(buf->ext_data, buf->used + add_len);
			if (nbuf == NULL)
				return -1;
			os_memset(nbuf + buf->used, 0, add_len);
			buf->ext_data = nbuf;
		} else {
			nbuf = os_realloc(buf, sizeof(struct wpabuf) +
					  buf->used + add_len);
			if (nbuf == NULL)
				return -1;
			buf = (struct wpabuf *) nbuf;
			os_memset(nbuf + sizeof(struct wpabuf) + buf->used, 0,
				  add_len);
			*_buf = buf;
		}
		buf->size = buf->used + add_len;
	}

	return 0;
}


/**
 * wpabuf_alloc - Allocate a wpabuf of the given size
 * @len: Length for the allocated buffer
 * Returns: Buffer to the allocated wpabuf or %NULL on failure
 */
struct wpabuf * wpabuf_alloc(size_t len)
{
	struct wpabuf *buf = os_zalloc(sizeof(struct wpabuf) + len);
	if (buf == NULL)
		return NULL;
	buf->size = len;
	return buf;
}


struct wpabuf * wpabuf_alloc_ext_data(u8 *data, size_t len)
{
	struct wpabuf *buf = os_zalloc(sizeof(struct wpabuf));
	if (buf == NULL)
		return NULL;

	buf->size = len;
	buf->used = len;
	buf->ext_data = data;

	return buf;
}


struct wpabuf * wpabuf_alloc_copy(const void *data, size_t len)
{
	struct wpabuf *buf = wpabuf_alloc(len);
	if (buf)
		wpabuf_put_data(buf, data, len);
	return buf;
}


struct wpabuf * wpabuf_dup(const struct wpabuf *src)
{
	struct wpabuf *buf = wpabuf_alloc(wpabuf_len(src));
	if (buf)
		wpabuf_put_data(buf, wpabuf_head(src), wpabuf_len(src));
	return buf;
}


/**
 * wpabuf_free - Free a wpabuf
 * @buf: wpabuf buffer
 */
void wpabuf_free(struct wpabuf *buf)
{
	if (buf == NULL)
		return;
	os_free(buf->ext_data);
	os_free(buf);
}


void * wpabuf_put(struct wpabuf *buf, size_t len)
{
	void *tmp = wpabuf_mhead_u8(buf) + wpabuf_len(buf);
	buf->used += len;
	if (buf->used > buf->size) {
		wpabuf_overflow(buf, len);
	}
	return tmp;
}
