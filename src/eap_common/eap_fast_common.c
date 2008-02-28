/*
 * EAP-FAST common helper functions (RFC 4851)
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

#include "includes.h"

#include "common.h"
#include "eap_fast_common.h"


void eap_fast_put_tlv_hdr(struct wpabuf *buf, u16 type, u16 len)
{
	struct pac_tlv_hdr hdr;
	hdr.type = host_to_be16(type);
	hdr.len = host_to_be16(len);
	wpabuf_put_data(buf, &hdr, sizeof(hdr));
}


void eap_fast_put_tlv(struct wpabuf *buf, u16 type, const void *data,
			     u16 len)
{
	eap_fast_put_tlv_hdr(buf, type, len);
	wpabuf_put_data(buf, data, len);
}


void eap_fast_put_tlv_buf(struct wpabuf *buf, u16 type,
				 const struct wpabuf *data)
{
	eap_fast_put_tlv_hdr(buf, type, wpabuf_len(data));
	wpabuf_put_buf(buf, data);
}
