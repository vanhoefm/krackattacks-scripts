/*
 * EAP peer method: EAP-TLV (draft-josefsson-pppext-eap-tls-eap-07.txt)
 * Copyright (c) 2004-2008, Jouni Malinen <j@w1.fi>
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

#ifndef EAP_TLV_H
#define EAP_TLV_H

#include "eap_common/eap_tlv_common.h"

struct wpabuf * eap_tlv_build_nak(int id, u16 nak_type);
struct wpabuf * eap_tlv_build_result(int id, u16 status);
int eap_tlv_process(struct eap_sm *sm, struct eap_method_ret *ret,
		    const struct wpabuf *req, struct wpabuf **resp,
		    int force_failure);

#endif /* EAP_TLV_H */
