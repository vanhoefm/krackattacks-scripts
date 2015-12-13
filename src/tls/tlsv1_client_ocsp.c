/*
 * TLSv1 client - OCSP
 * Copyright (c) 2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/tls.h"
#include "tlsv1_common.h"
#include "tlsv1_record.h"
#include "tlsv1_client.h"
#include "tlsv1_client_i.h"


enum tls_ocsp_result tls_process_ocsp_response(struct tlsv1_client *conn,
					       const u8 *resp, size_t len)
{
	wpa_hexdump(MSG_MSGDUMP, "TLSv1: OCSPResponse", resp, len);

	/* TODO */
	return TLS_OCSP_NO_RESPONSE;
}
