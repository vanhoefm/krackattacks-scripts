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
#include "asn1.h"
#include "tlsv1_common.h"
#include "tlsv1_record.h"
#include "tlsv1_client.h"
#include "tlsv1_client_i.h"


/* RFC 6960, 4.2.1: OCSPResponseStatus ::= ENUMERATED */
enum ocsp_response_status {
	OCSP_RESP_STATUS_SUCCESSFUL = 0,
	OCSP_RESP_STATUS_MALFORMED_REQ = 1,
	OCSP_RESP_STATUS_INT_ERROR = 2,
	OCSP_RESP_STATUS_TRY_LATER = 3,
	/* 4 not used */
	OCSP_RESP_STATUS_SIG_REQUIRED = 5,
	OCSP_RESP_STATUS_UNAUTHORIZED = 6,
};


static int is_oid_basic_ocsp_resp(struct asn1_oid *oid)
{
	return oid->len == 10 &&
		oid->oid[0] == 1 /* iso */ &&
		oid->oid[1] == 3 /* identified-organization */ &&
		oid->oid[2] == 6 /* dod */ &&
		oid->oid[3] == 1 /* internet */ &&
		oid->oid[4] == 5 /* security */ &&
		oid->oid[5] == 5 /* mechanisms */ &&
		oid->oid[6] == 7 /* id-pkix */ &&
		oid->oid[7] == 48 /* id-ad */ &&
		oid->oid[8] == 1 /* id-pkix-ocsp */ &&
		oid->oid[9] == 1 /* id-pkix-ocsp-basic */;
}


static enum tls_ocsp_result
tls_process_basic_ocsp_response(struct tlsv1_client *conn, const u8 *resp,
				size_t len)
{
	wpa_hexdump(MSG_MSGDUMP, "OCSP: BasicOCSPResponse", resp, len);

	/*
	 * RFC 6960, 4.2.1:
	 * BasicOCSPResponse       ::= SEQUENCE {
	 *    tbsResponseData      ResponseData,
	 *    signatureAlgorithm   AlgorithmIdentifier,
	 *    signature            BIT STRING,
	 *    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
	 */

	/* TODO */
	return TLS_OCSP_NO_RESPONSE;
}


enum tls_ocsp_result tls_process_ocsp_response(struct tlsv1_client *conn,
					       const u8 *resp, size_t len)
{
	struct asn1_hdr hdr;
	const u8 *pos, *end;
	u8 resp_status;
	struct asn1_oid oid;
	char obuf[80];

	wpa_hexdump(MSG_MSGDUMP, "TLSv1: OCSPResponse", resp, len);

	/*
	 * RFC 6960, 4.2.1:
	 * OCSPResponse ::= SEQUENCE {
	 *    responseStatus  OCSPResponseStatus,
	 *    responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }
	 */

	if (asn1_get_next(resp, len, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_UNIVERSAL ||
	    hdr.tag != ASN1_TAG_SEQUENCE) {
		wpa_printf(MSG_DEBUG,
			   "OCSP: Expected SEQUENCE (OCSPResponse) - found class %d tag 0x%x",
			   hdr.class, hdr.tag);
		return TLS_OCSP_INVALID;
	}
	pos = hdr.payload;
	end = hdr.payload + hdr.length;

	/* OCSPResponseStatus ::= ENUMERATED */
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_UNIVERSAL ||
	    hdr.tag != ASN1_TAG_ENUMERATED ||
	    hdr.length != 1) {
		wpa_printf(MSG_DEBUG,
			   "OCSP: Expected ENUMERATED (responseStatus) - found class %d tag 0x%x length %u",
			   hdr.class, hdr.tag, hdr.length);
		return TLS_OCSP_INVALID;
	}
	resp_status = hdr.payload[0];
	wpa_printf(MSG_DEBUG, "OCSP: responseStatus %u", resp_status);
	pos = hdr.payload + hdr.length;
	if (resp_status != OCSP_RESP_STATUS_SUCCESSFUL) {
		wpa_printf(MSG_DEBUG, "OCSP: No stapling result");
		return TLS_OCSP_NO_RESPONSE;
	}

	/* responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL */
	if (pos == end)
		return TLS_OCSP_NO_RESPONSE;

	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_CONTEXT_SPECIFIC ||
	    hdr.tag != 0) {
		wpa_printf(MSG_DEBUG,
			   "OCSP: Expected [0] EXPLICIT (responseBytes) - found class %d tag 0x%x",
			   hdr.class, hdr.tag);
		return TLS_OCSP_INVALID;
	}

	/*
	 * ResponseBytes ::= SEQUENCE {
	 *     responseType   OBJECT IDENTIFIER,
	 *     response       OCTET STRING }
	 */

	if (asn1_get_next(hdr.payload, hdr.length, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_UNIVERSAL ||
	    hdr.tag != ASN1_TAG_SEQUENCE) {
		wpa_printf(MSG_DEBUG,
			   "OCSP: Expected SEQUENCE (ResponseBytes) - found class %d tag 0x%x",
			   hdr.class, hdr.tag);
		return TLS_OCSP_INVALID;
	}
	pos = hdr.payload;
	end = hdr.payload + hdr.length;

	/* responseType   OBJECT IDENTIFIER */
	if (asn1_get_oid(pos, end - pos, &oid, &pos)) {
		wpa_printf(MSG_DEBUG,
			   "OCSP: Failed to parse OID (responseType)");
		return TLS_OCSP_INVALID;
	}
	asn1_oid_to_str(&oid, obuf, sizeof(obuf));
	wpa_printf(MSG_DEBUG, "OCSP: responseType %s", obuf);
	if (!is_oid_basic_ocsp_resp(&oid)) {
		wpa_printf(MSG_DEBUG, "OCSP: Ignore unsupported response type");
		return TLS_OCSP_NO_RESPONSE;
	}

	/* response       OCTET STRING */
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_UNIVERSAL ||
	    hdr.tag != ASN1_TAG_OCTETSTRING) {
		wpa_printf(MSG_DEBUG,
			   "OCSP: Expected OCTET STRING (response) - found class %d tag 0x%x",
			   hdr.class, hdr.tag);
		return TLS_OCSP_INVALID;
	}

	return tls_process_basic_ocsp_response(conn, hdr.payload, hdr.length);
}
