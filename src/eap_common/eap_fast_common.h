/*
 * EAP-FAST definitions (RFC 4851)
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
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

#ifndef EAP_FAST_H
#define EAP_FAST_H

#define EAP_FAST_VERSION 1
#define EAP_FAST_KEY_LEN 64
#define EAP_FAST_SIMCK_LEN 40
#define EAP_FAST_SKS_LEN 40

#define TLS_EXT_PAC_OPAQUE 35

/*
 * draft-cam-winget-eap-fast-provisioning-04.txt:
 * Section 4.2.1 - Formats for PAC TLV Attributes / Type Field
 * Note: bit 0x8000 (Mandatory) and bit 0x4000 (Reserved) are also defined
 * in the general PAC TLV format (Section 4.2).
 */
#define PAC_TYPE_PAC_KEY 1
#define PAC_TYPE_PAC_OPAQUE 2
#define PAC_TYPE_CRED_LIFETIME 3
#define PAC_TYPE_A_ID 4
#define PAC_TYPE_I_ID 5
/*
 * 6 was previous assigned for SERVER_PROTECTED_DATA, but
 * draft-cam-winget-eap-fast-provisioning-02.txt changed this to Reserved.
 */
#define PAC_TYPE_A_ID_INFO 7
#define PAC_TYPE_PAC_ACKNOWLEDGEMENT 8
#define PAC_TYPE_PAC_INFO 9
#define PAC_TYPE_PAC_TYPE 10

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct pac_tlv_hdr {
	be16 type;
	be16 len;
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */


#define EAP_FAST_PAC_KEY_LEN 32

/* draft-cam-winget-eap-fast-provisioning-04.txt: 4.2.6 PAC-Type TLV
 * Note: Machine Authentication PAC and User Authorization PAC were removed in
 * draft-cam-winget-eap-fast-provisioning-03.txt
 */
#define PAC_TYPE_TUNNEL_PAC 1
/* Application Specific Short Lived PACs (only in volatile storage) */
/* User Authorization PAC */
#define PAC_TYPE_USER_AUTHORIZATION 3
/* Application Specific Long Lived PACs */
/* Machine Authentication PAC */
#define PAC_TYPE_MACHINE_AUTHENTICATION 2


/*
 * draft-cam-winget-eap-fast-provisioning-04.txt:
 * Section 3.4 - Key Derivations Used in the EAP-FAST Provisioning Exchange
 */
struct eap_fast_key_block_provisioning {
	/* Extra key material after TLS key_block */
	u8 session_key_seed[EAP_FAST_SKS_LEN];
	u8 server_challenge[16]; /* MSCHAPv2 ServerChallenge */
	u8 client_challenge[16]; /* MSCHAPv2 ClientChallenge */
};

#endif /* EAP_FAST_H */
