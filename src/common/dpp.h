/*
 * DPP functionality shared between hostapd and wpa_supplicant
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DPP_H
#define DPP_H

#include <openssl/x509.h>

#include "utils/list.h"
#include "crypto/sha256.h"

#define DPP_BOOTSTRAP_MAX_FREQ 30

struct dpp_curve_params {
	const char *name;
	size_t hash_len;
	size_t aes_siv_key_len;
	size_t nonce_len;
	size_t prime_len;
	const char *jwk_crv;
};

enum dpp_bootstrap_type {
	DPP_BOOTSTRAP_QR_CODE,
};

struct dpp_bootstrap_info {
	struct dl_list list;
	unsigned int id;
	enum dpp_bootstrap_type type;
	char *uri;
	u8 mac_addr[ETH_ALEN];
	char *info;
	unsigned int freq[DPP_BOOTSTRAP_MAX_FREQ];
	unsigned int num_freq;
	int own;
	EVP_PKEY *pubkey;
	u8 pubkey_hash[SHA256_MAC_LEN];
	const struct dpp_curve_params *curve;
};

void dpp_bootstrap_info_free(struct dpp_bootstrap_info *info);
int dpp_parse_uri_chan_list(struct dpp_bootstrap_info *bi,
			    const char *chan_list);
int dpp_parse_uri_mac(struct dpp_bootstrap_info *bi, const char *mac);
int dpp_parse_uri_info(struct dpp_bootstrap_info *bi, const char *info);
struct dpp_bootstrap_info * dpp_parse_qr_code(const char *uri);
char * dpp_keygen(struct dpp_bootstrap_info *bi, const char *curve,
		  const u8 *privkey, size_t privkey_len);

#endif /* DPP_H */
