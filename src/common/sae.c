/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
/* TODO: move OpenSSL dependencies into crypto/crypto_openssl.c */
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include "common.h"
#include "crypto/sha256.h"
#include "crypto/random.h"
#include "sae.h"


static const u8 group19_prime[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const u8 group19_order[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
	0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};


static int val_zero_or_one(const u8 *val, size_t len)
{
	size_t i;

	for (i = 0; i < len - 1; i++) {
		if (val[i])
			return 0;
	}

	return val[len - 1] <= 1;
}


static int sae_get_rand(u8 *val)
{
	int iter = 0;

	do {
		if (random_get_bytes(val, sizeof(group19_prime)) < 0)
			return -1;
		if (iter++ > 100)
			return -1;
	} while (os_memcmp(val, group19_order, sizeof(group19_prime)) >= 0 ||
		 val_zero_or_one(val, sizeof(group19_prime)));

	return 0;
}


static void sae_bn_to_bin(const BIGNUM *bn, u8 *bin, size_t len)
{
	int offset = len - BN_num_bytes(bn);
	os_memset(bin, 0, offset);
	BN_bn2bin(bn, bin + offset);
}


static int sae_ec_point_to_bin(BN_CTX *bnctx, EC_GROUP *group, EC_POINT *point,
			       u8 *bin)
{
	BIGNUM *x, *y;
	int ret = -1;

	x = BN_new();
	y = BN_new();

	if (x && y &&
	    EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bnctx)) {
		sae_bn_to_bin(x, bin, 32);
		sae_bn_to_bin(y, bin + 32, 32);
		ret = 0;
	}

	BN_free(x);
	BN_free(y);
	return ret;
}


static void sae_pwd_seed_key(const u8 *addr1, const u8 *addr2, u8 *key)
{
	wpa_printf(MSG_DEBUG, "SAE: PWE derivation - addr1=" MACSTR
		   " addr2=" MACSTR, MAC2STR(addr1), MAC2STR(addr2));
	if (os_memcmp(addr1, addr2, ETH_ALEN) > 0) {
		os_memcpy(key, addr1, ETH_ALEN);
		os_memcpy(key + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		os_memcpy(key, addr2, ETH_ALEN);
		os_memcpy(key + ETH_ALEN, addr1, ETH_ALEN);
	}
}


static int sae_test_pwd_seed(BN_CTX *bnctx, EC_GROUP *group, const u8 *pwd_seed,
			     EC_POINT *pwe, u8 *pwe_bin)
{
	u8 pwd_value[32];
	BIGNUM *x;
	int y_bit;

	wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-seed", pwd_seed, 32);

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	sha256_prf(pwd_seed, 32, "SAE Hunting and Pecking",
		   group19_prime, sizeof(group19_prime),
		   pwd_value, sizeof(pwd_value));
	wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-value",
			pwd_value, sizeof(pwd_value));

	if (os_memcmp(pwd_value, group19_prime, sizeof(group19_prime)) >= 0)
		return 0;

	y_bit = pwd_seed[SHA256_MAC_LEN - 1] & 0x01;

	x = BN_bin2bn(pwd_value, sizeof(pwd_value), NULL);
	if (x == NULL)
		return -1;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, pwe, x, y_bit,
						     bnctx) ||
	    !EC_POINT_is_on_curve(group, pwe, bnctx)) {
		BN_free(x);
		wpa_printf(MSG_DEBUG, "SAE: No solution found");
		return 0;
	}
	BN_free(x);

	wpa_printf(MSG_DEBUG, "SAE: PWE found");

	if (sae_ec_point_to_bin(bnctx, group, pwe, pwe_bin) < 0)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "SAE: PWE x", pwe_bin, 32);
	wpa_hexdump_key(MSG_DEBUG, "SAE: PWE y", pwe_bin + 32, 32);
	return 1;
}


static int sae_derive_pwe(BN_CTX *bnctx, EC_GROUP *group, const u8 *addr1,
			  const u8 *addr2, const u8 *password,
			  size_t password_len, EC_POINT *pwe, u8 *pwe_bin)
{
	u8 counter, k = 4;
	u8 addrs[2 * ETH_ALEN];
	const u8 *addr[2];
	size_t len[2];
	int found = 0;
	EC_POINT *pwe_tmp;
	u8 pwe_bin_tmp[2 * 32];

	pwe_tmp = EC_POINT_new(group);
	if (pwe_tmp == NULL)
		return -1;

	wpa_hexdump_ascii_key(MSG_DEBUG, "SAE: password",
			      password, password_len);

	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              password || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = password;
	len[0] = password_len;
	addr[1] = &counter;
	len[1] = sizeof(counter);

	/*
	 * Continue for at least k iterations to protect against side-channel
	 * attacks that attempt to determine the number of iterations required
	 * in the loop.
	 */
	for (counter = 1; counter < k || !found; counter++) {
		u8 pwd_seed[SHA256_MAC_LEN];
		int res;

		wpa_printf(MSG_DEBUG, "SAE: counter = %u", counter);
		if (hmac_sha256_vector(addrs, sizeof(addrs), 2, addr, len,
				       pwd_seed) < 0)
			break;
		res = sae_test_pwd_seed(bnctx, group, pwd_seed,
					found ? pwe_tmp : pwe,
					found ? pwe_bin_tmp : pwe_bin);
		if (res < 0)
			break;
		if (res == 0)
			continue;
		if (found) {
			wpa_printf(MSG_DEBUG, "SAE: Ignore this PWE (one was "
				   "already selected)");
		} else {
			wpa_printf(MSG_DEBUG, "SAE: Use this PWE");
			found = 1;
		}

		if (counter > 200) {
			/* This should not happen in practice */
			wpa_printf(MSG_DEBUG, "SAE: Failed to derive PWE");
			break;
		}
	}

	EC_POINT_clear_free(pwe_tmp);

	return found ? 0 : -1;
}


static int sae_derive_commit(struct sae_data *sae, BN_CTX *bnctx,
			     EC_GROUP *group, EC_POINT *pwe)
{
	BIGNUM *x, *bn_rand, *bn_mask, *order;
	EC_POINT *elem;
	u8 mask[32];
	int ret = -1;

	if (sae_get_rand(sae->sae_rand) < 0 || sae_get_rand(mask) < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "SAE: rand",
			sae->sae_rand, sizeof(sae->sae_rand));
	wpa_hexdump_key(MSG_DEBUG, "SAE: mask", mask, sizeof(mask));

	x = BN_new();
	bn_rand = BN_bin2bn(sae->sae_rand, 32, NULL);
	bn_mask = BN_bin2bn(mask, sizeof(mask), NULL);
	order = BN_bin2bn(group19_order, sizeof(group19_order), NULL);
	elem = EC_POINT_new(group);
	if (x == NULL || bn_rand == NULL || bn_mask == NULL || order == NULL ||
	    elem == NULL)
		goto fail;

	/* commit-scalar = (rand + mask) modulo r */
	BN_add(x, bn_rand, bn_mask);
	BN_mod(x, x, order, bnctx);
	sae_bn_to_bin(x, sae->own_commit_scalar, 32);
	wpa_hexdump(MSG_DEBUG, "SAE: commit-scalar",
		    sae->own_commit_scalar, 32);

	/* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */
	if (!EC_POINT_mul(group, elem, NULL, pwe, bn_mask, bnctx) ||
	    !EC_POINT_invert(group, elem, bnctx) ||
	    sae_ec_point_to_bin(bnctx, group, elem, sae->own_commit_element) <
	    0)
		goto fail;

	wpa_hexdump(MSG_DEBUG, "SAE: commit-element x",
		    sae->own_commit_element, 32);
	wpa_hexdump(MSG_DEBUG, "SAE: commit-element y",
		    sae->own_commit_element + 32, 32);

	ret = 0;
fail:
	EC_POINT_free(elem);
	BN_free(order);
	BN_clear_free(bn_mask);
	os_memset(mask, 0, sizeof(mask));
	BN_clear_free(bn_rand);
	BN_clear_free(x);
	return ret;
}


int sae_prepare_commit(const u8 *addr1, const u8 *addr2,
		       const u8 *password, size_t password_len,
		       struct sae_data *sae)
{
	BN_CTX *bnctx;
	EC_POINT *pwe;
	EC_GROUP *group;
	int ret = 0;

	bnctx = BN_CTX_new();
	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	pwe = EC_POINT_new(group);
	if (bnctx == NULL || group == NULL || pwe == NULL ||
	    sae_derive_pwe(bnctx, group, addr1, addr2, password, password_len,
			   pwe, sae->pwe) < 0 ||
	    sae_derive_commit(sae, bnctx, group, pwe) < 0)
		ret = -1;

	EC_POINT_clear_free(pwe);
	EC_GROUP_free(group);
	BN_CTX_free(bnctx);

	return ret;
}


void sae_write_commit(struct sae_data *sae, struct wpabuf *buf)
{
	wpabuf_put_le16(buf, 19); /* Finite Cyclic Group */
	/* TODO: Anti-Clogging Token (if requested) */
	wpabuf_put_data(buf, sae->own_commit_scalar, 32);
	wpabuf_put_data(buf, sae->own_commit_element, 2 * 32);
}
