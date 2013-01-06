/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/crypto.h"
#include "crypto/sha256.h"
#include "crypto/random.h"
#include "crypto/dh_groups.h"
#include "ieee802_11_defs.h"
#include "sae.h"


int sae_set_group(struct sae_data *sae, int group)
{
	sae_clear_data(sae);

	/* First, check if this is an ECC group */
	sae->ec = crypto_ec_init(group);
	if (sae->ec) {
		sae->group = group;
		sae->prime_len = crypto_ec_prime_len(sae->ec);
		sae->prime = crypto_ec_get_prime(sae->ec);
		sae->order = crypto_ec_get_order(sae->ec);
		return 0;
	}

	/* Not an ECC group, check FFC */
	sae->dh = dh_groups_get(group);
	if (sae->dh) {
		sae->group = group;
		sae->prime_len = sae->dh->prime_len;
		if (sae->prime_len > SAE_MAX_PRIME_LEN) {
			sae_clear_data(sae);
			return -1;
		}

		sae->prime_buf = crypto_bignum_init_set(sae->dh->prime,
							sae->prime_len);
		if (sae->prime_buf == NULL) {
			sae_clear_data(sae);
			return -1;
		}
		sae->prime = sae->prime_buf;

		sae->order_buf = crypto_bignum_init_set(sae->dh->order,
							sae->dh->order_len);
		if (sae->order_buf == NULL) {
			sae_clear_data(sae);
			return -1;
		}
		sae->order = sae->order_buf;

		return 0;
	}

	/* Unsupported group */
	return -1;
}


void sae_clear_data(struct sae_data *sae)
{
	if (sae == NULL)
		return;
	crypto_ec_deinit(sae->ec);
	crypto_bignum_deinit(sae->prime_buf, 0);
	crypto_bignum_deinit(sae->order_buf, 0);
	os_memset(sae, 0, sizeof(*sae));
}


static int val_one(const u8 *val, size_t len)
{
	size_t i;

	for (i = 0; i < len - 1; i++) {
		if (val[i])
			return 0;
	}

	return val[len - 1] == 1;
}


static int val_zero_or_one(const u8 *val, size_t len)
{
	size_t i;

	for (i = 0; i < len - 1; i++) {
		if (val[i])
			return 0;
	}

	return val[len - 1] <= 1;
}


static int val_zero(const u8 *val, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (val[i])
			return 0;
	}
	return 1;
}


static void buf_shift_right(u8 *buf, size_t len, size_t bits)
{
	size_t i;
	for (i = len - 1; i > 0; i--)
		buf[i] = (buf[i - 1] << (8 - bits)) | (buf[i] >> bits);
	buf[0] >>= bits;
}


static int sae_get_rand(const u8 *order, size_t order_len_bits, u8 *val)
{
	int iter = 0;
	size_t order_len = (order_len_bits + 7) / 8;

	do {
		if (iter++ > 100)
			return -1;
		if (random_get_bytes(val, order_len) < 0)
			return -1;
		if (order_len_bits % 8)
			buf_shift_right(val, order_len, 8 - order_len_bits % 8);
	} while (os_memcmp(val, order, order_len) >= 0 ||
		 val_zero_or_one(val, order_len));

	return 0;
}


static struct crypto_bignum * sae_get_rand_and_mask(struct sae_data *sae)
{
	u8 mask[SAE_MAX_PRIME_LEN], order[SAE_MAX_PRIME_LEN];
	struct crypto_bignum *bn;
	size_t prime_len_bits = crypto_ec_prime_len_bits(sae->ec);

	if (crypto_bignum_to_bin(sae->order, order, sizeof(order),
				 sae->prime_len) < 0)
		return NULL;

	if (sae_get_rand(order, prime_len_bits, sae->sae_rand) < 0 ||
	    sae_get_rand(order, prime_len_bits, mask) < 0)
		return NULL;
	sae->rand_len = sae->prime_len;
	wpa_hexdump_key(MSG_DEBUG, "SAE: rand",
			sae->sae_rand, sae->rand_len);
	wpa_hexdump_key(MSG_DEBUG, "SAE: mask", mask, sae->prime_len);
	bn = crypto_bignum_init_set(mask, sae->prime_len);
	os_memset(mask, 0, sizeof(mask));
	return bn;
}


static struct crypto_bignum * sae_get_rand_and_mask_dh(struct sae_data *sae)
{
	u8 mask[SAE_MAX_PRIME_LEN];
	struct crypto_bignum *bn;

	if (sae_get_rand(sae->dh->order, sae->dh->order_len * 8, sae->sae_rand)
	    < 0 ||
	    sae_get_rand(sae->dh->order, sae->dh->order_len * 8, mask) < 0)
		return NULL;

	sae->rand_len = sae->dh->order_len;
	wpa_hexdump_key(MSG_DEBUG, "SAE: rand", sae->sae_rand, sae->rand_len);
	wpa_hexdump_key(MSG_DEBUG, "SAE: mask", mask, sae->dh->order_len);
	bn = crypto_bignum_init_set(mask, sae->dh->order_len);
	os_memset(mask, 0, sizeof(mask));
	return bn;
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


static int sae_test_pwd_seed(struct sae_data *sae, const u8 *pwd_seed,
			     struct crypto_ec_point *pwe, u8 *pwe_bin)
{
	u8 pwd_value[SAE_MAX_PRIME_LEN], prime[SAE_MAX_PRIME_LEN];
	struct crypto_bignum *x;
	int y_bit;
	size_t bits;

	if (crypto_bignum_to_bin(sae->prime, prime, sizeof(prime),
				 sae->prime_len) < 0)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-seed", pwd_seed, SHA256_MAC_LEN);

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	bits = crypto_ec_prime_len_bits(sae->ec);
	sha256_prf_bits(pwd_seed, SHA256_MAC_LEN, "SAE Hunting and Pecking",
			prime, sae->prime_len, pwd_value, bits);
	if (bits % 8)
		buf_shift_right(pwd_value, sizeof(pwd_value), 8 - bits % 8);
	wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-value",
			pwd_value, sae->prime_len);

	if (os_memcmp(pwd_value, prime, sae->prime_len) >= 0)
		return 0;

	y_bit = pwd_seed[SHA256_MAC_LEN - 1] & 0x01;

	x = crypto_bignum_init_set(pwd_value, sae->prime_len);
	if (x == NULL)
		return -1;
	if (crypto_ec_point_solve_y_coord(sae->ec, pwe, x, y_bit) < 0) {
		crypto_bignum_deinit(x, 0);
		wpa_printf(MSG_DEBUG, "SAE: No solution found");
		return 0;
	}
	crypto_bignum_deinit(x, 0);

	wpa_printf(MSG_DEBUG, "SAE: PWE found");

	if (crypto_ec_point_to_bin(sae->ec, pwe, pwe_bin,
				   pwe_bin + sae->prime_len) < 0)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "SAE: PWE x", pwe_bin, sae->prime_len);
	wpa_hexdump_key(MSG_DEBUG, "SAE: PWE y",
			pwe_bin + sae->prime_len, sae->prime_len);
	return 1;
}


static int sae_derive_pwe(struct sae_data *sae, const u8 *addr1,
			  const u8 *addr2, const u8 *password,
			  size_t password_len, struct crypto_ec_point *pwe,
			  u8 *pwe_bin)
{
	u8 counter, k = 4;
	u8 addrs[2 * ETH_ALEN];
	const u8 *addr[2];
	size_t len[2];
	int found = 0;
	struct crypto_ec_point *pwe_tmp;
	u8 pwe_bin_tmp[2 * SAE_MAX_PRIME_LEN];

	pwe_tmp = crypto_ec_point_init(sae->ec);
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

		if (counter > 200) {
			/* This should not happen in practice */
			wpa_printf(MSG_DEBUG, "SAE: Failed to derive PWE");
			break;
		}

		wpa_printf(MSG_DEBUG, "SAE: counter = %u", counter);
		if (hmac_sha256_vector(addrs, sizeof(addrs), 2, addr, len,
				       pwd_seed) < 0)
			break;
		res = sae_test_pwd_seed(sae, pwd_seed,
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
	}

	crypto_ec_point_deinit(pwe_tmp, 1);

	return found ? 0 : -1;
}


static int sae_derive_commit(struct sae_data *sae, struct crypto_ec_point *pwe)
{
	struct crypto_bignum *x, *bn_rand, *mask;
	struct crypto_ec_point *elem;
	int ret = -1;

	mask = sae_get_rand_and_mask(sae);
	if (mask == NULL) {
		wpa_printf(MSG_DEBUG, "SAE: Could not get rand/mask");
		return -1;
	}

	x = crypto_bignum_init();
	bn_rand = crypto_bignum_init_set(sae->sae_rand, sae->rand_len);
	elem = crypto_ec_point_init(sae->ec);
	if (x == NULL || bn_rand == NULL || elem == NULL)
		goto fail;

	/* commit-scalar = (rand + mask) modulo r */
	crypto_bignum_add(bn_rand, mask, x);
	crypto_bignum_mod(x, sae->order, x);
	crypto_bignum_to_bin(x, sae->own_commit_scalar,
			     sizeof(sae->own_commit_scalar), sae->prime_len);
	wpa_hexdump(MSG_DEBUG, "SAE: commit-scalar",
		    sae->own_commit_scalar, sae->prime_len);

	/* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */
	if (crypto_ec_point_mul(sae->ec, pwe, mask, elem) < 0 ||
	    crypto_ec_point_invert(sae->ec, elem) < 0 ||
	    crypto_ec_point_to_bin(sae->ec, elem, sae->own_commit_element,
				   sae->own_commit_element + sae->prime_len) <
	    0) {
		wpa_printf(MSG_DEBUG, "SAE: Could not compute commit-element");
		goto fail;
	}

	wpa_hexdump(MSG_DEBUG, "SAE: commit-element x",
		    sae->own_commit_element, sae->prime_len);
	wpa_hexdump(MSG_DEBUG, "SAE: commit-element y",
		    sae->own_commit_element + sae->prime_len, sae->prime_len);

	ret = 0;
fail:
	crypto_ec_point_deinit(elem, 0);
	crypto_bignum_deinit(mask, 1);
	crypto_bignum_deinit(bn_rand, 1);
	crypto_bignum_deinit(x, 1);
	return ret;
}


static int sae_prepare_commit_ec(const u8 *addr1, const u8 *addr2,
				 const u8 *password, size_t password_len,
				 struct sae_data *sae)
{
	struct crypto_ec_point *pwe;
	int ret = 0;

	pwe = crypto_ec_point_init(sae->ec);
	if (pwe == NULL ||
	    sae_derive_pwe(sae, addr1, addr2, password, password_len, pwe,
			   sae->pwe) < 0 ||
	    sae_derive_commit(sae, pwe) < 0)
		ret = -1;

	crypto_ec_point_deinit(pwe, 1);

	return ret;
}


static int sae_test_pwd_seed_dh(struct sae_data *sae, const u8 *pwd_seed,
				struct crypto_bignum *pwe)
{
	u8 pwd_value[SAE_MAX_PRIME_LEN];
	size_t bits = sae->prime_len * 8;
	u8 exp[1];
	struct crypto_bignum *a, *b;
	int res;

	wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-seed", pwd_seed, SHA256_MAC_LEN);

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	sha256_prf_bits(pwd_seed, SHA256_MAC_LEN, "SAE Hunting and Pecking",
			sae->dh->prime, sae->prime_len, pwd_value, bits);
	if (bits % 8)
		buf_shift_right(pwd_value, sizeof(pwd_value), 8 - bits % 8);
	wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-value", pwd_value, sae->prime_len);

	if (os_memcmp(pwd_value, sae->dh->prime, sae->prime_len) >= 0) {
		wpa_printf(MSG_DEBUG, "SAE: pwd-value >= p");
		return 0;
	}

	/* PWE = pwd-value^((p-1)/r) modulo p */

	a = crypto_bignum_init_set(pwd_value, sae->prime_len);

	if (sae->dh->safe_prime) {
		/*
		 * r = (p-1)/2 for the group used here, so this becomes:
		 * PWE = pwd-value^2 modulo p
		 */
		exp[0] = 2;
		b = crypto_bignum_init_set(exp, sizeof(exp));
		if (a == NULL || b == NULL)
			res = -1;
		else
			res = crypto_bignum_exptmod(a, b, sae->prime, pwe);
	} else {
		struct crypto_bignum *tmp;

		exp[0] = 1;
		b = crypto_bignum_init_set(exp, sizeof(exp));
		tmp = crypto_bignum_init();
		if (a == NULL || b == NULL || tmp == NULL ||
		    crypto_bignum_sub(sae->prime, b, tmp) < 0 ||
		    crypto_bignum_div(tmp, sae->order, b) < 0)
			res = -1;
		else
			res = crypto_bignum_exptmod(a, b, sae->prime, pwe);
		crypto_bignum_deinit(tmp, 0);
	}

	crypto_bignum_deinit(a, 0);
	crypto_bignum_deinit(b, 0);

	if (res < 0) {
		wpa_printf(MSG_DEBUG, "SAE: Failed to calculate PWE");
		return -1;
	}

	res = crypto_bignum_to_bin(pwe, sae->pwe, sizeof(sae->pwe),
				   sae->prime_len);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "SAE: Not room for PWE");
		return -1;
	}
	wpa_hexdump_key(MSG_DEBUG, "SAE: PWE candidate", sae->pwe, res);

	/* if (PWE > 1) --> found */
	if (val_zero_or_one(sae->pwe, sae->prime_len)) {
		wpa_printf(MSG_DEBUG, "SAE: PWE <= 1");
		return 0;
	}

	wpa_printf(MSG_DEBUG, "SAE: PWE found");
	return 1;
}


static int sae_derive_pwe_dh(struct sae_data *sae, const u8 *addr1,
			     const u8 *addr2, const u8 *password,
			     size_t password_len, struct crypto_bignum *pwe)
{
	u8 counter;
	u8 addrs[2 * ETH_ALEN];
	const u8 *addr[2];
	size_t len[2];
	int found = 0;

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

	for (counter = 1; !found; counter++) {
		u8 pwd_seed[SHA256_MAC_LEN];
		int res;

		if (counter > 200) {
			/* This should not happen in practice */
			wpa_printf(MSG_DEBUG, "SAE: Failed to derive PWE");
			break;
		}

		wpa_printf(MSG_DEBUG, "SAE: counter = %u", counter);
		if (hmac_sha256_vector(addrs, sizeof(addrs), 2, addr, len,
				       pwd_seed) < 0)
			break;
		res = sae_test_pwd_seed_dh(sae, pwd_seed, pwe);
		if (res < 0)
			break;
		if (res > 0) {
			wpa_printf(MSG_DEBUG, "SAE: Use this PWE");
			found = 1;
		}
	}

	return found ? 0 : -1;
}


static int sae_derive_commit_dh(struct sae_data *sae, struct crypto_bignum *pwe)
{
	struct crypto_bignum *x, *bn_rand, *mask, *elem;
	int ret = -1;

	mask = sae_get_rand_and_mask_dh(sae);
	if (mask == NULL) {
		wpa_printf(MSG_DEBUG, "SAE: Could not get rand/mask");
		return -1;
	}

	x = crypto_bignum_init();
	bn_rand = crypto_bignum_init_set(sae->sae_rand, sae->rand_len);
	elem = crypto_bignum_init();
	if (x == NULL || bn_rand == NULL || elem == NULL)
		goto fail;

	/* commit-scalar = (rand + mask) modulo r */
	crypto_bignum_add(bn_rand, mask, x);
	crypto_bignum_mod(x, sae->order, x);
	crypto_bignum_to_bin(x, sae->own_commit_scalar,
			     sizeof(sae->own_commit_scalar), sae->prime_len);
	wpa_hexdump(MSG_DEBUG, "SAE: commit-scalar",
		    sae->own_commit_scalar, sae->prime_len);

	/* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */
	if (crypto_bignum_exptmod(pwe, mask, sae->prime, elem) < 0 ||
	    crypto_bignum_inverse(elem, sae->prime, elem) < 0 ||
	    crypto_bignum_to_bin(elem, sae->own_commit_element,
				 sizeof(sae->own_commit_element),
				 sae->prime_len) < 0) {
		wpa_printf(MSG_DEBUG, "SAE: Could not compute commit-element");
		goto fail;
	}

	wpa_hexdump(MSG_DEBUG, "SAE: commit-element",
		    sae->own_commit_element, sae->prime_len);

	ret = 0;
fail:
	crypto_bignum_deinit(elem, 0);
	crypto_bignum_deinit(mask, 1);
	crypto_bignum_deinit(bn_rand, 1);
	crypto_bignum_deinit(x, 1);
	return ret;
}


static int sae_prepare_commit_dh(const u8 *addr1, const u8 *addr2,
				 const u8 *password, size_t password_len,
				 struct sae_data *sae)
{
	struct crypto_bignum *pwe;
	int ret = 0;

	pwe = crypto_bignum_init();
	if (pwe == NULL ||
	    sae_derive_pwe_dh(sae, addr1, addr2, password, password_len, pwe) <
	    0 ||
	    sae_derive_commit_dh(sae, pwe) < 0)
		ret = -1;

	crypto_bignum_deinit(pwe, 1);

	return ret;
}


int sae_prepare_commit(const u8 *addr1, const u8 *addr2,
		       const u8 *password, size_t password_len,
		       struct sae_data *sae)
{
	if (sae->ec) {
		return sae_prepare_commit_ec(addr1, addr2, password,
					     password_len, sae);
	}

	if (sae->dh) {
		return sae_prepare_commit_dh(addr1, addr2, password,
					     password_len, sae);
	}

	return -1;
}


static int sae_check_peer_commit(struct sae_data *sae)
{
	u8 order[SAE_MAX_PRIME_LEN], prime[SAE_MAX_PRIME_LEN];

	if (crypto_bignum_to_bin(sae->order, order, sizeof(order),
				 sae->prime_len) < 0 ||
	    crypto_bignum_to_bin(sae->prime, prime, sizeof(prime),
				 sae->prime_len) < 0)
		return -1;

	/* 0 < scalar < r */
	if (val_zero(sae->peer_commit_scalar, sae->prime_len) ||
	    os_memcmp(sae->peer_commit_scalar, order, sae->prime_len) >= 0) {
		wpa_printf(MSG_DEBUG, "SAE: Invalid peer scalar");
		return -1;
	}

	if (sae->dh) {
		if (os_memcmp(sae->peer_commit_element, prime, sae->prime_len)
		    >= 0 ||
		    val_zero_or_one(sae->peer_commit_element, sae->prime_len)) {
			wpa_printf(MSG_DEBUG, "SAE: Invalid peer element");
			return -1;
		}
		return 0;
	}

	/* element x and y coordinates < p */
	if (os_memcmp(sae->peer_commit_element, prime, sae->prime_len) >= 0 ||
	    os_memcmp(sae->peer_commit_element + sae->prime_len, prime,
		      sae->prime_len) >= 0) {
		wpa_printf(MSG_DEBUG, "SAE: Invalid coordinates in peer "
			   "element");
		return -1;
	}

	return 0;
}


static int sae_derive_k_ec(struct sae_data *sae, u8 *k)
{
	struct crypto_ec_point *pwe, *peer_elem, *K;
	struct crypto_bignum *rand_bn, *peer_scalar;
	int ret = -1;

	pwe = crypto_ec_point_from_bin(sae->ec, sae->pwe);
	peer_scalar = crypto_bignum_init_set(sae->peer_commit_scalar,
					     sae->prime_len);
	peer_elem = crypto_ec_point_from_bin(sae->ec, sae->peer_commit_element);
	K = crypto_ec_point_init(sae->ec);
	rand_bn = crypto_bignum_init_set(sae->sae_rand, sae->rand_len);
	if (pwe == NULL || peer_elem == NULL || peer_scalar == NULL ||
	    K == NULL || rand_bn == NULL)
		goto fail;

	if (!crypto_ec_point_is_on_curve(sae->ec, peer_elem)) {
		wpa_printf(MSG_DEBUG, "SAE: Peer element is not on curve");
		goto fail;
	}

	/*
	 * K = scalar-op(rand, (elem-op(scalar-op(peer-commit-scalar, PWE),
	 *                                        PEER-COMMIT-ELEMENT)))
	 * If K is identity element (point-at-infinity), reject
	 * k = F(K) (= x coordinate)
	 */

	if (crypto_ec_point_mul(sae->ec, pwe, peer_scalar, K) < 0 ||
	    crypto_ec_point_add(sae->ec, K, peer_elem, K) < 0 ||
	    crypto_ec_point_mul(sae->ec, K, rand_bn, K) < 0 ||
	    crypto_ec_point_is_at_infinity(sae->ec, K) ||
	    crypto_ec_point_to_bin(sae->ec, K, k, NULL) < 0) {
		wpa_printf(MSG_DEBUG, "SAE: Failed to calculate K and k");
		goto fail;
	}

	wpa_hexdump_key(MSG_DEBUG, "SAE: k", k, sae->prime_len);

	ret = 0;
fail:
	crypto_ec_point_deinit(pwe, 1);
	crypto_ec_point_deinit(peer_elem, 0);
	crypto_ec_point_deinit(K, 1);
	crypto_bignum_deinit(rand_bn, 1);
	return ret;
}


static int sae_derive_k_dh(struct sae_data *sae, u8 *k)
{
	struct crypto_bignum *pwe, *peer_elem, *K, *rand_bn, *peer_scalar;
	int ret = -1;

	pwe = crypto_bignum_init_set(sae->pwe, sae->prime_len);
	peer_scalar = crypto_bignum_init_set(sae->peer_commit_scalar,
					     sae->prime_len);
	peer_elem = crypto_bignum_init_set(sae->peer_commit_element,
					   sae->prime_len);
	K = crypto_bignum_init();
	rand_bn = crypto_bignum_init_set(sae->sae_rand, sae->rand_len);
	if (pwe == NULL || peer_elem == NULL || peer_scalar == NULL ||
	    K == NULL || rand_bn == NULL)
		goto fail;

	/*
	 * K = scalar-op(rand, (elem-op(scalar-op(peer-commit-scalar, PWE),
	 *                                        PEER-COMMIT-ELEMENT)))
	 * If K is identity element (one), reject.
	 * k = F(K) (= x coordinate)
	 */

	if (crypto_bignum_exptmod(pwe, peer_scalar, sae->prime, K) < 0 ||
	    crypto_bignum_mulmod(K, peer_elem, sae->prime, K) < 0 ||
	    crypto_bignum_exptmod(K, rand_bn, sae->prime, K) < 0 ||
	    crypto_bignum_to_bin(K, k, SAE_MAX_PRIME_LEN, sae->prime_len) < 0 ||
	    val_one(k, sae->prime_len)) {
		wpa_printf(MSG_DEBUG, "SAE: Failed to calculate K and k");
		goto fail;
	}

	wpa_hexdump_key(MSG_DEBUG, "SAE: k", k, sae->prime_len);

	ret = 0;
fail:
	crypto_bignum_deinit(pwe, 1);
	crypto_bignum_deinit(peer_elem, 0);
	crypto_bignum_deinit(K, 1);
	crypto_bignum_deinit(rand_bn, 1);
	return ret;
}


static int sae_derive_k(struct sae_data *sae, u8 *k)
{
	if (sae->ec)
		return sae_derive_k_ec(sae, k);
	return sae_derive_k_dh(sae, k);
}


static int sae_derive_keys(struct sae_data *sae, const u8 *k)
{
	u8 null_key[SAE_KEYSEED_KEY_LEN], val[SAE_MAX_PRIME_LEN];
	u8 keyseed[SHA256_MAC_LEN];
	u8 keys[SAE_KCK_LEN + SAE_PMK_LEN];
	struct crypto_bignum *own_scalar, *peer_scalar, *tmp;
	int ret = -1;

	own_scalar = crypto_bignum_init_set(sae->own_commit_scalar,
					    sae->prime_len);
	peer_scalar = crypto_bignum_init_set(sae->peer_commit_scalar,
					     sae->prime_len);
	tmp = crypto_bignum_init();
	if (own_scalar == NULL || peer_scalar == NULL || tmp == NULL)
		goto fail;

	/* keyseed = H(<0>32, k)
	 * KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
	 *                      (commit-scalar + peer-commit-scalar) modulo r)
	 * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
	 */

	os_memset(null_key, 0, sizeof(null_key));
	hmac_sha256(null_key, sizeof(null_key), k, sae->prime_len, keyseed);
	wpa_hexdump_key(MSG_DEBUG, "SAE: keyseed", keyseed, sizeof(keyseed));

	crypto_bignum_add(own_scalar, peer_scalar, tmp);
	crypto_bignum_mod(tmp, sae->order, tmp);
	crypto_bignum_to_bin(tmp, val, sizeof(val), sae->prime_len);
	wpa_hexdump(MSG_DEBUG, "SAE: PMKID", val, SAE_PMKID_LEN);
	sha256_prf(keyseed, sizeof(keyseed), "SAE KCK and PMK",
		   val, sae->prime_len, keys, sizeof(keys));
	os_memcpy(sae->kck, keys, SAE_KCK_LEN);
	os_memcpy(sae->pmk, keys + SAE_KCK_LEN, SAE_PMK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "SAE: KCK", sae->kck, SAE_KCK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "SAE: PMK", sae->pmk, SAE_PMK_LEN);

	ret = 0;
fail:
	crypto_bignum_deinit(tmp, 0);
	crypto_bignum_deinit(peer_scalar, 0);
	crypto_bignum_deinit(own_scalar, 0);
	return ret;
}


int sae_process_commit(struct sae_data *sae)
{
	u8 k[SAE_MAX_PRIME_LEN];
	if (sae_check_peer_commit(sae) < 0 ||
	    sae_derive_k(sae, k) < 0 ||
	    sae_derive_keys(sae, k) < 0)
		return -1;
	return 0;
}


void sae_write_commit(struct sae_data *sae, struct wpabuf *buf,
		      const struct wpabuf *token)
{
	wpabuf_put_le16(buf, sae->group); /* Finite Cyclic Group */
	if (token)
		wpabuf_put_buf(buf, token);
	wpabuf_put_data(buf, sae->own_commit_scalar, sae->prime_len);
	wpabuf_put_data(buf, sae->own_commit_element,
			(sae->ec ? 2 : 1) * sae->prime_len);
}


u16 sae_parse_commit(struct sae_data *sae, const u8 *data, size_t len,
		     const u8 **token, size_t *token_len, int *allowed_groups)
{
	const u8 *pos = data, *end = data + len;
	u16 group;

	wpa_hexdump(MSG_DEBUG, "SAE: Commit fields", data, len);
	if (token)
		*token = NULL;
	if (token_len)
		*token_len = 0;

	/* Check Finite Cyclic Group */
	if (pos + 2 > end)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	group = WPA_GET_LE16(pos);
	if (allowed_groups) {
		int i;
		for (i = 0; allowed_groups[i] >= 0; i++) {
			if (allowed_groups[i] == group)
				break;
		}
		if (allowed_groups[i] != group) {
			wpa_printf(MSG_DEBUG, "SAE: Proposed group %u not "
				   "enabled in the current configuration",
				   group);
			return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
		}
	}
	if (sae->state == SAE_COMMITTED && group != sae->group) {
		wpa_printf(MSG_DEBUG, "SAE: Do not allow group to be changed");
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}
	if (group != sae->group && sae_set_group(sae, group) < 0) {
		wpa_printf(MSG_DEBUG, "SAE: Unsupported Finite Cyclic Group %u",
			   group);
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}
	if (sae->dh && !allowed_groups) {
		wpa_printf(MSG_DEBUG, "SAE: Do not allow FFC group %u without "
			   "explicit configuration enabling it", group);
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}
	pos += 2;

	if (pos + (sae->ec ? 3 : 2) * sae->prime_len < end) {
		size_t tlen = end - (pos + (sae->ec ? 3 : 2) * sae->prime_len);
		wpa_hexdump(MSG_DEBUG, "SAE: Anti-Clogging Token", pos, tlen);
		if (token)
			*token = pos;
		if (token_len)
			*token_len = tlen;
		pos += tlen;
	}

	if (pos + sae->prime_len > end) {
		wpa_printf(MSG_DEBUG, "SAE: Not enough data for scalar");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	/*
	 * IEEE Std 802.11-2012, 11.3.8.6.1: If there is a protocol instance for
	 * the peer and it is in Authenticated state, the new Commit Message
	 * shall be dropped if the peer-scalar is identical to the one used in
	 * the existing protocol instance.
	 */
	if (sae->state == SAE_ACCEPTED &&
	    os_memcmp(sae->peer_commit_scalar, pos, sae->prime_len) == 0) {
		wpa_printf(MSG_DEBUG, "SAE: Do not accept re-use of previous "
			   "peer-commit-scalar");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	os_memcpy(sae->peer_commit_scalar, pos, sae->prime_len);
	wpa_hexdump(MSG_DEBUG, "SAE: Peer commit-scalar",
		    sae->peer_commit_scalar, sae->prime_len);
	pos += sae->prime_len;

	if (sae->dh) {
		if (pos + sae->prime_len > end) {
			wpa_printf(MSG_DEBUG, "SAE: Not enough data for "
				   "commit-element");
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
		os_memcpy(sae->peer_commit_element, pos, sae->prime_len);
		wpa_hexdump(MSG_DEBUG, "SAE: Peer commit-element",
			    sae->peer_commit_element, sae->prime_len);

		return WLAN_STATUS_SUCCESS;
	}

	if (pos + 2 * sae->prime_len > end) {
		wpa_printf(MSG_DEBUG, "SAE: Not enough data for "
			   "commit-element");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
	os_memcpy(sae->peer_commit_element, pos, 2 * sae->prime_len);
	wpa_hexdump(MSG_DEBUG, "SAE: Peer commit-element(x)",
		    sae->peer_commit_element, sae->prime_len);
	wpa_hexdump(MSG_DEBUG, "SAE: Peer commit-element(y)",
		    sae->peer_commit_element + sae->prime_len, sae->prime_len);

	return WLAN_STATUS_SUCCESS;
}


void sae_write_confirm(struct sae_data *sae, struct wpabuf *buf)
{
	const u8 *sc;
	const u8 *addr[5];
	size_t len[5];

	/* Send-Confirm */
	sc = wpabuf_put(buf, 0);
	wpabuf_put_le16(buf, sae->send_confirm);
	sae->send_confirm++;

	/* Confirm
	 * CN(key, X, Y, Z, ...) =
	 *    HMAC-SHA256(key, D2OS(X) || D2OS(Y) || D2OS(Z) | ...)
	 * confirm = CN(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
	 *              peer-commit-scalar, PEER-COMMIT-ELEMENT)
	 */
	addr[0] = sc;
	len[0] = 2;
	addr[1] = sae->own_commit_scalar;
	len[1] = sae->prime_len;
	addr[2] = sae->own_commit_element;
	len[2] = (sae->ec ? 2 : 1) * sae->prime_len;
	addr[3] = sae->peer_commit_scalar;
	len[3] = sae->prime_len;
	addr[4] = sae->peer_commit_element;
	len[4] = (sae->ec ? 2 : 1) * sae->prime_len;
	hmac_sha256_vector(sae->kck, sizeof(sae->kck), 5, addr, len,
			   wpabuf_put(buf, SHA256_MAC_LEN));
}


int sae_check_confirm(struct sae_data *sae, const u8 *data, size_t len)
{
	u16 rc;
	const u8 *addr[5];
	size_t elen[5];
	u8 verifier[SHA256_MAC_LEN];

	wpa_hexdump(MSG_DEBUG, "SAE: Confirm fields", data, len);

	if (len < 2 + SHA256_MAC_LEN) {
		wpa_printf(MSG_DEBUG, "SAE: Too short confirm message");
		return -1;
	}

	rc = WPA_GET_LE16(data);
	wpa_printf(MSG_DEBUG, "SAE: peer-send-confirm %u", rc);

	/* Confirm
	 * CN(key, X, Y, Z, ...) =
	 *    HMAC-SHA256(key, D2OS(X) || D2OS(Y) || D2OS(Z) | ...)
	 * verifier = CN(KCK, peer-send-confirm, peer-commit-scalar,
	 *               PEER-COMMIT-ELEMENT, commit-scalar, COMMIT-ELEMENT)
	 */
	addr[0] = data;
	elen[0] = 2;
	addr[1] = sae->peer_commit_scalar;
	elen[1] = sae->prime_len;
	addr[2] = sae->peer_commit_element;
	elen[2] = (sae->ec ? 2 : 1) * sae->prime_len;
	addr[3] = sae->own_commit_scalar;
	elen[3] = sae->prime_len;
	addr[4] = sae->own_commit_element;
	elen[4] = (sae->ec ? 2 : 1) * sae->prime_len;
	hmac_sha256_vector(sae->kck, sizeof(sae->kck), 5, addr, elen, verifier);

	if (os_memcmp(verifier, data + 2, SHA256_MAC_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "SAE: Confirm mismatch");
		wpa_hexdump(MSG_DEBUG, "SAE: Received confirm",
			    data + 2, SHA256_MAC_LEN);
		wpa_hexdump(MSG_DEBUG, "SAE: Calculated verifier",
			    verifier, SHA256_MAC_LEN);
		return -1;
	}

	return 0;
}
