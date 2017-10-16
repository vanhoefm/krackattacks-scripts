/*
 * EAP server/peer: EAP-pwd shared routines
 * Copyright (c) 2010, Dan Harkins <dharkins@lounge.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "crypto/sha256.h"
#include "crypto/crypto.h"
#include "eap_defs.h"
#include "eap_pwd_common.h"

/* The random function H(x) = HMAC-SHA256(0^32, x) */
struct crypto_hash * eap_pwd_h_init(void)
{
	u8 allzero[SHA256_MAC_LEN];
	os_memset(allzero, 0, SHA256_MAC_LEN);
	return crypto_hash_init(CRYPTO_HASH_ALG_HMAC_SHA256, allzero,
				SHA256_MAC_LEN);
}


void eap_pwd_h_update(struct crypto_hash *hash, const u8 *data, size_t len)
{
	crypto_hash_update(hash, data, len);
}


void eap_pwd_h_final(struct crypto_hash *hash, u8 *digest)
{
	size_t len = SHA256_MAC_LEN;
	crypto_hash_finish(hash, digest, &len);
}


/* a counter-based KDF based on NIST SP800-108 */
static int eap_pwd_kdf(const u8 *key, size_t keylen, const u8 *label,
		       size_t labellen, u8 *result, size_t resultbitlen)
{
	struct crypto_hash *hash;
	u8 digest[SHA256_MAC_LEN];
	u16 i, ctr, L;
	size_t resultbytelen, len = 0, mdlen;

	resultbytelen = (resultbitlen + 7) / 8;
	ctr = 0;
	L = htons(resultbitlen);
	while (len < resultbytelen) {
		ctr++;
		i = htons(ctr);
		hash = crypto_hash_init(CRYPTO_HASH_ALG_HMAC_SHA256,
					key, keylen);
		if (hash == NULL)
			return -1;
		if (ctr > 1)
			crypto_hash_update(hash, digest, SHA256_MAC_LEN);
		crypto_hash_update(hash, (u8 *) &i, sizeof(u16));
		crypto_hash_update(hash, label, labellen);
		crypto_hash_update(hash, (u8 *) &L, sizeof(u16));
		mdlen = SHA256_MAC_LEN;
		if (crypto_hash_finish(hash, digest, &mdlen) < 0)
			return -1;
		if ((len + mdlen) > resultbytelen)
			os_memcpy(result + len, digest, resultbytelen - len);
		else
			os_memcpy(result + len, digest, mdlen);
		len += mdlen;
	}

	/* since we're expanding to a bit length, mask off the excess */
	if (resultbitlen % 8) {
		u8 mask = 0xff;
		mask <<= (8 - (resultbitlen % 8));
		result[resultbytelen - 1] &= mask;
	}

	return 0;
}


/*
 * compute a "random" secret point on an elliptic curve based
 * on the password and identities.
 */
int compute_password_element(EAP_PWD_group *grp, u16 num,
			     const u8 *password, size_t password_len,
			     const u8 *id_server, size_t id_server_len,
			     const u8 *id_peer, size_t id_peer_len,
			     const u8 *token)
{
	struct crypto_hash *hash;
	unsigned char pwe_digest[SHA256_MAC_LEN], *prfbuf = NULL, ctr;
	int is_odd, ret = 0;
	size_t primebytelen, primebitlen;
	struct crypto_bignum *x_candidate = NULL, *rnd = NULL, *cofactor = NULL;

	grp->pwe = NULL;
	grp->group = crypto_ec_init(num);
	if (!grp->group) {
		wpa_printf(MSG_INFO, "EAP-pwd: unable to create EC group");
		goto fail;
	}

	cofactor = crypto_bignum_init();
	grp->pwe = crypto_ec_point_init(grp->group);
	if (!cofactor || !grp->pwe) {
		wpa_printf(MSG_INFO, "EAP-pwd: unable to create bignums");
		goto fail;
	}

	if (crypto_ec_cofactor(grp->group, cofactor) < 0) {
		wpa_printf(MSG_INFO, "EAP-pwd: unable to get cofactor for "
			   "curve");
		goto fail;
	}
	primebitlen = crypto_ec_prime_len_bits(grp->group);
	primebytelen = crypto_ec_prime_len(grp->group);
	if ((prfbuf = os_malloc(primebytelen)) == NULL) {
		wpa_printf(MSG_INFO, "EAP-pwd: unable to malloc space for prf "
			   "buffer");
		goto fail;
	}
	os_memset(prfbuf, 0, primebytelen);
	ctr = 0;
	while (1) {
		if (ctr > 30) {
			wpa_printf(MSG_INFO, "EAP-pwd: unable to find random "
				   "point on curve for group %d, something's "
				   "fishy", num);
			goto fail;
		}
		ctr++;

		/*
		 * compute counter-mode password value and stretch to prime
		 *    pwd-seed = H(token | peer-id | server-id | password |
		 *		   counter)
		 */
		hash = eap_pwd_h_init();
		if (hash == NULL)
			goto fail;
		eap_pwd_h_update(hash, token, sizeof(u32));
		eap_pwd_h_update(hash, id_peer, id_peer_len);
		eap_pwd_h_update(hash, id_server, id_server_len);
		eap_pwd_h_update(hash, password, password_len);
		eap_pwd_h_update(hash, &ctr, sizeof(ctr));
		eap_pwd_h_final(hash, pwe_digest);

		crypto_bignum_deinit(rnd, 1);
		rnd = crypto_bignum_init_set(pwe_digest, SHA256_MAC_LEN);
		if (!rnd) {
			wpa_printf(MSG_INFO, "EAP-pwd: unable to create rnd");
			goto fail;
		}
		if (eap_pwd_kdf(pwe_digest, SHA256_MAC_LEN,
				(u8 *) "EAP-pwd Hunting And Pecking",
				os_strlen("EAP-pwd Hunting And Pecking"),
				prfbuf, primebitlen) < 0)
			goto fail;

		crypto_bignum_deinit(x_candidate, 1);
		x_candidate = crypto_bignum_init_set(prfbuf, primebytelen);
		if (!x_candidate) {
			wpa_printf(MSG_INFO,
				   "EAP-pwd: unable to create x_candidate");
			goto fail;
		}

		/*
		 * eap_pwd_kdf() returns a string of bits 0..primebitlen but
		 * BN_bin2bn will treat that string of bits as a big endian
		 * number. If the primebitlen is not an even multiple of 8
		 * then excessive bits-- those _after_ primebitlen-- so now
		 * we have to shift right the amount we masked off.
		 */
		if ((primebitlen % 8) &&
		    crypto_bignum_rshift(x_candidate,
					 (8 - (primebitlen % 8)),
					 x_candidate) < 0)
			goto fail;

		if (crypto_bignum_cmp(x_candidate,
				      crypto_ec_get_prime(grp->group)) >= 0)
			continue;

		wpa_hexdump(MSG_DEBUG, "EAP-pwd: x_candidate",
			    prfbuf, primebytelen);

		/*
		 * need to unambiguously identify the solution, if there is
		 * one...
		 */
		is_odd = crypto_bignum_is_odd(rnd);

		/*
		 * solve the quadratic equation, if it's not solvable then we
		 * don't have a point
		 */
		if (crypto_ec_point_solve_y_coord(grp->group, grp->pwe,
						  x_candidate, is_odd) != 0) {
			wpa_printf(MSG_INFO, "EAP-pwd: Could not solve for y");
			continue;
		}
		/*
		 * If there's a solution to the equation then the point must be
		 * on the curve so why check again explicitly? OpenSSL code
		 * says this is required by X9.62. We're not X9.62 but it can't
		 * hurt just to be sure.
		 */
		if (!crypto_ec_point_is_on_curve(grp->group, grp->pwe)) {
			wpa_printf(MSG_INFO, "EAP-pwd: point is not on curve");
			continue;
		}

		if (!crypto_bignum_is_one(cofactor)) {
			/* make sure the point is not in a small sub-group */
			if (crypto_ec_point_mul(grp->group, grp->pwe,
						cofactor, grp->pwe) != 0) {
				wpa_printf(MSG_INFO, "EAP-pwd: cannot "
					   "multiply generator by order");
				continue;
			}
			if (crypto_ec_point_is_at_infinity(grp->group,
							   grp->pwe)) {
				wpa_printf(MSG_INFO, "EAP-pwd: point is at "
					   "infinity");
				continue;
			}
		}
		/* if we got here then we have a new generator. */
		break;
	}
	wpa_printf(MSG_DEBUG, "EAP-pwd: found a PWE in %d tries", ctr);
	grp->group_num = num;
	if (0) {
 fail:
		crypto_ec_deinit(grp->group);
		grp->group = NULL;
		crypto_ec_point_deinit(grp->pwe, 1);
		grp->pwe = NULL;
		ret = 1;
	}
	/* cleanliness and order.... */
	crypto_bignum_deinit(cofactor, 1);
	crypto_bignum_deinit(x_candidate, 1);
	crypto_bignum_deinit(rnd, 1);
	os_free(prfbuf);

	return ret;
}


int compute_keys(EAP_PWD_group *grp, const struct crypto_bignum *k,
		 const struct crypto_bignum *peer_scalar,
		 const struct crypto_bignum *server_scalar,
		 const u8 *confirm_peer, const u8 *confirm_server,
		 const u32 *ciphersuite, u8 *msk, u8 *emsk, u8 *session_id)
{
	struct crypto_hash *hash;
	u8 mk[SHA256_MAC_LEN], *cruft;
	u8 msk_emsk[EAP_MSK_LEN + EAP_EMSK_LEN];
	size_t prime_len, order_len;

	prime_len = crypto_ec_prime_len(grp->group);
	order_len = crypto_ec_order_len(grp->group);

	cruft = os_malloc(prime_len);
	if (!cruft)
		return -1;

	/*
	 * first compute the session-id = TypeCode | H(ciphersuite | scal_p |
	 *	scal_s)
	 */
	session_id[0] = EAP_TYPE_PWD;
	hash = eap_pwd_h_init();
	if (hash == NULL) {
		os_free(cruft);
		return -1;
	}
	eap_pwd_h_update(hash, (const u8 *) ciphersuite, sizeof(u32));
	crypto_bignum_to_bin(peer_scalar, cruft, order_len, order_len);
	eap_pwd_h_update(hash, cruft, order_len);
	crypto_bignum_to_bin(server_scalar, cruft, order_len, order_len);
	eap_pwd_h_update(hash, cruft, order_len);
	eap_pwd_h_final(hash, &session_id[1]);

	/* then compute MK = H(k | confirm-peer | confirm-server) */
	hash = eap_pwd_h_init();
	if (hash == NULL) {
		os_free(cruft);
		return -1;
	}
	crypto_bignum_to_bin(k, cruft, prime_len, prime_len);
	eap_pwd_h_update(hash, cruft, prime_len);
	os_free(cruft);
	eap_pwd_h_update(hash, confirm_peer, SHA256_MAC_LEN);
	eap_pwd_h_update(hash, confirm_server, SHA256_MAC_LEN);
	eap_pwd_h_final(hash, mk);

	/* stretch the mk with the session-id to get MSK | EMSK */
	if (eap_pwd_kdf(mk, SHA256_MAC_LEN,
			session_id, SHA256_MAC_LEN + 1,
			msk_emsk, (EAP_MSK_LEN + EAP_EMSK_LEN) * 8) < 0) {
		return -1;
	}

	os_memcpy(msk, msk_emsk, EAP_MSK_LEN);
	os_memcpy(emsk, msk_emsk + EAP_MSK_LEN, EAP_EMSK_LEN);

	return 1;
}
