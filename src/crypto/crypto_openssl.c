/*
 * WPA Supplicant / wrapper functions for libcrypto
 * Copyright (c) 2004-2009, Jouni Malinen <j@w1.fi>
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
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "common.h"
#include "crypto.h"

#if OPENSSL_VERSION_NUMBER < 0x00907000
#define DES_key_schedule des_key_schedule
#define DES_cblock des_cblock
#define DES_set_key(key, schedule) des_set_key((key), *(schedule))
#define DES_ecb_encrypt(input, output, ks, enc) \
	des_ecb_encrypt((input), (output), *(ks), (enc))
#endif /* openssl < 0.9.7 */


int openssl_digest_vector(const EVP_MD *type, size_t num_elem,
			  const u8 *addr[], const size_t *len, u8 *mac)
{
	EVP_MD_CTX ctx;
	size_t i;
	unsigned int mac_len;

	EVP_MD_CTX_init(&ctx);
	if (!EVP_DigestInit_ex(&ctx, type, NULL)) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestInit_ex failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	for (i = 0; i < num_elem; i++) {
		if (!EVP_DigestUpdate(&ctx, addr[i], len[i])) {
			wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestUpdate "
				   "failed: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
	}
	if (!EVP_DigestFinal(&ctx, mac, &mac_len)) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestFinal failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	return 0;
}


int md4_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return openssl_digest_vector(EVP_md4(), num_elem, addr, len, mac);
}


void des_encrypt(const u8 *clear, const u8 *key, u8 *cypher)
{
	u8 pkey[8], next, tmp;
	int i;
	DES_key_schedule ks;

	/* Add parity bits to the key */
	next = 0;
	for (i = 0; i < 7; i++) {
		tmp = key[i];
		pkey[i] = (tmp >> i) | next | 1;
		next = tmp << (7 - i);
	}
	pkey[i] = next | 1;

	DES_set_key(&pkey, &ks);
	DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cypher, &ks,
			DES_ENCRYPT);
}


int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return openssl_digest_vector(EVP_md5(), num_elem, addr, len, mac);
}


int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return openssl_digest_vector(EVP_sha1(), num_elem, addr, len, mac);
}


int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len,
		  u8 *mac)
{
	return openssl_digest_vector(EVP_sha256(), num_elem, addr, len, mac);
}


void * aes_encrypt_init(const u8 *key, size_t len)
{
	AES_KEY *ak;
	ak = os_malloc(sizeof(*ak));
	if (ak == NULL)
		return NULL;
	if (AES_set_encrypt_key(key, 8 * len, ak) < 0) {
		os_free(ak);
		return NULL;
	}
	return ak;
}


void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt)
{
	AES_encrypt(plain, crypt, ctx);
}


void aes_encrypt_deinit(void *ctx)
{
	os_free(ctx);
}


void * aes_decrypt_init(const u8 *key, size_t len)
{
	AES_KEY *ak;
	ak = os_malloc(sizeof(*ak));
	if (ak == NULL)
		return NULL;
	if (AES_set_decrypt_key(key, 8 * len, ak) < 0) {
		os_free(ak);
		return NULL;
	}
	return ak;
}


void aes_decrypt(void *ctx, const u8 *crypt, u8 *plain)
{
	AES_decrypt(crypt, plain, ctx);
}


void aes_decrypt_deinit(void *ctx)
{
	os_free(ctx);
}


int crypto_mod_exp(const u8 *base, size_t base_len,
		   const u8 *power, size_t power_len,
		   const u8 *modulus, size_t modulus_len,
		   u8 *result, size_t *result_len)
{
	BIGNUM *bn_base, *bn_exp, *bn_modulus, *bn_result;
	int ret = -1;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		return -1;

	bn_base = BN_bin2bn(base, base_len, NULL);
	bn_exp = BN_bin2bn(power, power_len, NULL);
	bn_modulus = BN_bin2bn(modulus, modulus_len, NULL);
	bn_result = BN_new();

	if (bn_base == NULL || bn_exp == NULL || bn_modulus == NULL ||
	    bn_result == NULL)
		goto error;

	if (BN_mod_exp(bn_result, bn_base, bn_exp, bn_modulus, ctx) != 1)
		goto error;

	*result_len = BN_bn2bin(bn_result, result);
	ret = 0;

error:
	BN_free(bn_base);
	BN_free(bn_exp);
	BN_free(bn_modulus);
	BN_free(bn_result);
	BN_CTX_free(ctx);
	return ret;
}


struct crypto_cipher {
	EVP_CIPHER_CTX enc;
	EVP_CIPHER_CTX dec;
};


struct crypto_cipher * crypto_cipher_init(enum crypto_cipher_alg alg,
					  const u8 *iv, const u8 *key,
					  size_t key_len)
{
	struct crypto_cipher *ctx;
	const EVP_CIPHER *cipher;

	ctx = os_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	switch (alg) {
#ifndef OPENSSL_NO_RC4
	case CRYPTO_CIPHER_ALG_RC4:
		cipher = EVP_rc4();
		break;
#endif /* OPENSSL_NO_RC4 */
#ifndef OPENSSL_NO_AES
	case CRYPTO_CIPHER_ALG_AES:
		switch (key_len) {
		case 16:
			cipher = EVP_aes_128_cbc();
			break;
		case 24:
			cipher = EVP_aes_192_cbc();
			break;
		case 32:
			cipher = EVP_aes_256_cbc();
			break;
		default:
			os_free(ctx);
			return NULL;
		}
		break;
#endif /* OPENSSL_NO_AES */
#ifndef OPENSSL_NO_DES
	case CRYPTO_CIPHER_ALG_3DES:
		cipher = EVP_des_ede3_cbc();
		break;
	case CRYPTO_CIPHER_ALG_DES:
		cipher = EVP_des_cbc();
		break;
#endif /* OPENSSL_NO_DES */
#ifndef OPENSSL_NO_RC2
	case CRYPTO_CIPHER_ALG_RC2:
		cipher = EVP_rc2_ecb();
		break;
#endif /* OPENSSL_NO_RC2 */
	default:
		os_free(ctx);
		return NULL;
	}

	EVP_CIPHER_CTX_init(&ctx->enc);
	EVP_CIPHER_CTX_set_padding(&ctx->enc, 0);
	if (!EVP_EncryptInit_ex(&ctx->enc, cipher, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_set_key_length(&ctx->enc, key_len) ||
	    !EVP_EncryptInit_ex(&ctx->enc, cipher, NULL, key, iv)) {
		EVP_CIPHER_CTX_cleanup(&ctx->enc);
		os_free(ctx);
		return NULL;
	}

	EVP_CIPHER_CTX_init(&ctx->dec);
	EVP_CIPHER_CTX_set_padding(&ctx->dec, 0);
	if (!EVP_DecryptInit_ex(&ctx->dec, cipher, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_set_key_length(&ctx->dec, key_len) ||
	    !EVP_DecryptInit_ex(&ctx->dec, cipher, NULL, key, iv)) {
		EVP_CIPHER_CTX_cleanup(&ctx->enc);
		EVP_CIPHER_CTX_cleanup(&ctx->dec);
		os_free(ctx);
		return NULL;
	}

	return ctx;
}


int crypto_cipher_encrypt(struct crypto_cipher *ctx, const u8 *plain,
			  u8 *crypt, size_t len)
{
	int outl;
	if (!EVP_EncryptUpdate(&ctx->enc, crypt, &outl, plain, len))
		return -1;
	return 0;
}


int crypto_cipher_decrypt(struct crypto_cipher *ctx, const u8 *crypt,
			  u8 *plain, size_t len)
{
	int outl;
	outl = len;
	if (!EVP_DecryptUpdate(&ctx->dec, plain, &outl, crypt, len))
		return -1;
	return 0;
}


void crypto_cipher_deinit(struct crypto_cipher *ctx)
{
	EVP_CIPHER_CTX_cleanup(&ctx->enc);
	EVP_CIPHER_CTX_cleanup(&ctx->dec);
	os_free(ctx);
}
