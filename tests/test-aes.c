/*
 * Test program for AES
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/crypto.h"
#include "crypto/aes_wrap.h"

#define BLOCK_SIZE 16

static void test_aes_perf(void)
{
#if 0 /* this did not seem to work with new compiler?! */
#ifdef __i386__
#define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))
	const int num_iters = 10;
	int i;
	unsigned int start, end;
	u8 key[16], pt[16], ct[16];
	void *ctx;

	printf("keySetupEnc:");
	for (i = 0; i < num_iters; i++) {
		rdtscll(start);
		ctx = aes_encrypt_init(key, 16);
		rdtscll(end);
		aes_encrypt_deinit(ctx);
		printf(" %d", end - start);
	}
	printf("\n");

	printf("Encrypt:");
	ctx = aes_encrypt_init(key, 16);
	for (i = 0; i < num_iters; i++) {
		rdtscll(start);
		aes_encrypt(ctx, pt, ct);
		rdtscll(end);
		printf(" %d", end - start);
	}
	aes_encrypt_deinit(ctx);
	printf("\n");
#endif /* __i386__ */
#endif
}


static int test_eax(void)
{
	u8 msg[] = { 0xF7, 0xFB };
	u8 key[] = { 0x91, 0x94, 0x5D, 0x3F, 0x4D, 0xCB, 0xEE, 0x0B,
		     0xF4, 0x5E, 0xF5, 0x22, 0x55, 0xF0, 0x95, 0xA4 };
	u8 nonce[] = { 0xBE, 0xCA, 0xF0, 0x43, 0xB0, 0xA2, 0x3D, 0x84,
		       0x31, 0x94, 0xBA, 0x97, 0x2C, 0x66, 0xDE, 0xBD };
	u8 hdr[] = { 0xFA, 0x3B, 0xFD, 0x48, 0x06, 0xEB, 0x53, 0xFA };
	u8 cipher[] = { 0x19, 0xDD, 0x5C, 0x4C, 0x93, 0x31, 0x04, 0x9D,
			0x0B, 0xDA, 0xB0, 0x27, 0x74, 0x08, 0xF6, 0x79,
			0x67, 0xE5 };
	u8 data[sizeof(msg)], tag[BLOCK_SIZE];

	memcpy(data, msg, sizeof(msg));
	if (aes_128_eax_encrypt(key, nonce, sizeof(nonce), hdr, sizeof(hdr),
				data, sizeof(data), tag)) {
		printf("AES-128 EAX mode encryption failed\n");
		return 1;
	}
	if (memcmp(data, cipher, sizeof(data)) != 0) {
		printf("AES-128 EAX mode encryption returned invalid cipher "
		       "text\n");
		return 1;
	}
	if (memcmp(tag, cipher + sizeof(data), BLOCK_SIZE) != 0) {
		printf("AES-128 EAX mode encryption returned invalid tag\n");
		return 1;
	}

	if (aes_128_eax_decrypt(key, nonce, sizeof(nonce), hdr, sizeof(hdr),
				data, sizeof(data), tag)) {
		printf("AES-128 EAX mode decryption failed\n");
		return 1;
	}
	if (memcmp(data, msg, sizeof(data)) != 0) {
		printf("AES-128 EAX mode decryption returned invalid plain "
		       "text\n");
		return 1;
	}

	return 0;
}


static int test_cbc(void)
{
	struct cbc_test_vector {
		u8 key[16];
		u8 iv[16];
		u8 plain[32];
		u8 cipher[32];
		size_t len;
	} vectors[] = {
		{
			{ 0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
			  0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06 },
			{ 0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
			  0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41 },
			"Single block msg",
			{ 0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8,
			  0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a },
			16
		},
		{
			{ 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0,
			  0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a },
			{ 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28,
			  0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 },
			{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
			{ 0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a,
			  0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
			  0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9,
			  0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1 },
			32
		}
	};
	int ret = 0;
	u8 *buf;
	unsigned int i;

	for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		struct cbc_test_vector *tv = &vectors[i];
		buf = malloc(tv->len);
		if (buf == NULL) {
			ret++;
			break;
		}
		memcpy(buf, tv->plain, tv->len);
		if (aes_128_cbc_encrypt(tv->key, tv->iv, buf, tv->len) ||
		    memcmp(buf, tv->cipher, tv->len) != 0) {
			printf("AES-CBC encrypt %d failed\n", i);
			ret++;
		}
		memcpy(buf, tv->cipher, tv->len);
		if (aes_128_cbc_decrypt(tv->key, tv->iv, buf, tv->len) ||
		    memcmp(buf, tv->plain, tv->len) != 0) {
			printf("AES-CBC decrypt %d failed\n", i);
			ret++;
		}
		free(buf);
	}

	return ret;
}


/*
 * GCM test vectors from
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 */
struct gcm_test_vector {
	char *k;
	char *p;
	char *aad;
	char *iv;
	char *c;
	char *t;
};

static const struct gcm_test_vector gcm_tests[] = {
	{
		/* Test Case 1 */
		"00000000000000000000000000000000",
		"",
		"",
		"000000000000000000000000",
		"",
		"58e2fccefa7e3061367f1d57a4e7455a"
	},
	{
		/* Test Case 2 */
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"",
		"000000000000000000000000",
		"0388dace60b6a392f328c2b971b2fe78",
		"ab6e47d42cec13bdf53a67b21257bddf"
	},
	{
		/* Test Case 3 */
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"",
		"cafebabefacedbaddecaf888",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
		"4d5c2af327cd64a62cf35abd2ba6fab4"
	},
	{
		/* Test Case 4 */
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"cafebabefacedbaddecaf888",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		"5bc94fbc3221a5db94fae95ae7121a47"
	},
	{
		/* Test Case 5 */
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"cafebabefacedbad",
		"61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
		"3612d2e79e3b0785561be14aaca2fccb"
	},
	{
		/* Test Case 6 */
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
		"8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
		"619cc5aefffe0bfa462af43c1699d050"
	},
	{
		/* Test Case 7 */
		"000000000000000000000000000000000000000000000000",
		"",
		"",
		"000000000000000000000000",
		"",
		"cd33b28ac773f74ba00ed1f312572435"
	},
	{
		/* Test Case 8 */
		"000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000",
		"",
		"000000000000000000000000",
		"98e7247c07f0fe411c267e4384b0f600",
		"2ff58d80033927ab8ef4d4587514f0fb"
	},
	{
		/* Test Case 9 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"",
		"cafebabefacedbaddecaf888",
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
		"9924a7c8587336bfb118024db8674a14"
	},
	{
		/* Test Case 10 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"cafebabefacedbaddecaf888",
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
		"2519498e80f1478f37ba55bd6d27618c"
	},
	{
		/* Test Case 11 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"cafebabefacedbad",
		"0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
		"65dcc57fcf623a24094fcca40d3533f8"
	},
	{
		/* Test Case 12 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
		"d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
		"dcf566ff291c25bbb8568fc3d376a6d9"
	},
	{
		/* Test Case 13 */
		"0000000000000000000000000000000000000000000000000000000000000000",
		"",
		"",
		"000000000000000000000000",
		"",
		"530f8afbc74536b9a963b4f1c4cb738b"
	},
	{
		/* Test Case 14 */
		"0000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000",
		"",
		"000000000000000000000000",
		"cea7403d4d606b6e074ec5d3baf39d18",
		"d0d1c8a799996bf0265b98b5d48ab919"
	},
	{
		/* Test Case 15 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"",
		"cafebabefacedbaddecaf888",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
		"b094dac5d93471bdec1a502270e3cc6c"
	},
	{
		/* Test Case 16 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"cafebabefacedbaddecaf888",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
		"76fc6ece0f4e1768cddf8853bb2d551b"
	},
	{
		/* Test Case 17 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"cafebabefacedbad",
		"c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
		"3a337dbf46a792c45e454913fe2ea8f2"
	},
	{
		/* Test Case 18 */
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
		"5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
		"a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
	}
};


static int test_gcm(void)
{
	int ret = 0;
	int i;
	u8 k[32], aad[32], iv[64], t[16], tag[16];
	u8 p[64], c[64], tmp[64];
	size_t k_len, p_len, aad_len, iv_len;

	for (i = 0; i < sizeof(gcm_tests) / sizeof(gcm_tests[0]); i++) {
		const struct gcm_test_vector *tc = &gcm_tests[i];

		k_len = os_strlen(tc->k) / 2;
		if (hexstr2bin(tc->k, k, k_len)) {
			printf("Invalid GCM test vector %d (k)\n", i);
			ret++;
			continue;
		}

		p_len = os_strlen(tc->p) / 2;
		if (hexstr2bin(tc->p, p, p_len)) {
			printf("Invalid GCM test vector %d (p)\n", i);
			ret++;
			continue;
		}

		aad_len = os_strlen(tc->aad) / 2;
		if (hexstr2bin(tc->aad, aad, aad_len)) {
			printf("Invalid GCM test vector %d (aad)\n", i);
			ret++;
			continue;
		}

		iv_len = os_strlen(tc->iv) / 2;
		if (hexstr2bin(tc->iv, iv, iv_len)) {
			printf("Invalid GCM test vector %d (iv)\n", i);
			ret++;
			continue;
		}

		if (hexstr2bin(tc->c, c, p_len)) {
			printf("Invalid GCM test vector %d (c)\n", i);
			ret++;
			continue;
		}

		if (hexstr2bin(tc->t, t, sizeof(t))) {
			printf("Invalid GCM test vector %d (t)\n", i);
			ret++;
			continue;
		}

		if (aes_gcm_ae(k, k_len, iv, iv_len, p, p_len, aad, aad_len,
			       tmp, tag) < 0) {
			printf("GCM-AE failed (test case %d)\n", i);
			ret++;
			continue;
		}

		if (os_memcmp(c, tmp, p_len) != 0) {
			printf("GCM-AE mismatch (test case %d)\n", i);
			ret++;
		}

		if (os_memcmp(tag, t, sizeof(tag)) != 0) {
			printf("GCM-AE tag mismatch (test case %d)\n", i);
			ret++;
		}

		if (p_len == 0) {
			if (aes_gmac(k, k_len, iv, iv_len, aad, aad_len, tag) <
			    0) {
				printf("GMAC failed (test case %d)\n", i);
				ret++;
				continue;
			}

			if (os_memcmp(tag, t, sizeof(tag)) != 0) {
				printf("GMAC tag mismatch (test case %d)\n", i);
				ret++;
			}
		}

		if (aes_gcm_ad(k, k_len, iv, iv_len, c, p_len, aad, aad_len,
			       t, tmp) < 0) {
			printf("GCM-AD failed (test case %d)\n", i);
			ret++;
			continue;
		}

		if (os_memcmp(p, tmp, p_len) != 0) {
			printf("GCM-AD mismatch (test case %d)\n", i);
			ret++;
		}
	}

	return ret;
}


/* OMAC1 AES-128 test vectors from
 * http://csrc.nist.gov/CryptoToolkit/modes/proposedmodes/omac/omac-ad.pdf
 * which are same as the examples from NIST SP800-38B
 * http://csrc.nist.gov/CryptoToolkit/modes/800-38_Series_Publications/SP800-38B.pdf
 */

struct omac1_test_vector {
	u8 k[16];
	u8 msg[64];
	int msg_len;
	u8 tag[16];
};

static struct omac1_test_vector test_vectors[] =
{
	{
		{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
		{ },
		0,
		{ 0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
		  0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46 }
	},
	{
		{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
		{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
		16,
		{ 0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
		  0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c }
	},
	{
		{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
		{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 },
		40,
		{ 0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
		  0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27 }
	},
	{
		{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
		{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		  0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		  0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 },
		64,
		{ 0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
		  0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe }
	},
};


int main(int argc, char *argv[])
{
	u8 kek[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	u8 plain[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	u8 crypt[] = {
		0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
		0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
		0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
	};
	u8 result[24];
	int ret = 0;
	unsigned int i;
	struct omac1_test_vector *tv;

	if (aes_wrap(kek, 2, plain, result)) {
		printf("AES-WRAP-128-128 reported failure\n");
		ret++;
	}
	if (memcmp(result, crypt, 24) != 0) {
		printf("AES-WRAP-128-128 failed\n");
		ret++;
	}
	if (aes_unwrap(kek, 2, crypt, result)) {
		printf("AES-UNWRAP-128-128 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain, 16) != 0) {
		printf("AES-UNWRAP-128-128 failed\n");
		ret++;
		for (i = 0; i < 16; i++)
			printf(" %02x", result[i]);
		printf("\n");
	}

	test_aes_perf();

	for (i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]); i++) {
		tv = &test_vectors[i];
		if (omac1_aes_128(tv->k, tv->msg, tv->msg_len, result) ||
		    memcmp(result, tv->tag, 16) != 0) {
			printf("OMAC1-AES-128 test vector %d failed\n", i);
			ret++;
		}

		if (tv->msg_len > 1) {
			const u8 *addr[2];
			size_t len[2];

			addr[0] = tv->msg;
			len[0] = 1;
			addr[1] = tv->msg + 1;
			len[1] = tv->msg_len - 1;

			if (omac1_aes_128_vector(tv->k, 2, addr, len,
						 result) ||
			    memcmp(result, tv->tag, 16) != 0) {
				printf("OMAC1-AES-128(vector) test vector %d "
				       "failed\n", i);
				ret++;
			}
		}
	}

	ret += test_eax();

	ret += test_cbc();

	ret += test_gcm();

	if (ret)
		printf("FAILED!\n");

	return ret;
}
