/*
 * DPP functionality shared between hostapd and wpa_supplicant
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include "utils/common.h"
#include "utils/base64.h"
#include "utils/json.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "crypto/aes.h"
#include "crypto/aes_siv.h"
#include "crypto/sha384.h"
#include "crypto/sha512.h"
#include "dpp.h"


#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Compatibility wrappers for older versions. */

static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	sig->r = r;
	sig->s = s;
	return 1;
}


static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr,
			   const BIGNUM **ps)
{
	if (pr)
		*pr = sig->r;
	if (ps)
		*ps = sig->s;
}

#endif


static const struct dpp_curve_params dpp_curves[] = {
	/* The mandatory to support and the default NIST P-256 curve needs to
	 * be the first entry on this list. */
	{ "prime256v1", 32, 32, 16, 32, "P-256" },
	{ "secp384r1", 48, 48, 24, 48, "P-384" },
	{ "secp521r1", 64, 64, 32, 66, "P-521" },
	{ "brainpoolP256r1", 32, 32, 16, 32, "BP-256R1" },
	{ "brainpoolP384r1", 48, 48, 24, 48, "BP-384R1" },
	{ "brainpoolP512r1", 64, 64, 32, 64, "BP-512R1" },
	{ NULL, 0, 0, 0, 0, NULL }
};


static struct wpabuf * dpp_get_pubkey_point(EVP_PKEY *pkey, int prefix)
{
	int len, res;
	EC_KEY *eckey;
	struct wpabuf *buf;
	unsigned char *pos;

	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (!eckey)
		return NULL;
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_UNCOMPRESSED);
	len = i2o_ECPublicKey(eckey, NULL);
	if (len <= 0) {
		wpa_printf(MSG_ERROR,
			   "DDP: Failed to determine public key encoding length");
		EC_KEY_free(eckey);
		return NULL;
	}

	buf = wpabuf_alloc(len);
	if (!buf) {
		EC_KEY_free(eckey);
		return NULL;
	}

	pos = wpabuf_put(buf, len);
	res = i2o_ECPublicKey(eckey, &pos);
	EC_KEY_free(eckey);
	if (res != len) {
		wpa_printf(MSG_ERROR,
			   "DDP: Failed to encode public key (res=%d/%d)",
			   res, len);
		wpabuf_free(buf);
		return NULL;
	}

	if (!prefix) {
		/* Remove 0x04 prefix to match DPP definition */
		pos = wpabuf_mhead(buf);
		os_memmove(pos, pos + 1, len - 1);
		buf->used--;
	}

	return buf;
}


static EVP_PKEY * dpp_set_pubkey_point_group(const EC_GROUP *group,
					     const u8 *buf_x, const u8 *buf_y,
					     size_t len)
{
	EC_KEY *eckey = NULL;
	BN_CTX *ctx;
	EC_POINT *point = NULL;
	BIGNUM *x = NULL, *y = NULL;
	EVP_PKEY *pkey = NULL;

	ctx = BN_CTX_new();
	if (!ctx) {
		wpa_printf(MSG_ERROR, "DPP: Out of memory");
		return NULL;
	}

	point = EC_POINT_new(group);
	x = BN_bin2bn(buf_x, len, NULL);
	y = BN_bin2bn(buf_y, len, NULL);
	if (!point || !x || !y) {
		wpa_printf(MSG_ERROR, "DPP: Out of memory");
		goto fail;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx)) {
		wpa_printf(MSG_ERROR,
			   "DPP: OpenSSL: EC_POINT_set_affine_coordinates_GFp failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	if (!EC_POINT_is_on_curve(group, point, ctx) ||
	    EC_POINT_is_at_infinity(group, point)) {
		wpa_printf(MSG_ERROR, "DPP: Invalid point");
		goto fail;
	}

	eckey = EC_KEY_new();
	if (!eckey ||
	    EC_KEY_set_group(eckey, group) != 1 ||
	    EC_KEY_set_public_key(eckey, point) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to set EC_KEY: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	pkey = EVP_PKEY_new();
	if (!pkey || EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1) {
		wpa_printf(MSG_ERROR, "DPP: Could not create EVP_PKEY");
		goto fail;
	}

out:
	BN_free(x);
	BN_free(y);
	EC_KEY_free(eckey);
	EC_POINT_free(point);
	BN_CTX_free(ctx);
	return pkey;
fail:
	EVP_PKEY_free(pkey);
	pkey = NULL;
	goto out;
}


static EVP_PKEY * dpp_set_pubkey_point(EVP_PKEY *group_key,
				       const u8 *buf, size_t len)
{
	EC_KEY *eckey;
	const EC_GROUP *group;
	EVP_PKEY *pkey = NULL;

	if (len & 1)
		return NULL;

	eckey = EVP_PKEY_get1_EC_KEY(group_key);
	if (!eckey) {
		wpa_printf(MSG_ERROR,
			   "DPP: Could not get EC_KEY from group_key");
		return NULL;
	}

	group = EC_KEY_get0_group(eckey);
	if (group)
		pkey = dpp_set_pubkey_point_group(group, buf, buf + len / 2,
						  len / 2);
	else
		wpa_printf(MSG_ERROR, "DPP: Could not get EC group");

	EC_KEY_free(eckey);
	return pkey;
}


struct wpabuf * dpp_alloc_msg(enum dpp_public_action_frame_type type,
			      size_t len)
{
	struct wpabuf *msg;

	msg = wpabuf_alloc(7 + len);
	if (!msg)
		return NULL;
	wpabuf_put_u8(msg, WLAN_ACTION_PUBLIC);
	wpabuf_put_u8(msg, WLAN_PA_VENDOR_SPECIFIC);
	wpabuf_put_be24(msg, OUI_WFA);
	wpabuf_put_u8(msg, DPP_OUI_TYPE);
	wpabuf_put_u8(msg, type);
	return msg;
}


const u8 * dpp_get_attr(const u8 *buf, size_t len, u16 req_id, u16 *ret_len)
{
	u16 id, alen;
	const u8 *pos = buf, *end = buf + len;

	while (end - pos >= 4) {
		id = WPA_GET_LE16(pos);
		pos += 2;
		alen = WPA_GET_LE16(pos);
		pos += 2;
		if (alen > end - pos)
			return NULL;
		if (id == req_id) {
			*ret_len = alen;
			return pos;
		}
		pos += alen;
	}

	return NULL;
}


int dpp_check_attrs(const u8 *buf, size_t len)
{
	const u8 *pos, *end;

	pos = buf;
	end = buf + len;
	while (end - pos >= 4) {
		u16 id, alen;

		id = WPA_GET_LE16(pos);
		pos += 2;
		alen = WPA_GET_LE16(pos);
		pos += 2;
		wpa_printf(MSG_MSGDUMP, "DPP: Attribute ID %04x len %u",
			   id, alen);
		if (alen > end - pos) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Truncated message - not enough room for the attribute - dropped");
			return -1;
		}
		pos += alen;
	}

	if (end != pos) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unexpected octets (%d) after the last attribute",
			   (int) (end - pos));
		return -1;
	}

	return 0;
}


void dpp_bootstrap_info_free(struct dpp_bootstrap_info *info)
{
	if (!info)
		return;
	os_free(info->uri);
	os_free(info->info);
	EVP_PKEY_free(info->pubkey);
	os_free(info);
}


static int dpp_uri_valid_info(const char *info)
{
	while (*info) {
		unsigned char val = *info++;

		if (val < 0x20 || val > 0x7e || val == 0x3b)
			return 0;
	}

	return 1;
}


static int dpp_clone_uri(struct dpp_bootstrap_info *bi, const char *uri)
{
	bi->uri = os_strdup(uri);
	return bi->uri ? 0 : -1;
}


int dpp_parse_uri_chan_list(struct dpp_bootstrap_info *bi,
			    const char *chan_list)
{
	const char *pos = chan_list;
	int opclass, channel, freq;

	while (pos && *pos && *pos != ';') {
		opclass = atoi(pos);
		if (opclass <= 0)
			goto fail;
		pos = os_strchr(pos, '/');
		if (!pos)
			goto fail;
		pos++;
		channel = atoi(pos);
		if (channel <= 0)
			goto fail;
		while (*pos >= '0' && *pos <= '9')
			pos++;
		freq = ieee80211_chan_to_freq(NULL, opclass, channel);
		wpa_printf(MSG_DEBUG,
			   "DPP: URI channel-list: opclass=%d channel=%d ==> freq=%d",
			   opclass, channel, freq);
		if (freq < 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Ignore unknown URI channel-list channel (opclass=%d channel=%d)",
				   opclass, channel);
		} else if (bi->num_freq == DPP_BOOTSTRAP_MAX_FREQ) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Too many channels in URI channel-list - ignore list");
			bi->num_freq = 0;
			break;
		} else {
			bi->freq[bi->num_freq++] = freq;
		}

		if (*pos == ';' || *pos == '\0')
			break;
		if (*pos != ',')
			goto fail;
		pos++;
	}

	return 0;
fail:
	wpa_printf(MSG_DEBUG, "DPP: Invalid URI channel-list");
	return -1;
}


int dpp_parse_uri_mac(struct dpp_bootstrap_info *bi, const char *mac)
{
	if (!mac)
		return 0;

	if (hwaddr_aton2(mac, bi->mac_addr) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Invalid URI mac");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "DPP: URI mac: " MACSTR, MAC2STR(bi->mac_addr));

	return 0;
}


int dpp_parse_uri_info(struct dpp_bootstrap_info *bi, const char *info)
{
	const char *end;

	if (!info)
		return 0;

	end = os_strchr(info, ';');
	if (!end)
		end = info + os_strlen(info);
	bi->info = os_malloc(end - info + 1);
	if (!bi->info)
		return -1;
	os_memcpy(bi->info, info, end - info);
	bi->info[end - info] = '\0';
	wpa_printf(MSG_DEBUG, "DPP: URI(information): %s", bi->info);
	if (!dpp_uri_valid_info(bi->info)) {
		wpa_printf(MSG_DEBUG, "DPP: Invalid URI information payload");
		return -1;
	}

	return 0;
}


static const struct dpp_curve_params *
dpp_get_curve_oid(const ASN1_OBJECT *poid)
{
	ASN1_OBJECT *oid;
	int i;

	for (i = 0; dpp_curves[i].name; i++) {
		oid = OBJ_txt2obj(dpp_curves[i].name, 0);
		if (oid && OBJ_cmp(poid, oid) == 0)
			return &dpp_curves[i];
	}
	return NULL;
}


static const struct dpp_curve_params * dpp_get_curve_nid(int nid)
{
	int i, tmp;

	if (!nid)
		return NULL;
	for (i = 0; dpp_curves[i].name; i++) {
		tmp = OBJ_txt2nid(dpp_curves[i].name);
		if (tmp == nid)
			return &dpp_curves[i];
	}
	return NULL;
}


static int dpp_parse_uri_pk(struct dpp_bootstrap_info *bi, const char *info)
{
	const char *end;
	u8 *data;
	size_t data_len;
	EVP_PKEY *pkey;
	const unsigned char *p;
	int res;
	X509_PUBKEY *pub = NULL;
	ASN1_OBJECT *ppkalg;
	const unsigned char *pk;
	int ppklen;
	X509_ALGOR *pa;
	ASN1_OBJECT *pa_oid;
	const void *pval;
	int ptype;
	const ASN1_OBJECT *poid;
	char buf[100];

	end = os_strchr(info, ';');
	if (!end)
		return -1;

	data = base64_decode((const unsigned char *) info, end - info,
			     &data_len);
	if (!data) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid base64 encoding on URI public-key");
		return -1;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Base64 decoded URI public-key",
		    data, data_len);

	if (sha256_vector(1, (const u8 **) &data, &data_len,
			  bi->pubkey_hash) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to hash public key");
		return -1;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Public key hash",
		    bi->pubkey_hash, SHA256_MAC_LEN);

	/* DER encoded ASN.1 SubjectPublicKeyInfo
	 *
	 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
	 *      algorithm            AlgorithmIdentifier,
	 *      subjectPublicKey     BIT STRING  }
	 *
	 * AlgorithmIdentifier  ::=  SEQUENCE  {
	 *      algorithm               OBJECT IDENTIFIER,
	 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
	 *
	 * subjectPublicKey = compressed format public key per ANSI X9.63
	 * algorithm = ecPublicKey (1.2.840.10045.2.1)
	 * parameters = shall be present and shall be OBJECT IDENTIFIER; e.g.,
	 *       prime256v1 (1.2.840.10045.3.1.7)
	 */

	p = data;
	pkey = d2i_PUBKEY(NULL, &p, data_len);
	os_free(data);

	if (!pkey) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Could not parse URI public-key SubjectPublicKeyInfo");
		return -1;
	}

	if (EVP_PKEY_type(EVP_PKEY_id(pkey)) != EVP_PKEY_EC) {
		wpa_printf(MSG_DEBUG,
			   "DPP: SubjectPublicKeyInfo does not describe an EC key");
		EVP_PKEY_free(pkey);
		return -1;
	}

	res = X509_PUBKEY_set(&pub, pkey);
	if (res != 1) {
		wpa_printf(MSG_DEBUG, "DPP: Could not set pubkey");
		goto fail;
	}

	res = X509_PUBKEY_get0_param(&ppkalg, &pk, &ppklen, &pa, pub);
	if (res != 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Could not extract SubjectPublicKeyInfo parameters");
		goto fail;
	}
	res = OBJ_obj2txt(buf, sizeof(buf), ppkalg, 0);
	if (res < 0 || (size_t) res >= sizeof(buf)) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Could not extract SubjectPublicKeyInfo algorithm");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: URI subjectPublicKey algorithm: %s", buf);
	if (os_strcmp(buf, "id-ecPublicKey") != 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unsupported SubjectPublicKeyInfo algorithm");
		goto fail;
	}

	X509_ALGOR_get0(&pa_oid, &ptype, (void *) &pval, pa);
	if (ptype != V_ASN1_OBJECT) {
		wpa_printf(MSG_DEBUG,
			   "DPP: SubjectPublicKeyInfo parameters did not contain an OID");
		goto fail;
	}
	poid = pval;
	res = OBJ_obj2txt(buf, sizeof(buf), poid, 0);
	if (res < 0 || (size_t) res >= sizeof(buf)) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Could not extract SubjectPublicKeyInfo parameters OID");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: URI subjectPublicKey parameters: %s", buf);
	bi->curve = dpp_get_curve_oid(poid);
	if (!bi->curve) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unsupported SubjectPublicKeyInfo curve: %s",
			   buf);
		goto fail;
	}

	wpa_hexdump(MSG_DEBUG, "DPP: URI subjectPublicKey", pk, ppklen);

	X509_PUBKEY_free(pub);
	bi->pubkey = pkey;
	return 0;
fail:
	X509_PUBKEY_free(pub);
	EVP_PKEY_free(pkey);
	return -1;
}


static struct dpp_bootstrap_info * dpp_parse_uri(const char *uri)
{
	const char *pos = uri;
	const char *end;
	const char *chan_list = NULL, *mac = NULL, *info = NULL, *pk = NULL;
	struct dpp_bootstrap_info *bi;

	wpa_hexdump_ascii(MSG_DEBUG, "DPP: URI", uri, os_strlen(uri));

	if (os_strncmp(pos, "DPP:", 4) != 0) {
		wpa_printf(MSG_INFO, "DPP: Not a DPP URI");
		return NULL;
	}
	pos += 4;

	for (;;) {
		end = os_strchr(pos, ';');
		if (!end)
			break;

		if (end == pos) {
			/* Handle terminating ";;" and ignore unexpected ";"
			 * for parsing robustness. */
			pos++;
			continue;
		}

		if (pos[0] == 'C' && pos[1] == ':' && !chan_list)
			chan_list = pos + 2;
		else if (pos[0] == 'M' && pos[1] == ':' && !mac)
			mac = pos + 2;
		else if (pos[0] == 'I' && pos[1] == ':' && !info)
			info = pos + 2;
		else if (pos[0] == 'K' && pos[1] == ':' && !pk)
			pk = pos + 2;
		else
			wpa_hexdump_ascii(MSG_DEBUG,
					  "DPP: Ignore unrecognized URI parameter",
					  pos, end - pos);
		pos = end + 1;
	}

	if (!pk) {
		wpa_printf(MSG_INFO, "DPP: URI missing public-key");
		return NULL;
	}

	bi = os_zalloc(sizeof(*bi));
	if (!bi)
		return NULL;

	if (dpp_clone_uri(bi, uri) < 0 ||
	    dpp_parse_uri_chan_list(bi, chan_list) < 0 ||
	    dpp_parse_uri_mac(bi, mac) < 0 ||
	    dpp_parse_uri_info(bi, info) < 0 ||
	    dpp_parse_uri_pk(bi, pk) < 0) {
		dpp_bootstrap_info_free(bi);
		bi = NULL;
	}

	return bi;
}


struct dpp_bootstrap_info * dpp_parse_qr_code(const char *uri)
{
	struct dpp_bootstrap_info *bi;

	bi = dpp_parse_uri(uri);
	if (bi)
		bi->type = DPP_BOOTSTRAP_QR_CODE;
	return bi;
}


static void dpp_debug_print_key(const char *title, EVP_PKEY *key)
{
	EC_KEY *eckey;
	BIO *out;
	size_t rlen;
	char *txt;
	int res;
	unsigned char *der = NULL;
	int der_len;

	out = BIO_new(BIO_s_mem());
	if (!out)
		return;

	EVP_PKEY_print_private(out, key, 0, NULL);
	rlen = BIO_ctrl_pending(out);
	txt = os_malloc(rlen + 1);
	if (txt) {
		res = BIO_read(out, txt, rlen);
		if (res > 0) {
			txt[res] = '\0';
			wpa_printf(MSG_DEBUG, "%s: %s", title, txt);
		}
		os_free(txt);
	}
	BIO_free(out);

	eckey = EVP_PKEY_get1_EC_KEY(key);
	if (!eckey)
		return;

	der_len = i2d_ECPrivateKey(eckey, &der);
	if (der_len > 0)
		wpa_hexdump_key(MSG_DEBUG, "DPP: ECPrivateKey", der, der_len);
	OPENSSL_free(der);
	if (der_len <= 0) {
		der = NULL;
		der_len = i2d_EC_PUBKEY(eckey, &der);
		if (der_len > 0)
			wpa_hexdump(MSG_DEBUG, "DPP: EC_PUBKEY", der, der_len);
		OPENSSL_free(der);
	}

	EC_KEY_free(eckey);
}


static EVP_PKEY * dpp_gen_keypair(const struct dpp_curve_params *curve)
{
#ifdef OPENSSL_IS_BORINGSSL
	EVP_PKEY_CTX *kctx = NULL;
	const EC_GROUP *group;
	EC_KEY *ec_params;
#else
	EVP_PKEY_CTX *pctx, *kctx = NULL;
#endif
	EVP_PKEY *params = NULL, *key = NULL;
	int nid;

	wpa_printf(MSG_DEBUG, "DPP: Generating a keypair");

	nid = OBJ_txt2nid(curve->name);
	if (nid == NID_undef) {
		wpa_printf(MSG_INFO, "DPP: Unsupported curve %s", curve->name);
		return NULL;
	}
#ifdef OPENSSL_IS_BORINGSSL
	group = EC_GROUP_new_by_curve_name(nid);
	ec_params = EC_KEY_new();
	if (!ec_params || EC_KEY_set_group(ec_params, group) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to generate EC_KEY parameters");
		goto fail;
	}
	EC_KEY_set_asn1_flag(ec_params, OPENSSL_EC_NAMED_CURVE);
	params = EVP_PKEY_new();
	if (!params || EVP_PKEY_set1_EC_KEY(params, ec_params) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to generate EVP_PKEY parameters");
		goto fail;
	}
#else
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx ||
	    EVP_PKEY_paramgen_init(pctx) != 1 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) != 1 ||
	    EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE) != 1 ||
	    EVP_PKEY_paramgen(pctx, &params) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to generate EVP_PKEY parameters");
		EVP_PKEY_CTX_free(pctx);
		goto fail;
	}
	EVP_PKEY_CTX_free(pctx);
#endif

	kctx = EVP_PKEY_CTX_new(params, NULL);
	if (!kctx ||
	    EVP_PKEY_keygen_init(kctx) != 1 ||
	    EVP_PKEY_keygen(kctx, &key) != 1) {
		wpa_printf(MSG_ERROR, "DPP: Failed to generate EC key");
		goto fail;
	}

	if (wpa_debug_show_keys)
		dpp_debug_print_key("Own generated key", key);

	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(kctx);
	return key;
fail:
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);
	return NULL;
}


static const struct dpp_curve_params *
dpp_get_curve_name(const char *name)
{
	int i;

	for (i = 0; dpp_curves[i].name; i++) {
		if (os_strcmp(name, dpp_curves[i].name) == 0 ||
		    (dpp_curves[i].jwk_crv &&
		     os_strcmp(name, dpp_curves[i].jwk_crv) == 0))
			return &dpp_curves[i];
	}
	return NULL;
}


static const struct dpp_curve_params *
dpp_get_curve_jwk_crv(const char *name)
{
	int i;

	for (i = 0; dpp_curves[i].name; i++) {
		if (dpp_curves[i].jwk_crv &&
		    os_strcmp(name, dpp_curves[i].jwk_crv) == 0)
			return &dpp_curves[i];
	}
	return NULL;
}


static EVP_PKEY * dpp_set_keypair(const struct dpp_curve_params **curve,
				  const u8 *privkey, size_t privkey_len)
{
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	const EC_GROUP *group;
	int nid;

	pkey = EVP_PKEY_new();
	if (!pkey)
		return NULL;
	eckey = d2i_ECPrivateKey(NULL, &privkey, privkey_len);
	if (!eckey) {
		wpa_printf(MSG_INFO,
			   "DPP: OpenSSL: d2i_ECPrivateKey() failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		EVP_PKEY_free(pkey);
		return NULL;
	}
	group = EC_KEY_get0_group(eckey);
	if (!group) {
		EC_KEY_free(eckey);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	nid = EC_GROUP_get_curve_name(group);
	*curve = dpp_get_curve_nid(nid);
	if (!*curve) {
		wpa_printf(MSG_INFO,
			   "DPP: Unsupported curve (nid=%d) in pre-assigned key",
			   nid);
		EC_KEY_free(eckey);
		EVP_PKEY_free(pkey);
		return NULL;
	}

	if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
		EC_KEY_free(eckey);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return pkey;
}


char * dpp_keygen(struct dpp_bootstrap_info *bi, const char *curve,
		  const u8 *privkey, size_t privkey_len)
{
	unsigned char *base64 = NULL;
	char *pos, *end;
	size_t len;
	unsigned char *der = NULL;
	int der_len;
	EC_KEY *eckey;

	if (!curve) {
		bi->curve = &dpp_curves[0];
	} else {
		bi->curve = dpp_get_curve_name(curve);
		if (!bi->curve) {
			wpa_printf(MSG_INFO, "DPP: Unsupported curve: %s",
				   curve);
			return NULL;
		}
	}
	if (privkey)
		bi->pubkey = dpp_set_keypair(&bi->curve, privkey, privkey_len);
	else
		bi->pubkey = dpp_gen_keypair(bi->curve);
	if (!bi->pubkey)
		goto fail;
	bi->own = 1;

	/* Need to get the compressed form of the public key through EC_KEY, so
	 * cannot use the simpler i2d_PUBKEY() here. */
	eckey = EVP_PKEY_get1_EC_KEY(bi->pubkey);
	if (!eckey)
		goto fail;
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);
	der_len = i2d_EC_PUBKEY(eckey, &der);
	EC_KEY_free(eckey);
	if (der_len <= 0) {
		wpa_printf(MSG_ERROR,
			   "DDP: Failed to build DER encoded public key");
		goto fail;
	}

	len = der_len;
	if (sha256_vector(1, (const u8 **) &der, &len, bi->pubkey_hash) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to hash public key");
		goto fail;
	}

	base64 = base64_encode(der, der_len, &len);
	OPENSSL_free(der);
	if (!base64)
		goto fail;
	pos = (char *) base64;
	end = pos + len;
	for (;;) {
		pos = os_strchr(pos, '\n');
		if (!pos)
			break;
		os_memmove(pos, pos + 1, end - pos);
	}
	return (char *) base64;
fail:
	os_free(base64);
	OPENSSL_free(der);
	return NULL;
}


static int dpp_derive_k1(const u8 *Mx, size_t Mx_len, u8 *k1,
			 unsigned int hash_len)
{
	u8 salt[DPP_MAX_HASH_LEN], prk[DPP_MAX_HASH_LEN];
	const char *info = "first intermediate key";
	int res = -1;

	/* k1 = HKDF(<>, "first intermediate key", M.x) */

	/* HKDF-Extract(<>, M.x) */
	os_memset(salt, 0, hash_len);
	if (hash_len == 32) {
		if (hmac_sha256(salt, SHA256_MAC_LEN, Mx, Mx_len, prk) < 0)
			return -1;
	} else if (hash_len == 48) {
		if (hmac_sha384(salt, SHA384_MAC_LEN, Mx, Mx_len, prk) < 0)
			return -1;
	} else if (hash_len == 64) {
		if (hmac_sha512(salt, SHA512_MAC_LEN, Mx, Mx_len, prk) < 0)
			return -1;
	} else {
		return -1;
	}
	wpa_hexdump_key(MSG_DEBUG, "DPP: PRK = HKDF-Extract(<>, IKM=M.x)",
			prk, hash_len);

	/* HKDF-Expand(PRK, info, L) */
	if (hash_len == 32)
		res = hmac_sha256_kdf(prk, SHA256_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      k1, SHA256_MAC_LEN);
	else if (hash_len == 48)
		res = hmac_sha384_kdf(prk, SHA384_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      k1, SHA384_MAC_LEN);
	else if (hash_len == 64)
		res = hmac_sha512_kdf(prk, SHA512_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      k1, SHA512_MAC_LEN);
	os_memset(prk, 0, hash_len);
	if (res < 0)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "DPP: k1 = HKDF-Expand(PRK, info, L)",
			k1, hash_len);
	return 0;
}


static int dpp_derive_k2(const u8 *Nx, size_t Nx_len, u8 *k2,
			 unsigned int hash_len)
{
	u8 salt[DPP_MAX_HASH_LEN], prk[DPP_MAX_HASH_LEN];
	const char *info = "second intermediate key";
	int res;

	/* k2 = HKDF(<>, "second intermediate key", N.x) */

	/* HKDF-Extract(<>, N.x) */
	os_memset(salt, 0, hash_len);
	if (hash_len == 32)
		res = hmac_sha256(salt, SHA256_MAC_LEN, Nx, Nx_len, prk);
	else if (hash_len == 48)
		res = hmac_sha384(salt, SHA384_MAC_LEN, Nx, Nx_len, prk);
	else if (hash_len == 64)
		res = hmac_sha512(salt, SHA512_MAC_LEN, Nx, Nx_len, prk);
	else
		res = -1;
	if (res < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "DPP: PRK = HKDF-Extract(<>, IKM=N.x)",
			prk, hash_len);

	/* HKDF-Expand(PRK, info, L) */
	if (hash_len == 32)
		res = hmac_sha256_kdf(prk, SHA256_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      k2, SHA256_MAC_LEN);
	else if (hash_len == 48)
		res = hmac_sha384_kdf(prk, SHA384_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      k2, SHA384_MAC_LEN);
	else if (hash_len == 64)
		res = hmac_sha512_kdf(prk, SHA512_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      k2, SHA512_MAC_LEN);
	os_memset(prk, 0, hash_len);
	if (res < 0)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "DPP: k2 = HKDF-Expand(PRK, info, L)",
			k2, hash_len);
	return 0;
}


static int dpp_derive_ke(struct dpp_authentication *auth, u8 *ke,
			 unsigned int hash_len)
{
	size_t nonce_len;
	u8 nonces[2 * DPP_MAX_NONCE_LEN];
	const char *info_ke = "DPP Key";
	u8 prk[DPP_MAX_HASH_LEN];
	int res;
	const u8 *addr[3];
	size_t len[3];
	size_t num_elem = 0;

	/* ke = HKDF(I-nonce | R-nonce, "DPP Key", M.x | N.x [| L.x]) */

	/* HKDF-Extract(I-nonce | R-nonce, M.x | N.x [| L.x]) */
	nonce_len = auth->curve->nonce_len;
	os_memcpy(nonces, auth->i_nonce, nonce_len);
	os_memcpy(&nonces[nonce_len], auth->r_nonce, nonce_len);
	addr[num_elem] = auth->Mx;
	len[num_elem] = auth->secret_len;
	num_elem++;
	addr[num_elem] = auth->Nx;
	len[num_elem] = auth->secret_len;
	num_elem++;
	if (auth->peer_bi && auth->own_bi) {
		addr[num_elem] = auth->Lx;
		len[num_elem] = auth->secret_len;
		num_elem++;
	}
	if (hash_len == 32)
		res = hmac_sha256_vector(nonces, 2 * nonce_len,
					 num_elem, addr, len, prk);
	else if (hash_len == 48)
		res = hmac_sha384_vector(nonces, 2 * nonce_len,
					 num_elem, addr, len, prk);
	else if (hash_len == 64)
		res = hmac_sha512_vector(nonces, 2 * nonce_len,
					 num_elem, addr, len, prk);
	else
		res = -1;
	if (res < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "DPP: PRK = HKDF-Extract(<>, IKM)",
			prk, hash_len);

	/* HKDF-Expand(PRK, info, L) */
	if (hash_len == 32)
		res = hmac_sha256_kdf(prk, SHA256_MAC_LEN, NULL,
				      (const u8 *) info_ke, os_strlen(info_ke),
				      ke, SHA256_MAC_LEN);
	else if (hash_len == 48)
		res = hmac_sha384_kdf(prk, SHA384_MAC_LEN, NULL,
				      (const u8 *) info_ke, os_strlen(info_ke),
				      ke, SHA384_MAC_LEN);
	else if (hash_len == 64)
		res = hmac_sha512_kdf(prk, SHA512_MAC_LEN, NULL,
				      (const u8 *) info_ke, os_strlen(info_ke),
				      ke, SHA512_MAC_LEN);
	os_memset(prk, 0, hash_len);
	if (res < 0)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "DPP: ke = HKDF-Expand(PRK, info, L)",
			ke, hash_len);
	return 0;
}


struct dpp_authentication * dpp_auth_init(void *msg_ctx,
					  struct dpp_bootstrap_info *peer_bi,
					  struct dpp_bootstrap_info *own_bi,
					  int configurator)
{
	struct dpp_authentication *auth;
	size_t nonce_len;
	EVP_PKEY_CTX *ctx = NULL;
	size_t secret_len;
	struct wpabuf *msg, *pi = NULL;
	u8 clear[4 + DPP_MAX_NONCE_LEN + 4 + 1];
	u8 wrapped_data[4 + DPP_MAX_NONCE_LEN + 4 + 1 + AES_BLOCK_SIZE];
	u8 *pos;
	const u8 *addr[1];
	size_t len[1], siv_len;

	auth = os_zalloc(sizeof(*auth));
	if (!auth)
		return NULL;
	auth->msg_ctx = msg_ctx;
	auth->initiator = 1;
	auth->configurator = configurator;
	auth->peer_bi = peer_bi;
	auth->own_bi = own_bi;
	auth->curve = peer_bi->curve;

	nonce_len = auth->curve->nonce_len;
	if (random_get_bytes(auth->i_nonce, nonce_len)) {
		wpa_printf(MSG_ERROR, "DPP: Failed to generate I-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: I-nonce", auth->i_nonce, nonce_len);

	auth->own_protocol_key = dpp_gen_keypair(auth->curve);
	if (!auth->own_protocol_key)
		goto fail;

	pi = dpp_get_pubkey_point(auth->own_protocol_key, 0);
	if (!pi)
		goto fail;

	/* ECDH: M = pI * BR */
	ctx = EVP_PKEY_CTX_new(auth->own_protocol_key, NULL);
	if (!ctx ||
	    EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, auth->peer_bi->pubkey) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &secret_len) != 1 ||
	    secret_len > DPP_MAX_SHARED_SECRET_LEN ||
	    EVP_PKEY_derive(ctx, auth->Mx, &secret_len) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to derive ECDH shared secret: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	auth->secret_len = secret_len;
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	wpa_hexdump_key(MSG_DEBUG, "DPP: ECDH shared secret (M.x)",
			auth->Mx, auth->secret_len);

	if (dpp_derive_k1(auth->Mx, auth->secret_len, auth->k1,
			  auth->curve->hash_len) < 0)
		goto fail;

	/* Build DPP Authentication Request frame attributes */
	msg = wpabuf_alloc(2 * (4 + SHA256_MAC_LEN) + 4 + wpabuf_len(pi) +
			   4 + sizeof(wrapped_data));
	if (!msg)
		goto fail;
	auth->req_attr = msg;

	/* Responder Bootstrapping Key Hash */
	wpabuf_put_le16(msg, DPP_ATTR_R_BOOTSTRAP_KEY_HASH);
	wpabuf_put_le16(msg, SHA256_MAC_LEN);
	wpabuf_put_data(msg, auth->peer_bi->pubkey_hash, SHA256_MAC_LEN);

	/* Initiator Bootstrapping Key Hash */
	wpabuf_put_le16(msg, DPP_ATTR_I_BOOTSTRAP_KEY_HASH);
	wpabuf_put_le16(msg, SHA256_MAC_LEN);
	if (auth->own_bi)
		wpabuf_put_data(msg, auth->own_bi->pubkey_hash, SHA256_MAC_LEN);
	else
		os_memset(wpabuf_put(msg, SHA256_MAC_LEN), 0, SHA256_MAC_LEN);

	/* Initiator Protocol Key */
	wpabuf_put_le16(msg, DPP_ATTR_I_PROTOCOL_KEY);
	wpabuf_put_le16(msg, wpabuf_len(pi));
	wpabuf_put_buf(msg, pi);
	wpabuf_free(pi);
	pi = NULL;

	/* Wrapped data ({I-nonce, I-capabilities}k1) */
	pos = clear;
	/* I-nonce */
	WPA_PUT_LE16(pos, DPP_ATTR_I_NONCE);
	pos += 2;
	WPA_PUT_LE16(pos, nonce_len);
	pos += 2;
	os_memcpy(pos, auth->i_nonce, nonce_len);
	pos += nonce_len;
	/* I-capabilities */
	WPA_PUT_LE16(pos, DPP_ATTR_I_CAPABILITIES);
	pos += 2;
	WPA_PUT_LE16(pos, 1);
	pos += 2;
	auth->i_capab = configurator ? DPP_CAPAB_CONFIGURATOR :
		DPP_CAPAB_ENROLLEE;
	*pos++ = auth->i_capab;

	addr[0] = wpabuf_head(msg);
	len[0] = wpabuf_len(msg);
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);
	siv_len = pos - clear;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext", clear, siv_len);
	if (aes_siv_encrypt(auth->k1, auth->curve->hash_len, clear, siv_len,
			    1, addr, len, wrapped_data) < 0)
		goto fail;
	siv_len += AES_BLOCK_SIZE;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, siv_len);

	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, siv_len);
	wpabuf_put_data(msg, wrapped_data, siv_len);

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Authentication Request frame attributes", msg);

	return auth;
fail:
	wpabuf_free(pi);
	EVP_PKEY_CTX_free(ctx);
	dpp_auth_deinit(auth);
	return NULL;
}


struct wpabuf * dpp_build_conf_req(struct dpp_authentication *auth,
				   const char *json)
{
	size_t nonce_len;
	size_t json_len, clear_len;
	struct wpabuf *clear = NULL, *msg = NULL;
	u8 *wrapped;

	wpa_printf(MSG_DEBUG, "DPP: Build configuration request");

	nonce_len = auth->curve->nonce_len;
	if (random_get_bytes(auth->e_nonce, nonce_len)) {
		wpa_printf(MSG_ERROR, "DPP: Failed to generate E-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: E-nonce", auth->e_nonce, nonce_len);
	json_len = os_strlen(json);
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: configAttr JSON", json, json_len);

	/* { E-nonce, configAttrib }ke */
	clear_len = 4 + nonce_len + 4 + json_len;
	clear = wpabuf_alloc(clear_len);
	msg = wpabuf_alloc(4 + clear_len + AES_BLOCK_SIZE);
	if (!clear || !msg)
		goto fail;

	/* E-nonce */
	wpabuf_put_le16(clear, DPP_ATTR_ENROLLEE_NONCE);
	wpabuf_put_le16(clear, nonce_len);
	wpabuf_put_data(clear, auth->e_nonce, nonce_len);

	/* configAttrib */
	wpabuf_put_le16(clear, DPP_ATTR_CONFIG_ATTR_OBJ);
	wpabuf_put_le16(clear, json_len);
	wpabuf_put_data(clear, json, json_len);

	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);
	wrapped = wpabuf_put(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);

	/* No AES-SIV AD */
	wpa_hexdump_buf(MSG_DEBUG, "DPP: AES-SIV cleartext", clear);
	if (aes_siv_encrypt(auth->ke, auth->curve->hash_len,
			    wpabuf_head(clear), wpabuf_len(clear),
			    0, NULL, NULL, wrapped) < 0)
		goto fail;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped, wpabuf_len(clear) + AES_BLOCK_SIZE);

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Configuration Request frame attributes", msg);
	wpabuf_free(clear);
	return msg;

fail:
	wpabuf_free(clear);
	wpabuf_free(msg);
	return NULL;
}


static void dpp_auth_success(struct dpp_authentication *auth)
{
	wpa_printf(MSG_DEBUG,
		   "DPP: Authentication success - clear temporary keys");
	os_memset(auth->Mx, 0, sizeof(auth->Mx));
	os_memset(auth->Nx, 0, sizeof(auth->Nx));
	os_memset(auth->Lx, 0, sizeof(auth->Lx));
	os_memset(auth->k1, 0, sizeof(auth->k1));
	os_memset(auth->k2, 0, sizeof(auth->k2));

	auth->auth_success = 1;
}


static int dpp_gen_r_auth(struct dpp_authentication *auth, u8 *r_auth)
{
	struct wpabuf *pix, *prx, *bix, *brx;
	const u8 *addr[7];
	size_t len[7];
	size_t i, num_elem = 0;
	size_t nonce_len;
	u8 zero = 0;
	int res = -1;

	/* R-auth = H(I-nonce | R-nonce | PI.x | PR.x | [BI.x |] BR.x | 0) */
	nonce_len = auth->curve->nonce_len;

	if (auth->initiator) {
		pix = dpp_get_pubkey_point(auth->own_protocol_key, 0);
		prx = dpp_get_pubkey_point(auth->peer_protocol_key, 0);
		if (auth->own_bi)
			bix = dpp_get_pubkey_point(auth->own_bi->pubkey, 0);
		else
			bix = NULL;
		brx = dpp_get_pubkey_point(auth->peer_bi->pubkey, 0);
	} else {
		pix = dpp_get_pubkey_point(auth->peer_protocol_key, 0);
		prx = dpp_get_pubkey_point(auth->own_protocol_key, 0);
		if (auth->peer_bi)
			bix = dpp_get_pubkey_point(auth->peer_bi->pubkey, 0);
		else
			bix = NULL;
		brx = dpp_get_pubkey_point(auth->own_bi->pubkey, 0);
	}
	if (!pix || !prx || !brx)
		goto fail;

	addr[num_elem] = auth->i_nonce;
	len[num_elem] = nonce_len;
	num_elem++;

	addr[num_elem] = auth->r_nonce;
	len[num_elem] = nonce_len;
	num_elem++;

	addr[num_elem] = wpabuf_head(pix);
	len[num_elem] = wpabuf_len(pix) / 2;
	num_elem++;

	addr[num_elem] = wpabuf_head(prx);
	len[num_elem] = wpabuf_len(prx) / 2;
	num_elem++;

	if (bix) {
		addr[num_elem] = wpabuf_head(bix);
		len[num_elem] = wpabuf_len(bix) / 2;
		num_elem++;
	}

	addr[num_elem] = wpabuf_head(brx);
	len[num_elem] = wpabuf_len(brx) / 2;
	num_elem++;

	addr[num_elem] = &zero;
	len[num_elem] = 1;
	num_elem++;

	wpa_printf(MSG_DEBUG, "DPP: R-auth hash components");
	for (i = 0; i < num_elem; i++)
		wpa_hexdump(MSG_DEBUG, "DPP: hash component", addr[i], len[i]);
	if (auth->curve->hash_len == 32)
		res = sha256_vector(num_elem, addr, len, r_auth);
	else if (auth->curve->hash_len == 48)
		res = sha384_vector(num_elem, addr, len, r_auth);
	else if (auth->curve->hash_len == 64)
		res = sha512_vector(num_elem, addr, len, r_auth);
	else
		res = -1;
	if (res == 0)
		wpa_hexdump(MSG_DEBUG, "DPP: R-auth", r_auth,
			    auth->curve->hash_len);
fail:
	wpabuf_free(pix);
	wpabuf_free(prx);
	wpabuf_free(bix);
	wpabuf_free(brx);
	return res;
}


static int dpp_gen_i_auth(struct dpp_authentication *auth, u8 *i_auth)
{
	struct wpabuf *pix = NULL, *prx = NULL, *bix = NULL, *brx = NULL;
	const u8 *addr[7];
	size_t len[7];
	size_t i, num_elem = 0;
	size_t nonce_len;
	u8 one = 1;
	int res = -1;

	/* I-auth = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [BI.x |] 1) */
	nonce_len = auth->curve->nonce_len;

	if (auth->initiator) {
		pix = dpp_get_pubkey_point(auth->own_protocol_key, 0);
		prx = dpp_get_pubkey_point(auth->peer_protocol_key, 0);
		if (auth->own_bi)
			bix = dpp_get_pubkey_point(auth->own_bi->pubkey, 0);
		else
			bix = NULL;
		if (!auth->peer_bi)
			goto fail;
		brx = dpp_get_pubkey_point(auth->peer_bi->pubkey, 0);
	} else {
		pix = dpp_get_pubkey_point(auth->peer_protocol_key, 0);
		prx = dpp_get_pubkey_point(auth->own_protocol_key, 0);
		if (auth->peer_bi)
			bix = dpp_get_pubkey_point(auth->peer_bi->pubkey, 0);
		else
			bix = NULL;
		if (!auth->own_bi)
			goto fail;
		brx = dpp_get_pubkey_point(auth->own_bi->pubkey, 0);
	}
	if (!pix || !prx || !brx)
		goto fail;

	addr[num_elem] = auth->r_nonce;
	len[num_elem] = nonce_len;
	num_elem++;

	addr[num_elem] = auth->i_nonce;
	len[num_elem] = nonce_len;
	num_elem++;

	addr[num_elem] = wpabuf_head(prx);
	len[num_elem] = wpabuf_len(prx) / 2;
	num_elem++;

	addr[num_elem] = wpabuf_head(pix);
	len[num_elem] = wpabuf_len(pix) / 2;
	num_elem++;

	addr[num_elem] = wpabuf_head(brx);
	len[num_elem] = wpabuf_len(brx) / 2;
	num_elem++;

	if (bix) {
		addr[num_elem] = wpabuf_head(bix);
		len[num_elem] = wpabuf_len(bix) / 2;
		num_elem++;
	}

	addr[num_elem] = &one;
	len[num_elem] = 1;
	num_elem++;

	wpa_printf(MSG_DEBUG, "DPP: I-auth hash components");
	for (i = 0; i < num_elem; i++)
		wpa_hexdump(MSG_DEBUG, "DPP: hash component", addr[i], len[i]);
	if (auth->curve->hash_len == 32)
		res = sha256_vector(num_elem, addr, len, i_auth);
	else if (auth->curve->hash_len == 48)
		res = sha384_vector(num_elem, addr, len, i_auth);
	else if (auth->curve->hash_len == 64)
		res = sha512_vector(num_elem, addr, len, i_auth);
	else
		res = -1;
	if (res == 0)
		wpa_hexdump(MSG_DEBUG, "DPP: I-auth", i_auth,
			    auth->curve->hash_len);
fail:
	wpabuf_free(pix);
	wpabuf_free(prx);
	wpabuf_free(bix);
	wpabuf_free(brx);
	return res;
}


static int dpp_auth_derive_l_responder(struct dpp_authentication *auth)
{
	const EC_GROUP *group;
	EC_POINT *l = NULL;
	EC_KEY *BI = NULL, *bR = NULL, *pR = NULL;
	const EC_POINT *BI_point;
	BN_CTX *bnctx;
	BIGNUM *lx, *sum, *q;
	const BIGNUM *bR_bn, *pR_bn;
	int ret = -1;
	int num_bytes, offset;

	/* L = ((bR + pR) modulo q) * BI */

	bnctx = BN_CTX_new();
	sum = BN_new();
	q = BN_new();
	lx = BN_new();
	if (!bnctx || !sum || !q || !lx)
		goto fail;
	BI = EVP_PKEY_get1_EC_KEY(auth->peer_bi->pubkey);
	if (!BI)
		goto fail;
	BI_point = EC_KEY_get0_public_key(BI);
	group = EC_KEY_get0_group(BI);
	if (!group)
		goto fail;

	bR = EVP_PKEY_get1_EC_KEY(auth->own_bi->pubkey);
	pR = EVP_PKEY_get1_EC_KEY(auth->own_protocol_key);
	if (!bR || !pR)
		goto fail;
	bR_bn = EC_KEY_get0_private_key(bR);
	pR_bn = EC_KEY_get0_private_key(pR);
	if (!bR_bn || !pR_bn)
		goto fail;
	if (EC_GROUP_get_order(group, q, bnctx) != 1 ||
	    BN_mod_add(sum, bR_bn, pR_bn, q, bnctx) != 1)
		goto fail;
	l = EC_POINT_new(group);
	if (!l ||
	    EC_POINT_mul(group, l, NULL, BI_point, sum, bnctx) != 1 ||
	    EC_POINT_get_affine_coordinates_GFp(group, l, lx, NULL,
						bnctx) != 1) {
		wpa_printf(MSG_ERROR,
			   "OpenSSL: failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	num_bytes = BN_num_bytes(lx);
	if ((size_t) num_bytes > auth->secret_len)
		goto fail;
	if (auth->secret_len > (size_t) num_bytes)
		offset = auth->secret_len - num_bytes;
	else
		offset = 0;

	os_memset(auth->Lx, 0, offset);
	BN_bn2bin(lx, auth->Lx + offset);
	wpa_hexdump_key(MSG_DEBUG, "DPP: L.x", auth->Lx, auth->secret_len);
	ret = 0;
fail:
	EC_POINT_clear_free(l);
	EC_KEY_free(BI);
	EC_KEY_free(bR);
	EC_KEY_free(pR);
	BN_clear_free(lx);
	BN_clear_free(sum);
	BN_free(q);
	BN_CTX_free(bnctx);
	return ret;
}


static int dpp_auth_derive_l_initiator(struct dpp_authentication *auth)
{
	const EC_GROUP *group;
	EC_POINT *l = NULL, *sum = NULL;
	EC_KEY *bI = NULL, *BR = NULL, *PR = NULL;
	const EC_POINT *BR_point, *PR_point;
	BN_CTX *bnctx;
	BIGNUM *lx;
	const BIGNUM *bI_bn;
	int ret = -1;
	int num_bytes, offset;

	/* L = bI * (BR + PR) */

	bnctx = BN_CTX_new();
	lx = BN_new();
	if (!bnctx || !lx)
		goto fail;
	BR = EVP_PKEY_get1_EC_KEY(auth->peer_bi->pubkey);
	PR = EVP_PKEY_get1_EC_KEY(auth->peer_protocol_key);
	if (!BR || !PR)
		goto fail;
	BR_point = EC_KEY_get0_public_key(BR);
	PR_point = EC_KEY_get0_public_key(PR);

	bI = EVP_PKEY_get1_EC_KEY(auth->own_bi->pubkey);
	if (!bI)
		goto fail;
	group = EC_KEY_get0_group(bI);
	bI_bn = EC_KEY_get0_private_key(bI);
	if (!group || !bI_bn)
		goto fail;
	sum = EC_POINT_new(group);
	l = EC_POINT_new(group);
	if (!sum || !l ||
	    EC_POINT_add(group, sum, BR_point, PR_point, bnctx) != 1 ||
	    EC_POINT_mul(group, l, NULL, sum, bI_bn, bnctx) != 1 ||
	    EC_POINT_get_affine_coordinates_GFp(group, l, lx, NULL,
						bnctx) != 1) {
		wpa_printf(MSG_ERROR,
			   "OpenSSL: failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	num_bytes = BN_num_bytes(lx);
	if ((size_t) num_bytes > auth->secret_len)
		goto fail;
	if (auth->secret_len > (size_t) num_bytes)
		offset = auth->secret_len - num_bytes;
	else
		offset = 0;

	os_memset(auth->Lx, 0, offset);
	BN_bn2bin(lx, auth->Lx + offset);
	wpa_hexdump_key(MSG_DEBUG, "DPP: L.x", auth->Lx, auth->secret_len);
	ret = 0;
fail:
	EC_POINT_clear_free(l);
	EC_KEY_free(bI);
	EC_KEY_free(BR);
	EC_KEY_free(PR);
	BN_clear_free(lx);
	BN_CTX_free(bnctx);
	return ret;
}


static int dpp_auth_build_resp(struct dpp_authentication *auth)
{
	size_t nonce_len;
	EVP_PKEY_CTX *ctx = NULL;
	size_t secret_len;
	struct wpabuf *msg, *pr = NULL;
	u8 r_auth[4 + DPP_MAX_HASH_LEN];
	u8 wrapped_r_auth[4 + DPP_MAX_HASH_LEN + AES_BLOCK_SIZE];
#define DPP_AUTH_RESP_CLEAR_LEN 2 * (4 + DPP_MAX_NONCE_LEN) + 4 + 1 + \
		4 + sizeof(wrapped_r_auth)
	size_t wrapped_r_auth_len;
	u8 clear[DPP_AUTH_RESP_CLEAR_LEN];
	u8 wrapped_data[DPP_AUTH_RESP_CLEAR_LEN + AES_BLOCK_SIZE];
	u8 *pos;
	const u8 *addr[1];
	size_t len[1], siv_len;

	wpa_printf(MSG_DEBUG, "DPP: Build Authentication Response");

	nonce_len = auth->curve->nonce_len;
	if (random_get_bytes(auth->r_nonce, nonce_len)) {
		wpa_printf(MSG_ERROR, "DPP: Failed to generate R-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: R-nonce", auth->r_nonce, nonce_len);

	auth->own_protocol_key = dpp_gen_keypair(auth->curve);
	if (!auth->own_protocol_key)
		goto fail;

	pr = dpp_get_pubkey_point(auth->own_protocol_key, 0);
	if (!pr)
		goto fail;

	/* ECDH: N = pR * PI */
	ctx = EVP_PKEY_CTX_new(auth->own_protocol_key, NULL);
	if (!ctx ||
	    EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, auth->peer_protocol_key) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &secret_len) != 1 ||
	    secret_len > DPP_MAX_SHARED_SECRET_LEN ||
	    EVP_PKEY_derive(ctx, auth->Nx, &secret_len) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to derive ECDH shared secret: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	wpa_hexdump_key(MSG_DEBUG, "DPP: ECDH shared secret (N.x)",
			auth->Nx, auth->secret_len);

	if (dpp_derive_k2(auth->Nx, auth->secret_len, auth->k2,
			  auth->curve->hash_len) < 0)
		goto fail;

	if (auth->own_bi && auth->peer_bi) {
		/* Mutual authentication */
		if (dpp_auth_derive_l_responder(auth) < 0)
			goto fail;
	}

	if (dpp_derive_ke(auth, auth->ke, auth->curve->hash_len) < 0)
		goto fail;

	/* R-auth = H(I-nonce | R-nonce | PI.x | PR.x | [BI.x |] BR.x | 0) */
	WPA_PUT_LE16(r_auth, DPP_ATTR_R_AUTH_TAG);
	WPA_PUT_LE16(&r_auth[2], auth->curve->hash_len);
	if (dpp_gen_r_auth(auth, r_auth + 4) < 0 ||
	    aes_siv_encrypt(auth->ke, auth->curve->hash_len,
			    r_auth, 4 + auth->curve->hash_len,
			    0, NULL, NULL, wrapped_r_auth) < 0)
		goto fail;
	wrapped_r_auth_len = 4 + auth->curve->hash_len + AES_BLOCK_SIZE;
	wpa_hexdump(MSG_DEBUG, "DPP: {R-auth}ke",
		    wrapped_r_auth, wrapped_r_auth_len);

	/* Build DPP Authentication Response frame attributes */
	msg = wpabuf_alloc(4 + 1 + 2 * (4 + SHA256_MAC_LEN) +
			   4 + wpabuf_len(pr) + 4 + sizeof(wrapped_data));
	if (!msg)
		goto fail;
	wpabuf_free(auth->resp_attr);
	auth->resp_attr = msg;

	/* DPP Status */
	wpabuf_put_le16(msg, DPP_ATTR_STATUS);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, DPP_STATUS_OK);

	/* Responder Bootstrapping Key Hash */
	wpabuf_put_le16(msg, DPP_ATTR_R_BOOTSTRAP_KEY_HASH);
	wpabuf_put_le16(msg, SHA256_MAC_LEN);
	wpabuf_put_data(msg, auth->own_bi->pubkey_hash, SHA256_MAC_LEN);

	if (auth->peer_bi) {
		/* Mutual authentication */
		/* Initiator Bootstrapping Key Hash */
		wpabuf_put_le16(msg, DPP_ATTR_I_BOOTSTRAP_KEY_HASH);
		wpabuf_put_le16(msg, SHA256_MAC_LEN);
		wpabuf_put_data(msg, auth->peer_bi->pubkey_hash,
				SHA256_MAC_LEN);
	}

	/* Responder Protocol Key */
	wpabuf_put_le16(msg, DPP_ATTR_R_PROTOCOL_KEY);
	wpabuf_put_le16(msg, wpabuf_len(pr));
	wpabuf_put_buf(msg, pr);
	wpabuf_free(pr);
	pr = NULL;

	/* Wrapped data ({R-nonce, I-nonce, R-capabilities, {R-auth}ke}k2) */
	pos = clear;
	/* R-nonce */
	WPA_PUT_LE16(pos, DPP_ATTR_R_NONCE);
	pos += 2;
	WPA_PUT_LE16(pos, nonce_len);
	pos += 2;
	os_memcpy(pos, auth->r_nonce, nonce_len);
	pos += nonce_len;
	/* I-nonce */
	WPA_PUT_LE16(pos, DPP_ATTR_I_NONCE);
	pos += 2;
	WPA_PUT_LE16(pos, nonce_len);
	pos += 2;
	os_memcpy(pos, auth->i_nonce, nonce_len);
	pos += nonce_len;
	/* R-capabilities */
	WPA_PUT_LE16(pos, DPP_ATTR_R_CAPABILITIES);
	pos += 2;
	WPA_PUT_LE16(pos, 1);
	pos += 2;
	auth->r_capab = auth->configurator ? DPP_CAPAB_CONFIGURATOR :
		DPP_CAPAB_ENROLLEE;
	*pos++ = auth->r_capab;
	/* {R-auth}ke */
	WPA_PUT_LE16(pos, DPP_ATTR_WRAPPED_DATA);
	pos += 2;
	WPA_PUT_LE16(pos, wrapped_r_auth_len);
	pos += 2;
	os_memcpy(pos, wrapped_r_auth, wrapped_r_auth_len);
	pos += wrapped_r_auth_len;

	addr[0] = wpabuf_head(msg);
	len[0] = wpabuf_len(msg);
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);
	siv_len = pos - clear;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext", clear, siv_len);
	if (aes_siv_encrypt(auth->k2, auth->curve->hash_len, clear, siv_len,
			    1, addr, len, wrapped_data) < 0)
		goto fail;
	siv_len += AES_BLOCK_SIZE;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, siv_len);

	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, siv_len);
	wpabuf_put_data(msg, wrapped_data, siv_len);

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Authentication Response frame attributes", msg);

	return 0;

fail:
	wpabuf_free(pr);
	return -1;
}


static int dpp_auth_build_resp_status(struct dpp_authentication *auth,
				      enum dpp_status_error status)
{
	size_t nonce_len;
	struct wpabuf *msg;
#define DPP_AUTH_RESP_CLEAR_LEN2 4 + DPP_MAX_NONCE_LEN + 4 + 1
	u8 clear[DPP_AUTH_RESP_CLEAR_LEN2];
	u8 wrapped_data[DPP_AUTH_RESP_CLEAR_LEN2 + AES_BLOCK_SIZE];
	u8 *pos;
	const u8 *addr[1];
	size_t len[1], siv_len;

	wpa_printf(MSG_DEBUG, "DPP: Build Authentication Response");

	/* Build DPP Authentication Response frame attributes */
	msg = wpabuf_alloc(4 + 1 + 2 * (4 + SHA256_MAC_LEN) +
			   4 + sizeof(wrapped_data));
	if (!msg)
		goto fail;
	wpabuf_free(auth->resp_attr);
	auth->resp_attr = msg;

	/* DPP Status */
	wpabuf_put_le16(msg, DPP_ATTR_STATUS);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, status);

	/* Responder Bootstrapping Key Hash */
	wpabuf_put_le16(msg, DPP_ATTR_R_BOOTSTRAP_KEY_HASH);
	wpabuf_put_le16(msg, SHA256_MAC_LEN);
	wpabuf_put_data(msg, auth->own_bi->pubkey_hash, SHA256_MAC_LEN);

	if (auth->peer_bi) {
		/* Mutual authentication */
		/* Initiator Bootstrapping Key Hash */
		wpabuf_put_le16(msg, DPP_ATTR_I_BOOTSTRAP_KEY_HASH);
		wpabuf_put_le16(msg, SHA256_MAC_LEN);
		wpabuf_put_data(msg, auth->peer_bi->pubkey_hash,
				SHA256_MAC_LEN);
	}

	/* Wrapped data ({I-nonce, R-capabilities}k1) */
	pos = clear;
	/* I-nonce */
	nonce_len = auth->curve->nonce_len;
	WPA_PUT_LE16(pos, DPP_ATTR_I_NONCE);
	pos += 2;
	WPA_PUT_LE16(pos, nonce_len);
	pos += 2;
	os_memcpy(pos, auth->i_nonce, nonce_len);
	pos += nonce_len;
	/* R-capabilities */
	WPA_PUT_LE16(pos, DPP_ATTR_R_CAPABILITIES);
	pos += 2;
	WPA_PUT_LE16(pos, 1);
	pos += 2;
	auth->r_capab = auth->configurator ? DPP_CAPAB_CONFIGURATOR :
		DPP_CAPAB_ENROLLEE;
	*pos++ = auth->r_capab;

	addr[0] = wpabuf_head(msg);
	len[0] = wpabuf_len(msg);
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);
	siv_len = pos - clear;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext", clear, siv_len);
	if (aes_siv_encrypt(auth->k1, auth->curve->hash_len, clear, siv_len,
			    1, addr, len, wrapped_data) < 0)
		goto fail;
	siv_len += AES_BLOCK_SIZE;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, siv_len);

	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, siv_len);
	wpabuf_put_data(msg, wrapped_data, siv_len);

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Authentication Response frame attributes", msg);

	return 0;

fail:
	return -1;
}


struct dpp_authentication *
dpp_auth_req_rx(void *msg_ctx, u8 dpp_allowed_roles, int qr_mutual,
		struct dpp_bootstrap_info *peer_bi,
		struct dpp_bootstrap_info *own_bi,
		unsigned int freq, const u8 *attr_start,
		const u8 *wrapped_data,	u16 wrapped_data_len)
{
	EVP_PKEY *pi = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	size_t secret_len;
	const u8 *addr[1];
	size_t len[1];
	u8 *unwrapped = NULL;
	size_t unwrapped_len = 0;
	const u8 *i_proto, *i_nonce, *i_capab, *i_bootstrap;
	u16 i_proto_len, i_nonce_len, i_capab_len, i_bootstrap_len;
	struct dpp_authentication *auth = NULL;
	size_t attr_len;

	if (wrapped_data_len < AES_BLOCK_SIZE)
		return NULL;

	attr_len = wrapped_data - 4 - attr_start;

	auth = os_zalloc(sizeof(*auth));
	if (!auth)
		goto fail;
	auth->msg_ctx = msg_ctx;
	auth->peer_bi = peer_bi;
	auth->own_bi = own_bi;
	auth->curve = own_bi->curve;
	auth->curr_freq = freq;

	i_proto = dpp_get_attr(attr_start, attr_len, DPP_ATTR_I_PROTOCOL_KEY,
			       &i_proto_len);
	if (!i_proto) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing required Initiator Protocol Key attribute");
		goto fail;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Initiator Protocol Key",
		    i_proto, i_proto_len);

	/* M = bR * PI */
	pi = dpp_set_pubkey_point(own_bi->pubkey, i_proto, i_proto_len);
	if (!pi) {
		wpa_printf(MSG_DEBUG, "DPP: Invalid Initiator Protocol Key");
		goto fail;
	}
	dpp_debug_print_key("Peer (Initiator) Protocol Key", pi);

	ctx = EVP_PKEY_CTX_new(own_bi->pubkey, NULL);
	if (!ctx ||
	    EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, pi) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &secret_len) != 1 ||
	    secret_len > DPP_MAX_SHARED_SECRET_LEN ||
	    EVP_PKEY_derive(ctx, auth->Mx, &secret_len) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to derive ECDH shared secret: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	auth->secret_len = secret_len;
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	wpa_hexdump_key(MSG_DEBUG, "DPP: ECDH shared secret (M.x)",
			auth->Mx, auth->secret_len);

	if (dpp_derive_k1(auth->Mx, auth->secret_len, auth->k1,
			  auth->curve->hash_len) < 0)
		goto fail;

	addr[0] = attr_start;
	len[0] = attr_len;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		goto fail;
	if (aes_siv_decrypt(auth->k1, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    1, addr, len, unwrapped) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in unwrapped data");
		goto fail;
	}

	i_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_I_NONCE,
			       &i_nonce_len);
	if (!i_nonce || i_nonce_len != auth->curve->nonce_len) {
		wpa_printf(MSG_DEBUG, "DPP: Missing or invalid I-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: I-nonce", i_nonce, i_nonce_len);
	os_memcpy(auth->i_nonce, i_nonce, i_nonce_len);

	i_capab = dpp_get_attr(unwrapped, unwrapped_len,
			       DPP_ATTR_I_CAPABILITIES,
			       &i_capab_len);
	if (!i_capab || i_capab_len < 1) {
		wpa_printf(MSG_DEBUG, "DPP: Missing or invalid I-capabilities");
		goto fail;
	}
	auth->i_capab = i_capab[0];
	wpa_printf(MSG_DEBUG, "DPP: I-capabilities: 0x%02x", auth->i_capab);

	bin_clear_free(unwrapped, unwrapped_len);
	unwrapped = NULL;

	switch (auth->i_capab & DPP_CAPAB_ROLE_MASK) {
	case DPP_CAPAB_ENROLLEE:
		if (!(dpp_allowed_roles & DPP_CAPAB_CONFIGURATOR)) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Local policy does not allow Configurator role");
			goto not_compatible;
		}
		wpa_printf(MSG_DEBUG, "DPP: Acting as Configurator");
		auth->configurator = 1;
		break;
	case DPP_CAPAB_CONFIGURATOR:
		if (!(dpp_allowed_roles & DPP_CAPAB_ENROLLEE)) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Local policy does not allow Enrollee role");
			goto not_compatible;
		}
		wpa_printf(MSG_DEBUG, "DPP: Acting as Enrollee");
		auth->configurator = 0;
		break;
	default:
		wpa_printf(MSG_DEBUG, "DPP: Unexpected role in I-capabilities");
		goto not_compatible;
	}

	auth->peer_protocol_key = pi;
	pi = NULL;
	if (qr_mutual && !peer_bi && own_bi->type == DPP_BOOTSTRAP_QR_CODE) {
		char hex[SHA256_MAC_LEN * 2 + 1];

		wpa_printf(MSG_DEBUG,
			   "DPP: Mutual authentication required with QR Codes, but peer info is not yet available - request more time");
		if (dpp_auth_build_resp_status(auth,
					       DPP_STATUS_RESPONSE_PENDING) < 0)
			goto fail;
		i_bootstrap = dpp_get_attr(attr_start, attr_len,
					   DPP_ATTR_I_BOOTSTRAP_KEY_HASH,
					   &i_bootstrap_len);
		if (i_bootstrap && i_bootstrap_len == SHA256_MAC_LEN) {
			auth->response_pending = 1;
			os_memcpy(auth->waiting_pubkey_hash,
				  i_bootstrap, i_bootstrap_len);
			wpa_snprintf_hex(hex, sizeof(hex), i_bootstrap,
					 i_bootstrap_len);
		} else {
			hex[0] = '\0';
		}

		wpa_msg(auth->msg_ctx, MSG_INFO, DPP_EVENT_SCAN_PEER_QR_CODE
			"%s", hex);
		return auth;
	}
	if (dpp_auth_build_resp(auth) < 0)
		goto fail;

	return auth;

not_compatible:
	wpa_msg(auth->msg_ctx, MSG_INFO, DPP_EVENT_NOT_COMPATIBLE
		"i-capab=0x%02x", auth->i_capab);
	if (dpp_allowed_roles & DPP_CAPAB_CONFIGURATOR)
		auth->configurator = 1;
	else
		auth->configurator = 0;
	auth->peer_protocol_key = pi;
	pi = NULL;
	if (dpp_auth_build_resp_status(auth, DPP_STATUS_NOT_COMPATIBLE) < 0)
		goto fail;

	auth->remove_on_tx_status = 1;
	return auth;
fail:
	bin_clear_free(unwrapped, unwrapped_len);
	EVP_PKEY_free(pi);
	EVP_PKEY_CTX_free(ctx);
	dpp_auth_deinit(auth);
	return NULL;
}


int dpp_notify_new_qr_code(struct dpp_authentication *auth,
			   struct dpp_bootstrap_info *peer_bi)
{
	if (!auth || !auth->response_pending ||
	    os_memcmp(auth->waiting_pubkey_hash, peer_bi->pubkey_hash,
		      SHA256_MAC_LEN) != 0)
		return 0;

	wpa_printf(MSG_DEBUG,
		   "DPP: New scanned QR Code has matching public key that was needed to continue DPP Authentication exchange with "
		   MACSTR, MAC2STR(auth->peer_mac_addr));
	auth->peer_bi = peer_bi;

	if (dpp_auth_build_resp(auth) < 0)
		return -1;

	return 1;
}


static struct wpabuf * dpp_auth_build_conf(struct dpp_authentication *auth)
{
	struct wpabuf *msg;
	u8 i_auth[4 + DPP_MAX_HASH_LEN];
	size_t i_auth_len;
	const u8 *addr[1];
	size_t len[1];
	u8 *wrapped_i_auth;

	wpa_printf(MSG_DEBUG, "DPP: Build Authentication Confirmation");

	i_auth_len = 4 + auth->curve->hash_len;
	/* Build DPP Authentication Confirmation frame attributes */
	msg = wpabuf_alloc(4 + 1 + 2 * (4 + SHA256_MAC_LEN) +
			   4 + i_auth_len + AES_BLOCK_SIZE);
	if (!msg)
		goto fail;

	/* DPP Status */
	wpabuf_put_le16(msg, DPP_ATTR_STATUS);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, DPP_STATUS_OK);

	/* Responder Bootstrapping Key Hash */
	wpabuf_put_le16(msg, DPP_ATTR_R_BOOTSTRAP_KEY_HASH);
	wpabuf_put_le16(msg, SHA256_MAC_LEN);
	wpabuf_put_data(msg, auth->peer_bi->pubkey_hash, SHA256_MAC_LEN);

	if (auth->own_bi) {
		/* Mutual authentication */
		/* Initiator Bootstrapping Key Hash */
		wpabuf_put_le16(msg, DPP_ATTR_I_BOOTSTRAP_KEY_HASH);
		wpabuf_put_le16(msg, SHA256_MAC_LEN);
		wpabuf_put_data(msg, auth->own_bi->pubkey_hash, SHA256_MAC_LEN);
	}

	addr[0] = wpabuf_head(msg);
	len[0] = wpabuf_len(msg);
	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, i_auth_len + AES_BLOCK_SIZE);
	wrapped_i_auth = wpabuf_put(msg, i_auth_len + AES_BLOCK_SIZE);
	/* I-auth = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [BI.x |] 1) */
	WPA_PUT_LE16(i_auth, DPP_ATTR_I_AUTH_TAG);
	WPA_PUT_LE16(&i_auth[2], auth->curve->hash_len);
	if (dpp_gen_i_auth(auth, i_auth + 4) < 0 ||
	    aes_siv_encrypt(auth->ke, auth->curve->hash_len,
			    i_auth, i_auth_len,
			    1, addr, len, wrapped_i_auth) < 0)
		goto fail;
	wpa_hexdump(MSG_DEBUG, "DPP: {I-auth}ke",
		    wrapped_i_auth, i_auth_len + AES_BLOCK_SIZE);

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Authentication Confirmation frame attributes",
			msg);
	dpp_auth_success(auth);

	return msg;

fail:
	return NULL;
}


static void
dpp_auth_resp_rx_status(struct dpp_authentication *auth,
			const u8 *attr_start, size_t attr_len,
			const u8 *wrapped_data, u16 wrapped_data_len,
			enum dpp_status_error status)
{
	const u8 *addr[1];
	size_t len[1];
	u8 *unwrapped = NULL;
	size_t unwrapped_len = 0;
	const u8 *i_nonce, *r_capab;
	u16 i_nonce_len, r_capab_len;

	if (status == DPP_STATUS_NOT_COMPATIBLE) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Responder reported incompatible roles");
	} else if (status == DPP_STATUS_RESPONSE_PENDING) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Responder reported more time needed");
	} else {
		wpa_printf(MSG_DEBUG,
			   "DPP: Responder reported failure (status %d)",
			   status);
		return;
	}

	addr[0] = attr_start;
	len[0] = attr_len;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		goto fail;
	if (aes_siv_decrypt(auth->k1, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    1, addr, len, unwrapped) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in unwrapped data");
		goto fail;
	}

	i_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_I_NONCE,
			       &i_nonce_len);
	if (!i_nonce || i_nonce_len != auth->curve->nonce_len) {
		wpa_printf(MSG_DEBUG, "DPP: Missing or invalid I-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: I-nonce", i_nonce, i_nonce_len);
	if (os_memcmp(auth->i_nonce, i_nonce, i_nonce_len) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: I-nonce mismatch");
		goto fail;
	}

	r_capab = dpp_get_attr(unwrapped, unwrapped_len,
			       DPP_ATTR_R_CAPABILITIES,
			       &r_capab_len);
	if (!r_capab || r_capab_len < 1) {
		wpa_printf(MSG_DEBUG, "DPP: Missing or invalid R-capabilities");
		goto fail;
	}
	auth->r_capab = r_capab[0];
	wpa_printf(MSG_DEBUG, "DPP: R-capabilities: 0x%02x", auth->r_capab);
	if (status == DPP_STATUS_NOT_COMPATIBLE) {
		wpa_msg(auth->msg_ctx, MSG_INFO, DPP_EVENT_NOT_COMPATIBLE
			"r-capab=0x%02x", auth->r_capab);
	} else if (status == DPP_STATUS_RESPONSE_PENDING) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Continue waiting for full DPP Authentication Response");
		wpa_msg(auth->msg_ctx, MSG_INFO, DPP_EVENT_RESPONSE_PENDING);
	}
fail:
	bin_clear_free(unwrapped, unwrapped_len);
}


struct wpabuf *
dpp_auth_resp_rx(struct dpp_authentication *auth, const u8 *attr_start,
		 size_t attr_len)
{
	EVP_PKEY *pr;
	EVP_PKEY_CTX *ctx = NULL;
	size_t secret_len;
	const u8 *addr[1];
	size_t len[1];
	u8 *unwrapped = NULL, *unwrapped2 = NULL;
	size_t unwrapped_len = 0, unwrapped2_len = 0;
	const u8 *r_bootstrap, *i_bootstrap, *wrapped_data, *status, *r_proto,
		*r_nonce, *i_nonce, *r_capab, *wrapped2, *r_auth;
	u16 r_bootstrap_len, i_bootstrap_len, wrapped_data_len, status_len,
		r_proto_len, r_nonce_len, i_nonce_len, r_capab_len,
		wrapped2_len, r_auth_len;
	u8 r_auth2[DPP_MAX_HASH_LEN];

	wrapped_data = dpp_get_attr(attr_start, attr_len, DPP_ATTR_WRAPPED_DATA,
				    &wrapped_data_len);
	if (!wrapped_data) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing required Wrapped data attribute");
		return NULL;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Wrapped data",
		    wrapped_data, wrapped_data_len);

	if (wrapped_data_len < AES_BLOCK_SIZE)
		return NULL;

	attr_len = wrapped_data - 4 - attr_start;

	r_bootstrap = dpp_get_attr(attr_start, attr_len,
				   DPP_ATTR_R_BOOTSTRAP_KEY_HASH,
				   &r_bootstrap_len);
	if (!r_bootstrap || r_bootstrap_len != SHA256_MAC_LEN) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required Responder Bootstrapping Key Hash attribute");
		return NULL;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Responder Bootstrapping Key Hash",
		    r_bootstrap, r_bootstrap_len);
	if (os_memcmp(r_bootstrap, auth->peer_bi->pubkey_hash,
		      SHA256_MAC_LEN) != 0) {
		wpa_hexdump(MSG_DEBUG,
			    "DPP: Expected Responder Bootstrapping Key Hash",
			    auth->peer_bi->pubkey_hash, SHA256_MAC_LEN);
		return NULL;
	}

	i_bootstrap = dpp_get_attr(attr_start, attr_len,
				   DPP_ATTR_I_BOOTSTRAP_KEY_HASH,
				   &i_bootstrap_len);
	if (i_bootstrap) {
		if (i_bootstrap_len != SHA256_MAC_LEN) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Invalid Initiator Bootstrapping Key Hash attribute");
			return NULL;
		}
		wpa_hexdump(MSG_MSGDUMP,
			    "DPP: Initiator Bootstrapping Key Hash",
			    i_bootstrap, i_bootstrap_len);
		if (!auth->own_bi ||
		    os_memcmp(i_bootstrap, auth->own_bi->pubkey_hash,
			      SHA256_MAC_LEN) != 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Initiator Bootstrapping Key Hash attribute did not match");
			return NULL;
		}
	}

	status = dpp_get_attr(attr_start, attr_len, DPP_ATTR_STATUS,
			      &status_len);
	if (!status || status_len < 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required DPP Status attribute");
		return NULL;
	}
	wpa_printf(MSG_DEBUG, "DPP: Status %u", status[0]);
	auth->auth_resp_status = status[0];
	if (status[0] != DPP_STATUS_OK) {
		dpp_auth_resp_rx_status(auth, attr_start,
					attr_len, wrapped_data,
					wrapped_data_len, status[0]);
		return NULL;
	}

	r_proto = dpp_get_attr(attr_start, attr_len, DPP_ATTR_R_PROTOCOL_KEY,
			       &r_proto_len);
	if (!r_proto) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing required Responder Protocol Key attribute");
		return NULL;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Responder Protocol Key",
		    r_proto, r_proto_len);

	/* N = pI * PR */
	pr = dpp_set_pubkey_point(auth->own_protocol_key, r_proto, r_proto_len);
	if (!pr) {
		wpa_printf(MSG_DEBUG, "DPP: Invalid Responder Protocol Key");
		return NULL;
	}
	dpp_debug_print_key("Peer (Responder) Protocol Key", pr);

	ctx = EVP_PKEY_CTX_new(auth->own_protocol_key, NULL);
	if (!ctx ||
	    EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, pr) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &secret_len) != 1 ||
	    secret_len > DPP_MAX_SHARED_SECRET_LEN ||
	    EVP_PKEY_derive(ctx, auth->Nx, &secret_len) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to derive ECDH shared secret: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;
	auth->peer_protocol_key = pr;
	pr = NULL;

	wpa_hexdump_key(MSG_DEBUG, "DPP: ECDH shared secret (N.x)",
			auth->Nx, auth->secret_len);

	if (dpp_derive_k2(auth->Nx, auth->secret_len, auth->k2,
			  auth->curve->hash_len) < 0)
		goto fail;

	addr[0] = attr_start;
	len[0] = attr_len;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		goto fail;
	if (aes_siv_decrypt(auth->k2, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    1, addr, len, unwrapped) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in unwrapped data");
		goto fail;
	}

	r_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_R_NONCE,
			       &r_nonce_len);
	if (!r_nonce || r_nonce_len != auth->curve->nonce_len) {
		wpa_printf(MSG_DEBUG, "DPP: Missing or invalid R-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: R-nonce", r_nonce, r_nonce_len);
	os_memcpy(auth->r_nonce, r_nonce, r_nonce_len);

	i_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_I_NONCE,
			       &i_nonce_len);
	if (!i_nonce || i_nonce_len != auth->curve->nonce_len) {
		wpa_printf(MSG_DEBUG, "DPP: Missing or invalid I-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: I-nonce", i_nonce, i_nonce_len);
	if (os_memcmp(auth->i_nonce, i_nonce, i_nonce_len) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: I-nonce mismatch");
		goto fail;
	}

	if (auth->own_bi && auth->peer_bi) {
		/* Mutual authentication */
		if (dpp_auth_derive_l_initiator(auth) < 0)
			goto fail;
	}

	if (dpp_derive_ke(auth, auth->ke, auth->curve->hash_len) < 0)
		goto fail;

	r_capab = dpp_get_attr(unwrapped, unwrapped_len,
			       DPP_ATTR_R_CAPABILITIES,
			       &r_capab_len);
	if (!r_capab || r_capab_len < 1) {
		wpa_printf(MSG_DEBUG, "DPP: Missing or invalid R-capabilities");
		goto fail;
	}
	auth->r_capab = r_capab[0];
	wpa_printf(MSG_DEBUG, "DPP: R-capabilities: 0x%02x", auth->r_capab);
	if ((auth->configurator && (auth->r_capab & DPP_CAPAB_CONFIGURATOR)) ||
	    (!auth->configurator && (auth->r_capab & DPP_CAPAB_ENROLLEE))) {
		wpa_printf(MSG_DEBUG, "DPP: Incompatible role selection");
		goto fail;
	}

	wrapped2 = dpp_get_attr(unwrapped, unwrapped_len,
				DPP_ATTR_WRAPPED_DATA, &wrapped2_len);
	if (!wrapped2 || wrapped2_len < AES_BLOCK_SIZE) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid Secondary Wrapped Data");
		goto fail;
	}

	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped2, wrapped2_len);
	unwrapped2_len = wrapped2_len - AES_BLOCK_SIZE;
	unwrapped2 = os_malloc(unwrapped2_len);
	if (!unwrapped2)
		goto fail;
	if (aes_siv_decrypt(auth->ke, auth->curve->hash_len,
			    wrapped2, wrapped2_len,
			    0, NULL, NULL, unwrapped2) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped2, unwrapped2_len);

	if (dpp_check_attrs(unwrapped2, unwrapped2_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in secondary unwrapped data");
		goto fail;
	}

	r_auth = dpp_get_attr(unwrapped2, unwrapped2_len, DPP_ATTR_R_AUTH_TAG,
			       &r_auth_len);
	if (!r_auth || r_auth_len != auth->curve->hash_len) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid Responder Authenticating Tag");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Received Responder Authenticating Tag",
		    r_auth, r_auth_len);
	/* R-auth' = H(I-nonce | R-nonce | PI.x | PR.x | [BI.x |] BR.x | 0) */
	if (dpp_gen_r_auth(auth, r_auth2) < 0)
		goto fail;
	wpa_hexdump(MSG_DEBUG, "DPP: Calculated Responder Authenticating Tag",
		    r_auth2, r_auth_len);
	if (os_memcmp(r_auth, r_auth2, r_auth_len) != 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Mismatching Responder Authenticating Tag");
		goto fail;
	}

	bin_clear_free(unwrapped, unwrapped_len);
	bin_clear_free(unwrapped2, unwrapped2_len);

	return dpp_auth_build_conf(auth);

fail:
	bin_clear_free(unwrapped, unwrapped_len);
	bin_clear_free(unwrapped2, unwrapped2_len);
	EVP_PKEY_free(pr);
	EVP_PKEY_CTX_free(ctx);
	return NULL;
}


int dpp_auth_conf_rx(struct dpp_authentication *auth, const u8 *attr_start,
		     size_t attr_len)
{
	const u8 *r_bootstrap, *i_bootstrap, *wrapped_data, *status, *i_auth;
	u16 r_bootstrap_len, i_bootstrap_len, wrapped_data_len, status_len,
		i_auth_len;
	const u8 *addr[1];
	size_t len[1];
	u8 *unwrapped = NULL;
	size_t unwrapped_len = 0;
	u8 i_auth2[DPP_MAX_HASH_LEN];

	wrapped_data = dpp_get_attr(attr_start, attr_len, DPP_ATTR_WRAPPED_DATA,
				    &wrapped_data_len);
	if (!wrapped_data) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing required Wrapped data attribute");
		return -1;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Wrapped data",
		    wrapped_data, wrapped_data_len);

	if (wrapped_data_len < AES_BLOCK_SIZE)
		return -1;

	attr_len = wrapped_data - 4 - attr_start;

	r_bootstrap = dpp_get_attr(attr_start, attr_len,
				   DPP_ATTR_R_BOOTSTRAP_KEY_HASH,
				   &r_bootstrap_len);
	if (!r_bootstrap || r_bootstrap > wrapped_data ||
	    r_bootstrap_len != SHA256_MAC_LEN) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required Responder Bootstrapping Key Hash attribute");
		return -1;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Responder Bootstrapping Key Hash",
		    r_bootstrap, r_bootstrap_len);
	if (os_memcmp(r_bootstrap, auth->own_bi->pubkey_hash,
		      SHA256_MAC_LEN) != 0) {
		wpa_hexdump(MSG_DEBUG,
			    "DPP: Expected Responder Bootstrapping Key Hash",
			    auth->peer_bi->pubkey_hash, SHA256_MAC_LEN);
		return -1;
	}

	i_bootstrap = dpp_get_attr(attr_start, attr_len,
				   DPP_ATTR_I_BOOTSTRAP_KEY_HASH,
				   &i_bootstrap_len);
	if (i_bootstrap) {
		if (i_bootstrap > wrapped_data ||
		    i_bootstrap_len != SHA256_MAC_LEN) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Invalid Initiator Bootstrapping Key Hash attribute");
			return -1;
		}
		wpa_hexdump(MSG_MSGDUMP,
			    "DPP: Initiator Bootstrapping Key Hash",
			    i_bootstrap, i_bootstrap_len);
		if (!auth->peer_bi ||
		    os_memcmp(i_bootstrap, auth->peer_bi->pubkey_hash,
			      SHA256_MAC_LEN) != 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Initiator Bootstrapping Key Hash attribute did not match");
			return -1;
		}
	}

	status = dpp_get_attr(attr_start, attr_len, DPP_ATTR_STATUS,
			      &status_len);
	if (!status || status_len < 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required DPP Status attribute");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "DPP: Status %u", status[0]);
	if (status[0] != DPP_STATUS_OK) {
		wpa_printf(MSG_DEBUG, "DPP: Authentication failed");
		return -1;
	}

	addr[0] = attr_start;
	len[0] = attr_len;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		return -1;
	if (aes_siv_decrypt(auth->ke, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    1, addr, len, unwrapped) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in unwrapped data");
		goto fail;
	}

	i_auth = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_I_AUTH_TAG,
			      &i_auth_len);
	if (!i_auth || i_auth_len != auth->curve->hash_len) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid Initiator Authenticating Tag");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Received Initiator Authenticating Tag",
		    i_auth, i_auth_len);
	/* I-auth' = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [BI.x |] 1) */
	if (dpp_gen_i_auth(auth, i_auth2) < 0)
		goto fail;
	wpa_hexdump(MSG_DEBUG, "DPP: Calculated Initiator Authenticating Tag",
		    i_auth2, i_auth_len);
	if (os_memcmp(i_auth, i_auth2, i_auth_len) != 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Mismatching Initiator Authenticating Tag");
		goto fail;
	}

	bin_clear_free(unwrapped, unwrapped_len);
	dpp_auth_success(auth);
	return 0;
fail:
	bin_clear_free(unwrapped, unwrapped_len);
	return -1;
}


void dpp_configuration_free(struct dpp_configuration *conf)
{
	if (!conf)
		return;
	str_clear_free(conf->passphrase);
	bin_clear_free(conf, sizeof(*conf));
}


void dpp_auth_deinit(struct dpp_authentication *auth)
{
	if (!auth)
		return;
	dpp_configuration_free(auth->conf_ap);
	dpp_configuration_free(auth->conf_sta);
	EVP_PKEY_free(auth->own_protocol_key);
	EVP_PKEY_free(auth->peer_protocol_key);
	wpabuf_free(auth->req_attr);
	wpabuf_free(auth->resp_attr);
	wpabuf_free(auth->conf_req);
	os_free(auth->connector);
	wpabuf_free(auth->net_access_key);
	wpabuf_free(auth->c_sign_key);
#ifdef CONFIG_TESTING_OPTIONS
	os_free(auth->config_obj_override);
	os_free(auth->discovery_override);
	os_free(auth->groups_override);
	os_free(auth->devices_override);
#endif /* CONFIG_TESTING_OPTIONS */
	bin_clear_free(auth, sizeof(*auth));
}


static struct wpabuf *
dpp_build_conf_start(struct dpp_authentication *auth,
		     struct dpp_configuration *conf, size_t tailroom)
{
	struct wpabuf *buf;
	char ssid[6 * sizeof(conf->ssid) + 1];

#ifdef CONFIG_TESTING_OPTIONS
	if (auth->discovery_override)
		tailroom += os_strlen(auth->discovery_override);
#endif /* CONFIG_TESTING_OPTIONS */

	buf = wpabuf_alloc(200 + tailroom);
	if (!buf)
		return NULL;
	wpabuf_put_str(buf, "{\"wi-fi_tech\":\"infra\",\"discovery\":");
#ifdef CONFIG_TESTING_OPTIONS
	if (auth->discovery_override) {
		wpa_printf(MSG_DEBUG, "DPP: TESTING - discovery override: '%s'",
			   auth->discovery_override);
		wpabuf_put_str(buf, auth->discovery_override);
		wpabuf_put_u8(buf, ',');
		return buf;
	}
#endif /* CONFIG_TESTING_OPTIONS */
	wpabuf_put_str(buf, "{\"ssid\":\"");
	json_escape_string(ssid, sizeof(ssid),
			   (const char *) conf->ssid, conf->ssid_len);
	wpabuf_put_str(buf, ssid);
	wpabuf_put_str(buf, "\"");
	/* TODO: optional channel information */
	wpabuf_put_str(buf, "},");

	return buf;
}


static int dpp_bn2bin_pad(const BIGNUM *bn, u8 *pos, size_t len)
{
	int num_bytes, offset;

	num_bytes = BN_num_bytes(bn);
	if ((size_t) num_bytes > len)
		return -1;
	offset = len - num_bytes;
	os_memset(pos, 0, offset);
	BN_bn2bin(bn, pos + offset);
	return 0;
}


static int dpp_build_jwk(struct wpabuf *buf, const char *name, EVP_PKEY *key,
			 const char *kid, const struct dpp_curve_params *curve)
{
	struct wpabuf *pub;
	const u8 *pos;
	char *x = NULL, *y = NULL;
	int ret = -1;

	pub = dpp_get_pubkey_point(key, 0);
	if (!pub)
		goto fail;
	pos = wpabuf_head(pub);
	x = (char *) base64_url_encode(pos, curve->prime_len, NULL, 0);
	pos += curve->prime_len;
	y = (char *) base64_url_encode(pos, curve->prime_len, NULL, 0);

	wpabuf_put_str(buf, "\"");
	wpabuf_put_str(buf, name);
	wpabuf_put_str(buf, "\":{\"kty\":\"EC\",\"crv\":\"");
	wpabuf_put_str(buf, curve->jwk_crv);
	wpabuf_put_str(buf, "\",\"x\":\"");
	wpabuf_put_str(buf, x);
	wpabuf_put_str(buf, "\",\"y\":\"");
	wpabuf_put_str(buf, y);
	if (kid) {
		wpabuf_put_str(buf, "\",\"kid\":\"");
		wpabuf_put_str(buf, kid);
	}
	wpabuf_put_str(buf, "\"}");
	ret = 0;
out:
	wpabuf_free(pub);
	os_free(x);
	os_free(y);
	return ret;
fail:
	goto out;
}


static struct wpabuf *
dpp_build_conf_obj_dpp(struct dpp_authentication *auth, int ap,
		       struct dpp_configuration *conf)
{
	struct wpabuf *buf = NULL;
	char *signed1 = NULL, *signed2 = NULL, *signed3 = NULL;
	size_t tailroom;
	const struct dpp_curve_params *curve;
	char jws_prot_hdr[100];
	size_t signed1_len, signed2_len, signed3_len;
	struct wpabuf *dppcon = NULL;
	unsigned char *signature = NULL;
	const unsigned char *p;
	size_t signature_len;
	EVP_MD_CTX *md_ctx = NULL;
	ECDSA_SIG *sig = NULL;
	char *dot = ".";
	const char *alg;
	const EVP_MD *sign_md;
	const BIGNUM *r, *s;
	size_t extra_len = 1000;

	if (!auth->conf) {
		wpa_printf(MSG_INFO,
			   "DPP: No configurator specified - cannot generate DPP config object");
		goto fail;
	}
	curve = auth->conf->curve;
	if (curve->hash_len == SHA256_MAC_LEN) {
		alg = "ES256";
		sign_md = EVP_sha256();
	} else if (curve->hash_len == SHA384_MAC_LEN) {
		alg = "ES384";
		sign_md = EVP_sha384();
	} else if (curve->hash_len == SHA512_MAC_LEN) {
		alg = "ES512";
		sign_md = EVP_sha512();
	} else {
		wpa_printf(MSG_DEBUG, "DPP: Unknown signature algorithm");
		goto fail;
	}

#ifdef CONFIG_TESTING_OPTIONS
	if (auth->groups_override)
		extra_len += os_strlen(auth->groups_override);
	if (auth->devices_override)
		extra_len += os_strlen(auth->devices_override);
#endif /* CONFIG_TESTING_OPTIONS */

	/* Connector (JSON dppCon object) */
	dppcon = wpabuf_alloc(extra_len + 2 * auth->curve->prime_len * 4 / 3);
	if (!dppcon)
		goto fail;
#ifdef CONFIG_TESTING_OPTIONS
	if (auth->groups_override || auth->devices_override) {
		wpabuf_put_u8(dppcon, '{');
		if (auth->groups_override) {
			wpa_printf(MSG_DEBUG,
				   "DPP: TESTING - groups override: '%s'",
				   auth->groups_override);
			wpabuf_put_str(dppcon, "\"groups\":");
			wpabuf_put_str(dppcon, auth->groups_override);
			wpabuf_put_u8(dppcon, ',');
		}
		if (auth->devices_override) {
			wpa_printf(MSG_DEBUG,
				   "DPP: TESTING - devices override: '%s'",
				   auth->devices_override);
			wpabuf_put_str(dppcon, "\"devices\":");
			wpabuf_put_str(dppcon, auth->devices_override);
			wpabuf_put_u8(dppcon, ',');
		}
		goto skip_groups;
	}
#endif /* CONFIG_TESTING_OPTIONS */
	wpabuf_put_str(dppcon, "{\"groups\":[{\"groupId\":\"*\",");
	wpabuf_printf(dppcon, "\"netRole\":\"%s\"}],", ap ? "ap" : "sta");
#ifdef CONFIG_TESTING_OPTIONS
skip_groups:
#endif /* CONFIG_TESTING_OPTIONS */
	if (dpp_build_jwk(dppcon, "netAccessKey", auth->peer_protocol_key, NULL,
			  auth->curve) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to build netAccessKey JWK");
		goto fail;
	}
	if (conf->netaccesskey_expiry) {
		struct os_tm tm;

		if (os_gmtime(conf->netaccesskey_expiry, &tm) < 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Failed to generate expiry string");
			goto fail;
		}
		wpabuf_printf(dppcon,
			      ",\"expiry\":\"%04u-%02u-%02uT%02u:%02u:%02uZ\"",
			      tm.year, tm.month, tm.day,
			      tm.hour, tm.min, tm.sec);
	}
	wpabuf_put_u8(dppcon, '}');
	wpa_printf(MSG_DEBUG, "DPP: dppCon: %s",
		   (const char *) wpabuf_head(dppcon));

	os_snprintf(jws_prot_hdr, sizeof(jws_prot_hdr),
		    "{\"typ\":\"dppCon\",\"kid\":\"%s\",\"alg\":\"%s\"}",
		    auth->conf->kid, alg);
	signed1 = (char *) base64_url_encode((unsigned char *) jws_prot_hdr,
					     os_strlen(jws_prot_hdr),
					     &signed1_len, 0);
	signed2 = (char *) base64_url_encode(wpabuf_head(dppcon),
					     wpabuf_len(dppcon),
					     &signed2_len, 0);
	if (!signed1 || !signed2)
		goto fail;

	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx)
		goto fail;

	ERR_clear_error();
	if (EVP_DigestSignInit(md_ctx, NULL, sign_md, NULL,
			       auth->conf->csign) != 1) {
		wpa_printf(MSG_DEBUG, "DPP: EVP_DigestSignInit failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	if (EVP_DigestSignUpdate(md_ctx, signed1, signed1_len) != 1 ||
	    EVP_DigestSignUpdate(md_ctx, dot, 1) != 1 ||
	    EVP_DigestSignUpdate(md_ctx, signed2, signed2_len) != 1) {
		wpa_printf(MSG_DEBUG, "DPP: EVP_DigestSignUpdate failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	if (EVP_DigestSignFinal(md_ctx, NULL, &signature_len) != 1) {
		wpa_printf(MSG_DEBUG, "DPP: EVP_DigestSignFinal failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	signature = os_malloc(signature_len);
	if (!signature)
		goto fail;
	if (EVP_DigestSignFinal(md_ctx, signature, &signature_len) != 1) {
		wpa_printf(MSG_DEBUG, "DPP: EVP_DigestSignFinal failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: signedConnector ECDSA signature (DER)",
		    signature, signature_len);
	/* Convert to raw coordinates r,s */
	p = signature;
	sig = d2i_ECDSA_SIG(NULL, &p, signature_len);
	if (!sig)
		goto fail;
	ECDSA_SIG_get0(sig, &r, &s);
	if (dpp_bn2bin_pad(r, signature, curve->prime_len) < 0 ||
	    dpp_bn2bin_pad(s, signature + curve->prime_len,
			   curve->prime_len) < 0)
		goto fail;
	signature_len = 2 * curve->prime_len;
	wpa_hexdump(MSG_DEBUG, "DPP: signedConnector ECDSA signature (raw r,s)",
		    signature, signature_len);
	signed3 = (char *) base64_url_encode(signature, signature_len,
					     &signed3_len, 0);
	if (!signed3)
		goto fail;

	tailroom = 1000;
	tailroom += 2 * curve->prime_len * 4 / 3 + os_strlen(auth->conf->kid);
	tailroom += signed1_len + signed2_len + signed3_len;
	buf = dpp_build_conf_start(auth, conf, tailroom);
	if (!buf)
		return NULL;

	wpabuf_put_str(buf, "\"cred\":{\"akm\":\"dpp\",\"signedConnector\":\"");
	wpabuf_put_str(buf, signed1);
	wpabuf_put_u8(buf, '.');
	wpabuf_put_str(buf, signed2);
	wpabuf_put_u8(buf, '.');
	wpabuf_put_str(buf, signed3);
	wpabuf_put_str(buf, "\",");
	if (dpp_build_jwk(buf, "csign", auth->conf->csign, auth->conf->kid,
			  curve) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to build csign JWK");
		goto fail;
	}
	if (auth->conf->csign_expiry) {
		struct os_tm tm;

		if (os_gmtime(auth->conf->csign_expiry, &tm) < 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Failed to generate expiry string");
			goto fail;
		}
		wpabuf_printf(buf,
			      ",\"expiry\":\"%04u-%02u-%02uT%02u:%02u:%02uZ\"",
			      tm.year, tm.month, tm.day,
			      tm.hour, tm.min, tm.sec);
	}

	wpabuf_put_str(buf, "}}");

	wpa_hexdump_ascii_key(MSG_DEBUG, "DPP: Configuration Object",
			      wpabuf_head(buf), wpabuf_len(buf));

out:
	EVP_MD_CTX_destroy(md_ctx);
	ECDSA_SIG_free(sig);
	os_free(signed1);
	os_free(signed2);
	os_free(signed3);
	os_free(signature);
	wpabuf_free(dppcon);
	return buf;
fail:
	wpa_printf(MSG_DEBUG, "DPP: Failed to build configuration object");
	wpabuf_free(buf);
	buf = NULL;
	goto out;
}


static struct wpabuf *
dpp_build_conf_obj_legacy(struct dpp_authentication *auth, int ap,
			  struct dpp_configuration *conf)
{
	struct wpabuf *buf;

	buf = dpp_build_conf_start(auth, conf, 1000);
	if (!buf)
		return NULL;

	wpabuf_put_str(buf, "\"cred\":{\"akm\":\"psk\",");
	if (conf->passphrase) {
		char pass[63 * 6 + 1];

		if (os_strlen(conf->passphrase) > 63) {
			wpabuf_free(buf);
			return NULL;
		}

		json_escape_string(pass, sizeof(pass), conf->passphrase,
				   os_strlen(conf->passphrase));
		wpabuf_put_str(buf, "\"pass\":\"");
		wpabuf_put_str(buf, pass);
		wpabuf_put_str(buf, "\"");
	} else {
		char psk[2 * sizeof(conf->psk) + 1];

		wpa_snprintf_hex(psk, sizeof(psk),
				 conf->psk, sizeof(conf->psk));
		wpabuf_put_str(buf, "\"psk_hex\":\"");
		wpabuf_put_str(buf, psk);
		wpabuf_put_str(buf, "\"");
	}
	wpabuf_put_str(buf, "}}");

	wpa_hexdump_ascii_key(MSG_DEBUG, "DPP: Configuration Object (legacy)",
			      wpabuf_head(buf), wpabuf_len(buf));

	return buf;
}


static struct wpabuf *
dpp_build_conf_obj(struct dpp_authentication *auth, int ap)
{
	struct dpp_configuration *conf;

#ifdef CONFIG_TESTING_OPTIONS
	if (auth->config_obj_override) {
		wpa_printf(MSG_DEBUG, "DPP: Testing - Config Object override");
		return wpabuf_alloc_copy(auth->config_obj_override,
					 os_strlen(auth->config_obj_override));
	}
#endif /* CONFIG_TESTING_OPTIONS */

	conf = ap ? auth->conf_ap : auth->conf_sta;
	if (!conf) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No configuration available for Enrollee(%s) - reject configuration request",
			   ap ? "ap" : "sta");
		return NULL;
	}

	if (conf->dpp)
		return dpp_build_conf_obj_dpp(auth, ap, conf);
	return dpp_build_conf_obj_legacy(auth, ap, conf);
}


static struct wpabuf *
dpp_build_conf_resp(struct dpp_authentication *auth, const u8 *e_nonce,
		    u16 e_nonce_len, int ap)
{
	struct wpabuf *conf;
	size_t clear_len;
	struct wpabuf *clear = NULL, *msg = NULL;
	u8 *wrapped;
	const u8 *addr[1];
	size_t len[1];
	enum dpp_status_error status;

	conf = dpp_build_conf_obj(auth, ap);
	if (conf) {
		wpa_hexdump_ascii(MSG_DEBUG, "DPP: configurationObject JSON",
				  wpabuf_head(conf), wpabuf_len(conf));
	}
	status = conf ? DPP_STATUS_OK : DPP_STATUS_CONFIGURE_FAILURE;

	/* { E-nonce, configurationObject}ke */
	clear_len = 4 + e_nonce_len;
	if (conf)
		clear_len += 4 + wpabuf_len(conf);
	clear = wpabuf_alloc(clear_len);
	msg = wpabuf_alloc(4 + 1 + 4 + clear_len + AES_BLOCK_SIZE);
	if (!clear || !msg)
		goto fail;

	/* E-nonce */
	wpabuf_put_le16(clear, DPP_ATTR_ENROLLEE_NONCE);
	wpabuf_put_le16(clear, e_nonce_len);
	wpabuf_put_data(clear, e_nonce, e_nonce_len);

	if (conf) {
		wpabuf_put_le16(clear, DPP_ATTR_CONFIG_OBJ);
		wpabuf_put_le16(clear, wpabuf_len(conf));
		wpabuf_put_buf(clear, conf);
		wpabuf_free(conf);
		conf = NULL;
	}

	/* DPP Status */
	wpabuf_put_le16(msg, DPP_ATTR_STATUS);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, status);

	addr[0] = wpabuf_head(msg);
	len[0] = wpabuf_len(msg);
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);

	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);
	wrapped = wpabuf_put(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);

	wpa_hexdump_buf(MSG_DEBUG, "DPP: AES-SIV cleartext", clear);
	if (aes_siv_encrypt(auth->ke, auth->curve->hash_len,
			    wpabuf_head(clear), wpabuf_len(clear),
			    1, addr, len, wrapped) < 0)
		goto fail;
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped, wpabuf_len(clear) + AES_BLOCK_SIZE);
	wpabuf_free(clear);
	clear = NULL;

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Configuration Response attributes", msg);
	return msg;
fail:
	wpabuf_free(conf);
	wpabuf_free(clear);
	wpabuf_free(msg);
	return NULL;
}


struct wpabuf *
dpp_conf_req_rx(struct dpp_authentication *auth, const u8 *attr_start,
		size_t attr_len)
{
	const u8 *wrapped_data, *e_nonce, *config_attr;
	u16 wrapped_data_len, e_nonce_len, config_attr_len;
	u8 *unwrapped = NULL;
	size_t unwrapped_len = 0;
	struct wpabuf *resp = NULL;
	struct json_token *root = NULL, *token;
	int ap;

	if (dpp_check_attrs(attr_start, attr_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in config request");
		return NULL;
	}

	wrapped_data = dpp_get_attr(attr_start, attr_len, DPP_ATTR_WRAPPED_DATA,
				    &wrapped_data_len);
	if (!wrapped_data || wrapped_data_len < AES_BLOCK_SIZE) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required Wrapped data attribute");
		return NULL;
	}

	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		return NULL;
	if (aes_siv_decrypt(auth->ke, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    0, NULL, NULL, unwrapped) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in unwrapped data");
		goto fail;
	}

	e_nonce = dpp_get_attr(unwrapped, unwrapped_len,
			       DPP_ATTR_ENROLLEE_NONCE,
			       &e_nonce_len);
	if (!e_nonce || e_nonce_len != auth->curve->nonce_len) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid Enrollee Nonce attribute");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Enrollee Nonce", e_nonce, e_nonce_len);

	config_attr = dpp_get_attr(unwrapped, unwrapped_len,
				   DPP_ATTR_CONFIG_ATTR_OBJ,
				   &config_attr_len);
	if (!config_attr) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid Config Attributes attribute");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: Config Attributes",
			  config_attr, config_attr_len);

	root = json_parse((const char *) config_attr, config_attr_len);
	if (!root) {
		wpa_printf(MSG_DEBUG, "DPP: Could not parse Config Attributes");
		goto fail;
	}

	token = json_get_member(root, "name");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No Config Attributes - name");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: Enrollee name = '%s'", token->string);

	token = json_get_member(root, "wi-fi_tech");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No Config Attributes - wi-fi_tech");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: wi-fi_tech = '%s'", token->string);
	if (os_strcmp(token->string, "infra") != 0) {
		wpa_printf(MSG_DEBUG, "DPP: Unsupported wi-fi_tech '%s'",
			   token->string);
		goto fail;
	}

	token = json_get_member(root, "netRole");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No Config Attributes - netRole");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: netRole = '%s'", token->string);
	if (os_strcmp(token->string, "sta") == 0) {
		ap = 0;
	} else if (os_strcmp(token->string, "ap") == 0) {
		ap = 1;
	} else {
		wpa_printf(MSG_DEBUG, "DPP: Unsupported netRole '%s'",
			   token->string);
		goto fail;
	}

	resp = dpp_build_conf_resp(auth, e_nonce, e_nonce_len, ap);

fail:
	json_free(root);
	os_free(unwrapped);
	return resp;
}


static struct wpabuf *
dpp_parse_jws_prot_hdr(const u8 *prot_hdr, u16 prot_hdr_len,
		       const EVP_MD **ret_md)
{
	struct json_token *root, *token;
	struct wpabuf *kid = NULL;

	root = json_parse((const char *) prot_hdr, prot_hdr_len);
	if (!root) {
		wpa_printf(MSG_DEBUG,
			   "DPP: JSON parsing failed for JWS Protected Header");
		goto fail;
	}

	if (root->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG,
			   "DPP: JWS Protected Header root is not an object");
		goto fail;
	}

	token = json_get_member(root, "typ");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No typ string value found");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: JWS Protected Header typ=%s",
		   token->string);
	if (os_strcmp(token->string, "dppCon") != 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unsupported JWS Protected Header typ=%s",
			   token->string);
		goto fail;
	}

	token = json_get_member(root, "alg");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No alg string value found");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: JWS Protected Header alg=%s",
		   token->string);
	if (os_strcmp(token->string, "ES256") == 0)
		*ret_md = EVP_sha256();
	else if (os_strcmp(token->string, "ES384") == 0)
		*ret_md = EVP_sha384();
	else if (os_strcmp(token->string, "ES512") == 0)
		*ret_md = EVP_sha512();
	else
		*ret_md = NULL;
	if (!*ret_md) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unsupported JWS Protected Header alg=%s",
			   token->string);
		goto fail;
	}

	kid = json_get_member_base64url(root, "kid");
	if (!kid) {
		wpa_printf(MSG_DEBUG, "DPP: No kid string value found");
		goto fail;
	}
	wpa_hexdump_buf(MSG_DEBUG, "DPP: JWS Protected Header kid (decoded)",
			kid);

fail:
	json_free(root);
	return kid;
}


static int dpp_parse_cred_legacy(struct dpp_authentication *auth,
				 struct json_token *cred)
{
	struct json_token *pass, *psk_hex;

	wpa_printf(MSG_DEBUG, "DPP: Legacy akm=psk credential");

	pass = json_get_member(cred, "pass");
	psk_hex = json_get_member(cred, "psk_hex");

	if (pass && pass->type == JSON_STRING) {
		size_t len = os_strlen(pass->string);

		wpa_hexdump_ascii_key(MSG_DEBUG, "DPP: Legacy passphrase",
				      pass->string, len);
		if (len < 8 || len > 63)
			return -1;
		os_strlcpy(auth->passphrase, pass->string,
			   sizeof(auth->passphrase));
	} else if (psk_hex && psk_hex->type == JSON_STRING) {
		if (os_strlen(psk_hex->string) != PMK_LEN * 2 ||
		    hexstr2bin(psk_hex->string, auth->psk, PMK_LEN) < 0) {
			wpa_printf(MSG_DEBUG, "DPP: Invalid psk_hex encoding");
			return -1;
		}
		wpa_hexdump_key(MSG_DEBUG, "DPP: Legacy PSK",
				auth->psk, PMK_LEN);
		auth->psk_set = 1;
	} else {
		wpa_printf(MSG_DEBUG, "DPP: No pass or psk_hex strings found");
		return -1;
	}

	return 0;
}


static EVP_PKEY * dpp_parse_jwk(struct json_token *jwk,
				const struct dpp_curve_params **key_curve)
{
	struct json_token *token;
	const struct dpp_curve_params *curve;
	struct wpabuf *x = NULL, *y = NULL;
	EC_GROUP *group;
	EVP_PKEY *pkey = NULL;

	token = json_get_member(jwk, "kty");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No kty in JWK");
		goto fail;
	}
	if (os_strcmp(token->string, "EC") != 0) {
		wpa_printf(MSG_DEBUG, "DPP: Unexpected JWK kty '%s",
			   token->string);
		goto fail;
	}

	token = json_get_member(jwk, "crv");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No crv in JWK");
		goto fail;
	}
	curve = dpp_get_curve_jwk_crv(token->string);
	if (!curve) {
		wpa_printf(MSG_DEBUG, "DPP: Unsupported JWK crv '%s'",
			   token->string);
		goto fail;
	}

	x = json_get_member_base64url(jwk, "x");
	if (!x) {
		wpa_printf(MSG_DEBUG, "DPP: No x in JWK");
		goto fail;
	}
	wpa_hexdump_buf(MSG_DEBUG, "DPP: JWK x", x);
	if (wpabuf_len(x) != curve->prime_len) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unexpected JWK x length %u (expected %u for curve %s)",
			   (unsigned int) wpabuf_len(x),
			   (unsigned int) curve->prime_len, curve->name);
		goto fail;
	}

	y = json_get_member_base64url(jwk, "y");
	if (!y) {
		wpa_printf(MSG_DEBUG, "DPP: No y in JWK");
		goto fail;
	}
	wpa_hexdump_buf(MSG_DEBUG, "DPP: JWK y", y);
	if (wpabuf_len(y) != curve->prime_len) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unexpected JWK y length %u (expected %u for curve %s)",
			   (unsigned int) wpabuf_len(y),
			   (unsigned int) curve->prime_len, curve->name);
		goto fail;
	}

	group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(curve->name));
	if (!group) {
		wpa_printf(MSG_DEBUG, "DPP: Could not prepare group for JWK");
		goto fail;
	}

	pkey = dpp_set_pubkey_point_group(group, wpabuf_head(x), wpabuf_head(y),
					  wpabuf_len(x));
	*key_curve = curve;

fail:
	wpabuf_free(x);
	wpabuf_free(y);

	return pkey;
}


int dpp_key_expired(const char *timestamp, os_time_t *expiry)
{
	struct os_time now;
	unsigned int year, month, day, hour, min, sec;
	os_time_t utime;
	const char *pos;

	/* ISO 8601 date and time:
	 * <date>T<time>
	 * YYYY-MM-DDTHH:MM:SSZ
	 * YYYY-MM-DDTHH:MM:SS+03:00
	 */
	if (os_strlen(timestamp) < 19) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Too short timestamp - assume expired key");
		return 1;
	}
	if (sscanf(timestamp, "%04u-%02u-%02uT%02u:%02u:%02u",
		   &year, &month, &day, &hour, &min, &sec) != 6) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to parse expiration day - assume expired key");
		return 1;
	}

	if (os_mktime(year, month, day, hour, min, sec, &utime) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid date/time information - assume expired key");
		return 1;
	}

	pos = timestamp + 19;
	if (*pos == 'Z' || *pos == '\0') {
		/* In UTC - no need to adjust */
	} else if (*pos == '-' || *pos == '+') {
		int items;

		/* Adjust local time to UTC */
		items = sscanf(pos + 1, "%02u:%02u", &hour, &min);
		if (items < 1) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Invalid time zone designator (%s) - assume expired key",
				   pos);
			return 1;
		}
		if (*pos == '-')
			utime += 3600 * hour;
		if (*pos == '+')
			utime -= 3600 * hour;
		if (items > 1) {
			if (*pos == '-')
				utime += 60 * min;
			if (*pos == '+')
				utime -= 60 * min;
		}
	} else {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid time zone designator (%s) - assume expired key",
			   pos);
		return 1;
	}
	if (expiry)
		*expiry = utime;

	if (os_get_time(&now) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Cannot get current time - assume expired key");
		return 1;
	}

	if (now.sec > utime) {
		wpa_printf(MSG_DEBUG, "DPP: Key has expired (%lu < %lu)",
			   utime, now.sec);
		return 1;
	}

	return 0;
}


static int dpp_parse_connector(struct dpp_authentication *auth,
			       const unsigned char *payload,
			       u16 payload_len)
{
	struct json_token *root, *groups, *devices, *netkey, *token;
	int ret = -1;
	EVP_PKEY *key = NULL;
	const struct dpp_curve_params *curve;
	unsigned int rules = 0;

	root = json_parse((const char *) payload, payload_len);
	if (!root) {
		wpa_printf(MSG_DEBUG, "DPP: JSON parsing of connector failed");
		goto fail;
	}

	groups = json_get_member(root, "groups");
	if (!groups || groups->type != JSON_ARRAY) {
		wpa_printf(MSG_DEBUG, "DPP: No groups array found");
		goto skip_groups;
	}
	for (token = groups->child; token; token = token->sibling) {
		struct json_token *id, *role;

		id = json_get_member(token, "groupId");
		if (!id || id->type != JSON_STRING) {
			wpa_printf(MSG_DEBUG, "DPP: Missing groupId string");
			goto fail;
		}

		role = json_get_member(token, "netRole");
		if (!role || role->type != JSON_STRING) {
			wpa_printf(MSG_DEBUG, "DPP: Missing netRole string");
			goto fail;
		}
		wpa_printf(MSG_DEBUG,
			   "DPP: connector group: groupId='%s' netRole='%s'",
			   id->string, role->string);
		rules++;
	}
skip_groups:

	devices = json_get_member(root, "devices");
	if (!devices || devices->type != JSON_ARRAY) {
		wpa_printf(MSG_DEBUG, "DPP: No devices array found");
		goto skip_devices;
	}
	for (token = devices->child; token; token = token->sibling) {
		struct wpabuf *id;
		struct json_token *role;

		id = json_get_member_base64url(token, "deviceId");
		if (!id) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Missing or invalid deviceId string");
			goto fail;
		}
		wpa_hexdump_buf(MSG_DEBUG, "DPP: deviceId", id);
		if (wpabuf_len(id) != SHA256_MAC_LEN) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Unexpected deviceId length");
			wpabuf_free(id);
			goto fail;
		}
		wpabuf_free(id);

		role = json_get_member(token, "netRole");
		if (!role || role->type != JSON_STRING) {
			wpa_printf(MSG_DEBUG, "DPP: Missing netRole string");
			goto fail;
		}
		wpa_printf(MSG_DEBUG, "DPP: connector device netRole='%s'",
			   role->string);
		rules++;
	}

skip_devices:
	if (!rules) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Connector includes no groups or devices");
		goto fail;
	}

	token = json_get_member(root, "expiry");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No expiry string found - connector does not expire");
	} else {
		wpa_printf(MSG_DEBUG, "DPP: expiry = %s", token->string);
		if (dpp_key_expired(token->string,
				    &auth->net_access_key_expiry)) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Connector (netAccessKey) has expired");
			goto fail;
		}
	}

	netkey = json_get_member(root, "netAccessKey");
	if (!netkey || netkey->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG, "DPP: No netAccessKey object found");
		goto fail;
	}

	key = dpp_parse_jwk(netkey, &curve);
	if (!key)
		goto fail;
	dpp_debug_print_key("DPP: Received netAccessKey", key);

	if (EVP_PKEY_cmp(key, auth->own_protocol_key) != 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: netAccessKey in connector does not match own protocol key");
#ifdef CONFIG_TESTING_OPTIONS
		if (auth->ignore_netaccesskey_mismatch) {
			wpa_printf(MSG_DEBUG,
				   "DPP: TESTING - skip netAccessKey mismatch");
		} else {
			goto fail;
		}
#else /* CONFIG_TESTING_OPTIONS */
		goto fail;
#endif /* CONFIG_TESTING_OPTIONS */
	}

	ret = 0;
fail:
	EVP_PKEY_free(key);
	json_free(root);
	return ret;
}


static int dpp_check_pubkey_match(EVP_PKEY *pub, struct wpabuf *r_hash)
{
	struct wpabuf *uncomp;
	int res;
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[1];
	size_t len[1];

	if (wpabuf_len(r_hash) != SHA256_MAC_LEN)
		return -1;
	uncomp = dpp_get_pubkey_point(pub, 1);
	if (!uncomp)
		return -1;
	addr[0] = wpabuf_head(uncomp);
	len[0] = wpabuf_len(uncomp);
	wpa_hexdump(MSG_DEBUG, "DPP: Uncompressed public key",
		    addr[0], len[0]);
	res = sha256_vector(1, addr, len, hash);
	wpabuf_free(uncomp);
	if (res < 0)
		return -1;
	if (os_memcmp(hash, wpabuf_head(r_hash), SHA256_MAC_LEN) != 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Received hash value does not match calculated public key hash value");
		wpa_hexdump(MSG_DEBUG, "DPP: Calculated hash",
			    hash, SHA256_MAC_LEN);
		return -1;
	}
	return 0;
}


static void dpp_copy_csign(struct dpp_authentication *auth, EVP_PKEY *csign)
{
	unsigned char *der = NULL;
	int der_len;

	der_len = i2d_PUBKEY(csign, &der);
	if (der_len <= 0)
		return;
	wpabuf_free(auth->c_sign_key);
	auth->c_sign_key = wpabuf_alloc_copy(der, der_len);
	OPENSSL_free(der);
}


static void dpp_copy_netaccesskey(struct dpp_authentication *auth)
{
	unsigned char *der = NULL;
	int der_len;
	EC_KEY *eckey;

	eckey = EVP_PKEY_get1_EC_KEY(auth->own_protocol_key);
	if (!eckey)
		return;

	der_len = i2d_ECPrivateKey(eckey, &der);
	if (der_len <= 0) {
		EC_KEY_free(eckey);
		return;
	}
	wpabuf_free(auth->net_access_key);
	auth->net_access_key = wpabuf_alloc_copy(der, der_len);
	OPENSSL_free(der);
	EC_KEY_free(eckey);
}


struct dpp_signed_connector_info {
	unsigned char *payload;
	size_t payload_len;
};

static int
dpp_process_signed_connector(struct dpp_signed_connector_info *info,
			     EVP_PKEY *csign_pub, const char *connector)
{
	int ret = -1;
	const char *pos, *end, *signed_start, *signed_end;
	struct wpabuf *kid = NULL;
	unsigned char *prot_hdr = NULL, *signature = NULL;
	size_t prot_hdr_len = 0, signature_len = 0;
	const EVP_MD *sign_md = NULL;
	unsigned char *der = NULL;
	int der_len;
	int res;
	EVP_MD_CTX *md_ctx = NULL;
	ECDSA_SIG *sig = NULL;
	BIGNUM *r = NULL, *s = NULL;

	os_memset(info, 0, sizeof(*info));

	signed_start = pos = connector;
	end = os_strchr(pos, '.');
	if (!end) {
		wpa_printf(MSG_DEBUG, "DPP: Missing dot(1) in signedConnector");
		goto fail;
	}
	prot_hdr = base64_url_decode((const unsigned char *) pos,
				     end - pos, &prot_hdr_len);
	if (!prot_hdr) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to base64url decode signedConnector JWS Protected Header");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG,
			  "DPP: signedConnector - JWS Protected Header",
			  prot_hdr, prot_hdr_len);
	kid = dpp_parse_jws_prot_hdr(prot_hdr, prot_hdr_len, &sign_md);
	if (!kid)
		goto fail;
	if (wpabuf_len(kid) != SHA256_MAC_LEN) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unexpected signedConnector JWS Protected Header kid length: %u (expected %u)",
			   (unsigned int) wpabuf_len(kid), SHA256_MAC_LEN);
		goto fail;
	}

	pos = end + 1;
	end = os_strchr(pos, '.');
	if (!end) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing dot(2) in signedConnector");
		goto fail;
	}
	signed_end = end - 1;
	info->payload = base64_url_decode((const unsigned char *) pos,
					  end - pos, &info->payload_len);
	if (!info->payload) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to base64url decode signedConnector JWS Payload");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG,
			  "DPP: signedConnector - JWS Payload",
			  info->payload, info->payload_len);
	pos = end + 1;
	signature = base64_url_decode((const unsigned char *) pos,
				      os_strlen(pos), &signature_len);
	if (!signature) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to base64url decode signedConnector signature");
		goto fail;
		}
	wpa_hexdump(MSG_DEBUG, "DPP: signedConnector - signature",
		    signature, signature_len);

	if (dpp_check_pubkey_match(csign_pub, kid) < 0)
		goto fail;

	if (signature_len & 0x01) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unexpected signedConnector signature length (%d)",
			   (int) signature_len);
		goto fail;
	}

	/* JWS Signature encodes the signature (r,s) as two octet strings. Need
	 * to convert that to DER encoded ECDSA_SIG for OpenSSL EVP routines. */
	r = BN_bin2bn(signature, signature_len / 2, NULL);
	s = BN_bin2bn(signature + signature_len / 2, signature_len / 2, NULL);
	sig = ECDSA_SIG_new();
	if (!r || !s || !sig || ECDSA_SIG_set0(sig, r, s) != 1)
		goto fail;
	r = NULL;
	s = NULL;

	der_len = i2d_ECDSA_SIG(sig, &der);
	if (der_len <= 0) {
		wpa_printf(MSG_DEBUG, "DPP: Could not DER encode signature");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: DER encoded signature", der, der_len);
	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx)
		goto fail;

	ERR_clear_error();
	if (EVP_DigestVerifyInit(md_ctx, NULL, sign_md, NULL, csign_pub) != 1) {
		wpa_printf(MSG_DEBUG, "DPP: EVP_DigestVerifyInit failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	if (EVP_DigestVerifyUpdate(md_ctx, signed_start,
				   signed_end - signed_start + 1) != 1) {
		wpa_printf(MSG_DEBUG, "DPP: EVP_DigestVerifyUpdate failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	res = EVP_DigestVerifyFinal(md_ctx, der, der_len);
	if (res != 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: EVP_DigestVerifyFinal failed (res=%d): %s",
			   res, ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	ret = 0;
fail:
	EVP_MD_CTX_destroy(md_ctx);
	os_free(prot_hdr);
	wpabuf_free(kid);
	os_free(signature);
	ECDSA_SIG_free(sig);
	BN_free(r);
	BN_free(s);
	OPENSSL_free(der);
	return ret;
}


static int dpp_parse_cred_dpp(struct dpp_authentication *auth,
			      struct json_token *cred)
{
	struct dpp_signed_connector_info info;
	struct json_token *token, *csign;
	int ret = -1;
	EVP_PKEY *csign_pub = NULL;
	const struct dpp_curve_params *key_curve = NULL;
	const char *signed_connector;

	os_memset(&info, 0, sizeof(info));

	wpa_printf(MSG_DEBUG, "DPP: Connector credential");

	csign = json_get_member(cred, "csign");
	if (!csign || csign->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG, "DPP: No csign JWK in JSON");
		goto fail;
	}

	csign_pub = dpp_parse_jwk(csign, &key_curve);
	if (!csign_pub) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to parse csign JWK");
		goto fail;
	}
	dpp_debug_print_key("DPP: Received C-sign-key", csign_pub);

	token = json_get_member(cred, "expiry");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No expiry string found - C-sign-key does not expire");
	} else {
		wpa_printf(MSG_DEBUG, "DPP: expiry = %s", token->string);
		if (dpp_key_expired(token->string, &auth->c_sign_key_expiry)) {
			wpa_printf(MSG_DEBUG, "DPP: C-sign-key has expired");
			goto fail;
		}
	}

	token = json_get_member(cred, "signedConnector");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No signedConnector string found");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: signedConnector",
			  token->string, os_strlen(token->string));
	signed_connector = token->string;

	if (os_strchr(signed_connector, '"') ||
	    os_strchr(signed_connector, '\n')) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unexpected character in signedConnector");
		goto fail;
	}

	if (dpp_process_signed_connector(&info, csign_pub,
					 signed_connector) < 0)
		goto fail;

	if (dpp_parse_connector(auth, info.payload, info.payload_len) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to parse connector");
		goto fail;
	}

	os_free(auth->connector);
	auth->connector = os_strdup(signed_connector);

	dpp_copy_csign(auth, csign_pub);
	dpp_copy_netaccesskey(auth);

	ret = 0;
fail:
	EVP_PKEY_free(csign_pub);
	os_free(info.payload);
	return ret;
}


static int dpp_parse_conf_obj(struct dpp_authentication *auth,
			      const u8 *conf_obj, u16 conf_obj_len)
{
	int ret = -1;
	struct json_token *root, *token, *discovery, *cred;

	root = json_parse((const char *) conf_obj, conf_obj_len);
	if (!root)
		return -1;
	if (root->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG, "DPP: JSON root is not an object");
		goto fail;
	}

	token = json_get_member(root, "wi-fi_tech");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG, "DPP: No wi-fi_tech string value found");
		goto fail;
	}
	if (os_strcmp(token->string, "infra") != 0) {
		wpa_printf(MSG_DEBUG, "DPP: Unsupported wi-fi_tech value: '%s'",
			   token->string);
		goto fail;
	}

	discovery = json_get_member(root, "discovery");
	if (!discovery || discovery->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG, "DPP: No discovery object in JSON");
		goto fail;
	}

	token = json_get_member(discovery, "ssid");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No discovery::ssid string value found");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: discovery::ssid",
			  token->string, os_strlen(token->string));
	if (os_strlen(token->string) > SSID_MAX_LEN) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Too long discovery::ssid string value");
		goto fail;
	}
	auth->ssid_len = os_strlen(token->string);
	os_memcpy(auth->ssid, token->string, auth->ssid_len);

	cred = json_get_member(root, "cred");
	if (!cred || cred->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG, "DPP: No cred object in JSON");
		goto fail;
	}

	token = json_get_member(cred, "akm");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No cred::akm string value found");
		goto fail;
	}
	if (os_strcmp(token->string, "psk") == 0) {
		if (dpp_parse_cred_legacy(auth, cred) < 0)
			goto fail;
	} else if (os_strcmp(token->string, "dpp") == 0) {
		if (dpp_parse_cred_dpp(auth, cred) < 0)
			goto fail;
	} else {
		wpa_printf(MSG_DEBUG, "DPP: Unsupported akm: %s",
			   token->string);
		goto fail;
	}

	wpa_printf(MSG_DEBUG, "DPP: JSON parsing completed successfully");
	ret = 0;
fail:
	json_free(root);
	return ret;
}


int dpp_conf_resp_rx(struct dpp_authentication *auth,
		     const struct wpabuf *resp)
{
	const u8 *wrapped_data, *e_nonce, *status, *conf_obj;
	u16 wrapped_data_len, e_nonce_len, status_len, conf_obj_len;
	const u8 *addr[1];
	size_t len[1];
	u8 *unwrapped = NULL;
	size_t unwrapped_len = 0;
	int ret = -1;

	if (dpp_check_attrs(wpabuf_head(resp), wpabuf_len(resp)) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in config response");
		return -1;
	}

	wrapped_data = dpp_get_attr(wpabuf_head(resp), wpabuf_len(resp),
				    DPP_ATTR_WRAPPED_DATA,
				    &wrapped_data_len);
	if (!wrapped_data || wrapped_data_len < AES_BLOCK_SIZE) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required Wrapped data attribute");
		return -1;
	}

	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		return -1;

	addr[0] = wpabuf_head(resp);
	len[0] = wrapped_data - 4 - (const u8 *) wpabuf_head(resp);
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD", addr[0], len[0]);

	if (aes_siv_decrypt(auth->ke, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    1, addr, len, unwrapped) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Invalid attribute in unwrapped data");
		goto fail;
	}

	e_nonce = dpp_get_attr(unwrapped, unwrapped_len,
			       DPP_ATTR_ENROLLEE_NONCE,
			       &e_nonce_len);
	if (!e_nonce || e_nonce_len != auth->curve->nonce_len) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid Enrollee Nonce attribute");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: Enrollee Nonce", e_nonce, e_nonce_len);
	if (os_memcmp(e_nonce, auth->e_nonce, e_nonce_len) != 0) {
		wpa_printf(MSG_DEBUG, "Enrollee Nonce mismatch");
		goto fail;
	}

	status = dpp_get_attr(wpabuf_head(resp), wpabuf_len(resp),
			      DPP_ATTR_STATUS, &status_len);
	if (!status || status_len < 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required DPP Status attribute");
		goto fail;
	}
	wpa_printf(MSG_DEBUG, "DPP: Status %u", status[0]);
	if (status[0] != DPP_STATUS_OK) {
		wpa_printf(MSG_DEBUG, "DPP: Configuration failed");
		goto fail;
	}

	conf_obj = dpp_get_attr(unwrapped, unwrapped_len,
				DPP_ATTR_CONFIG_OBJ, &conf_obj_len);
	if (!conf_obj) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing required Configuration Object attribute");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: configurationObject JSON",
			  conf_obj, conf_obj_len);
	if (dpp_parse_conf_obj(auth, conf_obj, conf_obj_len) < 0)
		goto fail;

	ret = 0;

fail:
	os_free(unwrapped);
	return ret;
}


void dpp_configurator_free(struct dpp_configurator *conf)
{
	if (!conf)
		return;
	EVP_PKEY_free(conf->csign);
	os_free(conf->kid);
	os_free(conf);
}


struct dpp_configurator *
dpp_keygen_configurator(const char *curve, const u8 *privkey,
			size_t privkey_len)
{
	struct dpp_configurator *conf;
	struct wpabuf *csign_pub = NULL;
	u8 kid_hash[SHA256_MAC_LEN];
	const u8 *addr[1];
	size_t len[1];

	conf = os_zalloc(sizeof(*conf));
	if (!conf)
		return NULL;

	if (!curve) {
		conf->curve = &dpp_curves[0];
	} else {
		conf->curve = dpp_get_curve_name(curve);
		if (!conf->curve) {
			wpa_printf(MSG_INFO, "DPP: Unsupported curve: %s",
				   curve);
			return NULL;
		}
	}
	if (privkey)
		conf->csign = dpp_set_keypair(&conf->curve, privkey,
					      privkey_len);
	else
		conf->csign = dpp_gen_keypair(conf->curve);
	if (!conf->csign)
		goto fail;
	conf->own = 1;

	csign_pub = dpp_get_pubkey_point(conf->csign, 1);
	if (!csign_pub) {
		wpa_printf(MSG_INFO, "DPP: Failed to extract C-sign-key");
		goto fail;
	}

	/* kid = SHA256(ANSI X9.63 uncompressed C-sign-key) */
	addr[0] = wpabuf_head(csign_pub);
	len[0] = wpabuf_len(csign_pub);
	if (sha256_vector(1, addr, len, kid_hash) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to derive kid for C-sign-key");
		goto fail;
	}

	conf->kid = (char *) base64_url_encode(kid_hash, sizeof(kid_hash),
					       NULL, 0);
	if (!conf->kid)
		goto fail;
out:
	wpabuf_free(csign_pub);
	return conf;
fail:
	dpp_configurator_free(conf);
	conf = NULL;
	goto out;
}


static int dpp_compatible_netrole(const char *role1, const char *role2)
{
	return (os_strcmp(role1, "sta") == 0 && os_strcmp(role2, "ap") == 0) ||
		(os_strcmp(role1, "ap") == 0 && os_strcmp(role2, "sta") == 0);
}


static int dpp_connector_compatible_group(struct json_token *root,
					  const char *group_id,
					  const char *net_role)
{
	struct json_token *groups, *token;

	groups = json_get_member(root, "groups");
	if (!groups || groups->type != JSON_ARRAY)
		return 0;

	for (token = groups->child; token; token = token->sibling) {
		struct json_token *id, *role;

		id = json_get_member(token, "groupId");
		if (!id || id->type != JSON_STRING)
			continue;

		role = json_get_member(token, "netRole");
		if (!role || role->type != JSON_STRING)
			continue;

		if (os_strcmp(id->string, "*") != 0 &&
		    os_strcmp(group_id, "*") != 0 &&
		    os_strcmp(id->string, group_id) != 0)
			continue;

		if (dpp_compatible_netrole(role->string, net_role))
			return 1;
	}

	return 0;
}


static int dpp_connector_match_groups(struct json_token *own_root,
				      struct json_token *peer_root)
{
	struct json_token *groups, *token;

	groups = json_get_member(peer_root, "groups");
	if (!groups || groups->type != JSON_ARRAY) {
		wpa_printf(MSG_DEBUG, "DPP: No peer groups array found");
		return 0;
	}

	for (token = groups->child; token; token = token->sibling) {
		struct json_token *id, *role;

		id = json_get_member(token, "groupId");
		if (!id || id->type != JSON_STRING) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Missing peer groupId string");
			continue;
		}

		role = json_get_member(token, "netRole");
		if (!role || role->type != JSON_STRING) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Missing peer groups::netRole string");
			continue;
		}
		wpa_printf(MSG_DEBUG,
			   "DPP: peer connector group: groupId='%s' netRole='%s'",
			   id->string, role->string);
		if (dpp_connector_compatible_group(own_root, id->string,
						   role->string)) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Compatible group/netRole in own connector");
			return 1;
		}
	}

	return 0;
}


static int dpp_connector_compatible_device(struct json_token *root,
					   const char *device_id,
					   const char *net_role)
{
	struct json_token *groups, *token;

	groups = json_get_member(root, "devices");
	if (!groups || groups->type != JSON_ARRAY)
		return 0;

	for (token = groups->child; token; token = token->sibling) {
		struct json_token *id, *role;

		id = json_get_member(token, "deviceId");
		if (!id || id->type != JSON_STRING)
			continue;

		role = json_get_member(token, "netRole");
		if (!role || role->type != JSON_STRING)
			continue;

		if (os_strcmp(id->string, device_id) != 0)
			continue;

		if (dpp_compatible_netrole(role->string, net_role))
			return 1;
	}

	return 0;
}


static int dpp_connector_match_devices(struct json_token *own_root,
				       struct json_token *peer_root,
				       const char *own_deviceid)
{
	struct json_token *devices, *token;

	devices = json_get_member(peer_root, "devices");
	if (!devices || devices->type != JSON_ARRAY) {
		wpa_printf(MSG_DEBUG, "DPP: No peer devices array found");
		return 0;
	}

	for (token = devices->child; token; token = token->sibling) {
		struct json_token *id, *role;

		id = json_get_member(token, "deviceId");
		if (!id || id->type != JSON_STRING) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Missing or invalid deviceId string");
			continue;
		}

		role = json_get_member(token, "netRole");
		if (!role || role->type != JSON_STRING) {
			wpa_printf(MSG_DEBUG, "DPP: Missing netRole string");
			continue;
		}
		wpa_printf(MSG_DEBUG,
			   "DPP: connector device deviceId='%s' netRole='%s'",
			   id->string, role->string);
		if (os_strcmp(id->string, own_deviceid) != 0)
			continue;

		wpa_printf(MSG_DEBUG,
			   "DPP: Listed deviceId matches own deviceId");
		/* TODO: Is this next step required? */
		if (dpp_connector_compatible_device(own_root, id->string,
						    role->string)) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Compatible device/netRole in own connector");
			return 1;
		}
		/* TODO: For now, accept this for interop testing purposes based
		 * on a simple match of deviceId while ignoring netRole. Once
		 * the spec is clearer on the expected behavior, either this
		 * comment or the following return 1 statement needs to be
		 * removed.
		 */
		return 1;
	}

	return 0;
}


static int dpp_connector_match(struct json_token *own_root,
			       struct json_token *peer_root,
			       const char *own_deviceid)
{
	return dpp_connector_match_groups(own_root, peer_root) ||
		dpp_connector_match_devices(own_root, peer_root, own_deviceid);
}


static int dpp_derive_pmk(const u8 *Nx, size_t Nx_len, u8 *pmk,
			  unsigned int hash_len)
{
	u8 salt[DPP_MAX_HASH_LEN], prk[DPP_MAX_HASH_LEN];
	const char *info = "DPP PMK";
	int res = -1;

	/* PMK = HKDF(<>, "DPP PMK", N.x) */

	/* HKDF-Extract(<>, N.x) */
	os_memset(salt, 0, hash_len);
	if (hash_len == 32) {
		if (hmac_sha256(salt, SHA256_MAC_LEN, Nx, Nx_len, prk) < 0)
			return -1;
	} else if (hash_len == 48) {
		if (hmac_sha384(salt, SHA384_MAC_LEN, Nx, Nx_len, prk) < 0)
			return -1;
	} else if (hash_len == 64) {
		if (hmac_sha512(salt, SHA512_MAC_LEN, Nx, Nx_len, prk) < 0)
			return -1;
	} else {
		return -1;
	}
	wpa_hexdump_key(MSG_DEBUG, "DPP: PRK = HKDF-Extract(<>, IKM=N.x)",
			prk, hash_len);

	/* HKDF-Expand(PRK, info, L) */
	if (hash_len == 32)
		res = hmac_sha256_kdf(prk, SHA256_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      pmk, SHA256_MAC_LEN);
	else if (hash_len == 48)
		res = hmac_sha384_kdf(prk, SHA384_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      pmk, SHA384_MAC_LEN);
	else if (hash_len == 64)
		res = hmac_sha512_kdf(prk, SHA512_MAC_LEN, NULL,
				      (const u8 *) info, os_strlen(info),
				      pmk, SHA512_MAC_LEN);
	os_memset(prk, 0, hash_len);
	if (res < 0)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "DPP: PMK = HKDF-Expand(PRK, info, L)",
			pmk, hash_len);
	return 0;
}


static int dpp_derive_pmkid(const struct dpp_curve_params *curve,
			    EVP_PKEY *own_key, EVP_PKEY *peer_key, u8 *pmkid)
{
	struct wpabuf *nkx, *pkx;
	int ret = -1, res;
	const u8 *addr[2];
	size_t len[2];
	u8 hash[DPP_MAX_HASH_LEN];

	/* PMKID = Truncate-128(H(min(NK.x, PK.x) | max(NK.x, PK.x))) */
	nkx = dpp_get_pubkey_point(own_key, 0);
	pkx = dpp_get_pubkey_point(peer_key, 0);
	if (!nkx || !pkx)
		goto fail;
	addr[0] = wpabuf_head(nkx);
	len[0] = wpabuf_len(nkx) / 2;
	addr[1] = wpabuf_head(pkx);
	len[1] = wpabuf_len(pkx) / 2;
	if (len[0] != len[1])
		goto fail;
	if (os_memcmp(addr[0], addr[1], len[0]) > 0) {
		addr[0] = wpabuf_head(pkx);
		addr[1] = wpabuf_head(nkx);
	}
	wpa_printf(MSG_DEBUG, "DPP: PMKID H=SHA%u",
		   (unsigned int) curve->hash_len * 8);
	wpa_hexdump(MSG_DEBUG, "DPP: PMKID hash payload 1", addr[0], len[0]);
	wpa_hexdump(MSG_DEBUG, "DPP: PMKID hash payload 2", addr[1], len[1]);
	if (curve->hash_len == 32)
		res = sha256_vector(2, addr, len, hash);
	else if (curve->hash_len == 48)
		res = sha384_vector(2, addr, len, hash);
	else if (curve->hash_len == 64)
		res = sha512_vector(2, addr, len, hash);
	else
		res = -1;
	if (res < 0)
		goto fail;
	wpa_hexdump(MSG_DEBUG, "DPP: PMKID hash output",
		    hash, curve->hash_len);
	os_memcpy(pmkid, hash, PMKID_LEN);
	wpa_hexdump(MSG_DEBUG, "DPP: PMKID", pmkid, PMKID_LEN);
	ret = 0;
fail:
	wpabuf_free(nkx);
	wpabuf_free(pkx);
	return ret;
}


static int dpp_netkey_hash(EVP_PKEY *key, u8 *hash)
{
	EC_KEY *eckey;
	unsigned char *der = NULL;
	int ret, der_len;
	const u8 *addr[1];
	size_t len[1];

	eckey = EVP_PKEY_get1_EC_KEY(key);
	if (!eckey)
		return -1;
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);
	der_len = i2d_EC_PUBKEY(eckey, &der);
	EC_KEY_free(eckey);
	if (der_len <= 0)
		return -1;
	addr[0] = der;
	len[0] = der_len;
	ret = sha256_vector(1, addr, len, hash);
	OPENSSL_free(der);
	return ret;
}


int dpp_peer_intro(struct dpp_introduction *intro, const char *own_connector,
		   const u8 *net_access_key, size_t net_access_key_len,
		   const u8 *csign_key, size_t csign_key_len,
		   const u8 *peer_connector, size_t peer_connector_len)
{
	struct json_token *root = NULL, *netkey, *token;
	struct json_token *own_root = NULL;
	int ret = -1;
	EVP_PKEY *own_key = NULL, *peer_key = NULL;
	struct wpabuf *own_key_pub = NULL;
	char *own_deviceid = NULL;
	const struct dpp_curve_params *curve, *own_curve;
	struct dpp_signed_connector_info info;
	const unsigned char *p;
	EVP_PKEY *csign = NULL;
	char *signed_connector = NULL;
	const char *pos, *end;
	unsigned char *own_conn = NULL;
	size_t own_conn_len;
	EVP_PKEY_CTX *ctx = NULL;
	size_t Nx_len;
	u8 Nx[DPP_MAX_SHARED_SECRET_LEN];
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[1];
	size_t len[1];

	os_memset(intro, 0, sizeof(*intro));
	os_memset(&info, 0, sizeof(info));

	p = csign_key;
	csign = d2i_PUBKEY(NULL, &p, csign_key_len);
	if (!csign) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to parse local C-sign-key information");
		goto fail;
	}

	own_key = dpp_set_keypair(&own_curve, net_access_key,
				  net_access_key_len);
	if (!own_key) {
		wpa_printf(MSG_ERROR, "DPP: Failed to parse own netAccessKey");
		goto fail;
	}
	/* deviceId = SHA256(ANSI X9.63 uncompressed netAccessKey) */
	own_key_pub = dpp_get_pubkey_point(own_key, 1);
	if (!own_key_pub)
		goto fail;
	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: ANSI X9.63 uncompressed public key of own netAccessKey",
			own_key_pub);
	addr[0] = wpabuf_head(own_key_pub);
	len[0] = wpabuf_len(own_key_pub);
	if (sha256_vector(1, addr, len, hash) < 0)
		goto fail;
	wpa_hexdump(MSG_DEBUG,
		    "DPP: SHA256 hash of ANSI X9.63 uncompressed form",
		    hash, SHA256_MAC_LEN);

	own_deviceid = (char *) base64_url_encode(hash, sizeof(hash), NULL, 0);
	if (!own_deviceid)
		goto fail;
	wpa_printf(MSG_DEBUG,
		   "DPP: Own deviceId (base64url encoded hash value): %s",
		   own_deviceid);

	pos = os_strchr(own_connector, '.');
	if (!pos) {
		wpa_printf(MSG_DEBUG, "DPP: Own connector is missing the first dot (.)");
		goto fail;
	}
	pos++;
	end = os_strchr(pos, '.');
	if (!end) {
		wpa_printf(MSG_DEBUG, "DPP: Own connector is missing the second dot (.)");
		goto fail;
	}
	own_conn = base64_url_decode((const unsigned char *) pos,
				     end - pos, &own_conn_len);
	if (!own_conn) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to base64url decode own signedConnector JWS Payload");
		goto fail;
	}

	own_root = json_parse((const char *) own_conn, own_conn_len);
	if (!own_root) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to parse local connector");
		goto fail;
	}

	wpa_hexdump_ascii(MSG_DEBUG, "DPP: Peer signedConnector",
			  peer_connector, peer_connector_len);
	signed_connector = os_malloc(peer_connector_len + 1);
	if (!signed_connector)
		goto fail;
	os_memcpy(signed_connector, peer_connector, peer_connector_len);
	signed_connector[peer_connector_len] = '\0';

	if (dpp_process_signed_connector(&info, csign, signed_connector) < 0)
		goto fail;

	root = json_parse((const char *) info.payload, info.payload_len);
	if (!root) {
		wpa_printf(MSG_DEBUG, "DPP: JSON parsing of connector failed");
		goto fail;
	}

	if (!dpp_connector_match(own_root, root, own_deviceid)) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Peer connector does not include compatible group/device netrole with own connector");
		goto fail;
	}

	token = json_get_member(root, "expiry");
	if (!token || token->type != JSON_STRING) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No expiry string found - connector does not expire");
	} else {
		wpa_printf(MSG_DEBUG, "DPP: expiry = %s", token->string);
		if (dpp_key_expired(token->string, NULL)) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Connector (netAccessKey) has expired");
			goto fail;
		}
	}

	netkey = json_get_member(root, "netAccessKey");
	if (!netkey || netkey->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG, "DPP: No netAccessKey object found");
		goto fail;
	}

	peer_key = dpp_parse_jwk(netkey, &curve);
	if (!peer_key)
		goto fail;
	dpp_debug_print_key("DPP: Received netAccessKey", peer_key);

	if (own_curve != curve) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Mismatching netAccessKey curves (%s != %s)",
			   own_curve->name, curve->name);
		goto fail;
	}

	/* ECDH: N = nk * PK */
	ctx = EVP_PKEY_CTX_new(own_key, NULL);
	if (!ctx ||
	    EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, peer_key) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &Nx_len) != 1 ||
	    Nx_len > DPP_MAX_SHARED_SECRET_LEN ||
	    EVP_PKEY_derive(ctx, Nx, &Nx_len) != 1) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to derive ECDH shared secret: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	wpa_hexdump_key(MSG_DEBUG, "DPP: ECDH shared secret (N.x)",
			Nx, Nx_len);

	/* PMK = HKDF(<>, "DPP PMK", N.x) */
	if (dpp_derive_pmk(Nx, Nx_len, intro->pmk, curve->hash_len) < 0) {
		wpa_printf(MSG_ERROR, "DPP: Failed to derive PMK");
		goto fail;
	}
	intro->pmk_len = curve->hash_len;

	/* PMKID = Truncate-128(H(min(NK.x, PK.x) | max(NK.x, PK.x))) */
	if (dpp_derive_pmkid(curve, own_key, peer_key, intro->pmkid) < 0) {
		wpa_printf(MSG_ERROR, "DPP: Failed to derive PMKID");
		goto fail;
	}

	if (dpp_netkey_hash(own_key, intro->nk_hash) < 0 ||
	    dpp_netkey_hash(peer_key, intro->pk_hash) < 0) {
		wpa_printf(MSG_ERROR, "DPP: Failed to derive NK/PK hash");
		goto fail;
	}

	ret = 0;
fail:
	if (ret < 0)
		os_memset(intro, 0, sizeof(*intro));
	os_memset(Nx, 0, sizeof(Nx));
	EVP_PKEY_CTX_free(ctx);
	os_free(own_conn);
	os_free(signed_connector);
	os_free(info.payload);
	EVP_PKEY_free(own_key);
	wpabuf_free(own_key_pub);
	os_free(own_deviceid);
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(csign);
	json_free(root);
	json_free(own_root);
	return ret;
}
