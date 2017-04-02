/*
 * hostapd - IEEE 802.11r - Fast BSS Transition
 * Copyright (c) 2004-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/list.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "crypto/aes.h"
#include "crypto/aes_siv.h"
#include "crypto/aes_wrap.h"
#include "crypto/random.h"
#include "ap_config.h"
#include "ieee802_11.h"
#include "wmm.h"
#include "wpa_auth.h"
#include "wpa_auth_i.h"


#ifdef CONFIG_IEEE80211R_AP

static int wpa_ft_send_rrb_auth_resp(struct wpa_state_machine *sm,
				     const u8 *current_ap, const u8 *sta_addr,
				     u16 status, const u8 *resp_ies,
				     size_t resp_ies_len);

struct tlv_list {
	u16 type;
	size_t len;
	const u8 *data;
};


/**
 * wpa_ft_rrb_decrypt - Decrypt FT RRB message
 * @key: AES-SIV key for AEAD
 * @key_len: Length of key in octets
 * @enc: Pointer to encrypted TLVs
 * @enc_len: Length of encrypted TLVs in octets
 * @auth: Pointer to authenticated TLVs
 * @auth_len: Length of authenticated TLVs in octets
 * @src_addr: MAC address of the frame sender
 * @type: Vendor-specific subtype of the RRB frame (FT_PACKET_*)
 * @plain: Pointer to return the pointer to the allocated plaintext buffer;
 *	needs to be freed by the caller if not NULL;
 *	will only be returned on success
 * @plain_len: Pointer to return the length of the allocated plaintext buffer
 *	in octets
 * Returns: 0 on success, -1 on error
 */
static int wpa_ft_rrb_decrypt(const u8 *key, const size_t key_len,
			      const u8 *enc, const size_t enc_len,
			      const u8 *auth, const size_t auth_len,
			      const u8 *src_addr, u8 type,
			      u8 **plain, size_t *plain_size)
{
	const u8 *ad[3] = { src_addr, auth, &type };
	size_t ad_len[3] = { ETH_ALEN, auth_len, sizeof(type) };

	wpa_hexdump_key(MSG_DEBUG, "FT(RRB): decrypt using key", key, key_len);

	if (!key) { /* skip decryption */
		*plain = os_memdup(enc, enc_len);
		if (enc_len > 0 && !*plain)
			goto err;

		*plain_size = enc_len;

		return 0;
	}

	*plain = NULL;

	/* SIV overhead */
	if (enc_len < AES_BLOCK_SIZE)
		goto err;

	*plain = os_zalloc(enc_len - AES_BLOCK_SIZE);
	if (!*plain)
		goto err;

	if (aes_siv_decrypt(key, key_len, enc, enc_len, 3, ad, ad_len,
			    *plain) < 0)
		goto err;

	*plain_size = enc_len - AES_BLOCK_SIZE;
	wpa_hexdump_key(MSG_DEBUG, "FT(RRB): decrypted TLVs",
			*plain, *plain_size);
	return 0;
err:
	os_free(*plain);
	*plain = NULL;
	*plain_size = 0;

	wpa_printf(MSG_ERROR, "FT(RRB): Failed to decrypt");

	return -1;
}


/* get first tlv record in packet matching type
 * @data (decrypted) packet
 * @return 0 on success else -1
 */
static int wpa_ft_rrb_get_tlv(const u8 *plain, size_t plain_len,
			      u16 type, size_t *tlv_len, const u8 **tlv_data)
{
	const struct ft_rrb_tlv *f;
	size_t left;
	le16 type16;
	size_t len;

	left = plain_len;
	type16 = host_to_le16(type);

	while (left >= sizeof(*f)) {
		f = (const struct ft_rrb_tlv *) plain;

		left -= sizeof(*f);
		plain += sizeof(*f);
		len = le_to_host16(f->len);

		if (left < len) {
			wpa_printf(MSG_DEBUG, "FT: RRB message truncated");
			break;
		}

		if (f->type == type16) {
			*tlv_len = len;
			*tlv_data = plain;
			return 0;
		}

		left -= len;
		plain += len;
	}

	return -1;
}


static void wpa_ft_rrb_dump(const u8 *plain, const size_t plain_len)
{
	const struct ft_rrb_tlv *f;
	size_t left;
	size_t len;

	left = plain_len;

	wpa_printf(MSG_DEBUG, "FT: RRB dump message");
	while (left >= sizeof(*f)) {
		f = (const struct ft_rrb_tlv *) plain;

		left -= sizeof(*f);
		plain += sizeof(*f);
		len = le_to_host16(f->len);

		wpa_printf(MSG_DEBUG, "FT: RRB TLV type = %d, len = %zu",
			   le_to_host16(f->type), len);

		if (left < len) {
			wpa_printf(MSG_DEBUG,
				   "FT: RRB message truncated: left %zu bytes, need %zu",
				   left, len);
			break;
		}

		wpa_hexdump(MSG_DEBUG, "FT: RRB TLV data", plain, len);

		left -= len;
		plain += len;
	}

	if (left > 0)
		wpa_hexdump(MSG_DEBUG, "FT: RRB TLV padding", plain, left);

	wpa_printf(MSG_DEBUG, "FT: RRB dump message end");
}


static size_t wpa_ft_tlv_len(const struct tlv_list *tlvs)
{
	size_t tlv_len = 0;
	int i;

	if (!tlvs)
		return 0;

	for (i = 0; tlvs[i].type != FT_RRB_LAST_EMPTY; i++) {
		tlv_len += sizeof(struct ft_rrb_tlv);
		tlv_len += tlvs[i].len;
	}

	return tlv_len;
}


static size_t wpa_ft_tlv_lin(const struct tlv_list *tlvs, u8 *start,
			     u8 *endpos)
{
	int i;
	size_t tlv_len;
	struct ft_rrb_tlv *hdr;
	u8 *pos;

	if (!tlvs)
		return 0;

	tlv_len = 0;
	pos = start;
	for (i = 0; tlvs[i].type != FT_RRB_LAST_EMPTY; i++) {
		if (tlv_len + sizeof(*hdr) > (size_t) (endpos - start))
			return tlv_len;
		tlv_len += sizeof(*hdr);
		hdr = (struct ft_rrb_tlv *) pos;
		hdr->type = host_to_le16(tlvs[i].type);
		hdr->len = host_to_le16(tlvs[i].len);
		pos = start + tlv_len;

		if (tlv_len + tlvs[i].len > (size_t) (endpos - start))
			return tlv_len;
		tlv_len += tlvs[i].len;
		os_memcpy(pos, tlvs[i].data, tlvs[i].len);
		pos = start + tlv_len;
	}

	return tlv_len;
}


static int wpa_ft_rrb_lin(const struct tlv_list *tlvs1,
			  const struct tlv_list *tlvs2,
			  u8 **plain, size_t *plain_len)
{
	u8 *pos, *endpos;
	size_t tlv_len;

	tlv_len = wpa_ft_tlv_len(tlvs1);
	tlv_len += wpa_ft_tlv_len(tlvs2);

	*plain_len = tlv_len;
	*plain = os_zalloc(tlv_len);
	if (!*plain) {
		wpa_printf(MSG_ERROR, "FT: Failed to allocate plaintext");
		goto err;
	}

	pos = *plain;
	endpos = *plain + tlv_len;
	pos += wpa_ft_tlv_lin(tlvs1, pos, endpos);
	pos += wpa_ft_tlv_lin(tlvs2, pos, endpos);

	/* sanity check */
	if (pos != endpos) {
		wpa_printf(MSG_ERROR, "FT: Length error building RRB");
		goto err;
	}

	return 0;

err:
	os_free(*plain);
	*plain = NULL;
	*plain_len = 0;
	return -1;
}


static int wpa_ft_rrb_encrypt(const u8 *key, const size_t key_len,
			      const u8 *plain, const size_t plain_len,
			      const u8 *auth, const size_t auth_len,
			      const u8 *src_addr, u8 type, u8 *enc)
{
	const u8 *ad[3] = { src_addr, auth, &type };
	size_t ad_len[3] = { ETH_ALEN, auth_len, sizeof(type) };

	wpa_hexdump_key(MSG_DEBUG, "FT(RRB): plaintext message",
			plain, plain_len);
	wpa_hexdump_key(MSG_DEBUG, "FT(RRB): encrypt using key", key, key_len);

	if (!key) {
		/* encryption not needed, return plaintext as packet */
		os_memcpy(enc, plain, plain_len);
	} else if (aes_siv_encrypt(key, key_len, plain, plain_len,
				   3, ad, ad_len, enc) < 0) {
		wpa_printf(MSG_ERROR, "FT: Failed to encrypt RRB-OUI message");
		return -1;
	}

	return 0;
}


/**
 * wpa_ft_rrb_build - Build and encrypt an FT RRB message
 * @key: AES-SIV key for AEAD
 * @key_len: Length of key in octets
 * @tlvs_enc0: First set of to-be-encrypted TLVs
 * @tlvs_enc1: Second set of to-be-encrypted TLVs
 * @tlvs_auth: Set of to-be-authenticated TLVs
 * @src_addr: MAC address of the frame sender
 * @type: Vendor-specific subtype of the RRB frame (FT_PACKET_*)
 * @packet Pointer to return the pointer to the allocated packet buffer;
 *         needs to be freed by the caller if not null;
 *         will only be returned on success
 * @packet_len: Pointer to return the length of the allocated buffer in octets
 * Returns: 0 on success, -1 on error
 */
static int wpa_ft_rrb_build(const u8 *key, const size_t key_len,
			    const struct tlv_list *tlvs_enc0,
			    const struct tlv_list *tlvs_enc1,
			    const struct tlv_list *tlvs_auth,
			    const u8 *src_addr, u8 type,
			    u8 **packet, size_t *packet_len)
{
	u8 *plain = NULL, *auth = NULL, *pos;
	size_t plain_len = 0, auth_len = 0;
	int ret = -1;

	if (wpa_ft_rrb_lin(tlvs_enc0, tlvs_enc1, &plain, &plain_len) < 0)
		goto out;

	if (wpa_ft_rrb_lin(tlvs_auth, NULL, &auth, &auth_len) < 0)
		goto out;

	*packet_len = sizeof(u16) + auth_len + plain_len;
	if (key)
		*packet_len += AES_BLOCK_SIZE;
	*packet = os_zalloc(*packet_len);
	if (!*packet)
		goto out;

	pos = *packet;
	WPA_PUT_LE16(pos, auth_len);
	pos += 2;
	os_memcpy(pos, auth, auth_len);
	pos += auth_len;
	if (wpa_ft_rrb_encrypt(key, key_len, plain, plain_len, auth,
			       auth_len, src_addr, type, pos) < 0)
		goto out;

	ret = 0;

out:
	bin_clear_free(plain, plain_len);
	os_free(auth);

	if (ret) {
		wpa_printf(MSG_ERROR, "FT: Failed to build RRB-OUI message");
		os_free(*packet);
		*packet = NULL;
		*packet_len = 0;
	}

	return ret;
}


#define RRB_GET_SRC(srcfield, type, field, txt, checklength) do { \
	if (wpa_ft_rrb_get_tlv(srcfield, srcfield##_len, type, \
				&f_##field##_len, &f_##field) < 0 || \
	    (checklength > 0 && ((size_t) checklength) != f_##field##_len)) { \
		wpa_printf(MSG_INFO, "FT: Missing required " #field \
			   " in %s from " MACSTR, txt, MAC2STR(src_addr)); \
		wpa_ft_rrb_dump(srcfield, srcfield##_len); \
		goto out; \
	} \
} while (0)

#define RRB_GET(type, field, txt, checklength) \
	RRB_GET_SRC(plain, type, field, txt, checklength)
#define RRB_GET_AUTH(type, field, txt, checklength) \
	RRB_GET_SRC(auth, type, field, txt, checklength)

#define RRB_GET_OPTIONAL_SRC(srcfield, type, field, txt, checklength) do { \
	if (wpa_ft_rrb_get_tlv(srcfield, srcfield##_len, type, \
				&f_##field##_len, &f_##field) < 0 || \
	    (checklength > 0 && ((size_t) checklength) != f_##field##_len)) { \
		wpa_printf(MSG_DEBUG, "FT: Missing optional " #field \
			   " in %s from " MACSTR, txt, MAC2STR(src_addr)); \
		f_##field##_len = 0; \
		f_##field = NULL; \
	} \
} while (0)

#define RRB_GET_OPTIONAL(type, field, txt, checklength) \
	RRB_GET_OPTIONAL_SRC(plain, type, field, txt, checklength)
#define RRB_GET_OPTIONAL_AUTH(type, field, txt, checklength) \
	RRB_GET_OPTIONAL_SRC(auth, type, field, txt, checklength)

static int wpa_ft_rrb_send(struct wpa_authenticator *wpa_auth, const u8 *dst,
			   const u8 *data, size_t data_len)
{
	if (wpa_auth->cb->send_ether == NULL)
		return -1;
	wpa_printf(MSG_DEBUG, "FT: RRB send to " MACSTR, MAC2STR(dst));
	return wpa_auth->cb->send_ether(wpa_auth->cb_ctx, dst, ETH_P_RRB,
					data, data_len);
}


static int wpa_ft_rrb_oui_send(struct wpa_authenticator *wpa_auth,
			       const u8 *dst, u8 oui_suffix,
			       const u8 *data, size_t data_len)
{
	if (!wpa_auth->cb->send_oui)
		return -1;
	wpa_printf(MSG_DEBUG, "FT: RRB-OUI type %u send to " MACSTR,
		   oui_suffix, MAC2STR(dst));
	return wpa_auth->cb->send_oui(wpa_auth->cb_ctx, dst, oui_suffix, data,
				      data_len);
}


static int wpa_ft_action_send(struct wpa_authenticator *wpa_auth,
			      const u8 *dst, const u8 *data, size_t data_len)
{
	if (wpa_auth->cb->send_ft_action == NULL)
		return -1;
	return wpa_auth->cb->send_ft_action(wpa_auth->cb_ctx, dst,
					    data, data_len);
}


static const u8 * wpa_ft_get_psk(struct wpa_authenticator *wpa_auth,
				 const u8 *addr, const u8 *p2p_dev_addr,
				 const u8 *prev_psk)
{
	if (wpa_auth->cb->get_psk == NULL)
		return NULL;
	return wpa_auth->cb->get_psk(wpa_auth->cb_ctx, addr, p2p_dev_addr,
				     prev_psk);
}


static struct wpa_state_machine *
wpa_ft_add_sta(struct wpa_authenticator *wpa_auth, const u8 *sta_addr)
{
	if (wpa_auth->cb->add_sta == NULL)
		return NULL;
	return wpa_auth->cb->add_sta(wpa_auth->cb_ctx, sta_addr);
}


static int wpa_ft_add_tspec(struct wpa_authenticator *wpa_auth,
			    const u8 *sta_addr,
			    u8 *tspec_ie, size_t tspec_ielen)
{
	if (wpa_auth->cb->add_tspec == NULL) {
		wpa_printf(MSG_DEBUG, "FT: add_tspec is not initialized");
		return -1;
	}
	return wpa_auth->cb->add_tspec(wpa_auth->cb_ctx, sta_addr, tspec_ie,
				       tspec_ielen);
}


int wpa_write_mdie(struct wpa_auth_config *conf, u8 *buf, size_t len)
{
	u8 *pos = buf;
	u8 capab;
	if (len < 2 + sizeof(struct rsn_mdie))
		return -1;

	*pos++ = WLAN_EID_MOBILITY_DOMAIN;
	*pos++ = MOBILITY_DOMAIN_ID_LEN + 1;
	os_memcpy(pos, conf->mobility_domain, MOBILITY_DOMAIN_ID_LEN);
	pos += MOBILITY_DOMAIN_ID_LEN;
	capab = 0;
	if (conf->ft_over_ds)
		capab |= RSN_FT_CAPAB_FT_OVER_DS;
	*pos++ = capab;

	return pos - buf;
}


int wpa_write_ftie(struct wpa_auth_config *conf, const u8 *r0kh_id,
		   size_t r0kh_id_len,
		   const u8 *anonce, const u8 *snonce,
		   u8 *buf, size_t len, const u8 *subelem,
		   size_t subelem_len)
{
	u8 *pos = buf, *ielen;
	struct rsn_ftie *hdr;

	if (len < 2 + sizeof(*hdr) + 2 + FT_R1KH_ID_LEN + 2 + r0kh_id_len +
	    subelem_len)
		return -1;

	*pos++ = WLAN_EID_FAST_BSS_TRANSITION;
	ielen = pos++;

	hdr = (struct rsn_ftie *) pos;
	os_memset(hdr, 0, sizeof(*hdr));
	pos += sizeof(*hdr);
	WPA_PUT_LE16(hdr->mic_control, 0);
	if (anonce)
		os_memcpy(hdr->anonce, anonce, WPA_NONCE_LEN);
	if (snonce)
		os_memcpy(hdr->snonce, snonce, WPA_NONCE_LEN);

	/* Optional Parameters */
	*pos++ = FTIE_SUBELEM_R1KH_ID;
	*pos++ = FT_R1KH_ID_LEN;
	os_memcpy(pos, conf->r1_key_holder, FT_R1KH_ID_LEN);
	pos += FT_R1KH_ID_LEN;

	if (r0kh_id) {
		*pos++ = FTIE_SUBELEM_R0KH_ID;
		*pos++ = r0kh_id_len;
		os_memcpy(pos, r0kh_id, r0kh_id_len);
		pos += r0kh_id_len;
	}

	if (subelem) {
		os_memcpy(pos, subelem, subelem_len);
		pos += subelem_len;
	}

	*ielen = pos - buf - 2;

	return pos - buf;
}


struct wpa_ft_pmk_r0_sa {
	struct wpa_ft_pmk_r0_sa *next;
	u8 pmk_r0[PMK_LEN];
	u8 pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 spa[ETH_ALEN];
	int pairwise; /* Pairwise cipher suite, WPA_CIPHER_* */
	/* TODO: expiration, identity, radius_class, EAP type, VLAN ID */
	int pmk_r1_pushed;
};

struct wpa_ft_pmk_r1_sa {
	struct wpa_ft_pmk_r1_sa *next;
	u8 pmk_r1[PMK_LEN];
	u8 pmk_r1_name[WPA_PMK_NAME_LEN];
	u8 spa[ETH_ALEN];
	int pairwise; /* Pairwise cipher suite, WPA_CIPHER_* */
	/* TODO: expiration, identity, radius_class, EAP type, VLAN ID */
};

struct wpa_ft_pmk_cache {
	struct wpa_ft_pmk_r0_sa *pmk_r0;
	struct wpa_ft_pmk_r1_sa *pmk_r1;
};

struct wpa_ft_pmk_cache * wpa_ft_pmk_cache_init(void)
{
	struct wpa_ft_pmk_cache *cache;

	cache = os_zalloc(sizeof(*cache));

	return cache;
}


void wpa_ft_pmk_cache_deinit(struct wpa_ft_pmk_cache *cache)
{
	struct wpa_ft_pmk_r0_sa *r0, *r0prev;
	struct wpa_ft_pmk_r1_sa *r1, *r1prev;

	r0 = cache->pmk_r0;
	while (r0) {
		r0prev = r0;
		r0 = r0->next;
		os_memset(r0prev->pmk_r0, 0, PMK_LEN);
		os_free(r0prev);
	}

	r1 = cache->pmk_r1;
	while (r1) {
		r1prev = r1;
		r1 = r1->next;
		os_memset(r1prev->pmk_r1, 0, PMK_LEN);
		os_free(r1prev);
	}

	os_free(cache);
}


static int wpa_ft_store_pmk_r0(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r0,
			       const u8 *pmk_r0_name, int pairwise)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r0_sa *r0;

	/* TODO: add expiration and limit on number of entries in cache */

	r0 = os_zalloc(sizeof(*r0));
	if (r0 == NULL)
		return -1;

	os_memcpy(r0->pmk_r0, pmk_r0, PMK_LEN);
	os_memcpy(r0->pmk_r0_name, pmk_r0_name, WPA_PMK_NAME_LEN);
	os_memcpy(r0->spa, spa, ETH_ALEN);
	r0->pairwise = pairwise;

	r0->next = cache->pmk_r0;
	cache->pmk_r0 = r0;

	return 0;
}


static int wpa_ft_fetch_pmk_r0(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r0_name,
			       const struct wpa_ft_pmk_r0_sa **r0_out)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r0_sa *r0;

	r0 = cache->pmk_r0;
	while (r0) {
		if (os_memcmp(r0->spa, spa, ETH_ALEN) == 0 &&
		    os_memcmp_const(r0->pmk_r0_name, pmk_r0_name,
				    WPA_PMK_NAME_LEN) == 0) {
			*r0_out = r0;
			return 0;
		}

		r0 = r0->next;
	}

	*r0_out = NULL;
	return -1;
}


static int wpa_ft_store_pmk_r1(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r1,
			       const u8 *pmk_r1_name, int pairwise)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r1_sa *r1;

	/* TODO: add expiration and limit on number of entries in cache */

	r1 = os_zalloc(sizeof(*r1));
	if (r1 == NULL)
		return -1;

	os_memcpy(r1->pmk_r1, pmk_r1, PMK_LEN);
	os_memcpy(r1->pmk_r1_name, pmk_r1_name, WPA_PMK_NAME_LEN);
	os_memcpy(r1->spa, spa, ETH_ALEN);
	r1->pairwise = pairwise;

	r1->next = cache->pmk_r1;
	cache->pmk_r1 = r1;

	return 0;
}


static int wpa_ft_fetch_pmk_r1(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r1_name,
			       u8 *pmk_r1, int *pairwise)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r1_sa *r1;

	r1 = cache->pmk_r1;
	while (r1) {
		if (os_memcmp(r1->spa, spa, ETH_ALEN) == 0 &&
		    os_memcmp_const(r1->pmk_r1_name, pmk_r1_name,
				    WPA_PMK_NAME_LEN) == 0) {
			os_memcpy(pmk_r1, r1->pmk_r1, PMK_LEN);
			if (pairwise)
				*pairwise = r1->pairwise;
			return 0;
		}

		r1 = r1->next;
	}

	return -1;
}


static void wpa_ft_rrb_lookup_r0kh(struct wpa_authenticator *wpa_auth,
				   const u8 *src_addr, const u8 *f_r0kh_id,
				   size_t f_r0kh_id_len,
				   struct ft_remote_r0kh **r0kh_out)
{
	struct ft_remote_r0kh *r0kh;

	for (r0kh = wpa_auth->conf.r0kh_list; r0kh; r0kh = r0kh->next) {
		if (src_addr && os_memcmp(r0kh->addr, src_addr, ETH_ALEN) != 0)
			continue;
		if (f_r0kh_id &&
		    (r0kh->id_len != f_r0kh_id_len ||
		     os_memcmp_const(f_r0kh_id, r0kh->id, f_r0kh_id_len) != 0))
			continue;
		break;
	}

	if (!r0kh)
		wpa_printf(MSG_DEBUG, "FT: No matching R0KH found");

	*r0kh_out = r0kh;
}


static void wpa_ft_rrb_lookup_r1kh(struct wpa_authenticator *wpa_auth,
				   const u8 *src_addr, const u8 *f_r1kh_id,
				   struct ft_remote_r1kh **r1kh_out)
{
	struct ft_remote_r1kh *r1kh;

	for (r1kh = wpa_auth->conf.r1kh_list; r1kh; r1kh = r1kh->next) {
		if (src_addr && os_memcmp(r1kh->addr, src_addr, ETH_ALEN) != 0)
			continue;
		if (f_r1kh_id &&
		    os_memcmp_const(r1kh->id, f_r1kh_id, FT_R1KH_ID_LEN) != 0)
			continue;
		break;
	}

	if (!r1kh)
		wpa_printf(MSG_DEBUG, "FT: No matching R1KH found");

	*r1kh_out = r1kh;
}


static int wpa_ft_rrb_check_r0kh(struct wpa_authenticator *wpa_auth,
				 const u8 *f_r0kh_id, size_t f_r0kh_id_len)
{
	if (f_r0kh_id_len != wpa_auth->conf.r0_key_holder_len ||
	    os_memcmp_const(f_r0kh_id, wpa_auth->conf.r0_key_holder,
			    f_r0kh_id_len) != 0)
		return -1;

	return 0;
}


static int wpa_ft_rrb_check_r1kh(struct wpa_authenticator *wpa_auth,
				 const u8 *f_r1kh_id)
{
	if (os_memcmp_const(f_r1kh_id, wpa_auth->conf.r1_key_holder,
			    FT_R1KH_ID_LEN) != 0)
		return -1;

	return 0;
}


static int wpa_ft_pull_pmk_r1(struct wpa_state_machine *sm,
			      const u8 *ies, size_t ies_len,
			      const u8 *pmk_r0_name)
{
	struct ft_remote_r0kh *r0kh;
	u8 *packet = NULL;
	const u8 *key;
	size_t packet_len, key_len;
	struct tlv_list req_enc[] = {
		{ .type = FT_RRB_PMK_R0_NAME, .len = WPA_PMK_NAME_LEN,
		  .data = pmk_r0_name },
		{ .type = FT_RRB_S1KH_ID, .len = ETH_ALEN,
		  .data = sm->addr },
		{ .type = FT_RRB_LAST_EMPTY, .len = 0, .data = NULL },
	};
	struct tlv_list req_auth[] = {
		{ .type = FT_RRB_NONCE, .len = FT_RRB_NONCE_LEN,
		  .data = sm->ft_pending_pull_nonce },
		{ .type = FT_RRB_R0KH_ID, .len = sm->r0kh_id_len,
		  .data = sm->r0kh_id },
		{ .type = FT_RRB_R1KH_ID, .len = FT_R1KH_ID_LEN,
		  .data = sm->wpa_auth->conf.r1_key_holder },
		{ .type = FT_RRB_LAST_EMPTY, .len = 0, .data = NULL },
	};

	wpa_ft_rrb_lookup_r0kh(sm->wpa_auth, NULL, sm->r0kh_id, sm->r0kh_id_len,
			       &r0kh);
	if (r0kh == NULL) {
		wpa_hexdump(MSG_DEBUG, "FT: Did not find R0KH-ID",
			    sm->r0kh_id, sm->r0kh_id_len);
		return -1;
	}
	key = r0kh->key;
	key_len = sizeof(r0kh->key);

	wpa_printf(MSG_DEBUG, "FT: Send PMK-R1 pull request to remote R0KH "
		   "address " MACSTR, MAC2STR(r0kh->addr));

	if (random_get_bytes(sm->ft_pending_pull_nonce, FT_RRB_NONCE_LEN) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to get random data for "
			   "nonce");
		return -1;
	}

	if (wpa_ft_rrb_build(key, key_len, req_enc, NULL, req_auth,
			     sm->wpa_auth->addr, FT_PACKET_R0KH_R1KH_PULL,
			     &packet, &packet_len) < 0)
		return -1;

	wpabuf_free(sm->ft_pending_req_ies);
	sm->ft_pending_req_ies = wpabuf_alloc_copy(ies, ies_len);
	if (!sm->ft_pending_req_ies) {
		os_free(packet);
		return -1;
	}

	wpa_ft_rrb_oui_send(sm->wpa_auth, r0kh->addr, FT_PACKET_R0KH_R1KH_PULL,
			    packet, packet_len);

	os_free(packet);

	return 0;
}


int wpa_auth_derive_ptk_ft(struct wpa_state_machine *sm, const u8 *pmk,
			   struct wpa_ptk *ptk)
{
	u8 pmk_r0[PMK_LEN], pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 pmk_r1[PMK_LEN];
	u8 ptk_name[WPA_PMK_NAME_LEN];
	const u8 *mdid = sm->wpa_auth->conf.mobility_domain;
	const u8 *r0kh = sm->wpa_auth->conf.r0_key_holder;
	size_t r0kh_len = sm->wpa_auth->conf.r0_key_holder_len;
	const u8 *r1kh = sm->wpa_auth->conf.r1_key_holder;
	const u8 *ssid = sm->wpa_auth->conf.ssid;
	size_t ssid_len = sm->wpa_auth->conf.ssid_len;
	int psk_local = sm->wpa_auth->conf.ft_psk_generate_local;

	if (sm->xxkey_len == 0) {
		wpa_printf(MSG_DEBUG, "FT: XXKey not available for key "
			   "derivation");
		return -1;
	}

	if (wpa_derive_pmk_r0(sm->xxkey, sm->xxkey_len, ssid, ssid_len, mdid,
			      r0kh, r0kh_len, sm->addr,
			      pmk_r0, pmk_r0_name) < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R0", pmk_r0, PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR0Name", pmk_r0_name, WPA_PMK_NAME_LEN);
	if (!psk_local || !wpa_key_mgmt_ft_psk(sm->wpa_key_mgmt))
		wpa_ft_store_pmk_r0(sm->wpa_auth, sm->addr, pmk_r0, pmk_r0_name,
				    sm->pairwise);

	if (wpa_derive_pmk_r1(pmk_r0, pmk_r0_name, r1kh, sm->addr,
			      pmk_r1, sm->pmk_r1_name) < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1", pmk_r1, PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR1Name", sm->pmk_r1_name,
		    WPA_PMK_NAME_LEN);
	if (!psk_local || !wpa_key_mgmt_ft_psk(sm->wpa_key_mgmt))
		wpa_ft_store_pmk_r1(sm->wpa_auth, sm->addr, pmk_r1,
				    sm->pmk_r1_name, sm->pairwise);

	return wpa_pmk_r1_to_ptk(pmk_r1, sm->SNonce, sm->ANonce, sm->addr,
				 sm->wpa_auth->addr, sm->pmk_r1_name,
				 ptk, ptk_name, sm->wpa_key_mgmt, sm->pairwise);
}


static inline int wpa_auth_get_seqnum(struct wpa_authenticator *wpa_auth,
				      const u8 *addr, int idx, u8 *seq)
{
	if (wpa_auth->cb->get_seqnum == NULL)
		return -1;
	return wpa_auth->cb->get_seqnum(wpa_auth->cb_ctx, addr, idx, seq);
}


static u8 * wpa_ft_gtk_subelem(struct wpa_state_machine *sm, size_t *len)
{
	u8 *subelem;
	struct wpa_group *gsm = sm->group;
	size_t subelem_len, pad_len;
	const u8 *key;
	size_t key_len;
	u8 keybuf[32];

	key_len = gsm->GTK_len;
	if (key_len > sizeof(keybuf))
		return NULL;

	/*
	 * Pad key for AES Key Wrap if it is not multiple of 8 bytes or is less
	 * than 16 bytes.
	 */
	pad_len = key_len % 8;
	if (pad_len)
		pad_len = 8 - pad_len;
	if (key_len + pad_len < 16)
		pad_len += 8;
	if (pad_len && key_len < sizeof(keybuf)) {
		os_memcpy(keybuf, gsm->GTK[gsm->GN - 1], key_len);
		os_memset(keybuf + key_len, 0, pad_len);
		keybuf[key_len] = 0xdd;
		key_len += pad_len;
		key = keybuf;
	} else
		key = gsm->GTK[gsm->GN - 1];

	/*
	 * Sub-elem ID[1] | Length[1] | Key Info[2] | Key Length[1] | RSC[8] |
	 * Key[5..32].
	 */
	subelem_len = 13 + key_len + 8;
	subelem = os_zalloc(subelem_len);
	if (subelem == NULL)
		return NULL;

	subelem[0] = FTIE_SUBELEM_GTK;
	subelem[1] = 11 + key_len + 8;
	/* Key ID in B0-B1 of Key Info */
	WPA_PUT_LE16(&subelem[2], gsm->GN & 0x03);
	subelem[4] = gsm->GTK_len;
	wpa_auth_get_seqnum(sm->wpa_auth, NULL, gsm->GN, subelem + 5);
	if (aes_wrap(sm->PTK.kek, sm->PTK.kek_len, key_len / 8, key,
		     subelem + 13)) {
		os_free(subelem);
		return NULL;
	}

	*len = subelem_len;
	return subelem;
}


#ifdef CONFIG_IEEE80211W
static u8 * wpa_ft_igtk_subelem(struct wpa_state_machine *sm, size_t *len)
{
	u8 *subelem, *pos;
	struct wpa_group *gsm = sm->group;
	size_t subelem_len;

	/* Sub-elem ID[1] | Length[1] | KeyID[2] | IPN[6] | Key Length[1] |
	 * Key[16+8] */
	subelem_len = 1 + 1 + 2 + 6 + 1 + WPA_IGTK_LEN + 8;
	subelem = os_zalloc(subelem_len);
	if (subelem == NULL)
		return NULL;

	pos = subelem;
	*pos++ = FTIE_SUBELEM_IGTK;
	*pos++ = subelem_len - 2;
	WPA_PUT_LE16(pos, gsm->GN_igtk);
	pos += 2;
	wpa_auth_get_seqnum(sm->wpa_auth, NULL, gsm->GN_igtk, pos);
	pos += 6;
	*pos++ = WPA_IGTK_LEN;
	if (aes_wrap(sm->PTK.kek, sm->PTK.kek_len, WPA_IGTK_LEN / 8,
		     gsm->IGTK[gsm->GN_igtk - 4], pos)) {
		os_free(subelem);
		return NULL;
	}

	*len = subelem_len;
	return subelem;
}
#endif /* CONFIG_IEEE80211W */


static u8 * wpa_ft_process_rdie(struct wpa_state_machine *sm,
				u8 *pos, u8 *end, u8 id, u8 descr_count,
				const u8 *ies, size_t ies_len)
{
	struct ieee802_11_elems parse;
	struct rsn_rdie *rdie;

	wpa_printf(MSG_DEBUG, "FT: Resource Request: id=%d descr_count=%d",
		   id, descr_count);
	wpa_hexdump(MSG_MSGDUMP, "FT: Resource descriptor IE(s)",
		    ies, ies_len);

	if (end - pos < (int) sizeof(*rdie)) {
		wpa_printf(MSG_ERROR, "FT: Not enough room for response RDIE");
		return pos;
	}

	*pos++ = WLAN_EID_RIC_DATA;
	*pos++ = sizeof(*rdie);
	rdie = (struct rsn_rdie *) pos;
	rdie->id = id;
	rdie->descr_count = 0;
	rdie->status_code = host_to_le16(WLAN_STATUS_SUCCESS);
	pos += sizeof(*rdie);

	if (ieee802_11_parse_elems((u8 *) ies, ies_len, &parse, 1) ==
	    ParseFailed) {
		wpa_printf(MSG_DEBUG, "FT: Failed to parse request IEs");
		rdie->status_code =
			host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
		return pos;
	}

	if (parse.wmm_tspec) {
		struct wmm_tspec_element *tspec;

		if (parse.wmm_tspec_len + 2 < (int) sizeof(*tspec)) {
			wpa_printf(MSG_DEBUG, "FT: Too short WMM TSPEC IE "
				   "(%d)", (int) parse.wmm_tspec_len);
			rdie->status_code =
				host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
			return pos;
		}
		if (end - pos < (int) sizeof(*tspec)) {
			wpa_printf(MSG_ERROR, "FT: Not enough room for "
				   "response TSPEC");
			rdie->status_code =
				host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
			return pos;
		}
		tspec = (struct wmm_tspec_element *) pos;
		os_memcpy(tspec, parse.wmm_tspec - 2, sizeof(*tspec));
	}

#ifdef NEED_AP_MLME
	if (parse.wmm_tspec && sm->wpa_auth->conf.ap_mlme) {
		int res;

		res = wmm_process_tspec((struct wmm_tspec_element *) pos);
		wpa_printf(MSG_DEBUG, "FT: ADDTS processing result: %d", res);
		if (res == WMM_ADDTS_STATUS_INVALID_PARAMETERS)
			rdie->status_code =
				host_to_le16(WLAN_STATUS_INVALID_PARAMETERS);
		else if (res == WMM_ADDTS_STATUS_REFUSED)
			rdie->status_code =
				host_to_le16(WLAN_STATUS_REQUEST_DECLINED);
		else {
			/* TSPEC accepted; include updated TSPEC in response */
			rdie->descr_count = 1;
			pos += sizeof(struct wmm_tspec_element);
		}
		return pos;
	}
#endif /* NEED_AP_MLME */

	if (parse.wmm_tspec && !sm->wpa_auth->conf.ap_mlme) {
		int res;

		res = wpa_ft_add_tspec(sm->wpa_auth, sm->addr, pos,
				       sizeof(struct wmm_tspec_element));
		if (res >= 0) {
			if (res)
				rdie->status_code = host_to_le16(res);
			else {
				/* TSPEC accepted; include updated TSPEC in
				 * response */
				rdie->descr_count = 1;
				pos += sizeof(struct wmm_tspec_element);
			}
			return pos;
		}
	}

	wpa_printf(MSG_DEBUG, "FT: No supported resource requested");
	rdie->status_code = host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
	return pos;
}


static u8 * wpa_ft_process_ric(struct wpa_state_machine *sm, u8 *pos, u8 *end,
			       const u8 *ric, size_t ric_len)
{
	const u8 *rpos, *start;
	const struct rsn_rdie *rdie;

	wpa_hexdump(MSG_MSGDUMP, "FT: RIC Request", ric, ric_len);

	rpos = ric;
	while (rpos + sizeof(*rdie) < ric + ric_len) {
		if (rpos[0] != WLAN_EID_RIC_DATA || rpos[1] < sizeof(*rdie) ||
		    rpos + 2 + rpos[1] > ric + ric_len)
			break;
		rdie = (const struct rsn_rdie *) (rpos + 2);
		rpos += 2 + rpos[1];
		start = rpos;

		while (rpos + 2 <= ric + ric_len &&
		       rpos + 2 + rpos[1] <= ric + ric_len) {
			if (rpos[0] == WLAN_EID_RIC_DATA)
				break;
			rpos += 2 + rpos[1];
		}
		pos = wpa_ft_process_rdie(sm, pos, end, rdie->id,
					  rdie->descr_count,
					  start, rpos - start);
	}

	return pos;
}


u8 * wpa_sm_write_assoc_resp_ies(struct wpa_state_machine *sm, u8 *pos,
				 size_t max_len, int auth_alg,
				 const u8 *req_ies, size_t req_ies_len)
{
	u8 *end, *mdie, *ftie, *rsnie = NULL, *r0kh_id, *subelem = NULL;
	size_t mdie_len, ftie_len, rsnie_len = 0, r0kh_id_len, subelem_len = 0;
	int res;
	struct wpa_auth_config *conf;
	struct rsn_ftie *_ftie;
	struct wpa_ft_ies parse;
	u8 *ric_start;
	u8 *anonce, *snonce;

	if (sm == NULL)
		return pos;

	conf = &sm->wpa_auth->conf;

	if (!wpa_key_mgmt_ft(sm->wpa_key_mgmt))
		return pos;

	end = pos + max_len;

	if (auth_alg == WLAN_AUTH_FT) {
		/*
		 * RSN (only present if this is a Reassociation Response and
		 * part of a fast BSS transition)
		 */
		res = wpa_write_rsn_ie(conf, pos, end - pos, sm->pmk_r1_name);
		if (res < 0)
			return pos;
		rsnie = pos;
		rsnie_len = res;
		pos += res;
	}

	/* Mobility Domain Information */
	res = wpa_write_mdie(conf, pos, end - pos);
	if (res < 0)
		return pos;
	mdie = pos;
	mdie_len = res;
	pos += res;

	/* Fast BSS Transition Information */
	if (auth_alg == WLAN_AUTH_FT) {
		subelem = wpa_ft_gtk_subelem(sm, &subelem_len);
		r0kh_id = sm->r0kh_id;
		r0kh_id_len = sm->r0kh_id_len;
		anonce = sm->ANonce;
		snonce = sm->SNonce;
#ifdef CONFIG_IEEE80211W
		if (sm->mgmt_frame_prot) {
			u8 *igtk;
			size_t igtk_len;
			u8 *nbuf;
			igtk = wpa_ft_igtk_subelem(sm, &igtk_len);
			if (igtk == NULL) {
				os_free(subelem);
				return pos;
			}
			nbuf = os_realloc(subelem, subelem_len + igtk_len);
			if (nbuf == NULL) {
				os_free(subelem);
				os_free(igtk);
				return pos;
			}
			subelem = nbuf;
			os_memcpy(subelem + subelem_len, igtk, igtk_len);
			subelem_len += igtk_len;
			os_free(igtk);
		}
#endif /* CONFIG_IEEE80211W */
	} else {
		r0kh_id = conf->r0_key_holder;
		r0kh_id_len = conf->r0_key_holder_len;
		anonce = NULL;
		snonce = NULL;
	}
	res = wpa_write_ftie(conf, r0kh_id, r0kh_id_len, anonce, snonce, pos,
			     end - pos, subelem, subelem_len);
	os_free(subelem);
	if (res < 0)
		return pos;
	ftie = pos;
	ftie_len = res;
	pos += res;

	_ftie = (struct rsn_ftie *) (ftie + 2);
	if (auth_alg == WLAN_AUTH_FT)
		_ftie->mic_control[1] = 3; /* Information element count */

	ric_start = pos;
	if (wpa_ft_parse_ies(req_ies, req_ies_len, &parse) == 0 && parse.ric) {
		pos = wpa_ft_process_ric(sm, pos, end, parse.ric,
					 parse.ric_len);
		if (auth_alg == WLAN_AUTH_FT)
			_ftie->mic_control[1] +=
				ieee802_11_ie_count(ric_start,
						    pos - ric_start);
	}
	if (ric_start == pos)
		ric_start = NULL;

	if (auth_alg == WLAN_AUTH_FT &&
	    wpa_ft_mic(sm->PTK.kck, sm->PTK.kck_len, sm->addr,
		       sm->wpa_auth->addr, 6,
		       mdie, mdie_len, ftie, ftie_len,
		       rsnie, rsnie_len,
		       ric_start, ric_start ? pos - ric_start : 0,
		       _ftie->mic) < 0)
		wpa_printf(MSG_DEBUG, "FT: Failed to calculate MIC");

	os_free(sm->assoc_resp_ftie);
	sm->assoc_resp_ftie = os_malloc(ftie_len);
	if (sm->assoc_resp_ftie)
		os_memcpy(sm->assoc_resp_ftie, ftie, ftie_len);

	return pos;
}


static inline int wpa_auth_set_key(struct wpa_authenticator *wpa_auth,
				   int vlan_id,
				   enum wpa_alg alg, const u8 *addr, int idx,
				   u8 *key, size_t key_len)
{
	if (wpa_auth->cb->set_key == NULL)
		return -1;
	return wpa_auth->cb->set_key(wpa_auth->cb_ctx, vlan_id, alg, addr, idx,
				     key, key_len);
}


void wpa_ft_install_ptk(struct wpa_state_machine *sm)
{
	enum wpa_alg alg;
	int klen;

	/* MLME-SETKEYS.request(PTK) */
	alg = wpa_cipher_to_alg(sm->pairwise);
	klen = wpa_cipher_key_len(sm->pairwise);
	if (!wpa_cipher_valid_pairwise(sm->pairwise)) {
		wpa_printf(MSG_DEBUG, "FT: Unknown pairwise alg 0x%x - skip "
			   "PTK configuration", sm->pairwise);
		return;
	}

	/* FIX: add STA entry to kernel/driver here? The set_key will fail
	 * most likely without this.. At the moment, STA entry is added only
	 * after association has been completed. This function will be called
	 * again after association to get the PTK configured, but that could be
	 * optimized by adding the STA entry earlier.
	 */
	if (wpa_auth_set_key(sm->wpa_auth, 0, alg, sm->addr, 0,
			     sm->PTK.tk, klen))
		return;

	/* FIX: MLME-SetProtection.Request(TA, Tx_Rx) */
	sm->pairwise_set = TRUE;
}


/* Derive PMK-R1 from PSK, check all available PSK */
static int wpa_ft_psk_pmk_r1(struct wpa_state_machine *sm,
			     const u8 *req_pmk_r1_name,
			     u8 *out_pmk_r1, int *out_pairwise)
{
	const u8 *pmk = NULL;
	u8 pmk_r0[PMK_LEN], pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 pmk_r1[PMK_LEN], pmk_r1_name[WPA_PMK_NAME_LEN];
	struct wpa_authenticator *wpa_auth = sm->wpa_auth;
	const u8 *mdid = wpa_auth->conf.mobility_domain;
	const u8 *r0kh = sm->r0kh_id;
	size_t r0kh_len = sm->r0kh_id_len;
	const u8 *r1kh = wpa_auth->conf.r1_key_holder;
	const u8 *ssid = wpa_auth->conf.ssid;
	size_t ssid_len = wpa_auth->conf.ssid_len;
	int pairwise;

	pairwise = sm->pairwise;

	for (;;) {
		pmk = wpa_ft_get_psk(wpa_auth, sm->addr, sm->p2p_dev_addr,
				     pmk);
		if (pmk == NULL)
			break;

		if (wpa_derive_pmk_r0(pmk, PMK_LEN, ssid, ssid_len, mdid, r0kh,
				      r0kh_len, sm->addr,
				      pmk_r0, pmk_r0_name) < 0 ||
		    wpa_derive_pmk_r1(pmk_r0, pmk_r0_name, r1kh, sm->addr,
				      pmk_r1, pmk_r1_name) < 0 ||
		    os_memcmp_const(pmk_r1_name, req_pmk_r1_name,
				    WPA_PMK_NAME_LEN) != 0)
			continue;

		/* We found a PSK that matches the requested pmk_r1_name */
		wpa_printf(MSG_DEBUG,
			   "FT: Found PSK to generate PMK-R1 locally");
		os_memcpy(out_pmk_r1, pmk_r1, PMK_LEN);
		if (out_pairwise)
			*out_pairwise = pairwise;
		return 0;
	}

	wpa_printf(MSG_DEBUG,
		   "FT: Did not find PSK to generate PMK-R1 locally");
	return -1;
}


/* Detect the configuration the station asked for.
 * Required to detect FT-PSK and pairwise cipher.
 */
static int wpa_ft_set_key_mgmt(struct wpa_state_machine *sm,
			       struct wpa_ft_ies *parse)
{
	int key_mgmt, ciphers;

	if (sm->wpa_key_mgmt)
		return 0;

	key_mgmt = parse->key_mgmt & sm->wpa_auth->conf.wpa_key_mgmt;
	if (!key_mgmt) {
		wpa_printf(MSG_DEBUG, "FT: Invalid key mgmt (0x%x) from "
			   MACSTR, parse->key_mgmt, MAC2STR(sm->addr));
		return -1;
	}
	if (key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X)
		sm->wpa_key_mgmt = WPA_KEY_MGMT_FT_IEEE8021X;
	else if (key_mgmt & WPA_KEY_MGMT_FT_PSK)
		sm->wpa_key_mgmt = WPA_KEY_MGMT_FT_PSK;
#ifdef CONFIG_FILS
	else if (key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA256)
		sm->wpa_key_mgmt = WPA_KEY_MGMT_FT_FILS_SHA256;
	else if (key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA384)
		sm->wpa_key_mgmt = WPA_KEY_MGMT_FT_FILS_SHA384;
#endif /* CONFIG_FILS */
	ciphers = parse->pairwise_cipher & sm->wpa_auth->conf.rsn_pairwise;
	if (!ciphers) {
		wpa_printf(MSG_DEBUG, "FT: Invalid pairwise cipher (0x%x) from "
			   MACSTR,
			   parse->pairwise_cipher, MAC2STR(sm->addr));
		return -1;
	}
	sm->pairwise = wpa_pick_pairwise_cipher(ciphers, 0);

	return 0;
}


static int wpa_ft_process_auth_req(struct wpa_state_machine *sm,
				   const u8 *ies, size_t ies_len,
				   u8 **resp_ies, size_t *resp_ies_len)
{
	struct rsn_mdie *mdie;
	struct rsn_ftie *ftie;
	u8 pmk_r1[PMK_LEN], pmk_r1_name[WPA_PMK_NAME_LEN];
	u8 ptk_name[WPA_PMK_NAME_LEN];
	struct wpa_auth_config *conf;
	struct wpa_ft_ies parse;
	size_t buflen;
	int ret;
	u8 *pos, *end;
	int pairwise;

	*resp_ies = NULL;
	*resp_ies_len = 0;

	sm->pmk_r1_name_valid = 0;
	conf = &sm->wpa_auth->conf;

	wpa_hexdump(MSG_DEBUG, "FT: Received authentication frame IEs",
		    ies, ies_len);

	if (wpa_ft_parse_ies(ies, ies_len, &parse) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to parse FT IEs");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	mdie = (struct rsn_mdie *) parse.mdie;
	if (mdie == NULL || parse.mdie_len < sizeof(*mdie) ||
	    os_memcmp(mdie->mobility_domain,
		      sm->wpa_auth->conf.mobility_domain,
		      MOBILITY_DOMAIN_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid MDIE");
		return WLAN_STATUS_INVALID_MDIE;
	}

	ftie = (struct rsn_ftie *) parse.ftie;
	if (ftie == NULL || parse.ftie_len < sizeof(*ftie)) {
		wpa_printf(MSG_DEBUG, "FT: Invalid FTIE");
		return WLAN_STATUS_INVALID_FTIE;
	}

	os_memcpy(sm->SNonce, ftie->snonce, WPA_NONCE_LEN);

	if (parse.r0kh_id == NULL) {
		wpa_printf(MSG_DEBUG, "FT: Invalid FTIE - no R0KH-ID");
		return WLAN_STATUS_INVALID_FTIE;
	}

	wpa_hexdump(MSG_DEBUG, "FT: STA R0KH-ID",
		    parse.r0kh_id, parse.r0kh_id_len);
	os_memcpy(sm->r0kh_id, parse.r0kh_id, parse.r0kh_id_len);
	sm->r0kh_id_len = parse.r0kh_id_len;

	if (parse.rsn_pmkid == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No PMKID in RSNIE");
		return WLAN_STATUS_INVALID_PMKID;
	}

	if (wpa_ft_set_key_mgmt(sm, &parse) < 0)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	wpa_hexdump(MSG_DEBUG, "FT: Requested PMKR0Name",
		    parse.rsn_pmkid, WPA_PMK_NAME_LEN);
	if (wpa_derive_pmk_r1_name(parse.rsn_pmkid,
				   sm->wpa_auth->conf.r1_key_holder, sm->addr,
				   pmk_r1_name) < 0)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	wpa_hexdump(MSG_DEBUG, "FT: Derived requested PMKR1Name",
		    pmk_r1_name, WPA_PMK_NAME_LEN);

	if (conf->ft_psk_generate_local &&
	    wpa_key_mgmt_ft_psk(sm->wpa_key_mgmt)) {
		if (wpa_ft_psk_pmk_r1(sm, pmk_r1_name, pmk_r1, &pairwise) < 0)
			return WLAN_STATUS_INVALID_PMKID;
	} else if (wpa_ft_fetch_pmk_r1(sm->wpa_auth, sm->addr, pmk_r1_name,
				       pmk_r1, &pairwise) < 0) {
		if (wpa_ft_pull_pmk_r1(sm, ies, ies_len, parse.rsn_pmkid) < 0) {
			wpa_printf(MSG_DEBUG, "FT: Did not have matching "
				   "PMK-R1 and unknown R0KH-ID");
			return WLAN_STATUS_INVALID_PMKID;
		}

		return -1; /* Status pending */
	}

	wpa_hexdump_key(MSG_DEBUG, "FT: Selected PMK-R1", pmk_r1, PMK_LEN);
	sm->pmk_r1_name_valid = 1;
	os_memcpy(sm->pmk_r1_name, pmk_r1_name, WPA_PMK_NAME_LEN);

	if (random_get_bytes(sm->ANonce, WPA_NONCE_LEN)) {
		wpa_printf(MSG_DEBUG, "FT: Failed to get random data for "
			   "ANonce");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	wpa_hexdump(MSG_DEBUG, "FT: Received SNonce",
		    sm->SNonce, WPA_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: Generated ANonce",
		    sm->ANonce, WPA_NONCE_LEN);

	if (wpa_pmk_r1_to_ptk(pmk_r1, sm->SNonce, sm->ANonce, sm->addr,
			      sm->wpa_auth->addr, pmk_r1_name,
			      &sm->PTK, ptk_name, sm->wpa_key_mgmt,
			      pairwise) < 0)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	sm->pairwise = pairwise;
	sm->PTK_valid = TRUE;
	wpa_ft_install_ptk(sm);

	buflen = 2 + sizeof(struct rsn_mdie) + 2 + sizeof(struct rsn_ftie) +
		2 + FT_R1KH_ID_LEN + 200;
	*resp_ies = os_zalloc(buflen);
	if (*resp_ies == NULL)
		goto fail;

	pos = *resp_ies;
	end = *resp_ies + buflen;

	ret = wpa_write_rsn_ie(conf, pos, end - pos, parse.rsn_pmkid);
	if (ret < 0)
		goto fail;
	pos += ret;

	ret = wpa_write_mdie(conf, pos, end - pos);
	if (ret < 0)
		goto fail;
	pos += ret;

	ret = wpa_write_ftie(conf, parse.r0kh_id, parse.r0kh_id_len,
			     sm->ANonce, sm->SNonce, pos, end - pos, NULL, 0);
	if (ret < 0)
		goto fail;
	pos += ret;

	*resp_ies_len = pos - *resp_ies;

	return WLAN_STATUS_SUCCESS;
fail:
	os_free(*resp_ies);
	*resp_ies = NULL;
	return WLAN_STATUS_UNSPECIFIED_FAILURE;
}


void wpa_ft_process_auth(struct wpa_state_machine *sm, const u8 *bssid,
			 u16 auth_transaction, const u8 *ies, size_t ies_len,
			 void (*cb)(void *ctx, const u8 *dst, const u8 *bssid,
				    u16 auth_transaction, u16 status,
				    const u8 *ies, size_t ies_len),
			 void *ctx)
{
	u16 status;
	u8 *resp_ies;
	size_t resp_ies_len;
	int res;

	if (sm == NULL) {
		wpa_printf(MSG_DEBUG, "FT: Received authentication frame, but "
			   "WPA SM not available");
		return;
	}

	wpa_printf(MSG_DEBUG, "FT: Received authentication frame: STA=" MACSTR
		   " BSSID=" MACSTR " transaction=%d",
		   MAC2STR(sm->addr), MAC2STR(bssid), auth_transaction);
	sm->ft_pending_cb = cb;
	sm->ft_pending_cb_ctx = ctx;
	sm->ft_pending_auth_transaction = auth_transaction;
	res = wpa_ft_process_auth_req(sm, ies, ies_len, &resp_ies,
				      &resp_ies_len);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "FT: Callback postponed until response is available");
		return;
	}
	status = res;

	wpa_printf(MSG_DEBUG, "FT: FT authentication response: dst=" MACSTR
		   " auth_transaction=%d status=%d",
		   MAC2STR(sm->addr), auth_transaction + 1, status);
	wpa_hexdump(MSG_DEBUG, "FT: Response IEs", resp_ies, resp_ies_len);
	cb(ctx, sm->addr, bssid, auth_transaction + 1, status,
	   resp_ies, resp_ies_len);
	os_free(resp_ies);
}


u16 wpa_ft_validate_reassoc(struct wpa_state_machine *sm, const u8 *ies,
			    size_t ies_len)
{
	struct wpa_ft_ies parse;
	struct rsn_mdie *mdie;
	struct rsn_ftie *ftie;
	u8 mic[WPA_EAPOL_KEY_MIC_MAX_LEN];
	size_t mic_len = 16;
	unsigned int count;

	if (sm == NULL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	wpa_hexdump(MSG_DEBUG, "FT: Reassoc Req IEs", ies, ies_len);

	if (wpa_ft_parse_ies(ies, ies_len, &parse) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to parse FT IEs");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (parse.rsn == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No RSNIE in Reassoc Req");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (parse.rsn_pmkid == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No PMKID in RSNIE");
		return WLAN_STATUS_INVALID_PMKID;
	}

	if (os_memcmp_const(parse.rsn_pmkid, sm->pmk_r1_name, WPA_PMK_NAME_LEN)
	    != 0) {
		wpa_printf(MSG_DEBUG, "FT: PMKID in Reassoc Req did not match "
			   "with the PMKR1Name derived from auth request");
		return WLAN_STATUS_INVALID_PMKID;
	}

	mdie = (struct rsn_mdie *) parse.mdie;
	if (mdie == NULL || parse.mdie_len < sizeof(*mdie) ||
	    os_memcmp(mdie->mobility_domain,
		      sm->wpa_auth->conf.mobility_domain,
		      MOBILITY_DOMAIN_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid MDIE");
		return WLAN_STATUS_INVALID_MDIE;
	}

	ftie = (struct rsn_ftie *) parse.ftie;
	if (ftie == NULL || parse.ftie_len < sizeof(*ftie)) {
		wpa_printf(MSG_DEBUG, "FT: Invalid FTIE");
		return WLAN_STATUS_INVALID_FTIE;
	}

	if (os_memcmp(ftie->snonce, sm->SNonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: SNonce mismatch in FTIE");
		wpa_hexdump(MSG_DEBUG, "FT: Received SNonce",
			    ftie->snonce, WPA_NONCE_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: Expected SNonce",
			    sm->SNonce, WPA_NONCE_LEN);
		return WLAN_STATUS_INVALID_FTIE;
	}

	if (os_memcmp(ftie->anonce, sm->ANonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: ANonce mismatch in FTIE");
		wpa_hexdump(MSG_DEBUG, "FT: Received ANonce",
			    ftie->anonce, WPA_NONCE_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: Expected ANonce",
			    sm->ANonce, WPA_NONCE_LEN);
		return WLAN_STATUS_INVALID_FTIE;
	}


	if (parse.r0kh_id == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No R0KH-ID subelem in FTIE");
		return WLAN_STATUS_INVALID_FTIE;
	}

	if (parse.r0kh_id_len != sm->r0kh_id_len ||
	    os_memcmp_const(parse.r0kh_id, sm->r0kh_id, parse.r0kh_id_len) != 0)
	{
		wpa_printf(MSG_DEBUG, "FT: R0KH-ID in FTIE did not match with "
			   "the current R0KH-ID");
		wpa_hexdump(MSG_DEBUG, "FT: R0KH-ID in FTIE",
			    parse.r0kh_id, parse.r0kh_id_len);
		wpa_hexdump(MSG_DEBUG, "FT: The current R0KH-ID",
			    sm->r0kh_id, sm->r0kh_id_len);
		return WLAN_STATUS_INVALID_FTIE;
	}

	if (parse.r1kh_id == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No R1KH-ID subelem in FTIE");
		return WLAN_STATUS_INVALID_FTIE;
	}

	if (os_memcmp_const(parse.r1kh_id, sm->wpa_auth->conf.r1_key_holder,
			    FT_R1KH_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Unknown R1KH-ID used in "
			   "ReassocReq");
		wpa_hexdump(MSG_DEBUG, "FT: R1KH-ID in FTIE",
			    parse.r1kh_id, FT_R1KH_ID_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: Expected R1KH-ID",
			    sm->wpa_auth->conf.r1_key_holder, FT_R1KH_ID_LEN);
		return WLAN_STATUS_INVALID_FTIE;
	}

	if (parse.rsn_pmkid == NULL ||
	    os_memcmp_const(parse.rsn_pmkid, sm->pmk_r1_name, WPA_PMK_NAME_LEN))
	{
		wpa_printf(MSG_DEBUG, "FT: No matching PMKR1Name (PMKID) in "
			   "RSNIE (pmkid=%d)", !!parse.rsn_pmkid);
		return WLAN_STATUS_INVALID_PMKID;
	}

	count = 3;
	if (parse.ric)
		count += ieee802_11_ie_count(parse.ric, parse.ric_len);
	if (ftie->mic_control[1] != count) {
		wpa_printf(MSG_DEBUG, "FT: Unexpected IE count in MIC "
			   "Control: received %u expected %u",
			   ftie->mic_control[1], count);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (wpa_ft_mic(sm->PTK.kck, sm->PTK.kck_len, sm->addr,
		       sm->wpa_auth->addr, 5,
		       parse.mdie - 2, parse.mdie_len + 2,
		       parse.ftie - 2, parse.ftie_len + 2,
		       parse.rsn - 2, parse.rsn_len + 2,
		       parse.ric, parse.ric_len,
		       mic) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to calculate MIC");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (os_memcmp_const(mic, ftie->mic, mic_len) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid MIC in FTIE");
		wpa_printf(MSG_DEBUG, "FT: addr=" MACSTR " auth_addr=" MACSTR,
			   MAC2STR(sm->addr), MAC2STR(sm->wpa_auth->addr));
		wpa_hexdump(MSG_MSGDUMP, "FT: Received MIC",
			    ftie->mic, mic_len);
		wpa_hexdump(MSG_MSGDUMP, "FT: Calculated MIC", mic, mic_len);
		wpa_hexdump(MSG_MSGDUMP, "FT: MDIE",
			    parse.mdie - 2, parse.mdie_len + 2);
		wpa_hexdump(MSG_MSGDUMP, "FT: FTIE",
			    parse.ftie - 2, parse.ftie_len + 2);
		wpa_hexdump(MSG_MSGDUMP, "FT: RSN",
			    parse.rsn - 2, parse.rsn_len + 2);
		return WLAN_STATUS_INVALID_FTIE;
	}

	return WLAN_STATUS_SUCCESS;
}


int wpa_ft_action_rx(struct wpa_state_machine *sm, const u8 *data, size_t len)
{
	const u8 *sta_addr, *target_ap;
	const u8 *ies;
	size_t ies_len;
	u8 action;
	struct ft_rrb_frame *frame;

	if (sm == NULL)
		return -1;

	/*
	 * data: Category[1] Action[1] STA_Address[6] Target_AP_Address[6]
	 * FT Request action frame body[variable]
	 */

	if (len < 14) {
		wpa_printf(MSG_DEBUG, "FT: Too short FT Action frame "
			   "(len=%lu)", (unsigned long) len);
		return -1;
	}

	action = data[1];
	sta_addr = data + 2;
	target_ap = data + 8;
	ies = data + 14;
	ies_len = len - 14;

	wpa_printf(MSG_DEBUG, "FT: Received FT Action frame (STA=" MACSTR
		   " Target AP=" MACSTR " Action=%d)",
		   MAC2STR(sta_addr), MAC2STR(target_ap), action);

	if (os_memcmp(sta_addr, sm->addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Mismatch in FT Action STA address: "
			   "STA=" MACSTR " STA-Address=" MACSTR,
			   MAC2STR(sm->addr), MAC2STR(sta_addr));
		return -1;
	}

	/*
	 * Do some sanity checking on the target AP address (not own and not
	 * broadcast. This could be extended to filter based on a list of known
	 * APs in the MD (if such a list were configured).
	 */
	if ((target_ap[0] & 0x01) ||
	    os_memcmp(target_ap, sm->wpa_auth->addr, ETH_ALEN) == 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid Target AP in FT Action "
			   "frame");
		return -1;
	}

	wpa_hexdump(MSG_MSGDUMP, "FT: Action frame body", ies, ies_len);

	if (!sm->wpa_auth->conf.ft_over_ds) {
		wpa_printf(MSG_DEBUG, "FT: Over-DS option disabled - reject");
		return -1;
	}

	/* RRB - Forward action frame to the target AP */
	frame = os_malloc(sizeof(*frame) + len);
	if (frame == NULL)
		return -1;
	frame->frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame->packet_type = FT_PACKET_REQUEST;
	frame->action_length = host_to_le16(len);
	os_memcpy(frame->ap_address, sm->wpa_auth->addr, ETH_ALEN);
	os_memcpy(frame + 1, data, len);

	wpa_ft_rrb_send(sm->wpa_auth, target_ap, (u8 *) frame,
			sizeof(*frame) + len);
	os_free(frame);

	return 0;
}


static void wpa_ft_rrb_rx_request_cb(void *ctx, const u8 *dst, const u8 *bssid,
				     u16 auth_transaction, u16 resp,
				     const u8 *ies, size_t ies_len)
{
	struct wpa_state_machine *sm = ctx;
	wpa_printf(MSG_DEBUG, "FT: Over-the-DS RX request cb for " MACSTR,
		   MAC2STR(sm->addr));
	wpa_ft_send_rrb_auth_resp(sm, sm->ft_pending_current_ap, sm->addr,
				  WLAN_STATUS_SUCCESS, ies, ies_len);
}


static int wpa_ft_rrb_rx_request(struct wpa_authenticator *wpa_auth,
				 const u8 *current_ap, const u8 *sta_addr,
				 const u8 *body, size_t len)
{
	struct wpa_state_machine *sm;
	u16 status;
	u8 *resp_ies;
	size_t resp_ies_len;
	int res;

	sm = wpa_ft_add_sta(wpa_auth, sta_addr);
	if (sm == NULL) {
		wpa_printf(MSG_DEBUG, "FT: Failed to add new STA based on "
			   "RRB Request");
		return -1;
	}

	wpa_hexdump(MSG_MSGDUMP, "FT: RRB Request Frame body", body, len);

	sm->ft_pending_cb = wpa_ft_rrb_rx_request_cb;
	sm->ft_pending_cb_ctx = sm;
	os_memcpy(sm->ft_pending_current_ap, current_ap, ETH_ALEN);
	res = wpa_ft_process_auth_req(sm, body, len, &resp_ies,
				      &resp_ies_len);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "FT: No immediate response available - wait for pull response");
		return 0;
	}
	status = res;

	res = wpa_ft_send_rrb_auth_resp(sm, current_ap, sta_addr, status,
					resp_ies, resp_ies_len);
	os_free(resp_ies);
	return res;
}


static int wpa_ft_send_rrb_auth_resp(struct wpa_state_machine *sm,
				     const u8 *current_ap, const u8 *sta_addr,
				     u16 status, const u8 *resp_ies,
				     size_t resp_ies_len)
{
	struct wpa_authenticator *wpa_auth = sm->wpa_auth;
	size_t rlen;
	struct ft_rrb_frame *frame;
	u8 *pos;

	wpa_printf(MSG_DEBUG, "FT: RRB authentication response: STA=" MACSTR
		   " CurrentAP=" MACSTR " status=%d",
		   MAC2STR(sm->addr), MAC2STR(current_ap), status);
	wpa_hexdump(MSG_DEBUG, "FT: Response IEs", resp_ies, resp_ies_len);

	/* RRB - Forward action frame response to the Current AP */

	/*
	 * data: Category[1] Action[1] STA_Address[6] Target_AP_Address[6]
	 * Status_Code[2] FT Request action frame body[variable]
	 */
	rlen = 2 + 2 * ETH_ALEN + 2 + resp_ies_len;

	frame = os_malloc(sizeof(*frame) + rlen);
	if (frame == NULL)
		return -1;
	frame->frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame->packet_type = FT_PACKET_RESPONSE;
	frame->action_length = host_to_le16(rlen);
	os_memcpy(frame->ap_address, wpa_auth->addr, ETH_ALEN);
	pos = (u8 *) (frame + 1);
	*pos++ = WLAN_ACTION_FT;
	*pos++ = 2; /* Action: Response */
	os_memcpy(pos, sta_addr, ETH_ALEN);
	pos += ETH_ALEN;
	os_memcpy(pos, wpa_auth->addr, ETH_ALEN);
	pos += ETH_ALEN;
	WPA_PUT_LE16(pos, status);
	pos += 2;
	if (resp_ies)
		os_memcpy(pos, resp_ies, resp_ies_len);

	wpa_ft_rrb_send(wpa_auth, current_ap, (u8 *) frame,
			sizeof(*frame) + rlen);
	os_free(frame);

	return 0;
}


static int wpa_ft_rrb_build_r0(const u8 *key, const size_t key_len,
			       const struct tlv_list *tlvs,
			       const struct wpa_ft_pmk_r0_sa *pmk_r0,
			       const u8 *r1kh_id, const u8 *s1kh_id,
			       const struct tlv_list *tlv_auth,
			       const u8 *src_addr, u8 type,
			       u8 **packet, size_t *packet_len)
{
	u8 pmk_r1[PMK_LEN];
	u8 pmk_r1_name[WPA_PMK_NAME_LEN];
	u8 f_pairwise[sizeof(le16)];
	int ret;
	struct tlv_list sess_tlv[] = {
		{ .type = FT_RRB_PMK_R1, .len = sizeof(pmk_r1),
		  .data = pmk_r1 },
		{ .type = FT_RRB_PMK_R1_NAME, .len = sizeof(pmk_r1_name),
		  .data = pmk_r1_name },
		{ .type = FT_RRB_PAIRWISE, .len = sizeof(f_pairwise),
		  .data = f_pairwise },
		{ .type = FT_RRB_LAST_EMPTY, .len = 0, .data = NULL },
	};

	if (wpa_derive_pmk_r1(pmk_r0->pmk_r0, pmk_r0->pmk_r0_name, r1kh_id,
			      s1kh_id, pmk_r1, pmk_r1_name) < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1", pmk_r1, PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR1Name", pmk_r1_name, WPA_PMK_NAME_LEN);
	WPA_PUT_LE16(f_pairwise, pmk_r0->pairwise);

	ret = wpa_ft_rrb_build(key, key_len, tlvs, sess_tlv, tlv_auth,
			       src_addr, type, packet, packet_len);

	os_memset(pmk_r1, 0, sizeof(pmk_r1));

	return ret;
}


static int wpa_ft_rrb_rx_pull(struct wpa_authenticator *wpa_auth,
			      const u8 *src_addr,
			      const u8 *enc, size_t enc_len,
			      const u8 *auth, size_t auth_len)
{
	const char *msgtype = "pull request";
	u8 *plain = NULL, *packet = NULL;
	size_t plain_len = 0, packet_len = 0;
	struct ft_remote_r1kh *r1kh;
	const u8 *key;
	size_t key_len;
	const u8 *f_nonce, *f_r0kh_id, *f_r1kh_id, *f_s1kh_id, *f_pmk_r0_name;
	size_t f_nonce_len, f_r0kh_id_len, f_r1kh_id_len, f_s1kh_id_len;
	size_t f_pmk_r0_name_len;
	const struct wpa_ft_pmk_r0_sa *r0;
	int ret;
	struct tlv_list resp[2];
	struct tlv_list resp_auth[4];

	wpa_printf(MSG_DEBUG, "FT: Received PMK-R1 pull");

	RRB_GET_AUTH(FT_RRB_R0KH_ID, r0kh_id, msgtype, -1);
	wpa_hexdump(MSG_DEBUG, "FT: R0KH-ID", f_r0kh_id, f_r0kh_id_len);

	if (wpa_ft_rrb_check_r0kh(wpa_auth, f_r0kh_id, f_r0kh_id_len)) {
		wpa_printf(MSG_DEBUG, "FT: R0KH-ID mismatch");
		goto out;
	}

	RRB_GET_AUTH(FT_RRB_R1KH_ID, r1kh_id, msgtype, FT_R1KH_ID_LEN);
	wpa_printf(MSG_DEBUG, "FT: R1KH-ID=" MACSTR, MAC2STR(f_r1kh_id));

	wpa_ft_rrb_lookup_r1kh(wpa_auth, src_addr, f_r1kh_id, &r1kh);
	if (!r1kh)
		goto out;
	key = r1kh->key;
	key_len = sizeof(r1kh->key);

	RRB_GET_AUTH(FT_RRB_NONCE, nonce, "pull request", FT_RRB_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: nonce", f_nonce, f_nonce_len);

	if (wpa_ft_rrb_decrypt(key, key_len, enc, enc_len, auth, auth_len,
			       src_addr, FT_PACKET_R0KH_R1KH_PULL,
			       &plain, &plain_len) < 0)
		goto out;

	RRB_GET(FT_RRB_PMK_R0_NAME, pmk_r0_name, msgtype, WPA_PMK_NAME_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR0Name", f_pmk_r0_name,
		    f_pmk_r0_name_len);

	RRB_GET(FT_RRB_S1KH_ID, s1kh_id, msgtype, ETH_ALEN);
	wpa_printf(MSG_DEBUG, "FT: S1KH-ID=" MACSTR, MAC2STR(f_s1kh_id));

	resp[0].type = FT_RRB_S1KH_ID;
	resp[0].len = f_s1kh_id_len;
	resp[0].data = f_s1kh_id;
	resp[1].type = FT_RRB_LAST_EMPTY;
	resp[1].len = 0;
	resp[1].data = NULL;

	resp_auth[0].type = FT_RRB_NONCE;
	resp_auth[0].len = f_nonce_len;
	resp_auth[0].data = f_nonce;
	resp_auth[1].type = FT_RRB_R0KH_ID;
	resp_auth[1].len = f_r0kh_id_len;
	resp_auth[1].data = f_r0kh_id;
	resp_auth[2].type = FT_RRB_R1KH_ID;
	resp_auth[2].len = f_r1kh_id_len;
	resp_auth[2].data = f_r1kh_id;
	resp_auth[3].type = FT_RRB_LAST_EMPTY;
	resp_auth[3].len = 0;
	resp_auth[3].data = NULL;

	if (wpa_ft_fetch_pmk_r0(wpa_auth, f_s1kh_id, f_pmk_r0_name, &r0) < 0) {
		wpa_printf(MSG_DEBUG, "FT: No matching PMK-R0-Name found");
		goto out;
	}

	ret = wpa_ft_rrb_build_r0(key, key_len, resp, r0, f_r1kh_id, f_s1kh_id,
				  resp_auth, wpa_auth->addr,
				  FT_PACKET_R0KH_R1KH_RESP,
				  &packet, &packet_len);

	if (!ret)
		wpa_ft_rrb_oui_send(wpa_auth, src_addr,
				    FT_PACKET_R0KH_R1KH_RESP, packet,
				    packet_len);

out:
	os_free(plain);
	os_free(packet);

	return 0;
}


/* @returns  0 on success
 *          -1 on error
 */
static int wpa_ft_rrb_rx_r1(struct wpa_authenticator *wpa_auth,
			    const u8 *src_addr, u8 type,
			    const u8 *enc, size_t enc_len,
			    const u8 *auth, size_t auth_len,
			    const char *msgtype, u8 *s1kh_id_out)
{
	u8 *plain = NULL;
	size_t plain_len = 0;
	struct ft_remote_r0kh *r0kh;
	const u8 *key;
	size_t key_len;
	const u8 *f_r1kh_id, *f_s1kh_id, *f_r0kh_id;
	const u8 *f_pmk_r1_name, *f_pairwise, *f_pmk_r1;
	size_t f_r1kh_id_len, f_s1kh_id_len, f_r0kh_id_len;
	size_t f_pmk_r1_name_len, f_pairwise_len, f_pmk_r1_len;
	int pairwise;
	int ret = -1;

	RRB_GET_AUTH(FT_RRB_R0KH_ID, r0kh_id, msgtype, -1);
	wpa_hexdump(MSG_DEBUG, "FT: R0KH-ID", f_r0kh_id, f_r0kh_id_len);

	RRB_GET_AUTH(FT_RRB_R1KH_ID, r1kh_id, msgtype, FT_R1KH_ID_LEN);
	wpa_printf(MSG_DEBUG, "FT: R1KH-ID=" MACSTR, MAC2STR(f_r1kh_id));

	if (wpa_ft_rrb_check_r1kh(wpa_auth, f_r1kh_id)) {
		wpa_printf(MSG_DEBUG, "FT: R1KH-ID mismatch");
		goto out;
	}

	wpa_ft_rrb_lookup_r0kh(wpa_auth, src_addr, f_r0kh_id, f_r0kh_id_len,
			       &r0kh);
	if (!r0kh)
		goto out;
	key = r0kh->key;
	key_len = sizeof(r0kh->key);

	if (wpa_ft_rrb_decrypt(key, key_len, enc, enc_len, auth, auth_len,
			       src_addr, type, &plain, &plain_len) < 0)
		goto out;

	RRB_GET(FT_RRB_S1KH_ID, s1kh_id, msgtype, ETH_ALEN);
	wpa_printf(MSG_DEBUG, "FT: S1KH-ID=" MACSTR, MAC2STR(f_s1kh_id));

	if (s1kh_id_out)
		os_memcpy(s1kh_id_out, f_s1kh_id, ETH_ALEN);

	RRB_GET(FT_RRB_PAIRWISE, pairwise, msgtype, sizeof(le16));
	wpa_hexdump(MSG_DEBUG, "FT: pairwise", f_pairwise, f_pairwise_len);

	RRB_GET(FT_RRB_PMK_R1_NAME, pmk_r1_name, msgtype, WPA_PMK_NAME_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR1Name",
		    f_pmk_r1_name, WPA_PMK_NAME_LEN);

	RRB_GET(FT_RRB_PMK_R1, pmk_r1, msgtype, PMK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1", f_pmk_r1, PMK_LEN);

	pairwise = WPA_GET_LE16(f_pairwise);

	if (wpa_ft_store_pmk_r1(wpa_auth, f_s1kh_id, f_pmk_r1, f_pmk_r1_name,
				pairwise) < 0)
		goto out;

	ret = 0;
out:
	if (plain) {
		os_memset(plain, 0, plain_len);
		os_free(plain);
	}

	return ret;

}


static void ft_finish_pull(struct wpa_state_machine *sm)
{
	int res;
	u8 *resp_ies;
	size_t resp_ies_len;
	u16 status;

	res = wpa_ft_process_auth_req(sm, wpabuf_head(sm->ft_pending_req_ies),
				      wpabuf_len(sm->ft_pending_req_ies),
				      &resp_ies, &resp_ies_len);
	wpabuf_free(sm->ft_pending_req_ies);
	sm->ft_pending_req_ies = NULL;
	if (res < 0)
		res = WLAN_STATUS_UNSPECIFIED_FAILURE;
	status = res;
	wpa_printf(MSG_DEBUG, "FT: Postponed auth callback result for " MACSTR
		   " - status %u", MAC2STR(sm->addr), status);

	sm->ft_pending_cb(sm->ft_pending_cb_ctx, sm->addr, sm->wpa_auth->addr,
			  sm->ft_pending_auth_transaction + 1, status,
			  resp_ies, resp_ies_len);
	os_free(resp_ies);
}


struct ft_get_sta_ctx {
	const u8 *nonce;
	const u8 *s1kh_id;
	struct wpa_state_machine *sm;
};


static int ft_get_sta_cb(struct wpa_state_machine *sm, void *ctx)
{
	struct ft_get_sta_ctx *info = ctx;

	if ((info->s1kh_id &&
	     os_memcmp(info->s1kh_id, sm->addr, ETH_ALEN) != 0) ||
	    os_memcmp(info->nonce, sm->ft_pending_pull_nonce,
		      FT_RRB_NONCE_LEN) != 0 ||
	    sm->ft_pending_cb == NULL || sm->ft_pending_req_ies == NULL)
		return 0;

	info->sm = sm;

	return 1;
}


static int wpa_ft_rrb_rx_resp(struct wpa_authenticator *wpa_auth,
			      const u8 *src_addr,
			      const u8 *enc, size_t enc_len,
			      const u8 *auth, size_t auth_len)
{
	const char *msgtype = "pull response";
	int ret = -1;
	struct ft_get_sta_ctx ctx;
	u8 s1kh_id[ETH_ALEN];
	const u8 *f_nonce;
	size_t f_nonce_len;

	wpa_printf(MSG_DEBUG, "FT: Received PMK-R1 pull response");

	RRB_GET_AUTH(FT_RRB_NONCE, nonce, msgtype, FT_RRB_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: nonce", f_nonce, f_nonce_len);

	os_memset(&ctx, 0, sizeof(ctx));
	ctx.nonce = f_nonce;
	if (!wpa_auth_for_each_sta(wpa_auth, ft_get_sta_cb, &ctx)) {
		/* nonce not found */
		wpa_printf(MSG_DEBUG, "FT: Invalid nonce");
		return -1;
	}

	ret = wpa_ft_rrb_rx_r1(wpa_auth, src_addr, FT_PACKET_R0KH_R1KH_RESP,
			       enc, enc_len, auth, auth_len, msgtype, s1kh_id);
	if (ret < 0)
		return -1;

	ctx.s1kh_id = s1kh_id;
	if (wpa_auth_for_each_sta(wpa_auth, ft_get_sta_cb, &ctx)) {
		wpa_printf(MSG_DEBUG,
			   "FT: Response to a pending pull request for " MACSTR,
			   MAC2STR(ctx.sm->addr));
		ft_finish_pull(ctx.sm);
	}

out:
	return ret;
}


static int wpa_ft_rrb_rx_push(struct wpa_authenticator *wpa_auth,
			      const u8 *src_addr,
			      const u8 *enc, size_t enc_len,
			      const u8 *auth, size_t auth_len)
{
	const char *msgtype = "push";
	struct os_time now;
	struct os_time tsend;
	const u8 *f_timestamp;
	size_t f_timestamp_len;

	wpa_printf(MSG_DEBUG, "FT: Received PMK-R1 push");

	RRB_GET_AUTH(FT_RRB_TIMESTAMP, timestamp, msgtype, sizeof(le32));
	tsend.sec = WPA_GET_LE32(f_timestamp);
	wpa_printf(MSG_DEBUG, "FT: timestamp=%ld", tsend.sec);
	os_get_time(&now);
	if ((now.sec > tsend.sec && now.sec - tsend.sec > 60) ||
	    (now.sec < tsend.sec && tsend.sec - now.sec > 60)) {
		wpa_printf(MSG_DEBUG,
			   "FT(RRB): push did not have a valid timestamp: sender time %ld own time %ld",
			   tsend.sec, now.sec);
		return -1;
	}

	if (wpa_ft_rrb_rx_r1(wpa_auth, src_addr, FT_PACKET_R0KH_R1KH_PUSH,
			     enc, enc_len, auth, auth_len, msgtype, NULL) < 0)
		return -1;

	return 0;
out:
	return -1;
}


int wpa_ft_rrb_rx(struct wpa_authenticator *wpa_auth, const u8 *src_addr,
		  const u8 *data, size_t data_len)
{
	struct ft_rrb_frame *frame;
	u16 alen;
	const u8 *pos, *end, *start;
	u8 action;
	const u8 *sta_addr, *target_ap_addr;

	wpa_printf(MSG_DEBUG, "FT: RRB received frame from remote AP " MACSTR,
		   MAC2STR(src_addr));

	if (data_len < sizeof(*frame)) {
		wpa_printf(MSG_DEBUG, "FT: Too short RRB frame (data_len=%lu)",
			   (unsigned long) data_len);
		return -1;
	}

	pos = data;
	frame = (struct ft_rrb_frame *) pos;
	pos += sizeof(*frame);

	alen = le_to_host16(frame->action_length);
	wpa_printf(MSG_DEBUG, "FT: RRB frame - frame_type=%d packet_type=%d "
		   "action_length=%d ap_address=" MACSTR,
		   frame->frame_type, frame->packet_type, alen,
		   MAC2STR(frame->ap_address));

	if (frame->frame_type != RSN_REMOTE_FRAME_TYPE_FT_RRB) {
		/* Discard frame per IEEE Std 802.11r-2008, 11A.10.3 */
		wpa_printf(MSG_DEBUG, "FT: RRB discarded frame with "
			   "unrecognized type %d", frame->frame_type);
		return -1;
	}

	if (alen > data_len - sizeof(*frame)) {
		wpa_printf(MSG_DEBUG, "FT: RRB frame too short for action "
			   "frame");
		return -1;
	}

	wpa_hexdump(MSG_MSGDUMP, "FT: RRB - FT Action frame", pos, alen);

	if (alen < 1 + 1 + 2 * ETH_ALEN) {
		wpa_printf(MSG_DEBUG, "FT: Too short RRB frame (not enough "
			   "room for Action Frame body); alen=%lu",
			   (unsigned long) alen);
		return -1;
	}
	start = pos;
	end = pos + alen;

	if (*pos != WLAN_ACTION_FT) {
		wpa_printf(MSG_DEBUG, "FT: Unexpected Action frame category "
			   "%d", *pos);
		return -1;
	}

	pos++;
	action = *pos++;
	sta_addr = pos;
	pos += ETH_ALEN;
	target_ap_addr = pos;
	pos += ETH_ALEN;
	wpa_printf(MSG_DEBUG, "FT: RRB Action Frame: action=%d sta_addr="
		   MACSTR " target_ap_addr=" MACSTR,
		   action, MAC2STR(sta_addr), MAC2STR(target_ap_addr));

	if (frame->packet_type == FT_PACKET_REQUEST) {
		wpa_printf(MSG_DEBUG, "FT: FT Packet Type - Request");

		if (action != 1) {
			wpa_printf(MSG_DEBUG, "FT: Unexpected Action %d in "
				   "RRB Request", action);
			return -1;
		}

		if (os_memcmp(target_ap_addr, wpa_auth->addr, ETH_ALEN) != 0) {
			wpa_printf(MSG_DEBUG, "FT: Target AP address in the "
				   "RRB Request does not match with own "
				   "address");
			return -1;
		}

		if (wpa_ft_rrb_rx_request(wpa_auth, frame->ap_address,
					  sta_addr, pos, end - pos) < 0)
			return -1;
	} else if (frame->packet_type == FT_PACKET_RESPONSE) {
		u16 status_code;

		if (end - pos < 2) {
			wpa_printf(MSG_DEBUG, "FT: Not enough room for status "
				   "code in RRB Response");
			return -1;
		}
		status_code = WPA_GET_LE16(pos);
		pos += 2;

		wpa_printf(MSG_DEBUG, "FT: FT Packet Type - Response "
			   "(status_code=%d)", status_code);

		if (wpa_ft_action_send(wpa_auth, sta_addr, start, alen) < 0)
			return -1;
	} else {
		wpa_printf(MSG_DEBUG, "FT: RRB discarded frame with unknown "
			   "packet_type %d", frame->packet_type);
		return -1;
	}

	if (end > pos) {
		wpa_hexdump(MSG_DEBUG, "FT: Ignore extra data in end",
			    pos, end - pos);
	}

	return 0;
}


void wpa_ft_rrb_oui_rx(struct wpa_authenticator *wpa_auth, const u8 *src_addr,
		       const u8 *dst_addr, u8 oui_suffix, const u8 *data,
		       size_t data_len)
{
	const u8 *auth, *enc;
	size_t alen, elen;

	wpa_printf(MSG_DEBUG, "FT: RRB-OUI received frame from remote AP "
		   MACSTR, MAC2STR(src_addr));
	wpa_printf(MSG_DEBUG, "FT: RRB-OUI frame - oui_suffix=%d", oui_suffix);

	if (is_multicast_ether_addr(src_addr)) {
		wpa_printf(MSG_DEBUG,
			   "FT: RRB-OUI received frame from multicast address "
			   MACSTR, MAC2STR(src_addr));
		return;
	}

	if (is_multicast_ether_addr(dst_addr)) {
		wpa_printf(MSG_DEBUG,
			   "FT: RRB-OUI received frame from remote AP " MACSTR
			   " to multicast address " MACSTR,
			   MAC2STR(src_addr), MAC2STR(dst_addr));
		return;
	}

	if (data_len < sizeof(u16)) {
		wpa_printf(MSG_DEBUG, "FT: RRB-OUI frame too short");
		return;
	}

	alen = WPA_GET_LE16(data);
	if (data_len < sizeof(u16) + alen) {
		wpa_printf(MSG_DEBUG, "FT: RRB-OUI frame too short");
		return;
	}

	auth = data + sizeof(u16);
	enc = data + sizeof(u16) + alen;
	elen = data_len - sizeof(u16) - alen;

	switch (oui_suffix) {
	case FT_PACKET_R0KH_R1KH_PULL:
		wpa_ft_rrb_rx_pull(wpa_auth, src_addr, enc, elen, auth, alen);
		break;
	case FT_PACKET_R0KH_R1KH_RESP:
		wpa_ft_rrb_rx_resp(wpa_auth, src_addr, enc, elen, auth, alen);
		break;
	case FT_PACKET_R0KH_R1KH_PUSH:
		wpa_ft_rrb_rx_push(wpa_auth, src_addr, enc, elen, auth, alen);
		break;
	}
}


static int wpa_ft_generate_pmk_r1(struct wpa_authenticator *wpa_auth,
				  struct wpa_ft_pmk_r0_sa *pmk_r0,
				  struct ft_remote_r1kh *r1kh,
				  const u8 *s1kh_id)
{
	struct os_time now;
	u8 *packet;
	size_t packet_len;
	u8 f_timestamp[sizeof(le32)];
	struct tlv_list push[] = {
		{ .type = FT_RRB_S1KH_ID, .len = ETH_ALEN,
		  .data = s1kh_id },
		{ .type = FT_RRB_PMK_R0_NAME, .len = WPA_PMK_NAME_LEN,
		  .data = pmk_r0->pmk_r0_name },
		{ .type = FT_RRB_LAST_EMPTY, .len = 0, .data = NULL },
	};
	struct tlv_list push_auth[] = {
		{ .type = FT_RRB_TIMESTAMP, .len = sizeof(f_timestamp),
		  .data = f_timestamp },
		{ .type = FT_RRB_R0KH_ID,
		  .len = wpa_auth->conf.r0_key_holder_len,
		  .data = wpa_auth->conf.r0_key_holder },
		{ .type = FT_RRB_R1KH_ID, .len = FT_R1KH_ID_LEN,
		  .data = r1kh->id },
		{ .type = FT_RRB_LAST_EMPTY, .len = 0, .data = NULL },
	};

	os_get_time(&now);
	WPA_PUT_LE32(f_timestamp, now.sec);

	if (wpa_ft_rrb_build_r0(r1kh->key, sizeof(r1kh->key), push, pmk_r0,
				r1kh->id, s1kh_id, push_auth, wpa_auth->addr,
				FT_PACKET_R0KH_R1KH_PUSH,
				&packet, &packet_len) < 0)
		return -1;

	wpa_ft_rrb_oui_send(wpa_auth, r1kh->addr, FT_PACKET_R0KH_R1KH_PUSH,
			    packet, packet_len);

	os_free(packet);
	return 0;
}


void wpa_ft_push_pmk_r1(struct wpa_authenticator *wpa_auth, const u8 *addr)
{
	struct wpa_ft_pmk_r0_sa *r0;
	struct ft_remote_r1kh *r1kh;

	if (!wpa_auth->conf.pmk_r1_push)
		return;

	r0 = wpa_auth->ft_pmk_cache->pmk_r0;
	while (r0) {
		if (os_memcmp(r0->spa, addr, ETH_ALEN) == 0)
			break;
		r0 = r0->next;
	}

	if (r0 == NULL || r0->pmk_r1_pushed)
		return;
	r0->pmk_r1_pushed = 1;

	wpa_printf(MSG_DEBUG, "FT: Deriving and pushing PMK-R1 keys to R1KHs "
		   "for STA " MACSTR, MAC2STR(addr));

	r1kh = wpa_auth->conf.r1kh_list;
	while (r1kh) {
		wpa_ft_generate_pmk_r1(wpa_auth, r0, r1kh, addr);
		r1kh = r1kh->next;
	}
}

#endif /* CONFIG_IEEE80211R_AP */
