/*
 * Received Data frame processing
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
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

#include "utils/includes.h"

#include "utils/common.h"
#include "crypto/aes_wrap.h"
#include "crypto/crypto.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "common/eapol_common.h"
#include "common/wpa_common.h"
#include "rsn_supp/wpa_ie.h"
#include "wlantest.h"


static const char * data_stype(u16 stype)
{
	switch (stype) {
	case WLAN_FC_STYPE_DATA:
		return "DATA";
	case WLAN_FC_STYPE_DATA_CFACK:
		return "DATA-CFACK";
	case WLAN_FC_STYPE_DATA_CFPOLL:
		return "DATA-CFPOLL";
	case WLAN_FC_STYPE_DATA_CFACKPOLL:
		return "DATA-CFACKPOLL";
	case WLAN_FC_STYPE_NULLFUNC:
		return "NULLFUNC";
	case WLAN_FC_STYPE_CFACK:
		return "CFACK";
	case WLAN_FC_STYPE_CFPOLL:
		return "CFPOLL";
	case WLAN_FC_STYPE_CFACKPOLL:
		return "CFACKPOLL";
	case WLAN_FC_STYPE_QOS_DATA:
		return "QOSDATA";
	case WLAN_FC_STYPE_QOS_DATA_CFACK:
		return "QOSDATA-CFACK";
	case WLAN_FC_STYPE_QOS_DATA_CFPOLL:
		return "QOSDATA-CFPOLL";
	case WLAN_FC_STYPE_QOS_DATA_CFACKPOLL:
		return "QOSDATA-CFACKPOLL";
	case WLAN_FC_STYPE_QOS_NULL:
		return "QOS-NULL";
	case WLAN_FC_STYPE_QOS_CFPOLL:
		return "QOS-CFPOLL";
	case WLAN_FC_STYPE_QOS_CFACKPOLL:
		return "QOS-CFACKPOLL";
	}
	return "??";
}


static int check_mic(const u8 *kck, int ver, const u8 *data, size_t len)
{
	u8 *buf;
	int ret = -1;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	u8 rx_mic[16];

	buf = os_malloc(len);
	if (buf == NULL)
		return -1;
	os_memcpy(buf, data, len);
	hdr = (struct ieee802_1x_hdr *) buf;
	key = (struct wpa_eapol_key *) (hdr + 1);

	os_memcpy(rx_mic, key->key_mic, 16);
	os_memset(key->key_mic, 0, 16);

	if (wpa_eapol_key_mic(kck, ver, buf, len, key->key_mic) == 0 &&
	    os_memcmp(rx_mic, key->key_mic, 16) == 0)
		ret = 0;

	os_free(buf);

	return ret;
}


static void rx_data_eapol_key_1_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *data, size_t len)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 1/4 " MACSTR " -> " MACSTR,
		   MAC2STR(src), MAC2STR(dst));
	bss = bss_get(wt, src);
	if (bss == NULL)
		return;
	sta = sta_get(bss, dst);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	os_memcpy(sta->anonce, hdr->key_nonce, WPA_NONCE_LEN);
}


static int try_pmk(struct wlantest_bss *bss, struct wlantest_sta *sta,
		   u16 ver, const u8 *data, size_t len,
		   struct wlantest_pmk *pmk)
{
	struct wpa_ptk ptk;
	size_t ptk_len = sta->pairwise_cipher == WPA_CIPHER_TKIP ? 64 : 48;
	wpa_pmk_to_ptk(pmk->pmk, sizeof(pmk->pmk),
		       "Pairwise key expansion",
		       bss->bssid, sta->addr, sta->anonce, sta->snonce,
		       (u8 *) &ptk, ptk_len,
		       wpa_key_mgmt_sha256(sta->key_mgmt));
	if (check_mic(ptk.kck, ver, data, len) < 0)
		return -1;

	wpa_printf(MSG_INFO, "Derived PTK for STA " MACSTR " BSSID " MACSTR,
		   MAC2STR(sta->addr), MAC2STR(bss->bssid));
	os_memcpy(&sta->ptk, &ptk, sizeof(ptk));
	wpa_hexdump(MSG_DEBUG, "PTK:KCK", sta->ptk.kck, 16);
	wpa_hexdump(MSG_DEBUG, "PTK:KEK", sta->ptk.kek, 16);
	wpa_hexdump(MSG_DEBUG, "PTK:TK1", sta->ptk.tk1, 16);
	if (ptk_len > 48)
		wpa_hexdump(MSG_DEBUG, "PTK:TK2", sta->ptk.u.tk2, 16);
	sta->ptk_set = 1;
	os_memset(sta->rsc_tods, 0, sizeof(sta->rsc_tods));
	os_memset(sta->rsc_fromds, 0, sizeof(sta->rsc_fromds));
	return 0;
}


static void derive_ptk(struct wlantest *wt, struct wlantest_bss *bss,
		       struct wlantest_sta *sta, u16 ver,
		       const u8 *data, size_t len)
{
	struct wlantest_pmk *pmk;

	dl_list_for_each(pmk, &bss->pmk, struct wlantest_pmk, list) {
		if (try_pmk(bss, sta, ver, data, len, pmk) == 0)
			return;
	}

	dl_list_for_each(pmk, &wt->pmk, struct wlantest_pmk, list) {
		if (try_pmk(bss, sta, ver, data, len, pmk) == 0)
			return;
	}
}


static void rx_data_eapol_key_2_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *data, size_t len)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data;
	u16 key_info, key_data_len;
	struct wpa_eapol_ie_parse ie;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 2/4 " MACSTR " -> " MACSTR,
		   MAC2STR(src), MAC2STR(dst));
	bss = bss_get(wt, dst);
	if (bss == NULL)
		return;
	sta = sta_get(bss, src);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	os_memcpy(sta->snonce, hdr->key_nonce, WPA_NONCE_LEN);
	key_info = WPA_GET_BE16(hdr->key_info);
	key_data_len = WPA_GET_BE16(hdr->key_data_length);
	derive_ptk(wt, bss, sta, key_info & WPA_KEY_INFO_TYPE_MASK, data, len);

	if (!sta->ptk_set) {
		wpa_printf(MSG_DEBUG, "No PTK known to process EAPOL-Key 2/4");
		return;
	}

	if (check_mic(sta->ptk.kck, key_info & WPA_KEY_INFO_TYPE_MASK,
		      data, len) < 0) {
		wpa_printf(MSG_INFO, "Mismatch in EAPOL-Key 2/4 MIC");
		return;
	}
	wpa_printf(MSG_DEBUG, "Valid MIC found in EAPOL-Key 2/4");

	key_data = (const u8 *) (hdr + 1);

	if (wpa_supplicant_parse_ies(key_data, key_data_len, &ie) < 0) {
		wpa_printf(MSG_INFO, "Failed to parse EAPOL-Key Key Data");
		return;
	}

	if (ie.wpa_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - WPA IE",
			    ie.wpa_ie, ie.wpa_ie_len);
		if (os_memcmp(ie.wpa_ie, sta->rsnie, ie.wpa_ie_len) != 0) {
			wpa_printf(MSG_INFO, "Mismatch in WPA IE between "
				   "EAPOL-Key 2/4 and (Re)Association "
				   "Request from " MACSTR, MAC2STR(sta->addr));
			wpa_hexdump(MSG_INFO, "WPA IE in EAPOL-Key",
				    ie.wpa_ie, ie.wpa_ie_len);
			wpa_hexdump(MSG_INFO, "WPA IE in (Re)Association "
				    "Request",
				    sta->rsnie,
				    sta->rsnie[0] ? 2 + sta->rsnie[1] : 0);
		}
	}

	if (ie.rsn_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - RSN IE",
			    ie.rsn_ie, ie.rsn_ie_len);
		if (os_memcmp(ie.rsn_ie, sta->rsnie, ie.rsn_ie_len) != 0) {
			wpa_printf(MSG_INFO, "Mismatch in WPA IE between "
				   "EAPOL-Key 2/4 and (Re)Association "
				   "Request from " MACSTR, MAC2STR(sta->addr));
			wpa_hexdump(MSG_INFO, "WPA IE in EAPOL-Key",
				    ie.rsn_ie, ie.rsn_ie_len);
			wpa_hexdump(MSG_INFO, "WPA IE in (Re)Association "
				    "Request",
				    sta->rsnie,
				    sta->rsnie[0] ? 2 + sta->rsnie[1] : 0);
		}
	}
}


static u8 * decrypt_eapol_key_data_rc4(const u8 *kek,
				       const struct wpa_eapol_key *hdr,
				       size_t *len)
{
	u8 ek[32], *buf;
	u16 keydatalen = WPA_GET_BE16(hdr->key_data_length);

	buf = os_malloc(keydatalen);
	if (buf == NULL)
		return NULL;

	os_memcpy(ek, hdr->key_iv, 16);
	os_memcpy(ek + 16, kek, 16);
	os_memcpy(buf, hdr + 1, keydatalen);
	if (rc4_skip(ek, 32, 256, buf, keydatalen)) {
		wpa_printf(MSG_INFO, "RC4 failed");
		os_free(buf);
		return NULL;
	}

	*len = keydatalen;
	return buf;
}


static u8 * decrypt_eapol_key_data_aes(const u8 *kek,
				       const struct wpa_eapol_key *hdr,
				       size_t *len)
{
	u8 *buf;
	u16 keydatalen = WPA_GET_BE16(hdr->key_data_length);

	if (keydatalen % 8) {
		wpa_printf(MSG_INFO, "Unsupported AES-WRAP len %d",
			   keydatalen);
		return NULL;
	}
	keydatalen -= 8; /* AES-WRAP adds 8 bytes */
	buf = os_malloc(keydatalen);
	if (buf == NULL)
		return NULL;
	if (aes_unwrap(kek, keydatalen / 8, (u8 *) (hdr + 1), buf)) {
		os_free(buf);
		wpa_printf(MSG_INFO, "AES unwrap failed - "
			   "could not decrypt EAPOL-Key key data");
		return NULL;
	}

	*len = keydatalen;
	return buf;
}


static u8 * decrypt_eapol_key_data(const u8 *kek, u16 ver,
				   const struct wpa_eapol_key *hdr,
				   size_t *len)
{
	switch (ver) {
	case WPA_KEY_INFO_TYPE_HMAC_MD5_RC4:
		return decrypt_eapol_key_data_rc4(kek, hdr, len);
	case WPA_KEY_INFO_TYPE_HMAC_SHA1_AES:
	case WPA_KEY_INFO_TYPE_AES_128_CMAC:
		return decrypt_eapol_key_data_aes(kek, hdr, len);
	default:
		wpa_printf(MSG_INFO, "Unsupported EAPOL-Key Key Descriptor "
			   "Version %u", ver);
		return NULL;
	}
}


static void learn_kde_keys(struct wlantest_bss *bss, u8 *buf, size_t len,
			   const u8 *rsc)
{
	struct wpa_eapol_ie_parse ie;

	if (wpa_supplicant_parse_ies(buf, len, &ie) < 0) {
		wpa_printf(MSG_INFO, "Failed to parse EAPOL-Key Key Data");
		return;
	}

	if (ie.wpa_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - WPA IE",
			    ie.wpa_ie, ie.wpa_ie_len);
	}

	if (ie.rsn_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - RSN IE",
			    ie.rsn_ie, ie.rsn_ie_len);
	}

	if (ie.gtk) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - GTK KDE",
			    ie.gtk, ie.gtk_len);
		if (ie.gtk_len >= 2 && ie.gtk_len <= 2 + 32) {
			int id;
			id = ie.gtk[0] & 0x03;
			wpa_printf(MSG_DEBUG, "GTK KeyID=%u tx=%u",
				   id, !!(ie.gtk[0] & 0x04));
			if ((ie.gtk[0] & 0xf8) || ie.gtk[1])
				wpa_printf(MSG_INFO, "GTK KDE: Reserved field "
					   "set: %02x %02x",
					   ie.gtk[0], ie.gtk[1]);
			wpa_hexdump(MSG_DEBUG, "GTK", ie.gtk + 2,
				    ie.gtk_len - 2);
			bss->gtk_len[id] = ie.gtk_len - 2;
			os_memcpy(bss->gtk[id], ie.gtk + 2, ie.gtk_len - 2);
			bss->rsc[id][0] = rsc[5];
			bss->rsc[id][1] = rsc[4];
			bss->rsc[id][2] = rsc[3];
			bss->rsc[id][3] = rsc[2];
			bss->rsc[id][4] = rsc[1];
			bss->rsc[id][5] = rsc[0];
			wpa_hexdump(MSG_DEBUG, "RSC", bss->rsc[id], 6);
		} else {
			wpa_printf(MSG_INFO, "Invalid GTK KDE length %u",
				   (unsigned) ie.gtk_len);
		}
	}

	if (ie.igtk) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - IGTK KDE",
			    ie.igtk, ie.igtk_len);
		if (ie.igtk_len == 24) {
			u16 id;
			id = WPA_GET_LE16(ie.igtk);
			if (id > 5) {
				wpa_printf(MSG_INFO, "Unexpected IGTK KeyID "
					   "%u", id);
			} else {
				wpa_printf(MSG_DEBUG, "IGTK KeyID %u", id);
				wpa_hexdump(MSG_DEBUG, "IPN", ie.igtk + 2, 6);
				wpa_hexdump(MSG_DEBUG, "IGTK", ie.igtk + 8,
					    16);
				os_memcpy(bss->igtk[id], ie.igtk + 8, 16);
				bss->igtk_set[id] = 1;
			}
		} else {
			wpa_printf(MSG_INFO, "Invalid IGTK KDE length %u",
				   (unsigned) ie.igtk_len);
		}
	}
}


static void rx_data_eapol_key_3_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *data, size_t len)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data;
	int recalc = 0;
	u16 key_info, ver;
	u8 *decrypted;
	size_t decrypted_len = 0;
	struct wpa_eapol_ie_parse ie;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 3/4 " MACSTR " -> " MACSTR,
		   MAC2STR(src), MAC2STR(dst));
	bss = bss_get(wt, src);
	if (bss == NULL)
		return;
	sta = sta_get(bss, dst);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	key_info = WPA_GET_BE16(hdr->key_info);

	if (os_memcmp(sta->anonce, hdr->key_nonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_INFO, "EAPOL-Key ANonce mismatch between 1/4 "
			   "and 3/4");
		recalc = 1;
	}
	os_memcpy(sta->anonce, hdr->key_nonce, WPA_NONCE_LEN);
	if (recalc) {
		derive_ptk(wt, bss, sta, key_info & WPA_KEY_INFO_TYPE_MASK,
			   data, len);
	}

	if (!sta->ptk_set) {
		wpa_printf(MSG_DEBUG, "No PTK known to process EAPOL-Key 3/4");
		return;
	}

	if (check_mic(sta->ptk.kck, key_info & WPA_KEY_INFO_TYPE_MASK,
		      data, len) < 0) {
		wpa_printf(MSG_INFO, "Mismatch in EAPOL-Key 3/4 MIC");
		return;
	}
	wpa_printf(MSG_DEBUG, "Valid MIC found in EAPOL-Key 3/4");

	key_data = (const u8 *) (hdr + 1);
	/* TODO: handle WPA without EncrKeyData bit */
	if (!(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_INFO, "EAPOL-Key 3/4 without EncrKeyData bit");
		return;
	}
	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	decrypted = decrypt_eapol_key_data(sta->ptk.kek, ver, hdr,
					   &decrypted_len);
	if (decrypted == NULL) {
		wpa_printf(MSG_INFO, "Failed to decrypt EAPOL-Key Key Data");
		return;
	}
	wpa_hexdump(MSG_DEBUG, "Decrypted EAPOL-Key Key Data",
		    decrypted, decrypted_len);
	if (wt->write_pcap_dumper) {
		/* Fill in a dummy Data frame header */
		u8 buf[24 + 8 + sizeof(*eapol) + sizeof(*hdr)];
		struct ieee80211_hdr *h;
		struct wpa_eapol_key *k;
		u8 *pos;
		size_t plain_len;

		plain_len = decrypted_len;
		pos = decrypted;
		while (pos + 1 < decrypted + decrypted_len) {
			if (pos[0] == 0xdd && pos[1] == 0x00) {
				/* Remove padding */
				plain_len = pos - decrypted;
				break;
			}
			pos += 2 + pos[1];
		}

		os_memset(buf, 0, sizeof(buf));
		h = (struct ieee80211_hdr *) buf;
		h->frame_control = host_to_le16(0x0208);
		os_memcpy(h->addr1, dst, ETH_ALEN);
		os_memcpy(h->addr2, src, ETH_ALEN);
		os_memcpy(h->addr3, src, ETH_ALEN);
		pos = (u8 *) (h + 1);
		os_memcpy(pos, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8);
		pos += 8;
		os_memcpy(pos, eapol, sizeof(*eapol));
		pos += sizeof(*eapol);
		os_memcpy(pos, hdr, sizeof(*hdr));
		k = (struct wpa_eapol_key *) pos;
		WPA_PUT_BE16(k->key_info,
			     key_info & ~WPA_KEY_INFO_ENCR_KEY_DATA);
		WPA_PUT_BE16(k->key_data_length, plain_len);
		write_pcap_decrypted(wt, buf, sizeof(buf),
				     decrypted, plain_len);
	}

	if (wpa_supplicant_parse_ies(decrypted, decrypted_len, &ie) < 0) {
		wpa_printf(MSG_INFO, "Failed to parse EAPOL-Key Key Data");
		os_free(decrypted);
		return;
	}

	if ((ie.wpa_ie &&
	     os_memcmp(ie.wpa_ie, bss->wpaie, ie.wpa_ie_len) != 0) ||
	    (ie.wpa_ie == NULL && bss->wpaie[0])) {
		wpa_printf(MSG_INFO, "Mismatch in WPA IE between "
			   "EAPOL-Key 3/4 and Beacon/Probe Response "
			   "from " MACSTR, MAC2STR(bss->bssid));
		wpa_hexdump(MSG_INFO, "WPA IE in EAPOL-Key",
			    ie.wpa_ie, ie.wpa_ie_len);
		wpa_hexdump(MSG_INFO, "WPA IE in Beacon/Probe "
			    "Response",
			    bss->wpaie,
			    bss->wpaie[0] ? 2 + bss->wpaie[1] : 0);
	}

	if ((ie.rsn_ie &&
	     os_memcmp(ie.rsn_ie, bss->rsnie, ie.rsn_ie_len) != 0) ||
	    (ie.rsn_ie == NULL && bss->rsnie[0])) {
		wpa_printf(MSG_INFO, "Mismatch in RSN IE between "
			   "EAPOL-Key 3/4 and Beacon/Probe Response "
			   "from " MACSTR, MAC2STR(bss->bssid));
		wpa_hexdump(MSG_INFO, "RSN IE in EAPOL-Key",
			    ie.rsn_ie, ie.rsn_ie_len);
		wpa_hexdump(MSG_INFO, "RSN IE in (Re)Association "
			    "Request",
			    bss->rsnie,
			    bss->rsnie[0] ? 2 + bss->rsnie[1] : 0);
	}

	learn_kde_keys(bss, decrypted, decrypted_len, hdr->key_rsc);
	os_free(decrypted);
}


static void rx_data_eapol_key_4_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *data, size_t len)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	u16 key_info;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 4/4 " MACSTR " -> " MACSTR,
		   MAC2STR(src), MAC2STR(dst));
	bss = bss_get(wt, dst);
	if (bss == NULL)
		return;
	sta = sta_get(bss, src);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	key_info = WPA_GET_BE16(hdr->key_info);

	if (!sta->ptk_set) {
		wpa_printf(MSG_DEBUG, "No PTK known to process EAPOL-Key 4/4");
		return;
	}

	if (sta->ptk_set &&
	    check_mic(sta->ptk.kck, key_info & WPA_KEY_INFO_TYPE_MASK,
		      data, len) < 0) {
		wpa_printf(MSG_INFO, "Mismatch in EAPOL-Key 4/4 MIC");
		return;
	}
	wpa_printf(MSG_DEBUG, "Valid MIC found in EAPOL-Key 4/4");
}


static void rx_data_eapol_key_1_of_2(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *data, size_t len)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data;
	u16 key_info, ver;
	u8 *decrypted;
	size_t decrypted_len = 0;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 1/2 " MACSTR " -> " MACSTR,
		   MAC2STR(src), MAC2STR(dst));
	bss = bss_get(wt, src);
	if (bss == NULL)
		return;
	sta = sta_get(bss, dst);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	key_info = WPA_GET_BE16(hdr->key_info);

	if (!sta->ptk_set) {
		wpa_printf(MSG_DEBUG, "No PTK known to process EAPOL-Key 1/2");
		return;
	}

	if (sta->ptk_set &&
	    check_mic(sta->ptk.kck, key_info & WPA_KEY_INFO_TYPE_MASK,
		      data, len) < 0) {
		wpa_printf(MSG_INFO, "Mismatch in EAPOL-Key 1/2 MIC");
		return;
	}
	wpa_printf(MSG_DEBUG, "Valid MIC found in EAPOL-Key 1/2");

	key_data = (const u8 *) (hdr + 1);
	/* TODO: handle WPA without EncrKeyData bit */
	if (!(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_INFO, "EAPOL-Key 1/2 without EncrKeyData bit");
		return;
	}
	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	decrypted = decrypt_eapol_key_data(sta->ptk.kek, ver, hdr,
					   &decrypted_len);
	if (decrypted == NULL) {
		wpa_printf(MSG_INFO, "Failed to decrypt EAPOL-Key Key Data");
		return;
	}
	wpa_hexdump(MSG_DEBUG, "Decrypted EAPOL-Key Key Data",
		    decrypted, decrypted_len);
	if (wt->write_pcap_dumper) {
		/* Fill in a dummy Data frame header */
		u8 buf[24 + 8 + sizeof(*eapol) + sizeof(*hdr)];
		struct ieee80211_hdr *h;
		struct wpa_eapol_key *k;
		u8 *pos;
		size_t plain_len;

		plain_len = decrypted_len;
		pos = decrypted;
		while (pos + 1 < decrypted + decrypted_len) {
			if (pos[0] == 0xdd && pos[1] == 0x00) {
				/* Remove padding */
				plain_len = pos - decrypted;
				break;
			}
			pos += 2 + pos[1];
		}

		os_memset(buf, 0, sizeof(buf));
		h = (struct ieee80211_hdr *) buf;
		h->frame_control = host_to_le16(0x0208);
		os_memcpy(h->addr1, dst, ETH_ALEN);
		os_memcpy(h->addr2, src, ETH_ALEN);
		os_memcpy(h->addr3, src, ETH_ALEN);
		pos = (u8 *) (h + 1);
		os_memcpy(pos, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8);
		pos += 8;
		os_memcpy(pos, eapol, sizeof(*eapol));
		pos += sizeof(*eapol);
		os_memcpy(pos, hdr, sizeof(*hdr));
		k = (struct wpa_eapol_key *) pos;
		WPA_PUT_BE16(k->key_info,
			     key_info & ~WPA_KEY_INFO_ENCR_KEY_DATA);
		WPA_PUT_BE16(k->key_data_length, plain_len);
		write_pcap_decrypted(wt, buf, sizeof(buf),
				     decrypted, plain_len);
	}
	learn_kde_keys(bss, decrypted, decrypted_len, hdr->key_rsc);
	os_free(decrypted);
}


static void rx_data_eapol_key_2_of_2(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *data, size_t len)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	u16 key_info;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 2/2 " MACSTR " -> " MACSTR,
		   MAC2STR(src), MAC2STR(dst));
	bss = bss_get(wt, dst);
	if (bss == NULL)
		return;
	sta = sta_get(bss, src);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	key_info = WPA_GET_BE16(hdr->key_info);

	if (!sta->ptk_set) {
		wpa_printf(MSG_DEBUG, "No PTK known to process EAPOL-Key 2/2");
		return;
	}

	if (sta->ptk_set &&
	    check_mic(sta->ptk.kck, key_info & WPA_KEY_INFO_TYPE_MASK,
		      data, len) < 0) {
		wpa_printf(MSG_INFO, "Mismatch in EAPOL-Key 2/2 MIC");
		return;
	}
	wpa_printf(MSG_DEBUG, "Valid MIC found in EAPOL-Key 2/2");
}


static void rx_data_eapol_key(struct wlantest *wt, const u8 *dst,
			      const u8 *src, const u8 *data, size_t len,
			      int prot)
{
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data;
	u16 key_info, key_length, ver, key_data_length;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);

	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key",
		    (const u8 *) hdr, len - sizeof(*eapol));
	if (len < sizeof(*hdr)) {
		wpa_printf(MSG_INFO, "Too short EAPOL-Key frame from " MACSTR,
			   MAC2STR(src));
		return;
	}

	if (hdr->type == EAPOL_KEY_TYPE_RC4) {
		/* TODO: EAPOL-Key RC4 for WEP */
		return;
	}

	if (hdr->type != EAPOL_KEY_TYPE_RSN &&
	    hdr->type != EAPOL_KEY_TYPE_WPA) {
		wpa_printf(MSG_DEBUG, "Unsupported EAPOL-Key type %u",
			   hdr->type);
		return;
	}

	key_info = WPA_GET_BE16(hdr->key_info);
	key_length = WPA_GET_BE16(hdr->key_length);
	key_data_length = WPA_GET_BE16(hdr->key_data_length);
	key_data = (const u8 *) (hdr + 1);
	if (key_data + key_data_length > data + len) {
		wpa_printf(MSG_INFO, "Truncated EAPOL-Key from " MACSTR,
			   MAC2STR(src));
		return;
	}
	if (key_data + key_data_length < data + len) {
		wpa_hexdump(MSG_DEBUG, "Extra data after EAPOL-Key Key Data "
			    "field", key_data + key_data_length,
			data + len - key_data - key_data_length);
	}


	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	wpa_printf(MSG_DEBUG, "EAPOL-Key ver=%u %c idx=%u%s%s%s%s%s%s%s%s "
		   "datalen=%u",
		   ver, key_info & WPA_KEY_INFO_KEY_TYPE ? 'P' : 'G',
		   (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) >>
		   WPA_KEY_INFO_KEY_INDEX_SHIFT,
		   (key_info & WPA_KEY_INFO_INSTALL) ? " Install" : "",
		   (key_info & WPA_KEY_INFO_ACK) ? " ACK" : "",
		   (key_info & WPA_KEY_INFO_MIC) ? " MIC" : "",
		   (key_info & WPA_KEY_INFO_SECURE) ? " Secure" : "",
		   (key_info & WPA_KEY_INFO_ERROR) ? " Error" : "",
		   (key_info & WPA_KEY_INFO_REQUEST) ? " Request" : "",
		   (key_info & WPA_KEY_INFO_ENCR_KEY_DATA) ? " Encr" : "",
		   (key_info & WPA_KEY_INFO_SMK_MESSAGE) ? " SMK" : "",
		   key_data_length);

	if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
	    ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES &&
	    ver != WPA_KEY_INFO_TYPE_AES_128_CMAC) {
		wpa_printf(MSG_DEBUG, "Unsupported EAPOL-Key Key Descriptor "
			   "Version %u", ver);
		return;
	}

	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Replay Counter",
		    hdr->replay_counter, WPA_REPLAY_COUNTER_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Nonce",
		    hdr->key_nonce, WPA_NONCE_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key IV",
		    hdr->key_iv, 16);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key RSC",
		    hdr->key_rsc, WPA_KEY_RSC_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key MIC",
		    hdr->key_mic, 16);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data",
		    key_data, key_data_length);

	if (key_info & (WPA_KEY_INFO_ERROR | WPA_KEY_INFO_REQUEST))
		return;

	if (key_info & WPA_KEY_INFO_SMK_MESSAGE)
		return;

	if (key_info & WPA_KEY_INFO_KEY_TYPE) {
		/* 4-Way Handshake */
		switch (key_info & (WPA_KEY_INFO_SECURE |
				    WPA_KEY_INFO_MIC |
				    WPA_KEY_INFO_ACK |
				    WPA_KEY_INFO_INSTALL)) {
		case WPA_KEY_INFO_ACK:
			rx_data_eapol_key_1_of_4(wt, dst, src, data, len);
			break;
		case WPA_KEY_INFO_MIC:
			rx_data_eapol_key_2_of_4(wt, dst, src, data, len);
			break;
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC |
			WPA_KEY_INFO_ACK | WPA_KEY_INFO_INSTALL:
			rx_data_eapol_key_3_of_4(wt, dst, src, data, len);
			break;
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC:
			rx_data_eapol_key_4_of_4(wt, dst, src, data, len);
			break;
		default:
			wpa_printf(MSG_DEBUG, "Unsupported EAPOL-Key frame");
			break;
		}
	} else {
		/* Group Key Handshake */
		switch (key_info & (WPA_KEY_INFO_SECURE |
				    WPA_KEY_INFO_MIC |
				    WPA_KEY_INFO_ACK)) {
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC |
			WPA_KEY_INFO_ACK:
			rx_data_eapol_key_1_of_2(wt, dst, src, data, len);
			break;
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC:
			rx_data_eapol_key_2_of_2(wt, dst, src, data, len);
			break;
		default:
			wpa_printf(MSG_DEBUG, "Unsupported EAPOL-Key frame");
			break;
		}
	}
}


static void rx_data_eapol(struct wlantest *wt, const u8 *dst, const u8 *src,
			  const u8 *data, size_t len, int prot)
{
	const struct ieee802_1x_hdr *hdr;
	u16 length;
	const u8 *p;

	wpa_hexdump(MSG_EXCESSIVE, "EAPOL", data, len);
	if (len < sizeof(*hdr)) {
		wpa_printf(MSG_INFO, "Too short EAPOL frame from " MACSTR,
			   MAC2STR(src));
		return;
	}

	hdr = (const struct ieee802_1x_hdr *) data;
	length = be_to_host16(hdr->length);
	wpa_printf(MSG_DEBUG, "RX EAPOL: " MACSTR " -> " MACSTR "%s ver=%u "
		   "type=%u len=%u",
		   MAC2STR(src), MAC2STR(dst), prot ? " Prot" : "",
		   hdr->version, hdr->type, length);
	if (sizeof(*hdr) + length > len) {
		wpa_printf(MSG_INFO, "Truncated EAPOL frame from " MACSTR,
			   MAC2STR(src));
		return;
	}

	if (sizeof(*hdr) + length < len) {
		wpa_printf(MSG_INFO, "EAPOL frame with %d extra bytes",
			   (int) (len - sizeof(*hdr) - length));
	}
	p = (const u8 *) (hdr + 1);

	switch (hdr->type) {
	case IEEE802_1X_TYPE_EAP_PACKET:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL - EAP packet", p, length);
		break;
	case IEEE802_1X_TYPE_EAPOL_START:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Start", p, length);
		break;
	case IEEE802_1X_TYPE_EAPOL_LOGOFF:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Logoff", p, length);
		break;
	case IEEE802_1X_TYPE_EAPOL_KEY:
		rx_data_eapol_key(wt, dst, src, data, sizeof(*hdr) + length,
				  prot);
		break;
	case IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL - Encapsulated ASF alert",
			    p, length);
		break;
	default:
		wpa_hexdump(MSG_MSGDUMP, "Unknown EAPOL payload", p, length);
		break;
	}
}


static void rx_data_eth(struct wlantest *wt, const u8 *dst, const u8 *src,
			u16 ethertype, const u8 *data, size_t len, int prot)
{
	if (ethertype == ETH_P_PAE)
		rx_data_eapol(wt, dst, src, data, len, prot);
}


static void rx_data_process(struct wlantest *wt, const u8 *dst, const u8 *src,
			    const u8 *data, size_t len, int prot)
{
	if (len == 0)
		return;

	if (len >= 8 && os_memcmp(data, "\xaa\xaa\x03\x00\x00\x00", 6) == 0) {
		rx_data_eth(wt, dst, src, WPA_GET_BE16(data + 6),
			    data + 8, len - 8, prot);
		return;
	}

	wpa_hexdump(MSG_DEBUG, "Unrecognized LLC", data, len > 8 ? 8 : len);
}


static void rx_data_bss_prot_group(struct wlantest *wt,
				   const struct ieee80211_hdr *hdr,
				   const u8 *qos, const u8 *dst, const u8 *src,
				   const u8 *data, size_t len)
{
	struct wlantest_bss *bss;
	int keyid;
	u8 *decrypted;
	size_t dlen;
	u8 pn[6];

	bss = bss_get(wt, hdr->addr2);
	if (bss == NULL)
		return;
	if (len < 4) {
		wpa_printf(MSG_INFO, "Too short group addressed data frame");
		return;
	}

	keyid = data[3] >> 6;
	if (bss->gtk_len[keyid] == 0) {
		wpa_printf(MSG_MSGDUMP, "No GTK known to decrypt the frame "
			   "(A2=" MACSTR " KeyID=%d)",
			   MAC2STR(hdr->addr2), keyid);
		return;
	}

	/* TODO: different replay protection for TKIP */
	ccmp_get_pn(pn, data);
	if (os_memcmp(pn, bss->rsc[keyid], 6) <= 0) {
		wpa_printf(MSG_INFO, "CCMP/TKIP replay detected: SA=" MACSTR,
			   MAC2STR(hdr->addr2));
		wpa_hexdump(MSG_INFO, "RX PN", pn, 6);
		wpa_hexdump(MSG_INFO, "RSC", bss->rsc[keyid], 6);
	}

	if (bss->group_cipher == WPA_CIPHER_TKIP)
		decrypted = tkip_decrypt(bss->gtk[keyid], hdr, data, len,
					 &dlen);
	else
		decrypted = ccmp_decrypt(bss->gtk[keyid], hdr, data, len,
					 &dlen);
	if (decrypted) {
		rx_data_process(wt, dst, src, decrypted, dlen, 1);
		os_memcpy(bss->rsc[keyid], pn, 6);
		write_pcap_decrypted(wt, (const u8 *) hdr, 24 + (qos ? 2 : 0),
				     decrypted, dlen);
	}
	os_free(decrypted);
}


static void rx_data_bss_prot(struct wlantest *wt,
			     const struct ieee80211_hdr *hdr, const u8 *qos,
			     const u8 *dst, const u8 *src, const u8 *data,
			     size_t len)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	int keyid;
	u16 fc = le_to_host16(hdr->frame_control);
	u8 *decrypted;
	size_t dlen;
	int tid;
	u8 pn[6], *rsc;

	if (hdr->addr1[0] & 0x01) {
		rx_data_bss_prot_group(wt, hdr, qos, dst, src, data, len);
		return;
	}

	if (fc & WLAN_FC_TODS) {
		bss = bss_get(wt, hdr->addr1);
		if (bss == NULL)
			return;
		sta = sta_get(bss, hdr->addr2);
	} else {
		bss = bss_get(wt, hdr->addr2);
		if (bss == NULL)
			return;
		sta = sta_get(bss, hdr->addr1);
	}
	if (sta == NULL || !sta->ptk_set) {
		wpa_printf(MSG_MSGDUMP, "No PTK known to decrypt the frame");
		return;
	}

	if (len < 4) {
		wpa_printf(MSG_INFO, "Too short encrypted data frame");
		return;
	}

	keyid = data[3] >> 6;
	if (keyid != 0) {
		wpa_printf(MSG_INFO, "Unexpected non-zero KeyID %d in "
			   "individually addressed Data frame from " MACSTR,
			   keyid, MAC2STR(hdr->addr2));
	}

	if (qos)
		tid = qos[0] & 0x0f;
	else
		tid = 0;
	if (fc & WLAN_FC_TODS)
		rsc = sta->rsc_tods[tid];
	else
		rsc = sta->rsc_fromds[tid];


	ccmp_get_pn(pn, data);
	if (os_memcmp(pn, rsc, 6) <= 0) {
		wpa_printf(MSG_INFO, "CCMP/TKIP replay detected: SA=" MACSTR,
			   MAC2STR(hdr->addr2));
		wpa_hexdump(MSG_INFO, "RX PN", pn, 6);
		wpa_hexdump(MSG_INFO, "RSC", rsc, 6);
	}

	if (sta->pairwise_cipher == WPA_CIPHER_TKIP)
		decrypted = tkip_decrypt(sta->ptk.tk1, hdr, data, len, &dlen);
	else
		decrypted = ccmp_decrypt(sta->ptk.tk1, hdr, data, len, &dlen);
	if (decrypted) {
		rx_data_process(wt, dst, src, decrypted, dlen, 1);
		os_memcpy(rsc, pn, 6);
		write_pcap_decrypted(wt, (const u8 *) hdr, 24 + (qos ? 2 : 0),
				     decrypted, dlen);
	}
	os_free(decrypted);
}


static void rx_data_bss(struct wlantest *wt, const struct ieee80211_hdr *hdr,
			const u8 *qos, const u8 *dst, const u8 *src,
			const u8 *data, size_t len)
{
	u16 fc = le_to_host16(hdr->frame_control);
	int prot = !!(fc & WLAN_FC_ISWEP);

	if (qos) {
		u8 ack = (qos[0] & 0x60) >> 5;
		wpa_printf(MSG_MSGDUMP, "BSS DATA: " MACSTR " -> " MACSTR
			   " len=%u%s tid=%u%s%s",
			   MAC2STR(src), MAC2STR(dst), (unsigned int) len,
			   prot ? " Prot" : "", qos[0] & 0x0f,
			   (qos[0] & 0x10) ? " EOSP" : "",
			   ack == 0 ? "" :
			   (ack == 1 ? " NoAck" :
			    (ack == 2 ? " NoExpAck" : " BA")));
	} else {
		wpa_printf(MSG_MSGDUMP, "BSS DATA: " MACSTR " -> " MACSTR
			   " len=%u%s",
			   MAC2STR(src), MAC2STR(dst), (unsigned int) len,
			   prot ? " Prot" : "");
	}

	if (prot)
		rx_data_bss_prot(wt, hdr, qos, dst, src, data, len);
	else
		rx_data_process(wt, dst, src, data, len, 0);
}


void rx_data(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_hdr *hdr;
	u16 fc, stype;
	size_t hdrlen;
	const u8 *qos = NULL;

	if (len < 24)
		return;

	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);
	hdrlen = 24;
	if ((fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)) ==
	    (WLAN_FC_TODS | WLAN_FC_FROMDS))
		hdrlen += ETH_ALEN;
	if (stype & 0x08) {
		qos = data + hdrlen;
		hdrlen += 2;
	}
	if (len < hdrlen)
		return;
	wt->rx_data++;

	switch (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)) {
	case 0:
		wpa_printf(MSG_EXCESSIVE, "DATA %s%s%s IBSS DA=" MACSTR " SA="
			   MACSTR " BSSID=" MACSTR,
			   data_stype(WLAN_FC_GET_STYPE(fc)),
			   fc & WLAN_FC_PWRMGT ? " PwrMgt" : "",
			   fc & WLAN_FC_ISWEP ? " Prot" : "",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3));
		break;
	case WLAN_FC_FROMDS:
		wpa_printf(MSG_EXCESSIVE, "DATA %s%s%s FromDS DA=" MACSTR
			   " BSSID=" MACSTR " SA=" MACSTR,
			   data_stype(WLAN_FC_GET_STYPE(fc)),
			   fc & WLAN_FC_PWRMGT ? " PwrMgt" : "",
			   fc & WLAN_FC_ISWEP ? " Prot" : "",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3));
		rx_data_bss(wt, hdr, qos, hdr->addr1, hdr->addr2,
			    data + hdrlen, len - hdrlen);
		break;
	case WLAN_FC_TODS:
		wpa_printf(MSG_EXCESSIVE, "DATA %s%s%s ToDS BSSID=" MACSTR
			   " SA=" MACSTR " DA=" MACSTR,
			   data_stype(WLAN_FC_GET_STYPE(fc)),
			   fc & WLAN_FC_PWRMGT ? " PwrMgt" : "",
			   fc & WLAN_FC_ISWEP ? " Prot" : "",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3));
		rx_data_bss(wt, hdr, qos, hdr->addr3, hdr->addr2,
			    data + hdrlen, len - hdrlen);
		break;
	case WLAN_FC_TODS | WLAN_FC_FROMDS:
		wpa_printf(MSG_EXCESSIVE, "DATA %s%s%s WDS RA=" MACSTR " TA="
			   MACSTR " DA=" MACSTR " SA=" MACSTR,
			   data_stype(WLAN_FC_GET_STYPE(fc)),
			   fc & WLAN_FC_PWRMGT ? " PwrMgt" : "",
			   fc & WLAN_FC_ISWEP ? " Prot" : "",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3),
			   MAC2STR((const u8 *) (hdr + 1)));
		break;
	}
}
