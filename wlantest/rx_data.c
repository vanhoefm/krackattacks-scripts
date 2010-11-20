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
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
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

	if (bss->group_cipher & (WPA_CIPHER_TKIP | WPA_CIPHER_CCMP) &&
	    !(data[3] & 0x20)) {
		    wpa_printf(MSG_INFO, "Expected TKIP/CCMP frame from "
			       MACSTR " did not have ExtIV bit set to 1",
			       MAC2STR(bss->bssid));
		    return;
	}

	if (bss->group_cipher == WPA_CIPHER_TKIP) {
		if (data[3] & 0x1f) {
			wpa_printf(MSG_INFO, "TKIP frame from " MACSTR " used "
				   "non-zero reserved bit",
				   MAC2STR(bss->bssid));
		}
		if (data[1] != ((data[0] | 0x20) & 0x7f)) {
			wpa_printf(MSG_INFO, "TKIP frame from " MACSTR " used "
				   "incorrect WEPSeed[1] (was 0x%x, expected "
				   "0x%x)",
				   MAC2STR(bss->bssid), data[1],
				   (data[0] | 0x20) & 0x7f);
		}
	} else if (bss->group_cipher == WPA_CIPHER_CCMP) {
		if (data[2] != 0 || (data[3] & 0x1f) != 0) {
			wpa_printf(MSG_INFO, "CCMP frame from " MACSTR " used "
				   "non-zero reserved bit",
				   MAC2STR(bss->bssid));
		}
	}

	keyid = data[3] >> 6;
	if (bss->gtk_len[keyid] == 0) {
		wpa_printf(MSG_MSGDUMP, "No GTK known to decrypt the frame "
			   "(A2=" MACSTR " KeyID=%d)",
			   MAC2STR(hdr->addr2), keyid);
		return;
	}

	if (bss->group_cipher == WPA_CIPHER_TKIP)
		tkip_get_pn(pn, data);
	else
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

	if (sta->pairwise_cipher & (WPA_CIPHER_TKIP | WPA_CIPHER_CCMP) &&
	    !(data[3] & 0x20)) {
		    wpa_printf(MSG_INFO, "Expected TKIP/CCMP frame from "
			       MACSTR " did not have ExtIV bit set to 1",
			       MAC2STR(src));
		    return;
	}

	if (sta->pairwise_cipher == WPA_CIPHER_TKIP) {
		if (data[3] & 0x1f) {
			wpa_printf(MSG_INFO, "TKIP frame from " MACSTR " used "
				   "non-zero reserved bit",
				   MAC2STR(hdr->addr2));
		}
		if (data[1] != ((data[0] | 0x20) & 0x7f)) {
			wpa_printf(MSG_INFO, "TKIP frame from " MACSTR " used "
				   "incorrect WEPSeed[1] (was 0x%x, expected "
				   "0x%x)",
				   MAC2STR(hdr->addr2), data[1],
				   (data[0] | 0x20) & 0x7f);
		}
	} else if (sta->pairwise_cipher == WPA_CIPHER_CCMP) {
		if (data[2] != 0 || (data[3] & 0x1f) != 0) {
			wpa_printf(MSG_INFO, "CCMP frame from " MACSTR " used "
				   "non-zero reserved bit",
				   MAC2STR(hdr->addr2));
		}
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


	if (sta->pairwise_cipher == WPA_CIPHER_TKIP)
		tkip_get_pn(pn, data);
	else
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
