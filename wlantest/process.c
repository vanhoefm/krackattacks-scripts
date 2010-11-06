/*
 * Received frame processing
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
#include "utils/radiotap.h"
#include "utils/radiotap_iter.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "wlantest.h"


static const char * mgmt_stype(u16 stype)
{
	switch (stype) {
	case WLAN_FC_STYPE_ASSOC_REQ:
		return "ASSOC-REQ";
	case WLAN_FC_STYPE_ASSOC_RESP:
		return "ASSOC-RESP";
	case WLAN_FC_STYPE_REASSOC_REQ:
		return "REASSOC-REQ";
	case WLAN_FC_STYPE_REASSOC_RESP:
		return "REASSOC-RESP";
	case WLAN_FC_STYPE_PROBE_REQ:
		return "PROBE-REQ";
	case WLAN_FC_STYPE_PROBE_RESP:
		return "PROBE-RESP";
	case WLAN_FC_STYPE_BEACON:
		return "BEACON";
	case WLAN_FC_STYPE_ATIM:
		return "ATIM";
	case WLAN_FC_STYPE_DISASSOC:
		return "DISASSOC";
	case WLAN_FC_STYPE_AUTH:
		return "AUTH";
	case WLAN_FC_STYPE_DEAUTH:
		return "DEAUTH";
	case WLAN_FC_STYPE_ACTION:
		return "ACTION";
	}
	return "??";
}


static void bss_update(struct wlantest_bss *bss,
		       struct ieee802_11_elems *elems)
{
	if (elems->ssid == NULL || elems->ssid_len > 32) {
		wpa_printf(MSG_INFO, "Invalid or missing SSID in a Beacon "
			   "frame for " MACSTR, MAC2STR(bss->bssid));
		bss->parse_error_reported = 1;
		return;
	}

	os_memcpy(bss->ssid, elems->ssid, elems->ssid_len);
	bss->ssid_len = elems->ssid_len;

	if (elems->rsn_ie == NULL) {
		if (bss->rsnie[0]) {
			wpa_printf(MSG_INFO, "BSS " MACSTR " - RSN IE removed",
				   MAC2STR(bss->bssid));
			bss->rsnie[0] = 0;
		}
	} else {
		if (bss->rsnie[0] == 0 ||
		    os_memcmp(bss->rsnie, elems->rsn_ie - 2,
			      elems->rsn_ie_len + 2) != 0) {
			wpa_printf(MSG_INFO, "BSS " MACSTR " - RSN IE "
				   "stored", MAC2STR(bss->bssid));
			wpa_hexdump(MSG_DEBUG, "RSN IE", elems->rsn_ie - 2,
				    elems->rsn_ie_len + 2);
		}
		os_memcpy(bss->rsnie, elems->rsn_ie - 2,
			  elems->rsn_ie_len + 2);
	}

	if (elems->wpa_ie == NULL) {
		if (bss->wpaie[0]) {
			wpa_printf(MSG_INFO, "BSS " MACSTR " - WPA IE removed",
				   MAC2STR(bss->bssid));
			bss->wpaie[0] = 0;
		}
	} else {
		if (bss->wpaie[0] == 0 ||
		    os_memcmp(bss->wpaie, elems->wpa_ie - 2,
			      elems->wpa_ie_len + 2) != 0) {
			wpa_printf(MSG_INFO, "BSS " MACSTR " - WPA IE "
				   "stored", MAC2STR(bss->bssid));
			wpa_hexdump(MSG_DEBUG, "WPA IE", elems->wpa_ie - 2,
				    elems->wpa_ie_len + 2);
		}
		os_memcpy(bss->wpaie, elems->wpa_ie - 2,
			  elems->wpa_ie_len + 2);
	}
}


static void rx_mgmt_beacon(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct ieee802_11_elems elems;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (bss->proberesp_seen)
		return; /* do not override with Beacon data */
	bss->capab_info = le_to_host16(mgmt->u.beacon.capab_info);
	if (ieee802_11_parse_elems(mgmt->u.beacon.variable,
				   len - (mgmt->u.beacon.variable - data),
				   &elems, 0) == ParseFailed) {
		if (bss->parse_error_reported)
			return;
		wpa_printf(MSG_INFO, "Invalid IEs in a Beacon frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		bss->parse_error_reported = 1;
		return;
	}

	bss_update(bss, &elems);
}


static void rx_mgmt_probe_resp(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct ieee802_11_elems elems;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;

	bss->capab_info = le_to_host16(mgmt->u.probe_resp.capab_info);
	if (ieee802_11_parse_elems(mgmt->u.probe_resp.variable,
				   len - (mgmt->u.probe_resp.variable - data),
				   &elems, 0) == ParseFailed) {
		if (bss->parse_error_reported)
			return;
		wpa_printf(MSG_INFO, "Invalid IEs in a Probe Response frame "
			   "from " MACSTR, MAC2STR(mgmt->sa));
		bss->parse_error_reported = 1;
		return;
	}

	bss_update(bss, &elems);
}


static void rx_mgmt_auth(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->da);
	else
		sta = sta_get(bss, mgmt->sa);
	if (sta == NULL)
		return;

	if (len < 24 + 6) {
		wpa_printf(MSG_INFO, "Too short Authentication frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	wpa_printf(MSG_DEBUG, "AUTH " MACSTR " -> " MACSTR
		   " (alg=%u trans=%u status=%u)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da),
		   le_to_host16(mgmt->u.auth.auth_alg),
		   le_to_host16(mgmt->u.auth.auth_transaction),
		   le_to_host16(mgmt->u.auth.status_code));
}


static void rx_mgmt(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_hdr *hdr;
	u16 fc, stype;

	if (len < 24)
		return;

	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
	wt->rx_mgmt++;
	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf((stype == WLAN_FC_STYPE_BEACON ||
		    stype == WLAN_FC_STYPE_PROBE_RESP ||
		    stype == WLAN_FC_STYPE_PROBE_REQ) ?
		   MSG_EXCESSIVE : MSG_MSGDUMP,
		   "MGMT %s%s%s DA=" MACSTR " SA=" MACSTR " BSSID=" MACSTR,
		   mgmt_stype(stype),
		   fc & WLAN_FC_PWRMGT ? " PwrMgt" : "",
		   fc & WLAN_FC_ISWEP ? " Prot" : "",
		   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
		   MAC2STR(hdr->addr3));

	switch (stype) {
	case WLAN_FC_STYPE_BEACON:
		rx_mgmt_beacon(wt, data, len);
		break;
	case WLAN_FC_STYPE_PROBE_RESP:
		rx_mgmt_probe_resp(wt, data, len);
		break;
	case WLAN_FC_STYPE_AUTH:
		rx_mgmt_auth(wt, data, len);
		break;
	}
}


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


static void rx_data(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_hdr *hdr;
	u16 fc;

	if (len < 24)
		return;

	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
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
		break;
	case WLAN_FC_TODS:
		wpa_printf(MSG_EXCESSIVE, "DATA %s%s%s ToDS BSSID=" MACSTR
			   " SA=" MACSTR " DA=" MACSTR,
			   data_stype(WLAN_FC_GET_STYPE(fc)),
			   fc & WLAN_FC_PWRMGT ? " PwrMgt" : "",
			   fc & WLAN_FC_ISWEP ? " Prot" : "",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3));
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


static void rx_frame(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_hdr *hdr;
	u16 fc;

	wpa_hexdump(MSG_EXCESSIVE, "RX frame", data, len);
	if (len < 2)
		return;

	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
	if (fc & WLAN_FC_PVER) {
		wpa_printf(MSG_DEBUG, "Drop RX frame with unexpected pver=%d",
			   fc & WLAN_FC_PVER);
		return;
	}

	switch (WLAN_FC_GET_TYPE(fc)) {
	case WLAN_FC_TYPE_MGMT:
		rx_mgmt(wt, data, len);
		break;
	case WLAN_FC_TYPE_CTRL:
		if (len < 10)
			return;
		wt->rx_ctrl++;
		break;
	case WLAN_FC_TYPE_DATA:
		rx_data(wt, data, len);
		break;
	default:
		wpa_printf(MSG_DEBUG, "Drop RX frame with unexpected type %d",
			   WLAN_FC_GET_TYPE(fc));
		break;
	}
}


static void tx_status(struct wlantest *wt, const u8 *data, size_t len, int ack)
{
	wpa_printf(MSG_DEBUG, "TX status: ack=%d", ack);
	wpa_hexdump(MSG_EXCESSIVE, "TX status frame", data, len);
}


static int check_fcs(const u8 *frame, size_t frame_len, const u8 *fcs)
{
	if (WPA_GET_LE32(fcs) != crc32(frame, frame_len))
		return -1;
	return 0;
}


void wlantest_process(struct wlantest *wt, const u8 *data, size_t len)
{
	struct ieee80211_radiotap_iterator iter;
	int ret;
	int rxflags = 0, txflags = 0, failed = 0, fcs = 0;
	const u8 *frame, *fcspos;
	size_t frame_len;

	wpa_hexdump(MSG_EXCESSIVE, "Process data", data, len);

	if (ieee80211_radiotap_iterator_init(&iter, (void *) data, len)) {
		wpa_printf(MSG_INFO, "Invalid radiotap frame");
		return;
	}

	for (;;) {
		ret = ieee80211_radiotap_iterator_next(&iter);
		wpa_printf(MSG_EXCESSIVE, "radiotap iter: %d "
			   "this_arg_index=%d", ret, iter.this_arg_index);
		if (ret == -ENOENT)
			break;
		if (ret) {
			wpa_printf(MSG_INFO, "Invalid radiotap header: %d",
				   ret);
			return;
		}
		switch (iter.this_arg_index) {
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iter.this_arg & IEEE80211_RADIOTAP_F_FCS)
				fcs = 1;
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			rxflags = 1;
			break;
		case IEEE80211_RADIOTAP_TX_FLAGS:
			txflags = 1;
			failed = le_to_host16((*(u16 *) iter.this_arg)) &
				IEEE80211_RADIOTAP_F_TX_FAIL;
			break;

		}
	}

	frame = data + iter.max_length;
	frame_len = len - iter.max_length;

	if (fcs && frame_len >= 4) {
		frame_len -= 4;
		fcspos = frame + frame_len;
		if (check_fcs(frame, frame_len, fcspos) < 0) {
			wpa_printf(MSG_EXCESSIVE, "Drop RX frame with invalid "
				   "FCS");
			wt->fcs_error++;
			return;
		}
	}

	if (rxflags && txflags)
		return;
	if (!txflags)
		rx_frame(wt, frame, frame_len);
	else
		tx_status(wt, frame, frame_len, !failed);
}
