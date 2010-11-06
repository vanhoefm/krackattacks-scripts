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


void rx_data(struct wlantest *wt, const u8 *data, size_t len)
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
