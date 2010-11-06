/*
 * BSS list
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
#include "common/ieee802_11_common.h"
#include "wlantest.h"


struct wlantest_bss * bss_get(struct wlantest *wt, const u8 *bssid)
{
	struct wlantest_bss *bss;

	if (bssid[0] & 0x01)
		return NULL; /* Skip group addressed frames */

	dl_list_for_each(bss, &wt->bss, struct wlantest_bss, list) {
		if (os_memcmp(bss->bssid, bssid, ETH_ALEN) == 0)
			return bss;
	}

	bss = os_zalloc(sizeof(*bss));
	if (bss == NULL)
		return NULL;
	dl_list_init(&bss->sta);
	os_memcpy(bss->bssid, bssid, ETH_ALEN);
	dl_list_add(&wt->bss, &bss->list);
	wpa_printf(MSG_DEBUG, "Discovered new BSS - " MACSTR,
		   MAC2STR(bss->bssid));
	return bss;
}


void bss_deinit(struct wlantest_bss *bss)
{
	struct wlantest_sta *sta, *n;
	dl_list_for_each_safe(sta, n, &bss->sta, struct wlantest_sta, list)
		sta_deinit(sta);
	dl_list_del(&bss->list);
	os_free(bss);
}


void bss_update(struct wlantest_bss *bss, struct ieee802_11_elems *elems)
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
