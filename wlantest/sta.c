/*
 * STA list
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


struct wlantest_sta * sta_get(struct wlantest_bss *bss, const u8 *addr)
{
	struct wlantest_sta *sta;

	if (addr[0] & 0x01)
		return NULL; /* Skip group addressed frames */

	dl_list_for_each(sta, &bss->sta, struct wlantest_sta, list) {
		if (os_memcmp(sta->addr, addr, ETH_ALEN) == 0)
			return sta;
	}

	sta = os_zalloc(sizeof(*sta));
	if (sta == NULL)
		return NULL;
	os_memcpy(sta->addr, addr, ETH_ALEN);
	dl_list_add(&bss->sta, &sta->list);
	wpa_printf(MSG_DEBUG, "Discovered new STA " MACSTR " in BSS " MACSTR,
		   MAC2STR(sta->addr), MAC2STR(bss->bssid));
	return sta;
}


void sta_deinit(struct wlantest_sta *sta)
{
	dl_list_del(&sta->list);
	os_free(sta);
}


void sta_update_assoc(struct wlantest_sta *sta, struct ieee802_11_elems *elems)
{
	if (elems->wpa_ie && elems->rsn_ie) {
		wpa_printf(MSG_INFO, "Both WPA IE and RSN IE included in "
			   "Association Request frame from " MACSTR,
			   MAC2STR(sta->addr));
	}

	if (elems->rsn_ie) {
		wpa_hexdump(MSG_DEBUG, "RSN IE", elems->rsn_ie - 2,
			    elems->rsn_ie_len + 2);
		os_memcpy(sta->rsnie, elems->rsn_ie - 2,
			  elems->rsn_ie_len + 2);
	} else if (elems->wpa_ie) {
		wpa_hexdump(MSG_DEBUG, "WPA IE", elems->wpa_ie - 2,
			    elems->wpa_ie_len + 2);
		os_memcpy(sta->rsnie, elems->wpa_ie - 2,
			  elems->wpa_ie_len + 2);
	} else
		sta->rsnie[0] = 0;
}
