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
