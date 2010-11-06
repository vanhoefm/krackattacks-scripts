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
