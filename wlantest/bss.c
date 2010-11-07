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
#include "crypto/sha1.h"
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
	dl_list_init(&bss->pmk);
	os_memcpy(bss->bssid, bssid, ETH_ALEN);
	dl_list_add(&wt->bss, &bss->list);
	wpa_printf(MSG_DEBUG, "Discovered new BSS - " MACSTR,
		   MAC2STR(bss->bssid));
	return bss;
}


void pmk_deinit(struct wlantest_pmk *pmk)
{
	dl_list_del(&pmk->list);
	os_free(pmk);
}


void bss_deinit(struct wlantest_bss *bss)
{
	struct wlantest_sta *sta, *n;
	struct wlantest_pmk *pmk, *np;
	dl_list_for_each_safe(sta, n, &bss->sta, struct wlantest_sta, list)
		sta_deinit(sta);
	dl_list_for_each_safe(pmk, np, &bss->pmk, struct wlantest_pmk, list)
		pmk_deinit(pmk);
	dl_list_del(&bss->list);
	os_free(bss);
}


static void bss_add_pmk(struct wlantest *wt, struct wlantest_bss *bss)
{
	struct wlantest_passphrase *p;
	struct wlantest_pmk *pmk;

	dl_list_for_each(p, &wt->passphrase, struct wlantest_passphrase, list)
	{
		if (!is_zero_ether_addr(p->bssid) &&
		    os_memcmp(p->bssid, bss->bssid, ETH_ALEN) != 0)
			continue;
		if (p->ssid_len &&
		    (p->ssid_len != bss->ssid_len ||
		     os_memcmp(p->ssid, bss->ssid, p->ssid_len) != 0))
			continue;

		pmk = os_zalloc(sizeof(*pmk));
		if (pmk == NULL)
			break;
		if (pbkdf2_sha1(p->passphrase, (char *) bss->ssid,
				bss->ssid_len, 4096,
				pmk->pmk, sizeof(pmk->pmk)) < 0) {
			os_free(pmk);
			continue;
		}

		wpa_printf(MSG_INFO, "Add possible PMK for BSSID " MACSTR
			   " based on passphrase '%s'",
			   MAC2STR(bss->bssid), p->passphrase);
		wpa_hexdump(MSG_DEBUG, "Possible PMK",
			    pmk->pmk, sizeof(pmk->pmk));
		dl_list_add(&bss->pmk, &pmk->list);
	}
}


void bss_update(struct wlantest *wt, struct wlantest_bss *bss,
		struct ieee802_11_elems *elems)
{
	if (elems->ssid == NULL || elems->ssid_len > 32) {
		wpa_printf(MSG_INFO, "Invalid or missing SSID in a Beacon "
			   "frame for " MACSTR, MAC2STR(bss->bssid));
		bss->parse_error_reported = 1;
		return;
	}

	if (bss->ssid_len != elems->ssid_len ||
	    os_memcmp(bss->ssid, elems->ssid, bss->ssid_len) != 0) {
		wpa_printf(MSG_DEBUG, "Store SSID '%s' for BSSID " MACSTR,
			   wpa_ssid_txt(elems->ssid, elems->ssid_len),
			   MAC2STR(bss->bssid));
		os_memcpy(bss->ssid, elems->ssid, elems->ssid_len);
		bss->ssid_len = elems->ssid_len;
		bss_add_pmk(wt, bss);
	}


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
