/*
 * BSS table
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
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
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "drivers/driver.h"
#include "wpa_supplicant_i.h"
#include "notify.h"
#include "bss.h"


#ifndef WPA_BSS_MAX_COUNT
#define WPA_BSS_MAX_COUNT 200
#endif /* WPA_BSS_MAX_COUNT */

/**
 * WPA_BSS_EXPIRATION_PERIOD - Period of expiration run in seconds
 */
#define WPA_BSS_EXPIRATION_PERIOD 10

/**
 * WPA_BSS_EXPIRATION_AGE - BSS entry age after which it can be expired
 *
 * This value control the time in seconds after which a BSS entry gets removed
 * if it has not been updated or is not in use.
 */
#define WPA_BSS_EXPIRATION_AGE 180

/**
 * WPA_BSS_EXPIRATION_SCAN_COUNT - Expire BSS after number of scans
 *
 * If the BSS entry has not been seen in this many scans, it will be removed.
 * Value 1 means that the entry is removed after the first scan without the
 * BSSID being seen. Larger values can be used to avoid BSS entries
 * disappearing if they are not visible in every scan (e.g., low signal quality
 * or interference).
 */
#define WPA_BSS_EXPIRATION_SCAN_COUNT 2


static void wpa_bss_remove(struct wpa_supplicant *wpa_s, struct wpa_bss *bss)
{
	dl_list_del(&bss->list);
	wpa_s->num_bss--;
	wpa_printf(MSG_DEBUG, "BSS: Remove id %u BSSID " MACSTR " SSID '%s'",
		   bss->id, MAC2STR(bss->bssid),
		   wpa_ssid_txt(bss->ssid, bss->ssid_len));
	wpas_notify_bss_removed(wpa_s, bss->bssid);
	os_free(bss);
}


static struct wpa_bss * wpa_bss_get(struct wpa_supplicant *wpa_s,
				    const u8 *bssid, const u8 *ssid,
				    size_t ssid_len)
{
	struct wpa_bss *bss;
	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		if (os_memcmp(bss->bssid, bssid, ETH_ALEN) == 0 &&
		    bss->ssid_len == ssid_len &&
		    os_memcmp(bss->ssid, ssid, ssid_len) == 0)
			return bss;
	}
	return NULL;
}


static void wpa_bss_copy_res(struct wpa_bss *dst, struct wpa_scan_res *src)
{
	os_time_t usec;

	dst->flags = src->flags;
	os_memcpy(dst->bssid, src->bssid, ETH_ALEN);
	dst->freq = src->freq;
	dst->beacon_int = src->beacon_int;
	dst->caps = src->caps;
	dst->qual = src->qual;
	dst->noise = src->noise;
	dst->level = src->level;
	dst->tsf = src->tsf;

	os_get_time(&dst->last_update);
	dst->last_update.sec -= src->age / 1000;
	usec = (src->age % 1000) * 1000;
	if (dst->last_update.usec < usec) {
		dst->last_update.sec--;
		dst->last_update.usec += 1000000;
	}
	dst->last_update.usec -= usec;
}


static void wpa_bss_add(struct wpa_supplicant *wpa_s,
			const u8 *ssid, size_t ssid_len,
			struct wpa_scan_res *res)
{
	struct wpa_bss *bss;

	bss = os_zalloc(sizeof(*bss) + res->ie_len);
	if (bss == NULL)
		return;
	bss->id = wpa_s->bss_next_id++;
	bss->last_update_idx = wpa_s->bss_update_idx;
	wpa_bss_copy_res(bss, res);
	os_memcpy(bss->ssid, ssid, ssid_len);
	bss->ssid_len = ssid_len;
	bss->ie_len = res->ie_len;
	os_memcpy(bss + 1, res + 1, res->ie_len);

	dl_list_add_tail(&wpa_s->bss, &bss->list);
	wpa_s->num_bss++;
	wpa_printf(MSG_DEBUG, "BSS: Add new id %u BSSID " MACSTR " SSID '%s'",
		   bss->id, MAC2STR(bss->bssid), wpa_ssid_txt(ssid, ssid_len));
	wpas_notify_bss_added(wpa_s, res->bssid);
	if (wpa_s->num_bss > WPA_BSS_MAX_COUNT) {
		/* Remove the oldest entry */
		wpa_bss_remove(wpa_s, dl_list_first(&wpa_s->bss,
						    struct wpa_bss, list));
	}
}


static void wpa_bss_update(struct wpa_supplicant *wpa_s, struct wpa_bss *bss,
			   struct wpa_scan_res *res)
{
	bss->scan_miss_count = 0;
	bss->last_update_idx = wpa_s->bss_update_idx;
	wpa_bss_copy_res(bss, res);
	/* Move the entry to the end of the list */
	dl_list_del(&bss->list);
	if (bss->ie_len >= res->ie_len) {
		os_memcpy(bss + 1, res + 1, res->ie_len);
		bss->ie_len = res->ie_len;
	} else {
		struct wpa_bss *nbss;
		nbss = os_realloc(bss, sizeof(*bss) + res->ie_len);
		if (nbss) {
			bss = nbss;
			os_memcpy(bss + 1, res + 1, res->ie_len);
			bss->ie_len = res->ie_len;
		}
	}
	dl_list_add_tail(&wpa_s->bss, &bss->list);
}


void wpa_bss_update_start(struct wpa_supplicant *wpa_s)
{
	wpa_s->bss_update_idx++;
	wpa_printf(MSG_DEBUG, "BSS: Start scan result update %u",
		   wpa_s->bss_update_idx);
}


void wpa_bss_update_scan_res(struct wpa_supplicant *wpa_s,
			     struct wpa_scan_res *res)
{
	const u8 *ssid;
	struct wpa_bss *bss;

	ssid = wpa_scan_get_ie(res, WLAN_EID_SSID);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "BSS: No SSID IE included for " MACSTR,
			   MAC2STR(res->bssid));
		return;
	}
	if (ssid[1] > 32) {
		wpa_printf(MSG_DEBUG, "BSS: Too long SSID IE included for "
			   MACSTR, MAC2STR(res->bssid));
		return;
	}

	/* TODO: add option for ignoring BSSes we are not interested in
	 * (to save memory) */
	bss = wpa_bss_get(wpa_s, res->bssid, ssid + 2, ssid[1]);
	if (bss == NULL)
		wpa_bss_add(wpa_s, ssid + 2, ssid[1], res);
	else
		wpa_bss_update(wpa_s, bss, res);
}


void wpa_bss_update_end(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss *bss, *n;

	/* TODO: expire only entries that were on the scanned frequencies/SSIDs
	 * list; need to get info from driver about scanned frequencies and
	 * SSIDs to be able to figure out which entries should be expired based
	 * on this */

	dl_list_for_each_safe(bss, n, &wpa_s->bss, struct wpa_bss, list) {
		if (bss->last_update_idx < wpa_s->bss_update_idx)
			bss->scan_miss_count++;
		if (bss->scan_miss_count >= WPA_BSS_EXPIRATION_SCAN_COUNT) {
			wpa_printf(MSG_DEBUG, "BSS: Expire BSS %u due to no "
				   "match in scan", bss->id);
			wpa_bss_remove(wpa_s, bss);
		}
	}
}


static void wpa_bss_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct wpa_bss *bss, *n;
	struct os_time t;

	if (dl_list_empty(&wpa_s->bss))
		return;

	os_get_time(&t);
	t.sec -= WPA_BSS_EXPIRATION_AGE;

	dl_list_for_each_safe(bss, n, &wpa_s->bss, struct wpa_bss, list) {
		if (os_memcmp(bss->bssid, wpa_s->bssid, ETH_ALEN) == 0 ||
		    os_memcmp(bss->bssid, wpa_s->pending_bssid, ETH_ALEN) == 0)
			continue; /* do not expire BSSes that are in use */

		if (os_time_before(&bss->last_update, &t)) {
			wpa_printf(MSG_DEBUG, "BSS: Expire BSS %u due to age",
				   bss->id);
			wpa_bss_remove(wpa_s, bss);
		} else
			break;
	}
	eloop_register_timeout(WPA_BSS_EXPIRATION_PERIOD, 0,
			       wpa_bss_timeout, wpa_s, NULL);
}


int wpa_bss_init(struct wpa_supplicant *wpa_s)
{
	dl_list_init(&wpa_s->bss);
	eloop_register_timeout(WPA_BSS_EXPIRATION_PERIOD, 0,
			       wpa_bss_timeout, wpa_s, NULL);
	return 0;
}


void wpa_bss_deinit(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss *bss, *n;
	eloop_cancel_timeout(wpa_bss_timeout, wpa_s, NULL);
	dl_list_for_each_safe(bss, n, &wpa_s->bss, struct wpa_bss, list)
		wpa_bss_remove(wpa_s, bss);
}
