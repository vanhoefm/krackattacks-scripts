/*
 * wlantest - IEEE 802.11 protocol monitoring and testing tool
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

#ifndef WLANTEST_H
#define WLANTEST_H

#include "utils/list.h"


struct wlantest_sta {
	struct dl_list list;
	u8 addr[ETH_ALEN];
};

struct wlantest_bss {
	struct dl_list list;
	u8 bssid[ETH_ALEN];
	u16 capab_info;
	u8 ssid[32];
	size_t ssid_len;
	int proberesp_seen;
	int parse_error_reported;
	u8 wpaie[257];
	u8 rsnie[257];
	struct dl_list sta; /* struct wlantest_sta */
};

struct wlantest {
	int monitor_sock;

	struct dl_list bss; /* struct wlantest_bss */

	unsigned int rx_mgmt;
	unsigned int rx_ctrl;
	unsigned int rx_data;
	unsigned int fcs_error;
};

int read_cap_file(struct wlantest *wt, const char *fname);
void wlantest_process(struct wlantest *wt, const u8 *data, size_t len);
u32 crc32(const u8 *frame, size_t frame_len);
int monitor_init(struct wlantest *wt, const char *ifname);
void monitor_deinit(struct wlantest *wt);

struct wlantest_bss * bss_get(struct wlantest *wt, const u8 *bssid);
void bss_deinit(struct wlantest_bss *bss);

struct wlantest_sta * sta_get(struct wlantest_bss *bss, const u8 *addr);
void sta_deinit(struct wlantest_sta *sta);

#endif /* WLANTEST_H */
