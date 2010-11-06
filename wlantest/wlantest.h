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
#include "common/wpa_common.h"

struct ieee802_11_elems;


struct wlantest_passphrase {
	struct dl_list list;
	char passphrase[64];
	u8 ssid[32];
	size_t ssid_len;
	u8 bssid[ETH_ALEN];
};

struct wlantest_pmk {
	struct dl_list list;
	u8 pmk[32];
};

struct wlantest_sta {
	struct dl_list list;
	u8 addr[ETH_ALEN];
	enum {
		STATE1 /* not authenticated */,
		STATE2 /* authenticated */,
		STATE3 /* associated */
	} state;
	u16 aid;
	u8 rsnie[257]; /* WPA/RSN IE */
	u8 anonce[32]; /* ANonce from the previous EAPOL-Key msg 1/4 or 3/4 */
	u8 snonce[32]; /* SNonce from the previous EAPOL-Key msg 2/4 */
	struct wpa_ptk ptk; /* Derived PTK */
	int ptk_set;
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
	struct dl_list pmk; /* struct wlantest_pmk */
};

struct wlantest {
	int monitor_sock;

	struct dl_list passphrase; /* struct wlantest_passphrase */
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
void rx_mgmt(struct wlantest *wt, const u8 *data, size_t len);
void rx_data(struct wlantest *wt, const u8 *data, size_t len);

struct wlantest_bss * bss_get(struct wlantest *wt, const u8 *bssid);
void bss_deinit(struct wlantest_bss *bss);
void bss_update(struct wlantest *wt, struct wlantest_bss *bss,
		struct ieee802_11_elems *elems);

struct wlantest_sta * sta_get(struct wlantest_bss *bss, const u8 *addr);
void sta_deinit(struct wlantest_sta *sta);
void sta_update_assoc(struct wlantest_sta *sta,
		      struct ieee802_11_elems *elems);

#endif /* WLANTEST_H */
