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
struct radius_msg;
struct ieee80211_hdr;

#define MAX_RADIUS_SECRET_LEN 128

struct wlantest_radius_secret {
	struct dl_list list;
	char secret[MAX_RADIUS_SECRET_LEN];
};

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
	u8 rsc_tods[16 + 1][6];
	u8 rsc_fromds[16 + 1][6];
	u8 ap_sa_query_tr[2];
	u8 sta_sa_query_tr[2];
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
	u8 gtk[4][32];
	size_t gtk_len[4];
	u8 rsc[4][6];
	u8 igtk[6][16];
	int igtk_set[6];
	u8 ipn[6][6];
};

struct wlantest_radius {
	struct dl_list list;
	u32 srv;
	u32 cli;
	struct radius_msg *last_req;
};

struct wlantest {
	int monitor_sock;
	int monitor_wired;

	struct dl_list passphrase; /* struct wlantest_passphrase */
	struct dl_list bss; /* struct wlantest_bss */
	struct dl_list secret; /* struct wlantest_radius_secret */
	struct dl_list radius; /* struct wlantest_radius */
	struct dl_list pmk; /* struct wlantest_pmk */

	unsigned int rx_mgmt;
	unsigned int rx_ctrl;
	unsigned int rx_data;
	unsigned int fcs_error;
};

int read_cap_file(struct wlantest *wt, const char *fname);
int read_wired_cap_file(struct wlantest *wt, const char *fname);
void wlantest_process(struct wlantest *wt, const u8 *data, size_t len);
void wlantest_process_wired(struct wlantest *wt, const u8 *data, size_t len);
u32 crc32(const u8 *frame, size_t frame_len);
int monitor_init(struct wlantest *wt, const char *ifname);
int monitor_init_wired(struct wlantest *wt, const char *ifname);
void monitor_deinit(struct wlantest *wt);
void rx_mgmt(struct wlantest *wt, const u8 *data, size_t len);
void rx_data(struct wlantest *wt, const u8 *data, size_t len);

struct wlantest_bss * bss_get(struct wlantest *wt, const u8 *bssid);
void bss_deinit(struct wlantest_bss *bss);
void bss_update(struct wlantest *wt, struct wlantest_bss *bss,
		struct ieee802_11_elems *elems);
void pmk_deinit(struct wlantest_pmk *pmk);

struct wlantest_sta * sta_get(struct wlantest_bss *bss, const u8 *addr);
void sta_deinit(struct wlantest_sta *sta);
void sta_update_assoc(struct wlantest_sta *sta,
		      struct ieee802_11_elems *elems);

u8 * ccmp_decrypt(const u8 *tk, const struct ieee80211_hdr *hdr,
		  const u8 *data, size_t data_len, size_t *decrypted_len);
void ccmp_get_pn(u8 *pn, const u8 *data);

#endif /* WLANTEST_H */
