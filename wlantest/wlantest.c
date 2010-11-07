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

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "wlantest.h"


extern int wpa_debug_level;
extern int wpa_debug_show_keys;


static void wlantest_terminate(int sig, void *signal_ctx)
{
	eloop_terminate();
}


static void usage(void)
{
	printf("wlantest [-ddhqq] [-i<ifname>] [-r<pcap file>] "
	       "[-p<passphrase>]\n"
		"         [-I<wired ifname>] [-R<wired pcap file>] "
	       "[-P<RADIUS shared secret>]\n");
}


static void passphrase_deinit(struct wlantest_passphrase *p)
{
	dl_list_del(&p->list);
	os_free(p);
}


static void secret_deinit(struct wlantest_radius_secret *r)
{
	dl_list_del(&r->list);
	os_free(r);
}


static void wlantest_init(struct wlantest *wt)
{
	os_memset(wt, 0, sizeof(*wt));
	wt->monitor_sock = -1;
	dl_list_init(&wt->passphrase);
	dl_list_init(&wt->bss);
	dl_list_init(&wt->secret);
	dl_list_init(&wt->radius);
	dl_list_init(&wt->pmk);
}


void radius_deinit(struct wlantest_radius *r)
{
	dl_list_del(&r->list);
	os_free(r);
}


static void wlantest_deinit(struct wlantest *wt)
{
	struct wlantest_bss *bss, *n;
	struct wlantest_passphrase *p, *pn;
	struct wlantest_radius_secret *s, *sn;
	struct wlantest_radius *r, *rn;
	struct wlantest_pmk *pmk, *np;

	if (wt->monitor_sock >= 0)
		monitor_deinit(wt);
	dl_list_for_each_safe(bss, n, &wt->bss, struct wlantest_bss, list)
		bss_deinit(bss);
	dl_list_for_each_safe(p, pn, &wt->passphrase,
			      struct wlantest_passphrase, list)
		passphrase_deinit(p);
	dl_list_for_each_safe(s, sn, &wt->secret,
			      struct wlantest_radius_secret, list)
		secret_deinit(s);
	dl_list_for_each_safe(r, rn, &wt->radius, struct wlantest_radius, list)
		radius_deinit(r);
	dl_list_for_each_safe(pmk, np, &wt->pmk, struct wlantest_pmk, list)
		pmk_deinit(pmk);
}


static void add_passphrase(struct wlantest *wt, const char *passphrase)
{
	struct wlantest_passphrase *p;
	size_t len = os_strlen(passphrase);

	if (len < 8 || len > 63)
		return;
	p = os_zalloc(sizeof(*p));
	if (p == NULL)
		return;
	os_memcpy(p->passphrase, passphrase, len);
	dl_list_add(&wt->passphrase, &p->list);
}


static void add_secret(struct wlantest *wt, const char *secret)
{
	struct wlantest_radius_secret *s;
	size_t len = os_strlen(secret);

	if (len >= MAX_RADIUS_SECRET_LEN)
		return;
	s = os_zalloc(sizeof(*s));
	if (s == NULL)
		return;
	os_memcpy(s->secret, secret, len);
	dl_list_add(&wt->secret, &s->list);
}


int main(int argc, char *argv[])
{
	int c;
	const char *read_file = NULL;
	const char *read_wired_file = NULL;
	const char *ifname = NULL;
	const char *ifname_wired = NULL;
	struct wlantest wt;

	wpa_debug_level = MSG_INFO;
	wpa_debug_show_keys = 1;

	if (os_program_init())
		return -1;

	wlantest_init(&wt);

	for (;;) {
		c = getopt(argc, argv, "dhi:I:p:P:qr:R:");
		if (c < 0)
			break;
		switch (c) {
		case 'd':
			if (wpa_debug_level > 0)
				wpa_debug_level--;
			break;
		case 'h':
			usage();
			return 0;
		case 'i':
			ifname = optarg;
			break;
		case 'I':
			ifname_wired = optarg;
			break;
		case 'p':
			add_passphrase(&wt, optarg);
			break;
		case 'P':
			add_secret(&wt, optarg);
			break;
		case 'q':
			wpa_debug_level++;
			break;
		case 'r':
			read_file = optarg;
			break;
		case 'R':
			read_wired_file = optarg;
			break;
		default:
			usage();
			return -1;
		}
	}

	if (ifname == NULL && ifname_wired == NULL &&
	    read_file == NULL && read_wired_file == NULL) {
		usage();
		return 0;
	}

	if (eloop_init())
		return -1;

	if (read_wired_file && read_wired_cap_file(&wt, read_wired_file) < 0)
		return -1;

	if (read_file && read_cap_file(&wt, read_file) < 0)
		return -1;

	if (ifname && monitor_init(&wt, ifname) < 0)
		return -1;

	if (ifname_wired && monitor_init_wired(&wt, ifname_wired) < 0)
		return -1;

	eloop_register_signal_terminate(wlantest_terminate, &wt);

	eloop_run();

	wpa_printf(MSG_INFO, "Processed: rx_mgmt=%u rx_ctrl=%u rx_data=%u "
		   "fcs_error=%u",
		   wt.rx_mgmt, wt.rx_ctrl, wt.rx_data, wt.fcs_error);

	wlantest_deinit(&wt);

	eloop_destroy();
	os_program_deinit();

	return 0;
}
