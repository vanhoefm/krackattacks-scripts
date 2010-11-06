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


static void wlantest_terminate(int sig, void *signal_ctx)
{
	eloop_terminate();
}


static void usage(void)
{
	printf("wlantest [-ddhqq] [-i<ifname>] [-r<pcap file>]\n");
}


int main(int argc, char *argv[])
{
	int c;
	const char *read_file = NULL;
	const char *ifname = NULL;
	struct wlantest wt;

	wpa_debug_level = MSG_INFO;

	if (os_program_init())
		return -1;

	os_memset(&wt, 0, sizeof(wt));
	wt.monitor_sock = -1;

	for (;;) {
		c = getopt(argc, argv, "dhi:r:q");
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
		case 'q':
			wpa_debug_level++;
			break;
		case 'r':
			read_file = optarg;
			break;
		default:
			usage();
			return -1;
		}
	}

	if (ifname == NULL && read_file == NULL) {
		usage();
		return 0;
	}

	if (eloop_init())
		return -1;

	if (read_file && read_cap_file(&wt, read_file) < 0)
		return -1;

	if (ifname && monitor_init(&wt, ifname) < 0)
		return -1;

	eloop_register_signal_terminate(wlantest_terminate, &wt);

	eloop_run();

	wpa_printf(MSG_INFO, "Processed: rx_mgmt=%u rx_ctrl=%u rx_data=%u "
		   "fcs_error=%u",
		   wt.rx_mgmt, wt.rx_ctrl, wt.rx_data, wt.fcs_error);

	if (ifname)
		monitor_deinit(&wt);

	eloop_destroy();
	os_program_deinit();

	return 0;
}
