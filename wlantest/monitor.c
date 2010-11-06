/*
 * Linux packet socket monitor
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
#include <net/if.h>
#include <netpacket/packet.h>

#include "utils/common.h"
#include "utils/eloop.h"
#include "wlantest.h"


static void monitor_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wlantest *wt = eloop_ctx;
	u8 buf[3000];
	int len;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_INFO, "recv(PACKET): %s", strerror(errno));
		return;
	}

	wlantest_process(wt, buf, len);
}


int monitor_init(struct wlantest *wt, const char *ifname)
{
	struct sockaddr_ll ll;

	os_memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = if_nametoindex(ifname);
	if (ll.sll_ifindex == 0) {
		wpa_printf(MSG_ERROR, "Monitor interface '%s' does not exist",
			   ifname);
		return -1;
	}

	wt->monitor_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (wt->monitor_sock < 0) {
		wpa_printf(MSG_ERROR, "socket(PF_PACKET,SOCK_RAW): %s",
			   strerror(errno));
		return -1;
	}

	if (bind(wt->monitor_sock, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		wpa_printf(MSG_ERROR, "bind(PACKET): %s", strerror(errno));
		close(wt->monitor_sock);
		wt->monitor_sock = -1;
		return -1;
	}

	if (eloop_register_read_sock(wt->monitor_sock, monitor_read, wt, NULL))
	{
		wpa_printf(MSG_ERROR, "Could not register monitor read "
			   "socket");
		close(wt->monitor_sock);
		wt->monitor_sock = -1;
		return -1;
	}

	return 0;
}


void monitor_deinit(struct wlantest *wt)
{
	if (wt->monitor_sock >= 0) {
		eloop_unregister_read_sock(wt->monitor_sock);
		close(wt->monitor_sock);
		wt->monitor_sock = -1;
	}
}
