/*
 * wlantest frame injection
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


static int inject_frame(int s, const void *data, size_t len)
{
#define	IEEE80211_RADIOTAP_F_FRAG	0x08
	unsigned char rtap_hdr[] = {
		0x00, 0x00, /* radiotap version */
		0x0e, 0x00, /* radiotap length */
		0x02, 0xc0, 0x00, 0x00, /* bmap: flags, tx and rx flags */
		IEEE80211_RADIOTAP_F_FRAG, /* F_FRAG (fragment if required) */
		0x00,       /* padding */
		0x00, 0x00, /* RX and TX flags to indicate that */
		0x00, 0x00, /* this is the injected frame directly */
	};
	struct iovec iov[2] = {
		{
			.iov_base = &rtap_hdr,
			.iov_len = sizeof(rtap_hdr),
		},
		{
			.iov_base = (void *) data,
			.iov_len = len,
		}
	};
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 2,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	int ret;

	ret = sendmsg(s, &msg, 0);
	if (ret < 0)
		perror("sendmsg");
	return ret;
}


int wlantest_inject(struct wlantest *wt, struct wlantest_bss *bss,
		    struct wlantest_sta *sta, u8 *frame, size_t len,
		    enum wlantest_inject_protection prot)
{
	int ret;

	wpa_hexdump(MSG_DEBUG, "Inject frame", frame, len);
	if (wt->monitor_sock < 0) {
		wpa_printf(MSG_INFO, "Cannot inject frames when monitor "
			   "interface is not in use");
		return -1;
	}

	/* TODO: encrypt if needed */
	if (prot != WLANTEST_INJECT_UNPROTECTED)
		return -1;

	ret = inject_frame(wt->monitor_sock, frame, len);
	return (ret < 0) ? -1 : 0;
}
