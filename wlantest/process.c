/*
 * Received frame processing
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
#include "utils/radiotap.h"
#include "utils/radiotap_iter.h"
#include "common/ieee802_11_defs.h"
#include "wlantest.h"


static void rx_frame(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_hdr *hdr;
	u16 fc;

	wpa_hexdump(MSG_EXCESSIVE, "RX frame", data, len);
	if (len < 2)
		return;

	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
	if (fc & WLAN_FC_PVER) {
		wpa_printf(MSG_DEBUG, "Drop RX frame with unexpected pver=%d",
			   fc & WLAN_FC_PVER);
		return;
	}

	switch (WLAN_FC_GET_TYPE(fc)) {
	case WLAN_FC_TYPE_MGMT:
		rx_mgmt(wt, data, len);
		break;
	case WLAN_FC_TYPE_CTRL:
		if (len < 10)
			return;
		wt->rx_ctrl++;
		break;
	case WLAN_FC_TYPE_DATA:
		rx_data(wt, data, len);
		break;
	default:
		wpa_printf(MSG_DEBUG, "Drop RX frame with unexpected type %d",
			   WLAN_FC_GET_TYPE(fc));
		break;
	}
}


static void tx_status(struct wlantest *wt, const u8 *data, size_t len, int ack)
{
	wpa_printf(MSG_DEBUG, "TX status: ack=%d", ack);
	wpa_hexdump(MSG_EXCESSIVE, "TX status frame", data, len);
}


static int check_fcs(const u8 *frame, size_t frame_len, const u8 *fcs)
{
	if (WPA_GET_LE32(fcs) != crc32(frame, frame_len))
		return -1;
	return 0;
}


void wlantest_process(struct wlantest *wt, const u8 *data, size_t len)
{
	struct ieee80211_radiotap_iterator iter;
	int ret;
	int rxflags = 0, txflags = 0, failed = 0, fcs = 0;
	const u8 *frame, *fcspos;
	size_t frame_len;

	wpa_hexdump(MSG_EXCESSIVE, "Process data", data, len);

	if (ieee80211_radiotap_iterator_init(&iter, (void *) data, len)) {
		wpa_printf(MSG_INFO, "Invalid radiotap frame");
		return;
	}

	for (;;) {
		ret = ieee80211_radiotap_iterator_next(&iter);
		wpa_printf(MSG_EXCESSIVE, "radiotap iter: %d "
			   "this_arg_index=%d", ret, iter.this_arg_index);
		if (ret == -ENOENT)
			break;
		if (ret) {
			wpa_printf(MSG_INFO, "Invalid radiotap header: %d",
				   ret);
			return;
		}
		switch (iter.this_arg_index) {
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iter.this_arg & IEEE80211_RADIOTAP_F_FCS)
				fcs = 1;
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			rxflags = 1;
			break;
		case IEEE80211_RADIOTAP_TX_FLAGS:
			txflags = 1;
			failed = le_to_host16((*(u16 *) iter.this_arg)) &
				IEEE80211_RADIOTAP_F_TX_FAIL;
			break;

		}
	}

	frame = data + iter.max_length;
	frame_len = len - iter.max_length;

	if (fcs && frame_len >= 4) {
		frame_len -= 4;
		fcspos = frame + frame_len;
		if (check_fcs(frame, frame_len, fcspos) < 0) {
			wpa_printf(MSG_EXCESSIVE, "Drop RX frame with invalid "
				   "FCS");
			wt->fcs_error++;
			return;
		}
	}

	if (rxflags && txflags)
		return;
	if (!txflags)
		rx_frame(wt, frame, frame_len);
	else
		tx_status(wt, frame, frame_len, !failed);
}
