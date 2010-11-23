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


static int rx_duplicate(struct wlantest *wt, const struct ieee80211_hdr *hdr,
			size_t len)
{
	u16 fc;
	int tid = 16;
	const u8 *sta_addr, *bssid;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	int to_ap;
	le16 *seq_ctrl;

	if (hdr->addr1[0] & 0x01)
		return 0; /* Ignore group addressed frames */

	fc = le_to_host16(hdr->frame_control);
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT) {
		bssid = hdr->addr3;
		if (os_memcmp(bssid, hdr->addr2, ETH_ALEN) == 0) {
			sta_addr = hdr->addr1;
			to_ap = 0;
		} else {
			if (os_memcmp(bssid, hdr->addr1, ETH_ALEN) != 0)
				return 0; /* Unsupported STA-to-STA frame */
			sta_addr = hdr->addr2;
			to_ap = 1;
		}
	} else {
		switch (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)) {
		case 0:
			return 0; /* IBSS not supported */
		case WLAN_FC_FROMDS:
			sta_addr = hdr->addr1;
			bssid = hdr->addr2;
			to_ap = 0;
			break;
		case WLAN_FC_TODS:
			sta_addr = hdr->addr2;
			bssid = hdr->addr1;
			to_ap = 1;
			break;
		case WLAN_FC_TODS | WLAN_FC_FROMDS:
			return 0; /* WDS not supported */
		default:
			return 0;
		}

		if ((WLAN_FC_GET_STYPE(fc) & 0x08) && len >= 26) {
			const u8 *qos = ((const u8 *) hdr) + 24;
			tid = qos[0] & 0x0f;
		}
	}

	bss = bss_find(wt, bssid);
	if (bss == NULL)
		return 0;
	sta = sta_find(bss, sta_addr);
	if (sta == NULL)
		return 0;

	if (to_ap)
		seq_ctrl = &sta->seq_ctrl_to_ap[tid];
	else
		seq_ctrl = &sta->seq_ctrl_to_sta[tid];

	if ((fc & WLAN_FC_RETRY) && hdr->seq_ctrl == *seq_ctrl) {
		u16 s = le_to_host16(hdr->seq_ctrl);
		wpa_printf(MSG_MSGDUMP, "Ignore duplicated frame (seq=%u "
			   "frag=%u A1=" MACSTR " A2=" MACSTR ")",
			   WLAN_GET_SEQ_SEQ(s), WLAN_GET_SEQ_FRAG(s),
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2));
		return 1;
	}

	*seq_ctrl = hdr->seq_ctrl;

	return 0;
}


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
		if (len < 24)
			break;
		if (rx_duplicate(wt, hdr, len))
			break;
		rx_mgmt(wt, data, len);
		break;
	case WLAN_FC_TYPE_CTRL:
		if (len < 10)
			break;
		wt->rx_ctrl++;
		break;
	case WLAN_FC_TYPE_DATA:
		if (len < 24)
			break;
		if (rx_duplicate(wt, hdr, len))
			break;
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
