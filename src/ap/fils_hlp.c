/*
 * FILS HLP request processing
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "sta_info.h"
#include "fils_hlp.h"


static void fils_process_hlp_req(struct hostapd_data *hapd,
				 struct sta_info *sta,
				 const u8 *pos, size_t len)
{
	const u8 *pkt, *end;

	wpa_printf(MSG_DEBUG, "FILS: HLP request from " MACSTR " (dst=" MACSTR
		   " src=" MACSTR " len=%u)",
		   MAC2STR(sta->addr), MAC2STR(pos), MAC2STR(pos + ETH_ALEN),
		   (unsigned int) len);
	if (os_memcmp(sta->addr, pos + ETH_ALEN, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG,
			   "FILS: Ignore HLP request with unexpected source address"
			   MACSTR, MAC2STR(pos + ETH_ALEN));
		return;
	}

	end = pos + len;
	pkt = pos + 2 * ETH_ALEN;
	if (end - pkt >= 6 &&
	    os_memcmp(pkt, "\xaa\xaa\x03\x00\x00\x00", 6) == 0)
		pkt += 6; /* Remove SNAP/LLC header */
	wpa_hexdump(MSG_MSGDUMP, "FILS: HLP request packet", pkt, end - pkt);
}


void fils_process_hlp(struct hostapd_data *hapd, struct sta_info *sta,
		      const u8 *pos, int left)
{
	const u8 *end = pos + left;
	u8 *tmp, *tmp_pos;

	/* Check if there are any FILS HLP Container elements */
	while (end - pos >= 2) {
		if (2 + pos[1] > end - pos)
			return;
		if (pos[0] == WLAN_EID_EXTENSION &&
		    pos[1] >= 1 + 2 * ETH_ALEN &&
		    pos[2] == WLAN_EID_EXT_FILS_HLP_CONTAINER)
			break;
		pos += 2 + pos[1];
	}
	if (end - pos < 2)
		return; /* No FILS HLP Container elements */

	tmp = os_malloc(end - pos);
	if (!tmp)
		return;

	while (end - pos >= 2) {
		if (2 + pos[1] > end - pos ||
		    pos[0] != WLAN_EID_EXTENSION ||
		    pos[1] < 1 + 2 * ETH_ALEN ||
		    pos[2] != WLAN_EID_EXT_FILS_HLP_CONTAINER)
			break;
		tmp_pos = tmp;
		os_memcpy(tmp_pos, pos + 3, pos[1] - 1);
		tmp_pos += pos[1] - 1;
		pos += 2 + pos[1];

		/* Add possible fragments */
		while (end - pos >= 2 && pos[0] == WLAN_EID_FRAGMENT &&
		       2 + pos[1] <= end - pos) {
			os_memcpy(tmp_pos, pos + 2, pos[1]);
			tmp_pos += pos[1];
			pos += 2 + pos[1];
		}

		fils_process_hlp_req(hapd, sta, tmp, tmp_pos - tmp);
	}

	os_free(tmp);
}
