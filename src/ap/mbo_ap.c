/*
 * hostapd - MBO
 * Copyright (c) 2016, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "sta_info.h"
#include "mbo_ap.h"


void mbo_ap_check_sta_assoc(struct hostapd_data *hapd, struct sta_info *sta,
			    struct ieee802_11_elems *elems)
{
	const u8 *pos, *attr;
	size_t len;

	if (!hapd->conf->mbo_enabled || !elems->mbo)
		return;

	pos = elems->mbo + 4;
	len = elems->mbo_len - 4;
	wpa_hexdump(MSG_DEBUG, "MBO: Association Request attributes", pos, len);

	attr = get_ie(pos, len, MBO_ATTR_ID_CELL_DATA_CAPA);
	if (attr && attr[1] >= 1)
		sta->cell_capa = attr[2];
}


int mbo_ap_get_info(struct sta_info *sta, char *buf, size_t buflen)
{
	int ret;

	if (!sta->cell_capa)
		return 0;

	ret = os_snprintf(buf, buflen, "mbo_cell_capa=%u\n", sta->cell_capa);
	if (os_snprintf_error(buflen, ret))
		return 0;
	return ret;
}


static void mbo_ap_wnm_notif_req_cell_capa(struct sta_info *sta,
					   const u8 *buf, size_t len)
{
	if (len < 1)
		return;
	wpa_printf(MSG_DEBUG, "MBO: STA " MACSTR
		   " updated cellular data capability: %u",
		   MAC2STR(sta->addr), buf[0]);
	sta->cell_capa = buf[0];
}


static void mbo_ap_wnm_notif_req_elem(struct sta_info *sta, u8 type,
				      const u8 *buf, size_t len)
{
	switch (type) {
	case WFA_WNM_NOTIF_SUBELEM_CELL_DATA_CAPA:
		mbo_ap_wnm_notif_req_cell_capa(sta, buf, len);
		break;
	default:
		wpa_printf(MSG_DEBUG,
			   "MBO: Ignore unknown WNM Notification WFA subelement %u",
			   type);
		break;
	}
}


void mbo_ap_wnm_notification_req(struct hostapd_data *hapd, const u8 *addr,
				 const u8 *buf, size_t len)
{
	const u8 *pos, *end;
	u8 ie_len;
	struct sta_info *sta;

	if (!hapd->conf->mbo_enabled)
		return;

	sta = ap_get_sta(hapd, addr);
	if (!sta)
		return;

	pos = buf;
	end = buf + len;

	while (end - pos > 1) {
		ie_len = pos[1];

		if (2 + ie_len > end - pos)
			break;

		if (pos[0] == WLAN_EID_VENDOR_SPECIFIC &&
		    ie_len >= 4 && WPA_GET_BE24(pos + 2) == OUI_WFA)
			mbo_ap_wnm_notif_req_elem(sta, pos[5],
						  pos + 6, ie_len - 4);
		else
			wpa_printf(MSG_DEBUG,
				   "MBO: Ignore unknown WNM Notification element %u (len=%u)",
				   pos[0], pos[1]);

		pos += 2 + pos[1];
	}
}
