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
