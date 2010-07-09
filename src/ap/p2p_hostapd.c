/*
 * hostapd / P2P integration
 * Copyright (c) 2009-2010, Atheros Communications
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
#include "p2p/p2p.h"
#include "hostapd.h"
#include "ap_drv_ops.h"
#include "sta_info.h"
#include "p2p_hostapd.h"


int hostapd_p2p_get_mib_sta(struct hostapd_data *hapd, struct sta_info *sta,
			    char *buf, size_t buflen)
{
	if (sta->p2p_ie == NULL)
		return 0;

	return p2p_ie_text(sta->p2p_ie, buf, buf + buflen);
}


int hostapd_p2p_set_noa(struct hostapd_data *hapd, u8 count, int start,
			int duration)
{
	wpa_printf(MSG_DEBUG, "P2P: Set NoA parameters: count=%u start=%d "
		   "duration=%d", count, start, duration);

	if (count == 0) {
		hapd->noa_enabled = 0;
		hapd->noa_start = 0;
		hapd->noa_duration = 0;
	}

	if (count != 255) {
		wpa_printf(MSG_DEBUG, "P2P: Non-periodic NoA - set "
			   "NoA parameters");
		return hostapd_driver_set_noa(hapd, count, start, duration);
	}

	hapd->noa_enabled = 1;
	hapd->noa_start = start;
	hapd->noa_duration = duration;

	if (hapd->num_sta_no_p2p == 0) {
		wpa_printf(MSG_DEBUG, "P2P: No legacy STAs connected - update "
			   "periodic NoA parameters");
		return hostapd_driver_set_noa(hapd, count, start, duration);
	}

	wpa_printf(MSG_DEBUG, "P2P: Legacy STA(s) connected - do not enable "
		   "periodic NoA");

	return 0;
}


void hostapd_p2p_non_p2p_sta_connected(struct hostapd_data *hapd)
{
	wpa_printf(MSG_DEBUG, "P2P: First non-P2P device connected");

	if (hapd->noa_enabled) {
		wpa_printf(MSG_DEBUG, "P2P: Disable periodic NoA");
		hostapd_driver_set_noa(hapd, 0, 0, 0);
	}
}


void hostapd_p2p_non_p2p_sta_disconnected(struct hostapd_data *hapd)
{
	wpa_printf(MSG_DEBUG, "P2P: Last non-P2P device disconnected");

	if (hapd->noa_enabled) {
		wpa_printf(MSG_DEBUG, "P2P: Enable periodic NoA");
		hostapd_driver_set_noa(hapd, 255, hapd->noa_start,
				       hapd->noa_duration);
	}
}
