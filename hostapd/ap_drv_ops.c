/*
 * hostapd - Driver operations
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
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

#include "includes.h"

#include "common.h"
#include "hostapd.h"
#include "driver_i.h"


static int hostapd_set_ap_wps_ie(struct hostapd_data *hapd,
				 const u8 *beacon_ie, size_t beacon_ie_len,
				 const u8 *probe_resp_ie,
				 size_t probe_resp_ie_len)
{
	if (hostapd_set_wps_beacon_ie(hapd, hapd->wps_beacon_ie,
				      hapd->wps_beacon_ie_len) < 0 ||
	    hostapd_set_wps_probe_resp_ie(hapd, hapd->wps_probe_resp_ie,
					  hapd->wps_probe_resp_ie_len) < 0)
		return -1;
	return 0;
}


void hostapd_set_driver_ops(struct hostapd_driver_ops *ops)
{
	ops->set_ap_wps_ie = hostapd_set_ap_wps_ie;
}
