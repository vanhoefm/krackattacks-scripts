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
				 const struct wpabuf *beacon,
				 const struct wpabuf *proberesp)
{
	if (hapd->driver == NULL || hapd->driver->set_ap_wps_ie == NULL)
		return 0;
	return hapd->driver->set_ap_wps_ie(hapd->conf->iface, hapd->drv_priv,
					   beacon, proberesp);
}


static int hostapd_send_mgmt_frame(struct hostapd_data *hapd, const void *msg,
			   size_t len)
{
	if (hapd->driver == NULL || hapd->driver->send_mlme == NULL)
		return 0;
	return hapd->driver->send_mlme(hapd->drv_priv, msg, len);
}


void hostapd_set_driver_ops(struct hostapd_driver_ops *ops)
{
	ops->set_ap_wps_ie = hostapd_set_ap_wps_ie;
	ops->send_mgmt_frame = hostapd_send_mgmt_frame;
}
