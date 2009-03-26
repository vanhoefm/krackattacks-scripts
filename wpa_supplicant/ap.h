/*
 * WPA Supplicant - Basic AP mode support routines
 * Copyright (c) 2003-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2009, Atheros Communications
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

#ifndef AP_H
#define AP_H

int wpa_supplicant_create_ap(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid);
void wpa_supplicant_ap_deinit(struct wpa_supplicant *wpa_s);

#endif /* AP_H */
