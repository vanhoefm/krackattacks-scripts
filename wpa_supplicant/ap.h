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
void wpa_supplicant_ap_rx_eapol(struct wpa_supplicant *wpa_s,
				const u8 *src_addr, const u8 *buf, size_t len);
int wpa_supplicant_ap_wps_pbc(struct wpa_supplicant *wpa_s, const u8 *bssid);
int wpa_supplicant_ap_wps_pin(struct wpa_supplicant *wpa_s, const u8 *bssid,
			      const char *pin, char *buf, size_t buflen);

#endif /* AP_H */
