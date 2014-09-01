/*
 * WPA Supplicant - Basic mesh mode routines
 * Copyright (c) 2013-2014, cozybit, Inc.  All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MESH_H
#define MESH_H

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid);
int wpa_supplicant_leave_mesh(struct wpa_supplicant *wpa_s);
void wpa_supplicant_mesh_iface_deinit(struct wpa_supplicant *wpa_s,
				      struct hostapd_iface *ifmsh);

#ifdef CONFIG_MESH

void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, size_t ie_len);

#else /* CONFIG_MESH */

static inline void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s,
					const u8 *addr,
					const u8 *ies, size_t ie_len)
{
}

#endif /* CONFIG_MESH */

#endif /* MESH_H */
