/*
 * wpa_supplicant - Event notifications
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
#include "config.h"
#include "wpa_supplicant_i.h"
#include "wps_supplicant.h"
#include "ctrl_iface_dbus.h"
#include "notify.h"


void wpas_notify_state_changed(struct wpa_supplicant *wpa_s,
			       wpa_states new_state, wpa_states old_state)
{
	/* notify the old DBus API */
	wpa_supplicant_dbus_notify_state_change(wpa_s, new_state,
						old_state);
}


void wpas_notify_network_changed(struct wpa_supplicant *wpa_s)
{
}


void wpas_notify_ap_scan_changed(struct wpa_supplicant *wpa_s)
{
}


void wpas_notify_bssid_changed(struct wpa_supplicant *wpa_s)
{
}


void wpas_notify_network_enabled_changed(struct wpa_supplicant *wpa_s,
					 struct wpa_ssid *ssid)
{
}


void wpas_notify_network_selected(struct wpa_supplicant *wpa_s,
				  struct wpa_ssid *ssid)
{
}


void wpas_notify_unregister_interface(struct wpa_supplicant *wpa_s)
{
	/* unregister interface in old DBus ctrl iface */
	wpas_dbus_unregister_iface(wpa_s);
}


void wpas_notify_scanning(struct wpa_supplicant *wpa_s)
{
	/* notify the old DBus API */
	wpa_supplicant_dbus_notify_scanning(wpa_s);
}


void wpas_notify_scan_done(struct wpa_supplicant *wpa_s, int success)
{
}


void wpas_notify_scan_results(struct wpa_supplicant *wpa_s)
{
	/* notify the old DBus API */
	wpa_supplicant_dbus_notify_scan_results(wpa_s);

	wpas_wps_notify_scan_results(wpa_s);
}


void wpas_notify_wps_credential(struct wpa_supplicant *wpa_s,
				const struct wps_credential *cred)
{
	/* notify the old DBus API */
	wpa_supplicant_dbus_notify_wps_cred(wpa_s, cred);
}


void wpas_notify_wps_event_m2d(struct wpa_supplicant *wpa_s,
			       struct wps_event_m2d *m2d)
{
}


void wpas_notify_wps_event_fail(struct wpa_supplicant *wpa_s,
				struct wps_event_fail *fail)
{
}


void wpas_notify_wps_event_success(struct wpa_supplicant *wpa_s)
{
}


void wpas_notify_network_added(struct wpa_supplicant *wpa_s,
			       struct wpa_ssid *ssid)
{
}


void wpas_notify_network_removed(struct wpa_supplicant *wpa_s,
				 struct wpa_ssid *ssid)
{
}


void wpas_notify_blob_added(struct wpa_supplicant *wpa_s, const char *name)
{
}


void wpas_notify_blob_removed(struct wpa_supplicant *wpa_s, const char *name)
{
}


void wpas_notify_debug_params_changed(struct wpa_global *global)
{
}
