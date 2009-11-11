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
#include "ctrl_iface_dbus_new.h"
#include "notify.h"

int wpas_notify_supplicant_initialized(struct wpa_global *global)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();

	if (global->params.dbus_ctrl_interface) {
		global->dbus_ctrl_iface =
			wpa_supplicant_dbus_ctrl_iface_init(global);
		if (global->dbus_ctrl_iface == NULL)
			return -1;

		if (cbs) {
			global->dbus_new_ctrl_iface =
				cbs->dbus_ctrl_init(global);
			if (global->dbus_new_ctrl_iface == NULL)
				return -1;
		}
	}

	return 0;
}


void wpas_notify_supplicant_deinitialized(struct wpa_global *global)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();

	if (global->dbus_ctrl_iface)
		wpa_supplicant_dbus_ctrl_iface_deinit(global->dbus_ctrl_iface);

	if (cbs && global->dbus_new_ctrl_iface)
		cbs->dbus_ctrl_deinit(global->dbus_new_ctrl_iface);
}


int wpas_notify_iface_added(struct wpa_supplicant *wpa_s)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();

	if (wpas_dbus_register_iface(wpa_s))
		return -1;

	if (cbs && cbs->register_interface(wpa_s))
		return -1;

	return 0;
}



void wpas_notify_iface_removed(struct wpa_supplicant *wpa_s)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();

	/* unregister interface in old DBus ctrl iface */
	wpas_dbus_unregister_iface(wpa_s);

	/* unregister interface in new DBus ctrl iface */
	if (cbs)
		cbs->unregister_interface(wpa_s);
}


void wpas_notify_state_changed(struct wpa_supplicant *wpa_s,
			       wpa_states new_state, wpa_states old_state)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();

	/* notify the old DBus API */
	wpa_supplicant_dbus_notify_state_change(wpa_s, new_state,
						old_state);

	/* notify the new DBus API */
	if (cbs)
		cbs->signal_state_changed(wpa_s, new_state, old_state);
}


void wpas_notify_network_changed(struct wpa_supplicant *wpa_s)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_prop_changed(wpa_s,
					 WPAS_DBUS_PROP_CURRENT_NETWORK);
}


void wpas_notify_ap_scan_changed(struct wpa_supplicant *wpa_s)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_prop_changed(wpa_s, WPAS_DBUS_PROP_AP_SCAN);
}


void wpas_notify_bssid_changed(struct wpa_supplicant *wpa_s)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_prop_changed(wpa_s, WPAS_DBUS_PROP_CURRENT_BSS);
}


void wpas_notify_network_enabled_changed(struct wpa_supplicant *wpa_s,
					 struct wpa_ssid *ssid)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_network_enabled_changed(wpa_s, ssid);
}


void wpas_notify_network_selected(struct wpa_supplicant *wpa_s,
				  struct wpa_ssid *ssid)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_network_selected(wpa_s, ssid->id);
}


void wpas_notify_scanning(struct wpa_supplicant *wpa_s)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	/* notify the old DBus API */
	wpa_supplicant_dbus_notify_scanning(wpa_s);
	/* notify the new DBus API */
	if (cbs)
		cbs->signal_prop_changed(wpa_s, WPAS_DBUS_PROP_SCANNING);
}


void wpas_notify_scan_done(struct wpa_supplicant *wpa_s, int success)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_scan_done(wpa_s, success);
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
#ifdef CONFIG_WPS
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
#endif /* CONFIG_WPS */

	/* notify the old DBus API */
	wpa_supplicant_dbus_notify_wps_cred(wpa_s, cred);
	/* notify the new DBus API */
#ifdef CONFIG_WPS
	if (cbs)
		cbs->signal_wps_credentials(wpa_s, cred);
#endif /* CONFIG_WPS */
}


void wpas_notify_wps_event_m2d(struct wpa_supplicant *wpa_s,
			       struct wps_event_m2d *m2d)
{
#ifdef CONFIG_WPS
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_wps_event_m2d(wpa_s, m2d);
#endif /* CONFIG_WPS */
}


void wpas_notify_wps_event_fail(struct wpa_supplicant *wpa_s,
				struct wps_event_fail *fail)
{
#ifdef CONFIG_WPS
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_wps_event_fail(wpa_s, fail);
#endif /* CONFIG_WPS */
}


void wpas_notify_wps_event_success(struct wpa_supplicant *wpa_s)
{
#ifdef CONFIG_WPS
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_wps_event_success(wpa_s);
#endif /* CONFIG_WPS */
}


void wpas_notify_network_added(struct wpa_supplicant *wpa_s,
			       struct wpa_ssid *ssid)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (wpa_s->global->dbus_new_ctrl_iface && cbs)
		cbs->register_network(wpa_s, ssid);
}


void wpas_notify_network_removed(struct wpa_supplicant *wpa_s,
				 struct wpa_ssid *ssid)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (wpa_s->global->dbus_new_ctrl_iface && cbs)
		cbs->unregister_network(wpa_s, ssid->id);
}


void wpas_notify_bss_added(struct wpa_supplicant *wpa_s,
				 u8 bssid[])
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->register_bss(wpa_s, bssid);
}


void wpas_notify_bss_removed(struct wpa_supplicant *wpa_s,
				 u8 bssid[])
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->unregister_bss(wpa_s, bssid);
}


void wpas_notify_blob_added(struct wpa_supplicant *wpa_s, const char *name)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_blob_added(wpa_s, name);
}


void wpas_notify_blob_removed(struct wpa_supplicant *wpa_s, const char *name)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_blob_removed(wpa_s, name);
}


void wpas_notify_debug_params_changed(struct wpa_global *global)
{
	struct wpas_dbus_callbacks *cbs = wpas_dbus_get_callbacks();
	if (cbs)
		cbs->signal_debug_params_changed(global);
}
