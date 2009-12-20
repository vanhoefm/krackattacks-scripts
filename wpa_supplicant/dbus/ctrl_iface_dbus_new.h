/*
 * WPA Supplicant / dbus-based control interface
 * Copyright (c) 2006, Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
 * Copyright (c) 2009, Witold Sowa <witold.sowa@gmail.com>
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

#ifndef CTRL_IFACE_DBUS_NEW_H
#define CTRL_IFACE_DBUS_NEW_H

struct wpa_global;
struct wpa_supplicant;
struct wpa_ssid;
struct wps_event_m2d;
struct wps_event_fail;
struct wps_credential;

enum wpas_dbus_prop {
	WPAS_DBUS_PROP_AP_SCAN,
	WPAS_DBUS_PROP_SCANNING,
	WPAS_DBUS_PROP_CURRENT_BSS,
	WPAS_DBUS_PROP_CURRENT_NETWORK,
};

struct wpas_dbus_callbacks {
	struct ctrl_iface_dbus_new_priv * (*dbus_ctrl_init)(
		struct wpa_global *global);

	void (*dbus_ctrl_deinit)(struct ctrl_iface_dbus_new_priv *iface);

	void (*signal_interface_created)(struct wpa_supplicant *wpa_s);
	void (*signal_interface_removed)(struct wpa_supplicant *wpa_s);

	int (*register_interface)(struct wpa_supplicant *wpa_s);
	int (*unregister_interface)(struct wpa_supplicant *wpa_s);

	void (*signal_scan_done)(struct wpa_supplicant *wpa_s, int success);

	void (*signal_blob_added)(struct wpa_supplicant *wpa_s,
				  const char *name);
	void (*signal_blob_removed)(struct wpa_supplicant *wpa_s,
				    const char *name);

	void (*signal_network_selected)(struct wpa_supplicant *wpa_s, int id);

	void (*signal_state_changed)(struct wpa_supplicant *wpa_s,
				     wpa_states new_state,
				     wpa_states old_state);

	int (*register_network)(struct wpa_supplicant *wpa_s,
				struct wpa_ssid *ssid);
	int (*unregister_network)(struct wpa_supplicant *wpa_s,
				  int nid);

	void (*signal_network_enabled_changed)(struct wpa_supplicant *wpa_s,
					       struct wpa_ssid *ssid);

	int (*register_bss)(struct wpa_supplicant *wpa_s, u8 bssid[ETH_ALEN]);
	int (*unregister_bss)(struct wpa_supplicant *wpa_s,
			      u8 bssid[ETH_ALEN]);

	void (*signal_prop_changed)(struct wpa_supplicant *wpa_s,
				    enum wpas_dbus_prop property);
	void (*signal_debug_params_changed)(struct wpa_global *global);

#ifdef CONFIG_WPS
	void (*signal_wps_event_success)(struct wpa_supplicant *wpa_s);
	void (*signal_wps_event_fail)(struct wpa_supplicant *wpa_s,
				      struct wps_event_fail *fail);
	void (*signal_wps_event_m2d)(struct wpa_supplicant *wpa_s,
				     struct wps_event_m2d *m2d);
	void (*signal_wps_credentials)(struct wpa_supplicant *wpa_s,
				       const struct wps_credential *cred);
#endif /* CONFIG_WPS */
};


#ifdef CONFIG_CTRL_IFACE_DBUS_NEW

#include <dbus/dbus.h>

#define WPAS_DBUS_OBJECT_PATH_MAX 150

#define WPAS_DBUS_NEW_SERVICE		"fi.w1.wpa_supplicant1"
#define WPAS_DBUS_NEW_PATH		"/fi/w1/wpa_supplicant1"
#define WPAS_DBUS_NEW_INTERFACE		"fi.w1.wpa_supplicant1"

#define WPAS_DBUS_NEW_PATH_INTERFACES	WPAS_DBUS_NEW_PATH "/Interfaces"
#define WPAS_DBUS_NEW_IFACE_INTERFACE	WPAS_DBUS_NEW_INTERFACE ".Interface"
#define WPAS_DBUS_NEW_IFACE_WPS WPAS_DBUS_NEW_IFACE_INTERFACE ".WPS"

#define WPAS_DBUS_NEW_NETWORKS_PART "Networks"
#define WPAS_DBUS_NEW_IFACE_NETWORK WPAS_DBUS_NEW_IFACE_INTERFACE ".Network"

#define WPAS_DBUS_NEW_BSSIDS_PART "BSSs"
#define WPAS_DBUS_NEW_IFACE_BSSID WPAS_DBUS_NEW_IFACE_INTERFACE ".BSS"


/* Errors */
#define WPAS_DBUS_ERROR_UNKNOWN_ERROR \
	WPAS_DBUS_NEW_INTERFACE ".UnknownError"
#define WPAS_DBUS_ERROR_INVALID_ARGS \
	WPAS_DBUS_NEW_INTERFACE ".InvalidArgs"

#define WPAS_DBUS_ERROR_IFACE_EXISTS \
	WPAS_DBUS_NEW_INTERFACE ".InterfaceExists"
#define WPAS_DBUS_ERROR_IFACE_UNKNOWN \
	WPAS_DBUS_NEW_INTERFACE ".InterfaceUnknown"

#define WPAS_DBUS_ERROR_NOT_CONNECTED \
	WPAS_DBUS_NEW_IFACE_INTERFACE ".NotConnected"
#define WPAS_DBUS_ERROR_NETWORK_UNKNOWN \
	WPAS_DBUS_NEW_IFACE_INTERFACE ".NetworkUnknown"

#define WPAS_DBUS_ERROR_BLOB_EXISTS \
	WPAS_DBUS_NEW_IFACE_INTERFACE ".BlobExists"
#define WPAS_DBUS_ERROR_BLOB_UNKNOWN \
	WPAS_DBUS_NEW_IFACE_INTERFACE ".BlobUnknown"

#define WPAS_DBUS_BSSID_FORMAT "%02x%02x%02x%02x%02x%02x"

struct wpas_dbus_callbacks * wpas_dbus_get_callbacks(void);
const char * wpas_dbus_get_path(struct wpa_supplicant *wpa_s);

#else /* CONFIG_CTRL_IFACE_DBUS_NEW */

static inline struct wpas_dbus_callbacks * wpas_dbus_get_callbacks(void)
{
	return NULL;
}

#endif /* CONFIG_CTRL_IFACE_DBUS_NEW */

#endif /* CTRL_IFACE_DBUS_H_NEW */
