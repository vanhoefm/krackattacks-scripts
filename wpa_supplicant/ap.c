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

#include "includes.h"

#include "common.h"
#include "../hostapd/hostapd.h"
#include "../hostapd/config.h"
#include "../hostapd/driver.h"
#include "eap_common/eap_defs.h"
#include "eap_server/eap_methods.h"
#include "eap_common/eap_wsc_common.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "ap.h"


int hostapd_for_each_interface(int (*cb)(struct hostapd_iface *iface,
					 void *ctx), void *ctx)
{
	/* TODO */
	return 0;
}


int hostapd_ctrl_iface_init(struct hostapd_data *hapd)
{
	return 0;
}


void hostapd_ctrl_iface_deinit(struct hostapd_data *hapd)
{
}


struct ap_driver_data {
	struct hostapd_data *hapd;
};


static void * ap_driver_init(struct hostapd_data *hapd)
{
	struct ap_driver_data *drv;

	drv = os_zalloc(sizeof(struct ap_driver_data));
	if (drv == NULL) {
		wpa_printf(MSG_ERROR, "Could not allocate memory for AP "
			   "driver data");
		return NULL;
	}
	drv->hapd = hapd;

	return drv;
}


static void ap_driver_deinit(void *priv)
{
	struct ap_driver_data *drv = priv;

	os_free(drv);
}


static int ap_driver_send_ether(void *priv, const u8 *dst, const u8 *src,
				u16 proto, const u8 *data, size_t data_len)
{
	return 0;
}


static struct hapd_driver_ops ap_driver_ops =
{
	.name = "wpa_supplicant",
	.init = ap_driver_init,
	.deinit = ap_driver_deinit,
	.send_ether = ap_driver_send_ether,
};

struct hapd_driver_ops *hostapd_drivers[] =
{
	&ap_driver_ops,
	NULL
};

int wpa_supplicant_create_ap(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid)
{
	struct wpa_driver_associate_params params;
	struct hostapd_iface *hapd_iface;
	struct hostapd_config *conf;
	size_t i;

	if (ssid->ssid == NULL || ssid->ssid_len == 0) {
		wpa_printf(MSG_ERROR, "No SSID configured for AP mode");
		return -1;
	}

	wpa_supplicant_ap_deinit(wpa_s);
	wpa_s->ap_iface = hapd_iface = os_zalloc(sizeof(*wpa_s->ap_iface));
	if (hapd_iface == NULL)
		return -1;

	wpa_s->ap_iface->conf = conf = hostapd_config_defaults();
	if (conf == NULL) {
		wpa_supplicant_ap_deinit(wpa_s);
		return -1;
	}

	hapd_iface->num_bss = conf->num_bss;
	hapd_iface->bss = os_zalloc(conf->num_bss *
				    sizeof(struct hostapd_data *));
	if (hapd_iface->bss == NULL) {
		wpa_supplicant_ap_deinit(wpa_s);
		return -1;
	}

	for (i = 0; i < conf->num_bss; i++) {
		hapd_iface->bss[i] =
			hostapd_alloc_bss_data(hapd_iface, conf,
					       &conf->bss[i]);
		if (hapd_iface->bss[i] == NULL) {
			wpa_supplicant_ap_deinit(wpa_s);
			return -1;
		}
	}

	if (hostapd_setup_interface(wpa_s->ap_iface)) {
		wpa_printf(MSG_ERROR, "Failed to initialize AP interface");
		wpa_supplicant_ap_deinit(wpa_s);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "Setting up AP (SSID='%s')",
		   wpa_ssid_txt(ssid->ssid, ssid->ssid_len));

	os_memset(&params, 0, sizeof(params));
	params.ssid = ssid->ssid;
	params.ssid_len = ssid->ssid_len;
	params.mode = ssid->mode;

	if (wpa_drv_associate(wpa_s, &params) < 0) {
		wpa_msg(wpa_s, MSG_INFO, "Failed to start AP functionality");
		return -1;
	}

	return 0;
}


void wpa_supplicant_ap_deinit(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->ap_iface == NULL)
		return;

	hostapd_interface_deinit(wpa_s->ap_iface);
	wpa_s->ap_iface = NULL;
}
