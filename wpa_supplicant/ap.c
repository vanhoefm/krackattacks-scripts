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
#ifdef NEED_AP_MLME
#include "../hostapd/ieee802_11.h"
#endif /* NEED_AP_MLME */
#include "../hostapd/wps_hostapd.h"
#include "../hostapd/ctrl_iface_ap.h"
#include "eap_common/eap_defs.h"
#include "eap_server/eap_methods.h"
#include "eap_common/eap_wsc_common.h"
#include "wps/wps.h"
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


static void * ap_driver_init(struct hostapd_data *hapd,
			     struct wpa_init_params *params)
{
	struct ap_driver_data *drv;
	struct wpa_supplicant *wpa_s = hapd->iface->owner;

	drv = os_zalloc(sizeof(struct ap_driver_data));
	if (drv == NULL) {
		wpa_printf(MSG_ERROR, "Could not allocate memory for AP "
			   "driver data");
		return NULL;
	}
	drv->hapd = hapd;
	os_memcpy(hapd->own_addr, wpa_s->own_addr, ETH_ALEN);

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
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_set_key(const char *iface, void *priv, wpa_alg alg,
			     const u8 *addr, int key_idx, int set_tx,
			     const u8 *seq, size_t seq_len, const u8 *key,
			     size_t key_len)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_set_key(wpa_s, alg, addr, key_idx, set_tx, seq, seq_len,
			       key, key_len);
}


static int ap_driver_get_seqnum(const char *iface, void *priv, const u8 *addr,
				int idx, u8 *seq)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_flush(void *priv)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_read_sta_data(void *priv,
				   struct hostap_sta_driver_data *data,
				   const u8 *addr)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_sta_set_flags(void *priv, const u8 *addr, int total_flags,
				   int flags_or, int flags_and)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_sta_set_flags(wpa_s, addr, total_flags, flags_or,
				     flags_and);
}


static int ap_driver_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
				int reason)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_sta_disassoc(void *priv, const u8 *own_addr,
				  const u8 *addr, int reason)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_sta_remove(void *priv, const u8 *addr)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_sta_remove(wpa_s, addr);
}


static int ap_driver_send_mlme(void *priv, const u8 *data, size_t len)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_send_mlme(wpa_s, data, len);
}


static int ap_driver_sta_add(const char *ifname, void *priv,
			     struct hostapd_sta_add_params *params)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_sta_add(wpa_s, params);
}


static int ap_driver_get_inact_sec(void *priv, const u8 *addr)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_set_freq(void *priv, struct hostapd_freq_params *freq)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return 0;
}


static int ap_driver_set_beacon(const char *iface, void *priv,
				const u8 *head, size_t head_len,
				const u8 *tail, size_t tail_len,
				int dtim_period)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_set_beacon(wpa_s, head, head_len, tail, tail_len,
				  dtim_period);
}


static int ap_driver_set_beacon_int(void *priv, int value)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_set_beacon_int(wpa_s, value);
}


static int ap_driver_set_cts_protect(void *priv, int value)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_set_preamble(void *priv, int value)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_set_short_slot_time(void *priv, int value)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static int ap_driver_set_tx_queue_params(void *priv, int queue, int aifs,
					 int cw_min, int cw_max,
					 int burst_time)
{
	wpa_printf(MSG_DEBUG, "AP TODO: %s", __func__);
	return -1;
}


static struct hostapd_hw_modes *ap_driver_get_hw_feature_data(void *priv,
							      u16 *num_modes,
							      u16 *flags)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_get_hw_feature_data(wpa_s, num_modes, flags);
}


static int ap_driver_hapd_send_eapol(void *priv, const u8 *addr,
				     const u8 *data, size_t data_len,
				     int encrypt, const u8 *own_addr)
{
	struct ap_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = drv->hapd->iface->owner;
	return wpa_drv_hapd_send_eapol(wpa_s, addr, data, data_len, encrypt,
				       own_addr);
}


struct wpa_driver_ops ap_driver_ops =
{
	.name = "wpa_supplicant",
	.hapd_init = ap_driver_init,
	.hapd_deinit = ap_driver_deinit,
	.send_ether = ap_driver_send_ether,
	.hapd_set_key = ap_driver_set_key,
	.get_seqnum = ap_driver_get_seqnum,
	.flush = ap_driver_flush,
	.read_sta_data = ap_driver_read_sta_data,
	.sta_set_flags = ap_driver_sta_set_flags,
	.sta_deauth = ap_driver_sta_deauth,
	.sta_disassoc = ap_driver_sta_disassoc,
	.sta_remove = ap_driver_sta_remove,
	.send_mlme = ap_driver_send_mlme,
	.sta_add = ap_driver_sta_add,
	.get_inact_sec = ap_driver_get_inact_sec,
	.set_freq = ap_driver_set_freq,
	.hapd_set_beacon = ap_driver_set_beacon,
	.set_beacon_int = ap_driver_set_beacon_int,
	.set_cts_protect = ap_driver_set_cts_protect,
	.set_preamble = ap_driver_set_preamble,
	.set_short_slot_time = ap_driver_set_short_slot_time,
	.set_tx_queue_params = ap_driver_set_tx_queue_params,
	.get_hw_feature_data = ap_driver_get_hw_feature_data,
	.hapd_send_eapol = ap_driver_hapd_send_eapol,
};


extern struct wpa_driver_ops *wpa_drivers[];

static int wpa_supplicant_conf_ap(struct wpa_supplicant *wpa_s,
				  struct wpa_ssid *ssid,
				  struct hostapd_config *conf)
{
	struct hostapd_bss_config *bss = &conf->bss[0];
	int j, pairwise;

	for (j = 0; wpa_drivers[j]; j++) {
		if (os_strcmp("wpa_supplicant", wpa_drivers[j]->name) == 0) {
			conf->driver = wpa_drivers[j];
			break;
		}
	}
	if (conf->driver == NULL) {
		wpa_printf(MSG_ERROR, "No AP driver ops found");
		return -1;
	}

	os_strlcpy(bss->iface, wpa_s->ifname, sizeof(bss->iface));

	if (ssid->frequency == 0) {
		/* default channel 11 */
		conf->hw_mode = HOSTAPD_MODE_IEEE80211G;
		conf->channel = 11;
	} else if (ssid->frequency >= 2412 && ssid->frequency <= 2472) {
		conf->hw_mode = HOSTAPD_MODE_IEEE80211G;
		conf->channel = (ssid->frequency - 2407) / 5;
	} else if ((ssid->frequency >= 5180 && ssid->frequency <= 5240) ||
		   (ssid->frequency >= 5745 && ssid->frequency <= 5825)) {
		conf->hw_mode = HOSTAPD_MODE_IEEE80211A;
		conf->channel = (ssid->frequency - 5000) / 5;
	} else {
		wpa_printf(MSG_ERROR, "Unsupported AP mode frequency: %d MHz",
			   ssid->frequency);
		return -1;
	}

	/* TODO: enable HT if driver supports it;
	 * drop to 11b if driver does not support 11g */

	if (ssid->ssid_len == 0) {
		wpa_printf(MSG_ERROR, "No SSID configured for AP mode");
		return -1;
	}
	os_memcpy(bss->ssid.ssid, ssid->ssid, ssid->ssid_len);
	bss->ssid.ssid[ssid->ssid_len] = '\0';
	bss->ssid.ssid_len = ssid->ssid_len;
	bss->ssid.ssid_set = 1;

	if (wpa_key_mgmt_wpa_psk(ssid->key_mgmt))
		bss->wpa = ssid->proto;
	bss->wpa_key_mgmt = ssid->key_mgmt;
	bss->wpa_pairwise = ssid->pairwise_cipher;
	if (ssid->passphrase) {
		bss->ssid.wpa_passphrase = os_strdup(ssid->passphrase);
	} else if (ssid->psk_set) {
		os_free(bss->ssid.wpa_psk);
		bss->ssid.wpa_psk = os_zalloc(sizeof(struct hostapd_wpa_psk));
		if (bss->ssid.wpa_psk == NULL)
			return -1;
		os_memcpy(bss->ssid.wpa_psk->psk, ssid->psk, PMK_LEN);
		bss->ssid.wpa_psk->group = 1;
	}

	/* Select group cipher based on the enabled pairwise cipher suites */
	pairwise = 0;
	if (bss->wpa & 1)
		pairwise |= bss->wpa_pairwise;
	if (bss->wpa & 2) {
		if (bss->rsn_pairwise == 0)
			bss->rsn_pairwise = bss->wpa_pairwise;
		pairwise |= bss->rsn_pairwise;
	}
	if (pairwise & WPA_CIPHER_TKIP)
		bss->wpa_group = WPA_CIPHER_TKIP;
	else
		bss->wpa_group = WPA_CIPHER_CCMP;

	if (bss->wpa && bss->ieee802_1x)
		bss->ssid.security_policy = SECURITY_WPA;
	else if (bss->wpa)
		bss->ssid.security_policy = SECURITY_WPA_PSK;
	else if (bss->ieee802_1x) {
		bss->ssid.security_policy = SECURITY_IEEE_802_1X;
		bss->ssid.wep.default_len = bss->default_wep_key_len;
	} else if (bss->ssid.wep.keys_set)
		bss->ssid.security_policy = SECURITY_STATIC_WEP;
	else
		bss->ssid.security_policy = SECURITY_PLAINTEXT;

#ifdef CONFIG_WPS
	/*
	 * Enable WPS by default, but require user interaction to actually use
	 * it. Only the internal Registrar is supported.
	 */
	bss->eap_server = 1;
	bss->wps_state = 2;
	bss->ap_setup_locked = 1;
	bss->config_methods = os_strdup("display push_button");
#endif /* CONFIG_WPS */

	return 0;
}


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

	wpa_printf(MSG_DEBUG, "Setting up AP (SSID='%s')",
		   wpa_ssid_txt(ssid->ssid, ssid->ssid_len));

	os_memset(&params, 0, sizeof(params));
	params.ssid = ssid->ssid;
	params.ssid_len = ssid->ssid_len;
	params.mode = ssid->mode;
	params.freq = ssid->frequency;

	if (wpa_drv_associate(wpa_s, &params) < 0) {
		wpa_msg(wpa_s, MSG_INFO, "Failed to start AP functionality");
		return -1;
	}

	wpa_s->ap_iface = hapd_iface = os_zalloc(sizeof(*wpa_s->ap_iface));
	if (hapd_iface == NULL)
		return -1;
	hapd_iface->owner = wpa_s;

	wpa_s->ap_iface->conf = conf = hostapd_config_defaults();
	if (conf == NULL) {
		wpa_supplicant_ap_deinit(wpa_s);
		return -1;
	}

	if (wpa_supplicant_conf_ap(wpa_s, ssid, conf)) {
		wpa_printf(MSG_ERROR, "Failed to create AP configuration");
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

		hapd_iface->bss[i]->msg_ctx = wpa_s;
	}

	if (hostapd_setup_interface(wpa_s->ap_iface)) {
		wpa_printf(MSG_ERROR, "Failed to initialize AP interface");
		wpa_supplicant_ap_deinit(wpa_s);
		return -1;
	}

	wpa_s->current_ssid = ssid;
	os_memcpy(wpa_s->bssid, wpa_s->own_addr, ETH_ALEN);
	wpa_supplicant_set_state(wpa_s, WPA_COMPLETED);

	return 0;
}


void wpa_supplicant_ap_deinit(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->ap_iface == NULL)
		return;

	hostapd_interface_deinit(wpa_s->ap_iface);
	wpa_s->ap_iface = NULL;
}


void ap_tx_status(void *ctx, const u8 *addr,
		  const u8 *buf, size_t len, int ack)
{
	struct wpa_supplicant *wpa_s = ctx;
	hostapd_tx_status(wpa_s->ap_iface->bss[0], addr, buf, len, ack);
}


void ap_rx_from_unknown_sta(void *ctx, struct ieee80211_hdr *hdr, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;
	hostapd_rx_from_unknown_sta(wpa_s->ap_iface->bss[0], hdr, len);
}


#ifdef NEED_AP_MLME
void ap_mgmt_rx(void *ctx, u8 *buf, size_t len, u16 stype,
		struct hostapd_frame_info *fi)
{
	struct wpa_supplicant *wpa_s = ctx;
	ieee802_11_mgmt(wpa_s->ap_iface->bss[0], buf, len, stype, fi);
}


void ap_mgmt_tx_cb(void *ctx, u8 *buf, size_t len, u16 stype, int ok)
{
	struct wpa_supplicant *wpa_s = ctx;
	ieee802_11_mgmt_cb(wpa_s->ap_iface->bss[0], buf, len, stype, ok);
}
#endif /* NEED_AP_MLME */


void wpa_supplicant_ap_rx_eapol(struct wpa_supplicant *wpa_s,
				const u8 *src_addr, const u8 *buf, size_t len)
{
	hostapd_eapol_receive(wpa_s->ap_iface->bss[0], src_addr, buf, len);
}


#ifdef CONFIG_WPS

int wpa_supplicant_ap_wps_pbc(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	return hostapd_wps_button_pushed(wpa_s->ap_iface->bss[0]);
}


int wpa_supplicant_ap_wps_pin(struct wpa_supplicant *wpa_s, const u8 *bssid,
			      const char *pin, char *buf, size_t buflen)
{
	int ret, ret_len = 0;

	if (pin == NULL) {
		unsigned int rpin = wps_generate_pin();
		ret_len = os_snprintf(buf, buflen, "%d", rpin);
		pin = buf;
	}

	ret = hostapd_wps_add_pin(wpa_s->ap_iface->bss[0], "any", pin, 0);
	if (ret)
		return -1;
	return ret_len;
}

#endif /* CONFIG_WPS */


#ifdef CONFIG_CTRL_IFACE

int ap_ctrl_iface_sta_first(struct wpa_supplicant *wpa_s,
			    char *buf, size_t buflen)
{
	if (wpa_s->ap_iface == NULL)
		return -1;
	return hostapd_ctrl_iface_sta_first(wpa_s->ap_iface->bss[0],
					    buf, buflen);
}


int ap_ctrl_iface_sta(struct wpa_supplicant *wpa_s, const char *txtaddr,
		      char *buf, size_t buflen)
{
	if (wpa_s->ap_iface == NULL)
		return -1;
	return hostapd_ctrl_iface_sta(wpa_s->ap_iface->bss[0], txtaddr,
				      buf, buflen);
}


int ap_ctrl_iface_sta_next(struct wpa_supplicant *wpa_s, const char *txtaddr,
			   char *buf, size_t buflen)
{
	if (wpa_s->ap_iface == NULL)
		return -1;
	return hostapd_ctrl_iface_sta_next(wpa_s->ap_iface->bss[0], txtaddr,
					   buf, buflen);
}


int ap_ctrl_iface_wpa_get_status(struct wpa_supplicant *wpa_s, char *buf,
				 size_t buflen, int verbose)
{
	char *pos = buf, *end = buf + buflen;
	int ret;
	struct hostapd_bss_config *conf;

	if (wpa_s->ap_iface == NULL)
		return -1;

	conf = wpa_s->ap_iface->bss[0]->conf;
	if (conf->wpa == 0)
		return 0;

	ret = os_snprintf(pos, end - pos,
			  "pairwise_cipher=%s\n"
			  "group_cipher=%s\n"
			  "key_mgmt=%s\n",
			  wpa_cipher_txt(conf->rsn_pairwise),
			  wpa_cipher_txt(conf->wpa_group),
			  wpa_key_mgmt_txt(conf->wpa_key_mgmt,
					   conf->wpa));
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;
	return pos - buf;
}

#endif /* CONFIG_CTRL_IFACE */
