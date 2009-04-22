/*
 * hostapd - internal driver interface wrappers
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2007-2008, Intel Corporation
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

#ifndef DRIVER_I_H
#define DRIVER_I_H

#include "drivers/driver.h"
#include "config.h"

static inline void *
hostapd_driver_init(struct hostapd_data *hapd, const u8 *bssid)
{
	struct wpa_init_params params;
	void *ret;
	size_t i;

	if (hapd->driver == NULL || hapd->driver->hapd_init == NULL)
		return NULL;

	os_memset(&params, 0, sizeof(params));
	params.bssid = bssid;
	params.ifname = hapd->conf->iface;
	params.ssid = (const u8 *) hapd->conf->ssid.ssid;
	params.ssid_len = hapd->conf->ssid.ssid_len;
	params.test_socket = hapd->conf->test_socket;
	params.use_pae_group_addr = hapd->conf->use_pae_group_addr;

	params.num_bridge = hapd->iface->num_bss;
	params.bridge = os_zalloc(hapd->iface->num_bss * sizeof(char *));
	if (params.bridge == NULL)
		return NULL;
	for (i = 0; i < hapd->iface->num_bss; i++) {
		struct hostapd_data *bss = hapd->iface->bss[i];
		if (bss->conf->bridge[0])
			params.bridge[i] = bss->conf->bridge;
	}

	params.own_addr = hapd->own_addr;

	ret = hapd->driver->hapd_init(hapd, &params);
	os_free(params.bridge);

	return ret;
}

static inline void
hostapd_driver_deinit(struct hostapd_data *hapd)
{
	if (hapd->driver == NULL || hapd->driver->hapd_deinit == NULL)
		return;
	hapd->driver->hapd_deinit(hapd->drv_priv);
}

static inline int
hostapd_set_ieee8021x(const char *ifname, struct hostapd_data *hapd,
		      int enabled)
{
	if (hapd->driver == NULL || hapd->driver->set_ieee8021x == NULL)
		return 0;
	return hapd->driver->set_ieee8021x(ifname, hapd->drv_priv, enabled);
}

static inline int
hostapd_set_privacy(struct hostapd_data *hapd, int enabled)
{
	if (hapd->driver == NULL || hapd->driver->set_privacy == NULL)
		return 0;
	return hapd->driver->set_privacy(hapd->conf->iface, hapd->drv_priv,
					 enabled);
}

static inline int
hostapd_set_key(const char *ifname, struct hostapd_data *hapd,
		wpa_alg alg, const u8 *addr, int key_idx,
		int set_tx, const u8 *seq, size_t seq_len,
		const u8 *key, size_t key_len)
{
	if (hapd->driver == NULL || hapd->driver->hapd_set_key == NULL)
		return 0;
	return hapd->driver->hapd_set_key(ifname, hapd->drv_priv, alg, addr,
					  key_idx, set_tx, seq, seq_len, key,
					  key_len);
}

static inline int
hostapd_get_seqnum(const char *ifname, struct hostapd_data *hapd,
		   const u8 *addr, int idx, u8 *seq)
{
	if (hapd->driver == NULL || hapd->driver->get_seqnum == NULL)
		return 0;
	return hapd->driver->get_seqnum(ifname, hapd->drv_priv, addr, idx,
					seq);
}

static inline int
hostapd_get_seqnum_igtk(const char *ifname, struct hostapd_data *hapd,
			const u8 *addr, int idx, u8 *seq)
{
	if (hapd->driver == NULL || hapd->driver->get_seqnum_igtk == NULL)
		return -1;
	return hapd->driver->get_seqnum_igtk(ifname, hapd->drv_priv, addr, idx,
					     seq);
}

static inline int
hostapd_flush(struct hostapd_data *hapd)
{
	if (hapd->driver == NULL || hapd->driver->flush == NULL)
		return 0;
	return hapd->driver->flush(hapd->drv_priv);
}

static inline int
hostapd_set_generic_elem(struct hostapd_data *hapd, const u8 *elem,
			 size_t elem_len)
{
	if (hapd->driver == NULL || hapd->driver->set_generic_elem == NULL)
		return 0;
	return hapd->driver->set_generic_elem(hapd->conf->iface,
					      hapd->drv_priv, elem, elem_len);
}

static inline int
hostapd_read_sta_data(struct hostapd_data *hapd,
		      struct hostap_sta_driver_data *data, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->read_sta_data == NULL)
		return -1;
	return hapd->driver->read_sta_data(hapd->drv_priv, data, addr);
}

static inline int
hostapd_send_eapol(struct hostapd_data *hapd, const u8 *addr, const u8 *data,
		   size_t data_len, int encrypt)
{
	if (hapd->driver == NULL || hapd->driver->hapd_send_eapol == NULL)
		return 0;
	return hapd->driver->hapd_send_eapol(hapd->drv_priv, addr, data,
					     data_len, encrypt,
					     hapd->own_addr);
}

static inline int
hostapd_sta_deauth(struct hostapd_data *hapd, const u8 *addr, int reason)
{
	if (hapd->driver == NULL || hapd->driver->sta_deauth == NULL)
		return 0;
	return hapd->driver->sta_deauth(hapd->drv_priv, hapd->own_addr, addr,
					reason);
}

static inline int
hostapd_sta_disassoc(struct hostapd_data *hapd, const u8 *addr, int reason)
{
	if (hapd->driver == NULL || hapd->driver->sta_disassoc == NULL)
		return 0;
	return hapd->driver->sta_disassoc(hapd->drv_priv, hapd->own_addr, addr,
					  reason);
}

static inline int
hostapd_sta_remove(struct hostapd_data *hapd, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->sta_remove == NULL)
		return 0;
	return hapd->driver->sta_remove(hapd->drv_priv, addr);
}

static inline int
hostapd_get_ssid(struct hostapd_data *hapd, u8 *buf, size_t len)
{
	if (hapd->driver == NULL || hapd->driver->hapd_get_ssid == NULL)
		return 0;
	return hapd->driver->hapd_get_ssid(hapd->conf->iface, hapd->drv_priv,
					   buf, len);
}

static inline int
hostapd_set_ssid(struct hostapd_data *hapd, const u8 *buf, size_t len)
{
	if (hapd->driver == NULL || hapd->driver->hapd_set_ssid == NULL)
		return 0;
	return hapd->driver->hapd_set_ssid(hapd->conf->iface, hapd->drv_priv,
					   buf, len);
}

static inline int
hostapd_send_mgmt_frame(struct hostapd_data *hapd, const void *msg, size_t len)
{
	if (hapd->driver == NULL || hapd->driver->send_mlme == NULL)
		return 0;
	return hapd->driver->send_mlme(hapd->drv_priv, msg, len);
}

static inline int
hostapd_set_countermeasures(struct hostapd_data *hapd, int enabled)
{
	if (hapd->driver == NULL ||
	    hapd->driver->hapd_set_countermeasures == NULL)
		return 0;
	return hapd->driver->hapd_set_countermeasures(hapd->drv_priv, enabled);
}

static inline int
hostapd_sta_add(const char *ifname, struct hostapd_data *hapd, const u8 *addr,
		u16 aid, u16 capability, const u8 *supp_rates,
		size_t supp_rates_len, int flags, u16 listen_interval,
		const struct ht_cap_ie *ht_capabilities)
{
	struct hostapd_sta_add_params params;

	if (hapd->driver == NULL)
		return 0;
	if (hapd->driver->sta_add == NULL)
		return 0;

	os_memset(&params, 0, sizeof(params));
	params.addr = addr;
	params.aid = aid;
	params.capability = capability;
	params.supp_rates = supp_rates;
	params.supp_rates_len = supp_rates_len;
	params.flags = flags;
	params.listen_interval = listen_interval;
	params.ht_capabilities = ht_capabilities;
	return hapd->driver->sta_add(ifname, hapd->drv_priv, &params);
}

static inline int
hostapd_get_inact_sec(struct hostapd_data *hapd, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->get_inact_sec == NULL)
		return 0;
	return hapd->driver->get_inact_sec(hapd->drv_priv, addr);
}

static inline int
hostapd_set_freq(struct hostapd_data *hapd, int mode, int freq, int channel,
		 int ht_enabled, int sec_channel_offset)
{
	struct hostapd_freq_params data;
	if (hapd->driver == NULL)
		return 0;
	if (hapd->driver->set_freq == NULL)
		return 0;
	os_memset(&data, 0, sizeof(data));
	data.mode = mode;
	data.freq = freq;
	data.channel = channel;
	data.ht_enabled = ht_enabled;
	data.sec_channel_offset = sec_channel_offset;
	return hapd->driver->set_freq(hapd->drv_priv, &data);
}

static inline int
hostapd_set_rts(struct hostapd_data *hapd, int rts)
{
	if (hapd->driver == NULL || hapd->driver->set_rts == NULL)
		return 0;
	return hapd->driver->set_rts(hapd->drv_priv, rts);
}

static inline int
hostapd_set_frag(struct hostapd_data *hapd, int frag)
{
	if (hapd->driver == NULL || hapd->driver->set_frag == NULL)
		return 0;
	return hapd->driver->set_frag(hapd->drv_priv, frag);
}

static inline int
hostapd_sta_set_flags(struct hostapd_data *hapd, u8 *addr,
		      int total_flags, int flags_or, int flags_and)
{
	if (hapd->driver == NULL || hapd->driver->sta_set_flags == NULL)
		return 0;
	return hapd->driver->sta_set_flags(hapd->drv_priv, addr, total_flags,
					   flags_or, flags_and);
}

static inline int
hostapd_set_rate_sets(struct hostapd_data *hapd, int *supp_rates,
		      int *basic_rates, int mode)
{
	if (hapd->driver == NULL || hapd->driver->set_rate_sets == NULL)
		return 0;
	return hapd->driver->set_rate_sets(hapd->drv_priv, supp_rates,
					   basic_rates, mode);
}

static inline int
hostapd_set_country(struct hostapd_data *hapd, const char *country)
{
	if (hapd->driver == NULL ||
	    hapd->driver->set_country == NULL)
		return 0;
	return hapd->driver->set_country(hapd->drv_priv, country);
}

static inline int
hostapd_sta_clear_stats(struct hostapd_data *hapd, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->sta_clear_stats == NULL)
		return 0;
	return hapd->driver->sta_clear_stats(hapd->drv_priv, addr);
}

static inline int
hostapd_set_beacon(const char *ifname, struct hostapd_data *hapd,
		   const u8 *head, size_t head_len,
		   const u8 *tail, size_t tail_len, int dtim_period)
{
	if (hapd->driver == NULL || hapd->driver->hapd_set_beacon == NULL)
		return 0;
	return hapd->driver->hapd_set_beacon(ifname, hapd->drv_priv,
					     head, head_len,
					     tail, tail_len, dtim_period);
}

static inline int
hostapd_set_internal_bridge(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_internal_bridge == NULL)
		return 0;
	return hapd->driver->set_internal_bridge(hapd->drv_priv, value);
}

static inline int
hostapd_set_beacon_int(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_beacon_int == NULL)
		return 0;
	return hapd->driver->set_beacon_int(hapd->drv_priv, value);
}

static inline int
hostapd_set_cts_protect(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_cts_protect == NULL)
		return 0;
	return hapd->driver->set_cts_protect(hapd->drv_priv, value);
}

static inline int
hostapd_set_preamble(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_preamble == NULL)
		return 0;
	return hapd->driver->set_preamble(hapd->drv_priv, value);
}

static inline int
hostapd_set_short_slot_time(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_short_slot_time == NULL)
		return 0;
	return hapd->driver->set_short_slot_time(hapd->drv_priv, value);
}

static inline int
hostapd_set_tx_queue_params(struct hostapd_data *hapd, int queue, int aifs,
			    int cw_min, int cw_max, int burst_time)
{
	if (hapd->driver == NULL || hapd->driver->set_tx_queue_params == NULL)
		return 0;
	return hapd->driver->set_tx_queue_params(hapd->drv_priv, queue, aifs,
						 cw_min, cw_max, burst_time);
}

static inline int
hostapd_bss_add(struct hostapd_data *hapd, const char *ifname, const u8 *bssid)
{
	if (hapd->driver == NULL || hapd->driver->bss_add == NULL)
		return 0;
	return hapd->driver->bss_add(hapd->drv_priv, ifname, bssid);
}

static inline int
hostapd_bss_remove(struct hostapd_data *hapd, const char *ifname)
{
	if (hapd->driver == NULL || hapd->driver->bss_remove == NULL)
		return 0;
	return hapd->driver->bss_remove(hapd->drv_priv, ifname);
}

static inline int
hostapd_valid_bss_mask(struct hostapd_data *hapd, const u8 *addr,
		       const u8 *mask)
{
	if (hapd->driver == NULL || hapd->driver->valid_bss_mask == NULL)
		return 1;
	return hapd->driver->valid_bss_mask(hapd->drv_priv, addr, mask);
}

static inline int
hostapd_if_add(struct hostapd_data *hapd, enum hostapd_driver_if_type type,
	       char *ifname, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->if_add == NULL)
		return -1;
	return hapd->driver->if_add(hapd->conf->iface, hapd->drv_priv, type,
				    ifname, addr);
}

static inline int
hostapd_if_update(struct hostapd_data *hapd, enum hostapd_driver_if_type type,
		  char *ifname, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->if_update == NULL)
		return -1;
	return hapd->driver->if_update(hapd->drv_priv, type, ifname, addr);
}

static inline int
hostapd_if_remove(struct hostapd_data *hapd, enum hostapd_driver_if_type type,
		  char *ifname, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->if_remove == NULL)
		return -1;
	return hapd->driver->if_remove(hapd->drv_priv, type, ifname, addr);
}

static inline struct hostapd_hw_modes *
hostapd_get_hw_feature_data(struct hostapd_data *hapd, u16 *num_modes,
			    u16 *flags)
{
	if (hapd->driver == NULL ||
	    hapd->driver->get_hw_feature_data == NULL)
		return NULL;
	return hapd->driver->get_hw_feature_data(hapd->drv_priv, num_modes,
						 flags);
}

static inline int
hostapd_set_sta_vlan(const char *ifname, struct hostapd_data *hapd,
		     const u8 *addr, int vlan_id)
{
	if (hapd->driver == NULL || hapd->driver->set_sta_vlan == NULL)
		return 0;
	return hapd->driver->set_sta_vlan(hapd->drv_priv, addr, ifname, vlan_id);
}

static inline int
hostapd_driver_commit(struct hostapd_data *hapd)
{
	if (hapd->driver == NULL || hapd->driver->commit == NULL)
		return 0;
	return hapd->driver->commit(hapd->drv_priv);
}

static inline int
hostapd_set_radius_acl_auth(struct hostapd_data *hapd, const u8 *mac,
			    int accepted, u32 session_timeout)
{
	if (hapd->driver == NULL || hapd->driver->set_radius_acl_auth == NULL)
		return 0;
	return hapd->driver->set_radius_acl_auth(hapd->drv_priv, mac, accepted,
						 session_timeout);
}

static inline int
hostapd_set_radius_acl_expire(struct hostapd_data *hapd, const u8 *mac)
{
	if (hapd->driver == NULL ||
	    hapd->driver->set_radius_acl_expire == NULL)
		return 0;
	return hapd->driver->set_radius_acl_expire(hapd->drv_priv, mac);
}

#ifdef CONFIG_IEEE80211N
static inline int
hostapd_set_ht_params(const char *ifname, struct hostapd_data *hapd,
		      const u8 *ht_capab, size_t ht_capab_len,
		      const u8 *ht_oper, size_t ht_oper_len)
{
	if (hapd->driver == NULL || hapd->driver->set_ht_params == NULL ||
	    ht_capab == NULL || ht_oper == NULL)
		return 0;
	return hapd->driver->set_ht_params(
		ifname, hapd->drv_priv, ht_capab, ht_capab_len,
		ht_oper, ht_oper_len);
}
#endif /* CONFIG_IEEE80211N */

static inline int
hostapd_drv_none(struct hostapd_data *hapd)
{
	return hapd->driver && os_strcmp(hapd->driver->name, "none") == 0;
}

static inline int
hostapd_set_wps_beacon_ie(struct hostapd_data *hapd, const u8 *ie, size_t len)
{
	if (hapd->driver == NULL || hapd->driver->set_wps_beacon_ie == NULL)
		return 0;
	return hapd->driver->set_wps_beacon_ie(hapd->conf->iface,
					       hapd->drv_priv, ie, len);
}

static inline int
hostapd_set_wps_probe_resp_ie(struct hostapd_data *hapd, const u8 *ie,
			      size_t len)
{
	if (hapd->driver == NULL ||
	    hapd->driver->set_wps_probe_resp_ie == NULL)
		return 0;
	return hapd->driver->set_wps_probe_resp_ie(hapd->conf->iface,
						   hapd->drv_priv, ie, len);
}

static inline int hostapd_driver_set_mode(struct hostapd_data *hapd, int mode)
{
	if (hapd->driver == NULL || hapd->driver->set_mode == NULL)
		return 0;
	return hapd->driver->set_mode(hapd->drv_priv, mode);
}

static inline int hostapd_driver_scan(struct hostapd_data *hapd,
				      struct wpa_driver_scan_params *params)
{
	if (hapd->driver && hapd->driver->scan2)
		return hapd->driver->scan2(hapd->drv_priv, params);
	return -1;
}

static inline struct wpa_scan_results * hostapd_driver_get_scan_results(
	struct hostapd_data *hapd)
{
	if (hapd->driver && hapd->driver->get_scan_results2)
		return hapd->driver->get_scan_results2(hapd->drv_priv);
	return NULL;
}

#endif /* DRIVER_I_H */
