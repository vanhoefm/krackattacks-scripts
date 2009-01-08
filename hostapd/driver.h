/*
 * hostapd - driver interface definition
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

#ifndef DRIVER_H
#define DRIVER_H

struct hostapd_sta_add_params {
	const u8 *addr;
	u16 aid;
	u16 capability;
	const u8 *supp_rates;
	size_t supp_rates_len;
	int flags;
	u16 listen_interval;
	const struct ht_cap_ie *ht_capabilities;
};

struct hostapd_freq_params {
	int mode;
	int freq;
	int ht_enabled;
	int sec_channel_offset; /* 0 = HT40 disabled, -1 = HT40 enabled,
				 * secondary channel below primary, 1 = HT40
				 * enabled, secondary channel above primary */
};

enum hostapd_driver_if_type {
	HOSTAPD_IF_VLAN, HOSTAPD_IF_WDS
};

struct wpa_driver_ops {
	const char *name;		/* as appears in the config file */

	void * (*init)(struct hostapd_data *hapd);
	void * (*init_bssid)(struct hostapd_data *hapd, const u8 *bssid);
	void (*deinit)(void *priv);

	int (*wireless_event_init)(void *priv);
	void (*wireless_event_deinit)(void *priv);

	/**
	 * set_8021x - enable/disable IEEE 802.1X support
	 * @ifname: Interface name (for multi-SSID/VLAN support)
	 * @priv: driver private data
	 * @enabled: 1 = enable, 0 = disable
	 *
	 * Returns: 0 on success, -1 on failure
	 *
	 * Configure the kernel driver to enable/disable 802.1X support.
	 * This may be an empty function if 802.1X support is always enabled.
	 */
	int (*set_ieee8021x)(const char *ifname, void *priv, int enabled);

	/**
	 * set_privacy - enable/disable privacy
	 * @priv: driver private data
	 * @enabled: 1 = privacy enabled, 0 = disabled
	 *
	 * Return: 0 on success, -1 on failure
	 *
	 * Configure privacy.
	 */
	int (*set_privacy)(const char *ifname, void *priv, int enabled);

	int (*set_encryption)(const char *ifname, void *priv, const char *alg,
			      const u8 *addr, int idx,
			      const u8 *key, size_t key_len, int txkey);
	int (*get_seqnum)(const char *ifname, void *priv, const u8 *addr,
			  int idx, u8 *seq);
	int (*get_seqnum_igtk)(const char *ifname, void *priv, const u8 *addr,
			       int idx, u8 *seq);
	int (*flush)(void *priv);
	int (*set_generic_elem)(const char *ifname, void *priv, const u8 *elem,
				size_t elem_len);

	int (*read_sta_data)(void *priv, struct hostap_sta_driver_data *data,
			     const u8 *addr);
	int (*send_eapol)(void *priv, const u8 *addr, const u8 *data,
			  size_t data_len, int encrypt, const u8 *own_addr);
	int (*sta_deauth)(void *priv, const u8 *addr, int reason);
	int (*sta_disassoc)(void *priv, const u8 *addr, int reason);
	int (*sta_remove)(void *priv, const u8 *addr);
	int (*get_ssid)(const char *ifname, void *priv, u8 *buf, int len);
	int (*set_ssid)(const char *ifname, void *priv, const u8 *buf,
			int len);
	int (*set_countermeasures)(void *priv, int enabled);
	int (*send_mgmt_frame)(void *priv, const void *msg, size_t len,
			       int flags);
	int (*set_assoc_ap)(void *priv, const u8 *addr);
	/* note: sta_add() is deprecated; use sta_add2() instead */
	int (*sta_add)(const char *ifname, void *priv, const u8 *addr, u16 aid,
		       u16 capability, u8 *supp_rates, size_t supp_rates_len,
		       int flags, u16 listen_interval);
	int (*sta_add2)(const char *ifname, void *priv,
			struct hostapd_sta_add_params *params);
	int (*get_inact_sec)(void *priv, const u8 *addr);
	int (*sta_clear_stats)(void *priv, const u8 *addr);

	/* note: set_freq() is deprecated; use sta_freq() instead */
	int (*set_freq)(void *priv, int mode, int freq);
	int (*set_freq2)(void *priv, struct hostapd_freq_params *freq);
	int (*set_rts)(void *priv, int rts);
	int (*get_rts)(void *priv, int *rts);
	int (*set_frag)(void *priv, int frag);
	int (*get_frag)(void *priv, int *frag);
	int (*set_retry)(void *priv, int short_retry, int long_retry);
	int (*get_retry)(void *priv, int *short_retry, int *long_retry);

	int (*sta_set_flags)(void *priv, const u8 *addr,
			     int total_flags, int flags_or, int flags_and);
	int (*set_rate_sets)(void *priv, int *supp_rates, int *basic_rates,
			     int mode);
	int (*set_regulatory_domain)(void *priv, unsigned int rd);
	int (*set_country)(void *priv, const char *country);
	int (*set_ieee80211d)(void *priv, int enabled);
	int (*set_beacon)(const char *ifname, void *priv,
			  u8 *head, size_t head_len,
			  u8 *tail, size_t tail_len);

	/* Configure internal bridge:
	 * 0 = disabled, i.e., client separation is enabled (no bridging of
	 *     packets between associated STAs
	 * 1 = enabled, i.e., bridge packets between associated STAs (default)
	 */
	int (*set_internal_bridge)(void *priv, int value);
	int (*set_beacon_int)(void *priv, int value);
	int (*set_dtim_period)(const char *ifname, void *priv, int value);
	/* Configure broadcast SSID mode:
	 * 0 = include SSID in Beacon frames and reply to Probe Request frames
	 *     that use broadcast SSID
	 * 1 = hide SSID from Beacon frames and ignore Probe Request frames for
	 *     broadcast SSID
	 */
	int (*set_broadcast_ssid)(void *priv, int value);
	int (*set_cts_protect)(void *priv, int value);
	int (*set_key_tx_rx_threshold)(void *priv, int value);
	int (*set_preamble)(void *priv, int value);
	int (*set_short_slot_time)(void *priv, int value);
	int (*set_tx_queue_params)(void *priv, int queue, int aifs, int cw_min,
				   int cw_max, int burst_time);
	int (*bss_add)(void *priv, const char *ifname, const u8 *bssid);
	int (*bss_remove)(void *priv, const char *ifname);
	int (*valid_bss_mask)(void *priv, const u8 *addr, const u8 *mask);
	int (*passive_scan)(void *priv, int now, int our_mode_only,
			    int interval, int _listen, int *channel,
			    int *last_rx);
	struct hostapd_hw_modes * (*get_hw_feature_data)(void *priv,
							 u16 *num_modes,
							 u16 *flags);
	int (*if_add)(const char *iface, void *priv,
		      enum hostapd_driver_if_type type, char *ifname,
		      const u8 *addr);
	int (*if_update)(void *priv, enum hostapd_driver_if_type type,
			 char *ifname, const u8 *addr);
	int (*if_remove)(void *priv, enum hostapd_driver_if_type type,
			 const char *ifname, const u8 *addr);
	int (*set_sta_vlan)(void *priv, const u8 *addr, const char *ifname,
			    int vlan_id);
	/**
	 * commit - Optional commit changes handler
	 * @priv: driver private data
	 * Returns: 0 on success, -1 on failure
	 *
	 * This optional handler function can be registered if the driver
	 * interface implementation needs to commit changes (e.g., by setting
	 * network interface up) at the end of initial configuration. If set,
	 * this handler will be called after initial setup has been completed.
	 */
	int (*commit)(void *priv);

	int (*send_ether)(void *priv, const u8 *dst, const u8 *src, u16 proto,
			  const u8 *data, size_t data_len);

	int (*set_radius_acl_auth)(void *priv, const u8 *mac, int accepted, 
				   u32 session_timeout);
	int (*set_radius_acl_expire)(void *priv, const u8 *mac);

	int (*set_ht_params)(const char *ifname, void *priv,
			     const u8 *ht_capab, size_t ht_capab_len,
			     const u8 *ht_oper, size_t ht_oper_len);

	int (*set_wps_beacon_ie)(const char *ifname, void *priv,
				 const u8 *ie, size_t len);
	int (*set_wps_probe_resp_ie)(const char *ifname, void *priv,
				     const u8 *ie, size_t len);
};

#endif /* DRIVER_H */
