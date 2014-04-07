/*
 * IEEE 802.11v WNM related functions and structures
 * Copyright (c) 2011-2012, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WNM_STA_H
#define WNM_STA_H

struct tsf_info {
	u8 tsf_offset[2];
	u8 beacon_interval[2];
};

struct condensed_country_string {
	u8 country_string[2];
};

struct bss_transition_candidate {
	u8 preference;
};

struct bss_termination_duration {
	u8 duration[10];
};

struct bearing {
	u8 bearing[8];
};

struct measurement_pilot {
	u8 measurement_pilot;
	u8 subelem_len;
	u8 subelems[255];
};

struct rrm_enabled_capabilities {
	u8 capabilities[5];
};

struct multiple_bssid {
	u8 max_bssid_indicator;
	u8 subelem_len;
	u8 subelems[255];
};

struct neighbor_report {
	u8 bssid[ETH_ALEN];
	u8 bssid_information[4];
	u8 regulatory_class;
	u8 channel_number;
	u8 phy_type;
	struct tsf_info *tsf_info;
	struct condensed_country_string *con_coun_str;
	struct bss_transition_candidate *bss_tran_can;
	struct bss_termination_duration *bss_term_dur;
	struct bearing *bearing;
	struct measurement_pilot *meas_pilot;
	struct rrm_enabled_capabilities *rrm_cap;
	struct multiple_bssid *mul_bssid;
};


int ieee802_11_send_wnmsleep_req(struct wpa_supplicant *wpa_s,
				 u8 action, u16 intval, struct wpabuf *tfs_req);

void ieee802_11_rx_wnm_action(struct wpa_supplicant *wpa_s,
			      const struct ieee80211_mgmt *mgmt, size_t len);

void wnm_scan_response(struct wpa_supplicant *wpa_s,
		       struct wpa_scan_results *scan_res);

int wnm_send_bss_transition_mgmt_query(struct wpa_supplicant *wpa_s,
				       u8 query_reason);
void wnm_deallocate_memory(struct wpa_supplicant *wpa_s);

#endif /* WNM_STA_H */
