/*
 * wpa_supplicant - SME
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
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
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "common/wpa_common.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/pmksa_cache.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "wpas_glue.h"
#include "wps_supplicant.h"
#include "p2p_supplicant.h"
#include "notify.h"
#include "blacklist.h"
#include "bss.h"
#include "scan.h"
#include "sme.h"

#define SME_AUTH_TIMEOUT 5
#define SME_ASSOC_TIMEOUT 5

static void sme_auth_timer(void *eloop_ctx, void *timeout_ctx);
static void sme_assoc_timer(void *eloop_ctx, void *timeout_ctx);
#ifdef CONFIG_IEEE80211W
static void sme_stop_sa_query(struct wpa_supplicant *wpa_s);
#endif /* CONFIG_IEEE80211W */


void sme_authenticate(struct wpa_supplicant *wpa_s,
		      struct wpa_bss *bss, struct wpa_ssid *ssid)
{
	struct wpa_driver_auth_params params;
	struct wpa_ssid *old_ssid;
#ifdef CONFIG_IEEE80211R
	const u8 *ie;
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211R
	const u8 *md = NULL;
#endif /* CONFIG_IEEE80211R */
	int i, bssid_changed;

	if (bss == NULL) {
		wpa_msg(wpa_s, MSG_ERROR, "SME: No scan result available for "
			"the network");
		return;
	}

	wpa_s->current_bss = bss;

	os_memset(&params, 0, sizeof(params));
	wpa_s->reassociate = 0;

	params.freq = bss->freq;
	params.bssid = bss->bssid;
	params.ssid = bss->ssid;
	params.ssid_len = bss->ssid_len;

	if (wpa_s->sme.ssid_len != params.ssid_len ||
	    os_memcmp(wpa_s->sme.ssid, params.ssid, params.ssid_len) != 0)
		wpa_s->sme.prev_bssid_set = 0;

	wpa_s->sme.freq = params.freq;
	os_memcpy(wpa_s->sme.ssid, params.ssid, params.ssid_len);
	wpa_s->sme.ssid_len = params.ssid_len;

	params.auth_alg = WPA_AUTH_ALG_OPEN;
#ifdef IEEE8021X_EAPOL
	if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if (ssid->leap) {
			if (ssid->non_leap == 0)
				params.auth_alg = WPA_AUTH_ALG_LEAP;
			else
				params.auth_alg |= WPA_AUTH_ALG_LEAP;
		}
	}
#endif /* IEEE8021X_EAPOL */
	wpa_dbg(wpa_s, MSG_DEBUG, "Automatic auth_alg selection: 0x%x",
		params.auth_alg);
	if (ssid->auth_alg) {
		params.auth_alg = ssid->auth_alg;
		wpa_dbg(wpa_s, MSG_DEBUG, "Overriding auth_alg selection: "
			"0x%x", params.auth_alg);
	}

	for (i = 0; i < NUM_WEP_KEYS; i++) {
		if (ssid->wep_key_len[i])
			params.wep_key[i] = ssid->wep_key[i];
		params.wep_key_len[i] = ssid->wep_key_len[i];
	}
	params.wep_tx_keyidx = ssid->wep_tx_keyidx;

	bssid_changed = !is_zero_ether_addr(wpa_s->bssid);
	os_memset(wpa_s->bssid, 0, ETH_ALEN);
	os_memcpy(wpa_s->pending_bssid, bss->bssid, ETH_ALEN);
	if (bssid_changed)
		wpas_notify_bssid_changed(wpa_s);

	if ((wpa_bss_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE) ||
	     wpa_bss_get_ie(bss, WLAN_EID_RSN)) &&
	    (ssid->key_mgmt & (WPA_KEY_MGMT_IEEE8021X | WPA_KEY_MGMT_PSK |
			       WPA_KEY_MGMT_FT_IEEE8021X |
			       WPA_KEY_MGMT_FT_PSK |
			       WPA_KEY_MGMT_IEEE8021X_SHA256 |
			       WPA_KEY_MGMT_PSK_SHA256))) {
		int try_opportunistic;
		try_opportunistic = ssid->proactive_key_caching &&
			(ssid->proto & WPA_PROTO_RSN);
		if (pmksa_cache_set_current(wpa_s->wpa, NULL, bss->bssid,
					    wpa_s->current_ssid,
					    try_opportunistic) == 0)
			eapol_sm_notify_pmkid_attempt(wpa_s->eapol, 1);
		wpa_s->sme.assoc_req_ie_len = sizeof(wpa_s->sme.assoc_req_ie);
		if (wpa_supplicant_set_suites(wpa_s, bss, ssid,
					      wpa_s->sme.assoc_req_ie,
					      &wpa_s->sme.assoc_req_ie_len)) {
			wpa_msg(wpa_s, MSG_WARNING, "SME: Failed to set WPA "
				"key management and encryption suites");
			return;
		}
	} else if (ssid->key_mgmt &
		   (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X |
		    WPA_KEY_MGMT_WPA_NONE | WPA_KEY_MGMT_FT_PSK |
		    WPA_KEY_MGMT_FT_IEEE8021X | WPA_KEY_MGMT_PSK_SHA256 |
		    WPA_KEY_MGMT_IEEE8021X_SHA256)) {
		wpa_s->sme.assoc_req_ie_len = sizeof(wpa_s->sme.assoc_req_ie);
		if (wpa_supplicant_set_suites(wpa_s, NULL, ssid,
					      wpa_s->sme.assoc_req_ie,
					      &wpa_s->sme.assoc_req_ie_len)) {
			wpa_msg(wpa_s, MSG_WARNING, "SME: Failed to set WPA "
				"key management and encryption suites (no "
				"scan results)");
			return;
		}
#ifdef CONFIG_WPS
	} else if (ssid->key_mgmt & WPA_KEY_MGMT_WPS) {
		struct wpabuf *wps_ie;
		wps_ie = wps_build_assoc_req_ie(wpas_wps_get_req_type(ssid));
		if (wps_ie && wpabuf_len(wps_ie) <=
		    sizeof(wpa_s->sme.assoc_req_ie)) {
			wpa_s->sme.assoc_req_ie_len = wpabuf_len(wps_ie);
			os_memcpy(wpa_s->sme.assoc_req_ie, wpabuf_head(wps_ie),
				  wpa_s->sme.assoc_req_ie_len);
		} else
			wpa_s->sme.assoc_req_ie_len = 0;
		wpabuf_free(wps_ie);
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
#endif /* CONFIG_WPS */
	} else {
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
		wpa_s->sme.assoc_req_ie_len = 0;
	}

#ifdef CONFIG_IEEE80211R
	ie = wpa_bss_get_ie(bss, WLAN_EID_MOBILITY_DOMAIN);
	if (ie && ie[1] >= MOBILITY_DOMAIN_ID_LEN)
		md = ie + 2;
	wpa_sm_set_ft_params(wpa_s->wpa, ie, ie ? 2 + ie[1] : 0);
	if (md) {
		/* Prepare for the next transition */
		wpa_ft_prepare_auth_request(wpa_s->wpa, ie);
	}

	if (md && ssid->key_mgmt & (WPA_KEY_MGMT_FT_PSK |
				    WPA_KEY_MGMT_FT_IEEE8021X)) {
		if (wpa_s->sme.assoc_req_ie_len + 5 <
		    sizeof(wpa_s->sme.assoc_req_ie)) {
			struct rsn_mdie *mdie;
			u8 *pos = wpa_s->sme.assoc_req_ie +
				wpa_s->sme.assoc_req_ie_len;
			*pos++ = WLAN_EID_MOBILITY_DOMAIN;
			*pos++ = sizeof(*mdie);
			mdie = (struct rsn_mdie *) pos;
			os_memcpy(mdie->mobility_domain, md,
				  MOBILITY_DOMAIN_ID_LEN);
			mdie->ft_capab = md[MOBILITY_DOMAIN_ID_LEN];
			wpa_s->sme.assoc_req_ie_len += 5;
		}

		if (wpa_s->sme.ft_used &&
		    os_memcmp(md, wpa_s->sme.mobility_domain, 2) == 0 &&
		    wpa_sm_has_ptk(wpa_s->wpa)) {
			wpa_dbg(wpa_s, MSG_DEBUG, "SME: Trying to use FT "
				"over-the-air");
			params.auth_alg = WPA_AUTH_ALG_FT;
			params.ie = wpa_s->sme.ft_ies;
			params.ie_len = wpa_s->sme.ft_ies_len;
		}
	}
#endif /* CONFIG_IEEE80211R */

#ifdef CONFIG_IEEE80211W
	wpa_s->sme.mfp = ssid->ieee80211w;
	if (ssid->ieee80211w != NO_MGMT_FRAME_PROTECTION) {
		const u8 *rsn = wpa_bss_get_ie(bss, WLAN_EID_RSN);
		struct wpa_ie_data _ie;
		if (rsn && wpa_parse_wpa_ie(rsn, 2 + rsn[1], &_ie) == 0 &&
		    _ie.capabilities &
		    (WPA_CAPABILITY_MFPC | WPA_CAPABILITY_MFPR)) {
			wpa_dbg(wpa_s, MSG_DEBUG, "SME: Selected AP supports "
				"MFP: require MFP");
			wpa_s->sme.mfp = MGMT_FRAME_PROTECTION_REQUIRED;
		}
	}
#endif /* CONFIG_IEEE80211W */

#ifdef CONFIG_P2P
	if (wpa_s->global->p2p) {
		u8 *pos;
		size_t len;
		int res;
		int p2p_group;
		p2p_group = wpa_s->drv_flags & WPA_DRIVER_FLAGS_P2P_CAPABLE;
		pos = wpa_s->sme.assoc_req_ie + wpa_s->sme.assoc_req_ie_len;
		len = sizeof(wpa_s->sme.assoc_req_ie) -
			wpa_s->sme.assoc_req_ie_len;
		res = wpas_p2p_assoc_req_ie(wpa_s, bss, pos, len, p2p_group);
		if (res >= 0)
			wpa_s->sme.assoc_req_ie_len += res;
	}
#endif /* CONFIG_P2P */

	wpa_supplicant_cancel_scan(wpa_s);

	wpa_msg(wpa_s, MSG_INFO, "SME: Trying to authenticate with " MACSTR
		" (SSID='%s' freq=%d MHz)", MAC2STR(params.bssid),
		wpa_ssid_txt(params.ssid, params.ssid_len), params.freq);

	wpa_clear_keys(wpa_s, bss->bssid);
	wpa_supplicant_set_state(wpa_s, WPA_AUTHENTICATING);
	old_ssid = wpa_s->current_ssid;
	wpa_s->current_ssid = ssid;
	wpa_supplicant_rsn_supp_set_config(wpa_s, wpa_s->current_ssid);
	wpa_supplicant_initiate_eapol(wpa_s);
	if (old_ssid != wpa_s->current_ssid)
		wpas_notify_network_changed(wpa_s);

	wpa_s->sme.auth_alg = params.auth_alg;
	if (wpa_drv_authenticate(wpa_s, &params) < 0) {
		wpa_msg(wpa_s, MSG_INFO, "SME: Authentication request to the "
			"driver failed");
		wpa_supplicant_req_scan(wpa_s, 1, 0);
		return;
	}

	eloop_register_timeout(SME_AUTH_TIMEOUT, 0, sme_auth_timer, wpa_s,
			       NULL);

	/*
	 * Association will be started based on the authentication event from
	 * the driver.
	 */
}


void sme_event_auth(struct wpa_supplicant *wpa_s, union wpa_event_data *data)
{
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (ssid == NULL) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Ignore authentication event "
			"when network is not selected");
		return;
	}

	if (wpa_s->wpa_state != WPA_AUTHENTICATING) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Ignore authentication event "
			"when not in authenticating state");
		return;
	}

	if (os_memcmp(wpa_s->pending_bssid, data->auth.peer, ETH_ALEN) != 0) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Ignore authentication with "
			"unexpected peer " MACSTR,
			MAC2STR(data->auth.peer));
		return;
	}

	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Authentication response: peer=" MACSTR
		" auth_type=%d status_code=%d",
		MAC2STR(data->auth.peer), data->auth.auth_type,
		data->auth.status_code);
	wpa_hexdump(MSG_MSGDUMP, "SME: Authentication response IEs",
		    data->auth.ies, data->auth.ies_len);

	eloop_cancel_timeout(sme_auth_timer, wpa_s, NULL);

	if (data->auth.status_code != WLAN_STATUS_SUCCESS) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Authentication failed (status "
			"code %d)", data->auth.status_code);

		if (data->auth.status_code !=
		    WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG ||
		    wpa_s->sme.auth_alg == data->auth.auth_type ||
		    wpa_s->current_ssid->auth_alg == WPA_AUTH_ALG_LEAP) {
			wpas_connection_failed(wpa_s, wpa_s->pending_bssid);
			return;
		}

		switch (data->auth.auth_type) {
		case WLAN_AUTH_OPEN:
			wpa_s->current_ssid->auth_alg = WPA_AUTH_ALG_SHARED;

			wpa_dbg(wpa_s, MSG_DEBUG, "SME: Trying SHARED auth");
			wpa_supplicant_associate(wpa_s, wpa_s->current_bss,
						 wpa_s->current_ssid);
			return;

		case WLAN_AUTH_SHARED_KEY:
			wpa_s->current_ssid->auth_alg = WPA_AUTH_ALG_LEAP;

			wpa_dbg(wpa_s, MSG_DEBUG, "SME: Trying LEAP auth");
			wpa_supplicant_associate(wpa_s, wpa_s->current_bss,
						 wpa_s->current_ssid);
			return;

		default:
			return;
		}
	}

#ifdef CONFIG_IEEE80211R
	if (data->auth.auth_type == WLAN_AUTH_FT) {
		union wpa_event_data edata;
		os_memset(&edata, 0, sizeof(edata));
		edata.ft_ies.ies = data->auth.ies;
		edata.ft_ies.ies_len = data->auth.ies_len;
		os_memcpy(edata.ft_ies.target_ap, data->auth.peer, ETH_ALEN);
		wpa_supplicant_event(wpa_s, EVENT_FT_RESPONSE, &edata);
	}
#endif /* CONFIG_IEEE80211R */

	sme_associate(wpa_s, ssid->mode, data->auth.peer,
		      data->auth.auth_type);
}


void sme_associate(struct wpa_supplicant *wpa_s, enum wpas_mode mode,
		   const u8 *bssid, u16 auth_type)
{
	struct wpa_driver_associate_params params;
	struct ieee802_11_elems elems;

	os_memset(&params, 0, sizeof(params));
	params.bssid = bssid;
	params.ssid = wpa_s->sme.ssid;
	params.ssid_len = wpa_s->sme.ssid_len;
	params.freq = wpa_s->sme.freq;
	params.wpa_ie = wpa_s->sme.assoc_req_ie_len ?
		wpa_s->sme.assoc_req_ie : NULL;
	params.wpa_ie_len = wpa_s->sme.assoc_req_ie_len;
	params.pairwise_suite = cipher_suite2driver(wpa_s->pairwise_cipher);
	params.group_suite = cipher_suite2driver(wpa_s->group_cipher);
#ifdef CONFIG_IEEE80211R
	if (auth_type == WLAN_AUTH_FT && wpa_s->sme.ft_ies) {
		params.wpa_ie = wpa_s->sme.ft_ies;
		params.wpa_ie_len = wpa_s->sme.ft_ies_len;
	}
#endif /* CONFIG_IEEE80211R */
	params.mode = mode;
	params.mgmt_frame_protection = wpa_s->sme.mfp;
	if (wpa_s->sme.prev_bssid_set)
		params.prev_bssid = wpa_s->sme.prev_bssid;

	wpa_msg(wpa_s, MSG_INFO, "Trying to associate with " MACSTR
		" (SSID='%s' freq=%d MHz)", MAC2STR(params.bssid),
		params.ssid ? wpa_ssid_txt(params.ssid, params.ssid_len) : "",
		params.freq);

	wpa_supplicant_set_state(wpa_s, WPA_ASSOCIATING);

	if (params.wpa_ie == NULL ||
	    ieee802_11_parse_elems(params.wpa_ie, params.wpa_ie_len, &elems, 0)
	    < 0) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Could not parse own IEs?!");
		os_memset(&elems, 0, sizeof(elems));
	}
	if (elems.rsn_ie)
		wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, elems.rsn_ie - 2,
					elems.rsn_ie_len + 2);
	else if (elems.wpa_ie)
		wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, elems.wpa_ie - 2,
					elems.wpa_ie_len + 2);
	else
		wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
	if (elems.p2p &&
	    (wpa_s->drv_flags & WPA_DRIVER_FLAGS_P2P_CAPABLE))
		params.p2p = 1;

	if (wpa_s->parent->set_sta_uapsd)
		params.uapsd = wpa_s->parent->sta_uapsd;
	else
		params.uapsd = -1;

	if (wpa_drv_associate(wpa_s, &params) < 0) {
		wpa_msg(wpa_s, MSG_INFO, "SME: Association request to the "
			"driver failed");
		wpas_connection_failed(wpa_s, wpa_s->pending_bssid);
		os_memset(wpa_s->pending_bssid, 0, ETH_ALEN);
		return;
	}

	eloop_register_timeout(SME_ASSOC_TIMEOUT, 0, sme_assoc_timer, wpa_s,
			       NULL);
}


int sme_update_ft_ies(struct wpa_supplicant *wpa_s, const u8 *md,
		      const u8 *ies, size_t ies_len)
{
	if (md == NULL || ies == NULL) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Remove mobility domain");
		os_free(wpa_s->sme.ft_ies);
		wpa_s->sme.ft_ies = NULL;
		wpa_s->sme.ft_ies_len = 0;
		wpa_s->sme.ft_used = 0;
		return 0;
	}

	os_memcpy(wpa_s->sme.mobility_domain, md, MOBILITY_DOMAIN_ID_LEN);
	wpa_hexdump(MSG_DEBUG, "SME: FT IEs", ies, ies_len);
	os_free(wpa_s->sme.ft_ies);
	wpa_s->sme.ft_ies = os_malloc(ies_len);
	if (wpa_s->sme.ft_ies == NULL)
		return -1;
	os_memcpy(wpa_s->sme.ft_ies, ies, ies_len);
	wpa_s->sme.ft_ies_len = ies_len;
	return 0;
}


static void sme_deauth(struct wpa_supplicant *wpa_s)
{
	int bssid_changed;

	bssid_changed = !is_zero_ether_addr(wpa_s->bssid);

	if (wpa_drv_deauthenticate(wpa_s, wpa_s->pending_bssid,
				   WLAN_REASON_DEAUTH_LEAVING) < 0) {
		wpa_msg(wpa_s, MSG_INFO, "SME: Deauth request to the driver "
			"failed");
	}
	wpa_s->sme.prev_bssid_set = 0;

	wpas_connection_failed(wpa_s, wpa_s->pending_bssid);
	wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
	os_memset(wpa_s->bssid, 0, ETH_ALEN);
	os_memset(wpa_s->pending_bssid, 0, ETH_ALEN);
	if (bssid_changed)
		wpas_notify_bssid_changed(wpa_s);
}


void sme_event_assoc_reject(struct wpa_supplicant *wpa_s,
			    union wpa_event_data *data)
{
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Association with " MACSTR " failed: "
		"status code %d", MAC2STR(wpa_s->pending_bssid),
		data->assoc_reject.status_code);

	eloop_cancel_timeout(sme_assoc_timer, wpa_s, NULL);

	/*
	 * For now, unconditionally terminate the previous authentication. In
	 * theory, this should not be needed, but mac80211 gets quite confused
	 * if the authentication is left pending.. Some roaming cases might
	 * benefit from using the previous authentication, so this could be
	 * optimized in the future.
	 */
	sme_deauth(wpa_s);
}


void sme_event_auth_timed_out(struct wpa_supplicant *wpa_s,
			      union wpa_event_data *data)
{
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Authentication timed out");
	wpas_connection_failed(wpa_s, wpa_s->pending_bssid);
}


void sme_event_assoc_timed_out(struct wpa_supplicant *wpa_s,
			       union wpa_event_data *data)
{
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Association timed out");
	wpas_connection_failed(wpa_s, wpa_s->pending_bssid);
	wpa_supplicant_mark_disassoc(wpa_s);
}


void sme_event_disassoc(struct wpa_supplicant *wpa_s,
			union wpa_event_data *data)
{
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Disassociation event received");
	if (wpa_s->sme.prev_bssid_set &&
	    !(wpa_s->drv_flags & WPA_DRIVER_FLAGS_USER_SPACE_MLME)) {
		/*
		 * cfg80211/mac80211 can get into somewhat confused state if
		 * the AP only disassociates us and leaves us in authenticated
		 * state. For now, force the state to be cleared to avoid
		 * confusing errors if we try to associate with the AP again.
		 */
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Deauthenticate to clear "
			"driver state");
		wpa_drv_deauthenticate(wpa_s, wpa_s->sme.prev_bssid,
				       WLAN_REASON_DEAUTH_LEAVING);
	}
}


static void sme_auth_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	if (wpa_s->wpa_state == WPA_AUTHENTICATING) {
		wpa_msg(wpa_s, MSG_DEBUG, "SME: Authentication timeout");
		sme_deauth(wpa_s);
	}
}


static void sme_assoc_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	if (wpa_s->wpa_state == WPA_ASSOCIATING) {
		wpa_msg(wpa_s, MSG_DEBUG, "SME: Association timeout");
		sme_deauth(wpa_s);
	}
}


void sme_state_changed(struct wpa_supplicant *wpa_s)
{
	/* Make sure timers are cleaned up appropriately. */
	if (wpa_s->wpa_state != WPA_ASSOCIATING)
		eloop_cancel_timeout(sme_assoc_timer, wpa_s, NULL);
	if (wpa_s->wpa_state != WPA_AUTHENTICATING)
		eloop_cancel_timeout(sme_auth_timer, wpa_s, NULL);
}


void sme_disassoc_while_authenticating(struct wpa_supplicant *wpa_s,
				       const u8 *prev_pending_bssid)
{
	/*
	 * mac80211-workaround to force deauth on failed auth cmd,
	 * requires us to remain in authenticating state to allow the
	 * second authentication attempt to be continued properly.
	 */
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Allow pending authentication "
		"to proceed after disconnection event");
	wpa_supplicant_set_state(wpa_s, WPA_AUTHENTICATING);
	os_memcpy(wpa_s->pending_bssid, prev_pending_bssid, ETH_ALEN);

	/*
	 * Re-arm authentication timer in case auth fails for whatever reason.
	 */
	eloop_cancel_timeout(sme_auth_timer, wpa_s, NULL);
	eloop_register_timeout(SME_AUTH_TIMEOUT, 0, sme_auth_timer, wpa_s,
			       NULL);
}


void sme_deinit(struct wpa_supplicant *wpa_s)
{
	os_free(wpa_s->sme.ft_ies);
	wpa_s->sme.ft_ies = NULL;
	wpa_s->sme.ft_ies_len = 0;
#ifdef CONFIG_IEEE80211W
	sme_stop_sa_query(wpa_s);
#endif /* CONFIG_IEEE80211W */

	eloop_cancel_timeout(sme_assoc_timer, wpa_s, NULL);
	eloop_cancel_timeout(sme_auth_timer, wpa_s, NULL);
}


#ifdef CONFIG_IEEE80211W

static const unsigned int sa_query_max_timeout = 1000;
static const unsigned int sa_query_retry_timeout = 201;

static int sme_check_sa_query_timeout(struct wpa_supplicant *wpa_s)
{
	u32 tu;
	struct os_time now, passed;
	os_get_time(&now);
	os_time_sub(&now, &wpa_s->sme.sa_query_start, &passed);
	tu = (passed.sec * 1000000 + passed.usec) / 1024;
	if (sa_query_max_timeout < tu) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: SA Query timed out");
		sme_stop_sa_query(wpa_s);
		wpa_supplicant_deauthenticate(
			wpa_s, WLAN_REASON_PREV_AUTH_NOT_VALID);
		return 1;
	}

	return 0;
}


static void sme_send_sa_query_req(struct wpa_supplicant *wpa_s,
				  const u8 *trans_id)
{
	u8 req[2 + WLAN_SA_QUERY_TR_ID_LEN];
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Sending SA Query Request to "
		MACSTR, MAC2STR(wpa_s->bssid));
	wpa_hexdump(MSG_DEBUG, "SME: SA Query Transaction ID",
		    trans_id, WLAN_SA_QUERY_TR_ID_LEN);
	req[0] = WLAN_ACTION_SA_QUERY;
	req[1] = WLAN_SA_QUERY_REQUEST;
	os_memcpy(req + 2, trans_id, WLAN_SA_QUERY_TR_ID_LEN);
	if (wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				wpa_s->own_addr, wpa_s->bssid,
				req, sizeof(req)) < 0)
		wpa_msg(wpa_s, MSG_INFO, "SME: Failed to send SA Query "
			"Request");
}


static void sme_sa_query_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	unsigned int timeout, sec, usec;
	u8 *trans_id, *nbuf;

	if (wpa_s->sme.sa_query_count > 0 &&
	    sme_check_sa_query_timeout(wpa_s))
		return;

	nbuf = os_realloc(wpa_s->sme.sa_query_trans_id,
			  (wpa_s->sme.sa_query_count + 1) *
			  WLAN_SA_QUERY_TR_ID_LEN);
	if (nbuf == NULL)
		return;
	if (wpa_s->sme.sa_query_count == 0) {
		/* Starting a new SA Query procedure */
		os_get_time(&wpa_s->sme.sa_query_start);
	}
	trans_id = nbuf + wpa_s->sme.sa_query_count * WLAN_SA_QUERY_TR_ID_LEN;
	wpa_s->sme.sa_query_trans_id = nbuf;
	wpa_s->sme.sa_query_count++;

	os_get_random(trans_id, WLAN_SA_QUERY_TR_ID_LEN);

	timeout = sa_query_retry_timeout;
	sec = ((timeout / 1000) * 1024) / 1000;
	usec = (timeout % 1000) * 1024;
	eloop_register_timeout(sec, usec, sme_sa_query_timer, wpa_s, NULL);

	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Association SA Query attempt %d",
		wpa_s->sme.sa_query_count);

	sme_send_sa_query_req(wpa_s, trans_id);
}


static void sme_start_sa_query(struct wpa_supplicant *wpa_s)
{
	sme_sa_query_timer(wpa_s, NULL);
}


void sme_stop_sa_query(struct wpa_supplicant *wpa_s)
{
	eloop_cancel_timeout(sme_sa_query_timer, wpa_s, NULL);
	os_free(wpa_s->sme.sa_query_trans_id);
	wpa_s->sme.sa_query_trans_id = NULL;
	wpa_s->sme.sa_query_count = 0;
}


void sme_event_unprot_disconnect(struct wpa_supplicant *wpa_s, const u8 *sa,
				 const u8 *da, u16 reason_code)
{
	struct wpa_ssid *ssid;

	if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME))
		return;
	if (wpa_s->wpa_state != WPA_COMPLETED)
		return;
	ssid = wpa_s->current_ssid;
	if (ssid == NULL || ssid->ieee80211w == 0)
		return;
	if (os_memcmp(sa, wpa_s->bssid, ETH_ALEN) != 0)
		return;
	if (reason_code != WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA &&
	    reason_code != WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA)
		return;
	if (wpa_s->sme.sa_query_count > 0)
		return;

	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Unprotected disconnect dropped - "
		"possible AP/STA state mismatch - trigger SA Query");
	sme_start_sa_query(wpa_s);
}


void sme_sa_query_rx(struct wpa_supplicant *wpa_s, const u8 *sa,
		     const u8 *data, size_t len)
{
	int i;

	if (wpa_s->sme.sa_query_trans_id == NULL ||
	    len < 1 + WLAN_SA_QUERY_TR_ID_LEN ||
	    data[0] != WLAN_SA_QUERY_RESPONSE)
		return;
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Received SA Query response from "
		MACSTR " (trans_id %02x%02x)", MAC2STR(sa), data[1], data[2]);

	if (os_memcmp(sa, wpa_s->bssid, ETH_ALEN) != 0)
		return;

	for (i = 0; i < wpa_s->sme.sa_query_count; i++) {
		if (os_memcmp(wpa_s->sme.sa_query_trans_id +
			      i * WLAN_SA_QUERY_TR_ID_LEN,
			      data + 1, WLAN_SA_QUERY_TR_ID_LEN) == 0)
			break;
	}

	if (i >= wpa_s->sme.sa_query_count) {
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: No matching SA Query "
			"transaction identifier found");
		return;
	}

	wpa_dbg(wpa_s, MSG_DEBUG, "SME: Reply to pending SA Query received "
		"from " MACSTR, MAC2STR(sa));
	sme_stop_sa_query(wpa_s);
}

#endif /* CONFIG_IEEE80211W */
