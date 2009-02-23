/*
 * hostapd / Callback functions for driver wrappers
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
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

#include "hostapd.h"
#include "driver_i.h"
#include "ieee802_11.h"
#include "radius/radius.h"
#include "sta_info.h"
#include "accounting.h"
#include "tkip_countermeasures.h"
#include "ieee802_1x.h"
#include "wpa.h"
#include "iapp.h"
#include "wme.h"


struct prune_data {
	struct hostapd_data *hapd;
	const u8 *addr;
};

static int prune_associations(struct hostapd_iface *iface, void *ctx)
{
	struct prune_data *data = ctx;
	struct sta_info *osta;
	struct hostapd_data *ohapd;
	size_t j;

	for (j = 0; j < iface->num_bss; j++) {
		ohapd = iface->bss[j];
		if (ohapd == data->hapd)
			continue;
		osta = ap_get_sta(ohapd, data->addr);
		if (!osta)
			continue;

		ap_sta_disassociate(ohapd, osta, WLAN_REASON_UNSPECIFIED);
	}

	return 0;
}

/**
 * hostapd_prune_associations - Remove extraneous associations
 * @hapd: Pointer to BSS data for the most recent association
 * @sta: Pointer to the associated STA data
 *
 * This function looks through all radios and BSS's for previous
 * (stale) associations of STA. If any are found they are removed.
 */
static void hostapd_prune_associations(struct hostapd_data *hapd,
				       struct sta_info *sta)
{
	struct prune_data data;
	data.hapd = hapd;
	data.addr = sta->addr;
	hostapd_for_each_interface(prune_associations, &data);
}


/**
 * hostapd_new_assoc_sta - Notify that a new station associated with the AP
 * @hapd: Pointer to BSS data
 * @sta: Pointer to the associated STA data
 * @reassoc: 1 to indicate this was a re-association; 0 = first association
 *
 * This function will be called whenever a station associates with the AP. It
 * can be called from ieee802_11.c for drivers that export MLME to hostapd and
 * from driver_*.c for drivers that take care of management frames (IEEE 802.11
 * authentication and association) internally.
 */
void hostapd_new_assoc_sta(struct hostapd_data *hapd, struct sta_info *sta,
			   int reassoc)
{
	if (hapd->tkip_countermeasures) {
		hostapd_sta_deauth(hapd, sta->addr,
				   WLAN_REASON_MICHAEL_MIC_FAILURE);
		return;
	}

	hostapd_prune_associations(hapd, sta);

	/* IEEE 802.11F (IAPP) */
	if (hapd->conf->ieee802_11f)
		iapp_new_station(hapd->iapp, sta);

	/* Start accounting here, if IEEE 802.1X and WPA are not used.
	 * IEEE 802.1X/WPA code will start accounting after the station has
	 * been authorized. */
	if (!hapd->conf->ieee802_1x && !hapd->conf->wpa)
		accounting_sta_start(hapd, sta);

	hostapd_wme_sta_config(hapd, sta);

	/* Start IEEE 802.1X authentication process for new stations */
	ieee802_1x_new_station(hapd, sta);
	if (reassoc) {
		if (sta->auth_alg != WLAN_AUTH_FT &&
		    !(sta->flags & (WLAN_STA_WPS | WLAN_STA_MAYBE_WPS)))
			wpa_auth_sm_event(sta->wpa_sm, WPA_REAUTH);
	} else
		wpa_auth_sta_associated(hapd->wpa_auth, sta->wpa_sm);
}


void hostapd_tx_status(struct hostapd_data *hapd, const u8 *addr,
		       const u8 *buf, size_t len, int ack)
{
	struct sta_info *sta;

	sta = ap_get_sta(hapd, addr);
	if (sta && sta->flags & WLAN_STA_PENDING_POLL) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR " %s pending "
			   "activity poll", MAC2STR(sta->addr),
			   ack ? "ACKed" : "did not ACK");
		if (ack)
			sta->flags &= ~WLAN_STA_PENDING_POLL;
	}
	if (sta)
		ieee802_1x_tx_status(hapd, sta, buf, len, ack);
}


void hostapd_rx_from_unknown_sta(struct hostapd_data *hapd, const u8 *addr)
{
	struct sta_info *sta;

	sta = ap_get_sta(hapd, addr);
	if (!sta || !(sta->flags & WLAN_STA_ASSOC)) {
		wpa_printf(MSG_DEBUG, "Data/PS-poll frame from not associated "
			   "STA " MACSTR, MAC2STR(addr));
		if (sta && (sta->flags & WLAN_STA_AUTH))
			hostapd_sta_disassoc(
				hapd, addr,
				WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
		else
			hostapd_sta_deauth(
				hapd, addr,
				WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
	}
}


int hostapd_notif_assoc(struct hostapd_data *hapd, const u8 *addr,
			const u8 *ie, size_t ielen)
{
	struct sta_info *sta;
	int new_assoc, res;

	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "associated");

	sta = ap_get_sta(hapd, addr);
	if (sta) {
		accounting_sta_stop(hapd, sta);
	} else {
		sta = ap_sta_add(hapd, addr);
		if (sta == NULL)
			return -1;
	}
	sta->flags &= ~(WLAN_STA_WPS | WLAN_STA_MAYBE_WPS);

	if (hapd->conf->wpa) {
		if (ie == NULL || ielen == 0) {
			if (hapd->conf->wps_state) {
				wpa_printf(MSG_DEBUG, "STA did not include "
					   "WPA/RSN IE in (Re)Association "
					   "Request - possible WPS use");
				sta->flags |= WLAN_STA_MAYBE_WPS;
				goto skip_wpa_check;
			}

			wpa_printf(MSG_DEBUG, "No WPA/RSN IE from STA");
			return -1;
		}
		if (hapd->conf->wps_state && ie[0] == 0xdd && ie[1] >= 4 &&
		    os_memcmp(ie + 2, "\x00\x50\xf2\x04", 4) == 0) {
			sta->flags |= WLAN_STA_WPS;
			goto skip_wpa_check;
		}

		if (sta->wpa_sm == NULL)
			sta->wpa_sm = wpa_auth_sta_init(hapd->wpa_auth,
							sta->addr);
		if (sta->wpa_sm == NULL) {
			wpa_printf(MSG_ERROR, "Failed to initialize WPA state "
				   "machine");
			return -1;
		}
		res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,
					  ie, ielen, NULL, 0);
		if (res != WPA_IE_OK) {
			wpa_printf(MSG_DEBUG, "WPA/RSN information element "
				   "rejected? (res %u)", res);
			wpa_hexdump(MSG_DEBUG, "IE", ie, ielen);
			return -1;
		}
	} else if (hapd->conf->wps_state) {
		if (ie && ielen > 4 && ie[0] == 0xdd && ie[1] >= 4 &&
		    os_memcmp(ie + 2, "\x00\x50\xf2\x04", 4) == 0) {
			sta->flags |= WLAN_STA_WPS;
		} else
			sta->flags |= WLAN_STA_MAYBE_WPS;
	}
skip_wpa_check:

	new_assoc = (sta->flags & WLAN_STA_ASSOC) == 0;
	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
	wpa_auth_sm_event(sta->wpa_sm, WPA_ASSOC);

	hostapd_new_assoc_sta(hapd, sta, !new_assoc);

	ieee802_1x_notify_port_enabled(sta->eapol_sm, 1);

	return 0;
}


void hostapd_notif_disassoc(struct hostapd_data *hapd, const u8 *addr)
{
	struct sta_info *sta;

	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "disassociated");

	sta = ap_get_sta(hapd, addr);
	if (sta == NULL) {
		wpa_printf(MSG_DEBUG, "Disassociation notification for "
			   "unknown STA " MACSTR, MAC2STR(addr));
		return;
	}

	sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
	wpa_auth_sm_event(sta->wpa_sm, WPA_DISASSOC);
	sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
	ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
	ap_free_sta(hapd, sta);
}


void hostapd_eapol_receive(struct hostapd_data *hapd, const u8 *sa,
			   const u8 *buf, size_t len)
{
	ieee802_1x_receive(hapd, sa, buf, len);
}


#ifdef NEED_MLME
void hostapd_mgmt_rx(struct hostapd_data *hapd, u8 *buf, size_t len,
		     u16 stype, struct hostapd_frame_info *fi)
{
	ieee802_11_mgmt(hapd, buf, len, stype, fi);
}


void hostapd_mgmt_tx_cb(struct hostapd_data *hapd, u8 *buf, size_t len,
			u16 stype, int ok)
{
	ieee802_11_mgmt_cb(hapd, buf, len, stype, ok);
}
#endif /* NEED_MLME */


void hostapd_michael_mic_failure(struct hostapd_data *hapd, const u8 *addr)
{
	michael_mic_failure(hapd, addr, 1);
}
