/*
 * hostapd / WMM (Wi-Fi Multimedia)
 * Copyright 2002-2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
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
#include "ieee802_11.h"
#include "wme.h"
#include "sta_info.h"
#include "driver_i.h"


/* TODO: maintain separate sequence and fragment numbers for each AC
 * TODO: IGMP snooping to track which multicasts to forward - and use QOS-DATA
 * if only WMM stations are receiving a certain group */


static u8 wmm_oui[3] = { 0x00, 0x50, 0xf2 };


/*
 * Add WMM Parameter Element to Beacon, Probe Response, and (Re)Association
 * Response frames.
 */
u8 * hostapd_eid_wmm(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	struct wmm_parameter_element *wmm =
		(struct wmm_parameter_element *) (pos + 2);
	int e;

	if (!hapd->conf->wmm_enabled)
		return eid;
	eid[0] = WLAN_EID_VENDOR_SPECIFIC;
	wmm->oui[0] = 0x00;
	wmm->oui[1] = 0x50;
	wmm->oui[2] = 0xf2;
	wmm->oui_type = WMM_OUI_TYPE;
	wmm->oui_subtype = WMM_OUI_SUBTYPE_PARAMETER_ELEMENT;
	wmm->version = WMM_VERSION;
	wmm->qos_info = hapd->parameter_set_count & 0xf;

	/* fill in a parameter set record for each AC */
	for (e = 0; e < 4; e++) {
		struct wmm_ac_parameter *ac = &wmm->ac[e];
		struct hostapd_wmm_ac_params *acp =
			&hapd->iconf->wmm_ac_params[e];

		ac->aifsn = acp->aifs;
		ac->acm = acp->admission_control_mandatory;
		ac->aci = e;
		ac->reserved = 0;
		ac->e_cw_min = acp->cwmin;
		ac->e_cw_max = acp->cwmax;
		ac->txop_limit = host_to_le16(acp->txop_limit);
	}

	pos = (u8 *) (wmm + 1);
	eid[1] = pos - eid - 2; /* element length */

	return pos;
}


/* This function is called when a station sends an association request with
 * WMM info element. The function returns zero on success or non-zero on any
 * error in WMM element. eid does not include Element ID and Length octets. */
int hostapd_eid_wmm_valid(struct hostapd_data *hapd, u8 *eid, size_t len)
{
	struct wmm_information_element *wmm;

	wpa_hexdump(MSG_MSGDUMP, "WMM IE", eid, len);

	if (len < sizeof(struct wmm_information_element)) {
		wpa_printf(MSG_DEBUG, "Too short WMM IE (len=%lu)",
			   (unsigned long) len);
		return -1;
	}

	wmm = (struct wmm_information_element *) eid;
	wpa_printf(MSG_DEBUG, "Validating WMM IE: OUI %02x:%02x:%02x  "
		   "OUI type %d  OUI sub-type %d  version %d",
		   wmm->oui[0], wmm->oui[1], wmm->oui[2], wmm->oui_type,
		   wmm->oui_subtype, wmm->version);
	if (os_memcmp(wmm->oui, wmm_oui, sizeof(wmm_oui)) != 0 ||
	    wmm->oui_type != WMM_OUI_TYPE ||
	    wmm->oui_subtype != WMM_OUI_SUBTYPE_INFORMATION_ELEMENT ||
	    wmm->version != WMM_VERSION) {
		wpa_printf(MSG_DEBUG, "Unsupported WMM IE OUI/Type/Subtype/"
			   "Version");
		return -1;
	}

	return 0;
}


/* This function is called when a station sends an ACK frame for an AssocResp
 * frame (status=success) and the matching AssocReq contained a WMM element.
 */
int hostapd_wmm_sta_config(struct hostapd_data *hapd, struct sta_info *sta)
{
	/* update kernel STA data for WMM related items (WLAN_STA_WPA flag) */
	if (sta->flags & WLAN_STA_WMM)
		hostapd_sta_set_flags(hapd, sta->addr, sta->flags,
				      WLAN_STA_WMM, ~0);
	else
		hostapd_sta_set_flags(hapd, sta->addr, sta->flags,
				      0, ~WLAN_STA_WMM);

	return 0;
}


static void wmm_send_action(struct hostapd_data *hapd, const u8 *addr,
			    const struct wmm_tspec_element *tspec,
			    u8 action_code, u8 dialogue_token, u8 status_code)
{
	u8 buf[256];
	struct ieee80211_mgmt *m = (struct ieee80211_mgmt *) buf;
	struct wmm_tspec_element *t = (struct wmm_tspec_element *)
		m->u.action.u.wmm_action.variable;
	int len;

	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		       "action response - reason %d", status_code);
	os_memset(buf, 0, sizeof(buf));
	m->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					WLAN_FC_STYPE_ACTION);
	os_memcpy(m->da, addr, ETH_ALEN);
	os_memcpy(m->sa, hapd->own_addr, ETH_ALEN);
	os_memcpy(m->bssid, hapd->own_addr, ETH_ALEN);
	m->u.action.category = WLAN_ACTION_WMM;
	m->u.action.u.wmm_action.action_code = action_code;
	m->u.action.u.wmm_action.dialog_token = dialogue_token;
	m->u.action.u.wmm_action.status_code = status_code;
	os_memcpy(t, tspec, sizeof(struct wmm_tspec_element));
	len = ((u8 *) (t + 1)) - buf;

	if (hostapd_send_mgmt_frame(hapd, m, len, 0) < 0)
		perror("wmm_send_action: send");
}


/* given frame data payload size in bytes, and data_rate in bits per second
 * returns time to complete frame exchange */
/* FIX: should not use floating point types */
static double wmm_frame_exchange_time(int bytes, int data_rate, int encryption,
				      int cts_protection)
{
	/* TODO: account for MAC/PHY headers correctly */
	/* TODO: account for encryption headers */
	/* TODO: account for WDS headers */
	/* TODO: account for CTS protection */
	/* TODO: account for SIFS + ACK at minimum PHY rate */
	return (bytes + 400) * 8.0 / data_rate;
}


static void wmm_addts_req(struct hostapd_data *hapd,
			  struct ieee80211_mgmt *mgmt,
			  struct wmm_tspec_element *tspec, size_t len)
{
	/* FIX: should not use floating point types */
	double medium_time, pps;

	/* TODO: account for airtime and answer no to tspec setup requests
	 * when none left!! */

	pps = (le_to_host32(tspec->mean_data_rate) / 8.0) /
		le_to_host16(tspec->nominal_msdu_size);
	medium_time = (le_to_host16(tspec->surplus_bandwidth_allowance) / 8) *
		pps *
		wmm_frame_exchange_time(le_to_host16(tspec->nominal_msdu_size),
					le_to_host32(tspec->minimum_phy_rate),
					0, 0);
	tspec->medium_time = host_to_le16(medium_time * 1000000.0 / 32.0);

	wmm_send_action(hapd, mgmt->sa, tspec, WMM_ACTION_CODE_ADDTS_RESP,
			mgmt->u.action.u.wmm_action.dialog_token,
			WMM_ADDTS_STATUS_ADMISSION_ACCEPTED);
}


void hostapd_wmm_action(struct hostapd_data *hapd, struct ieee80211_mgmt *mgmt,
			size_t len)
{
	int action_code;
	int left = len - IEEE80211_HDRLEN - 4;
	u8 *pos = ((u8 *) mgmt) + IEEE80211_HDRLEN + 4;
	struct ieee802_11_elems elems;
	struct sta_info *sta = ap_get_sta(hapd, mgmt->sa);

	/* check that the request comes from a valid station */
	if (!sta ||
	    (sta->flags & (WLAN_STA_ASSOC | WLAN_STA_WMM)) !=
	    (WLAN_STA_ASSOC | WLAN_STA_WMM)) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "wmm action received is not from associated wmm"
			       " station");
		/* TODO: respond with action frame refused status code */
		return;
	}

	/* extract the tspec info element */
	if (ieee802_11_parse_elems(pos, left, &elems, 1) == ParseFailed) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "hostapd_wmm_action - could not parse wmm "
			       "action");
		/* TODO: respond with action frame invalid parameters status
		 * code */
		return;
	}

	if (!elems.wmm_tspec ||
	    elems.wmm_tspec_len != (sizeof(struct wmm_tspec_element) - 2)) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "hostapd_wmm_action - missing or wrong length "
			       "tspec");
		/* TODO: respond with action frame invalid parameters status
		 * code */
		return;
	}

	/* TODO: check the request is for an AC with ACM set, if not, refuse
	 * request */

	action_code = mgmt->u.action.u.wmm_action.action_code;
	switch (action_code) {
	case WMM_ACTION_CODE_ADDTS_REQ:
		wmm_addts_req(hapd, mgmt, (struct wmm_tspec_element *)
			      (elems.wmm_tspec - 2), len);
		return;
#if 0
	/* TODO: needed for client implementation */
	case WMM_ACTION_CODE_ADDTS_RESP:
		wmm_setup_request(hapd, mgmt, len);
		return;
	/* TODO: handle station teardown requests */
	case WMM_ACTION_CODE_DELTS:
		wmm_teardown(hapd, mgmt, len);
		return;
#endif
	}

	hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		       "hostapd_wmm_action - unknown action code %d",
		       action_code);
}
