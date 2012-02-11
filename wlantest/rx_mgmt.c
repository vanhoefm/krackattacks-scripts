/*
 * Received Management frame processing
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "crypto/aes_wrap.h"
#include "wlantest.h"


static const char * mgmt_stype(u16 stype)
{
	switch (stype) {
	case WLAN_FC_STYPE_ASSOC_REQ:
		return "ASSOC-REQ";
	case WLAN_FC_STYPE_ASSOC_RESP:
		return "ASSOC-RESP";
	case WLAN_FC_STYPE_REASSOC_REQ:
		return "REASSOC-REQ";
	case WLAN_FC_STYPE_REASSOC_RESP:
		return "REASSOC-RESP";
	case WLAN_FC_STYPE_PROBE_REQ:
		return "PROBE-REQ";
	case WLAN_FC_STYPE_PROBE_RESP:
		return "PROBE-RESP";
	case WLAN_FC_STYPE_BEACON:
		return "BEACON";
	case WLAN_FC_STYPE_ATIM:
		return "ATIM";
	case WLAN_FC_STYPE_DISASSOC:
		return "DISASSOC";
	case WLAN_FC_STYPE_AUTH:
		return "AUTH";
	case WLAN_FC_STYPE_DEAUTH:
		return "DEAUTH";
	case WLAN_FC_STYPE_ACTION:
		return "ACTION";
	}
	return "??";
}


static void rx_mgmt_beacon(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct ieee802_11_elems elems;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (bss->proberesp_seen)
		return; /* do not override with Beacon data */
	bss->capab_info = le_to_host16(mgmt->u.beacon.capab_info);
	if (ieee802_11_parse_elems(mgmt->u.beacon.variable,
				   len - (mgmt->u.beacon.variable - data),
				   &elems, 0) == ParseFailed) {
		if (bss->parse_error_reported)
			return;
		wpa_printf(MSG_INFO, "Invalid IEs in a Beacon frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		bss->parse_error_reported = 1;
		return;
	}

	bss_update(wt, bss, &elems);
}


static void rx_mgmt_probe_resp(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct ieee802_11_elems elems;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;

	bss->capab_info = le_to_host16(mgmt->u.probe_resp.capab_info);
	if (ieee802_11_parse_elems(mgmt->u.probe_resp.variable,
				   len - (mgmt->u.probe_resp.variable - data),
				   &elems, 0) == ParseFailed) {
		if (bss->parse_error_reported)
			return;
		wpa_printf(MSG_INFO, "Invalid IEs in a Probe Response frame "
			   "from " MACSTR, MAC2STR(mgmt->sa));
		bss->parse_error_reported = 1;
		return;
	}

	bss_update(wt, bss, &elems);
}


static void rx_mgmt_auth(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	u16 alg, trans, status;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->da);
	else
		sta = sta_get(bss, mgmt->sa);
	if (sta == NULL)
		return;

	if (len < 24 + 6) {
		wpa_printf(MSG_INFO, "Too short Authentication frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	alg = le_to_host16(mgmt->u.auth.auth_alg);
	trans = le_to_host16(mgmt->u.auth.auth_transaction);
	status = le_to_host16(mgmt->u.auth.status_code);

	wpa_printf(MSG_DEBUG, "AUTH " MACSTR " -> " MACSTR
		   " (alg=%u trans=%u status=%u)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da), alg, trans, status);

	if (alg == 0 && trans == 2 && status == 0) {
		if (sta->state == STATE1) {
			wpa_printf(MSG_DEBUG, "STA " MACSTR
				   " moved to State 2 with " MACSTR,
				   MAC2STR(sta->addr), MAC2STR(bss->bssid));
			sta->state = STATE2;
		}
	}

	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta->counters[WLANTEST_STA_COUNTER_AUTH_RX]++;
	else
		sta->counters[WLANTEST_STA_COUNTER_AUTH_TX]++;
}


static void deauth_all_stas(struct wlantest_bss *bss)
{
	struct wlantest_sta *sta;
	dl_list_for_each(sta, &bss->sta, struct wlantest_sta, list) {
		if (sta->state == STATE1)
			continue;
		wpa_printf(MSG_DEBUG, "STA " MACSTR
			   " moved to State 1 with " MACSTR,
			   MAC2STR(sta->addr), MAC2STR(bss->bssid));
		sta->state = STATE1;
	}
}


static void tdls_link_down(struct wlantest_bss *bss, struct wlantest_sta *sta)
{
	struct wlantest_tdls *tdls;
	dl_list_for_each(tdls, &bss->tdls, struct wlantest_tdls, list) {
		if ((tdls->init == sta || tdls->resp == sta) && tdls->link_up)
		{
			wpa_printf(MSG_DEBUG, "TDLS: Set link down based on "
				   "STA deauth/disassoc");
			tdls->link_up = 0;
		}
	}
}


static void rx_mgmt_deauth(struct wlantest *wt, const u8 *data, size_t len,
			   int valid)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	u16 fc, reason;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->da);
	else
		sta = sta_get(bss, mgmt->sa);

	if (len < 24 + 2) {
		wpa_printf(MSG_INFO, "Too short Deauthentication frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	reason = le_to_host16(mgmt->u.deauth.reason_code);
	wpa_printf(MSG_DEBUG, "DEAUTH " MACSTR " -> " MACSTR
		   " (reason=%u) (valid=%d)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da),
		   reason, valid);
	wpa_hexdump(MSG_MSGDUMP, "DEAUTH payload", data + 24, len - 24);

	if (sta == NULL) {
		if (valid && mgmt->da[0] == 0xff)
			deauth_all_stas(bss);
		return;
	}

	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0) {
		sta->counters[valid ? WLANTEST_STA_COUNTER_VALID_DEAUTH_RX :
			      WLANTEST_STA_COUNTER_INVALID_DEAUTH_RX]++;
		if (sta->pwrmgt && !sta->pspoll)
			sta->counters[WLANTEST_STA_COUNTER_DEAUTH_RX_ASLEEP]++;
		else
			sta->counters[WLANTEST_STA_COUNTER_DEAUTH_RX_AWAKE]++;

		fc = le_to_host16(mgmt->frame_control);
		if (!(fc & WLAN_FC_ISWEP) && reason == 6)
			sta->counters[WLANTEST_STA_COUNTER_DEAUTH_RX_RC6]++;
		else if (!(fc & WLAN_FC_ISWEP) && reason == 7)
			sta->counters[WLANTEST_STA_COUNTER_DEAUTH_RX_RC7]++;
	} else
		sta->counters[valid ? WLANTEST_STA_COUNTER_VALID_DEAUTH_TX :
			      WLANTEST_STA_COUNTER_INVALID_DEAUTH_TX]++;

	if (!valid) {
		wpa_printf(MSG_INFO, "Do not change STA " MACSTR " State "
			   "since Disassociation frame was not protected "
			   "correctly", MAC2STR(sta->addr));
		return;
	}

	if (sta->state != STATE1) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR
			   " moved to State 1 with " MACSTR,
			   MAC2STR(sta->addr), MAC2STR(bss->bssid));
		sta->state = STATE1;
	}
	tdls_link_down(bss, sta);
}


static void rx_mgmt_assoc_req(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	struct ieee802_11_elems elems;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	sta = sta_get(bss, mgmt->sa);
	if (sta == NULL)
		return;

	if (len < 24 + 4) {
		wpa_printf(MSG_INFO, "Too short Association Request frame "
			   "from " MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	wpa_printf(MSG_DEBUG, "ASSOCREQ " MACSTR " -> " MACSTR
		   " (capab=0x%x listen_int=%u)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da),
		   le_to_host16(mgmt->u.assoc_req.capab_info),
		   le_to_host16(mgmt->u.assoc_req.listen_interval));

	sta->counters[WLANTEST_STA_COUNTER_ASSOCREQ_TX]++;

	if (ieee802_11_parse_elems(mgmt->u.assoc_req.variable,
				   len - (mgmt->u.assoc_req.variable - data),
				   &elems, 0) == ParseFailed) {
		wpa_printf(MSG_INFO, "Invalid IEs in Association Request "
			   "frame from " MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	sta->assocreq_capab_info = le_to_host16(mgmt->u.assoc_req.capab_info);
	sta->assocreq_listen_int =
		le_to_host16(mgmt->u.assoc_req.listen_interval);
	os_free(sta->assocreq_ies);
	sta->assocreq_ies_len = len - (mgmt->u.assoc_req.variable - data);
	sta->assocreq_ies = os_malloc(sta->assocreq_ies_len);
	if (sta->assocreq_ies)
		os_memcpy(sta->assocreq_ies, mgmt->u.assoc_req.variable,
			  sta->assocreq_ies_len);

	sta_update_assoc(sta, &elems);
}


static void rx_mgmt_assoc_resp(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	u16 capab, status, aid;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	sta = sta_get(bss, mgmt->da);
	if (sta == NULL)
		return;

	if (len < 24 + 6) {
		wpa_printf(MSG_INFO, "Too short Association Response frame "
			   "from " MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	capab = le_to_host16(mgmt->u.assoc_resp.capab_info);
	status = le_to_host16(mgmt->u.assoc_resp.status_code);
	aid = le_to_host16(mgmt->u.assoc_resp.aid);

	wpa_printf(MSG_DEBUG, "ASSOCRESP " MACSTR " -> " MACSTR
		   " (capab=0x%x status=%u aid=%u)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da), capab, status,
		   aid & 0x3fff);

	if (status == WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY) {
		struct ieee802_11_elems elems;
		const u8 *ies = mgmt->u.assoc_resp.variable;
		size_t ies_len = len - (mgmt->u.assoc_resp.variable - data);
		if (ieee802_11_parse_elems(ies, ies_len, &elems, 0) ==
		    ParseFailed) {
			wpa_printf(MSG_INFO, "Failed to parse IEs in "
				   "AssocResp from " MACSTR,
				   MAC2STR(mgmt->sa));
		} else if (elems.timeout_int == NULL ||
			   elems.timeout_int_len != 5 ||
			   elems.timeout_int[0] !=
			   WLAN_TIMEOUT_ASSOC_COMEBACK) {
			wpa_printf(MSG_INFO, "No valid Timeout Interval IE "
				   "with Assoc Comeback time in AssocResp "
				   "(status=30) from " MACSTR,
				   MAC2STR(mgmt->sa));
		} else {
			sta->counters[
				WLANTEST_STA_COUNTER_ASSOCRESP_COMEBACK]++;
		}
	}

	if (status)
		return;

	if ((aid & 0xc000) != 0xc000) {
		wpa_printf(MSG_DEBUG, "Two MSBs of the AID were not set to 1 "
			   "in Association Response from " MACSTR,
			   MAC2STR(mgmt->sa));
	}
	sta->aid = aid & 0xc000;

	if (sta->state < STATE2) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR " was not in State 2 when "
			   "getting associated", MAC2STR(sta->addr));
	}

	if (sta->state < STATE3) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR
			   " moved to State 3 with " MACSTR,
			   MAC2STR(sta->addr), MAC2STR(bss->bssid));
		sta->state = STATE3;
	}
}


static void rx_mgmt_reassoc_req(struct wlantest *wt, const u8 *data,
				size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	struct ieee802_11_elems elems;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	sta = sta_get(bss, mgmt->sa);
	if (sta == NULL)
		return;

	if (len < 24 + 4 + ETH_ALEN) {
		wpa_printf(MSG_INFO, "Too short Reassociation Request frame "
			   "from " MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	wpa_printf(MSG_DEBUG, "REASSOCREQ " MACSTR " -> " MACSTR
		   " (capab=0x%x listen_int=%u current_ap=" MACSTR ")",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da),
		   le_to_host16(mgmt->u.reassoc_req.capab_info),
		   le_to_host16(mgmt->u.reassoc_req.listen_interval),
		   MAC2STR(mgmt->u.reassoc_req.current_ap));

	sta->counters[WLANTEST_STA_COUNTER_REASSOCREQ_TX]++;

	if (ieee802_11_parse_elems(mgmt->u.reassoc_req.variable,
				   len - (mgmt->u.reassoc_req.variable - data),
				   &elems, 0) == ParseFailed) {
		wpa_printf(MSG_INFO, "Invalid IEs in Reassociation Request "
			   "frame from " MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	sta->assocreq_capab_info =
		le_to_host16(mgmt->u.reassoc_req.capab_info);
	sta->assocreq_listen_int =
		le_to_host16(mgmt->u.reassoc_req.listen_interval);
	os_free(sta->assocreq_ies);
	sta->assocreq_ies_len = len - (mgmt->u.reassoc_req.variable - data);
	sta->assocreq_ies = os_malloc(sta->assocreq_ies_len);
	if (sta->assocreq_ies)
		os_memcpy(sta->assocreq_ies, mgmt->u.reassoc_req.variable,
			  sta->assocreq_ies_len);

	sta_update_assoc(sta, &elems);
}


static void rx_mgmt_reassoc_resp(struct wlantest *wt, const u8 *data,
				 size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	u16 capab, status, aid;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	sta = sta_get(bss, mgmt->da);
	if (sta == NULL)
		return;

	if (len < 24 + 6) {
		wpa_printf(MSG_INFO, "Too short Reassociation Response frame "
			   "from " MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	capab = le_to_host16(mgmt->u.reassoc_resp.capab_info);
	status = le_to_host16(mgmt->u.reassoc_resp.status_code);
	aid = le_to_host16(mgmt->u.reassoc_resp.aid);

	wpa_printf(MSG_DEBUG, "REASSOCRESP " MACSTR " -> " MACSTR
		   " (capab=0x%x status=%u aid=%u)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da), capab, status,
		   aid & 0x3fff);

	if (status == WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY) {
		struct ieee802_11_elems elems;
		const u8 *ies = mgmt->u.reassoc_resp.variable;
		size_t ies_len = len - (mgmt->u.reassoc_resp.variable - data);
		if (ieee802_11_parse_elems(ies, ies_len, &elems, 0) ==
		    ParseFailed) {
			wpa_printf(MSG_INFO, "Failed to parse IEs in "
				   "ReassocResp from " MACSTR,
				   MAC2STR(mgmt->sa));
		} else if (elems.timeout_int == NULL ||
			   elems.timeout_int_len != 5 ||
			   elems.timeout_int[0] !=
			   WLAN_TIMEOUT_ASSOC_COMEBACK) {
			wpa_printf(MSG_INFO, "No valid Timeout Interval IE "
				   "with Assoc Comeback time in ReassocResp "
				   "(status=30) from " MACSTR,
				   MAC2STR(mgmt->sa));
		} else {
			sta->counters[
				WLANTEST_STA_COUNTER_REASSOCRESP_COMEBACK]++;
		}
	}

	if (status)
		return;

	if ((aid & 0xc000) != 0xc000) {
		wpa_printf(MSG_DEBUG, "Two MSBs of the AID were not set to 1 "
			   "in Reassociation Response from " MACSTR,
			   MAC2STR(mgmt->sa));
	}
	sta->aid = aid & 0xc000;

	if (sta->state < STATE2) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR " was not in State 2 when "
			   "getting associated", MAC2STR(sta->addr));
	}

	if (sta->state < STATE3) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR
			   " moved to State 3 with " MACSTR,
			   MAC2STR(sta->addr), MAC2STR(bss->bssid));
		sta->state = STATE3;
	}
}


static void disassoc_all_stas(struct wlantest_bss *bss)
{
	struct wlantest_sta *sta;
	dl_list_for_each(sta, &bss->sta, struct wlantest_sta, list) {
		if (sta->state <= STATE2)
			continue;
		wpa_printf(MSG_DEBUG, "STA " MACSTR
			   " moved to State 2 with " MACSTR,
			   MAC2STR(sta->addr), MAC2STR(bss->bssid));
		sta->state = STATE2;
	}
}


static void rx_mgmt_disassoc(struct wlantest *wt, const u8 *data, size_t len,
			     int valid)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	u16 fc, reason;

	mgmt = (const struct ieee80211_mgmt *) data;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->da);
	else
		sta = sta_get(bss, mgmt->sa);

	if (len < 24 + 2) {
		wpa_printf(MSG_INFO, "Too short Disassociation frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	reason = le_to_host16(mgmt->u.disassoc.reason_code);
	wpa_printf(MSG_DEBUG, "DISASSOC " MACSTR " -> " MACSTR
		   " (reason=%u) (valid=%d)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da),
		   reason, valid);
	wpa_hexdump(MSG_MSGDUMP, "DISASSOC payload", data + 24, len - 24);

	if (sta == NULL) {
		if (valid && mgmt->da[0] == 0xff)
			disassoc_all_stas(bss);
		return;
	}

	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0) {
		sta->counters[valid ? WLANTEST_STA_COUNTER_VALID_DISASSOC_RX :
			      WLANTEST_STA_COUNTER_INVALID_DISASSOC_RX]++;
		if (sta->pwrmgt && !sta->pspoll)
			sta->counters[
				WLANTEST_STA_COUNTER_DISASSOC_RX_ASLEEP]++;
		else
			sta->counters[
				WLANTEST_STA_COUNTER_DISASSOC_RX_AWAKE]++;

		fc = le_to_host16(mgmt->frame_control);
		if (!(fc & WLAN_FC_ISWEP) && reason == 6)
			sta->counters[WLANTEST_STA_COUNTER_DISASSOC_RX_RC6]++;
		else if (!(fc & WLAN_FC_ISWEP) && reason == 7)
			sta->counters[WLANTEST_STA_COUNTER_DISASSOC_RX_RC7]++;
	} else
		sta->counters[valid ? WLANTEST_STA_COUNTER_VALID_DISASSOC_TX :
			      WLANTEST_STA_COUNTER_INVALID_DISASSOC_TX]++;

	if (!valid) {
		wpa_printf(MSG_INFO, "Do not change STA " MACSTR " State "
			   "since Disassociation frame was not protected "
			   "correctly", MAC2STR(sta->addr));
		return;
	}

	if (sta->state < STATE2) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR " was not in State 2 or 3 "
			   "when getting disassociated", MAC2STR(sta->addr));
	}

	if (sta->state > STATE2) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR
			   " moved to State 2 with " MACSTR,
			   MAC2STR(sta->addr), MAC2STR(bss->bssid));
		sta->state = STATE2;
	}
	tdls_link_down(bss, sta);
}


static void rx_mgmt_action_sa_query_req(struct wlantest *wt,
					struct wlantest_sta *sta,
					const struct ieee80211_mgmt *mgmt,
					size_t len, int valid)
{
	const u8 *rx_id;
	u8 *id;

	rx_id = (const u8 *) mgmt->u.action.u.sa_query_req.trans_id;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		id = sta->ap_sa_query_tr;
	else
		id = sta->sta_sa_query_tr;
	wpa_printf(MSG_INFO, "SA Query Request " MACSTR " -> " MACSTR
		   " (trans_id=%02x%02x)%s",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da), rx_id[0], rx_id[1],
		   valid ? "" : " (invalid protection)");
	os_memcpy(id, mgmt->u.action.u.sa_query_req.trans_id, 2);
	if (os_memcmp(mgmt->sa, sta->addr, ETH_ALEN) == 0)
		sta->counters[valid ?
			      WLANTEST_STA_COUNTER_VALID_SAQUERYREQ_TX :
			      WLANTEST_STA_COUNTER_INVALID_SAQUERYREQ_TX]++;
	else
		sta->counters[valid ?
			      WLANTEST_STA_COUNTER_VALID_SAQUERYREQ_RX :
			      WLANTEST_STA_COUNTER_INVALID_SAQUERYREQ_RX]++;
}


static void rx_mgmt_action_sa_query_resp(struct wlantest *wt,
					 struct wlantest_sta *sta,
					 const struct ieee80211_mgmt *mgmt,
					 size_t len, int valid)
{
	const u8 *rx_id;
	u8 *id;
	int match;

	rx_id = (const u8 *) mgmt->u.action.u.sa_query_resp.trans_id;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		id = sta->sta_sa_query_tr;
	else
		id = sta->ap_sa_query_tr;
	match = os_memcmp(rx_id, id, 2) == 0;
	wpa_printf(MSG_INFO, "SA Query Response " MACSTR " -> " MACSTR
		   " (trans_id=%02x%02x; %s)%s",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da), rx_id[0], rx_id[1],
		   match ? "match" : "mismatch",
		   valid ? "" : " (invalid protection)");
	if (os_memcmp(mgmt->sa, sta->addr, ETH_ALEN) == 0)
		sta->counters[(valid && match) ?
			      WLANTEST_STA_COUNTER_VALID_SAQUERYRESP_TX :
			      WLANTEST_STA_COUNTER_INVALID_SAQUERYRESP_TX]++;
	else
		sta->counters[(valid && match) ?
			      WLANTEST_STA_COUNTER_VALID_SAQUERYRESP_RX :
			      WLANTEST_STA_COUNTER_INVALID_SAQUERYRESP_RX]++;
}


static void rx_mgmt_action_sa_query(struct wlantest *wt,
				    struct wlantest_sta *sta,
				    const struct ieee80211_mgmt *mgmt,
				    size_t len, int valid)
{
	if (len < 24 + 2 + WLAN_SA_QUERY_TR_ID_LEN) {
		wpa_printf(MSG_INFO, "Too short SA Query frame from " MACSTR,
			   MAC2STR(mgmt->sa));
		return;
	}

	if (len > 24 + 2 + WLAN_SA_QUERY_TR_ID_LEN) {
		size_t elen = len - (24 + 2 + WLAN_SA_QUERY_TR_ID_LEN);
		wpa_printf(MSG_INFO, "Unexpected %u octets of extra data at "
			   "the end of SA Query frame from " MACSTR,
			   (unsigned) elen, MAC2STR(mgmt->sa));
		wpa_hexdump(MSG_INFO, "SA Query extra data",
			    ((const u8 *) mgmt) + len - elen, elen);
	}

	switch (mgmt->u.action.u.sa_query_req.action) {
	case WLAN_SA_QUERY_REQUEST:
		rx_mgmt_action_sa_query_req(wt, sta, mgmt, len, valid);
		break;
	case WLAN_SA_QUERY_RESPONSE:
		rx_mgmt_action_sa_query_resp(wt, sta, mgmt, len, valid);
		break;
	default:
		wpa_printf(MSG_INFO, "Unexpected SA Query action value %u "
			   "from " MACSTR,
			   mgmt->u.action.u.sa_query_req.action,
			   MAC2STR(mgmt->sa));
	}
}


static void rx_mgmt_action(struct wlantest *wt, const u8 *data, size_t len,
			   int valid)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;

	mgmt = (const struct ieee80211_mgmt *) data;
	if (mgmt->da[0] & 0x01) {
		wpa_printf(MSG_DEBUG, "Group addressed Action frame: DA="
			   MACSTR " SA=" MACSTR " BSSID=" MACSTR
			   " category=%u",
			   MAC2STR(mgmt->da), MAC2STR(mgmt->sa),
			   MAC2STR(mgmt->bssid), mgmt->u.action.category);
		return; /* Ignore group addressed Action frames for now */
	}
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->da);
	else
		sta = sta_get(bss, mgmt->sa);
	if (sta == NULL)
		return;

	if (len < 24 + 1) {
		wpa_printf(MSG_INFO, "Too short Action frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		return;
	}

	wpa_printf(MSG_DEBUG, "ACTION " MACSTR " -> " MACSTR
		   " (category=%u) (valid=%d)",
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da),
		   mgmt->u.action.category, valid);
	wpa_hexdump(MSG_MSGDUMP, "ACTION payload", data + 24, len - 24);

	if (mgmt->u.action.category != WLAN_ACTION_PUBLIC &&
	    sta->state < STATE3) {
		wpa_printf(MSG_INFO, "Action frame sent when STA is not in "
			   "State 3 (SA=" MACSTR " DATA=" MACSTR ")",
			   MAC2STR(mgmt->sa), MAC2STR(mgmt->da));
	}

	switch (mgmt->u.action.category) {
	case WLAN_ACTION_SA_QUERY:
		rx_mgmt_action_sa_query(wt, sta, mgmt, len, valid);
		break;
	}
}


static int check_mmie_mic(const u8 *igtk, const u8 *data, size_t len)
{
	u8 *buf;
	u8 mic[16];
	u16 fc;
	const struct ieee80211_hdr *hdr;

	buf = os_malloc(len + 20 - 24);
	if (buf == NULL)
		return -1;

	/* BIP AAD: FC(masked) A1 A2 A3 */
	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
	fc &= ~(WLAN_FC_RETRY | WLAN_FC_PWRMGT | WLAN_FC_MOREDATA);
	WPA_PUT_LE16(buf, fc);
	os_memcpy(buf + 2, hdr->addr1, 3 * ETH_ALEN);

	/* Frame body with MMIE MIC masked to zero */
	os_memcpy(buf + 20, data + 24, len - 24 - 8);
	os_memset(buf + 20 + len - 24 - 8, 0, 8);

	wpa_hexdump(MSG_MSGDUMP, "BIP: AAD|Body(masked)", buf, len + 20 - 24);
	/* MIC = L(AES-128-CMAC(AAD || Frame Body(masked)), 0, 64) */
	if (omac1_aes_128(igtk, buf, len + 20 - 24, mic) < 0) {
		os_free(buf);
		return -1;
	}

	os_free(buf);

	if (os_memcmp(data + len - 8, mic, 8) != 0)
		return -1;

	return 0;
}


static int check_bip(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	u16 fc, stype;
	const u8 *mmie;
	u16 keyid;
	struct wlantest_bss *bss;

	mgmt = (const struct ieee80211_mgmt *) data;
	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);

	if (stype == WLAN_FC_STYPE_ACTION) {
		if (len < 24 + 1)
			return 0;
		if (mgmt->u.action.category == WLAN_ACTION_PUBLIC)
			return 0; /* Not a robust management frame */
	}

	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return 0; /* No key known yet */

	if (len < 24 + 18 || data[len - 18] != WLAN_EID_MMIE ||
	    data[len - 17] != 16) {
		/* No MMIE */
		if (bss->rsn_capab & WPA_CAPABILITY_MFPC) {
			wpa_printf(MSG_INFO, "Robust group-addressed "
				   "management frame sent without BIP by "
				   MACSTR, MAC2STR(mgmt->sa));
			bss->counters[WLANTEST_BSS_COUNTER_MISSING_BIP_MMIE]++;
			return -1;
		}
		return 0;
	}

	mmie = data + len - 16;
	keyid = WPA_GET_LE16(mmie);
	if (keyid & 0xf000) {
		wpa_printf(MSG_INFO, "MMIE KeyID reserved bits not zero "
			   "(%04x) from " MACSTR, keyid, MAC2STR(mgmt->sa));
		keyid &= 0x0fff;
	}
	if (keyid < 4 || keyid > 5) {
		wpa_printf(MSG_INFO, "Unexpected MMIE KeyID %u from " MACSTR,
			   keyid, MAC2STR(mgmt->sa));
		bss->counters[WLANTEST_BSS_COUNTER_INVALID_BIP_MMIE]++;
		return 0;
	}
	wpa_printf(MSG_DEBUG, "MMIE KeyID %u", keyid);
	wpa_hexdump(MSG_MSGDUMP, "MMIE IPN", mmie + 2, 6);
	wpa_hexdump(MSG_MSGDUMP, "MMIE MIC", mmie + 8, 8);

	if (!bss->igtk_set[keyid]) {
		wpa_printf(MSG_DEBUG, "No IGTK known to validate BIP frame");
		return 0;
	}

	if (os_memcmp(mmie + 2, bss->ipn[keyid], 6) <= 0) {
		wpa_printf(MSG_INFO, "BIP replay detected: SA=" MACSTR,
			   MAC2STR(mgmt->sa));
		wpa_hexdump(MSG_INFO, "RX IPN", mmie + 2, 6);
		wpa_hexdump(MSG_INFO, "Last RX IPN", bss->ipn[keyid], 6);
	}

	if (check_mmie_mic(bss->igtk[keyid], data, len) < 0) {
		wpa_printf(MSG_INFO, "Invalid MMIE MIC in a frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		bss->counters[WLANTEST_BSS_COUNTER_INVALID_BIP_MMIE]++;
		return -1;
	}

	wpa_printf(MSG_DEBUG, "Valid MMIE MIC");
	os_memcpy(bss->ipn[keyid], mmie + 2, 6);
	bss->counters[WLANTEST_BSS_COUNTER_VALID_BIP_MMIE]++;

	if (stype == WLAN_FC_STYPE_DEAUTH)
		bss->counters[WLANTEST_BSS_COUNTER_BIP_DEAUTH]++;
	else if (stype == WLAN_FC_STYPE_DISASSOC)
		bss->counters[WLANTEST_BSS_COUNTER_BIP_DISASSOC]++;

	return 0;
}


static u8 * mgmt_ccmp_decrypt(struct wlantest *wt, const u8 *data, size_t len,
			      size_t *dlen)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;
	const struct ieee80211_hdr *hdr;
	int keyid;
	u8 *decrypted, *frame = NULL;
	u8 pn[6], *rsc;

	hdr = (const struct ieee80211_hdr *) data;
	bss = bss_get(wt, hdr->addr3);
	if (bss == NULL)
		return NULL;
	if (os_memcmp(hdr->addr1, hdr->addr3, ETH_ALEN) == 0)
		sta = sta_get(bss, hdr->addr2);
	else
		sta = sta_get(bss, hdr->addr1);
	if (sta == NULL || !sta->ptk_set) {
		wpa_printf(MSG_MSGDUMP, "No PTK known to decrypt the frame");
		return NULL;
	}

	if (len < 24 + 4)
		return NULL;

	if (!(data[24 + 3] & 0x20)) {
		wpa_printf(MSG_INFO, "Expected CCMP frame from " MACSTR
			   " did not have ExtIV bit set to 1",
			   MAC2STR(hdr->addr2));
		return NULL;
	}

	if (data[24 + 2] != 0 || (data[24 + 3] & 0x1f) != 0) {
		wpa_printf(MSG_INFO, "CCMP mgmt frame from " MACSTR " used "
			   "non-zero reserved bit", MAC2STR(hdr->addr2));
	}

	keyid = data[24 + 3] >> 6;
	if (keyid != 0) {
		wpa_printf(MSG_INFO, "Unexpected non-zero KeyID %d in "
			   "individually addressed Management frame from "
			   MACSTR, keyid, MAC2STR(hdr->addr2));
	}

	if (os_memcmp(hdr->addr1, hdr->addr3, ETH_ALEN) == 0)
		rsc = sta->rsc_tods[16];
	else
		rsc = sta->rsc_fromds[16];

	ccmp_get_pn(pn, data + 24);
	if (os_memcmp(pn, rsc, 6) <= 0) {
		u16 seq_ctrl = le_to_host16(hdr->seq_ctrl);
		wpa_printf(MSG_INFO, "CCMP/TKIP replay detected: A1=" MACSTR
			   " A2=" MACSTR " A3=" MACSTR " seq=%u frag=%u",
			   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			   MAC2STR(hdr->addr3),
			   WLAN_GET_SEQ_SEQ(seq_ctrl),
			   WLAN_GET_SEQ_FRAG(seq_ctrl));
		wpa_hexdump(MSG_INFO, "RX PN", pn, 6);
		wpa_hexdump(MSG_INFO, "RSC", rsc, 6);
	}

	decrypted = ccmp_decrypt(sta->ptk.tk1, hdr, data + 24, len - 24, dlen);
	if (decrypted) {
		os_memcpy(rsc, pn, 6);
		frame = os_malloc(24 + *dlen);
		if (frame) {
			os_memcpy(frame, data, 24);
			os_memcpy(frame + 24, decrypted, *dlen);
			*dlen += 24;
		}
	}

	os_free(decrypted);

	return frame;
}


static int check_mgmt_ccmp(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;

	mgmt = (const struct ieee80211_mgmt *) data;
	fc = le_to_host16(mgmt->frame_control);

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ACTION) {
		if (len > 24 &&
		    mgmt->u.action.category == WLAN_ACTION_PUBLIC)
			return 0; /* Not a robust management frame */
	}

	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return 0;
	if (os_memcmp(mgmt->da, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->sa);
	else
		sta = sta_get(bss, mgmt->da);
	if (sta == NULL)
		return 0;

	if ((sta->rsn_capab & WPA_CAPABILITY_MFPC) &&
	    (sta->state == STATE3 ||
	     WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ACTION)) {
		wpa_printf(MSG_INFO, "Robust individually-addressed "
			   "management frame sent without CCMP by "
			   MACSTR, MAC2STR(mgmt->sa));
		return -1;
	}

	return 0;
}


void rx_mgmt(struct wlantest *wt, const u8 *data, size_t len)
{
	const struct ieee80211_hdr *hdr;
	u16 fc, stype;
	int valid = 1;
	u8 *decrypted = NULL;
	size_t dlen;

	if (len < 24)
		return;

	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
	wt->rx_mgmt++;
	stype = WLAN_FC_GET_STYPE(fc);

	if ((hdr->addr1[0] & 0x01) &&
	    (stype == WLAN_FC_STYPE_DEAUTH ||
	     stype == WLAN_FC_STYPE_DISASSOC ||
	     stype == WLAN_FC_STYPE_ACTION)) {
		if (check_bip(wt, data, len) < 0)
			valid = 0;
	}

	wpa_printf((stype == WLAN_FC_STYPE_BEACON ||
		    stype == WLAN_FC_STYPE_PROBE_RESP ||
		    stype == WLAN_FC_STYPE_PROBE_REQ) ?
		   MSG_EXCESSIVE : MSG_MSGDUMP,
		   "MGMT %s%s%s DA=" MACSTR " SA=" MACSTR " BSSID=" MACSTR,
		   mgmt_stype(stype),
		   fc & WLAN_FC_PWRMGT ? " PwrMgt" : "",
		   fc & WLAN_FC_ISWEP ? " Prot" : "",
		   MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
		   MAC2STR(hdr->addr3));

	if ((fc & WLAN_FC_ISWEP) &&
	    !(hdr->addr1[0] & 0x01) &&
	    (stype == WLAN_FC_STYPE_DEAUTH ||
	     stype == WLAN_FC_STYPE_DISASSOC ||
	     stype == WLAN_FC_STYPE_ACTION)) {
		decrypted = mgmt_ccmp_decrypt(wt, data, len, &dlen);
		if (decrypted) {
			write_pcap_decrypted(wt, decrypted, dlen, NULL, 0);
			data = decrypted;
			len = dlen;
		} else
			valid = 0;
	}

	if (!(fc & WLAN_FC_ISWEP) &&
	    !(hdr->addr1[0] & 0x01) &&
	    (stype == WLAN_FC_STYPE_DEAUTH ||
	     stype == WLAN_FC_STYPE_DISASSOC ||
	     stype == WLAN_FC_STYPE_ACTION)) {
		if (check_mgmt_ccmp(wt, data, len) < 0)
			valid = 0;
	}

	switch (stype) {
	case WLAN_FC_STYPE_BEACON:
		rx_mgmt_beacon(wt, data, len);
		break;
	case WLAN_FC_STYPE_PROBE_RESP:
		rx_mgmt_probe_resp(wt, data, len);
		break;
	case WLAN_FC_STYPE_AUTH:
		rx_mgmt_auth(wt, data, len);
		break;
	case WLAN_FC_STYPE_DEAUTH:
		rx_mgmt_deauth(wt, data, len, valid);
		break;
	case WLAN_FC_STYPE_ASSOC_REQ:
		rx_mgmt_assoc_req(wt, data, len);
		break;
	case WLAN_FC_STYPE_ASSOC_RESP:
		rx_mgmt_assoc_resp(wt, data, len);
		break;
	case WLAN_FC_STYPE_REASSOC_REQ:
		rx_mgmt_reassoc_req(wt, data, len);
		break;
	case WLAN_FC_STYPE_REASSOC_RESP:
		rx_mgmt_reassoc_resp(wt, data, len);
		break;
	case WLAN_FC_STYPE_DISASSOC:
		rx_mgmt_disassoc(wt, data, len, valid);
		break;
	case WLAN_FC_STYPE_ACTION:
		rx_mgmt_action(wt, data, len, valid);
		break;
	}

	os_free(decrypted);

	wt->last_mgmt_valid = valid;
}


static void rx_mgmt_deauth_ack(struct wlantest *wt,
			       const struct ieee80211_hdr *hdr)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;

	mgmt = (const struct ieee80211_mgmt *) hdr;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->da);
	else
		sta = sta_get(bss, mgmt->sa);
	if (sta == NULL)
		return;

	wpa_printf(MSG_DEBUG, "DEAUTH from " MACSTR " acknowledged by " MACSTR,
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->da));
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0) {
		int c;
		c = wt->last_mgmt_valid ?
			WLANTEST_STA_COUNTER_VALID_DEAUTH_RX_ACK :
			WLANTEST_STA_COUNTER_INVALID_DEAUTH_RX_ACK;
		sta->counters[c]++;
	}
}


static void rx_mgmt_disassoc_ack(struct wlantest *wt,
				 const struct ieee80211_hdr *hdr)
{
	const struct ieee80211_mgmt *mgmt;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;

	mgmt = (const struct ieee80211_mgmt *) hdr;
	bss = bss_get(wt, mgmt->bssid);
	if (bss == NULL)
		return;
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0)
		sta = sta_get(bss, mgmt->da);
	else
		sta = sta_get(bss, mgmt->sa);
	if (sta == NULL)
		return;

	wpa_printf(MSG_DEBUG, "DISASSOC from " MACSTR " acknowledged by "
		   MACSTR, MAC2STR(mgmt->sa), MAC2STR(mgmt->da));
	if (os_memcmp(mgmt->sa, mgmt->bssid, ETH_ALEN) == 0) {
		int c;
		c = wt->last_mgmt_valid ?
			WLANTEST_STA_COUNTER_VALID_DISASSOC_RX_ACK :
			WLANTEST_STA_COUNTER_INVALID_DISASSOC_RX_ACK;
		sta->counters[c]++;
	}
}


void rx_mgmt_ack(struct wlantest *wt, const struct ieee80211_hdr *hdr)
{
	u16 fc, stype;
	fc = le_to_host16(hdr->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf(MSG_MSGDUMP, "MGMT ACK: stype=%u a1=" MACSTR " a2=" MACSTR
		   " a3=" MACSTR,
		   stype, MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
		   MAC2STR(hdr->addr3));

	switch (stype) {
	case WLAN_FC_STYPE_DEAUTH:
		rx_mgmt_deauth_ack(wt, hdr);
		break;
	case WLAN_FC_STYPE_DISASSOC:
		rx_mgmt_disassoc_ack(wt, hdr);
		break;
	}
}
