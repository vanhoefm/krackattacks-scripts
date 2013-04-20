/*
 * wpa_supplicant - WNM
 * Copyright (c) 2011-2013, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "rsn_supp/wpa.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "ctrl_iface.h"
#include "bss.h"
#include "wnm_sta.h"

#define MAX_TFS_IE_LEN  1024
#define WNM_MAX_NEIGHBOR_REPORT 10


/* get the TFS IE from driver */
static int ieee80211_11_get_tfs_ie(struct wpa_supplicant *wpa_s, u8 *buf,
				   u16 *buf_len, enum wnm_oper oper)
{
	wpa_printf(MSG_DEBUG, "%s: TFS get operation %d", __func__, oper);

	return wpa_drv_wnm_oper(wpa_s, oper, wpa_s->bssid, buf, buf_len);
}


/* set the TFS IE to driver */
static int ieee80211_11_set_tfs_ie(struct wpa_supplicant *wpa_s,
				   const u8 *addr, u8 *buf, u16 *buf_len,
				   enum wnm_oper oper)
{
	wpa_printf(MSG_DEBUG, "%s: TFS set operation %d", __func__, oper);

	return wpa_drv_wnm_oper(wpa_s, oper, addr, buf, buf_len);
}


/* MLME-SLEEPMODE.request */
int ieee802_11_send_wnmsleep_req(struct wpa_supplicant *wpa_s,
				 u8 action, u16 intval, struct wpabuf *tfs_req)
{
	struct ieee80211_mgmt *mgmt;
	int res;
	size_t len;
	struct wnm_sleep_element *wnmsleep_ie;
	u8 *wnmtfs_ie;
	u8 wnmsleep_ie_len;
	u16 wnmtfs_ie_len;  /* possibly multiple IE(s) */
	enum wnm_oper tfs_oper = action == 0 ? WNM_SLEEP_TFS_REQ_IE_ADD :
		WNM_SLEEP_TFS_REQ_IE_NONE;

	wpa_printf(MSG_DEBUG, "WNM: Request to send WNM-Sleep Mode Request "
		   "action=%s to " MACSTR,
		   action == 0 ? "enter" : "exit",
		   MAC2STR(wpa_s->bssid));

	/* WNM-Sleep Mode IE */
	wnmsleep_ie_len = sizeof(struct wnm_sleep_element);
	wnmsleep_ie = os_zalloc(sizeof(struct wnm_sleep_element));
	if (wnmsleep_ie == NULL)
		return -1;
	wnmsleep_ie->eid = WLAN_EID_WNMSLEEP;
	wnmsleep_ie->len = wnmsleep_ie_len - 2;
	wnmsleep_ie->action_type = action;
	wnmsleep_ie->status = WNM_STATUS_SLEEP_ACCEPT;
	wnmsleep_ie->intval = host_to_le16(intval);
	wpa_hexdump(MSG_DEBUG, "WNM: WNM-Sleep Mode element",
		    (u8 *) wnmsleep_ie, wnmsleep_ie_len);

	/* TFS IE(s) */
	if (tfs_req) {
		wnmtfs_ie_len = wpabuf_len(tfs_req);
		wnmtfs_ie = os_malloc(wnmtfs_ie_len);
		if (wnmtfs_ie == NULL) {
			os_free(wnmsleep_ie);
			return -1;
		}
		os_memcpy(wnmtfs_ie, wpabuf_head(tfs_req), wnmtfs_ie_len);
	} else {
		wnmtfs_ie = os_zalloc(MAX_TFS_IE_LEN);
		if (wnmtfs_ie == NULL) {
			os_free(wnmsleep_ie);
			return -1;
		}
		if (ieee80211_11_get_tfs_ie(wpa_s, wnmtfs_ie, &wnmtfs_ie_len,
					    tfs_oper)) {
			wnmtfs_ie_len = 0;
			os_free(wnmtfs_ie);
			wnmtfs_ie = NULL;
		}
	}
	wpa_hexdump(MSG_DEBUG, "WNM: TFS Request element",
		    (u8 *) wnmtfs_ie, wnmtfs_ie_len);

	mgmt = os_zalloc(sizeof(*mgmt) + wnmsleep_ie_len + wnmtfs_ie_len);
	if (mgmt == NULL) {
		wpa_printf(MSG_DEBUG, "MLME: Failed to allocate buffer for "
			   "WNM-Sleep Request action frame");
		os_free(wnmsleep_ie);
		os_free(wnmtfs_ie);
		return -1;
	}

	os_memcpy(mgmt->da, wpa_s->bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, wpa_s->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	mgmt->u.action.category = WLAN_ACTION_WNM;
	mgmt->u.action.u.wnm_sleep_req.action = WNM_SLEEP_MODE_REQ;
	mgmt->u.action.u.wnm_sleep_req.dialogtoken = 1;
	os_memcpy(mgmt->u.action.u.wnm_sleep_req.variable, wnmsleep_ie,
		  wnmsleep_ie_len);
	/* copy TFS IE here */
	if (wnmtfs_ie_len > 0) {
		os_memcpy(mgmt->u.action.u.wnm_sleep_req.variable +
			  wnmsleep_ie_len, wnmtfs_ie, wnmtfs_ie_len);
	}

	len = 1 + sizeof(mgmt->u.action.u.wnm_sleep_req) + wnmsleep_ie_len +
		wnmtfs_ie_len;

	res = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  &mgmt->u.action.category, len, 0);
	if (res < 0)
		wpa_printf(MSG_DEBUG, "Failed to send WNM-Sleep Request "
			   "(action=%d, intval=%d)", action, intval);

	os_free(wnmsleep_ie);
	os_free(wnmtfs_ie);
	os_free(mgmt);

	return res;
}


static void wnm_sleep_mode_enter_success(struct wpa_supplicant *wpa_s,
					 u8 *tfsresp_ie_start,
					 u8 *tfsresp_ie_end)
{
	wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_ENTER_CONFIRM,
			 wpa_s->bssid, NULL, NULL);
	/* remove GTK/IGTK ?? */

	/* set the TFS Resp IE(s) */
	if (tfsresp_ie_start && tfsresp_ie_end &&
	    tfsresp_ie_end - tfsresp_ie_start >= 0) {
		u16 tfsresp_ie_len;
		tfsresp_ie_len = (tfsresp_ie_end + tfsresp_ie_end[1] + 2) -
			tfsresp_ie_start;
		wpa_printf(MSG_DEBUG, "TFS Resp IE(s) found");
		/* pass the TFS Resp IE(s) to driver for processing */
		if (ieee80211_11_set_tfs_ie(wpa_s, wpa_s->bssid,
					    tfsresp_ie_start,
					    &tfsresp_ie_len,
					    WNM_SLEEP_TFS_RESP_IE_SET))
			wpa_printf(MSG_DEBUG, "WNM: Fail to set TFS Resp IE");
	}
}


static void wnm_sleep_mode_exit_success(struct wpa_supplicant *wpa_s,
					const u8 *frm, u16 key_len_total)
{
	u8 *ptr, *end;
	u8 gtk_len;

	wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_EXIT_CONFIRM,  wpa_s->bssid,
			 NULL, NULL);

	/* Install GTK/IGTK */

	/* point to key data field */
	ptr = (u8 *) frm + 1 + 1 + 2;
	end = ptr + key_len_total;
	wpa_hexdump_key(MSG_DEBUG, "WNM: Key Data", ptr, key_len_total);

	while (ptr + 1 < end) {
		if (ptr + 2 + ptr[1] > end) {
			wpa_printf(MSG_DEBUG, "WNM: Invalid Key Data element "
				   "length");
			if (end > ptr) {
				wpa_hexdump(MSG_DEBUG, "WNM: Remaining data",
					    ptr, end - ptr);
			}
			break;
		}
		if (*ptr == WNM_SLEEP_SUBELEM_GTK) {
			if (ptr[1] < 11 + 5) {
				wpa_printf(MSG_DEBUG, "WNM: Too short GTK "
					   "subelem");
				break;
			}
			gtk_len = *(ptr + 4);
			if (ptr[1] < 11 + gtk_len ||
			    gtk_len < 5 || gtk_len > 32) {
				wpa_printf(MSG_DEBUG, "WNM: Invalid GTK "
					   "subelem");
				break;
			}
			wpa_wnmsleep_install_key(
				wpa_s->wpa,
				WNM_SLEEP_SUBELEM_GTK,
				ptr);
			ptr += 13 + gtk_len;
#ifdef CONFIG_IEEE80211W
		} else if (*ptr == WNM_SLEEP_SUBELEM_IGTK) {
			if (ptr[1] < 2 + 6 + WPA_IGTK_LEN) {
				wpa_printf(MSG_DEBUG, "WNM: Too short IGTK "
					   "subelem");
				break;
			}
			wpa_wnmsleep_install_key(wpa_s->wpa,
						 WNM_SLEEP_SUBELEM_IGTK, ptr);
			ptr += 10 + WPA_IGTK_LEN;
#endif /* CONFIG_IEEE80211W */
		} else
			break; /* skip the loop */
	}
}


static void ieee802_11_rx_wnmsleep_resp(struct wpa_supplicant *wpa_s,
					const u8 *frm, int len)
{
	/*
	 * Action [1] | Diaglog Token [1] | Key Data Len [2] | Key Data |
	 * WNM-Sleep Mode IE | TFS Response IE
	 */
	u8 *pos = (u8 *) frm; /* point to action field */
	u16 key_len_total = le_to_host16(*((u16 *)(frm+2)));
	struct wnm_sleep_element *wnmsleep_ie = NULL;
	/* multiple TFS Resp IE (assuming consecutive) */
	u8 *tfsresp_ie_start = NULL;
	u8 *tfsresp_ie_end = NULL;

	wpa_printf(MSG_DEBUG, "action=%d token = %d key_len_total = %d",
		   frm[0], frm[1], key_len_total);
	pos += 4 + key_len_total;
	if (pos > frm + len) {
		wpa_printf(MSG_INFO, "WNM: Too short frame for Key Data field");
		return;
	}
	while (pos - frm < len) {
		u8 ie_len = *(pos + 1);
		if (pos + 2 + ie_len > frm + len) {
			wpa_printf(MSG_INFO, "WNM: Invalid IE len %u", ie_len);
			break;
		}
		wpa_hexdump(MSG_DEBUG, "WNM: Element", pos, 2 + ie_len);
		if (*pos == WLAN_EID_WNMSLEEP)
			wnmsleep_ie = (struct wnm_sleep_element *) pos;
		else if (*pos == WLAN_EID_TFS_RESP) {
			if (!tfsresp_ie_start)
				tfsresp_ie_start = pos;
			tfsresp_ie_end = pos;
		} else
			wpa_printf(MSG_DEBUG, "EID %d not recognized", *pos);
		pos += ie_len + 2;
	}

	if (!wnmsleep_ie) {
		wpa_printf(MSG_DEBUG, "No WNM-Sleep IE found");
		return;
	}

	if (wnmsleep_ie->status == WNM_STATUS_SLEEP_ACCEPT ||
	    wnmsleep_ie->status == WNM_STATUS_SLEEP_EXIT_ACCEPT_GTK_UPDATE) {
		wpa_printf(MSG_DEBUG, "Successfully recv WNM-Sleep Response "
			   "frame (action=%d, intval=%d)",
			   wnmsleep_ie->action_type, wnmsleep_ie->intval);
		if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_ENTER) {
			wnm_sleep_mode_enter_success(wpa_s, tfsresp_ie_start,
						     tfsresp_ie_end);
		} else if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_EXIT) {
			wnm_sleep_mode_exit_success(wpa_s, frm, key_len_total);
		}
	} else {
		wpa_printf(MSG_DEBUG, "Reject recv WNM-Sleep Response frame "
			   "(action=%d, intval=%d)",
			   wnmsleep_ie->action_type, wnmsleep_ie->intval);
		if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_ENTER)
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_ENTER_FAIL,
					 wpa_s->bssid, NULL, NULL);
		else if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_EXIT)
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_EXIT_FAIL,
					 wpa_s->bssid, NULL, NULL);
	}
}


void wnm_deallocate_memory(struct wpa_supplicant *wpa_s)
{
	int i;

	for (i = 0; i < wpa_s->wnm_num_neighbor_report; i++) {
		os_free(wpa_s->wnm_neighbor_report_elements[i].tsf_info);
		os_free(wpa_s->wnm_neighbor_report_elements[i].con_coun_str);
		os_free(wpa_s->wnm_neighbor_report_elements[i].bss_tran_can);
		os_free(wpa_s->wnm_neighbor_report_elements[i].bss_term_dur);
		os_free(wpa_s->wnm_neighbor_report_elements[i].bearing);
		os_free(wpa_s->wnm_neighbor_report_elements[i].meas_pilot);
		os_free(wpa_s->wnm_neighbor_report_elements[i].rrm_cap);
		os_free(wpa_s->wnm_neighbor_report_elements[i].mul_bssid);
	}

	os_free(wpa_s->wnm_neighbor_report_elements);
	wpa_s->wnm_neighbor_report_elements = NULL;
}


static void wnm_parse_neighbor_report_elem(struct neighbor_report *rep,
					   u8 id, u8 elen, const u8 *pos)
{
	switch (id) {
	case WNM_NEIGHBOR_TSF:
		if (elen < 2 + 2) {
			wpa_printf(MSG_DEBUG, "WNM: Too short TSF");
			break;
		}
		rep->tsf_info = os_zalloc(sizeof(struct tsf_info));
		if (rep->tsf_info == NULL)
			break;
		rep->tsf_info->present = 1;
		os_memcpy(rep->tsf_info->tsf_offset, pos, 2);
		os_memcpy(rep->tsf_info->beacon_interval, pos + 2, 2);
		break;
	case WNM_NEIGHBOR_CONDENSED_COUNTRY_STRING:
		if (elen < 2) {
			wpa_printf(MSG_DEBUG, "WNM: Too short condensed "
				   "country string");
			break;
		}
		rep->con_coun_str =
			os_zalloc(sizeof(struct condensed_country_string));
		if (rep->con_coun_str == NULL)
			break;
		rep->con_coun_str->present = 1;
		os_memcpy(rep->con_coun_str->country_string, pos, 2);
		break;
	case WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE:
		if (elen < 1) {
			wpa_printf(MSG_DEBUG, "WNM: Too short BSS transition "
				   "candidate");
			break;
		}
		rep->bss_tran_can =
			os_zalloc(sizeof(struct bss_transition_candidate));
		if (rep->bss_tran_can == NULL)
			break;
		rep->bss_tran_can->present = 1;
		rep->bss_tran_can->preference = pos[0];
		break;
	case WNM_NEIGHBOR_BSS_TERMINATION_DURATION:
		if (elen < 12) {
			wpa_printf(MSG_DEBUG, "WNM: Too short BSS termination "
				   "duration");
			break;
		}
		rep->bss_term_dur =
			os_zalloc(sizeof(struct bss_termination_duration));
		if (rep->bss_term_dur == NULL)
			break;
		rep->bss_term_dur->present = 1;
		os_memcpy(rep->bss_term_dur->duration, pos, 12);
		break;
	case WNM_NEIGHBOR_BEARING:
		if (elen < 8) {
			wpa_printf(MSG_DEBUG, "WNM: Too short neighbor "
				   "bearing");
			break;
		}
		rep->bearing = os_zalloc(sizeof(struct bearing));
		if (rep->bearing == NULL)
			break;
		rep->bearing->present = 1;
		os_memcpy(rep->bearing->bearing, pos, 8);
		break;
	case WNM_NEIGHBOR_MEASUREMENT_PILOT:
		if (elen < 2) {
			wpa_printf(MSG_DEBUG, "WNM: Too short measurement "
				   "pilot");
			break;
		}
		rep->meas_pilot = os_zalloc(sizeof(struct measurement_pilot));
		if (rep->meas_pilot == NULL)
			break;
		rep->meas_pilot->present = 1;
		rep->meas_pilot->measurement_pilot = pos[0];
		rep->meas_pilot->num_vendor_specific = pos[1];
		os_memcpy(rep->meas_pilot->vendor_specific, pos + 2, elen - 2);
		break;
	case WNM_NEIGHBOR_RRM_ENABLED_CAPABILITIES:
		if (elen < 4) {
			wpa_printf(MSG_DEBUG, "WNM: Too short RRM enabled "
				   "capabilities");
			break;
		}
		rep->rrm_cap =
			os_zalloc(sizeof(struct rrm_enabled_capabilities));
		if (rep->rrm_cap == NULL)
			break;
		rep->rrm_cap->present = 1;
		os_memcpy(rep->rrm_cap->capabilities, pos, 4);
		break;
	case WNM_NEIGHBOR_MULTIPLE_BSSID:
		if (elen < 2) {
			wpa_printf(MSG_DEBUG, "WNM: Too short multiple BSSID");
			break;
		}
		rep->mul_bssid = os_zalloc(sizeof(struct multiple_bssid));
		if (rep->mul_bssid == NULL)
			break;
		rep->mul_bssid->present = 1;
		rep->mul_bssid->max_bssid_indicator = pos[0];
		rep->mul_bssid->num_vendor_specific = pos[1];
		os_memcpy(rep->mul_bssid->vendor_specific, pos + 2, elen - 2);
		break;
	}
}


static void wnm_parse_neighbor_report(struct wpa_supplicant *wpa_s,
				      const u8 *pos, u8 len,
				      struct neighbor_report *rep)
{
	u8 left = len;

	if (left < 13) {
		wpa_printf(MSG_DEBUG, "WNM: Too short neighbor report");
		return;
	}

	os_memcpy(rep->bssid, pos, ETH_ALEN);
	os_memcpy(rep->bssid_information, pos + ETH_ALEN, 4);
	rep->regulatory_class = *(pos + 10);
	rep->channel_number = *(pos + 11);
	rep->phy_type = *(pos + 12);

	pos += 13;
	left -= 13;

	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		wnm_parse_neighbor_report_elem(rep, id, elen, pos);
		left -= 2 + elen;
		pos += elen;
	}
}


static int compare_scan_neighbor_results(struct wpa_supplicant *wpa_s,
					 struct wpa_scan_results *scan_res,
					 struct neighbor_report *neigh_rep,
					 u8 num_neigh_rep, u8 *bssid_to_connect)
{

	u8 i, j;

	if (scan_res == NULL || num_neigh_rep == 0)
		return 0;

	for (i = 0; i < num_neigh_rep; i++) {
		for (j = 0; j < scan_res->num; j++) {
			/* Check for a better RSSI AP */
			if (os_memcmp(scan_res->res[j]->bssid,
				      neigh_rep[i].bssid, ETH_ALEN) == 0 &&
			    scan_res->res[j]->level >
			    wpa_s->current_bss->level) {
				/* Got a BSSID with better RSSI value */
				os_memcpy(bssid_to_connect, neigh_rep[i].bssid,
					  ETH_ALEN);
				return 1;
			}
		}
	}

	return 0;
}


static void wnm_send_bss_transition_mgmt_resp(
	struct wpa_supplicant *wpa_s, u8 dialog_token,
	enum bss_trans_mgmt_status_code status, u8 delay,
	const u8 *target_bssid)
{
	u8 buf[1000], *pos;
	struct ieee80211_mgmt *mgmt;
	size_t len;

	wpa_printf(MSG_DEBUG, "WNM: Send BSS Transition Management Response "
		   "to " MACSTR " dialog_token=%u status=%u delay=%d",
		   MAC2STR(wpa_s->bssid), dialog_token, status, delay);

	mgmt = (struct ieee80211_mgmt *) buf;
	os_memset(&buf, 0, sizeof(buf));
	os_memcpy(mgmt->da, wpa_s->bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, wpa_s->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	mgmt->u.action.category = WLAN_ACTION_WNM;
	mgmt->u.action.u.bss_tm_resp.action = WNM_BSS_TRANS_MGMT_RESP;
	mgmt->u.action.u.bss_tm_resp.dialog_token = dialog_token;
	mgmt->u.action.u.bss_tm_resp.status_code = status;
	mgmt->u.action.u.bss_tm_resp.bss_termination_delay = delay;
	pos = mgmt->u.action.u.bss_tm_resp.variable;
	if (target_bssid) {
		os_memcpy(pos, target_bssid, ETH_ALEN);
		pos += ETH_ALEN;
	}

	len = pos - (u8 *) &mgmt->u.action.category;

	wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
			    wpa_s->own_addr, wpa_s->bssid,
			    &mgmt->u.action.category, len, 0);
}


void wnm_scan_response(struct wpa_supplicant *wpa_s,
		       struct wpa_scan_results *scan_res)
{
	u8 bssid[ETH_ALEN];

	if (scan_res == NULL) {
		wpa_printf(MSG_ERROR, "Scan result is NULL");
		goto send_bss_resp_fail;
	}

	/* Compare the Neighbor Report and scan results */
	if (compare_scan_neighbor_results(wpa_s, scan_res,
					  wpa_s->wnm_neighbor_report_elements,
					  wpa_s->wnm_num_neighbor_report,
					  bssid) == 1) {
		/* Associate to the network */
		struct wpa_bss *bss;
		struct wpa_ssid *ssid = wpa_s->current_ssid;

		bss = wpa_bss_get_bssid(wpa_s, bssid);
		if (!bss) {
			wpa_printf(MSG_DEBUG, "WNM: Target AP not found from "
				   "BSS table");
			goto send_bss_resp_fail;
		}

		/* Send the BSS Management Response - Accept */
		if (wpa_s->wnm_reply) {
			wnm_send_bss_transition_mgmt_resp(wpa_s,
						  wpa_s->wnm_dialog_token,
						  WNM_BSS_TM_ACCEPT,
						  0, NULL);
		}

		wpa_s->reassociate = 1;
		wpa_supplicant_connect(wpa_s, bss, ssid);
		wnm_deallocate_memory(wpa_s);
		return;
	}

	/* Send reject response for all the failures */
send_bss_resp_fail:
	wnm_deallocate_memory(wpa_s);
	if (wpa_s->wnm_reply) {
		wnm_send_bss_transition_mgmt_resp(wpa_s,
						  wpa_s->wnm_dialog_token,
						  WNM_BSS_TM_REJECT_UNSPECIFIED,
						  0, NULL);
	}
	return;
}


static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
					     const u8 *pos, const u8 *end,
					     int reply)
{
	if (pos + 5 > end)
		return;

	wpa_s->wnm_dialog_token = pos[0];
	wpa_s->wnm_mode = pos[1];
	wpa_s->wnm_dissoc_timer = WPA_GET_LE16(pos + 2);
	wpa_s->wnm_validity_interval = pos[4];
	wpa_s->wnm_reply = reply;

	wpa_printf(MSG_DEBUG, "WNM: BSS Transition Management Request: "
		   "dialog_token=%u request_mode=0x%x "
		   "disassoc_timer=%u validity_interval=%u",
		   wpa_s->wnm_dialog_token, wpa_s->wnm_mode,
		   wpa_s->wnm_dissoc_timer, wpa_s->wnm_validity_interval);

	pos += 5;

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED) {
		if (pos + 12 > end) {
			wpa_printf(MSG_DEBUG, "WNM: Too short BSS TM Request");
			return;
		}
		os_memcpy(wpa_s->wnm_bss_termination_duration, pos, 12);
		pos += 12; /* BSS Termination Duration */
	}

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT) {
		char url[256];
		unsigned int beacon_int;

		if (pos + 1 > end || pos + 1 + pos[0] > end) {
			wpa_printf(MSG_DEBUG, "WNM: Invalid BSS Transition "
				   "Management Request (URL)");
			return;
		}
		os_memcpy(url, pos + 1, pos[0]);
		url[pos[0]] = '\0';
		pos += 1 + pos[0];

		if (wpa_s->current_bss)
			beacon_int = wpa_s->current_bss->beacon_int;
		else
			beacon_int = 100; /* best guess */

		wpa_msg(wpa_s, MSG_INFO, ESS_DISASSOC_IMMINENT "%d %u %s",
			wpa_sm_pmf_enabled(wpa_s->wpa),
			wpa_s->wnm_dissoc_timer * beacon_int * 128 / 125, url);
	}

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_DISASSOC_IMMINENT) {
		wpa_msg(wpa_s, MSG_INFO, "WNM: Disassociation Imminent - "
			"Disassociation Timer %u", wpa_s->wnm_dissoc_timer);
		if (wpa_s->wnm_dissoc_timer && !wpa_s->scanning) {
			/* TODO: mark current BSS less preferred for
			 * selection */
			wpa_printf(MSG_DEBUG, "Trying to find another BSS");
			wpa_supplicant_req_scan(wpa_s, 0, 0);
		}
	}

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
		wpa_msg(wpa_s, MSG_INFO, "WNM: Preferred List Available");
		wpa_s->wnm_num_neighbor_report = 0;
		os_free(wpa_s->wnm_neighbor_report_elements);
		wpa_s->wnm_neighbor_report_elements = os_zalloc(
			WNM_MAX_NEIGHBOR_REPORT *
			sizeof(struct neighbor_report));
		if (wpa_s->wnm_neighbor_report_elements == NULL)
			return;

		while (pos + 2 <= end &&
		       wpa_s->wnm_num_neighbor_report < WNM_MAX_NEIGHBOR_REPORT)
		{
			u8 tag = *pos++;
			u8 len = *pos++;

			wpa_printf(MSG_DEBUG, "WNM: Neighbor report tag %u",
				   tag);
			if (pos + len > end) {
				wpa_printf(MSG_DEBUG, "WNM: Truncated request");
				return;
			}
			wnm_parse_neighbor_report(
				wpa_s, pos, len,
				&wpa_s->wnm_neighbor_report_elements[
					wpa_s->wnm_num_neighbor_report]);

			pos += len;
			wpa_s->wnm_num_neighbor_report++;
		}

		wpa_s->scan_res_handler = wnm_scan_response;
		wpa_supplicant_req_scan(wpa_s, 0, 0);
	} else if (reply) {
		enum bss_trans_mgmt_status_code status;
		if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT)
			status = WNM_BSS_TM_ACCEPT;
		else {
			wpa_msg(wpa_s, MSG_INFO, "WNM: BSS Transition Management Request did not include candidates");
			status = WNM_BSS_TM_REJECT_UNSPECIFIED;
		}
		wnm_send_bss_transition_mgmt_resp(wpa_s,
						  wpa_s->wnm_dialog_token,
						  status, 0, NULL);
	}
}


int wnm_send_bss_transition_mgmt_query(struct wpa_supplicant *wpa_s,
				       u8 query_reason)
{
	u8 buf[1000], *pos;
	struct ieee80211_mgmt *mgmt;
	size_t len;
	int ret;

	wpa_printf(MSG_DEBUG, "WNM: Send BSS Transition Management Query to "
		   MACSTR " query_reason=%u",
		   MAC2STR(wpa_s->bssid), query_reason);

	mgmt = (struct ieee80211_mgmt *) buf;
	os_memset(&buf, 0, sizeof(buf));
	os_memcpy(mgmt->da, wpa_s->bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, wpa_s->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	mgmt->u.action.category = WLAN_ACTION_WNM;
	mgmt->u.action.u.bss_tm_query.action = WNM_BSS_TRANS_MGMT_QUERY;
	mgmt->u.action.u.bss_tm_query.dialog_token = 0;
	mgmt->u.action.u.bss_tm_query.query_reason = query_reason;
	pos = mgmt->u.action.u.bss_tm_query.variable;

	len = pos - (u8 *) &mgmt->u.action.category;

	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  &mgmt->u.action.category, len, 0);

	return ret;
}


void ieee802_11_rx_wnm_action(struct wpa_supplicant *wpa_s,
			      struct rx_action *action)
{
	const u8 *pos, *end;
	u8 act;

	if (action->data == NULL || action->len == 0)
		return;

	pos = action->data;
	end = pos + action->len;
	act = *pos++;

	wpa_printf(MSG_DEBUG, "WNM: RX action %u from " MACSTR,
		   act, MAC2STR(action->sa));
	if (wpa_s->wpa_state < WPA_ASSOCIATED ||
	    os_memcmp(action->sa, wpa_s->bssid, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "WNM: Ignore unexpected WNM Action "
			   "frame");
		return;
	}

	switch (act) {
	case WNM_BSS_TRANS_MGMT_REQ:
		ieee802_11_rx_bss_trans_mgmt_req(wpa_s, pos, end,
						 !(action->da[0] & 0x01));
		break;
	case WNM_SLEEP_MODE_RESP:
		ieee802_11_rx_wnmsleep_resp(wpa_s, action->data, action->len);
		break;
	default:
		wpa_printf(MSG_ERROR, "WNM: Unknown request");
		break;
	}
}
