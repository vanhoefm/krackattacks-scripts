/*
 * wpa_supplicant - WNM
 * Copyright (c) 2011-2012, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "rsn_supp/wpa.h"
#include "../wpa_supplicant/wpa_supplicant_i.h"
#include "../wpa_supplicant/driver_i.h"

#define MAX_TFS_IE_LEN  1024

#ifdef CONFIG_IEEE80211V

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
				 u8 action, u8 intval)
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

	/* WNM-Sleep Mode IE */
	wnmsleep_ie_len = sizeof(struct wnm_sleep_element);
	wnmsleep_ie = os_zalloc(sizeof(struct wnm_sleep_element));
	if (wnmsleep_ie == NULL)
		return -1;
	wnmsleep_ie->eid = WLAN_EID_WNMSLEEP;
	wnmsleep_ie->len = wnmsleep_ie_len - 2;
	wnmsleep_ie->action_type = action;
	wnmsleep_ie->status = WNM_STATUS_SLEEP_ACCEPT;
	wnmsleep_ie->intval = intval;

	/* TFS IE(s) */
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

	mgmt = os_zalloc(sizeof(*mgmt) + wnmsleep_ie_len + wnmtfs_ie_len);
	if (mgmt == NULL) {
		wpa_printf(MSG_DEBUG, "MLME: Failed to allocate buffer for "
			   "WNM-Sleep Request action frame");
		return -1;
	}

	os_memcpy(mgmt->da, wpa_s->bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, wpa_s->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	mgmt->u.action.category = WLAN_ACTION_WNM;
	mgmt->u.action.u.wnm_sleep_req.action = WNM_SLEEP_MODE_REQ;
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


static void ieee802_11_rx_wnmsleep_resp(struct wpa_supplicant *wpa_s,
					const u8 *frm, int len)
{
	/*
	 * Action [1] | Diaglog Token [1] | Key Data Len [2] | Key Data |
	 * WNM-Sleep Mode IE | TFS Response IE
	 */
	u8 *pos = (u8 *) frm; /* point to action field */
	u16 key_len_total = le_to_host16(*((u16 *)(frm+2)));
	u8 gtk_len;
#ifdef CONFIG_IEEE80211W
	u8 igtk_len;
#endif /* CONFIG_IEEE80211W */
	struct wnm_sleep_element *wnmsleep_ie = NULL;
	/* multiple TFS Resp IE (assuming consecutive) */
	u8 *tfsresp_ie_start = NULL;
	u8 *tfsresp_ie_end = NULL;
	u16 tfsresp_ie_len = 0;

	wpa_printf(MSG_DEBUG, "action=%d token = %d key_len_total = %d",
		   frm[0], frm[1], key_len_total);
	pos += 4 + key_len_total;
	while (pos - frm < len) {
		u8 ie_len = *(pos + 1);
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

	if (wnmsleep_ie->status == WNM_STATUS_SLEEP_ACCEPT) {
		wpa_printf(MSG_DEBUG, "Successfully recv WNM-Sleep Response "
			   "frame (action=%d, intval=%d)",
			   wnmsleep_ie->action_type, wnmsleep_ie->intval);
		if (wnmsleep_ie->action_type == 0) {
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_ENTER_CONFIRM,
					 wpa_s->bssid, NULL, NULL);
			/* remove GTK/IGTK ?? */

			/* set the TFS Resp IE(s) */
			if (tfsresp_ie_start && tfsresp_ie_end &&
			    tfsresp_ie_end - tfsresp_ie_start >= 0) {
				tfsresp_ie_len = (tfsresp_ie_end +
						  tfsresp_ie_end[1] + 2) -
					tfsresp_ie_start;
				wpa_printf(MSG_DEBUG, "TFS Resp IE(s) found");
				/*
				 * pass the TFS Resp IE(s) to driver for
				 * processing
				 */
				if (ieee80211_11_set_tfs_ie(
					    wpa_s, wpa_s->bssid,
					    tfsresp_ie_start,
					    &tfsresp_ie_len,
					    WNM_SLEEP_TFS_RESP_IE_SET))
					wpa_printf(MSG_DEBUG, "Fail to set "
						   "TFS Resp IE");
			}
		} else if (wnmsleep_ie->action_type == 1) {
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_EXIT_CONFIRM,
					 wpa_s->bssid, NULL, NULL);
			/* Install GTK/IGTK */
			do {
				/* point to key data field */
				u8 *ptr = (u8 *) frm + 1 + 1 + 2;
				while (ptr < (u8 *) frm + 4 + key_len_total) {
					if (*ptr == WNM_SLEEP_SUBELEM_GTK) {
						gtk_len = *(ptr + 4);
						wpa_wnmsleep_install_key(
							wpa_s->wpa,
							WNM_SLEEP_SUBELEM_GTK,
							ptr);
						ptr += 13 + gtk_len;
#ifdef CONFIG_IEEE80211W
					} else if (*ptr ==
						   WNM_SLEEP_SUBELEM_IGTK) {
						igtk_len = WPA_IGTK_LEN;
						wpa_wnmsleep_install_key(
							wpa_s->wpa,
							WNM_SLEEP_SUBELEM_IGTK,
							ptr);
						ptr += 10 + WPA_IGTK_LEN;
#endif /* CONFIG_IEEE80211W */
					} else
						break; /* skip the loop */
				}
			} while(0);
		}
	} else {
		wpa_printf(MSG_DEBUG, "Reject recv WNM-Sleep Response frame "
			   "(action=%d, intval=%d)",
			   wnmsleep_ie->action_type, wnmsleep_ie->intval);
		if (wnmsleep_ie->action_type == 0)
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_ENTER_FAIL,
					 wpa_s->bssid, NULL, NULL);
		else if (wnmsleep_ie->action_type == 1)
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_EXIT_FAIL,
					 wpa_s->bssid, NULL, NULL);
	}
}


void ieee802_11_rx_wnm_action(struct wpa_supplicant *wpa_s,
			      struct rx_action *action)
{
	u8 *pos = (u8 *) action->data; /* point to action field */
	u8 act = *pos++;
	/* u8 dialog_token = *pos++; */

	switch (act) {
	case WNM_SLEEP_MODE_RESP:
		ieee802_11_rx_wnmsleep_resp(wpa_s, action->data, action->len);
		break;
	default:
		break;
	}
}

#endif /* CONFIG_IEEE80211V */
