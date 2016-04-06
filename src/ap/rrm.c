/*
 * hostapd / Radio Measurement (RRM)
 * Copyright(c) 2013 - 2016 Intel Mobile Communications GmbH.
 * Copyright(c) 2011 - 2016 Intel Corporation. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "hostapd.h"
#include "ap_drv_ops.h"
#include "rrm.h"


static u16 hostapd_parse_location_lci_req_age(const u8 *buf, size_t len)
{
	const u8 *subelem;

	/* Range Request element + Location Subject + Maximum Age subelement */
	if (len < 3 + 1 + 4)
		return 0;

	/* Subelements are arranged as IEs */
	subelem = get_ie(buf + 4, len - 4, LCI_REQ_SUBELEM_MAX_AGE);
	if (subelem && subelem[1] == 2)
		return *(u16 *) (subelem + 2);

	return 0;
}


static int hostapd_check_lci_age(struct hostapd_neighbor_entry *nr, u16 max_age)
{
	struct os_time curr, diff;
	unsigned long diff_l;

	if (!max_age)
		return 0;

	if (max_age == 0xffff)
		return 1;

	if (os_get_time(&curr))
		return 0;

	os_time_sub(&curr, &nr->lci_date, &diff);

	/* avoid overflow */
	if (diff.sec > 0xffff)
		return 0;

	/* LCI age is calculated in 10th of a second units. */
	diff_l = diff.sec * 10 + diff.usec / 100000;

	return max_age > diff_l;
}


static size_t hostapd_neighbor_report_len(struct wpabuf *buf,
					  struct hostapd_neighbor_entry *nr,
					  int send_lci, int send_civic)
{
	size_t len = 2 + wpabuf_len(nr->nr);

	if (send_lci && nr->lci)
		len += 2 + wpabuf_len(nr->lci);

	if (send_civic && nr->civic)
		len += 2 + wpabuf_len(nr->civic);

	return len;
}


static void hostapd_send_nei_report_resp(struct hostapd_data *hapd,
					 const u8 *addr, u8 dialog_token,
					 struct wpa_ssid_value *ssid, u8 lci,
					 u8 civic, u16 lci_max_age)
{
	struct hostapd_neighbor_entry *nr;
	struct wpabuf *buf;
	u8 *msmt_token;

	/*
	 * The number and length of the Neighbor Report elements in a Neighbor
	 * Report frame is limited by the maximum allowed MMPDU size; + 3 bytes
	 * of RRM header.
	 */
	buf = wpabuf_alloc(3 + IEEE80211_MAX_MMPDU_SIZE);
	if (!buf)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_RADIO_MEASUREMENT);
	wpabuf_put_u8(buf, WLAN_RRM_NEIGHBOR_REPORT_RESPONSE);
	wpabuf_put_u8(buf, dialog_token);

	dl_list_for_each(nr, &hapd->nr_db, struct hostapd_neighbor_entry,
			 list) {
		int send_lci;
		size_t len;

		if (ssid->ssid_len != nr->ssid.ssid_len ||
		    os_memcmp(ssid->ssid, nr->ssid.ssid, ssid->ssid_len) != 0)
			continue;

		send_lci = (lci != 0) && hostapd_check_lci_age(nr, lci_max_age);
		len = hostapd_neighbor_report_len(buf, nr, send_lci, civic);

		if (len - 2 > 0xff) {
			wpa_printf(MSG_DEBUG,
				   "NR entry for " MACSTR " exceeds 0xFF bytes",
				   MAC2STR(nr->bssid));
			continue;
		}

		if (len > wpabuf_tailroom(buf))
			break;

		wpabuf_put_u8(buf, WLAN_EID_NEIGHBOR_REPORT);
		wpabuf_put_u8(buf, len - 2);
		wpabuf_put_buf(buf, nr->nr);

		if (send_lci && nr->lci) {
			wpabuf_put_u8(buf, WLAN_EID_MEASURE_REPORT);
			wpabuf_put_u8(buf, wpabuf_len(nr->lci));
			/*
			 * Override measurement token - the first byte of the
			 * Measurement Report element.
			 */
			msmt_token = wpabuf_put(buf, 0);
			wpabuf_put_buf(buf, nr->lci);
			*msmt_token = lci;
		}

		if (civic && nr->civic) {
			wpabuf_put_u8(buf, WLAN_EID_MEASURE_REPORT);
			wpabuf_put_u8(buf, wpabuf_len(nr->civic));
			/*
			 * Override measurement token - the first byte of the
			 * Measurement Report element.
			 */
			msmt_token = wpabuf_put(buf, 0);
			wpabuf_put_buf(buf, nr->civic);
			*msmt_token = civic;
		}
	}

	hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
				wpabuf_head(buf), wpabuf_len(buf));
	wpabuf_free(buf);
}


static void hostapd_handle_nei_report_req(struct hostapd_data *hapd,
					  const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	const u8 *pos, *ie, *end;
	struct wpa_ssid_value ssid = {
		.ssid_len = 0
	};
	u8 token;
	u8 lci = 0, civic = 0; /* Measurement tokens */
	u16 lci_max_age = 0;

	if (!(hapd->conf->radio_measurements[0] &
	      WLAN_RRM_CAPS_NEIGHBOR_REPORT))
		return;

	end = buf + len;

	token = mgmt->u.action.u.rrm.dialog_token;
	pos = mgmt->u.action.u.rrm.variable;
	len = end - pos;

	ie = get_ie(pos, len, WLAN_EID_SSID);
	if (ie && ie[1] && ie[1] <= SSID_MAX_LEN) {
		ssid.ssid_len = ie[1];
		os_memcpy(ssid.ssid, ie + 2, ssid.ssid_len);
	} else {
		ssid.ssid_len = hapd->conf->ssid.ssid_len;
		os_memcpy(ssid.ssid, hapd->conf->ssid.ssid, ssid.ssid_len);
	}

	while ((ie = get_ie(pos, len, WLAN_EID_MEASURE_REQUEST))) {
		if (ie[1] < 3)
			break;

		wpa_printf(MSG_DEBUG,
			   "Neighbor report request, measure type %u",
			   ie[4]);

		switch (ie[4]) { /* Measurement Type */
		case MEASURE_TYPE_LCI:
			lci = ie[2]; /* Measurement Token */
			lci_max_age = hostapd_parse_location_lci_req_age(ie + 2,
									 ie[1]);
			break;
		case MEASURE_TYPE_LOCATION_CIVIC:
			civic = ie[2]; /* Measurement token */
			break;
		}

		pos = ie + ie[1] + 2;
		len = end - pos;
	}

	hostapd_send_nei_report_resp(hapd, mgmt->sa, token, &ssid, lci, civic,
				     lci_max_age);
}


void hostapd_handle_radio_measurement(struct hostapd_data *hapd,
				      const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;

	/*
	 * Check for enough bytes: header + (1B)Category + (1B)Action +
	 * (1B)Dialog Token.
	 */
	if (len < IEEE80211_HDRLEN + 3)
		return;

	wpa_printf(MSG_DEBUG, "Radio measurement frame, action %u from " MACSTR,
		   mgmt->u.action.u.rrm.action, MAC2STR(mgmt->sa));

	switch (mgmt->u.action.u.rrm.action) {
	case WLAN_RRM_NEIGHBOR_REPORT_REQUEST:
		hostapd_handle_nei_report_req(hapd, buf, len);
		break;
	default:
		wpa_printf(MSG_DEBUG, "RRM action %u is not supported",
			   mgmt->u.action.u.rrm.action);
		break;
	}
}
