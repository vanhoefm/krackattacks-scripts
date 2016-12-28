/*
 * wpa_supplicant - Radio Measurements
 * Copyright (c) 2003-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_common.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "bss.h"


static void wpas_rrm_neighbor_rep_timeout_handler(void *data, void *user_ctx)
{
	struct rrm_data *rrm = data;

	if (!rrm->notify_neighbor_rep) {
		wpa_printf(MSG_ERROR,
			   "RRM: Unexpected neighbor report timeout");
		return;
	}

	wpa_printf(MSG_DEBUG, "RRM: Notifying neighbor report - NONE");
	rrm->notify_neighbor_rep(rrm->neighbor_rep_cb_ctx, NULL);

	rrm->notify_neighbor_rep = NULL;
	rrm->neighbor_rep_cb_ctx = NULL;
}


/*
 * wpas_rrm_reset - Clear and reset all RRM data in wpa_supplicant
 * @wpa_s: Pointer to wpa_supplicant
 */
void wpas_rrm_reset(struct wpa_supplicant *wpa_s)
{
	wpa_s->rrm.rrm_used = 0;

	eloop_cancel_timeout(wpas_rrm_neighbor_rep_timeout_handler, &wpa_s->rrm,
			     NULL);
	if (wpa_s->rrm.notify_neighbor_rep)
		wpas_rrm_neighbor_rep_timeout_handler(&wpa_s->rrm, NULL);
	wpa_s->rrm.next_neighbor_rep_token = 1;
}


/*
 * wpas_rrm_process_neighbor_rep - Handle incoming neighbor report
 * @wpa_s: Pointer to wpa_supplicant
 * @report: Neighbor report buffer, prefixed by a 1-byte dialog token
 * @report_len: Length of neighbor report buffer
 */
void wpas_rrm_process_neighbor_rep(struct wpa_supplicant *wpa_s,
				   const u8 *report, size_t report_len)
{
	struct wpabuf *neighbor_rep;

	wpa_hexdump(MSG_DEBUG, "RRM: New Neighbor Report", report, report_len);
	if (report_len < 1)
		return;

	if (report[0] != wpa_s->rrm.next_neighbor_rep_token - 1) {
		wpa_printf(MSG_DEBUG,
			   "RRM: Discarding neighbor report with token %d (expected %d)",
			   report[0], wpa_s->rrm.next_neighbor_rep_token - 1);
		return;
	}

	eloop_cancel_timeout(wpas_rrm_neighbor_rep_timeout_handler, &wpa_s->rrm,
			     NULL);

	if (!wpa_s->rrm.notify_neighbor_rep) {
		wpa_printf(MSG_ERROR, "RRM: Unexpected neighbor report");
		return;
	}

	/* skipping the first byte, which is only an id (dialog token) */
	neighbor_rep = wpabuf_alloc(report_len - 1);
	if (neighbor_rep == NULL)
		return;
	wpabuf_put_data(neighbor_rep, report + 1, report_len - 1);
	wpa_printf(MSG_DEBUG, "RRM: Notifying neighbor report (token = %d)",
		   report[0]);
	wpa_s->rrm.notify_neighbor_rep(wpa_s->rrm.neighbor_rep_cb_ctx,
				       neighbor_rep);
	wpa_s->rrm.notify_neighbor_rep = NULL;
	wpa_s->rrm.neighbor_rep_cb_ctx = NULL;
}


#if defined(__CYGWIN__) || defined(CONFIG_NATIVE_WINDOWS)
/* Workaround different, undefined for Windows, error codes used here */
#define ENOTCONN -1
#define EOPNOTSUPP -1
#define ECANCELED -1
#endif

/* Measurement Request element + Location Subject + Maximum Age subelement */
#define MEASURE_REQUEST_LCI_LEN (3 + 1 + 4)
/* Measurement Request element + Location Civic Request */
#define MEASURE_REQUEST_CIVIC_LEN (3 + 5)


/**
 * wpas_rrm_send_neighbor_rep_request - Request a neighbor report from our AP
 * @wpa_s: Pointer to wpa_supplicant
 * @ssid: if not null, this is sent in the request. Otherwise, no SSID IE
 *	  is sent in the request.
 * @lci: if set, neighbor request will include LCI request
 * @civic: if set, neighbor request will include civic location request
 * @cb: Callback function to be called once the requested report arrives, or
 *	timed out after RRM_NEIGHBOR_REPORT_TIMEOUT seconds.
 *	In the former case, 'neighbor_rep' is a newly allocated wpabuf, and it's
 *	the requester's responsibility to free it.
 *	In the latter case NULL will be sent in 'neighbor_rep'.
 * @cb_ctx: Context value to send the callback function
 * Returns: 0 in case of success, negative error code otherwise
 *
 * In case there is a previous request which has not been answered yet, the
 * new request fails. The caller may retry after RRM_NEIGHBOR_REPORT_TIMEOUT.
 * Request must contain a callback function.
 */
int wpas_rrm_send_neighbor_rep_request(struct wpa_supplicant *wpa_s,
				       const struct wpa_ssid_value *ssid,
				       int lci, int civic,
				       void (*cb)(void *ctx,
						  struct wpabuf *neighbor_rep),
				       void *cb_ctx)
{
	struct wpabuf *buf;
	const u8 *rrm_ie;

	if (wpa_s->wpa_state != WPA_COMPLETED || wpa_s->current_ssid == NULL) {
		wpa_printf(MSG_DEBUG, "RRM: No connection, no RRM.");
		return -ENOTCONN;
	}

	if (!wpa_s->rrm.rrm_used) {
		wpa_printf(MSG_DEBUG, "RRM: No RRM in current connection.");
		return -EOPNOTSUPP;
	}

	rrm_ie = wpa_bss_get_ie(wpa_s->current_bss,
				WLAN_EID_RRM_ENABLED_CAPABILITIES);
	if (!rrm_ie || !(wpa_s->current_bss->caps & IEEE80211_CAP_RRM) ||
	    !(rrm_ie[2] & WLAN_RRM_CAPS_NEIGHBOR_REPORT)) {
		wpa_printf(MSG_DEBUG,
			   "RRM: No network support for Neighbor Report.");
		return -EOPNOTSUPP;
	}

	if (!cb) {
		wpa_printf(MSG_DEBUG,
			   "RRM: Neighbor Report request must provide a callback.");
		return -EINVAL;
	}

	/* Refuse if there's a live request */
	if (wpa_s->rrm.notify_neighbor_rep) {
		wpa_printf(MSG_DEBUG,
			   "RRM: Currently handling previous Neighbor Report.");
		return -EBUSY;
	}

	/* 3 = action category + action code + dialog token */
	buf = wpabuf_alloc(3 + (ssid ? 2 + ssid->ssid_len : 0) +
			   (lci ? 2 + MEASURE_REQUEST_LCI_LEN : 0) +
			   (civic ? 2 + MEASURE_REQUEST_CIVIC_LEN : 0));
	if (buf == NULL) {
		wpa_printf(MSG_DEBUG,
			   "RRM: Failed to allocate Neighbor Report Request");
		return -ENOMEM;
	}

	wpa_printf(MSG_DEBUG, "RRM: Neighbor report request (for %s), token=%d",
		   (ssid ? wpa_ssid_txt(ssid->ssid, ssid->ssid_len) : ""),
		   wpa_s->rrm.next_neighbor_rep_token);

	wpabuf_put_u8(buf, WLAN_ACTION_RADIO_MEASUREMENT);
	wpabuf_put_u8(buf, WLAN_RRM_NEIGHBOR_REPORT_REQUEST);
	wpabuf_put_u8(buf, wpa_s->rrm.next_neighbor_rep_token);
	if (ssid) {
		wpabuf_put_u8(buf, WLAN_EID_SSID);
		wpabuf_put_u8(buf, ssid->ssid_len);
		wpabuf_put_data(buf, ssid->ssid, ssid->ssid_len);
	}

	if (lci) {
		/* IEEE P802.11-REVmc/D5.0 9.4.2.21 */
		wpabuf_put_u8(buf, WLAN_EID_MEASURE_REQUEST);
		wpabuf_put_u8(buf, MEASURE_REQUEST_LCI_LEN);

		/*
		 * Measurement token; nonzero number that is unique among the
		 * Measurement Request elements in a particular frame.
		 */
		wpabuf_put_u8(buf, 1); /* Measurement Token */

		/*
		 * Parallel, Enable, Request, and Report bits are 0, Duration is
		 * reserved.
		 */
		wpabuf_put_u8(buf, 0); /* Measurement Request Mode */
		wpabuf_put_u8(buf, MEASURE_TYPE_LCI); /* Measurement Type */

		/* IEEE P802.11-REVmc/D5.0 9.4.2.21.10 - LCI request */
		/* Location Subject */
		wpabuf_put_u8(buf, LOCATION_SUBJECT_REMOTE);

		/* Optional Subelements */
		/*
		 * IEEE P802.11-REVmc/D5.0 Figure 9-170
		 * The Maximum Age subelement is required, otherwise the AP can
		 * send only data that was determined after receiving the
		 * request. Setting it here to unlimited age.
		 */
		wpabuf_put_u8(buf, LCI_REQ_SUBELEM_MAX_AGE);
		wpabuf_put_u8(buf, 2);
		wpabuf_put_le16(buf, 0xffff);
	}

	if (civic) {
		/* IEEE P802.11-REVmc/D5.0 9.4.2.21 */
		wpabuf_put_u8(buf, WLAN_EID_MEASURE_REQUEST);
		wpabuf_put_u8(buf, MEASURE_REQUEST_CIVIC_LEN);

		/*
		 * Measurement token; nonzero number that is unique among the
		 * Measurement Request elements in a particular frame.
		 */
		wpabuf_put_u8(buf, 2); /* Measurement Token */

		/*
		 * Parallel, Enable, Request, and Report bits are 0, Duration is
		 * reserved.
		 */
		wpabuf_put_u8(buf, 0); /* Measurement Request Mode */
		/* Measurement Type */
		wpabuf_put_u8(buf, MEASURE_TYPE_LOCATION_CIVIC);

		/* IEEE P802.11-REVmc/D5.0 9.4.2.21.14:
		 * Location Civic request */
		/* Location Subject */
		wpabuf_put_u8(buf, LOCATION_SUBJECT_REMOTE);
		wpabuf_put_u8(buf, 0); /* Civic Location Type: IETF RFC 4776 */
		/* Location Service Interval Units: Seconds */
		wpabuf_put_u8(buf, 0);
		/* Location Service Interval: 0 - Only one report is requested
		 */
		wpabuf_put_le16(buf, 0);
		/* No optional subelements */
	}

	wpa_s->rrm.next_neighbor_rep_token++;

	if (wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				wpa_s->own_addr, wpa_s->bssid,
				wpabuf_head(buf), wpabuf_len(buf), 0) < 0) {
		wpa_printf(MSG_DEBUG,
			   "RRM: Failed to send Neighbor Report Request");
		wpabuf_free(buf);
		return -ECANCELED;
	}

	wpa_s->rrm.neighbor_rep_cb_ctx = cb_ctx;
	wpa_s->rrm.notify_neighbor_rep = cb;
	eloop_register_timeout(RRM_NEIGHBOR_REPORT_TIMEOUT, 0,
			       wpas_rrm_neighbor_rep_timeout_handler,
			       &wpa_s->rrm, NULL);

	wpabuf_free(buf);
	return 0;
}


static int wpas_rrm_report_elem(struct wpabuf *buf, u8 token, u8 mode, u8 type,
				const u8 *data, size_t data_len)
{
	if (wpabuf_tailroom(buf) < 5 + data_len)
		return -1;

	wpabuf_put_u8(buf, WLAN_EID_MEASURE_REPORT);
	wpabuf_put_u8(buf, 3 + data_len);
	wpabuf_put_u8(buf, token);
	wpabuf_put_u8(buf, mode);
	wpabuf_put_u8(buf, type);

	if (data_len)
		wpabuf_put_data(buf, data, data_len);

	return 0;
}


static int
wpas_rrm_build_lci_report(struct wpa_supplicant *wpa_s,
			  const struct rrm_measurement_request_element *req,
			  struct wpabuf **buf)
{
	u8 subject;
	u16 max_age = 0;
	struct os_reltime t, diff;
	unsigned long diff_l;
	const u8 *subelem;
	const u8 *request = req->variable;
	size_t len = req->len - 3;

	if (len < 4)
		return -1;

	if (!wpa_s->lci)
		goto reject;

	subject = *request++;
	len--;

	wpa_printf(MSG_DEBUG, "Measurement request location subject=%u",
		   subject);

	if (subject != LOCATION_SUBJECT_REMOTE) {
		wpa_printf(MSG_INFO,
			   "Not building LCI report - bad location subject");
		return 0;
	}

	/* Subelements are formatted exactly like elements */
	subelem = get_ie(request, len, LCI_REQ_SUBELEM_MAX_AGE);
	if (subelem && subelem[1] == 2)
		max_age = WPA_GET_LE16(subelem + 2);

	if (os_get_reltime(&t))
		goto reject;

	os_reltime_sub(&t, &wpa_s->lci_time, &diff);
	/* LCI age is calculated in 10th of a second units. */
	diff_l = diff.sec * 10 + diff.usec / 100000;

	if (max_age != 0xffff && max_age < diff_l)
		goto reject;

	if (wpabuf_resize(buf, 5 + wpabuf_len(wpa_s->lci)))
		return -1;

	if (wpas_rrm_report_elem(*buf, req->token,
				 MEASUREMENT_REPORT_MODE_ACCEPT, req->type,
				 wpabuf_head_u8(wpa_s->lci),
				 wpabuf_len(wpa_s->lci)) < 0) {
		wpa_printf(MSG_DEBUG, "Failed to add LCI report element");
		return -1;
	}

	return 0;

reject:
	if (wpabuf_resize(buf, sizeof(struct rrm_measurement_report_element))) {
		wpa_printf(MSG_DEBUG, "RRM: Memory allocation failed");
		return -1;
	}

	if (wpas_rrm_report_elem(*buf, req->token,
				 MEASUREMENT_REPORT_MODE_REJECT_INCAPABLE,
				 req->type, NULL, 0) < 0) {
		wpa_printf(MSG_DEBUG, "RRM: Failed to add report element");
		return -1;
	}

	return 0;
}


static void wpas_rrm_send_msr_report_mpdu(struct wpa_supplicant *wpa_s,
					  const u8 *data, size_t len)
{
	struct wpabuf *report = wpabuf_alloc(len + 3);

	if (!report)
		return;

	wpabuf_put_u8(report, WLAN_ACTION_RADIO_MEASUREMENT);
	wpabuf_put_u8(report, WLAN_RRM_RADIO_MEASUREMENT_REPORT);
	wpabuf_put_u8(report, wpa_s->rrm.token);

	wpabuf_put_data(report, data, len);

	if (wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				wpa_s->own_addr, wpa_s->bssid,
				wpabuf_head(report), wpabuf_len(report), 0)) {
		wpa_printf(MSG_ERROR,
			   "RRM: Radio measurement report failed: Sending Action frame failed");
	}

	wpabuf_free(report);
}


static void wpas_rrm_send_msr_report(struct wpa_supplicant *wpa_s,
				     struct wpabuf *buf)
{
	int len = wpabuf_len(buf);
	const u8 *pos = wpabuf_head_u8(buf), *next = pos;

#define MPDU_REPORT_LEN (int) (IEEE80211_MAX_MMPDU_SIZE - IEEE80211_HDRLEN - 3)

	while (len) {
		int send_len = (len > MPDU_REPORT_LEN) ? next - pos : len;

		if (send_len == len ||
		    (send_len + next[1] + 2) > MPDU_REPORT_LEN) {
			wpas_rrm_send_msr_report_mpdu(wpa_s, pos, send_len);
			len -= send_len;
			pos = next;
		}

		next += next[1] + 2;
	}
#undef MPDU_REPORT_LEN
}


static int
wpas_rrm_handle_msr_req_element(
	struct wpa_supplicant *wpa_s,
	const struct rrm_measurement_request_element *req,
	struct wpabuf **buf)
{
	wpa_printf(MSG_DEBUG, "Measurement request type %d token %d",
		   req->type, req->token);

	if (req->mode & MEASUREMENT_REQUEST_MODE_ENABLE) {
		/* Enable bit is not supported for now */
		wpa_printf(MSG_DEBUG, "RRM: Enable bit not supported, ignore");
		return 0;
	}

	if ((req->mode & MEASUREMENT_REQUEST_MODE_PARALLEL) &&
	    req->type > MEASURE_TYPE_RPI_HIST) {
		/* Parallel measurements are not supported for now */
		wpa_printf(MSG_DEBUG,
			   "RRM: Parallel measurements are not supported, reject");
		goto reject;
	}

	switch (req->type) {
	case MEASURE_TYPE_LCI:
		return wpas_rrm_build_lci_report(wpa_s, req, buf);
	default:
		wpa_printf(MSG_INFO,
			   "RRM: Unsupported radio measurement type %u",
			   req->type);
		break;
	}

reject:
	if (wpabuf_resize(buf, sizeof(struct rrm_measurement_report_element))) {
		wpa_printf(MSG_DEBUG, "RRM: Memory allocation failed");
		return -1;
	}

	if (wpas_rrm_report_elem(*buf, req->token,
				 MEASUREMENT_REPORT_MODE_REJECT_INCAPABLE,
				 req->type, NULL, 0) < 0) {
		wpa_printf(MSG_DEBUG, "RRM: Failed to add report element");
		return -1;
	}

	return 0;
}


static struct wpabuf *
wpas_rrm_process_msr_req_elems(struct wpa_supplicant *wpa_s, const u8 *pos,
			       size_t len)
{
	struct wpabuf *buf = NULL;

	while (len) {
		const struct rrm_measurement_request_element *req;
		int res;

		if (len < 2) {
			wpa_printf(MSG_DEBUG, "RRM: Truncated element");
			goto out;
		}

		req = (const struct rrm_measurement_request_element *) pos;
		if (req->eid != WLAN_EID_MEASURE_REQUEST) {
			wpa_printf(MSG_DEBUG,
				   "RRM: Expected Measurement Request element, but EID is %u",
				   req->eid);
			goto out;
		}

		if (req->len < 3) {
			wpa_printf(MSG_DEBUG, "RRM: Element length too short");
			goto out;
		}

		if (req->len > len - 2) {
			wpa_printf(MSG_DEBUG, "RRM: Element length too long");
			goto out;
		}

		res = wpas_rrm_handle_msr_req_element(wpa_s, req, &buf);
		if (res < 0)
			goto out;

		pos += req->len + 2;
		len -= req->len + 2;
	}

	return buf;

out:
	wpabuf_free(buf);
	return NULL;
}


void wpas_rrm_handle_radio_measurement_request(struct wpa_supplicant *wpa_s,
					       const u8 *src,
					       const u8 *frame, size_t len)
{
	struct wpabuf *report;

	if (wpa_s->wpa_state != WPA_COMPLETED) {
		wpa_printf(MSG_INFO,
			   "RRM: Ignoring radio measurement request: Not associated");
		return;
	}

	if (!wpa_s->rrm.rrm_used) {
		wpa_printf(MSG_INFO,
			   "RRM: Ignoring radio measurement request: Not RRM network");
		return;
	}

	if (len < 3) {
		wpa_printf(MSG_INFO,
			   "RRM: Ignoring too short radio measurement request");
		return;
	}

	wpa_s->rrm.token = *frame;

	/* Number of repetitions is not supported */

	report = wpas_rrm_process_msr_req_elems(wpa_s, frame + 3, len - 3);
	if (!report)
		return;

	wpas_rrm_send_msr_report(wpa_s, report);
	wpabuf_free(report);
}


void wpas_rrm_handle_link_measurement_request(struct wpa_supplicant *wpa_s,
					      const u8 *src,
					      const u8 *frame, size_t len,
					      int rssi)
{
	struct wpabuf *buf;
	const struct rrm_link_measurement_request *req;
	struct rrm_link_measurement_report report;

	if (wpa_s->wpa_state != WPA_COMPLETED) {
		wpa_printf(MSG_INFO,
			   "RRM: Ignoring link measurement request. Not associated");
		return;
	}

	if (!wpa_s->rrm.rrm_used) {
		wpa_printf(MSG_INFO,
			   "RRM: Ignoring link measurement request. Not RRM network");
		return;
	}

	if (!(wpa_s->drv_rrm_flags & WPA_DRIVER_FLAGS_TX_POWER_INSERTION)) {
		wpa_printf(MSG_INFO,
			   "RRM: Measurement report failed. TX power insertion not supported");
		return;
	}

	req = (const struct rrm_link_measurement_request *) frame;
	if (len < sizeof(*req)) {
		wpa_printf(MSG_INFO,
			   "RRM: Link measurement report failed. Request too short");
		return;
	}

	os_memset(&report, 0, sizeof(report));
	report.tpc.eid = WLAN_EID_TPC_REPORT;
	report.tpc.len = 2;
	report.rsni = 255; /* 255 indicates that RSNI is not available */
	report.dialog_token = req->dialog_token;
	report.rcpi = rssi_to_rcpi(rssi);

	/* action_category + action_code */
	buf = wpabuf_alloc(2 + sizeof(report));
	if (buf == NULL) {
		wpa_printf(MSG_ERROR,
			   "RRM: Link measurement report failed. Buffer allocation failed");
		return;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_RADIO_MEASUREMENT);
	wpabuf_put_u8(buf, WLAN_RRM_LINK_MEASUREMENT_REPORT);
	wpabuf_put_data(buf, &report, sizeof(report));
	wpa_hexdump(MSG_DEBUG, "RRM: Link measurement report:",
		    wpabuf_head(buf), wpabuf_len(buf));

	if (wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, src,
				wpa_s->own_addr, wpa_s->bssid,
				wpabuf_head(buf), wpabuf_len(buf), 0)) {
		wpa_printf(MSG_ERROR,
			   "RRM: Link measurement report failed. Send action failed");
	}
	wpabuf_free(buf);
}
