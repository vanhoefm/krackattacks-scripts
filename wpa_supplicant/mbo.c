/*
 * wpa_supplicant - MBO
 *
 * Copyright(c) 2015 Intel Deutschland GmbH
 * Contact Information:
 * Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "bss.h"

/* type + length + oui + oui type */
#define MBO_IE_HEADER 6


static int wpas_mbo_validate_non_pref_chan(u8 oper_class, u8 chan, u8 reason)
{
	if (reason > MBO_NON_PREF_CHAN_REASON_INT_INTERFERENCE)
		return -1;

	/* Only checking the validity of the channel and oper_class */
	if (ieee80211_chan_to_freq(NULL, oper_class, chan) == -1)
		return -1;

	return 0;
}


static void wpas_mbo_non_pref_chan_attr_body(struct wpa_supplicant *wpa_s,
					     struct wpabuf *mbo,
					     u8 start, u8 end)
{
	u8 i;

	wpabuf_put_u8(mbo, wpa_s->non_pref_chan[start].oper_class);

	for (i = start; i < end; i++)
		wpabuf_put_u8(mbo, wpa_s->non_pref_chan[i].chan);

	wpabuf_put_u8(mbo, wpa_s->non_pref_chan[start].preference);
	wpabuf_put_u8(mbo, wpa_s->non_pref_chan[start].reason);
	wpabuf_put_u8(mbo, wpa_s->non_pref_chan[start].reason_detail);
}


static void wpas_mbo_non_pref_chan_attr(struct wpa_supplicant *wpa_s,
					struct wpabuf *mbo, u8 start, u8 end)
{
	size_t size = end - start + 4;

	if (size + 2 > wpabuf_tailroom(mbo))
		return;

	wpabuf_put_u8(mbo, MBO_ATTR_ID_NON_PREF_CHAN_REPORT);
	wpabuf_put_u8(mbo, size); /* Length */

	wpas_mbo_non_pref_chan_attr_body(wpa_s, mbo, start, end);
}


static void wpas_mbo_non_pref_chan_subelem_hdr(struct wpabuf *mbo, u8 len)
{
	wpabuf_put_u8(mbo, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(mbo, len); /* Length */
	wpabuf_put_be24(mbo, OUI_WFA);
	wpabuf_put_u8(mbo, MBO_ATTR_ID_NON_PREF_CHAN_REPORT);
}


static void wpas_mbo_non_pref_chan_subelement(struct wpa_supplicant *wpa_s,
					      struct wpabuf *mbo, u8 start,
					      u8 end)
{
	size_t size = end - start + 8;

	if (size + 2 > wpabuf_tailroom(mbo))
		return;

	wpas_mbo_non_pref_chan_subelem_hdr(mbo, size);
	wpas_mbo_non_pref_chan_attr_body(wpa_s, mbo, start, end);
}


static void wpas_mbo_non_pref_chan_attrs(struct wpa_supplicant *wpa_s,
					 struct wpabuf *mbo, int subelement)
{
	u8 i, start = 0;
	struct wpa_mbo_non_pref_channel *start_pref;

	if (!wpa_s->non_pref_chan || !wpa_s->non_pref_chan_num) {
		if (subelement)
			wpas_mbo_non_pref_chan_subelem_hdr(mbo, 4);
		return;
	}
	start_pref = &wpa_s->non_pref_chan[0];

	for (i = 1; i <= wpa_s->non_pref_chan_num; i++) {
		struct wpa_mbo_non_pref_channel *non_pref = NULL;

		if (i < wpa_s->non_pref_chan_num)
			non_pref = &wpa_s->non_pref_chan[i];
		if (!non_pref ||
		    non_pref->oper_class != start_pref->oper_class ||
		    non_pref->reason != start_pref->reason ||
		    non_pref->reason_detail != start_pref->reason_detail ||
		    non_pref->preference != start_pref->preference) {
			if (subelement)
				wpas_mbo_non_pref_chan_subelement(wpa_s, mbo,
								  start, i);
			else
				wpas_mbo_non_pref_chan_attr(wpa_s, mbo, start,
							    i);

			if (!non_pref)
				return;

			start = i;
			start_pref = non_pref;
		}
	}
}


int wpas_mbo_ie(struct wpa_supplicant *wpa_s, u8 *buf, size_t len)
{
	struct wpabuf *mbo;
	int res;

	if (len < MBO_IE_HEADER + 3 + 7)
		return 0;

	/* Leave room for the MBO IE header */
	mbo = wpabuf_alloc(len - MBO_IE_HEADER);
	if (!mbo)
		return 0;

	/* Add non-preferred channels attribute */
	wpas_mbo_non_pref_chan_attrs(wpa_s, mbo, 0);

	/*
	 * Send cellular capabilities attribute even if AP does not advertise
	 * cellular capabilities.
	 */
	wpabuf_put_u8(mbo, MBO_ATTR_ID_CELL_DATA_CAPA);
	wpabuf_put_u8(mbo, 1);
	wpabuf_put_u8(mbo, wpa_s->conf->mbo_cell_capa);

	res = mbo_add_ie(buf, len, wpabuf_head_u8(mbo), wpabuf_len(mbo));
	if (!res)
		wpa_printf(MSG_ERROR, "Failed to add MBO IE");

	wpabuf_free(mbo);
	return res;
}


static void wpas_mbo_send_wnm_notification(struct wpa_supplicant *wpa_s)
{
	struct wpabuf *buf;
	int res;

	/*
	 * Send WNM-Notification Request frame only in case of a change in
	 * non-preferred channels list during association, if the AP supports
	 * MBO.
	 */
	if (wpa_s->wpa_state != WPA_COMPLETED || !wpa_s->current_bss ||
	    !wpa_bss_get_vendor_ie(wpa_s->current_bss, MBO_IE_VENDOR_TYPE))
		return;

	buf = wpabuf_alloc(512);
	if (!buf)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_WNM);
	wpabuf_put_u8(buf, WNM_NOTIFICATION_REQ);
	wpa_s->mbo_wnm_token++;
	if (wpa_s->mbo_wnm_token == 0)
		wpa_s->mbo_wnm_token++;
	wpabuf_put_u8(buf, wpa_s->mbo_wnm_token);
	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC); /* Type */

	wpas_mbo_non_pref_chan_attrs(wpa_s, buf, 1);

	res = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  wpabuf_head(buf), wpabuf_len(buf), 0);
	if (res < 0)
		wpa_printf(MSG_DEBUG,
			   "Failed to send WNM-Notification Request frame with non-preferred channel list");

	wpabuf_free(buf);
}


static int wpa_non_pref_chan_is_eq(struct wpa_mbo_non_pref_channel *a,
				   struct wpa_mbo_non_pref_channel *b)
{
	return a->oper_class == b->oper_class && a->chan == b->chan;
}


/*
 * wpa_non_pref_chan_cmp - Compare two channels for sorting
 *
 * In MBO IE non-preferred channel subelement we can put many channels in an
 * attribute if they are in the same operating class and have the same
 * preference, reason, and reason detail. To make it easy for the functions that
 * build the IE attributes and WNM Request subelements, save the channels sorted
 * by their oper_class, reason, and reason_detail.
 */
static int wpa_non_pref_chan_cmp(const void *_a, const void *_b)
{
	const struct wpa_mbo_non_pref_channel *a = _a, *b = _b;

	if (a->oper_class != b->oper_class)
		return a->oper_class - b->oper_class;
	if (a->reason != b->reason)
		return a->reason - b->reason;
	if (a->reason_detail != b->reason_detail)
		return a->reason_detail - b->reason_detail;
	return a->preference - b->preference;
}


int wpas_mbo_update_non_pref_chan(struct wpa_supplicant *wpa_s,
				  const char *non_pref_chan)
{
	char *cmd, *token, *context = NULL;
	struct wpa_mbo_non_pref_channel *chans = NULL, *tmp_chans;
	size_t num = 0, size = 0;
	unsigned i;

	wpa_printf(MSG_DEBUG, "MBO: Update non-preferred channels, non_pref_chan=%s",
		   non_pref_chan ? non_pref_chan : "N/A");

	/*
	 * The shortest channel configuration is 10 characters - commas, 3
	 * colons, and 4 values that one of them (oper_class) is 2 digits or
	 * more.
	 */
	if (!non_pref_chan || os_strlen(non_pref_chan) < 10)
		goto update;

	cmd = os_strdup(non_pref_chan);
	if (!cmd)
		return -1;

	while ((token = str_token(cmd, " ", &context))) {
		struct wpa_mbo_non_pref_channel *chan;
		int ret;
		unsigned int _oper_class;
		unsigned int _chan;
		unsigned int _preference;
		unsigned int _reason;
		unsigned int _reason_detail;

		if (num == size) {
			size = size ? size * 2 : 1;
			tmp_chans = os_realloc_array(chans, size,
						     sizeof(*chans));
			if (!tmp_chans) {
				wpa_printf(MSG_ERROR,
					   "Couldn't reallocate non_pref_chan");
				goto fail;
			}
			chans = tmp_chans;
		}

		chan = &chans[num];

		ret = sscanf(token, "%u:%u:%u:%u:%u", &_oper_class,
			     &_chan, &_preference, &_reason,
			     &_reason_detail);
		if ((ret != 4 && ret != 5) ||
		    _oper_class > 255 || _chan > 255 ||
		    _preference > 255 || _reason > 65535 ||
		    (ret == 5 && _reason_detail > 255)) {
			wpa_printf(MSG_ERROR, "Invalid non-pref chan input %s",
				   token);
			goto fail;
		}
		chan->oper_class = _oper_class;
		chan->chan = _chan;
		chan->preference = _preference;
		chan->reason = _reason;
		chan->reason_detail = ret == 4 ? 0 : _reason_detail;

		if (wpas_mbo_validate_non_pref_chan(chan->oper_class,
						    chan->chan, chan->reason)) {
			wpa_printf(MSG_ERROR,
				   "Invalid non_pref_chan: oper class %d chan %d reason %d",
				   chan->oper_class, chan->chan, chan->reason);
			goto fail;
		}

		for (i = 0; i < num; i++)
			if (wpa_non_pref_chan_is_eq(chan, &chans[i]))
				break;
		if (i != num) {
			wpa_printf(MSG_ERROR,
				   "oper class %d chan %d is duplicated",
				   chan->oper_class, chan->chan);
			goto fail;
		}

		num++;
	}

	os_free(cmd);

	if (chans) {
		qsort(chans, num, sizeof(struct wpa_mbo_non_pref_channel),
		      wpa_non_pref_chan_cmp);
	}

update:
	os_free(wpa_s->non_pref_chan);
	wpa_s->non_pref_chan = chans;
	wpa_s->non_pref_chan_num = num;
	wpas_mbo_send_wnm_notification(wpa_s);

	return 0;

fail:
	os_free(chans);
	os_free(cmd);
	return -1;
}


void wpas_mbo_scan_ie(struct wpa_supplicant *wpa_s, struct wpabuf *ie)
{
	wpabuf_put_u8(ie, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(ie, 7);
	wpabuf_put_be24(ie, OUI_WFA);
	wpabuf_put_u8(ie, MBO_OUI_TYPE);

	wpabuf_put_u8(ie, MBO_ATTR_ID_CELL_DATA_CAPA);
	wpabuf_put_u8(ie, 1);
	wpabuf_put_u8(ie, wpa_s->conf->mbo_cell_capa);
}
