/*
 * Wi-Fi Multimedia Admission Control (WMM-AC)
 * Copyright(c) 2014, Intel Mobile Communication GmbH.
 * Copyright(c) 2014, Intel Corporation. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "utils/common.h"
#include "utils/list.h"
#include "common/ieee802_11_common.h"
#include "wpa_supplicant_i.h"
#include "bss.h"
#include "driver_i.h"
#include "wmm_ac.h"


static const enum wmm_ac up_to_ac[8] = {
	WMM_AC_BK,
	WMM_AC_BE,
	WMM_AC_BE,
	WMM_AC_BK,
	WMM_AC_VI,
	WMM_AC_VI,
	WMM_AC_VO,
	WMM_AC_VO
};


static inline u8 wmm_ac_get_tsid(const struct wmm_tspec_element *tspec)
{
	return (tspec->ts_info[0] >> 1) & 0x0f;
}


static int wmm_ac_send_addts_request(struct wpa_supplicant *wpa_s,
				     const struct wmm_ac_addts_request *req)
{
	struct wpabuf *buf;
	int ret;

	wpa_printf(MSG_DEBUG, "Sending ADDTS Request to " MACSTR,
		   MAC2STR(req->address));

	/* category + action code + dialog token + status + sizeof(tspec) */
	buf = wpabuf_alloc(4 + sizeof(req->tspec));
	if (!buf) {
		wpa_printf(MSG_ERROR, "WMM AC: Allocation error");
		return -1;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_WMM);
	wpabuf_put_u8(buf, WMM_ACTION_CODE_ADDTS_REQ);
	wpabuf_put_u8(buf, req->dialog_token);
	wpabuf_put_u8(buf, 0); /* status code */
	wpabuf_put_data(buf, &req->tspec, sizeof(req->tspec));

	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, req->address,
				wpa_s->own_addr, wpa_s->bssid,
				wpabuf_head(buf), wpabuf_len(buf), 0);
	if (ret) {
		wpa_printf(MSG_WARNING,
			   "WMM AC: Failed to send ADDTS Request");
	}

	wpabuf_free(buf);
	return ret;
}


static int wmm_ac_send_delts(struct wpa_supplicant *wpa_s,
			     const struct wmm_tspec_element *tspec,
			     const u8 *address)
{
	struct wpabuf *buf;
	int ret;

	/* category + action code + dialog token + status + sizeof(tspec) */
	buf = wpabuf_alloc(4 + sizeof(*tspec));
	if (!buf)
		return -1;

	wpa_printf(MSG_DEBUG, "Sending DELTS to " MACSTR, MAC2STR(address));

	/* category + action code + dialog token + status + sizeof(tspec) */
	wpabuf_put_u8(buf, WLAN_ACTION_WMM);
	wpabuf_put_u8(buf, WMM_ACTION_CODE_DELTS);
	wpabuf_put_u8(buf, 0); /* Dialog Token (not used) */
	wpabuf_put_u8(buf, 0); /* Status Code (not used) */
	wpabuf_put_data(buf, tspec, sizeof(*tspec));

	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, address,
				  wpa_s->own_addr, wpa_s->bssid,
				  wpabuf_head(buf), wpabuf_len(buf), 0);
	if (ret)
		wpa_printf(MSG_WARNING, "Failed to send DELTS frame");

	wpabuf_free(buf);
	return ret;
}


/* return the AC using the given TSPEC tid */
static int wmm_ac_find_tsid(struct wpa_supplicant *wpa_s, u8 tsid,
			    enum ts_dir_idx *dir)
{
	int ac;
	enum ts_dir_idx idx;

	for (ac = 0; ac < WMM_AC_NUM; ac++) {
		for (idx = 0; idx < TS_DIR_IDX_COUNT; idx++) {
			if (wpa_s->tspecs[ac][idx] &&
			    wmm_ac_get_tsid(wpa_s->tspecs[ac][idx]) == tsid) {
				if (dir)
					*dir = idx;
				return ac;
			}
		}
	}

	return -1;
}


static struct wmm_ac_addts_request *
wmm_ac_build_addts_req(struct wpa_supplicant *wpa_s,
		       const struct wmm_ac_ts_setup_params *params,
		       const u8 *address)
{
	struct wmm_ac_addts_request *addts_req;
	struct wmm_tspec_element *tspec;
	u8 ac = up_to_ac[params->user_priority];
	u8 uapsd = wpa_s->wmm_ac_assoc_info->ac_params[ac].uapsd;

	addts_req = os_zalloc(sizeof(*addts_req));
	if (!addts_req)
		return NULL;

	tspec = &addts_req->tspec;
	os_memcpy(addts_req->address, address, ETH_ALEN);

	/* The dialog token cannot be zero */
	if (++wpa_s->wmm_ac_last_dialog_token == 0)
		wpa_s->wmm_ac_last_dialog_token++;

	addts_req->dialog_token = wpa_s->wmm_ac_last_dialog_token;
	tspec->eid = WLAN_EID_VENDOR_SPECIFIC;
	tspec->length = sizeof(*tspec) - 2; /* reduce eid and length */
	tspec->oui[0] = 0x00;
	tspec->oui[1] = 0x50;
	tspec->oui[2] = 0xf2;
	tspec->oui_type = WMM_OUI_TYPE;
	tspec->oui_subtype = WMM_OUI_SUBTYPE_TSPEC_ELEMENT;
	tspec->version = WMM_VERSION;

	tspec->ts_info[0] = params->tsid << 1;
	tspec->ts_info[0] |= params->direction << 5;
	tspec->ts_info[0] |= WMM_AC_ACCESS_POLICY_EDCA << 7;
	tspec->ts_info[1] = uapsd << 2;
	tspec->ts_info[1] |= params->user_priority << 3;
	tspec->ts_info[2] = 0;

	tspec->nominal_msdu_size = host_to_le16(params->nominal_msdu_size);
	if (params->fixed_nominal_msdu)
		tspec->nominal_msdu_size |=
			host_to_le16(WMM_AC_FIXED_MSDU_SIZE);

	tspec->mean_data_rate = host_to_le32(params->mean_data_rate);
	tspec->minimum_phy_rate = host_to_le32(params->minimum_phy_rate);
	tspec->surplus_bandwidth_allowance =
		host_to_le16(params->surplus_bandwidth_allowance);

	return addts_req;
}


static int param_in_range(const char *name, long value,
			  long min_val, long max_val)
{
	if (value < min_val || (max_val >= 0 && value > max_val)) {
		wpa_printf(MSG_DEBUG,
			   "WMM AC: param %s (%ld) is out of range (%ld-%ld)",
			   name, value, min_val, max_val);
		return 0;
	}

	return 1;
}


static int wmm_ac_should_replace_ts(struct wpa_supplicant *wpa_s,
				    u8 tsid, u8 ac, u8 dir)
{
	enum ts_dir_idx idx;
	int cur_ac, existing_ts = 0, replace_ts = 0;

	cur_ac = wmm_ac_find_tsid(wpa_s, tsid, &idx);
	if (cur_ac >= 0) {
		if (cur_ac != ac) {
			wpa_printf(MSG_DEBUG,
				   "WMM AC: TSID %i already exists on different ac (%d)",
				   tsid, cur_ac);
			return -1;
		}

		/* same tsid - this tspec will replace the current one */
		replace_ts |= BIT(idx);
	}

	for (idx = 0; idx < TS_DIR_IDX_COUNT; idx++) {
		if (wpa_s->tspecs[ac][idx])
			existing_ts |= BIT(idx);
	}

	switch (dir) {
	case WMM_AC_DIR_UPLINK:
		/* replace existing uplink/bidi tspecs */
		replace_ts |= existing_ts & (BIT(TS_DIR_IDX_UPLINK) |
					     BIT(TS_DIR_IDX_BIDI));
		break;
	case WMM_AC_DIR_DOWNLINK:
		/* replace existing downlink/bidi tspecs */
		replace_ts |= existing_ts & (BIT(TS_DIR_IDX_DOWNLINK) |
					     BIT(TS_DIR_IDX_BIDI));
		break;
	case WMM_AC_DIR_BIDIRECTIONAL:
		/* replace all existing tspecs */
		replace_ts |= existing_ts;
		break;
	default:
		return -1;
	}

	return replace_ts;
}


static int wmm_ac_ts_req_is_valid(struct wpa_supplicant *wpa_s,
				  const struct wmm_ac_ts_setup_params *params)
{
	enum wmm_ac req_ac;

#define PARAM_IN_RANGE(field, min_value, max_value) \
	param_in_range(#field, params->field, min_value, max_value)

	if (!PARAM_IN_RANGE(tsid, 0, WMM_AC_MAX_TID) ||
	    !PARAM_IN_RANGE(user_priority, 0, WMM_AC_MAX_USER_PRIORITY) ||
	    !PARAM_IN_RANGE(nominal_msdu_size, 1, WMM_AC_MAX_NOMINAL_MSDU) ||
	    !PARAM_IN_RANGE(mean_data_rate, 1, -1) ||
	    !PARAM_IN_RANGE(minimum_phy_rate, 1, -1) ||
	    !PARAM_IN_RANGE(surplus_bandwidth_allowance, WMM_AC_MIN_SBA_UNITY,
			    -1))
		return 0;
#undef PARAM_IN_RANGE

	if (!(params->direction == WMM_TSPEC_DIRECTION_UPLINK ||
	      params->direction == WMM_TSPEC_DIRECTION_DOWNLINK ||
	      params->direction == WMM_TSPEC_DIRECTION_BI_DIRECTIONAL)) {
		wpa_printf(MSG_DEBUG, "WMM AC: invalid TS direction: %d",
			   params->direction);
		return 0;
	}

	req_ac = up_to_ac[params->user_priority];

	/* Requested accesss category must have acm */
	if (!wpa_s->wmm_ac_assoc_info->ac_params[req_ac].acm) {
		wpa_printf(MSG_DEBUG, "WMM AC: AC %d is not ACM", req_ac);
		return 0;
	}

	if (wmm_ac_should_replace_ts(wpa_s, params->tsid, req_ac,
				     params->direction) < 0)
		return 0;

	return 1;
}


static struct wmm_ac_assoc_data *
wmm_ac_process_param_elem(struct wpa_supplicant *wpa_s, const u8 *ies,
			  size_t ies_len)
{
	struct ieee802_11_elems elems;
	struct wmm_parameter_element *wmm_params;
	struct wmm_ac_assoc_data *assoc_data;
	int i;

	/* Parsing WMM Parameter Element */
	if (ieee802_11_parse_elems(ies, ies_len, &elems, 1) != ParseOK) {
		wpa_printf(MSG_DEBUG, "WMM AC: could not parse assoc ies");
		return NULL;
	}

	if (!elems.wmm) {
		wpa_printf(MSG_DEBUG, "WMM AC: No WMM IE");
		return NULL;
	}

	if (elems.wmm_len != sizeof(*wmm_params)) {
		wpa_printf(MSG_WARNING, "WMM AC: Invalid WMM ie length");
		return NULL;
	}

	wmm_params = (struct wmm_parameter_element *)(elems.wmm);

	assoc_data = os_zalloc(sizeof(*assoc_data));
	if (!assoc_data)
		return NULL;

	for (i = 0; i < WMM_AC_NUM; i++)
		assoc_data->ac_params[i].acm =
			!!(wmm_params->ac[i].aci_aifsn & WMM_AC_ACM);

	wpa_printf(MSG_DEBUG,
		   "WMM AC: AC mandatory: AC_BE=%u AC_BK=%u AC_VI=%u AC_VO=%u",
		   assoc_data->ac_params[WMM_AC_BE].acm,
		   assoc_data->ac_params[WMM_AC_BK].acm,
		   assoc_data->ac_params[WMM_AC_VI].acm,
		   assoc_data->ac_params[WMM_AC_VO].acm);

	return assoc_data;
}


static int wmm_ac_init(struct wpa_supplicant *wpa_s, const u8 *ies,
		       size_t ies_len, const struct wmm_params *wmm_params)
{
	struct wmm_ac_assoc_data *assoc_data;
	u8 ac;

	if (wpa_s->wmm_ac_assoc_info) {
		wpa_printf(MSG_ERROR, "WMM AC: Already initialized");
		return -1;
	}

	if (!ies) {
		wpa_printf(MSG_ERROR, "WMM AC: Missing IEs");
		return -1;
	}

	if (!(wmm_params->info_bitmap & WMM_PARAMS_UAPSD_QUEUES_INFO)) {
		wpa_printf(MSG_DEBUG, "WMM AC: Missing U-APSD configuration");
		return -1;
	}

	os_memset(wpa_s->tspecs, 0, sizeof(wpa_s->tspecs));
	wpa_s->wmm_ac_last_dialog_token = 0;

	assoc_data = wmm_ac_process_param_elem(wpa_s, ies, ies_len);
	if (!assoc_data)
		return -1;

	wpa_printf(MSG_DEBUG, "WMM AC: U-APSD queues=0x%x",
		   wmm_params->uapsd_queues);

	for (ac = 0; ac < WMM_AC_NUM; ac++) {
		assoc_data->ac_params[ac].uapsd =
			!!(wmm_params->uapsd_queues & BIT(ac));
	}

	wpa_s->wmm_ac_assoc_info = assoc_data;
	return 0;
}


static void wmm_ac_del_ts(struct wpa_supplicant *wpa_s, u8 ac, int dir_bitmap)
{
	enum ts_dir_idx idx;

	for (idx = 0; idx < TS_DIR_IDX_COUNT; idx++) {
		if (!(dir_bitmap & BIT(idx)))
			continue;

		if (!wpa_s->tspecs[ac][idx])
			continue;

		os_free(wpa_s->tspecs[ac][idx]);
		wpa_s->tspecs[ac][idx] = NULL;
	}
}


static void wmm_ac_deinit(struct wpa_supplicant *wpa_s)
{
	int i;

	for (i = 0; i < WMM_AC_NUM; i++)
		wmm_ac_del_ts(wpa_s, i, TS_DIR_IDX_ALL);

	os_free(wpa_s->wmm_ac_assoc_info);
	wpa_s->wmm_ac_assoc_info = NULL;
}


void wmm_ac_notify_assoc(struct wpa_supplicant *wpa_s, const u8 *ies,
			 size_t ies_len, const struct wmm_params *wmm_params)
{
	if (wmm_ac_init(wpa_s, ies, ies_len, wmm_params))
		return;

	wpa_printf(MSG_DEBUG,
		   "WMM AC: Valid WMM association, WMM AC is enabled");
}


void wmm_ac_notify_disassoc(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s->wmm_ac_assoc_info)
		return;

	wmm_ac_deinit(wpa_s);
	wpa_printf(MSG_DEBUG, "WMM AC: WMM AC is disabled");
}


int wpas_wmm_ac_delts(struct wpa_supplicant *wpa_s, u8 tsid)
{
	struct wmm_tspec_element *tspec;
	int ac;
	enum ts_dir_idx dir;

	if (!wpa_s->wmm_ac_assoc_info) {
		wpa_printf(MSG_DEBUG,
			   "WMM AC: Failed to delete TS, WMM AC is disabled");
		return -1;
	}

	ac = wmm_ac_find_tsid(wpa_s, tsid, &dir);
	if (ac < 0) {
		wpa_printf(MSG_DEBUG, "WMM AC: TS does not exist");
		return -1;
	}

	tspec = wpa_s->tspecs[ac][dir];
	wmm_ac_send_delts(wpa_s, tspec, wpa_s->bssid);

	os_free(tspec);
	wpa_s->tspecs[ac][dir] = NULL;

	wpa_printf(MSG_DEBUG, "WMM AC: TS was deleted (TSID=%u addr=" MACSTR
		   ")", tsid, MAC2STR(wpa_s->bssid));

	return 0;
}


int wpas_wmm_ac_addts(struct wpa_supplicant *wpa_s,
		      struct wmm_ac_ts_setup_params *params)
{
	struct wmm_ac_addts_request *addts_req;

	if (!wpa_s->wmm_ac_assoc_info) {
		wpa_printf(MSG_DEBUG,
			   "WMM AC: Cannot add TS - missing assoc data");
		return -1;
	}

	/*
	 * we can setup downlink TS even without driver support.
	 * however, we need driver support for the other directions.
	 */
	if (params->direction != WMM_AC_DIR_DOWNLINK &&
	    !wpa_s->wmm_ac_supported) {
		wpa_printf(MSG_DEBUG,
			   "Cannot set uplink/bidi TS without driver support");
		return -1;
	}

	if (!wmm_ac_ts_req_is_valid(wpa_s, params))
		return -1;

	wpa_printf(MSG_DEBUG, "WMM AC: TS setup request (addr=" MACSTR
		   " tsid=%u user priority=%u direction=%d)",
		   MAC2STR(wpa_s->bssid), params->tsid,
		   params->user_priority, params->direction);

	addts_req = wmm_ac_build_addts_req(wpa_s, params, wpa_s->bssid);
	if (!addts_req)
		return -1;

	if (wmm_ac_send_addts_request(wpa_s, addts_req))
		goto err;

	/* TODO: wait for ADDTS response, etc. */
	os_free(addts_req);
	return 0;
err:
	os_free(addts_req);
	return -1;
}
