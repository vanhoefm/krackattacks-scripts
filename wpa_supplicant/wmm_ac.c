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
#include "common/ieee802_11_common.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "wmm_ac.h"


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


static void wmm_ac_deinit(struct wpa_supplicant *wpa_s)
{
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
