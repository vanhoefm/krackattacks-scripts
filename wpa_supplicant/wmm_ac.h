/*
 * Wi-Fi Multimedia Admission Control (WMM-AC)
 * Copyright(c) 2014, Intel Mobile Communication GmbH.
 * Copyright(c) 2014, Intel Corporation. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WMM_AC_H
#define WMM_AC_H

#include "common/ieee802_11_defs.h"
#include "drivers/driver.h"

struct wpa_supplicant;

/**
 * struct wmm_ac_assoc_data - WMM Admission Control Association Data
 *
 * This struct will store any relevant WMM association data needed by WMM AC.
 * In case there is a valid WMM association, an instance of this struct will be
 * created. In case there is no instance of this struct, the station is not
 * associated to a valid WMM BSS and hence, WMM AC will not be used.
 */
struct wmm_ac_assoc_data {
	struct {
		/*
		 * acm - Admission Control Mandatory
		 * In case an access category is ACM, the traffic will have
		 * to be admitted by WMM-AC's admission mechanism before use.
		 */
		unsigned int acm:1;

		/*
		 * uapsd_queues - Unscheduled Automatic Power Save Delivery
		 *		  queues.
		 * Indicates whether ACs are configured for U-APSD (or legacy
		 * PS). Storing this value is necessary in order to set the
		 * Power Save Bit (PSB) in ADDTS request Action frames (if not
		 * given).
		 */
		unsigned int uapsd:1;
	} ac_params[WMM_AC_NUM];
};

void wmm_ac_notify_assoc(struct wpa_supplicant *wpa_s, const u8 *ies,
			 size_t ies_len, const struct wmm_params *wmm_params);
void wmm_ac_notify_disassoc(struct wpa_supplicant *wpa_s);

#endif /* WMM_AC_H */
