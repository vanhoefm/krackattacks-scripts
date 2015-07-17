/*
 * FST module - auxiliary definitions
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef FST_INTERNAL_H
#define FST_INTERNAL_H

#include "utils/includes.h"
#include "utils/common.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "fst/fst_iface.h"
#include "fst/fst_group.h"
#include "fst/fst_session.h"

#define fst_printf(level, format, ...) \
	wpa_printf((level), "FST: " format, ##__VA_ARGS__)

#define fst_printf_group(group, level, format, ...) \
	wpa_printf((level), "FST: %s: " format, \
		   fst_group_get_id(group), ##__VA_ARGS__)

#define fst_printf_iface(iface, level, format, ...) \
	fst_printf_group(fst_iface_get_group(iface), (level), "%s: " format, \
			 fst_iface_get_name(iface), ##__VA_ARGS__)

static inline enum mb_band_id
fst_hw_mode_to_band(enum hostapd_hw_mode mode)
{
	switch (mode) {
	case HOSTAPD_MODE_IEEE80211B:
	case HOSTAPD_MODE_IEEE80211G:
		return MB_BAND_ID_WIFI_2_4GHZ;
	case HOSTAPD_MODE_IEEE80211A:
		return MB_BAND_ID_WIFI_5GHZ;
	case HOSTAPD_MODE_IEEE80211AD:
		return MB_BAND_ID_WIFI_60GHZ;
	default:
		WPA_ASSERT(0);
		return MB_BAND_ID_WIFI_2_4GHZ;
	}
}

#define IE_HEADER_SIZE               ((u8) (2 * sizeof(u8)))
#define IE_BUFFER_LENGTH(ie_len_val) ((size_t) ((ie_len_val) + IE_HEADER_SIZE))

struct fst_ctrl_handle {
	struct fst_ctrl ctrl;
	struct dl_list global_ctrls_lentry;
};

extern struct dl_list fst_global_ctrls_list;

#define foreach_fst_ctrl_call(clb, ...) \
	do { \
		struct fst_ctrl_handle *__fst_ctrl_h; \
		dl_list_for_each(__fst_ctrl_h, &fst_global_ctrls_list, \
			struct fst_ctrl_handle, global_ctrls_lentry) \
			if (__fst_ctrl_h->ctrl.clb) \
				__fst_ctrl_h->ctrl.clb(__VA_ARGS__);\
	} while (0)

#endif /* FST_INTERNAL_H */
