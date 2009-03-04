/*
 * hostapd / WMM (Wi-Fi Multimedia)
 * Copyright 2002-2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef WME_H
#define WME_H

#ifdef __linux__
#include <endian.h>
#endif /* __linux__ */

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/types.h>
#include <sys/endian.h>
#endif /* defined(__FreeBSD__) || defined(__NetBSD__) ||
	* defined(__DragonFly__) */


/*
 * WMM Information Element (used in (Re)Association Request frames; may also be
 * used in Beacon frames)
 */
struct wmm_information_element {
	/* Element ID: 221 (0xdd); Length: 7 */
	/* required fields for WMM version 1 */
	u8 oui[3]; /* 00:50:f2 */
	u8 oui_type; /* 2 */
	u8 oui_subtype; /* 0 */
	u8 version; /* 1 for WMM version 1.0 */
	u8 qos_info; /* AP/STA specific QoS info */

} __attribute__ ((packed));

struct wmm_ac_parameter {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	/* byte 1: ACI/AIFSN */
	u8 	aifsn:4,
		acm:1,
		aci:2,
		reserved:1;

	/* byte 2: ECWmin/ECWmax (CW = 2^ECW - 1) */
	u8 	e_cw_min:4,
		e_cw_max:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	/* byte 1: ACI/AIFSN */
	u8 	reserved:1,
		aci:2,
		acm:1,
		aifsn:4;

	/* byte 2: ECWmin/ECWmax */
	u8 	e_cw_max:4,
		e_cw_min:4;
#else
#error	"Please fix <endian.h>"
#endif

	/* bytes 3 & 4 */
	le16 txop_limit;
} __attribute__ ((packed));

/*
 * WMM Parameter Element (used in Beacon, Probe Response, and (Re)Association
 * Response frmaes)
 */
struct wmm_parameter_element {
	/* Element ID: 221 (0xdd); Length: 24 */
	/* required fields for WMM version 1 */
	u8 oui[3]; /* 00:50:f2 */
	u8 oui_type; /* 2 */
	u8 oui_subtype; /* 1 */
	u8 version; /* 1 for WMM version 1.0 */
	u8 qos_info; /* AP/STA specif QoS info */
	u8 reserved; /* 0 */
	struct wmm_ac_parameter ac[4]; /* AC_BE, AC_BK, AC_VI, AC_VO */

} __attribute__ ((packed));

/* WMM TSPEC Element */
struct wmm_tspec_element {
	u8 eid; /* 221 = 0xdd */
	u8 length; /* 6 + 55 = 61 */
	u8 oui[3]; /* 00:50:f2 */
	u8 oui_type; /* 2 */
	u8 oui_subtype; /* 2 */
	u8 version; /* 1 */
	/* WMM TSPEC body (55 octets): */
	u8 ts_info[3];
	le16 nominal_msdu_size;
	le16 maximum_msdu_size;
	le32 minimum_service_interval;
	le32 maximum_service_interval;
	le32 inactivity_interval;
	le32 suspension_interval;
	le32 service_start_time;
	le32 minimum_data_rate;
	le32 mean_data_rate;
	le32 peak_data_rate;
	le32 maximum_burst_size;
	le32 delay_bound;
	le32 minimum_phy_rate;
	le16 surplus_bandwidth_allowance;
	le16 medium_time;
} __attribute__ ((packed));


/* Access Categories / ACI to AC coding */
enum {
	WMM_AC_BE = 0 /* Best Effort */,
	WMM_AC_BK = 1 /* Background */,
	WMM_AC_VI = 2 /* Video */,
	WMM_AC_VO = 3 /* Voice */
};

struct ieee80211_mgmt;

u8 * hostapd_eid_wmm(struct hostapd_data *hapd, u8 *eid);
int hostapd_eid_wmm_valid(struct hostapd_data *hapd, u8 *eid, size_t len);
#ifdef NEED_MLME
int hostapd_wmm_sta_config(struct hostapd_data *hapd, struct sta_info *sta);
#else /* NEED_MLME */
static inline int hostapd_wmm_sta_config(struct hostapd_data *hapd,
					 struct sta_info *sta)
{
	return 0;
}
#endif /* NEED_MLME */
void hostapd_wmm_action(struct hostapd_data *hapd, struct ieee80211_mgmt *mgmt,
			size_t len);

#endif /* WME_H */
