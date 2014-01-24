/*
 * Qualcomm Atheros OUI and vendor specific assignments
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef QCA_VENDOR_H
#define QCA_VENDOR_H

/*
 * This file is a registry of identifier assignments from the Qualcomm Atheros
 * OUI 00:13:74 for purposes other than MAC address assignment. New identifiers
 * can be assigned through normal review process for changes to the upstream
 * hostap.git repository.
 */

#define OUI_QCA 0x001374

/**
 * enum qca_nl80211_vendor_subcmds - QCA nl80211 vendor command identifiers
 *
 * @QCA_NL80211_VENDOR_SUBCMD_UNSPEC: Reserved value 0
 *
 * @QCA_NL80211_VENDOR_SUBCMD_TEST: Test command/event
 *
 * @QCA_NL80211_VENDOR_SUBCMD_AVOID_FREQUENCY: Recommendation of frequency
 *	ranges to avoid to reduce issues due to interference or internal
 *	co-existence information in the driver. The event data structure is
 *	defined in struct qca_avoid_freq_list.
 */
enum qca_nl80211_vendor_subcmds {
	QCA_NL80211_VENDOR_SUBCMD_UNSPEC = 0,
	QCA_NL80211_VENDOR_SUBCMD_TEST = 1,
	/* subcmds 2..9 not yet allocated */
	QCA_NL80211_VENDOR_SUBCMD_AVOID_FREQUENCY = 10,
};


struct qca_avoid_freq_range {
	u32 start_freq;
	u32 end_freq;
} STRUCT_PACKED;

struct qca_avoid_freq_list {
	u32 count;
	struct qca_avoid_freq_range range[0];
} STRUCT_PACKED;

#endif /* QCA_VENDOR_H */
