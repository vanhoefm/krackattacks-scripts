/*
 * hostapd / IEEE 802.11ax HE
 * Copyright (c) 2016-2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/qca-vendor.h"
#include "hostapd.h"
#include "ap_config.h"
#include "beacon.h"
#include "ieee802_11.h"
#include "dfs.h"

u8 * hostapd_eid_vendor_he_capab(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_he_capabilities *cap;
	u8 *pos = eid;

	if (!hapd->iface->current_mode)
		return eid;

	/* For now, use a vendor specific element since the P802.11ax draft is
	 * still subject to changes and the contents of this element may change.
	 * This can be replaced with the actual element once P802.11ax is
	 * finalized. */
	/* Vendor HE Capabilities element */
	*pos++ = WLAN_EID_VENDOR_SPECIFIC;
	*pos++ = 4 /* The Vendor OUI, subtype */ +
		sizeof(struct ieee80211_he_capabilities);

	WPA_PUT_BE32(pos, (OUI_QCA << 8) | QCA_VENDOR_ELEM_HE_CAPAB);
	pos += 4;
	cap = (struct ieee80211_he_capabilities *) pos;
	os_memset(cap, 0, sizeof(*cap));

	if (hapd->iface->conf->he_phy_capab.he_su_beamformer)
		cap->he_phy_capab_info[HE_PHYCAP_SU_BEAMFORMER_CAPAB_IDX] |=
			HE_PHYCAP_SU_BEAMFORMER_CAPAB;

	if (hapd->iface->conf->he_phy_capab.he_su_beamformee)
		cap->he_phy_capab_info[HE_PHYCAP_SU_BEAMFORMEE_CAPAB_IDX] |=
			HE_PHYCAP_SU_BEAMFORMEE_CAPAB;

	if (hapd->iface->conf->he_phy_capab.he_mu_beamformer)
		cap->he_phy_capab_info[HE_PHYCAP_MU_BEAMFORMER_CAPAB_IDX] |=
			HE_PHYCAP_MU_BEAMFORMER_CAPAB;

	pos += sizeof(*cap);

	return pos;
}


u8 * hostapd_eid_vendor_he_operation(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_he_operation *oper;
	u8 *pos = eid;

	if (!hapd->iface->current_mode)
		return eid;

	/* For now, use a vendor specific element since the P802.11ax draft is
	 * still subject to changes and the contents of this element may change.
	 * This can be replaced with the actual element once P802.11ax is
	 * finalized. */
	/* Vendor HE Operation element */
	*pos++ = WLAN_EID_VENDOR_SPECIFIC;
	*pos++ = 4 /* The Vendor OUI, subtype */ +
		sizeof(struct ieee80211_he_operation);

	WPA_PUT_BE32(pos, (OUI_QCA << 8) | QCA_VENDOR_ELEM_HE_OPER);
	pos += 4;
	oper = (struct ieee80211_he_operation *) pos;
	os_memset(oper, 0, sizeof(*oper));

	if (hapd->iface->conf->he_op.he_bss_color)
		oper->he_oper_params |= hapd->iface->conf->he_op.he_bss_color;

	if (hapd->iface->conf->he_op.he_default_pe_duration)
		oper->he_oper_params |=
			(hapd->iface->conf->he_op.he_default_pe_duration <<
			 HE_OPERATION_DFLT_PE_DURATION_OFFSET);

	if (hapd->iface->conf->he_op.he_twt_required)
		oper->he_oper_params |= HE_OPERATION_TWT_REQUIRED;

	if (hapd->iface->conf->he_op.he_rts_threshold)
		oper->he_oper_params |=
			(hapd->iface->conf->he_op.he_rts_threshold <<
			 HE_OPERATION_RTS_THRESHOLD_OFFSET);

	pos += sizeof(*oper);

	return pos;
}
