/*
 * Hotspot 2.0 AP ANQP processing
 * Copyright (c) 2009, Atheros Communications, Inc.
 * Copyright (c) 2011-2012, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "common/ieee802_11_defs.h"
#include "hostapd.h"
#include "ap_config.h"
#include "hs20.h"


u8 * hostapd_eid_hs20_indication(struct hostapd_data *hapd, u8 *eid)
{
	u8 conf;
	if (!hapd->conf->hs20)
		return eid;
	*eid++ = WLAN_EID_VENDOR_SPECIFIC;
	*eid++ = 7;
	WPA_PUT_BE24(eid, OUI_WFA);
	eid += 3;
	*eid++ = HS20_INDICATION_OUI_TYPE;
	conf = HS20_VERSION; /* Release Number */
	conf |= HS20_ANQP_DOMAIN_ID_PRESENT;
	if (hapd->conf->disable_dgaf)
		conf |= HS20_DGAF_DISABLED;
	*eid++ = conf;
	WPA_PUT_LE16(eid, hapd->conf->anqp_domain_id);
	eid += 2;

	return eid;
}
