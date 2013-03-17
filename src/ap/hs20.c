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
#include "ap_drv_ops.h"
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


int hs20_send_wnm_notification(struct hostapd_data *hapd, const u8 *addr,
			       u8 osu_method, const char *url)
{
	struct wpabuf *buf;
	size_t len = 0;
	int ret;

	/* TODO: should refuse to send notification if the STA is not associated
	 * or if the STA did not indicate support for WNM-Notification */

	if (url) {
		len = 1 + os_strlen(url);
		if (5 + len > 255) {
			wpa_printf(MSG_INFO, "HS 2.0: Too long URL for "
				   "WNM-Notification: '%s'", url);
			return -1;
		}
	}

	buf = wpabuf_alloc(4 + 7 + len);
	if (buf == NULL)
		return -1;

	wpabuf_put_u8(buf, WLAN_ACTION_WNM);
	wpabuf_put_u8(buf, WNM_NOTIFICATION_REQ);
	wpabuf_put_u8(buf, 1); /* Dialog token */
	wpabuf_put_u8(buf, 1); /* Type - 1 reserved for WFA */

	/* Subscription Remediation subelement */
	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(buf, 5 + len);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, HS20_WNM_SUB_REM_NEEDED);
	if (url) {
		wpabuf_put_u8(buf, len - 1);
		wpabuf_put_data(buf, url, len - 1);
		wpabuf_put_u8(buf, osu_method);
	} else {
		/* Server URL and Server Method fields not included */
		wpabuf_put_u8(buf, 0);
	}

	ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
				      wpabuf_head(buf), wpabuf_len(buf));

	wpabuf_free(buf);

	return ret;
}
