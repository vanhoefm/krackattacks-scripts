/*
 * Copyright (c) 2009, Atheros Communications, Inc.
 * Copyright (c) 2011-2013, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "common/gas.h"
#include "common/wpa_ctrl.h"
#include "rsn_supp/wpa.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "config.h"
#include "bss.h"
#include "blacklist.h"
#include "gas_query.h"
#include "interworking.h"
#include "hs20_supplicant.h"


void wpas_hs20_add_indication(struct wpabuf *buf, int pps_mo_id)
{
	u8 conf;

	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(buf, pps_mo_id >= 0 ? 7 : 5);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, HS20_INDICATION_OUI_TYPE);
	conf = HS20_VERSION;
	if (pps_mo_id >= 0)
		conf |= HS20_PPS_MO_ID_PRESENT;
	wpabuf_put_u8(buf, conf);
	if (pps_mo_id >= 0)
		wpabuf_put_le16(buf, pps_mo_id);
}


int is_hs20_network(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
		    struct wpa_bss *bss)
{
	if (!wpa_s->conf->hs20 || !ssid)
		return 0;

	if (ssid->parent_cred)
		return 1;

	if (bss && !wpa_bss_get_vendor_ie(bss, HS20_IE_VENDOR_TYPE))
		return 0;

	/*
	 * This may catch some non-Hotspot 2.0 cases, but it is safer to do that
	 * than cause Hotspot 2.0 connections without indication element getting
	 * added. Non-Hotspot 2.0 APs should ignore the unknown vendor element.
	 */

	if (!(ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X))
		return 0;
	if (!(ssid->pairwise_cipher & WPA_CIPHER_CCMP))
		return 0;
	if (ssid->proto != WPA_PROTO_RSN)
		return 0;

	return 1;
}


int hs20_get_pps_mo_id(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	struct wpa_cred *cred;

	if (ssid == NULL || ssid->parent_cred == NULL)
		return 0;

	for (cred = wpa_s->conf->cred; cred; cred = cred->next) {
		if (ssid->parent_cred == cred)
			return cred->update_identifier;
	}

	return 0;
}


struct wpabuf * hs20_build_anqp_req(u32 stypes, const u8 *payload,
				    size_t payload_len)
{
	struct wpabuf *buf;
	u8 *len_pos;

	buf = gas_anqp_build_initial_req(0, 100 + payload_len);
	if (buf == NULL)
		return NULL;

	len_pos = gas_anqp_add_element(buf, ANQP_VENDOR_SPECIFIC);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, HS20_ANQP_OUI_TYPE);
	if (stypes == BIT(HS20_STYPE_NAI_HOME_REALM_QUERY)) {
		wpabuf_put_u8(buf, HS20_STYPE_NAI_HOME_REALM_QUERY);
		wpabuf_put_u8(buf, 0); /* Reserved */
		if (payload)
			wpabuf_put_data(buf, payload, payload_len);
	} else if (stypes == BIT(HS20_STYPE_ICON_REQUEST)) {
		wpabuf_put_u8(buf, HS20_STYPE_ICON_REQUEST);
		wpabuf_put_u8(buf, 0); /* Reserved */
		if (payload)
			wpabuf_put_data(buf, payload, payload_len);
	} else {
		u8 i;
		wpabuf_put_u8(buf, HS20_STYPE_QUERY_LIST);
		wpabuf_put_u8(buf, 0); /* Reserved */
		for (i = 0; i < 32; i++) {
			if (stypes & BIT(i))
				wpabuf_put_u8(buf, i);
		}
	}
	gas_anqp_set_element_len(buf, len_pos);

	gas_anqp_set_len(buf);

	return buf;
}


int hs20_anqp_send_req(struct wpa_supplicant *wpa_s, const u8 *dst, u32 stypes,
		       const u8 *payload, size_t payload_len)
{
	struct wpabuf *buf;
	int ret = 0;
	int freq;
	struct wpa_bss *bss;
	int res;

	freq = wpa_s->assoc_freq;
	bss = wpa_bss_get_bssid(wpa_s, dst);
	if (bss) {
		wpa_bss_anqp_unshare_alloc(bss);
		freq = bss->freq;
	}
	if (freq <= 0)
		return -1;

	wpa_printf(MSG_DEBUG, "HS20: ANQP Query Request to " MACSTR " for "
		   "subtypes 0x%x", MAC2STR(dst), stypes);

	buf = hs20_build_anqp_req(stypes, payload, payload_len);
	if (buf == NULL)
		return -1;

	res = gas_query_req(wpa_s->gas, dst, freq, buf, anqp_resp_cb, wpa_s);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "ANQP: Failed to send Query Request");
		wpabuf_free(buf);
		ret = -1;
	} else
		wpa_printf(MSG_DEBUG, "ANQP: Query started with dialog token "
			   "%u", res);

	return ret;
}


void hs20_parse_rx_hs20_anqp_resp(struct wpa_supplicant *wpa_s,
				  const u8 *sa, const u8 *data, size_t slen)
{
	const u8 *pos = data;
	u8 subtype;
	struct wpa_bss *bss = wpa_bss_get_bssid(wpa_s, sa);
	struct wpa_bss_anqp *anqp = NULL;
	u16 data_len;

	if (slen < 2)
		return;

	if (bss)
		anqp = bss->anqp;

	subtype = *pos++;
	slen--;

	pos++; /* Reserved */
	slen--;

	switch (subtype) {
	case HS20_STYPE_CAPABILITY_LIST:
		wpa_msg(wpa_s, MSG_INFO, "RX-HS20-ANQP " MACSTR
			" HS Capability List", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "HS Capability List", pos, slen);
		break;
	case HS20_STYPE_OPERATOR_FRIENDLY_NAME:
		wpa_msg(wpa_s, MSG_INFO, "RX-HS20-ANQP " MACSTR
			" Operator Friendly Name", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "oper friendly name", pos, slen);
		if (anqp) {
			wpabuf_free(anqp->hs20_operator_friendly_name);
			anqp->hs20_operator_friendly_name =
				wpabuf_alloc_copy(pos, slen);
		}
		break;
	case HS20_STYPE_WAN_METRICS:
		wpa_hexdump(MSG_DEBUG, "WAN Metrics", pos, slen);
		if (slen < 13) {
			wpa_dbg(wpa_s, MSG_DEBUG, "HS 2.0: Too short WAN "
				"Metrics value from " MACSTR, MAC2STR(sa));
			break;
		}
		wpa_msg(wpa_s, MSG_INFO, "RX-HS20-ANQP " MACSTR
			" WAN Metrics %02x:%u:%u:%u:%u:%u", MAC2STR(sa),
			pos[0], WPA_GET_LE32(pos + 1), WPA_GET_LE32(pos + 5),
			pos[9], pos[10], WPA_GET_LE16(pos + 11));
		if (anqp) {
			wpabuf_free(anqp->hs20_wan_metrics);
			anqp->hs20_wan_metrics = wpabuf_alloc_copy(pos, slen);
		}
		break;
	case HS20_STYPE_CONNECTION_CAPABILITY:
		wpa_msg(wpa_s, MSG_INFO, "RX-HS20-ANQP " MACSTR
			" Connection Capability", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "conn capability", pos, slen);
		if (anqp) {
			wpabuf_free(anqp->hs20_connection_capability);
			anqp->hs20_connection_capability =
				wpabuf_alloc_copy(pos, slen);
		}
		break;
	case HS20_STYPE_OPERATING_CLASS:
		wpa_msg(wpa_s, MSG_INFO, "RX-HS20-ANQP " MACSTR
			" Operating Class", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "Operating Class", pos, slen);
		if (anqp) {
			wpabuf_free(anqp->hs20_operating_class);
			anqp->hs20_operating_class =
				wpabuf_alloc_copy(pos, slen);
		}
		break;
	case HS20_STYPE_OSU_PROVIDERS_LIST:
		wpa_msg(wpa_s, MSG_INFO, "RX-HS20-ANQP " MACSTR
			" OSU Providers list", MAC2STR(sa));
		if (anqp) {
			wpabuf_free(anqp->hs20_osu_providers_list);
			anqp->hs20_osu_providers_list =
				wpabuf_alloc_copy(pos, slen);
		}
		break;
	case HS20_STYPE_ICON_BINARY_FILE:
		wpa_msg(wpa_s, MSG_INFO, "RX-HS20-ANQP " MACSTR
			" Icon Binary File", MAC2STR(sa));

		if (slen < 4) {
			wpa_dbg(wpa_s, MSG_DEBUG, "HS 2.0: Too short Icon "
				"Binary File value from " MACSTR, MAC2STR(sa));
			break;
		}

		wpa_printf(MSG_DEBUG, "HS 2.0: Download Status Code %u", *pos);
		pos++;
		slen--;

		if ((size_t) 1 + pos[0] > slen) {
			wpa_dbg(wpa_s, MSG_DEBUG, "HS 2.0: Too short Icon "
				"Binary File value from " MACSTR, MAC2STR(sa));
			break;
		}
		wpa_hexdump_ascii(MSG_DEBUG, "Icon Type", pos + 1, pos[0]);
		slen -= 1 + pos[0];
		pos += 1 + pos[0];

		if (slen < 2) {
			wpa_dbg(wpa_s, MSG_DEBUG, "HS 2.0: Too short Icon "
				"Binary File value from " MACSTR, MAC2STR(sa));
			break;
		}
		data_len = WPA_GET_BE16(pos);
		pos += 2;
		slen -= 2;

		if (data_len > slen) {
			wpa_dbg(wpa_s, MSG_DEBUG, "HS 2.0: Too short Icon "
				"Binary File value from " MACSTR, MAC2STR(sa));
			break;
		}

		wpa_printf(MSG_DEBUG, "Icon Binary Data: %u bytes", data_len);
		break;
	default:
		wpa_printf(MSG_DEBUG, "HS20: Unsupported subtype %u", subtype);
		break;
	}
}


void hs20_rx_subscription_remediation(struct wpa_supplicant *wpa_s,
				      const char *url, u8 osu_method)
{
	if (url)
		wpa_msg(wpa_s, MSG_INFO, HS20_SUBSCRIPTION_REMEDIATION "%u %s",
			osu_method, url);
	else
		wpa_msg(wpa_s, MSG_INFO, HS20_SUBSCRIPTION_REMEDIATION);
}


void hs20_rx_deauth_imminent_notice(struct wpa_supplicant *wpa_s, u8 code,
				    u16 reauth_delay, const char *url)
{
	if (!wpa_sm_pmf_enabled(wpa_s->wpa)) {
		wpa_printf(MSG_DEBUG, "HS 2.0: Ignore deauthentication imminent notice since PMF was not enabled");
		return;
	}

	wpa_msg(wpa_s, MSG_INFO, HS20_DEAUTH_IMMINENT_NOTICE "%u %u %s",
		code, reauth_delay, url);

	if (code == HS20_DEAUTH_REASON_CODE_BSS) {
		wpa_printf(MSG_DEBUG, "HS 2.0: Add BSS to blacklist");
		wpa_blacklist_add(wpa_s, wpa_s->bssid);
	}

	if (code == HS20_DEAUTH_REASON_CODE_ESS && wpa_s->current_ssid) {
		struct os_time now;
		os_get_time(&now);
		if (now.sec + reauth_delay <=
		    wpa_s->current_ssid->disabled_until.sec)
			return;
		wpa_printf(MSG_DEBUG, "HS 2.0: Disable network for %u seconds",
			   reauth_delay);
		wpa_s->current_ssid->disabled_until.sec =
			now.sec + reauth_delay;
	}
}
