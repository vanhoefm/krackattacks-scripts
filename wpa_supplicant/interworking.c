/*
 * Interworking (IEEE 802.11u)
 * Copyright (c) 2011, Qualcomm Atheros
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

#include "includes.h"

#include "common.h"
#include "common/ieee802_11_defs.h"
#include "common/gas.h"
#include "drivers/driver.h"
#include "wpa_supplicant_i.h"
#include "bss.h"
#include "gas_query.h"
#include "interworking.h"


static void interworking_next_anqp_fetch(struct wpa_supplicant *wpa_s);


static struct wpabuf * anqp_build_req(u16 info_ids[], size_t num_ids,
				      struct wpabuf *extra)
{
	struct wpabuf *buf;
	size_t i;
	u8 *len_pos;

	buf = gas_anqp_build_initial_req(0, 4 + num_ids * 2 +
					 (extra ? wpabuf_len(extra) : 0));
	if (buf == NULL)
		return NULL;

	len_pos = gas_anqp_add_element(buf, ANQP_QUERY_LIST);
	for (i = 0; i < num_ids; i++)
		wpabuf_put_le16(buf, info_ids[i]);
	gas_anqp_set_element_len(buf, len_pos);
	if (extra)
		wpabuf_put_buf(buf, extra);

	gas_anqp_set_len(buf);

	return buf;
}


static void interworking_anqp_resp_cb(void *ctx, const u8 *dst,
				      u8 dialog_token,
				      enum gas_query_result result,
				      const struct wpabuf *adv_proto,
				      const struct wpabuf *resp,
				      u16 status_code)
{
	struct wpa_supplicant *wpa_s = ctx;

	anqp_resp_cb(wpa_s, dst, dialog_token, result, adv_proto, resp,
		     status_code);
	interworking_next_anqp_fetch(wpa_s);
}


static int interworking_anqp_send_req(struct wpa_supplicant *wpa_s,
				      struct wpa_bss *bss)
{
	struct wpabuf *buf;
	int ret = 0;
	int res;
	u16 info_ids[] = {
		ANQP_CAPABILITY_LIST,
		ANQP_VENUE_NAME,
		ANQP_NETWORK_AUTH_TYPE,
		ANQP_ROAMING_CONSORTIUM,
		ANQP_IP_ADDR_TYPE_AVAILABILITY,
		ANQP_NAI_REALM,
		ANQP_3GPP_CELLULAR_NETWORK,
		ANQP_DOMAIN_NAME
	};
	struct wpabuf *extra = NULL;

	wpa_printf(MSG_DEBUG, "Interworking: ANQP Query Request to " MACSTR,
		   MAC2STR(bss->bssid));

	buf = anqp_build_req(info_ids, sizeof(info_ids) / sizeof(info_ids[0]),
			     extra);
	wpabuf_free(extra);
	if (buf == NULL)
		return -1;

	res = gas_query_req(wpa_s->gas, bss->bssid, bss->freq, buf,
			    interworking_anqp_resp_cb, wpa_s);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "ANQP: Failed to send Query Request");
		ret = -1;
	} else
		wpa_printf(MSG_DEBUG, "ANQP: Query started with dialog token "
			   "%u", res);

	wpabuf_free(buf);
	return ret;
}


static void interworking_next_anqp_fetch(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss *bss;
	int found = 0;
	const u8 *ie;

	if (!wpa_s->fetch_anqp_in_progress)
		return;

	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		if (!(bss->caps & IEEE80211_CAP_ESS))
			continue;
		ie = wpa_bss_get_ie(bss, WLAN_EID_EXT_CAPAB);
		if (ie == NULL || ie[1] < 4 || !(ie[5] & 0x80))
			continue; /* AP does not support Interworking */

		if (!(bss->flags & WPA_BSS_ANQP_FETCH_TRIED)) {
			found++;
			bss->flags |= WPA_BSS_ANQP_FETCH_TRIED;
			wpa_msg(wpa_s, MSG_INFO, "Starting ANQP fetch for "
				MACSTR, MAC2STR(bss->bssid));
			interworking_anqp_send_req(wpa_s, bss);
			break;
		}
	}

	if (found == 0) {
		wpa_msg(wpa_s, MSG_INFO, "ANQP fetch completed");
		wpa_s->fetch_anqp_in_progress = 0;
	}
}


int interworking_fetch_anqp(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss *bss;

	if (wpa_s->fetch_anqp_in_progress)
		return 0;

	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list)
		bss->flags &= ~WPA_BSS_ANQP_FETCH_TRIED;

	wpa_s->fetch_anqp_in_progress = 1;
	interworking_next_anqp_fetch(wpa_s);

	return 0;
}


void interworking_stop_fetch_anqp(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s->fetch_anqp_in_progress)
		return;

	wpa_s->fetch_anqp_in_progress = 0;
}


int anqp_send_req(struct wpa_supplicant *wpa_s, const u8 *dst,
		  u16 info_ids[], size_t num_ids)
{
	struct wpabuf *buf;
	int ret = 0;
	int freq;
	struct wpa_bss *bss;
	int res;

	freq = wpa_s->assoc_freq;
	bss = wpa_bss_get_bssid(wpa_s, dst);
	if (bss)
		freq = bss->freq;
	if (freq <= 0)
		return -1;

	wpa_printf(MSG_DEBUG, "ANQP: Query Request to " MACSTR " for %u id(s)",
		   MAC2STR(dst), (unsigned int) num_ids);

	buf = anqp_build_req(info_ids, num_ids, NULL);
	if (buf == NULL)
		return -1;

	res = gas_query_req(wpa_s->gas, dst, freq, buf, anqp_resp_cb, wpa_s);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "ANQP: Failed to send Query Request");
		ret = -1;
	} else
		wpa_printf(MSG_DEBUG, "ANQP: Query started with dialog token "
			   "%u", res);

	wpabuf_free(buf);
	return ret;
}


static void interworking_parse_rx_anqp_resp(struct wpa_supplicant *wpa_s,
					    const u8 *sa, u16 info_id,
					    const u8 *data, size_t slen)
{
	const u8 *pos = data;
	struct wpa_bss *bss = wpa_bss_get_bssid(wpa_s, sa);

	switch (info_id) {
	case ANQP_CAPABILITY_LIST:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" ANQP Capability list", MAC2STR(sa));
		break;
	case ANQP_VENUE_NAME:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" Venue Name", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "ANQP: Venue Name", pos, slen);
		if (bss) {
			wpabuf_free(bss->anqp_venue_name);
			bss->anqp_venue_name = wpabuf_alloc_copy(pos, slen);
		}
		break;
	case ANQP_NETWORK_AUTH_TYPE:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" Network Authentication Type information",
			MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "ANQP: Network Authentication "
				  "Type", pos, slen);
		if (bss) {
			wpabuf_free(bss->anqp_network_auth_type);
			bss->anqp_network_auth_type =
				wpabuf_alloc_copy(pos, slen);
		}
		break;
	case ANQP_ROAMING_CONSORTIUM:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" Roaming Consortium list", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "ANQP: Roaming Consortium",
				  pos, slen);
		if (bss) {
			wpabuf_free(bss->anqp_roaming_consortium);
			bss->anqp_roaming_consortium =
				wpabuf_alloc_copy(pos, slen);
		}
		break;
	case ANQP_IP_ADDR_TYPE_AVAILABILITY:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" IP Address Type Availability information",
			MAC2STR(sa));
		wpa_hexdump(MSG_MSGDUMP, "ANQP: IP Address Availability",
			    pos, slen);
		if (bss) {
			wpabuf_free(bss->anqp_ip_addr_type_availability);
			bss->anqp_ip_addr_type_availability =
				wpabuf_alloc_copy(pos, slen);
		}
		break;
	case ANQP_NAI_REALM:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" NAI Realm list", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "ANQP: NAI Realm", pos, slen);
		if (bss) {
			wpabuf_free(bss->anqp_nai_realm);
			bss->anqp_nai_realm = wpabuf_alloc_copy(pos, slen);
		}
		break;
	case ANQP_3GPP_CELLULAR_NETWORK:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" 3GPP Cellular Network information", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_DEBUG, "ANQP: 3GPP Cellular Network",
				  pos, slen);
		if (bss) {
			wpabuf_free(bss->anqp_3gpp);
			bss->anqp_3gpp = wpabuf_alloc_copy(pos, slen);
		}
		break;
	case ANQP_DOMAIN_NAME:
		wpa_msg(wpa_s, MSG_INFO, "RX-ANQP " MACSTR
			" Domain Name list", MAC2STR(sa));
		wpa_hexdump_ascii(MSG_MSGDUMP, "ANQP: Domain Name", pos, slen);
		if (bss) {
			wpabuf_free(bss->anqp_domain_name);
			bss->anqp_domain_name = wpabuf_alloc_copy(pos, slen);
		}
		break;
	case ANQP_VENDOR_SPECIFIC:
		if (slen < 3)
			return;

		switch (WPA_GET_BE24(pos)) {
		default:
			wpa_printf(MSG_DEBUG, "Interworking: Unsupported "
				   "vendor-specific ANQP OUI %06x",
				   WPA_GET_BE24(pos));
			return;
		}
		break;
	default:
		wpa_printf(MSG_DEBUG, "Interworking: Unsupported ANQP Info ID "
			   "%u", info_id);
		break;
	}
}


void anqp_resp_cb(void *ctx, const u8 *dst, u8 dialog_token,
		  enum gas_query_result result,
		  const struct wpabuf *adv_proto,
		  const struct wpabuf *resp, u16 status_code)
{
	struct wpa_supplicant *wpa_s = ctx;
	const u8 *pos;
	const u8 *end;
	u16 info_id;
	u16 slen;

	if (result != GAS_QUERY_SUCCESS)
		return;

	pos = wpabuf_head(adv_proto);
	if (wpabuf_len(adv_proto) < 4 || pos[0] != WLAN_EID_ADV_PROTO ||
	    pos[1] < 2 || pos[3] != ACCESS_NETWORK_QUERY_PROTOCOL) {
		wpa_printf(MSG_DEBUG, "ANQP: Unexpected Advertisement "
			   "Protocol in response");
		return;
	}

	pos = wpabuf_head(resp);
	end = pos + wpabuf_len(resp);

	while (pos < end) {
		if (pos + 4 > end) {
			wpa_printf(MSG_DEBUG, "ANQP: Invalid element");
			break;
		}
		info_id = WPA_GET_LE16(pos);
		pos += 2;
		slen = WPA_GET_LE16(pos);
		pos += 2;
		if (pos + slen > end) {
			wpa_printf(MSG_DEBUG, "ANQP: Invalid element length "
				   "for Info ID %u", info_id);
			break;
		}
		interworking_parse_rx_anqp_resp(wpa_s, dst, info_id, pos,
						slen);
		pos += slen;
	}
}
