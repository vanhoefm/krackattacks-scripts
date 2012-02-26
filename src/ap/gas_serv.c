/*
 * Generic advertisement service (GAS) server
 * Copyright (c) 2011-2012, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "common/ieee802_11_defs.h"
#include "common/gas.h"
#include "utils/eloop.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "sta_info.h"
#include "gas_serv.h"


static struct gas_dialog_info *
gas_dialog_create(struct hostapd_data *hapd, const u8 *addr, u8 dialog_token)
{
	struct sta_info *sta;
	struct gas_dialog_info *dia = NULL;
	int i, j;

	sta = ap_get_sta(hapd, addr);
	if (!sta) {
		/*
		 * We need a STA entry to be able to maintain state for
		 * the GAS query.
		 */
		wpa_printf(MSG_DEBUG, "ANQP: Add a temporary STA entry for "
			   "GAS query");
		sta = ap_sta_add(hapd, addr);
		if (!sta) {
			wpa_printf(MSG_DEBUG, "Failed to add STA " MACSTR
				   " for GAS query", MAC2STR(addr));
			return NULL;
		}
		sta->flags |= WLAN_STA_GAS;
		/*
		 * The default inactivity is 300 seconds. We don't need
		 * it to be that long.
		 */
		ap_sta_session_timeout(hapd, sta, 5);
	}

	if (sta->gas_dialog == NULL) {
		sta->gas_dialog = os_zalloc(GAS_DIALOG_MAX *
					    sizeof(struct gas_dialog_info));
		if (sta->gas_dialog == NULL)
			return NULL;
	}

	for (i = sta->gas_dialog_next, j = 0; j < GAS_DIALOG_MAX; i++, j++) {
		if (i == GAS_DIALOG_MAX)
			i = 0;
		if (sta->gas_dialog[i].valid)
			continue;
		dia = &sta->gas_dialog[i];
		dia->valid = 1;
		dia->index = i;
		dia->dialog_token = dialog_token;
		sta->gas_dialog_next = (++i == GAS_DIALOG_MAX) ? 0 : i;
		return dia;
	}

	wpa_msg(hapd->msg_ctx, MSG_ERROR, "ANQP: Could not create dialog for "
		MACSTR " dialog_token %u. Consider increasing "
		"GAS_DIALOG_MAX.", MAC2STR(addr), dialog_token);

	return NULL;
}


struct gas_dialog_info *
gas_serv_dialog_find(struct hostapd_data *hapd, const u8 *addr,
		     u8 dialog_token)
{
	struct sta_info *sta;
	int i;

	sta = ap_get_sta(hapd, addr);
	if (!sta) {
		wpa_printf(MSG_DEBUG, "ANQP: could not find STA " MACSTR,
			   MAC2STR(addr));
		return NULL;
	}
	for (i = 0; sta->gas_dialog && i < GAS_DIALOG_MAX; i++) {
		if (sta->gas_dialog[i].dialog_token != dialog_token ||
		    !sta->gas_dialog[i].valid)
			continue;
		return &sta->gas_dialog[i];
	}
	wpa_printf(MSG_DEBUG, "ANQP: Could not find dialog for "
		   MACSTR " dialog_token %u", MAC2STR(addr), dialog_token);
	return NULL;
}


void gas_serv_dialog_clear(struct gas_dialog_info *dia)
{
	wpabuf_free(dia->sd_resp);
	os_memset(dia, 0, sizeof(*dia));
}


static void gas_serv_free_dialogs(struct hostapd_data *hapd,
				  const u8 *sta_addr)
{
	struct sta_info *sta;
	int i;

	sta = ap_get_sta(hapd, sta_addr);
	if (sta == NULL || sta->gas_dialog == NULL)
		return;

	for (i = 0; i < GAS_DIALOG_MAX; i++) {
		if (sta->gas_dialog[i].valid)
			return;
	}

	os_free(sta->gas_dialog);
	sta->gas_dialog = NULL;
}


static void anqp_add_capab_list(struct hostapd_data *hapd,
				struct wpabuf *buf)
{
	u8 *len;

	len = gas_anqp_add_element(buf, ANQP_CAPABILITY_LIST);
	wpabuf_put_le16(buf, ANQP_CAPABILITY_LIST);
	if (hapd->conf->venue_name)
		wpabuf_put_le16(buf, ANQP_VENUE_NAME);
	if (hapd->conf->roaming_consortium)
		wpabuf_put_le16(buf, ANQP_ROAMING_CONSORTIUM);
	gas_anqp_set_element_len(buf, len);
}


static void anqp_add_venue_name(struct hostapd_data *hapd, struct wpabuf *buf)
{
	if (hapd->conf->venue_name) {
		u8 *len;
		unsigned int i;
		len = gas_anqp_add_element(buf, ANQP_VENUE_NAME);
		wpabuf_put_u8(buf, hapd->conf->venue_group);
		wpabuf_put_u8(buf, hapd->conf->venue_type);
		for (i = 0; i < hapd->conf->venue_name_count; i++) {
			struct hostapd_venue_name *vn;
			vn = &hapd->conf->venue_name[i];
			wpabuf_put_u8(buf, 3 + vn->name_len);
			wpabuf_put_data(buf, vn->lang, 3);
			wpabuf_put_data(buf, vn->name, vn->name_len);
		}
		gas_anqp_set_element_len(buf, len);
	}
}


static void anqp_add_roaming_consortium(struct hostapd_data *hapd,
					struct wpabuf *buf)
{
	unsigned int i;
	u8 *len;

	len = gas_anqp_add_element(buf, ANQP_ROAMING_CONSORTIUM);
	for (i = 0; i < hapd->conf->roaming_consortium_count; i++) {
		struct hostapd_roaming_consortium *rc;
		rc = &hapd->conf->roaming_consortium[i];
		wpabuf_put_u8(buf, rc->len);
		wpabuf_put_data(buf, rc->oi, rc->len);
	}
	gas_anqp_set_element_len(buf, len);
}


static struct wpabuf *
gas_serv_build_gas_resp_payload(struct hostapd_data *hapd,
				unsigned int request,
				struct gas_dialog_info *di)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(1400);
	if (buf == NULL)
		return NULL;

	if (request & ANQP_REQ_CAPABILITY_LIST)
		anqp_add_capab_list(hapd, buf);
	if (request & ANQP_REQ_VENUE_NAME)
		anqp_add_venue_name(hapd, buf);
	if (request & ANQP_REQ_ROAMING_CONSORTIUM)
		anqp_add_roaming_consortium(hapd, buf);

	return buf;
}


static void gas_serv_clear_cached_ies(void *eloop_data, void *user_ctx)
{
	struct gas_dialog_info *dia = eloop_data;

	wpa_printf(MSG_DEBUG, "GAS: Timeout triggered, clearing dialog for "
		   "dialog token %d", dia->dialog_token);

	gas_serv_dialog_clear(dia);
}


struct anqp_query_info {
	unsigned int request;
	unsigned int remote_request;
	const void *param;
	u32 param_arg;
	u16 remote_delay;
};


static void set_anqp_req(unsigned int bit, const char *name, int local,
			 unsigned int remote, u16 remote_delay,
			 struct anqp_query_info *qi)
{
	qi->request |= bit;
	if (local) {
		wpa_printf(MSG_DEBUG, "ANQP: %s (local)", name);
	} else if (bit & remote) {
		wpa_printf(MSG_DEBUG, "ANQP: %s (remote)", name);
		qi->remote_request |= bit;
		if (remote_delay > qi->remote_delay)
			qi->remote_delay = remote_delay;
	} else {
		wpa_printf(MSG_DEBUG, "ANQP: %s not available", name);
	}
}


static void rx_anqp_query_list_id(struct hostapd_data *hapd, u16 info_id,
				  struct anqp_query_info *qi)
{
	switch (info_id) {
	case ANQP_CAPABILITY_LIST:
		set_anqp_req(ANQP_REQ_CAPABILITY_LIST, "Capability List", 1, 0,
			     0, qi);
		break;
	case ANQP_VENUE_NAME:
		set_anqp_req(ANQP_REQ_VENUE_NAME, "Venue Name",
			     hapd->conf->venue_name != NULL, 0, 0, qi);
		break;
	case ANQP_ROAMING_CONSORTIUM:
		set_anqp_req(ANQP_REQ_ROAMING_CONSORTIUM, "Roaming Consortium",
			     hapd->conf->roaming_consortium != NULL, 0, 0, qi);
		break;
	default:
		wpa_printf(MSG_DEBUG, "ANQP: Unsupported Info Id %u",
			   info_id);
		break;
	}
}


static void rx_anqp_query_list(struct hostapd_data *hapd,
			       const u8 *pos, const u8 *end,
			       struct anqp_query_info *qi)
{
	wpa_printf(MSG_DEBUG, "ANQP: %u Info IDs requested in Query list",
		   (unsigned int) (end - pos) / 2);

	while (pos + 2 <= end) {
		rx_anqp_query_list_id(hapd, WPA_GET_LE16(pos), qi);
		pos += 2;
	}
}


static void gas_serv_req_local_processing(struct hostapd_data *hapd,
					  const u8 *sa, u8 dialog_token,
					  struct anqp_query_info *qi)
{
	struct wpabuf *buf, *tx_buf;

	buf = gas_serv_build_gas_resp_payload(hapd, qi->request, NULL);
	wpa_hexdump_buf(MSG_MSGDUMP, "ANQP: Locally generated ANQP responses",
			buf);
	if (!buf)
		return;

	if (wpabuf_len(buf) > hapd->gas_frag_limit ||
	    hapd->conf->gas_comeback_delay) {
		struct gas_dialog_info *di;
		u16 comeback_delay = 1;

		if (hapd->conf->gas_comeback_delay) {
			/* Testing - allow overriding of the delay value */
			comeback_delay = hapd->conf->gas_comeback_delay;
		}

		wpa_printf(MSG_DEBUG, "ANQP: Too long response to fit in "
			   "initial response - use GAS comeback");
		di = gas_dialog_create(hapd, sa, dialog_token);
		if (!di) {
			wpa_printf(MSG_INFO, "ANQP: Could not create dialog "
				   "for " MACSTR " (dialog token %u)",
				   MAC2STR(sa), dialog_token);
			wpabuf_free(buf);
			return;
		}
		di->sd_resp = buf;
		di->sd_resp_pos = 0;
		tx_buf = gas_anqp_build_initial_resp_buf(
			dialog_token, WLAN_STATUS_SUCCESS, comeback_delay,
			NULL);
	} else {
		wpa_printf(MSG_DEBUG, "ANQP: Initial response (no comeback)");
		tx_buf = gas_anqp_build_initial_resp_buf(
			dialog_token, WLAN_STATUS_SUCCESS, 0, buf);
		wpabuf_free(buf);
	}
	if (!tx_buf)
		return;

	hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sa,
				wpabuf_head(tx_buf), wpabuf_len(tx_buf));
	wpabuf_free(tx_buf);
}


static void gas_serv_rx_gas_initial_req(struct hostapd_data *hapd,
					const u8 *sa,
					const u8 *data, size_t len)
{
	const u8 *pos = data;
	const u8 *end = data + len;
	const u8 *next;
	u8 dialog_token;
	u16 slen;
	struct anqp_query_info qi;
	const u8 *adv_proto;

	if (len < 1 + 2)
		return;

	os_memset(&qi, 0, sizeof(qi));

	dialog_token = *pos++;
	wpa_msg(hapd->msg_ctx, MSG_DEBUG,
		"GAS: GAS Initial Request from " MACSTR " (dialog token %u) ",
		MAC2STR(sa), dialog_token);

	if (*pos != WLAN_EID_ADV_PROTO) {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG,
			"GAS: Unexpected IE in GAS Initial Request: %u", *pos);
		return;
	}
	adv_proto = pos++;

	slen = *pos++;
	next = pos + slen;
	if (next > end || slen < 2) {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG,
			"GAS: Invalid IE in GAS Initial Request");
		return;
	}
	pos++; /* skip QueryRespLenLimit and PAME-BI */

	if (*pos != ACCESS_NETWORK_QUERY_PROTOCOL) {
		struct wpabuf *buf;
		wpa_msg(hapd->msg_ctx, MSG_DEBUG,
			"GAS: Unsupported GAS advertisement protocol id %u",
			*pos);
		if (sa[0] & 0x01)
			return; /* Invalid source address - drop silently */
		buf = gas_build_initial_resp(
			dialog_token, WLAN_STATUS_GAS_ADV_PROTO_NOT_SUPPORTED,
			0, 2 + slen + 2);
		if (buf == NULL)
			return;
		wpabuf_put_data(buf, adv_proto, 2 + slen);
		wpabuf_put_le16(buf, 0); /* Query Response Length */
		hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sa,
					wpabuf_head(buf), wpabuf_len(buf));
		wpabuf_free(buf);
		return;
	}

	pos = next;
	/* Query Request */
	if (pos + 2 > end)
		return;
	slen = WPA_GET_LE16(pos);
	pos += 2;
	if (pos + slen > end)
		return;
	end = pos + slen;

	/* ANQP Query Request */
	while (pos < end) {
		u16 info_id, elen;

		if (pos + 4 > end)
			return;

		info_id = WPA_GET_LE16(pos);
		pos += 2;
		elen = WPA_GET_LE16(pos);
		pos += 2;

		if (pos + elen > end) {
			wpa_printf(MSG_DEBUG, "ANQP: Invalid Query Request");
			return;
		}

		switch (info_id) {
		case ANQP_QUERY_LIST:
			rx_anqp_query_list(hapd, pos, pos + elen, &qi);
			break;
		default:
			wpa_printf(MSG_DEBUG, "ANQP: Unsupported Query "
				   "Request element %u", info_id);
			break;
		}

		pos += elen;
	}

	gas_serv_req_local_processing(hapd, sa, dialog_token, &qi);
}


void gas_serv_tx_gas_response(struct hostapd_data *hapd, const u8 *dst,
			      struct gas_dialog_info *dialog)
{
	struct wpabuf *buf, *tx_buf;
	u8 dialog_token = dialog->dialog_token;
	size_t frag_len;

	if (dialog->sd_resp == NULL) {
		buf = gas_serv_build_gas_resp_payload(hapd,
						      dialog->all_requested,
						      dialog);
		wpa_hexdump_buf(MSG_MSGDUMP, "ANQP: Generated ANQP responses",
			buf);
		if (!buf)
			goto tx_gas_response_done;
		dialog->sd_resp = buf;
		dialog->sd_resp_pos = 0;
	}
	frag_len = wpabuf_len(dialog->sd_resp) - dialog->sd_resp_pos;
	if (frag_len > hapd->gas_frag_limit || dialog->comeback_delay ||
	    hapd->conf->gas_comeback_delay) {
		u16 comeback_delay_tus = dialog->comeback_delay +
			GAS_SERV_COMEBACK_DELAY_FUDGE;
		u32 comeback_delay_secs, comeback_delay_usecs;

		if (hapd->conf->gas_comeback_delay) {
			/* Testing - allow overriding of the delay value */
			comeback_delay_tus = hapd->conf->gas_comeback_delay;
		}

		wpa_printf(MSG_DEBUG, "GAS: Response frag_len %u (frag limit "
			   "%u) and comeback delay %u, "
			   "requesting comebacks", (unsigned int) frag_len,
			   (unsigned int) hapd->gas_frag_limit,
			   dialog->comeback_delay);
		tx_buf = gas_anqp_build_initial_resp_buf(dialog_token,
							 WLAN_STATUS_SUCCESS,
							 comeback_delay_tus,
							 NULL);
		if (tx_buf) {
			wpa_msg(hapd->msg_ctx, MSG_DEBUG,
				"GAS: Tx GAS Initial Resp (comeback = 10TU)");
			hostapd_drv_send_action(hapd, hapd->iface->freq, 0,
						dst,
						wpabuf_head(tx_buf),
						wpabuf_len(tx_buf));
		}
		wpabuf_free(tx_buf);

		/* start a timer of 1.5 * comeback-delay */
		comeback_delay_tus = comeback_delay_tus +
			(comeback_delay_tus / 2);
		comeback_delay_secs = (comeback_delay_tus * 1024) / 1000000;
		comeback_delay_usecs = (comeback_delay_tus * 1024) -
			(comeback_delay_secs * 1000000);
		eloop_register_timeout(comeback_delay_secs,
				       comeback_delay_usecs,
				       gas_serv_clear_cached_ies, dialog,
				       NULL);
		goto tx_gas_response_done;
	}

	buf = wpabuf_alloc_copy(wpabuf_head_u8(dialog->sd_resp) +
				dialog->sd_resp_pos, frag_len);
	if (buf == NULL) {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: Buffer allocation "
			"failed");
		goto tx_gas_response_done;
	}
	tx_buf = gas_anqp_build_initial_resp_buf(dialog_token,
						 WLAN_STATUS_SUCCESS, 0, buf);
	wpabuf_free(buf);
	if (tx_buf == NULL)
		goto tx_gas_response_done;
	wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: Tx GAS Initial "
		"Response (frag_id %d frag_len %d)",
		dialog->sd_frag_id, (int) frag_len);
	dialog->sd_frag_id++;

	hostapd_drv_send_action(hapd, hapd->iface->freq, 0, dst,
				wpabuf_head(tx_buf), wpabuf_len(tx_buf));
	wpabuf_free(tx_buf);
tx_gas_response_done:
	gas_serv_clear_cached_ies(dialog, NULL);
}


static void gas_serv_rx_gas_comeback_req(struct hostapd_data *hapd,
					 const u8 *sa,
					 const u8 *data, size_t len)
{
	struct gas_dialog_info *dialog;
	struct wpabuf *buf, *tx_buf;
	u8 dialog_token;
	size_t frag_len;
	int more = 0;

	wpa_hexdump(MSG_DEBUG, "GAS: RX GAS Comeback Request", data, len);
	if (len < 1)
		return;
	dialog_token = *data;
	wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: Dialog Token: %u",
		dialog_token);

	dialog = gas_serv_dialog_find(hapd, sa, dialog_token);
	if (!dialog) {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: No pending SD "
			"response fragment for " MACSTR " dialog token %u",
			MAC2STR(sa), dialog_token);

		if (sa[0] & 0x01)
			return; /* Invalid source address - drop silently */
		tx_buf = gas_anqp_build_comeback_resp_buf(
			dialog_token, WLAN_STATUS_NO_OUTSTANDING_GAS_REQ, 0, 0,
			0, NULL);
		if (tx_buf == NULL)
			return;
		goto send_resp;
	}

	if (dialog->sd_resp == NULL) {
		wpa_printf(MSG_DEBUG, "GAS: Remote request 0x%x received 0x%x",
			   dialog->requested, dialog->received);
		if ((dialog->requested & dialog->received) !=
		    dialog->requested) {
			wpa_printf(MSG_DEBUG, "GAS: Did not receive response "
				   "from remote processing");
			gas_serv_dialog_clear(dialog);
			tx_buf = gas_anqp_build_comeback_resp_buf(
				dialog_token,
				WLAN_STATUS_GAS_RESP_NOT_RECEIVED, 0, 0, 0,
				NULL);
			if (tx_buf == NULL)
				return;
			goto send_resp;
		}

		buf = gas_serv_build_gas_resp_payload(hapd,
						      dialog->all_requested,
						      dialog);
		wpa_hexdump_buf(MSG_MSGDUMP, "ANQP: Generated ANQP responses",
			buf);
		if (!buf)
			goto rx_gas_comeback_req_done;
		dialog->sd_resp = buf;
		dialog->sd_resp_pos = 0;
	}
	frag_len = wpabuf_len(dialog->sd_resp) - dialog->sd_resp_pos;
	if (frag_len > hapd->gas_frag_limit) {
		frag_len = hapd->gas_frag_limit;
		more = 1;
	}
	wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: resp frag_len %u",
		(unsigned int) frag_len);
	buf = wpabuf_alloc_copy(wpabuf_head_u8(dialog->sd_resp) +
				dialog->sd_resp_pos, frag_len);
	if (buf == NULL) {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: Failed to allocate "
			"buffer");
		goto rx_gas_comeback_req_done;
	}
	tx_buf = gas_anqp_build_comeback_resp_buf(dialog_token,
						  WLAN_STATUS_SUCCESS,
						  dialog->sd_frag_id,
						  more, 0, buf);
	wpabuf_free(buf);
	if (tx_buf == NULL)
		goto rx_gas_comeback_req_done;
	wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: Tx GAS Comeback Response "
		"(frag_id %d more=%d frag_len=%d)",
		dialog->sd_frag_id, more, (int) frag_len);
	dialog->sd_frag_id++;
	dialog->sd_resp_pos += frag_len;

	if (more) {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: %d more bytes remain "
			"to be sent",
			(int) (wpabuf_len(dialog->sd_resp) -
			       dialog->sd_resp_pos));
	} else {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG, "GAS: All fragments of "
			"SD response sent");
		gas_serv_dialog_clear(dialog);
		gas_serv_free_dialogs(hapd, sa);
	}

send_resp:
	hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sa,
				wpabuf_head(tx_buf), wpabuf_len(tx_buf));
	wpabuf_free(tx_buf);
	return;

rx_gas_comeback_req_done:
	gas_serv_clear_cached_ies(dialog, NULL);
}


static void gas_serv_rx_public_action(void *ctx, const u8 *buf, size_t len,
				      int freq)
{
	struct hostapd_data *hapd = ctx;
	const struct ieee80211_mgmt *mgmt;
	size_t hdr_len;
	const u8 *sa, *bssid, *data;

	mgmt = (const struct ieee80211_mgmt *) buf;
	hdr_len = (const u8 *) &mgmt->u.action.u.vs_public_action.action - buf;
	if (hdr_len > len)
		return;
	if (mgmt->u.action.category != WLAN_ACTION_PUBLIC)
		return;
	sa = mgmt->sa;
	bssid = mgmt->bssid;
	len -= hdr_len;
	data = &mgmt->u.action.u.public_action.action;
	switch (data[0]) {
	case WLAN_PA_GAS_INITIAL_REQ:
		gas_serv_rx_gas_initial_req(hapd, sa, data + 1, len - 1);
		break;
	case WLAN_PA_GAS_COMEBACK_REQ:
		gas_serv_rx_gas_comeback_req(hapd, sa, data + 1, len - 1);
		break;
	}
}


int gas_serv_init(struct hostapd_data *hapd)
{
	hapd->public_action_cb = gas_serv_rx_public_action;
	hapd->public_action_cb_ctx = hapd;
	hapd->gas_frag_limit = 1400;
	if (hapd->conf->gas_frag_limit > 0)
		hapd->gas_frag_limit = hapd->conf->gas_frag_limit;
	return 0;
}


void gas_serv_deinit(struct hostapd_data *hapd)
{
}
