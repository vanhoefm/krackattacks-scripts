/*
 * wpa_supplicant - DPP
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/dpp.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "offchannel.h"
#include "dpp_supplicant.h"


static int wpas_dpp_listen_start(struct wpa_supplicant *wpa_s,
				 unsigned int freq);
static void wpas_dpp_tx_status(struct wpa_supplicant *wpa_s,
			       unsigned int freq, const u8 *dst,
			       const u8 *src, const u8 *bssid,
			       const u8 *data, size_t data_len,
			       enum offchannel_send_action_result result);

static const u8 broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


static unsigned int wpas_dpp_next_id(struct wpa_supplicant *wpa_s)
{
	struct dpp_bootstrap_info *bi;
	unsigned int max_id = 0;

	dl_list_for_each(bi, &wpa_s->dpp_bootstrap, struct dpp_bootstrap_info,
			 list) {
		if (bi->id > max_id)
			max_id = bi->id;
	}
	return max_id + 1;
}


/**
 * wpas_dpp_qr_code - Parse and add DPP bootstrapping info from a QR Code
 * @wpa_s: Pointer to wpa_supplicant data
 * @cmd: DPP URI read from a QR Code
 * Returns: Identifier of the stored info or -1 on failure
 */
int wpas_dpp_qr_code(struct wpa_supplicant *wpa_s, const char *cmd)
{
	struct dpp_bootstrap_info *bi;
	struct dpp_authentication *auth = wpa_s->dpp_auth;

	bi = dpp_parse_qr_code(cmd);
	if (!bi)
		return -1;

	bi->id = wpas_dpp_next_id(wpa_s);
	dl_list_add(&wpa_s->dpp_bootstrap, &bi->list);

	if (auth && auth->response_pending &&
	    dpp_notify_new_qr_code(auth, bi) == 1) {
		struct wpabuf *msg;

		wpa_printf(MSG_DEBUG,
			   "DPP: Sending out pending authentication response");
		msg = dpp_alloc_msg(DPP_PA_AUTHENTICATION_RESP,
				    wpabuf_len(auth->resp_attr));
		if (!msg)
			goto out;
		wpabuf_put_buf(msg, wpa_s->dpp_auth->resp_attr);

		offchannel_send_action(wpa_s, auth->curr_freq,
				       auth->peer_mac_addr, wpa_s->own_addr,
				       broadcast,
				       wpabuf_head(msg), wpabuf_len(msg),
				       500, wpas_dpp_tx_status, 0);
		wpabuf_free(msg);
	}

out:
	return bi->id;
}


static char * get_param(const char *cmd, const char *param)
{
	const char *pos, *end;
	char *val;
	size_t len;

	pos = os_strstr(cmd, param);
	if (!pos)
		return NULL;

	pos += os_strlen(param);
	end = os_strchr(pos, ' ');
	if (end)
		len = end - pos;
	else
		len = os_strlen(pos);
	val = os_malloc(len + 1);
	if (!val)
		return NULL;
	os_memcpy(val, pos, len);
	val[len] = '\0';
	return val;
}


int wpas_dpp_bootstrap_gen(struct wpa_supplicant *wpa_s, const char *cmd)
{
	char *chan = NULL, *mac = NULL, *info = NULL, *pk = NULL, *curve = NULL;
	char *key = NULL;
	u8 *privkey = NULL;
	size_t privkey_len = 0;
	size_t len;
	int ret = -1;
	struct dpp_bootstrap_info *bi;

	bi = os_zalloc(sizeof(*bi));
	if (!bi)
		goto fail;

	if (os_strstr(cmd, "type=qrcode"))
		bi->type = DPP_BOOTSTRAP_QR_CODE;
	else
		goto fail;

	chan = get_param(cmd, " chan=");
	mac = get_param(cmd, " mac=");
	info = get_param(cmd, " info=");
	curve = get_param(cmd, " curve=");
	key = get_param(cmd, " key=");

	if (key) {
		privkey_len = os_strlen(key) / 2;
		privkey = os_malloc(privkey_len);
		if (!privkey ||
		    hexstr2bin(key, privkey, privkey_len) < 0)
			goto fail;
	}

	pk = dpp_keygen(bi, curve, privkey, privkey_len);
	if (!pk)
		goto fail;

	len = 4; /* "DPP:" */
	if (chan) {
		if (dpp_parse_uri_chan_list(bi, chan) < 0)
			goto fail;
		len += 3 + os_strlen(chan); /* C:...; */
	}
	if (mac) {
		if (dpp_parse_uri_mac(bi, mac) < 0)
			goto fail;
		len += 3 + os_strlen(mac); /* M:...; */
	}
	if (info) {
		if (dpp_parse_uri_info(bi, info) < 0)
			goto fail;
		len += 3 + os_strlen(info); /* I:...; */
	}
	len += 4 + os_strlen(pk);
	bi->uri = os_malloc(len + 1);
	if (!bi->uri)
		goto fail;
	os_snprintf(bi->uri, len + 1, "DPP:%s%s%s%s%s%s%s%s%sK:%s;;",
		    chan ? "C:" : "", chan ? chan : "", chan ? ";" : "",
		    mac ? "M:" : "", mac ? mac : "", mac ? ";" : "",
		    info ? "I:" : "", info ? info : "", info ? ";" : "",
		    pk);
	bi->id = wpas_dpp_next_id(wpa_s);
	dl_list_add(&wpa_s->dpp_bootstrap, &bi->list);
	ret = bi->id;
	bi = NULL;
fail:
	os_free(curve);
	os_free(pk);
	os_free(chan);
	os_free(mac);
	os_free(info);
	str_clear_free(key);
	bin_clear_free(privkey, privkey_len);
	dpp_bootstrap_info_free(bi);
	return ret;
}


static struct dpp_bootstrap_info *
dpp_bootstrap_get_id(struct wpa_supplicant *wpa_s, unsigned int id)
{
	struct dpp_bootstrap_info *bi;

	dl_list_for_each(bi, &wpa_s->dpp_bootstrap, struct dpp_bootstrap_info,
			 list) {
		if (bi->id == id)
			return bi;
	}
	return NULL;
}


static int dpp_bootstrap_del(struct wpa_supplicant *wpa_s, unsigned int id)
{
	struct dpp_bootstrap_info *bi, *tmp;
	int found = 0;

	dl_list_for_each_safe(bi, tmp, &wpa_s->dpp_bootstrap,
			      struct dpp_bootstrap_info, list) {
		if (id && bi->id != id)
			continue;
		found = 1;
		dl_list_del(&bi->list);
		dpp_bootstrap_info_free(bi);
	}

	if (id == 0)
		return 0; /* flush succeeds regardless of entries found */
	return found ? 0 : -1;
}


int wpas_dpp_bootstrap_remove(struct wpa_supplicant *wpa_s, const char *id)
{
	unsigned int id_val;

	if (os_strcmp(id, "*") == 0) {
		id_val = 0;
	} else {
		id_val = atoi(id);
		if (id_val == 0)
			return -1;
	}

	return dpp_bootstrap_del(wpa_s, id_val);
}


const char * wpas_dpp_bootstrap_get_uri(struct wpa_supplicant *wpa_s,
					unsigned int id)
{
	struct dpp_bootstrap_info *bi;

	bi = dpp_bootstrap_get_id(wpa_s, id);
	if (!bi)
		return NULL;
	return bi->uri;
}


static void wpas_dpp_tx_status(struct wpa_supplicant *wpa_s,
			       unsigned int freq, const u8 *dst,
			       const u8 *src, const u8 *bssid,
			       const u8 *data, size_t data_len,
			       enum offchannel_send_action_result result)
{
	wpa_printf(MSG_DEBUG, "DPP: TX status: freq=%u dst=" MACSTR
		   " result=%s",
		   freq, MAC2STR(dst),
		   result == OFFCHANNEL_SEND_ACTION_SUCCESS ? "SUCCESS" :
		   (result == OFFCHANNEL_SEND_ACTION_NO_ACK ? "no-ACK" :
		    "FAILED"));

	if (!wpa_s->dpp_auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Ignore TX status since there is no ongoing authentication exchange");
		return;
	}

	if (wpa_s->dpp_auth->remove_on_tx_status) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Terminate authentication exchange due to an earlier error");
		dpp_auth_deinit(wpa_s->dpp_auth);
		wpa_s->dpp_auth = NULL;
		return;
	}

	if (!is_broadcast_ether_addr(dst) &&
	    result != OFFCHANNEL_SEND_ACTION_SUCCESS) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unicast DPP Action frame was not ACKed");
		/* TODO: In case of DPP Authentication Request frame, move to
		 * the next channel immediately */
	}
}


static void wpas_dpp_reply_wait_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;

	if (!wpa_s->dpp_auth)
		return;
	wpa_printf(MSG_DEBUG, "DPP: Continue reply wait on channel %u MHz",
		   wpa_s->dpp_auth->curr_freq);
	wpas_dpp_listen_start(wpa_s, wpa_s->dpp_auth->curr_freq);
}


int wpas_dpp_auth_init(struct wpa_supplicant *wpa_s, const char *cmd)
{
	const char *pos;
	struct dpp_bootstrap_info *peer_bi, *own_bi = NULL;
	struct wpabuf *msg;
	const u8 *dst;
	int res;
	int configurator = 1;
	unsigned int wait_time;

	pos = os_strstr(cmd, " peer=");
	if (!pos)
		return -1;
	pos += 6;
	peer_bi = dpp_bootstrap_get_id(wpa_s, atoi(pos));
	if (!peer_bi) {
		wpa_printf(MSG_INFO,
			   "DPP: Could not find bootstrapping info for the identified peer");
		return -1;
	}

	pos = os_strstr(cmd, " own=");
	if (pos) {
		pos += 5;
		own_bi = dpp_bootstrap_get_id(wpa_s, atoi(pos));
		if (!own_bi) {
			wpa_printf(MSG_INFO,
				   "DPP: Could not find bootstrapping info for the identified local entry");
			return -1;
		}

		if (peer_bi->curve != own_bi->curve) {
			wpa_printf(MSG_INFO,
				   "DPP: Mismatching curves in bootstrapping info (peer=%s own=%s)",
				   peer_bi->curve->name, own_bi->curve->name);
			return -1;
		}
	}

	pos = os_strstr(cmd, " role=");
	if (pos) {
		pos += 6;
		if (os_strncmp(pos, "configurator", 12) == 0)
			configurator = 1;
		else if (os_strncmp(pos, "enrollee", 8) == 0)
			configurator = 0;
		else
			return -1;
	}

	if (wpa_s->dpp_auth) {
		eloop_cancel_timeout(wpas_dpp_reply_wait_timeout, wpa_s, NULL);
		offchannel_send_action_done(wpa_s);
		dpp_auth_deinit(wpa_s->dpp_auth);
	}
	wpa_s->dpp_auth = dpp_auth_init(wpa_s, peer_bi, own_bi, configurator);
	if (!wpa_s->dpp_auth)
		return -1;

	/* TODO: Support iteration over all frequencies and filtering of
	 * frequencies based on locally enabled channels that allow initiation
	 * of transmission. */
	if (peer_bi->num_freq > 0)
		wpa_s->dpp_auth->curr_freq = peer_bi->freq[0];
	else
		wpa_s->dpp_auth->curr_freq = 2412;

	msg = dpp_alloc_msg(DPP_PA_AUTHENTICATION_REQ,
			    wpabuf_len(wpa_s->dpp_auth->req_attr));
	if (!msg)
		return -1;
	wpabuf_put_buf(msg, wpa_s->dpp_auth->req_attr);

	if (is_zero_ether_addr(peer_bi->mac_addr)) {
		dst = broadcast;
	} else {
		dst = peer_bi->mac_addr;
		os_memcpy(wpa_s->dpp_auth->peer_mac_addr, peer_bi->mac_addr,
			  ETH_ALEN);
	}
	eloop_cancel_timeout(wpas_dpp_reply_wait_timeout, wpa_s, NULL);
	wait_time = wpa_s->max_remain_on_chan;
	if (wait_time > 2000)
		wait_time = 2000;
	eloop_register_timeout(wait_time / 1000, (wait_time % 1000) * 1000,
			       wpas_dpp_reply_wait_timeout,
			       wpa_s, NULL);
	res = offchannel_send_action(wpa_s, wpa_s->dpp_auth->curr_freq,
				     dst, wpa_s->own_addr, broadcast,
				     wpabuf_head(msg), wpabuf_len(msg),
				     wait_time, wpas_dpp_tx_status, 0);
	wpabuf_free(msg);

	return res;
}


struct wpas_dpp_listen_work {
	unsigned int freq;
	unsigned int duration;
	struct wpabuf *probe_resp_ie;
};


static void wpas_dpp_listen_work_free(struct wpas_dpp_listen_work *lwork)
{
	if (!lwork)
		return;
	os_free(lwork);
}


static void wpas_dpp_listen_work_done(struct wpa_supplicant *wpa_s)
{
	struct wpas_dpp_listen_work *lwork;

	if (!wpa_s->dpp_listen_work)
		return;

	lwork = wpa_s->dpp_listen_work->ctx;
	wpas_dpp_listen_work_free(lwork);
	radio_work_done(wpa_s->dpp_listen_work);
	wpa_s->dpp_listen_work = NULL;
}


static void dpp_start_listen_cb(struct wpa_radio_work *work, int deinit)
{
	struct wpa_supplicant *wpa_s = work->wpa_s;
	struct wpas_dpp_listen_work *lwork = work->ctx;

	if (deinit) {
		if (work->started) {
			wpa_s->dpp_listen_work = NULL;
			wpas_dpp_listen_stop(wpa_s);
		}
		wpas_dpp_listen_work_free(lwork);
		return;
	}

	wpa_s->dpp_listen_work = work;

	wpa_s->dpp_pending_listen_freq = lwork->freq;

	if (wpa_drv_remain_on_channel(wpa_s, lwork->freq,
				      wpa_s->max_remain_on_chan) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to request the driver to remain on channel (%u MHz) for listen",
			   lwork->freq);
		wpas_dpp_listen_work_done(wpa_s);
		wpa_s->dpp_pending_listen_freq = 0;
		return;
	}
	wpa_s->off_channel_freq = 0;
	wpa_s->roc_waiting_drv_freq = lwork->freq;
}


static int wpas_dpp_listen_start(struct wpa_supplicant *wpa_s,
				 unsigned int freq)
{
	struct wpas_dpp_listen_work *lwork;

	if (wpa_s->dpp_listen_work) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Reject start_listen since dpp_listen_work already exists");
		return -1;
	}

	if (wpa_s->dpp_listen_freq)
		wpas_dpp_listen_stop(wpa_s);
	wpa_s->dpp_listen_freq = freq;

	lwork = os_zalloc(sizeof(*lwork));
	if (!lwork)
		return -1;
	lwork->freq = freq;

	if (radio_add_work(wpa_s, freq, "dpp-listen", 0, dpp_start_listen_cb,
			   lwork) < 0) {
		wpas_dpp_listen_work_free(lwork);
		return -1;
	}

	return 0;
}


int wpas_dpp_listen(struct wpa_supplicant *wpa_s, const char *cmd)
{
	int freq;

	freq = atoi(cmd);
	if (freq <= 0)
		return -1;

	if (os_strstr(cmd, " role=configurator"))
		wpa_s->dpp_allowed_roles = DPP_CAPAB_CONFIGURATOR;
	else if (os_strstr(cmd, " role=enrollee"))
		wpa_s->dpp_allowed_roles = DPP_CAPAB_ENROLLEE;
	else
		wpa_s->dpp_allowed_roles = DPP_CAPAB_CONFIGURATOR |
			DPP_CAPAB_ENROLLEE;
	wpa_s->dpp_qr_mutual = os_strstr(cmd, " qr=mutual") != NULL;
	if (wpa_s->dpp_listen_freq == (unsigned int) freq) {
		wpa_printf(MSG_DEBUG, "DPP: Already listening on %u MHz",
			   freq);
		return 0;
	}

	return wpas_dpp_listen_start(wpa_s, freq);
}


void wpas_dpp_listen_stop(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s->dpp_listen_freq)
		return;

	wpa_printf(MSG_DEBUG, "DPP: Stop listen on %u MHz",
		   wpa_s->dpp_listen_freq);
	wpa_drv_cancel_remain_on_channel(wpa_s);
	wpa_s->dpp_listen_freq = 0;
	wpas_dpp_listen_work_done(wpa_s);
}


void wpas_dpp_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
				   unsigned int freq)
{
	if (!wpa_s->dpp_listen_freq && !wpa_s->dpp_pending_listen_freq)
		return;

	wpa_printf(MSG_DEBUG,
		   "DPP: remain-on-channel callback (off_channel_freq=%u dpp_pending_listen_freq=%d roc_waiting_drv_freq=%d freq=%u)",
		   wpa_s->off_channel_freq, wpa_s->dpp_pending_listen_freq,
		   wpa_s->roc_waiting_drv_freq, freq);
	if (wpa_s->off_channel_freq &&
	    wpa_s->off_channel_freq == wpa_s->dpp_pending_listen_freq) {
		wpa_printf(MSG_DEBUG, "DPP: Listen on %u MHz started", freq);
		wpa_s->dpp_pending_listen_freq = 0;
	} else {
		wpa_printf(MSG_DEBUG,
			   "DPP: Ignore remain-on-channel callback (off_channel_freq=%u dpp_pending_listen_freq=%d freq=%u)",
			   wpa_s->off_channel_freq,
			   wpa_s->dpp_pending_listen_freq, freq);
	}
}


void wpas_dpp_cancel_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
					  unsigned int freq)
{
	wpas_dpp_listen_work_done(wpa_s);

	if (wpa_s->dpp_auth) {
		/* Continue listen with a new remain-on-channel */
		wpa_printf(MSG_DEBUG,
			   "DPP: Continue wait on %u MHz for the ongoing DPP provisioning session",
			   wpa_s->dpp_auth->curr_freq);
		wpas_dpp_listen_start(wpa_s, wpa_s->dpp_auth->curr_freq);
		return;
	}

	if (wpa_s->dpp_listen_freq) {
		/* Continue listen with a new remain-on-channel */
		wpas_dpp_listen_start(wpa_s, wpa_s->dpp_listen_freq);
	}
}


static void wpas_dpp_rx_auth_req(struct wpa_supplicant *wpa_s, const u8 *src,
				 const u8 *buf, size_t len, unsigned int freq)
{
	const u8 *r_bootstrap, *i_bootstrap, *wrapped_data;
	u16 r_bootstrap_len, i_bootstrap_len, wrapped_data_len;
	struct dpp_bootstrap_info *bi, *own_bi = NULL, *peer_bi = NULL;
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "DPP: Authentication Request from " MACSTR,
		   MAC2STR(src));

	wrapped_data = dpp_get_attr(buf, len, DPP_ATTR_WRAPPED_DATA,
				    &wrapped_data_len);
	if (!wrapped_data) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing required Wrapped data attribute");
		return;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Wrapped data",
		    wrapped_data, wrapped_data_len);

	r_bootstrap = dpp_get_attr(buf, len, DPP_ATTR_R_BOOTSTRAP_KEY_HASH,
				   &r_bootstrap_len);
	if (!r_bootstrap || r_bootstrap > wrapped_data ||
	    r_bootstrap_len != SHA256_MAC_LEN) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required Responder Bootstrapping Key Hash attribute");
		return;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Responder Bootstrapping Key Hash",
		    r_bootstrap, r_bootstrap_len);

	i_bootstrap = dpp_get_attr(buf, len, DPP_ATTR_I_BOOTSTRAP_KEY_HASH,
				   &i_bootstrap_len);
	if (!i_bootstrap || i_bootstrap > wrapped_data ||
	    i_bootstrap_len != SHA256_MAC_LEN) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid required Initiator Bootstrapping Key Hash attribute");
		return;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Initiator Bootstrapping Key Hash",
		    i_bootstrap, i_bootstrap_len);

	/* Try to find own and peer bootstrapping key matches based on the
	 * received hash values */
	dl_list_for_each(bi, &wpa_s->dpp_bootstrap, struct dpp_bootstrap_info,
			 list) {
		if (!own_bi && bi->own &&
		    os_memcmp(bi->pubkey_hash, r_bootstrap,
			      SHA256_MAC_LEN) == 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Found matching own bootstrapping information");
			own_bi = bi;
		}

		if (!peer_bi && !bi->own &&
		    os_memcmp(bi->pubkey_hash, i_bootstrap,
			      SHA256_MAC_LEN) == 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Found matching peer bootstrapping information");
			peer_bi = bi;
		}

		if (own_bi && peer_bi)
			break;
	}

	if (!own_bi) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No matching own bootstrapping key found - ignore message");
		return;
	}

	if (wpa_s->dpp_auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Already in DPP authentication exchange - ignore new one");
		return;
	}

	wpa_s->dpp_auth = dpp_auth_req_rx(wpa_s, wpa_s->dpp_allowed_roles,
					  wpa_s->dpp_qr_mutual,
					  peer_bi, own_bi, freq, buf,
					  wrapped_data, wrapped_data_len);
	if (!wpa_s->dpp_auth) {
		wpa_printf(MSG_DEBUG, "DPP: No response generated");
		return;
	}
	os_memcpy(wpa_s->dpp_auth->peer_mac_addr, src, ETH_ALEN);

	msg = dpp_alloc_msg(DPP_PA_AUTHENTICATION_RESP,
			    wpabuf_len(wpa_s->dpp_auth->resp_attr));
	if (!msg)
		return;
	wpabuf_put_buf(msg, wpa_s->dpp_auth->resp_attr);

	offchannel_send_action(wpa_s, wpa_s->dpp_auth->curr_freq,
			       src, wpa_s->own_addr, broadcast,
			       wpabuf_head(msg), wpabuf_len(msg),
			       500, wpas_dpp_tx_status, 0);
	wpabuf_free(msg);
}


static void wpas_dpp_rx_auth_resp(struct wpa_supplicant *wpa_s, const u8 *src,
				  const u8 *buf, size_t len)
{
	struct dpp_authentication *auth = wpa_s->dpp_auth;
	struct wpabuf *msg, *attr;

	wpa_printf(MSG_DEBUG, "DPP: Authentication Response from " MACSTR,
		   MAC2STR(src));

	if (!auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No DPP Authentication in progress - drop");
		return;
	}

	if (!is_zero_ether_addr(auth->peer_mac_addr) &&
	    os_memcmp(src, auth->peer_mac_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: MAC address mismatch (expected "
			   MACSTR ") - drop", MAC2STR(auth->peer_mac_addr));
		return;
	}

	eloop_cancel_timeout(wpas_dpp_reply_wait_timeout, wpa_s, NULL);

	attr = dpp_auth_resp_rx(auth, buf, len);
	if (!attr) {
		if (auth->auth_resp_status == DPP_STATUS_RESPONSE_PENDING) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Start wait for full response");
			offchannel_send_action_done(wpa_s);
			wpas_dpp_listen_start(wpa_s, auth->curr_freq);
			return;
		}
		wpa_printf(MSG_DEBUG, "DPP: No confirm generated");
		return;
	}
	os_memcpy(auth->peer_mac_addr, src, ETH_ALEN);

	msg = dpp_alloc_msg(DPP_PA_AUTHENTICATION_CONF, wpabuf_len(attr));
	if (!msg) {
		wpabuf_free(attr);
		return;
	}
	wpabuf_put_buf(msg, attr);
	wpabuf_free(attr);

	offchannel_send_action(wpa_s, auth->curr_freq,
			       src, wpa_s->own_addr, broadcast,
			       wpabuf_head(msg), wpabuf_len(msg),
			       500, wpas_dpp_tx_status, 0);
	wpabuf_free(msg);

	wpa_printf(MSG_DEBUG, "DPP: Authentication succeeded");
	wpa_msg(wpa_s, MSG_INFO, DPP_EVENT_AUTH_SUCCESS "init=1");
}


static void wpas_dpp_rx_auth_conf(struct wpa_supplicant *wpa_s, const u8 *src,
				  const u8 *buf, size_t len)
{
	struct dpp_authentication *auth = wpa_s->dpp_auth;

	wpa_printf(MSG_DEBUG, "DPP: Authentication Confirmation from " MACSTR,
		   MAC2STR(src));

	if (!auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No DPP Authentication in progress - drop");
		return;
	}

	if (os_memcmp(src, auth->peer_mac_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: MAC address mismatch (expected "
			   MACSTR ") - drop", MAC2STR(auth->peer_mac_addr));
		return;
	}

	if (dpp_auth_conf_rx(auth, buf, len) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Authentication failed");
		return;
	}

	wpa_printf(MSG_DEBUG, "DPP: Authentication succeeded");
	wpa_msg(wpa_s, MSG_INFO, DPP_EVENT_AUTH_SUCCESS "init=0");
}


void wpas_dpp_rx_action(struct wpa_supplicant *wpa_s, const u8 *src,
			const u8 *buf, size_t len, unsigned int freq)
{
	enum dpp_public_action_frame_type type;

	if (len < 1)
		return;
	type = buf[0];
	buf++;
	len--;

	wpa_printf(MSG_DEBUG,
		   "DPP: Received DPP Public Action frame type %d from "
		   MACSTR " freq=%u",
		   type, MAC2STR(src), freq);
	wpa_hexdump(MSG_MSGDUMP, "DPP: Received message attributes", buf, len);
	if (dpp_check_attrs(buf, len) < 0)
		return;

	switch (type) {
	case DPP_PA_AUTHENTICATION_REQ:
		wpas_dpp_rx_auth_req(wpa_s, src, buf, len, freq);
		break;
	case DPP_PA_AUTHENTICATION_RESP:
		wpas_dpp_rx_auth_resp(wpa_s, src, buf, len);
		break;
	case DPP_PA_AUTHENTICATION_CONF:
		wpas_dpp_rx_auth_conf(wpa_s, src, buf, len);
		break;
	default:
		wpa_printf(MSG_DEBUG,
			   "DPP: Ignored unsupported frame subtype %d", type);
		break;
	}
}


int wpas_dpp_init(struct wpa_supplicant *wpa_s)
{
	dl_list_init(&wpa_s->dpp_bootstrap);
	wpa_s->dpp_init_done = 1;
	return 0;
}


void wpas_dpp_deinit(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s->dpp_init_done)
		return;
	eloop_cancel_timeout(wpas_dpp_reply_wait_timeout, wpa_s, NULL);
	offchannel_send_action_done(wpa_s);
	wpas_dpp_listen_stop(wpa_s);
	dpp_bootstrap_del(wpa_s, 0);
	dpp_auth_deinit(wpa_s->dpp_auth);
	wpa_s->dpp_auth = NULL;
}
