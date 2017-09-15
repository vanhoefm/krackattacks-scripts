/*
 * hostapd / DPP integration
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/dpp.h"
#include "common/gas.h"
#include "common/wpa_ctrl.h"
#include "hostapd.h"
#include "ap_drv_ops.h"
#include "gas_query_ap.h"
#include "wpa_auth.h"
#include "dpp_hostapd.h"


static void hostapd_dpp_auth_success(struct hostapd_data *hapd, int initiator);

static const u8 broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


static struct dpp_configurator *
hostapd_dpp_configurator_get_id(struct hostapd_data *hapd, unsigned int id)
{
	struct dpp_configurator *conf;

	dl_list_for_each(conf, &hapd->dpp_configurator,
			 struct dpp_configurator, list) {
		if (conf->id == id)
			return conf;
	}
	return NULL;
}


static unsigned int hapd_dpp_next_id(struct hostapd_data *hapd)
{
	struct dpp_bootstrap_info *bi;
	unsigned int max_id = 0;

	dl_list_for_each(bi, &hapd->dpp_bootstrap, struct dpp_bootstrap_info,
			 list) {
		if (bi->id > max_id)
			max_id = bi->id;
	}
	return max_id + 1;
}


/**
 * hostapd_dpp_qr_code - Parse and add DPP bootstrapping info from a QR Code
 * @hapd: Pointer to hostapd_data
 * @cmd: DPP URI read from a QR Code
 * Returns: Identifier of the stored info or -1 on failure
 */
int hostapd_dpp_qr_code(struct hostapd_data *hapd, const char *cmd)
{
	struct dpp_bootstrap_info *bi;
	struct dpp_authentication *auth = hapd->dpp_auth;

	bi = dpp_parse_qr_code(cmd);
	if (!bi)
		return -1;

	bi->id = hapd_dpp_next_id(hapd);
	dl_list_add(&hapd->dpp_bootstrap, &bi->list);

	if (auth && auth->response_pending &&
	    dpp_notify_new_qr_code(auth, bi) == 1) {
		struct wpabuf *msg;

		wpa_printf(MSG_DEBUG,
			   "DPP: Sending out pending authentication response");
		msg = dpp_alloc_msg(DPP_PA_AUTHENTICATION_RESP,
				    wpabuf_len(auth->resp_attr));
		if (!msg)
			goto out;
		wpabuf_put_buf(msg, hapd->dpp_auth->resp_attr);

		hostapd_drv_send_action(hapd, auth->curr_freq, 0,
					auth->peer_mac_addr,
					wpabuf_head(msg), wpabuf_len(msg));
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


int hostapd_dpp_bootstrap_gen(struct hostapd_data *hapd, const char *cmd)
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
	else if (os_strstr(cmd, "type=pkex"))
		bi->type = DPP_BOOTSTRAP_PKEX;
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
	bi->id = hapd_dpp_next_id(hapd);
	dl_list_add(&hapd->dpp_bootstrap, &bi->list);
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
dpp_bootstrap_get_id(struct hostapd_data *hapd, unsigned int id)
{
	struct dpp_bootstrap_info *bi;

	dl_list_for_each(bi, &hapd->dpp_bootstrap, struct dpp_bootstrap_info,
			 list) {
		if (bi->id == id)
			return bi;
	}
	return NULL;
}


static int dpp_bootstrap_del(struct hostapd_data *hapd, unsigned int id)
{
	struct dpp_bootstrap_info *bi, *tmp;
	int found = 0;

	dl_list_for_each_safe(bi, tmp, &hapd->dpp_bootstrap,
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


int hostapd_dpp_bootstrap_remove(struct hostapd_data *hapd, const char *id)
{
	unsigned int id_val;

	if (os_strcmp(id, "*") == 0) {
		id_val = 0;
	} else {
		id_val = atoi(id);
		if (id_val == 0)
			return -1;
	}

	return dpp_bootstrap_del(hapd, id_val);
}


const char * hostapd_dpp_bootstrap_get_uri(struct hostapd_data *hapd,
					   unsigned int id)
{
	struct dpp_bootstrap_info *bi;

	bi = dpp_bootstrap_get_id(hapd, id);
	if (!bi)
		return NULL;
	return bi->uri;
}


int hostapd_dpp_bootstrap_info(struct hostapd_data *hapd, int id,
			       char *reply, int reply_size)
{
	struct dpp_bootstrap_info *bi;

	bi = dpp_bootstrap_get_id(hapd, id);
	if (!bi)
		return -1;
	return os_snprintf(reply, reply_size, "type=%s\n"
			   "mac_addr=" MACSTR "\n"
			   "info=%s\n"
			   "num_freq=%u\n"
			   "curve=%s\n",
			   dpp_bootstrap_type_txt(bi->type),
			   MAC2STR(bi->mac_addr),
			   bi->info ? bi->info : "",
			   bi->num_freq,
			   bi->curve->name);
}


void hostapd_dpp_tx_status(struct hostapd_data *hapd, const u8 *dst,
			   const u8 *data, size_t data_len, int ok)
{
	wpa_printf(MSG_DEBUG, "DPP: TX status: dst=" MACSTR " ok=%d",
		   MAC2STR(dst), ok);

	if (!hapd->dpp_auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Ignore TX status since there is no ongoing authentication exchange");
		return;
	}

	if (hapd->dpp_auth->remove_on_tx_status) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Terminate authentication exchange due to an earlier error");
		dpp_auth_deinit(hapd->dpp_auth);
		hapd->dpp_auth = NULL;
		return;
	}

	if (hapd->dpp_auth_ok_on_ack)
		hostapd_dpp_auth_success(hapd, 1);
}


static void hostapd_dpp_set_testing_options(struct hostapd_data *hapd,
					    struct dpp_authentication *auth)
{
#ifdef CONFIG_TESTING_OPTIONS
	if (hapd->dpp_config_obj_override)
		auth->config_obj_override =
			os_strdup(hapd->dpp_config_obj_override);
	if (hapd->dpp_discovery_override)
		auth->discovery_override =
			os_strdup(hapd->dpp_discovery_override);
	if (hapd->dpp_groups_override)
		auth->groups_override = os_strdup(hapd->dpp_groups_override);
	auth->ignore_netaccesskey_mismatch =
		hapd->dpp_ignore_netaccesskey_mismatch;
#endif /* CONFIG_TESTING_OPTIONS */
}


static void hostapd_dpp_set_configurator(struct hostapd_data *hapd,
					 struct dpp_authentication *auth,
					 const char *cmd)
{
	const char *pos, *end;
	struct dpp_configuration *conf_sta = NULL, *conf_ap = NULL;
	struct dpp_configurator *conf = NULL;
	u8 ssid[32] = { "test" };
	size_t ssid_len = 4;
	char pass[64] = { };
	size_t pass_len = 0;
	u8 psk[PMK_LEN];
	int psk_set = 0;

	if (!cmd)
		return;

	wpa_printf(MSG_DEBUG, "DPP: Set configurator parameters: %s", cmd);
	pos = os_strstr(cmd, " ssid=");
	if (pos) {
		pos += 6;
		end = os_strchr(pos, ' ');
		ssid_len = end ? (size_t) (end - pos) : os_strlen(pos);
		ssid_len /= 2;
		if (ssid_len > sizeof(ssid) ||
		    hexstr2bin(pos, ssid, ssid_len) < 0)
			goto fail;
	}

	pos = os_strstr(cmd, " pass=");
	if (pos) {
		pos += 6;
		end = os_strchr(pos, ' ');
		pass_len = end ? (size_t) (end - pos) : os_strlen(pos);
		pass_len /= 2;
		if (pass_len > sizeof(pass) - 1 || pass_len < 8 ||
		    hexstr2bin(pos, (u8 *) pass, pass_len) < 0)
			goto fail;
	}

	pos = os_strstr(cmd, " psk=");
	if (pos) {
		pos += 5;
		if (hexstr2bin(pos, psk, PMK_LEN) < 0)
			goto fail;
		psk_set = 1;
	}

	if (os_strstr(cmd, " conf=sta-")) {
		conf_sta = os_zalloc(sizeof(struct dpp_configuration));
		if (!conf_sta)
			goto fail;
		os_memcpy(conf_sta->ssid, ssid, ssid_len);
		conf_sta->ssid_len = ssid_len;
		if (os_strstr(cmd, " conf=sta-psk")) {
			conf_sta->dpp = 0;
			if (psk_set) {
				os_memcpy(conf_sta->psk, psk, PMK_LEN);
			} else {
				conf_sta->passphrase = os_strdup(pass);
				if (!conf_sta->passphrase)
					goto fail;
			}
		} else if (os_strstr(cmd, " conf=sta-dpp")) {
			conf_sta->dpp = 1;
		} else {
			goto fail;
		}
	}

	if (os_strstr(cmd, " conf=ap-")) {
		conf_ap = os_zalloc(sizeof(struct dpp_configuration));
		if (!conf_ap)
			goto fail;
		os_memcpy(conf_ap->ssid, ssid, ssid_len);
		conf_ap->ssid_len = ssid_len;
		if (os_strstr(cmd, " conf=ap-psk")) {
			conf_ap->dpp = 0;
			if (psk_set) {
				os_memcpy(conf_ap->psk, psk, PMK_LEN);
			} else {
				conf_ap->passphrase = os_strdup(pass);
				if (!conf_ap->passphrase)
					goto fail;
			}
		} else if (os_strstr(cmd, " conf=ap-dpp")) {
			conf_ap->dpp = 1;
		} else {
			goto fail;
		}
	}

	pos = os_strstr(cmd, " expiry=");
	if (pos) {
		long int val;

		pos += 8;
		val = strtol(pos, NULL, 0);
		if (val <= 0)
			goto fail;
		if (conf_sta)
			conf_sta->netaccesskey_expiry = val;
		if (conf_ap)
			conf_ap->netaccesskey_expiry = val;
	}

	pos = os_strstr(cmd, " configurator=");
	if (pos) {
		auth->configurator = 1;
		pos += 14;
		conf = hostapd_dpp_configurator_get_id(hapd, atoi(pos));
		if (!conf) {
			wpa_printf(MSG_INFO,
				   "DPP: Could not find the specified configurator");
			goto fail;
		}
	}
	auth->conf_sta = conf_sta;
	auth->conf_ap = conf_ap;
	auth->conf = conf;
	return;

fail:
	wpa_printf(MSG_DEBUG, "DPP: Failed to set configurator parameters");
	dpp_configuration_free(conf_sta);
	dpp_configuration_free(conf_ap);
}


int hostapd_dpp_auth_init(struct hostapd_data *hapd, const char *cmd)
{
	const char *pos;
	struct dpp_bootstrap_info *peer_bi, *own_bi = NULL;
	struct wpabuf *msg;
	const u8 *dst;
	int res;
	int configurator = 1;
	struct dpp_configuration *conf_sta = NULL, *conf_ap = NULL;

	pos = os_strstr(cmd, " peer=");
	if (!pos)
		return -1;
	pos += 6;
	peer_bi = dpp_bootstrap_get_id(hapd, atoi(pos));
	if (!peer_bi) {
		wpa_printf(MSG_INFO,
			   "DPP: Could not find bootstrapping info for the identified peer");
		return -1;
	}

	pos = os_strstr(cmd, " own=");
	if (pos) {
		pos += 5;
		own_bi = dpp_bootstrap_get_id(hapd, atoi(pos));
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
			goto fail;
	}

	if (hapd->dpp_auth)
		dpp_auth_deinit(hapd->dpp_auth);
	hapd->dpp_auth = dpp_auth_init(hapd, peer_bi, own_bi, configurator);
	if (!hapd->dpp_auth)
		goto fail;
	hostapd_dpp_set_testing_options(hapd, hapd->dpp_auth);
	hostapd_dpp_set_configurator(hapd, hapd->dpp_auth, cmd);

	/* TODO: Support iteration over all frequencies and filtering of
	 * frequencies based on locally enabled channels that allow initiation
	 * of transmission. */
	if (peer_bi->num_freq > 0)
		hapd->dpp_auth->curr_freq = peer_bi->freq[0];
	else
		hapd->dpp_auth->curr_freq = 2412;

	msg = dpp_alloc_msg(DPP_PA_AUTHENTICATION_REQ,
			    wpabuf_len(hapd->dpp_auth->req_attr));
	if (!msg)
		return -1;
	wpabuf_put_buf(msg, hapd->dpp_auth->req_attr);

	if (is_zero_ether_addr(peer_bi->mac_addr)) {
		dst = broadcast;
	} else {
		dst = peer_bi->mac_addr;
		os_memcpy(hapd->dpp_auth->peer_mac_addr, peer_bi->mac_addr,
			  ETH_ALEN);
	}
	hapd->dpp_auth_ok_on_ack = 0;

	res = hostapd_drv_send_action(hapd, hapd->dpp_auth->curr_freq, 0,
				      dst, wpabuf_head(msg), wpabuf_len(msg));
	wpabuf_free(msg);

	return res;
fail:
	dpp_configuration_free(conf_sta);
	dpp_configuration_free(conf_ap);
	return -1;
}


static void hostapd_dpp_rx_auth_req(struct hostapd_data *hapd, const u8 *src,
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
	dl_list_for_each(bi, &hapd->dpp_bootstrap, struct dpp_bootstrap_info,
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

	if (hapd->dpp_auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Already in DPP authentication exchange - ignore new one");
		return;
	}

	hapd->dpp_auth_ok_on_ack = 0;
	hapd->dpp_auth = dpp_auth_req_rx(hapd->msg_ctx, hapd->dpp_allowed_roles,
					 hapd->dpp_qr_mutual,
					 peer_bi, own_bi, freq, buf,
					 wrapped_data, wrapped_data_len);
	if (!hapd->dpp_auth) {
		wpa_printf(MSG_DEBUG, "DPP: No response generated");
		return;
	}
	hostapd_dpp_set_testing_options(hapd, hapd->dpp_auth);
	hostapd_dpp_set_configurator(hapd, hapd->dpp_auth,
				     hapd->dpp_configurator_params);
	os_memcpy(hapd->dpp_auth->peer_mac_addr, src, ETH_ALEN);

	msg = dpp_alloc_msg(DPP_PA_AUTHENTICATION_RESP,
			    wpabuf_len(hapd->dpp_auth->resp_attr));
	if (!msg)
		return;
	wpabuf_put_buf(msg, hapd->dpp_auth->resp_attr);

	hostapd_drv_send_action(hapd, hapd->dpp_auth->curr_freq, 0,
				src, wpabuf_head(msg), wpabuf_len(msg));
	wpabuf_free(msg);
}


static void hostapd_dpp_gas_resp_cb(void *ctx, const u8 *addr, u8 dialog_token,
				    enum gas_query_ap_result result,
				    const struct wpabuf *adv_proto,
				    const struct wpabuf *resp, u16 status_code)
{
	struct hostapd_data *hapd = ctx;
	const u8 *pos;
	struct dpp_authentication *auth = hapd->dpp_auth;

	if (!auth || !auth->auth_success) {
		wpa_printf(MSG_DEBUG, "DPP: No matching exchange in progress");
		return;
	}
	if (!resp || status_code != WLAN_STATUS_SUCCESS) {
		wpa_printf(MSG_DEBUG, "DPP: GAS query did not succeed");
		goto fail;
	}

	wpa_hexdump_buf(MSG_DEBUG, "DPP: Configuration Response adv_proto",
			adv_proto);
	wpa_hexdump_buf(MSG_DEBUG, "DPP: Configuration Response (GAS response)",
			resp);

	if (wpabuf_len(adv_proto) != 10 ||
	    !(pos = wpabuf_head(adv_proto)) ||
	    pos[0] != WLAN_EID_ADV_PROTO ||
	    pos[1] != 8 ||
	    pos[3] != WLAN_EID_VENDOR_SPECIFIC ||
	    pos[4] != 5 ||
	    WPA_GET_BE24(&pos[5]) != OUI_WFA ||
	    pos[8] != 0x1a ||
	    pos[9] != 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Not a DPP Advertisement Protocol ID");
		goto fail;
	}

	if (dpp_conf_resp_rx(auth, resp) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Configuration attempt failed");
		goto fail;
	}

	wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_CONF_RECEIVED);
	if (auth->ssid_len)
		wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_CONFOBJ_SSID "%s",
			wpa_ssid_txt(auth->ssid, auth->ssid_len));
	if (auth->connector) {
		/* TODO: Save the Connector and consider using a command
		 * to fetch the value instead of sending an event with
		 * it. The Connector could end up being larger than what
		 * most clients are ready to receive as an event
		 * message. */
		wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_CONNECTOR "%s",
			auth->connector);
	} else if (auth->passphrase[0]) {
		char hex[64 * 2 + 1];

		wpa_snprintf_hex(hex, sizeof(hex),
				 (const u8 *) auth->passphrase,
				 os_strlen(auth->passphrase));
		wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_CONFOBJ_PASS "%s",
			hex);
	} else if (auth->psk_set) {
		char hex[PMK_LEN * 2 + 1];

		wpa_snprintf_hex(hex, sizeof(hex), auth->psk, PMK_LEN);
		wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_CONFOBJ_PSK "%s",
			hex);
	}
	if (auth->c_sign_key) {
		char *hex;
		size_t hexlen;

		hexlen = 2 * wpabuf_len(auth->c_sign_key) + 1;
		hex = os_malloc(hexlen);
		if (hex) {
			wpa_snprintf_hex(hex, hexlen,
					 wpabuf_head(auth->c_sign_key),
					 wpabuf_len(auth->c_sign_key));
			if (auth->c_sign_key_expiry)
				wpa_msg(hapd->msg_ctx, MSG_INFO,
					DPP_EVENT_C_SIGN_KEY "%s %lu", hex,
					(unsigned long)
					auth->c_sign_key_expiry);
			else
				wpa_msg(hapd->msg_ctx, MSG_INFO,
					DPP_EVENT_C_SIGN_KEY "%s", hex);
			os_free(hex);
		}
	}
	if (auth->net_access_key) {
		char *hex;
		size_t hexlen;

		hexlen = 2 * wpabuf_len(auth->net_access_key) + 1;
		hex = os_malloc(hexlen);
		if (hex) {
			wpa_snprintf_hex(hex, hexlen,
					 wpabuf_head(auth->net_access_key),
					 wpabuf_len(auth->net_access_key));
			if (auth->net_access_key_expiry)
				wpa_msg(hapd->msg_ctx, MSG_INFO,
					DPP_EVENT_NET_ACCESS_KEY "%s %lu", hex,
					(unsigned long)
					auth->net_access_key_expiry);
			else
				wpa_msg(hapd->msg_ctx, MSG_INFO,
					DPP_EVENT_NET_ACCESS_KEY "%s", hex);
			os_free(hex);
		}
	}
	dpp_auth_deinit(hapd->dpp_auth);
	hapd->dpp_auth = NULL;
	return;

fail:
	wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_CONF_FAILED);
	dpp_auth_deinit(hapd->dpp_auth);
	hapd->dpp_auth = NULL;
}


static void hostapd_dpp_start_gas_client(struct hostapd_data *hapd)
{
	struct dpp_authentication *auth = hapd->dpp_auth;
	struct wpabuf *buf, *conf_req;
	char json[100];
	int res;
	int netrole_ap = 1;

	os_snprintf(json, sizeof(json),
		    "{\"name\":\"Test\","
		    "\"wi-fi_tech\":\"infra\","
		    "\"netRole\":\"%s\"}",
		    netrole_ap ? "ap" : "sta");
	wpa_printf(MSG_DEBUG, "DPP: GAS Config Attributes: %s", json);

	conf_req = dpp_build_conf_req(auth, json);
	if (!conf_req) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No configuration request data available");
		return;
	}

	buf = gas_build_initial_req(0, 10 + 2 + wpabuf_len(conf_req));
	if (!buf) {
		wpabuf_free(conf_req);
		return;
	}

	/* Advertisement Protocol IE */
	wpabuf_put_u8(buf, WLAN_EID_ADV_PROTO);
	wpabuf_put_u8(buf, 8); /* Length */
	wpabuf_put_u8(buf, 0x7f);
	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(buf, 5);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, DPP_OUI_TYPE);
	wpabuf_put_u8(buf, 0x01);

	/* GAS Query */
	wpabuf_put_le16(buf, wpabuf_len(conf_req));
	wpabuf_put_buf(buf, conf_req);
	wpabuf_free(conf_req);

	wpa_printf(MSG_DEBUG, "DPP: GAS request to " MACSTR " (freq %u MHz)",
		   MAC2STR(auth->peer_mac_addr), auth->curr_freq);

	res = gas_query_ap_req(hapd->gas, auth->peer_mac_addr, auth->curr_freq,
			       buf, hostapd_dpp_gas_resp_cb, hapd);
	if (res < 0) {
		wpa_msg(hapd->msg_ctx, MSG_DEBUG,
			"GAS: Failed to send Query Request");
		wpabuf_free(buf);
	} else {
		wpa_printf(MSG_DEBUG,
			   "DPP: GAS query started with dialog token %u", res);
	}
}


static void hostapd_dpp_auth_success(struct hostapd_data *hapd, int initiator)
{
	wpa_printf(MSG_DEBUG, "DPP: Authentication succeeded");
	wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_AUTH_SUCCESS "init=%d",
		initiator);

	if (!hapd->dpp_auth->configurator)
		hostapd_dpp_start_gas_client(hapd);
}


static void hostapd_dpp_rx_auth_resp(struct hostapd_data *hapd, const u8 *src,
				  const u8 *buf, size_t len)
{
	struct dpp_authentication *auth = hapd->dpp_auth;
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

	attr = dpp_auth_resp_rx(auth, buf, len);
	if (!attr) {
		if (auth->auth_resp_status == DPP_STATUS_RESPONSE_PENDING) {
			wpa_printf(MSG_DEBUG, "DPP: Wait for full response");
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

	hostapd_drv_send_action(hapd, auth->curr_freq, 0, src,
				wpabuf_head(msg), wpabuf_len(msg));
	wpabuf_free(msg);
	hapd->dpp_auth_ok_on_ack = 1;
}


static void hostapd_dpp_rx_auth_conf(struct hostapd_data *hapd, const u8 *src,
				     const u8 *buf, size_t len)
{
	struct dpp_authentication *auth = hapd->dpp_auth;

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

	hostapd_dpp_auth_success(hapd, 0);
}


static void hostapd_dpp_rx_peer_disc_req(struct hostapd_data *hapd,
					 const u8 *src,
					 const u8 *buf, size_t len,
					 unsigned int freq)
{
	const u8 *connector, *trans_id;
	u16 connector_len, trans_id_len;
	struct os_time now;
	struct dpp_introduction intro;
	os_time_t expire;
	int expiration;
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "DPP: Peer Discovery Request from " MACSTR,
		   MAC2STR(src));
	if (!hapd->wpa_auth ||
	    !(hapd->conf->wpa_key_mgmt & WPA_KEY_MGMT_DPP) ||
	    !(hapd->conf->wpa & WPA_PROTO_RSN)) {
		wpa_printf(MSG_DEBUG, "DPP: DPP AKM not in use");
		return;
	}

	if (!hapd->conf->dpp_connector || !hapd->conf->dpp_netaccesskey ||
	    !hapd->conf->dpp_csign) {
		wpa_printf(MSG_DEBUG, "DPP: No own Connector/keys set");
		return;
	}

	os_get_time(&now);
	if (hapd->conf->dpp_csign_expiry &&
	    hapd->conf->dpp_csign_expiry < now.sec) {
		wpa_printf(MSG_DEBUG, "DPP: C-sign-key expired");
		return;
	}

	if (hapd->conf->dpp_netaccesskey_expiry &&
	    hapd->conf->dpp_netaccesskey_expiry < now.sec) {
		wpa_printf(MSG_INFO, "DPP: Own netAccessKey expired");
		return;
	}

	trans_id = dpp_get_attr(buf, len, DPP_ATTR_TRANSACTION_ID,
			       &trans_id_len);
	if (!trans_id || trans_id_len != 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Peer did not include Transaction ID");
		return;
	}

	connector = dpp_get_attr(buf, len, DPP_ATTR_CONNECTOR, &connector_len);
	if (!connector) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Peer did not include its Connector");
		return;
	}

	if (dpp_peer_intro(&intro, hapd->conf->dpp_connector,
			   wpabuf_head(hapd->conf->dpp_netaccesskey),
			   wpabuf_len(hapd->conf->dpp_netaccesskey),
			   wpabuf_head(hapd->conf->dpp_csign),
			   wpabuf_len(hapd->conf->dpp_csign),
			   connector, connector_len, &expire) < 0) {
		wpa_printf(MSG_INFO,
			   "DPP: Network Introduction protocol resulted in failure");
		return;
	}

	if (!expire || hapd->conf->dpp_netaccesskey_expiry < expire)
		expire = hapd->conf->dpp_netaccesskey_expiry;
	if (!expire || hapd->conf->dpp_csign_expiry < expire)
		expire = hapd->conf->dpp_csign_expiry;
	if (expire)
		expiration = expire - now.sec;
	else
		expiration = 0;

	if (wpa_auth_pmksa_add2(hapd->wpa_auth, src, intro.pmk, intro.pmk_len,
				intro.pmkid, expiration,
				WPA_KEY_MGMT_DPP) < 0) {
		wpa_printf(MSG_ERROR, "DPP: Failed to add PMKSA cache entry");
		return;
	}

	msg = dpp_alloc_msg(DPP_PA_PEER_DISCOVERY_RESP,
			    5 + 4 + os_strlen(hapd->conf->dpp_connector));
	if (!msg)
		return;

	/* Transaction ID */
	wpabuf_put_le16(msg, DPP_ATTR_TRANSACTION_ID);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, trans_id[0]);

	/* DPP Connector */
	wpabuf_put_le16(msg, DPP_ATTR_CONNECTOR);
	wpabuf_put_le16(msg, os_strlen(hapd->conf->dpp_connector));
	wpabuf_put_str(msg, hapd->conf->dpp_connector);

	wpa_printf(MSG_DEBUG, "DPP: Send Peer Discovery Response to " MACSTR,
		   MAC2STR(src));
	hostapd_drv_send_action(hapd, freq, 0, src,
				wpabuf_head(msg), wpabuf_len(msg));
	wpabuf_free(msg);
}


static void
hostapd_dpp_rx_pkex_exchange_req(struct hostapd_data *hapd, const u8 *src,
				 const u8 *buf, size_t len, unsigned int freq)
{
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "DPP: PKEX Exchange Request from " MACSTR,
		   MAC2STR(src));

	/* TODO: Support multiple PKEX codes by iterating over all the enabled
	 * values here */

	if (!hapd->dpp_pkex_code || !hapd->dpp_pkex_bi) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No PKEX code configured - ignore request");
		return;
	}

	if (hapd->dpp_pkex) {
		/* TODO: Support parallel operations */
		wpa_printf(MSG_DEBUG,
			   "DPP: Already in PKEX session - ignore new request");
		return;
	}

	hapd->dpp_pkex = dpp_pkex_rx_exchange_req(hapd->dpp_pkex_bi,
						  hapd->own_addr, src,
						  hapd->dpp_pkex_identifier,
						  hapd->dpp_pkex_code,
						  buf, len);
	if (!hapd->dpp_pkex) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to process the request - ignore it");
		return;
	}

	msg = hapd->dpp_pkex->exchange_resp;
	hostapd_drv_send_action(hapd, freq, 0, src,
				wpabuf_head(msg), wpabuf_len(msg));
}


static void
hostapd_dpp_rx_pkex_exchange_resp(struct hostapd_data *hapd, const u8 *src,
				  const u8 *buf, size_t len, unsigned int freq)
{
	struct wpabuf *msg;

	wpa_printf(MSG_DEBUG, "DPP: PKEX Exchange Response from " MACSTR,
		   MAC2STR(src));

	/* TODO: Support multiple PKEX codes by iterating over all the enabled
	 * values here */

	if (!hapd->dpp_pkex || !hapd->dpp_pkex->initiator ||
	    hapd->dpp_pkex->exchange_done) {
		wpa_printf(MSG_DEBUG, "DPP: No matching PKEX session");
		return;
	}

	os_memcpy(hapd->dpp_pkex->peer_mac, src, ETH_ALEN);
	msg = dpp_pkex_rx_exchange_resp(hapd->dpp_pkex, buf, len);
	if (!msg) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to process the response");
		return;
	}

	wpa_printf(MSG_DEBUG, "DPP: Send PKEX Commit-Reveal Request to " MACSTR,
		   MAC2STR(src));

	hostapd_drv_send_action(hapd, freq, 0, src,
				wpabuf_head(msg), wpabuf_len(msg));
	wpabuf_free(msg);
}


static void
hostapd_dpp_rx_pkex_commit_reveal_req(struct hostapd_data *hapd, const u8 *src,
				      const u8 *buf, size_t len,
				      unsigned int freq)
{
	struct wpabuf *msg;
	struct dpp_pkex *pkex = hapd->dpp_pkex;
	struct dpp_bootstrap_info *bi;

	wpa_printf(MSG_DEBUG, "DPP: PKEX Commit-Reveal Request from " MACSTR,
		   MAC2STR(src));

	if (!pkex || pkex->initiator || !pkex->exchange_done) {
		wpa_printf(MSG_DEBUG, "DPP: No matching PKEX session");
		return;
	}

	msg = dpp_pkex_rx_commit_reveal_req(pkex, buf, len);
	if (!msg) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to process the request");
		return;
	}

	wpa_printf(MSG_DEBUG, "DPP: Send PKEX Commit-Reveal Response to "
		   MACSTR, MAC2STR(src));

	hostapd_drv_send_action(hapd, freq, 0, src,
				wpabuf_head(msg), wpabuf_len(msg));
	wpabuf_free(msg);

	bi = os_zalloc(sizeof(*bi));
	if (!bi)
		return;
	bi->id = hapd_dpp_next_id(hapd);
	bi->type = DPP_BOOTSTRAP_PKEX;
	os_memcpy(bi->mac_addr, src, ETH_ALEN);
	bi->num_freq = 1;
	bi->freq[0] = freq;
	bi->curve = pkex->own_bi->curve;
	bi->pubkey = pkex->peer_bootstrap_key;
	pkex->peer_bootstrap_key = NULL;
	dpp_pkex_free(pkex);
	hapd->dpp_pkex = NULL;
	if (dpp_bootstrap_key_hash(bi) < 0) {
		dpp_bootstrap_info_free(bi);
		return;
	}
	dl_list_add(&hapd->dpp_bootstrap, &bi->list);
}


static void
hostapd_dpp_rx_pkex_commit_reveal_resp(struct hostapd_data *hapd, const u8 *src,
				       const u8 *buf, size_t len,
				       unsigned int freq)
{
	int res;
	struct dpp_bootstrap_info *bi, *own_bi;
	struct dpp_pkex *pkex = hapd->dpp_pkex;
	char cmd[500];

	wpa_printf(MSG_DEBUG, "DPP: PKEX Commit-Reveal Response from " MACSTR,
		   MAC2STR(src));

	if (!pkex || !pkex->initiator || !pkex->exchange_done) {
		wpa_printf(MSG_DEBUG, "DPP: No matching PKEX session");
		return;
	}

	res = dpp_pkex_rx_commit_reveal_resp(pkex, buf, len);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to process the response");
		return;
	}

	own_bi = pkex->own_bi;

	bi = os_zalloc(sizeof(*bi));
	if (!bi)
		return;
	bi->id = hapd_dpp_next_id(hapd);
	bi->type = DPP_BOOTSTRAP_PKEX;
	os_memcpy(bi->mac_addr, src, ETH_ALEN);
	bi->num_freq = 1;
	bi->freq[0] = freq;
	bi->curve = own_bi->curve;
	bi->pubkey = pkex->peer_bootstrap_key;
	pkex->peer_bootstrap_key = NULL;
	dpp_pkex_free(pkex);
	hapd->dpp_pkex = NULL;
	if (dpp_bootstrap_key_hash(bi) < 0) {
		dpp_bootstrap_info_free(bi);
		return;
	}
	dl_list_add(&hapd->dpp_bootstrap, &bi->list);

	os_snprintf(cmd, sizeof(cmd), " peer=%u %s",
		    bi->id,
		    hapd->dpp_pkex_auth_cmd ? hapd->dpp_pkex_auth_cmd : "");
	wpa_printf(MSG_DEBUG,
		   "DPP: Start authentication after PKEX with parameters: %s",
		   cmd);
	if (hostapd_dpp_auth_init(hapd, cmd) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Authentication initialization failed");
		return;
	}
}


void hostapd_dpp_rx_action(struct hostapd_data *hapd, const u8 *src,
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
		hostapd_dpp_rx_auth_req(hapd, src, buf, len, freq);
		break;
	case DPP_PA_AUTHENTICATION_RESP:
		hostapd_dpp_rx_auth_resp(hapd, src, buf, len);
		break;
	case DPP_PA_AUTHENTICATION_CONF:
		hostapd_dpp_rx_auth_conf(hapd, src, buf, len);
		break;
	case DPP_PA_PEER_DISCOVERY_REQ:
		hostapd_dpp_rx_peer_disc_req(hapd, src, buf, len, freq);
		break;
	case DPP_PA_PKEX_EXCHANGE_REQ:
		hostapd_dpp_rx_pkex_exchange_req(hapd, src, buf, len, freq);
		break;
	case DPP_PA_PKEX_EXCHANGE_RESP:
		hostapd_dpp_rx_pkex_exchange_resp(hapd, src, buf, len, freq);
		break;
	case DPP_PA_PKEX_COMMIT_REVEAL_REQ:
		hostapd_dpp_rx_pkex_commit_reveal_req(hapd, src, buf, len, freq);
		break;
	case DPP_PA_PKEX_COMMIT_REVEAL_RESP:
		hostapd_dpp_rx_pkex_commit_reveal_resp(hapd, src, buf, len,
						       freq);
		break;
	default:
		wpa_printf(MSG_DEBUG,
			   "DPP: Ignored unsupported frame subtype %d", type);
		break;
	}
}


struct wpabuf *
hostapd_dpp_gas_req_handler(struct hostapd_data *hapd, const u8 *sa,
			    const u8 *query, size_t query_len)
{
	struct dpp_authentication *auth = hapd->dpp_auth;
	struct wpabuf *resp;

	wpa_printf(MSG_DEBUG, "DPP: GAS request from " MACSTR, MAC2STR(sa));
	if (!auth || !auth->auth_success ||
	    os_memcmp(sa, auth->peer_mac_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: No matching exchange in progress");
		return NULL;
	}
	wpa_hexdump(MSG_DEBUG,
		    "DPP: Received Configuration Request (GAS Query Request)",
		    query, query_len);
	resp = dpp_conf_req_rx(auth, query, query_len);
	if (!resp)
		wpa_msg(hapd->msg_ctx, MSG_INFO, DPP_EVENT_CONF_FAILED);
	return resp;
}


static unsigned int hostapd_dpp_next_configurator_id(struct hostapd_data *hapd)
{
	struct dpp_configurator *conf;
	unsigned int max_id = 0;

	dl_list_for_each(conf, &hapd->dpp_configurator,
			 struct dpp_configurator, list) {
		if (conf->id > max_id)
			max_id = conf->id;
	}
	return max_id + 1;
}


int hostapd_dpp_configurator_add(struct hostapd_data *hapd, const char *cmd)
{
	char *expiry = NULL, *curve = NULL;
	char *key = NULL;
	u8 *privkey = NULL;
	size_t privkey_len = 0;
	int ret = -1;
	struct dpp_configurator *conf = NULL;

	expiry = get_param(cmd, " expiry=");
	curve = get_param(cmd, " curve=");
	key = get_param(cmd, " key=");

	if (key) {
		privkey_len = os_strlen(key) / 2;
		privkey = os_malloc(privkey_len);
		if (!privkey ||
		    hexstr2bin(key, privkey, privkey_len) < 0)
			goto fail;
	}

	conf = dpp_keygen_configurator(curve, privkey, privkey_len);
	if (!conf)
		goto fail;

	if (expiry) {
		long int val;

		val = strtol(expiry, NULL, 0);
		if (val <= 0)
			goto fail;
		conf->csign_expiry = val;
	}

	conf->id = hostapd_dpp_next_configurator_id(hapd);
	dl_list_add(&hapd->dpp_configurator, &conf->list);
	ret = conf->id;
	conf = NULL;
fail:
	os_free(curve);
	os_free(expiry);
	str_clear_free(key);
	bin_clear_free(privkey, privkey_len);
	dpp_configurator_free(conf);
	return ret;
}


static int dpp_configurator_del(struct hostapd_data *hapd, unsigned int id)
{
	struct dpp_configurator *conf, *tmp;
	int found = 0;

	dl_list_for_each_safe(conf, tmp, &hapd->dpp_configurator,
			      struct dpp_configurator, list) {
		if (id && conf->id != id)
			continue;
		found = 1;
		dl_list_del(&conf->list);
		dpp_configurator_free(conf);
	}

	if (id == 0)
		return 0; /* flush succeeds regardless of entries found */
	return found ? 0 : -1;
}


int hostapd_dpp_configurator_remove(struct hostapd_data *hapd, const char *id)
{
	unsigned int id_val;

	if (os_strcmp(id, "*") == 0) {
		id_val = 0;
	} else {
		id_val = atoi(id);
		if (id_val == 0)
			return -1;
	}

	return dpp_configurator_del(hapd, id_val);
}


int hostapd_dpp_pkex_add(struct hostapd_data *hapd, const char *cmd)
{
	struct dpp_bootstrap_info *own_bi;
	const char *pos, *end;

	pos = os_strstr(cmd, " own=");
	if (!pos)
		return -1;
	pos += 5;
	own_bi = dpp_bootstrap_get_id(hapd, atoi(pos));
	if (!own_bi) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Identified bootstrap info not found");
		return -1;
	}
	if (own_bi->type != DPP_BOOTSTRAP_PKEX) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Identified bootstrap info not for PKEX");
		return -1;
	}
	hapd->dpp_pkex_bi = own_bi;

	os_free(hapd->dpp_pkex_identifier);
	hapd->dpp_pkex_identifier = NULL;
	pos = os_strstr(cmd, " identifier=");
	if (pos) {
		pos += 12;
		end = os_strchr(pos, ' ');
		if (!end)
			return -1;
		hapd->dpp_pkex_identifier = os_malloc(end - pos + 1);
		if (!hapd->dpp_pkex_identifier)
			return -1;
		os_memcpy(hapd->dpp_pkex_identifier, pos, end - pos);
		hapd->dpp_pkex_identifier[end - pos] = '\0';
	}

	pos = os_strstr(cmd, " code=");
	if (!pos)
		return -1;
	os_free(hapd->dpp_pkex_code);
	hapd->dpp_pkex_code = os_strdup(pos + 6);
	if (!hapd->dpp_pkex_code)
		return -1;

	if (os_strstr(cmd, " init=1")) {
		struct wpabuf *msg;

		wpa_printf(MSG_DEBUG, "DPP: Initiating PKEX");
		dpp_pkex_free(hapd->dpp_pkex);
		hapd->dpp_pkex = dpp_pkex_init(own_bi, hapd->own_addr,
					       hapd->dpp_pkex_identifier,
					       hapd->dpp_pkex_code);
		if (!hapd->dpp_pkex)
			return -1;

		msg = hapd->dpp_pkex->exchange_req;
		/* TODO: Which channel to use? */
		hostapd_drv_send_action(hapd, 2437, 0, broadcast,
					wpabuf_head(msg), wpabuf_len(msg));
	}

	/* TODO: Support multiple PKEX info entries */

	os_free(hapd->dpp_pkex_auth_cmd);
	hapd->dpp_pkex_auth_cmd = os_strdup(cmd);

	return 1;
}


int hostapd_dpp_pkex_remove(struct hostapd_data *hapd, const char *id)
{
	unsigned int id_val;

	if (os_strcmp(id, "*") == 0) {
		id_val = 0;
	} else {
		id_val = atoi(id);
		if (id_val == 0)
			return -1;
	}

	if ((id_val != 0 && id_val != 1) || !hapd->dpp_pkex_code)
		return -1;

	/* TODO: Support multiple PKEX entries */
	os_free(hapd->dpp_pkex_code);
	hapd->dpp_pkex_code = NULL;
	os_free(hapd->dpp_pkex_identifier);
	hapd->dpp_pkex_identifier = NULL;
	os_free(hapd->dpp_pkex_auth_cmd);
	hapd->dpp_pkex_auth_cmd = NULL;
	hapd->dpp_pkex_bi = NULL;
	/* TODO: Remove dpp_pkex only if it is for the identified PKEX code */
	dpp_pkex_free(hapd->dpp_pkex);
	hapd->dpp_pkex = NULL;
	return 0;
}


int hostapd_dpp_init(struct hostapd_data *hapd)
{
	dl_list_init(&hapd->dpp_bootstrap);
	dl_list_init(&hapd->dpp_configurator);
	hapd->dpp_allowed_roles = DPP_CAPAB_CONFIGURATOR | DPP_CAPAB_ENROLLEE;
	hapd->dpp_init_done = 1;
	return 0;
}


void hostapd_dpp_deinit(struct hostapd_data *hapd)
{
#ifdef CONFIG_TESTING_OPTIONS
	os_free(hapd->dpp_config_obj_override);
	hapd->dpp_config_obj_override = NULL;
	os_free(hapd->dpp_discovery_override);
	hapd->dpp_discovery_override = NULL;
	os_free(hapd->dpp_groups_override);
	hapd->dpp_groups_override = NULL;
	hapd->dpp_ignore_netaccesskey_mismatch = 0;
#endif /* CONFIG_TESTING_OPTIONS */
	if (!hapd->dpp_init_done)
		return;
	dpp_bootstrap_del(hapd, 0);
	dpp_configurator_del(hapd, 0);
	dpp_auth_deinit(hapd->dpp_auth);
	hapd->dpp_auth = NULL;
	hostapd_dpp_pkex_remove(hapd, "*");
	hapd->dpp_pkex = NULL;
	os_free(hapd->dpp_configurator_params);
	hapd->dpp_configurator_params = NULL;
}
