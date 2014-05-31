/*
 * WPA Supplicant / Control interface (shared code for all backends)
 * Copyright (c) 2004-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/uuid.h"
#include "common/version.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/wpa_ctrl.h"
#include "eap_peer/eap.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/preauth.h"
#include "rsn_supp/pmksa_cache.h"
#include "l2_packet/l2_packet.h"
#include "wps/wps.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "wps_supplicant.h"
#include "ibss_rsn.h"
#include "ap.h"
#include "p2p_supplicant.h"
#include "p2p/p2p.h"
#include "hs20_supplicant.h"
#include "wifi_display.h"
#include "notify.h"
#include "bss.h"
#include "scan.h"
#include "ctrl_iface.h"
#include "interworking.h"
#include "blacklist.h"
#include "autoscan.h"
#include "wnm_sta.h"
#include "offchannel.h"

static int wpa_supplicant_global_iface_list(struct wpa_global *global,
					    char *buf, int len);
static int wpa_supplicant_global_iface_interfaces(struct wpa_global *global,
						  char *buf, int len);
static int * freq_range_to_channel_list(struct wpa_supplicant *wpa_s,
					char *val);

static int set_bssid_filter(struct wpa_supplicant *wpa_s, char *val)
{
	char *pos;
	u8 addr[ETH_ALEN], *filter = NULL, *n;
	size_t count = 0;

	pos = val;
	while (pos) {
		if (*pos == '\0')
			break;
		if (hwaddr_aton(pos, addr)) {
			os_free(filter);
			return -1;
		}
		n = os_realloc_array(filter, count + 1, ETH_ALEN);
		if (n == NULL) {
			os_free(filter);
			return -1;
		}
		filter = n;
		os_memcpy(filter + count * ETH_ALEN, addr, ETH_ALEN);
		count++;

		pos = os_strchr(pos, ' ');
		if (pos)
			pos++;
	}

	wpa_hexdump(MSG_DEBUG, "bssid_filter", filter, count * ETH_ALEN);
	os_free(wpa_s->bssid_filter);
	wpa_s->bssid_filter = filter;
	wpa_s->bssid_filter_count = count;

	return 0;
}


static int set_disallow_aps(struct wpa_supplicant *wpa_s, char *val)
{
	char *pos;
	u8 addr[ETH_ALEN], *bssid = NULL, *n;
	struct wpa_ssid_value *ssid = NULL, *ns;
	size_t count = 0, ssid_count = 0;
	struct wpa_ssid *c;

	/*
	 * disallow_list ::= <ssid_spec> | <bssid_spec> | <disallow_list> | ""
	 * SSID_SPEC ::= ssid <SSID_HEX>
	 * BSSID_SPEC ::= bssid <BSSID_HEX>
	 */

	pos = val;
	while (pos) {
		if (*pos == '\0')
			break;
		if (os_strncmp(pos, "bssid ", 6) == 0) {
			int res;
			pos += 6;
			res = hwaddr_aton2(pos, addr);
			if (res < 0) {
				os_free(ssid);
				os_free(bssid);
				wpa_printf(MSG_DEBUG, "Invalid disallow_aps "
					   "BSSID value '%s'", pos);
				return -1;
			}
			pos += res;
			n = os_realloc_array(bssid, count + 1, ETH_ALEN);
			if (n == NULL) {
				os_free(ssid);
				os_free(bssid);
				return -1;
			}
			bssid = n;
			os_memcpy(bssid + count * ETH_ALEN, addr, ETH_ALEN);
			count++;
		} else if (os_strncmp(pos, "ssid ", 5) == 0) {
			char *end;
			pos += 5;

			end = pos;
			while (*end) {
				if (*end == '\0' || *end == ' ')
					break;
				end++;
			}

			ns = os_realloc_array(ssid, ssid_count + 1,
					      sizeof(struct wpa_ssid_value));
			if (ns == NULL) {
				os_free(ssid);
				os_free(bssid);
				return -1;
			}
			ssid = ns;

			if ((end - pos) & 0x01 || end - pos > 2 * 32 ||
			    hexstr2bin(pos, ssid[ssid_count].ssid,
				       (end - pos) / 2) < 0) {
				os_free(ssid);
				os_free(bssid);
				wpa_printf(MSG_DEBUG, "Invalid disallow_aps "
					   "SSID value '%s'", pos);
				return -1;
			}
			ssid[ssid_count].ssid_len = (end - pos) / 2;
			wpa_hexdump_ascii(MSG_DEBUG, "disallow_aps SSID",
					  ssid[ssid_count].ssid,
					  ssid[ssid_count].ssid_len);
			ssid_count++;
			pos = end;
		} else {
			wpa_printf(MSG_DEBUG, "Unexpected disallow_aps value "
				   "'%s'", pos);
			os_free(ssid);
			os_free(bssid);
			return -1;
		}

		pos = os_strchr(pos, ' ');
		if (pos)
			pos++;
	}

	wpa_hexdump(MSG_DEBUG, "disallow_aps_bssid", bssid, count * ETH_ALEN);
	os_free(wpa_s->disallow_aps_bssid);
	wpa_s->disallow_aps_bssid = bssid;
	wpa_s->disallow_aps_bssid_count = count;

	wpa_printf(MSG_DEBUG, "disallow_aps_ssid_count %d", (int) ssid_count);
	os_free(wpa_s->disallow_aps_ssid);
	wpa_s->disallow_aps_ssid = ssid;
	wpa_s->disallow_aps_ssid_count = ssid_count;

	if (!wpa_s->current_ssid || wpa_s->wpa_state < WPA_AUTHENTICATING)
		return 0;

	c = wpa_s->current_ssid;
	if (c->mode != WPAS_MODE_INFRA && c->mode != WPAS_MODE_IBSS)
		return 0;

	if (!disallowed_bssid(wpa_s, wpa_s->bssid) &&
	    !disallowed_ssid(wpa_s, c->ssid, c->ssid_len))
		return 0;

	wpa_printf(MSG_DEBUG, "Disconnect and try to find another network "
		   "because current AP was marked disallowed");

#ifdef CONFIG_SME
	wpa_s->sme.prev_bssid_set = 0;
#endif /* CONFIG_SME */
	wpa_s->reassociate = 1;
	wpa_supplicant_deauthenticate(wpa_s, WLAN_REASON_DEAUTH_LEAVING);
	wpa_supplicant_req_scan(wpa_s, 0, 0);

	return 0;
}


#ifndef CONFIG_NO_CONFIG_BLOBS
static int wpas_ctrl_set_blob(struct wpa_supplicant *wpa_s, char *pos)
{
	char *name = pos;
	struct wpa_config_blob *blob;
	size_t len;

	pos = os_strchr(pos, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';
	len = os_strlen(pos);
	if (len & 1)
		return -1;

	wpa_printf(MSG_DEBUG, "CTRL: Set blob '%s'", name);
	blob = os_zalloc(sizeof(*blob));
	if (blob == NULL)
		return -1;
	blob->name = os_strdup(name);
	blob->data = os_malloc(len / 2);
	if (blob->name == NULL || blob->data == NULL) {
		wpa_config_free_blob(blob);
		return -1;
	}

	if (hexstr2bin(pos, blob->data, len / 2) < 0) {
		wpa_printf(MSG_DEBUG, "CTRL: Invalid blob hex data");
		wpa_config_free_blob(blob);
		return -1;
	}
	blob->len = len / 2;

	wpa_config_set_blob(wpa_s->conf, blob);

	return 0;
}
#endif /* CONFIG_NO_CONFIG_BLOBS */


static int wpas_ctrl_pno(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *params;
	char *pos;
	int *freqs = NULL;
	int ret;

	if (atoi(cmd)) {
		params = os_strchr(cmd, ' ');
		os_free(wpa_s->manual_sched_scan_freqs);
		if (params) {
			params++;
			pos = os_strstr(params, "freq=");
			if (pos)
				freqs = freq_range_to_channel_list(wpa_s,
								   pos + 5);
		}
		wpa_s->manual_sched_scan_freqs = freqs;
		ret = wpas_start_pno(wpa_s);
	} else {
		ret = wpas_stop_pno(wpa_s);
	}
	return ret;
}


static int wpa_supplicant_ctrl_iface_set(struct wpa_supplicant *wpa_s,
					 char *cmd)
{
	char *value;
	int ret = 0;

	value = os_strchr(cmd, ' ');
	if (value == NULL)
		return -1;
	*value++ = '\0';

	wpa_printf(MSG_DEBUG, "CTRL_IFACE SET '%s'='%s'", cmd, value);
	if (os_strcasecmp(cmd, "EAPOL::heldPeriod") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   atoi(value), -1, -1, -1);
	} else if (os_strcasecmp(cmd, "EAPOL::authPeriod") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   -1, atoi(value), -1, -1);
	} else if (os_strcasecmp(cmd, "EAPOL::startPeriod") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   -1, -1, atoi(value), -1);
	} else if (os_strcasecmp(cmd, "EAPOL::maxStart") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   -1, -1, -1, atoi(value));
	} else if (os_strcasecmp(cmd, "dot11RSNAConfigPMKLifetime") == 0) {
		if (wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_LIFETIME,
				     atoi(value)))
			ret = -1;
	} else if (os_strcasecmp(cmd, "dot11RSNAConfigPMKReauthThreshold") ==
		   0) {
		if (wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_REAUTH_THRESHOLD,
				     atoi(value)))
			ret = -1;
	} else if (os_strcasecmp(cmd, "dot11RSNAConfigSATimeout") == 0) {
		if (wpa_sm_set_param(wpa_s->wpa, RSNA_SA_TIMEOUT, atoi(value)))
			ret = -1;
	} else if (os_strcasecmp(cmd, "wps_fragment_size") == 0) {
		wpa_s->wps_fragment_size = atoi(value);
#ifdef CONFIG_WPS_TESTING
	} else if (os_strcasecmp(cmd, "wps_version_number") == 0) {
		long int val;
		val = strtol(value, NULL, 0);
		if (val < 0 || val > 0xff) {
			ret = -1;
			wpa_printf(MSG_DEBUG, "WPS: Invalid "
				   "wps_version_number %ld", val);
		} else {
			wps_version_number = val;
			wpa_printf(MSG_DEBUG, "WPS: Testing - force WPS "
				   "version %u.%u",
				   (wps_version_number & 0xf0) >> 4,
				   wps_version_number & 0x0f);
		}
	} else if (os_strcasecmp(cmd, "wps_testing_dummy_cred") == 0) {
		wps_testing_dummy_cred = atoi(value);
		wpa_printf(MSG_DEBUG, "WPS: Testing - dummy_cred=%d",
			   wps_testing_dummy_cred);
	} else if (os_strcasecmp(cmd, "wps_corrupt_pkhash") == 0) {
		wps_corrupt_pkhash = atoi(value);
		wpa_printf(MSG_DEBUG, "WPS: Testing - wps_corrupt_pkhash=%d",
			   wps_corrupt_pkhash);
#endif /* CONFIG_WPS_TESTING */
	} else if (os_strcasecmp(cmd, "ampdu") == 0) {
		if (wpa_drv_ampdu(wpa_s, atoi(value)) < 0)
			ret = -1;
#ifdef CONFIG_TDLS
#ifdef CONFIG_TDLS_TESTING
	} else if (os_strcasecmp(cmd, "tdls_testing") == 0) {
		extern unsigned int tdls_testing;
		tdls_testing = strtol(value, NULL, 0);
		wpa_printf(MSG_DEBUG, "TDLS: tdls_testing=0x%x", tdls_testing);
#endif /* CONFIG_TDLS_TESTING */
	} else if (os_strcasecmp(cmd, "tdls_disabled") == 0) {
		int disabled = atoi(value);
		wpa_printf(MSG_DEBUG, "TDLS: tdls_disabled=%d", disabled);
		if (disabled) {
			if (wpa_drv_tdls_oper(wpa_s, TDLS_DISABLE, NULL) < 0)
				ret = -1;
		} else if (wpa_drv_tdls_oper(wpa_s, TDLS_ENABLE, NULL) < 0)
			ret = -1;
		wpa_tdls_enable(wpa_s->wpa, !disabled);
#endif /* CONFIG_TDLS */
	} else if (os_strcasecmp(cmd, "pno") == 0) {
		ret = wpas_ctrl_pno(wpa_s, value);
	} else if (os_strcasecmp(cmd, "radio_disabled") == 0) {
		int disabled = atoi(value);
		if (wpa_drv_radio_disable(wpa_s, disabled) < 0)
			ret = -1;
		else if (disabled)
			wpa_supplicant_set_state(wpa_s, WPA_INACTIVE);
	} else if (os_strcasecmp(cmd, "uapsd") == 0) {
		if (os_strcmp(value, "disable") == 0)
			wpa_s->set_sta_uapsd = 0;
		else {
			int be, bk, vi, vo;
			char *pos;
			/* format: BE,BK,VI,VO;max SP Length */
			be = atoi(value);
			pos = os_strchr(value, ',');
			if (pos == NULL)
				return -1;
			pos++;
			bk = atoi(pos);
			pos = os_strchr(pos, ',');
			if (pos == NULL)
				return -1;
			pos++;
			vi = atoi(pos);
			pos = os_strchr(pos, ',');
			if (pos == NULL)
				return -1;
			pos++;
			vo = atoi(pos);
			/* ignore max SP Length for now */

			wpa_s->set_sta_uapsd = 1;
			wpa_s->sta_uapsd = 0;
			if (be)
				wpa_s->sta_uapsd |= BIT(0);
			if (bk)
				wpa_s->sta_uapsd |= BIT(1);
			if (vi)
				wpa_s->sta_uapsd |= BIT(2);
			if (vo)
				wpa_s->sta_uapsd |= BIT(3);
		}
	} else if (os_strcasecmp(cmd, "ps") == 0) {
		ret = wpa_drv_set_p2p_powersave(wpa_s, atoi(value), -1, -1);
#ifdef CONFIG_WIFI_DISPLAY
	} else if (os_strcasecmp(cmd, "wifi_display") == 0) {
		int enabled = !!atoi(value);
		if (enabled && !wpa_s->global->p2p)
			ret = -1;
		else
			wifi_display_enable(wpa_s->global, enabled);
#endif /* CONFIG_WIFI_DISPLAY */
	} else if (os_strcasecmp(cmd, "bssid_filter") == 0) {
		ret = set_bssid_filter(wpa_s, value);
	} else if (os_strcasecmp(cmd, "disallow_aps") == 0) {
		ret = set_disallow_aps(wpa_s, value);
	} else if (os_strcasecmp(cmd, "no_keep_alive") == 0) {
		wpa_s->no_keep_alive = !!atoi(value);
#ifdef CONFIG_TESTING_OPTIONS
	} else if (os_strcasecmp(cmd, "ext_mgmt_frame_handling") == 0) {
		wpa_s->ext_mgmt_frame_handling = !!atoi(value);
#endif /* CONFIG_TESTING_OPTIONS */
#ifndef CONFIG_NO_CONFIG_BLOBS
	} else if (os_strcmp(cmd, "blob") == 0) {
		ret = wpas_ctrl_set_blob(wpa_s, value);
#endif /* CONFIG_NO_CONFIG_BLOBS */
	} else {
		value[-1] = '=';
		ret = wpa_config_process_global(wpa_s->conf, cmd, -1);
		if (ret == 0)
			wpa_supplicant_update_config(wpa_s);
	}

	return ret;
}


static int wpa_supplicant_ctrl_iface_get(struct wpa_supplicant *wpa_s,
					 char *cmd, char *buf, size_t buflen)
{
	int res = -1;

	wpa_printf(MSG_DEBUG, "CTRL_IFACE GET '%s'", cmd);

	if (os_strcmp(cmd, "version") == 0) {
		res = os_snprintf(buf, buflen, "%s", VERSION_STR);
	} else if (os_strcasecmp(cmd, "country") == 0) {
		if (wpa_s->conf->country[0] && wpa_s->conf->country[1])
			res = os_snprintf(buf, buflen, "%c%c",
					  wpa_s->conf->country[0],
					  wpa_s->conf->country[1]);
#ifdef CONFIG_WIFI_DISPLAY
	} else if (os_strcasecmp(cmd, "wifi_display") == 0) {
		int enabled;
		if (wpa_s->global->p2p == NULL ||
		    wpa_s->global->p2p_disabled)
			enabled = 0;
		else
			enabled = wpa_s->global->wifi_display;
		res = os_snprintf(buf, buflen, "%d", enabled);
		if (res < 0 || (unsigned int) res >= buflen)
			return -1;
		return res;
#endif /* CONFIG_WIFI_DISPLAY */
#ifdef CONFIG_TESTING_GET_GTK
	} else if (os_strcmp(cmd, "gtk") == 0) {
		if (wpa_s->last_gtk_len == 0)
			return -1;
		res = wpa_snprintf_hex(buf, buflen, wpa_s->last_gtk,
				       wpa_s->last_gtk_len);
		return res;
#endif /* CONFIG_TESTING_GET_GTK */
	}

	if (res < 0 || (unsigned int) res >= buflen)
		return -1;
	return res;
}


#ifdef IEEE8021X_EAPOL
static int wpa_supplicant_ctrl_iface_preauth(struct wpa_supplicant *wpa_s,
					     char *addr)
{
	u8 bssid[ETH_ALEN];
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (hwaddr_aton(addr, bssid)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE PREAUTH: invalid address "
			   "'%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE PREAUTH " MACSTR, MAC2STR(bssid));
	rsn_preauth_deinit(wpa_s->wpa);
	if (rsn_preauth_init(wpa_s->wpa, bssid, ssid ? &ssid->eap : NULL))
		return -1;

	return 0;
}
#endif /* IEEE8021X_EAPOL */


#ifdef CONFIG_PEERKEY
/* MLME-STKSTART.request(peer) */
static int wpa_supplicant_ctrl_iface_stkstart(
	struct wpa_supplicant *wpa_s, char *addr)
{
	u8 peer[ETH_ALEN];

	if (hwaddr_aton(addr, peer)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE STKSTART: invalid "
			   "address '%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE STKSTART " MACSTR,
		   MAC2STR(peer));

	return wpa_sm_stkstart(wpa_s->wpa, peer);
}
#endif /* CONFIG_PEERKEY */


#ifdef CONFIG_TDLS

static int wpa_supplicant_ctrl_iface_tdls_discover(
	struct wpa_supplicant *wpa_s, char *addr)
{
	u8 peer[ETH_ALEN];
	int ret;

	if (hwaddr_aton(addr, peer)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE TDLS_DISCOVER: invalid "
			   "address '%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE TDLS_DISCOVER " MACSTR,
		   MAC2STR(peer));

	if (wpa_tdls_is_external_setup(wpa_s->wpa))
		ret = wpa_tdls_send_discovery_request(wpa_s->wpa, peer);
	else
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_DISCOVERY_REQ, peer);

	return ret;
}


static int wpa_supplicant_ctrl_iface_tdls_setup(
	struct wpa_supplicant *wpa_s, char *addr)
{
	u8 peer[ETH_ALEN];
	int ret;

	if (hwaddr_aton(addr, peer)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE TDLS_SETUP: invalid "
			   "address '%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE TDLS_SETUP " MACSTR,
		   MAC2STR(peer));

	if ((wpa_s->conf->tdls_external_control) &&
	    wpa_tdls_is_external_setup(wpa_s->wpa))
		return wpa_drv_tdls_oper(wpa_s, TDLS_SETUP, peer);

	wpa_tdls_remove(wpa_s->wpa, peer);

	if (wpa_tdls_is_external_setup(wpa_s->wpa))
		ret = wpa_tdls_start(wpa_s->wpa, peer);
	else
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_SETUP, peer);

	return ret;
}


static int wpa_supplicant_ctrl_iface_tdls_teardown(
	struct wpa_supplicant *wpa_s, char *addr)
{
	u8 peer[ETH_ALEN];
	int ret;

	if (hwaddr_aton(addr, peer)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE TDLS_TEARDOWN: invalid "
			   "address '%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE TDLS_TEARDOWN " MACSTR,
		   MAC2STR(peer));

	if ((wpa_s->conf->tdls_external_control) &&
	    wpa_tdls_is_external_setup(wpa_s->wpa))
		return wpa_drv_tdls_oper(wpa_s, TDLS_TEARDOWN, peer);

	if (wpa_tdls_is_external_setup(wpa_s->wpa))
		ret = wpa_tdls_teardown_link(
			wpa_s->wpa, peer,
			WLAN_REASON_TDLS_TEARDOWN_UNSPECIFIED);
	else
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_TEARDOWN, peer);

	return ret;
}


static int ctrl_iface_get_capability_tdls(
	struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	int ret;

	ret = os_snprintf(buf, buflen, "%s\n",
			  wpa_s->drv_flags & WPA_DRIVER_FLAGS_TDLS_SUPPORT ?
			  (wpa_s->drv_flags &
			   WPA_DRIVER_FLAGS_TDLS_EXTERNAL_SETUP ?
			   "EXTERNAL" : "INTERNAL") : "UNSUPPORTED");
	if (ret < 0 || (size_t) ret > buflen)
		return -1;
	return ret;
}

#endif /* CONFIG_TDLS */


#ifdef CONFIG_IEEE80211R
static int wpa_supplicant_ctrl_iface_ft_ds(
	struct wpa_supplicant *wpa_s, char *addr)
{
	u8 target_ap[ETH_ALEN];
	struct wpa_bss *bss;
	const u8 *mdie;

	if (hwaddr_aton(addr, target_ap)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE FT_DS: invalid "
			   "address '%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE FT_DS " MACSTR, MAC2STR(target_ap));

	bss = wpa_bss_get_bssid(wpa_s, target_ap);
	if (bss)
		mdie = wpa_bss_get_ie(bss, WLAN_EID_MOBILITY_DOMAIN);
	else
		mdie = NULL;

	return wpa_ft_start_over_ds(wpa_s->wpa, target_ap, mdie);
}
#endif /* CONFIG_IEEE80211R */


#ifdef CONFIG_WPS
static int wpa_supplicant_ctrl_iface_wps_pbc(struct wpa_supplicant *wpa_s,
					     char *cmd)
{
	u8 bssid[ETH_ALEN], *_bssid = bssid;
#ifdef CONFIG_P2P
	u8 p2p_dev_addr[ETH_ALEN];
#endif /* CONFIG_P2P */
#ifdef CONFIG_AP
	u8 *_p2p_dev_addr = NULL;
#endif /* CONFIG_AP */

	if (cmd == NULL || os_strcmp(cmd, "any") == 0) {
		_bssid = NULL;
#ifdef CONFIG_P2P
	} else if (os_strncmp(cmd, "p2p_dev_addr=", 13) == 0) {
		if (hwaddr_aton(cmd + 13, p2p_dev_addr)) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE WPS_PBC: invalid "
				   "P2P Device Address '%s'",
				   cmd + 13);
			return -1;
		}
		_p2p_dev_addr = p2p_dev_addr;
#endif /* CONFIG_P2P */
	} else if (hwaddr_aton(cmd, bssid)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE WPS_PBC: invalid BSSID '%s'",
			   cmd);
		return -1;
	}

#ifdef CONFIG_AP
	if (wpa_s->ap_iface)
		return wpa_supplicant_ap_wps_pbc(wpa_s, _bssid, _p2p_dev_addr);
#endif /* CONFIG_AP */

	return wpas_wps_start_pbc(wpa_s, _bssid, 0);
}


static int wpa_supplicant_ctrl_iface_wps_pin(struct wpa_supplicant *wpa_s,
					     char *cmd, char *buf,
					     size_t buflen)
{
	u8 bssid[ETH_ALEN], *_bssid = bssid;
	char *pin;
	int ret;

	pin = os_strchr(cmd, ' ');
	if (pin)
		*pin++ = '\0';

	if (os_strcmp(cmd, "any") == 0)
		_bssid = NULL;
	else if (os_strcmp(cmd, "get") == 0) {
		ret = wps_generate_pin();
		goto done;
	} else if (hwaddr_aton(cmd, bssid)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE WPS_PIN: invalid BSSID '%s'",
			   cmd);
		return -1;
	}

#ifdef CONFIG_AP
	if (wpa_s->ap_iface) {
		int timeout = 0;
		char *pos;

		if (pin) {
			pos = os_strchr(pin, ' ');
			if (pos) {
				*pos++ = '\0';
				timeout = atoi(pos);
			}
		}

		return wpa_supplicant_ap_wps_pin(wpa_s, _bssid, pin,
						 buf, buflen, timeout);
	}
#endif /* CONFIG_AP */

	if (pin) {
		ret = wpas_wps_start_pin(wpa_s, _bssid, pin, 0,
					 DEV_PW_DEFAULT);
		if (ret < 0)
			return -1;
		ret = os_snprintf(buf, buflen, "%s", pin);
		if (ret < 0 || (size_t) ret >= buflen)
			return -1;
		return ret;
	}

	ret = wpas_wps_start_pin(wpa_s, _bssid, NULL, 0, DEV_PW_DEFAULT);
	if (ret < 0)
		return -1;

done:
	/* Return the generated PIN */
	ret = os_snprintf(buf, buflen, "%08d", ret);
	if (ret < 0 || (size_t) ret >= buflen)
		return -1;
	return ret;
}


static int wpa_supplicant_ctrl_iface_wps_check_pin(
	struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen)
{
	char pin[9];
	size_t len;
	char *pos;
	int ret;

	wpa_hexdump_ascii_key(MSG_DEBUG, "WPS_CHECK_PIN",
			      (u8 *) cmd, os_strlen(cmd));
	for (pos = cmd, len = 0; *pos != '\0'; pos++) {
		if (*pos < '0' || *pos > '9')
			continue;
		pin[len++] = *pos;
		if (len == 9) {
			wpa_printf(MSG_DEBUG, "WPS: Too long PIN");
			return -1;
		}
	}
	if (len != 4 && len != 8) {
		wpa_printf(MSG_DEBUG, "WPS: Invalid PIN length %d", (int) len);
		return -1;
	}
	pin[len] = '\0';

	if (len == 8) {
		unsigned int pin_val;
		pin_val = atoi(pin);
		if (!wps_pin_valid(pin_val)) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid checksum digit");
			ret = os_snprintf(buf, buflen, "FAIL-CHECKSUM\n");
			if (ret < 0 || (size_t) ret >= buflen)
				return -1;
			return ret;
		}
	}

	ret = os_snprintf(buf, buflen, "%s", pin);
	if (ret < 0 || (size_t) ret >= buflen)
		return -1;

	return ret;
}


#ifdef CONFIG_WPS_NFC

static int wpa_supplicant_ctrl_iface_wps_nfc(struct wpa_supplicant *wpa_s,
					     char *cmd)
{
	u8 bssid[ETH_ALEN], *_bssid = bssid;

	if (cmd == NULL || cmd[0] == '\0')
		_bssid = NULL;
	else if (hwaddr_aton(cmd, bssid))
		return -1;

	return wpas_wps_start_nfc(wpa_s, NULL, _bssid, NULL, 0, 0, NULL, NULL,
				  0, 0);
}


static int wpa_supplicant_ctrl_iface_wps_nfc_config_token(
	struct wpa_supplicant *wpa_s, char *cmd, char *reply, size_t max_len)
{
	int ndef;
	struct wpabuf *buf;
	int res;
	char *pos;

	pos = os_strchr(cmd, ' ');
	if (pos)
		*pos++ = '\0';
	if (os_strcmp(cmd, "WPS") == 0)
		ndef = 0;
	else if (os_strcmp(cmd, "NDEF") == 0)
		ndef = 1;
	else
		return -1;

	buf = wpas_wps_nfc_config_token(wpa_s, ndef, pos);
	if (buf == NULL)
		return -1;

	res = wpa_snprintf_hex_uppercase(reply, max_len, wpabuf_head(buf),
					 wpabuf_len(buf));
	reply[res++] = '\n';
	reply[res] = '\0';

	wpabuf_free(buf);

	return res;
}


static int wpa_supplicant_ctrl_iface_wps_nfc_token(
	struct wpa_supplicant *wpa_s, char *cmd, char *reply, size_t max_len)
{
	int ndef;
	struct wpabuf *buf;
	int res;

	if (os_strcmp(cmd, "WPS") == 0)
		ndef = 0;
	else if (os_strcmp(cmd, "NDEF") == 0)
		ndef = 1;
	else
		return -1;

	buf = wpas_wps_nfc_token(wpa_s, ndef);
	if (buf == NULL)
		return -1;

	res = wpa_snprintf_hex_uppercase(reply, max_len, wpabuf_head(buf),
					 wpabuf_len(buf));
	reply[res++] = '\n';
	reply[res] = '\0';

	wpabuf_free(buf);

	return res;
}


static int wpa_supplicant_ctrl_iface_wps_nfc_tag_read(
	struct wpa_supplicant *wpa_s, char *pos)
{
	size_t len;
	struct wpabuf *buf;
	int ret;
	char *freq;
	int forced_freq = 0;

	freq = strstr(pos, " freq=");
	if (freq) {
		*freq = '\0';
		freq += 6;
		forced_freq = atoi(freq);
	}

	len = os_strlen(pos);
	if (len & 0x01)
		return -1;
	len /= 2;

	buf = wpabuf_alloc(len);
	if (buf == NULL)
		return -1;
	if (hexstr2bin(pos, wpabuf_put(buf, len), len) < 0) {
		wpabuf_free(buf);
		return -1;
	}

	ret = wpas_wps_nfc_tag_read(wpa_s, buf, forced_freq);
	wpabuf_free(buf);

	return ret;
}


static int wpas_ctrl_nfc_get_handover_req_wps(struct wpa_supplicant *wpa_s,
					      char *reply, size_t max_len,
					      int ndef)
{
	struct wpabuf *buf;
	int res;

	buf = wpas_wps_nfc_handover_req(wpa_s, ndef);
	if (buf == NULL)
		return -1;

	res = wpa_snprintf_hex_uppercase(reply, max_len, wpabuf_head(buf),
					 wpabuf_len(buf));
	reply[res++] = '\n';
	reply[res] = '\0';

	wpabuf_free(buf);

	return res;
}


#ifdef CONFIG_P2P
static int wpas_ctrl_nfc_get_handover_req_p2p(struct wpa_supplicant *wpa_s,
					      char *reply, size_t max_len,
					      int ndef)
{
	struct wpabuf *buf;
	int res;

	buf = wpas_p2p_nfc_handover_req(wpa_s, ndef);
	if (buf == NULL) {
		wpa_printf(MSG_DEBUG, "P2P: Could not generate NFC handover request");
		return -1;
	}

	res = wpa_snprintf_hex_uppercase(reply, max_len, wpabuf_head(buf),
					 wpabuf_len(buf));
	reply[res++] = '\n';
	reply[res] = '\0';

	wpabuf_free(buf);

	return res;
}
#endif /* CONFIG_P2P */


static int wpas_ctrl_nfc_get_handover_req(struct wpa_supplicant *wpa_s,
					  char *cmd, char *reply,
					  size_t max_len)
{
	char *pos;
	int ndef;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';

	if (os_strcmp(cmd, "WPS") == 0)
		ndef = 0;
	else if (os_strcmp(cmd, "NDEF") == 0)
		ndef = 1;
	else
		return -1;

	if (os_strcmp(pos, "WPS") == 0 || os_strcmp(pos, "WPS-CR") == 0) {
		if (!ndef)
			return -1;
		return wpas_ctrl_nfc_get_handover_req_wps(
			wpa_s, reply, max_len, ndef);
	}

#ifdef CONFIG_P2P
	if (os_strcmp(pos, "P2P-CR") == 0) {
		return wpas_ctrl_nfc_get_handover_req_p2p(
			wpa_s, reply, max_len, ndef);
	}
#endif /* CONFIG_P2P */

	return -1;
}


static int wpas_ctrl_nfc_get_handover_sel_wps(struct wpa_supplicant *wpa_s,
					      char *reply, size_t max_len,
					      int ndef, int cr, char *uuid)
{
	struct wpabuf *buf;
	int res;

	buf = wpas_wps_nfc_handover_sel(wpa_s, ndef, cr, uuid);
	if (buf == NULL)
		return -1;

	res = wpa_snprintf_hex_uppercase(reply, max_len, wpabuf_head(buf),
					 wpabuf_len(buf));
	reply[res++] = '\n';
	reply[res] = '\0';

	wpabuf_free(buf);

	return res;
}


#ifdef CONFIG_P2P
static int wpas_ctrl_nfc_get_handover_sel_p2p(struct wpa_supplicant *wpa_s,
					      char *reply, size_t max_len,
					      int ndef, int tag)
{
	struct wpabuf *buf;
	int res;

	buf = wpas_p2p_nfc_handover_sel(wpa_s, ndef, tag);
	if (buf == NULL)
		return -1;

	res = wpa_snprintf_hex_uppercase(reply, max_len, wpabuf_head(buf),
					 wpabuf_len(buf));
	reply[res++] = '\n';
	reply[res] = '\0';

	wpabuf_free(buf);

	return res;
}
#endif /* CONFIG_P2P */


static int wpas_ctrl_nfc_get_handover_sel(struct wpa_supplicant *wpa_s,
					  char *cmd, char *reply,
					  size_t max_len)
{
	char *pos, *pos2;
	int ndef;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';

	if (os_strcmp(cmd, "WPS") == 0)
		ndef = 0;
	else if (os_strcmp(cmd, "NDEF") == 0)
		ndef = 1;
	else
		return -1;

	pos2 = os_strchr(pos, ' ');
	if (pos2)
		*pos2++ = '\0';
	if (os_strcmp(pos, "WPS") == 0 || os_strcmp(pos, "WPS-CR") == 0) {
		if (!ndef)
			return -1;
		return wpas_ctrl_nfc_get_handover_sel_wps(
			wpa_s, reply, max_len, ndef,
			os_strcmp(pos, "WPS-CR") == 0, pos2);
	}

#ifdef CONFIG_P2P
	if (os_strcmp(pos, "P2P-CR") == 0) {
		return wpas_ctrl_nfc_get_handover_sel_p2p(
			wpa_s, reply, max_len, ndef, 0);
	}

	if (os_strcmp(pos, "P2P-CR-TAG") == 0) {
		return wpas_ctrl_nfc_get_handover_sel_p2p(
			wpa_s, reply, max_len, ndef, 1);
	}
#endif /* CONFIG_P2P */

	return -1;
}


static int wpas_ctrl_nfc_report_handover(struct wpa_supplicant *wpa_s,
					 char *cmd)
{
	size_t len;
	struct wpabuf *req, *sel;
	int ret;
	char *pos, *role, *type, *pos2;
#ifdef CONFIG_P2P
	char *freq;
	int forced_freq = 0;

	freq = strstr(cmd, " freq=");
	if (freq) {
		*freq = '\0';
		freq += 6;
		forced_freq = atoi(freq);
	}
#endif /* CONFIG_P2P */

	role = cmd;
	pos = os_strchr(role, ' ');
	if (pos == NULL) {
		wpa_printf(MSG_DEBUG, "NFC: Missing type in handover report");
		return -1;
	}
	*pos++ = '\0';

	type = pos;
	pos = os_strchr(type, ' ');
	if (pos == NULL) {
		wpa_printf(MSG_DEBUG, "NFC: Missing request message in handover report");
		return -1;
	}
	*pos++ = '\0';

	pos2 = os_strchr(pos, ' ');
	if (pos2 == NULL) {
		wpa_printf(MSG_DEBUG, "NFC: Missing select message in handover report");
		return -1;
	}
	*pos2++ = '\0';

	len = os_strlen(pos);
	if (len & 0x01) {
		wpa_printf(MSG_DEBUG, "NFC: Invalid request message length in handover report");
		return -1;
	}
	len /= 2;

	req = wpabuf_alloc(len);
	if (req == NULL) {
		wpa_printf(MSG_DEBUG, "NFC: Failed to allocate memory for request message");
		return -1;
	}
	if (hexstr2bin(pos, wpabuf_put(req, len), len) < 0) {
		wpa_printf(MSG_DEBUG, "NFC: Invalid request message hexdump in handover report");
		wpabuf_free(req);
		return -1;
	}

	len = os_strlen(pos2);
	if (len & 0x01) {
		wpa_printf(MSG_DEBUG, "NFC: Invalid select message length in handover report");
		wpabuf_free(req);
		return -1;
	}
	len /= 2;

	sel = wpabuf_alloc(len);
	if (sel == NULL) {
		wpa_printf(MSG_DEBUG, "NFC: Failed to allocate memory for select message");
		wpabuf_free(req);
		return -1;
	}
	if (hexstr2bin(pos2, wpabuf_put(sel, len), len) < 0) {
		wpa_printf(MSG_DEBUG, "NFC: Invalid select message hexdump in handover report");
		wpabuf_free(req);
		wpabuf_free(sel);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NFC: Connection handover reported - role=%s type=%s req_len=%d sel_len=%d",
		   role, type, (int) wpabuf_len(req), (int) wpabuf_len(sel));

	if (os_strcmp(role, "INIT") == 0 && os_strcmp(type, "WPS") == 0) {
		ret = wpas_wps_nfc_report_handover(wpa_s, req, sel);
#ifdef CONFIG_AP
	} else if (os_strcmp(role, "RESP") == 0 && os_strcmp(type, "WPS") == 0)
	{
		ret = wpas_ap_wps_nfc_report_handover(wpa_s, req, sel);
		if (ret < 0)
			ret = wpas_er_wps_nfc_report_handover(wpa_s, req, sel);
#endif /* CONFIG_AP */
#ifdef CONFIG_P2P
	} else if (os_strcmp(role, "INIT") == 0 && os_strcmp(type, "P2P") == 0)
	{
		ret = wpas_p2p_nfc_report_handover(wpa_s, 1, req, sel, 0);
	} else if (os_strcmp(role, "RESP") == 0 && os_strcmp(type, "P2P") == 0)
	{
		ret = wpas_p2p_nfc_report_handover(wpa_s, 0, req, sel,
						   forced_freq);
#endif /* CONFIG_P2P */
	} else {
		wpa_printf(MSG_DEBUG, "NFC: Unsupported connection handover "
			   "reported: role=%s type=%s", role, type);
		ret = -1;
	}
	wpabuf_free(req);
	wpabuf_free(sel);

	if (ret)
		wpa_printf(MSG_DEBUG, "NFC: Failed to process reported handover messages");

	return ret;
}

#endif /* CONFIG_WPS_NFC */


static int wpa_supplicant_ctrl_iface_wps_reg(struct wpa_supplicant *wpa_s,
					     char *cmd)
{
	u8 bssid[ETH_ALEN];
	char *pin;
	char *new_ssid;
	char *new_auth;
	char *new_encr;
	char *new_key;
	struct wps_new_ap_settings ap;

	pin = os_strchr(cmd, ' ');
	if (pin == NULL)
		return -1;
	*pin++ = '\0';

	if (hwaddr_aton(cmd, bssid)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE WPS_REG: invalid BSSID '%s'",
			   cmd);
		return -1;
	}

	new_ssid = os_strchr(pin, ' ');
	if (new_ssid == NULL)
		return wpas_wps_start_reg(wpa_s, bssid, pin, NULL);
	*new_ssid++ = '\0';

	new_auth = os_strchr(new_ssid, ' ');
	if (new_auth == NULL)
		return -1;
	*new_auth++ = '\0';

	new_encr = os_strchr(new_auth, ' ');
	if (new_encr == NULL)
		return -1;
	*new_encr++ = '\0';

	new_key = os_strchr(new_encr, ' ');
	if (new_key == NULL)
		return -1;
	*new_key++ = '\0';

	os_memset(&ap, 0, sizeof(ap));
	ap.ssid_hex = new_ssid;
	ap.auth = new_auth;
	ap.encr = new_encr;
	ap.key_hex = new_key;
	return wpas_wps_start_reg(wpa_s, bssid, pin, &ap);
}


#ifdef CONFIG_AP
static int wpa_supplicant_ctrl_iface_wps_ap_pin(struct wpa_supplicant *wpa_s,
						char *cmd, char *buf,
						size_t buflen)
{
	int timeout = 300;
	char *pos;
	const char *pin_txt;

	if (!wpa_s->ap_iface)
		return -1;

	pos = os_strchr(cmd, ' ');
	if (pos)
		*pos++ = '\0';

	if (os_strcmp(cmd, "disable") == 0) {
		wpas_wps_ap_pin_disable(wpa_s);
		return os_snprintf(buf, buflen, "OK\n");
	}

	if (os_strcmp(cmd, "random") == 0) {
		if (pos)
			timeout = atoi(pos);
		pin_txt = wpas_wps_ap_pin_random(wpa_s, timeout);
		if (pin_txt == NULL)
			return -1;
		return os_snprintf(buf, buflen, "%s", pin_txt);
	}

	if (os_strcmp(cmd, "get") == 0) {
		pin_txt = wpas_wps_ap_pin_get(wpa_s);
		if (pin_txt == NULL)
			return -1;
		return os_snprintf(buf, buflen, "%s", pin_txt);
	}

	if (os_strcmp(cmd, "set") == 0) {
		char *pin;
		if (pos == NULL)
			return -1;
		pin = pos;
		pos = os_strchr(pos, ' ');
		if (pos) {
			*pos++ = '\0';
			timeout = atoi(pos);
		}
		if (os_strlen(pin) > buflen)
			return -1;
		if (wpas_wps_ap_pin_set(wpa_s, pin, timeout) < 0)
			return -1;
		return os_snprintf(buf, buflen, "%s", pin);
	}

	return -1;
}
#endif /* CONFIG_AP */


#ifdef CONFIG_WPS_ER
static int wpa_supplicant_ctrl_iface_wps_er_pin(struct wpa_supplicant *wpa_s,
						char *cmd)
{
	char *uuid = cmd, *pin, *pos;
	u8 addr_buf[ETH_ALEN], *addr = NULL;
	pin = os_strchr(uuid, ' ');
	if (pin == NULL)
		return -1;
	*pin++ = '\0';
	pos = os_strchr(pin, ' ');
	if (pos) {
		*pos++ = '\0';
		if (hwaddr_aton(pos, addr_buf) == 0)
			addr = addr_buf;
	}
	return wpas_wps_er_add_pin(wpa_s, addr, uuid, pin);
}


static int wpa_supplicant_ctrl_iface_wps_er_learn(struct wpa_supplicant *wpa_s,
						  char *cmd)
{
	char *uuid = cmd, *pin;
	pin = os_strchr(uuid, ' ');
	if (pin == NULL)
		return -1;
	*pin++ = '\0';
	return wpas_wps_er_learn(wpa_s, uuid, pin);
}


static int wpa_supplicant_ctrl_iface_wps_er_set_config(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	char *uuid = cmd, *id;
	id = os_strchr(uuid, ' ');
	if (id == NULL)
		return -1;
	*id++ = '\0';
	return wpas_wps_er_set_config(wpa_s, uuid, atoi(id));
}


static int wpa_supplicant_ctrl_iface_wps_er_config(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pin;
	char *new_ssid;
	char *new_auth;
	char *new_encr;
	char *new_key;
	struct wps_new_ap_settings ap;

	pin = os_strchr(cmd, ' ');
	if (pin == NULL)
		return -1;
	*pin++ = '\0';

	new_ssid = os_strchr(pin, ' ');
	if (new_ssid == NULL)
		return -1;
	*new_ssid++ = '\0';

	new_auth = os_strchr(new_ssid, ' ');
	if (new_auth == NULL)
		return -1;
	*new_auth++ = '\0';

	new_encr = os_strchr(new_auth, ' ');
	if (new_encr == NULL)
		return -1;
	*new_encr++ = '\0';

	new_key = os_strchr(new_encr, ' ');
	if (new_key == NULL)
		return -1;
	*new_key++ = '\0';

	os_memset(&ap, 0, sizeof(ap));
	ap.ssid_hex = new_ssid;
	ap.auth = new_auth;
	ap.encr = new_encr;
	ap.key_hex = new_key;
	return wpas_wps_er_config(wpa_s, cmd, pin, &ap);
}


#ifdef CONFIG_WPS_NFC
static int wpa_supplicant_ctrl_iface_wps_er_nfc_config_token(
	struct wpa_supplicant *wpa_s, char *cmd, char *reply, size_t max_len)
{
	int ndef;
	struct wpabuf *buf;
	int res;
	char *uuid;

	uuid = os_strchr(cmd, ' ');
	if (uuid == NULL)
		return -1;
	*uuid++ = '\0';

	if (os_strcmp(cmd, "WPS") == 0)
		ndef = 0;
	else if (os_strcmp(cmd, "NDEF") == 0)
		ndef = 1;
	else
		return -1;

	buf = wpas_wps_er_nfc_config_token(wpa_s, ndef, uuid);
	if (buf == NULL)
		return -1;

	res = wpa_snprintf_hex_uppercase(reply, max_len, wpabuf_head(buf),
					 wpabuf_len(buf));
	reply[res++] = '\n';
	reply[res] = '\0';

	wpabuf_free(buf);

	return res;
}
#endif /* CONFIG_WPS_NFC */
#endif /* CONFIG_WPS_ER */

#endif /* CONFIG_WPS */


#ifdef CONFIG_IBSS_RSN
static int wpa_supplicant_ctrl_iface_ibss_rsn(
	struct wpa_supplicant *wpa_s, char *addr)
{
	u8 peer[ETH_ALEN];

	if (hwaddr_aton(addr, peer)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE IBSS_RSN: invalid "
			   "address '%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE IBSS_RSN " MACSTR,
		   MAC2STR(peer));

	return ibss_rsn_start(wpa_s->ibss_rsn, peer);
}
#endif /* CONFIG_IBSS_RSN */


static int wpa_supplicant_ctrl_iface_ctrl_rsp(struct wpa_supplicant *wpa_s,
					      char *rsp)
{
#ifdef IEEE8021X_EAPOL
	char *pos, *id_pos;
	int id;
	struct wpa_ssid *ssid;

	pos = os_strchr(rsp, '-');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';
	id_pos = pos;
	pos = os_strchr(pos, ':');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';
	id = atoi(id_pos);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: field=%s id=%d", rsp, id);
	wpa_hexdump_ascii_key(MSG_DEBUG, "CTRL_IFACE: value",
			      (u8 *) pos, os_strlen(pos));

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find SSID id=%d "
			   "to update", id);
		return -1;
	}

	return wpa_supplicant_ctrl_iface_ctrl_rsp_handle(wpa_s, ssid, rsp,
							 pos);
#else /* IEEE8021X_EAPOL */
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: 802.1X not included");
	return -1;
#endif /* IEEE8021X_EAPOL */
}


static int wpa_supplicant_ctrl_iface_status(struct wpa_supplicant *wpa_s,
					    const char *params,
					    char *buf, size_t buflen)
{
	char *pos, *end, tmp[30];
	int res, verbose, wps, ret;
#ifdef CONFIG_HS20
	const u8 *hs20;
#endif /* CONFIG_HS20 */

	if (os_strcmp(params, "-DRIVER") == 0)
		return wpa_drv_status(wpa_s, buf, buflen);
	verbose = os_strcmp(params, "-VERBOSE") == 0;
	wps = os_strcmp(params, "-WPS") == 0;
	pos = buf;
	end = buf + buflen;
	if (wpa_s->wpa_state >= WPA_ASSOCIATED) {
		struct wpa_ssid *ssid = wpa_s->current_ssid;
		ret = os_snprintf(pos, end - pos, "bssid=" MACSTR "\n",
				  MAC2STR(wpa_s->bssid));
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
		if (ssid) {
			u8 *_ssid = ssid->ssid;
			size_t ssid_len = ssid->ssid_len;
			u8 ssid_buf[MAX_SSID_LEN];
			if (ssid_len == 0) {
				int _res = wpa_drv_get_ssid(wpa_s, ssid_buf);
				if (_res < 0)
					ssid_len = 0;
				else
					ssid_len = _res;
				_ssid = ssid_buf;
			}
			ret = os_snprintf(pos, end - pos, "ssid=%s\nid=%d\n",
					  wpa_ssid_txt(_ssid, ssid_len),
					  ssid->id);
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;

			if (wps && ssid->passphrase &&
			    wpa_key_mgmt_wpa_psk(ssid->key_mgmt) &&
			    (ssid->mode == WPAS_MODE_AP ||
			     ssid->mode == WPAS_MODE_P2P_GO)) {
				ret = os_snprintf(pos, end - pos,
						  "passphrase=%s\n",
						  ssid->passphrase);
				if (ret < 0 || ret >= end - pos)
					return pos - buf;
				pos += ret;
			}
			if (ssid->id_str) {
				ret = os_snprintf(pos, end - pos,
						  "id_str=%s\n",
						  ssid->id_str);
				if (ret < 0 || ret >= end - pos)
					return pos - buf;
				pos += ret;
			}

			switch (ssid->mode) {
			case WPAS_MODE_INFRA:
				ret = os_snprintf(pos, end - pos,
						  "mode=station\n");
				break;
			case WPAS_MODE_IBSS:
				ret = os_snprintf(pos, end - pos,
						  "mode=IBSS\n");
				break;
			case WPAS_MODE_AP:
				ret = os_snprintf(pos, end - pos,
						  "mode=AP\n");
				break;
			case WPAS_MODE_P2P_GO:
				ret = os_snprintf(pos, end - pos,
						  "mode=P2P GO\n");
				break;
			case WPAS_MODE_P2P_GROUP_FORMATION:
				ret = os_snprintf(pos, end - pos,
						  "mode=P2P GO - group "
						  "formation\n");
				break;
			default:
				ret = 0;
				break;
			}
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;
		}

#ifdef CONFIG_AP
		if (wpa_s->ap_iface) {
			pos += ap_ctrl_iface_wpa_get_status(wpa_s, pos,
							    end - pos,
							    verbose);
		} else
#endif /* CONFIG_AP */
		pos += wpa_sm_get_status(wpa_s->wpa, pos, end - pos, verbose);
	}
#ifdef CONFIG_SAE
	if (wpa_s->wpa_state >= WPA_ASSOCIATED &&
#ifdef CONFIG_AP
	    !wpa_s->ap_iface &&
#endif /* CONFIG_AP */
	    wpa_s->sme.sae.state == SAE_ACCEPTED) {
		ret = os_snprintf(pos, end - pos, "sae_group=%d\n",
				  wpa_s->sme.sae.group);
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}
#endif /* CONFIG_SAE */
	ret = os_snprintf(pos, end - pos, "wpa_state=%s\n",
			  wpa_supplicant_state_txt(wpa_s->wpa_state));
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;

	if (wpa_s->l2 &&
	    l2_packet_get_ip_addr(wpa_s->l2, tmp, sizeof(tmp)) >= 0) {
		ret = os_snprintf(pos, end - pos, "ip_address=%s\n", tmp);
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

#ifdef CONFIG_P2P
	if (wpa_s->global->p2p) {
		ret = os_snprintf(pos, end - pos, "p2p_device_address=" MACSTR
				  "\n", MAC2STR(wpa_s->global->p2p_dev_addr));
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}
#endif /* CONFIG_P2P */

	ret = os_snprintf(pos, end - pos, "address=" MACSTR "\n",
			  MAC2STR(wpa_s->own_addr));
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;

#ifdef CONFIG_HS20
	if (wpa_s->current_bss &&
	    (hs20 = wpa_bss_get_vendor_ie(wpa_s->current_bss,
					  HS20_IE_VENDOR_TYPE)) &&
	    wpa_s->wpa_proto == WPA_PROTO_RSN &&
	    wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt)) {
		int release = 1;
		if (hs20[1] >= 5) {
			u8 rel_num = (hs20[6] & 0xf0) >> 4;
			release = rel_num + 1;
		}
		ret = os_snprintf(pos, end - pos, "hs20=%d\n", release);
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	if (wpa_s->current_ssid) {
		struct wpa_cred *cred;
		char *type;

		for (cred = wpa_s->conf->cred; cred; cred = cred->next) {
			size_t i;

			if (wpa_s->current_ssid->parent_cred != cred)
				continue;

			if (cred->provisioning_sp) {
				ret = os_snprintf(pos, end - pos,
						  "provisioning_sp=%s\n",
						  cred->provisioning_sp);
				if (ret < 0 || ret >= end - pos)
					return pos - buf;
				pos += ret;
			}

			if (!cred->domain)
				goto no_domain;

			i = 0;
			if (wpa_s->current_bss && wpa_s->current_bss->anqp) {
				struct wpabuf *names =
					wpa_s->current_bss->anqp->domain_name;
				for (i = 0; names && i < cred->num_domain; i++)
				{
					if (domain_name_list_contains(
						    names, cred->domain[i], 1))
						break;
				}
				if (i == cred->num_domain)
					i = 0; /* show first entry by default */
			}
			ret = os_snprintf(pos, end - pos, "home_sp=%s\n",
					  cred->domain[i]);
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;

		no_domain:
			if (wpa_s->current_bss == NULL ||
			    wpa_s->current_bss->anqp == NULL)
				res = -1;
			else
				res = interworking_home_sp_cred(
					wpa_s, cred,
					wpa_s->current_bss->anqp->domain_name);
			if (res > 0)
				type = "home";
			else if (res == 0)
				type = "roaming";
			else
				type = "unknown";

			ret = os_snprintf(pos, end - pos, "sp_type=%s\n", type);
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;

			break;
		}
	}
#endif /* CONFIG_HS20 */

	if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt) ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		res = eapol_sm_get_status(wpa_s->eapol, pos, end - pos,
					  verbose);
		if (res >= 0)
			pos += res;
	}

	res = rsn_preauth_get_status(wpa_s->wpa, pos, end - pos, verbose);
	if (res >= 0)
		pos += res;

#ifdef CONFIG_WPS
	{
		char uuid_str[100];
		uuid_bin2str(wpa_s->wps->uuid, uuid_str, sizeof(uuid_str));
		ret = os_snprintf(pos, end - pos, "uuid=%s\n", uuid_str);
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}
#endif /* CONFIG_WPS */

#ifdef ANDROID
	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_STATE_CHANGE
		     "id=%d state=%d BSSID=" MACSTR " SSID=%s",
		     wpa_s->current_ssid ? wpa_s->current_ssid->id : -1,
		     wpa_s->wpa_state,
		     MAC2STR(wpa_s->bssid),
		     wpa_s->current_ssid && wpa_s->current_ssid->ssid ?
		     wpa_ssid_txt(wpa_s->current_ssid->ssid,
				  wpa_s->current_ssid->ssid_len) : "");
	if (wpa_s->wpa_state == WPA_COMPLETED) {
		struct wpa_ssid *ssid = wpa_s->current_ssid;
		wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_CONNECTED
			     "- connection to " MACSTR
			     " completed %s [id=%d id_str=%s]",
			     MAC2STR(wpa_s->bssid), "(auth)",
			     ssid ? ssid->id : -1,
			     ssid && ssid->id_str ? ssid->id_str : "");
	}
#endif /* ANDROID */

	return pos - buf;
}


static int wpa_supplicant_ctrl_iface_bssid(struct wpa_supplicant *wpa_s,
					   char *cmd)
{
	char *pos;
	int id;
	struct wpa_ssid *ssid;
	u8 bssid[ETH_ALEN];

	/* cmd: "<network id> <BSSID>" */
	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';
	id = atoi(cmd);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: id=%d bssid='%s'", id, pos);
	if (hwaddr_aton(pos, bssid)) {
		wpa_printf(MSG_DEBUG ,"CTRL_IFACE: invalid BSSID '%s'", pos);
		return -1;
	}

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find SSID id=%d "
			   "to update", id);
		return -1;
	}

	os_memcpy(ssid->bssid, bssid, ETH_ALEN);
	ssid->bssid_set = !is_zero_ether_addr(bssid);

	return 0;
}


static int wpa_supplicant_ctrl_iface_blacklist(struct wpa_supplicant *wpa_s,
					       char *cmd, char *buf,
					       size_t buflen)
{
	u8 bssid[ETH_ALEN];
	struct wpa_blacklist *e;
	char *pos, *end;
	int ret;

	/* cmd: "BLACKLIST [<BSSID>]" */
	if (*cmd == '\0') {
		pos = buf;
		end = buf + buflen;
		e = wpa_s->blacklist;
		while (e) {
			ret = os_snprintf(pos, end - pos, MACSTR "\n",
					  MAC2STR(e->bssid));
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;
			e = e->next;
		}
		return pos - buf;
	}

	cmd++;
	if (os_strncmp(cmd, "clear", 5) == 0) {
		wpa_blacklist_clear(wpa_s);
		os_memcpy(buf, "OK\n", 3);
		return 3;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: BLACKLIST bssid='%s'", cmd);
	if (hwaddr_aton(cmd, bssid)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: invalid BSSID '%s'", cmd);
		return -1;
	}

	/*
	 * Add the BSSID twice, so its count will be 2, causing it to be
	 * skipped when processing scan results.
	 */
	ret = wpa_blacklist_add(wpa_s, bssid);
	if (ret < 0)
		return -1;
	ret = wpa_blacklist_add(wpa_s, bssid);
	if (ret < 0)
		return -1;
	os_memcpy(buf, "OK\n", 3);
	return 3;
}


static const char * debug_level_str(int level)
{
	switch (level) {
	case MSG_EXCESSIVE:
		return "EXCESSIVE";
	case MSG_MSGDUMP:
		return "MSGDUMP";
	case MSG_DEBUG:
		return "DEBUG";
	case MSG_INFO:
		return "INFO";
	case MSG_WARNING:
		return "WARNING";
	case MSG_ERROR:
		return "ERROR";
	default:
		return "?";
	}
}


static int str_to_debug_level(const char *s)
{
	if (os_strcasecmp(s, "EXCESSIVE") == 0)
		return MSG_EXCESSIVE;
	if (os_strcasecmp(s, "MSGDUMP") == 0)
		return MSG_MSGDUMP;
	if (os_strcasecmp(s, "DEBUG") == 0)
		return MSG_DEBUG;
	if (os_strcasecmp(s, "INFO") == 0)
		return MSG_INFO;
	if (os_strcasecmp(s, "WARNING") == 0)
		return MSG_WARNING;
	if (os_strcasecmp(s, "ERROR") == 0)
		return MSG_ERROR;
	return -1;
}


static int wpa_supplicant_ctrl_iface_log_level(struct wpa_supplicant *wpa_s,
					       char *cmd, char *buf,
					       size_t buflen)
{
	char *pos, *end, *stamp;
	int ret;

	if (cmd == NULL) {
		return -1;
	}

	/* cmd: "LOG_LEVEL [<level>]" */
	if (*cmd == '\0') {
		pos = buf;
		end = buf + buflen;
		ret = os_snprintf(pos, end - pos, "Current level: %s\n"
				  "Timestamp: %d\n",
				  debug_level_str(wpa_debug_level),
				  wpa_debug_timestamp);
		if (ret < 0 || ret >= end - pos)
			ret = 0;

		return ret;
	}

	while (*cmd == ' ')
		cmd++;

	stamp = os_strchr(cmd, ' ');
	if (stamp) {
		*stamp++ = '\0';
		while (*stamp == ' ') {
			stamp++;
		}
	}

	if (cmd && os_strlen(cmd)) {
		int level = str_to_debug_level(cmd);
		if (level < 0)
			return -1;
		wpa_debug_level = level;
	}

	if (stamp && os_strlen(stamp))
		wpa_debug_timestamp = atoi(stamp);

	os_memcpy(buf, "OK\n", 3);
	return 3;
}


static int wpa_supplicant_ctrl_iface_list_networks(
	struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	char *pos, *end;
	struct wpa_ssid *ssid;
	int ret;

	pos = buf;
	end = buf + buflen;
	ret = os_snprintf(pos, end - pos,
			  "network id / ssid / bssid / flags\n");
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;

	ssid = wpa_s->conf->ssid;
	while (ssid) {
		ret = os_snprintf(pos, end - pos, "%d\t%s",
				  ssid->id,
				  wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
		if (ssid->bssid_set) {
			ret = os_snprintf(pos, end - pos, "\t" MACSTR,
					  MAC2STR(ssid->bssid));
		} else {
			ret = os_snprintf(pos, end - pos, "\tany");
		}
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
		ret = os_snprintf(pos, end - pos, "\t%s%s%s%s",
				  ssid == wpa_s->current_ssid ?
				  "[CURRENT]" : "",
				  ssid->disabled ? "[DISABLED]" : "",
				  ssid->disabled_until.sec ?
				  "[TEMP-DISABLED]" : "",
				  ssid->disabled == 2 ? "[P2P-PERSISTENT]" :
				  "");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
		ret = os_snprintf(pos, end - pos, "\n");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;

		ssid = ssid->next;
	}

	return pos - buf;
}


static char * wpa_supplicant_cipher_txt(char *pos, char *end, int cipher)
{
	int ret;
	ret = os_snprintf(pos, end - pos, "-");
	if (ret < 0 || ret >= end - pos)
		return pos;
	pos += ret;
	ret = wpa_write_ciphers(pos, end, cipher, "+");
	if (ret < 0)
		return pos;
	pos += ret;
	return pos;
}


static char * wpa_supplicant_ie_txt(char *pos, char *end, const char *proto,
				    const u8 *ie, size_t ie_len)
{
	struct wpa_ie_data data;
	char *start;
	int ret;

	ret = os_snprintf(pos, end - pos, "[%s-", proto);
	if (ret < 0 || ret >= end - pos)
		return pos;
	pos += ret;

	if (wpa_parse_wpa_ie(ie, ie_len, &data) < 0) {
		ret = os_snprintf(pos, end - pos, "?]");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
		return pos;
	}

	start = pos;
	if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X) {
		ret = os_snprintf(pos, end - pos, "%sEAP",
				  pos == start ? "" : "+");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}
	if (data.key_mgmt & WPA_KEY_MGMT_PSK) {
		ret = os_snprintf(pos, end - pos, "%sPSK",
				  pos == start ? "" : "+");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}
	if (data.key_mgmt & WPA_KEY_MGMT_WPA_NONE) {
		ret = os_snprintf(pos, end - pos, "%sNone",
				  pos == start ? "" : "+");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}
#ifdef CONFIG_IEEE80211R
	if (data.key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X) {
		ret = os_snprintf(pos, end - pos, "%sFT/EAP",
				  pos == start ? "" : "+");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}
	if (data.key_mgmt & WPA_KEY_MGMT_FT_PSK) {
		ret = os_snprintf(pos, end - pos, "%sFT/PSK",
				  pos == start ? "" : "+");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
	if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256) {
		ret = os_snprintf(pos, end - pos, "%sEAP-SHA256",
				  pos == start ? "" : "+");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}
	if (data.key_mgmt & WPA_KEY_MGMT_PSK_SHA256) {
		ret = os_snprintf(pos, end - pos, "%sPSK-SHA256",
				  pos == start ? "" : "+");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}
#endif /* CONFIG_IEEE80211W */

	pos = wpa_supplicant_cipher_txt(pos, end, data.pairwise_cipher);

	if (data.capabilities & WPA_CAPABILITY_PREAUTH) {
		ret = os_snprintf(pos, end - pos, "-preauth");
		if (ret < 0 || ret >= end - pos)
			return pos;
		pos += ret;
	}

	ret = os_snprintf(pos, end - pos, "]");
	if (ret < 0 || ret >= end - pos)
		return pos;
	pos += ret;

	return pos;
}


#ifdef CONFIG_WPS
static char * wpa_supplicant_wps_ie_txt_buf(struct wpa_supplicant *wpa_s,
					    char *pos, char *end,
					    struct wpabuf *wps_ie)
{
	int ret;
	const char *txt;

	if (wps_ie == NULL)
		return pos;
	if (wps_is_selected_pbc_registrar(wps_ie))
		txt = "[WPS-PBC]";
	else if (wps_is_addr_authorized(wps_ie, wpa_s->own_addr, 0))
		txt = "[WPS-AUTH]";
	else if (wps_is_selected_pin_registrar(wps_ie))
		txt = "[WPS-PIN]";
	else
		txt = "[WPS]";

	ret = os_snprintf(pos, end - pos, "%s", txt);
	if (ret >= 0 && ret < end - pos)
		pos += ret;
	wpabuf_free(wps_ie);
	return pos;
}
#endif /* CONFIG_WPS */


static char * wpa_supplicant_wps_ie_txt(struct wpa_supplicant *wpa_s,
					char *pos, char *end,
					const struct wpa_bss *bss)
{
#ifdef CONFIG_WPS
	struct wpabuf *wps_ie;
	wps_ie = wpa_bss_get_vendor_ie_multi(bss, WPS_IE_VENDOR_TYPE);
	return wpa_supplicant_wps_ie_txt_buf(wpa_s, pos, end, wps_ie);
#else /* CONFIG_WPS */
	return pos;
#endif /* CONFIG_WPS */
}


/* Format one result on one text line into a buffer. */
static int wpa_supplicant_ctrl_iface_scan_result(
	struct wpa_supplicant *wpa_s,
	const struct wpa_bss *bss, char *buf, size_t buflen)
{
	char *pos, *end;
	int ret;
	const u8 *ie, *ie2, *p2p;

	p2p = wpa_bss_get_vendor_ie(bss, P2P_IE_VENDOR_TYPE);
	if (!p2p)
		p2p = wpa_bss_get_vendor_ie_beacon(bss, P2P_IE_VENDOR_TYPE);
	if (p2p && bss->ssid_len == P2P_WILDCARD_SSID_LEN &&
	    os_memcmp(bss->ssid, P2P_WILDCARD_SSID, P2P_WILDCARD_SSID_LEN) ==
	    0)
		return 0; /* Do not show P2P listen discovery results here */

	pos = buf;
	end = buf + buflen;

	ret = os_snprintf(pos, end - pos, MACSTR "\t%d\t%d\t",
			  MAC2STR(bss->bssid), bss->freq, bss->level);
	if (ret < 0 || ret >= end - pos)
		return -1;
	pos += ret;
	ie = wpa_bss_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE);
	if (ie)
		pos = wpa_supplicant_ie_txt(pos, end, "WPA", ie, 2 + ie[1]);
	ie2 = wpa_bss_get_ie(bss, WLAN_EID_RSN);
	if (ie2)
		pos = wpa_supplicant_ie_txt(pos, end, "WPA2", ie2, 2 + ie2[1]);
	pos = wpa_supplicant_wps_ie_txt(wpa_s, pos, end, bss);
	if (!ie && !ie2 && bss->caps & IEEE80211_CAP_PRIVACY) {
		ret = os_snprintf(pos, end - pos, "[WEP]");
		if (ret < 0 || ret >= end - pos)
			return -1;
		pos += ret;
	}
	if (bss_is_dmg(bss)) {
		const char *s;
		ret = os_snprintf(pos, end - pos, "[DMG]");
		if (ret < 0 || ret >= end - pos)
			return -1;
		pos += ret;
		switch (bss->caps & IEEE80211_CAP_DMG_MASK) {
		case IEEE80211_CAP_DMG_IBSS:
			s = "[IBSS]";
			break;
		case IEEE80211_CAP_DMG_AP:
			s = "[ESS]";
			break;
		case IEEE80211_CAP_DMG_PBSS:
			s = "[PBSS]";
			break;
		default:
			s = "";
			break;
		}
		ret = os_snprintf(pos, end - pos, "%s", s);
		if (ret < 0 || ret >= end - pos)
			return -1;
		pos += ret;
	} else {
		if (bss->caps & IEEE80211_CAP_IBSS) {
			ret = os_snprintf(pos, end - pos, "[IBSS]");
			if (ret < 0 || ret >= end - pos)
				return -1;
			pos += ret;
		}
		if (bss->caps & IEEE80211_CAP_ESS) {
			ret = os_snprintf(pos, end - pos, "[ESS]");
			if (ret < 0 || ret >= end - pos)
				return -1;
			pos += ret;
		}
	}
	if (p2p) {
		ret = os_snprintf(pos, end - pos, "[P2P]");
		if (ret < 0 || ret >= end - pos)
			return -1;
		pos += ret;
	}
#ifdef CONFIG_HS20
	if (wpa_bss_get_vendor_ie(bss, HS20_IE_VENDOR_TYPE) && ie2) {
		ret = os_snprintf(pos, end - pos, "[HS20]");
		if (ret < 0 || ret >= end - pos)
			return -1;
		pos += ret;
	}
#endif /* CONFIG_HS20 */

	ret = os_snprintf(pos, end - pos, "\t%s",
			  wpa_ssid_txt(bss->ssid, bss->ssid_len));
	if (ret < 0 || ret >= end - pos)
		return -1;
	pos += ret;

	ret = os_snprintf(pos, end - pos, "\n");
	if (ret < 0 || ret >= end - pos)
		return -1;
	pos += ret;

	return pos - buf;
}


static int wpa_supplicant_ctrl_iface_scan_results(
	struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	char *pos, *end;
	struct wpa_bss *bss;
	int ret;

	pos = buf;
	end = buf + buflen;
	ret = os_snprintf(pos, end - pos, "bssid / frequency / signal level / "
			  "flags / ssid\n");
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;

	dl_list_for_each(bss, &wpa_s->bss_id, struct wpa_bss, list_id) {
		ret = wpa_supplicant_ctrl_iface_scan_result(wpa_s, bss, pos,
							    end - pos);
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


static int wpa_supplicant_ctrl_iface_select_network(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int id;
	struct wpa_ssid *ssid;
	char *pos;

	/* cmd: "<network id>" or "any" */
	if (os_strncmp(cmd, "any", 3) == 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: SELECT_NETWORK any");
		ssid = NULL;
	} else {
		id = atoi(cmd);
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: SELECT_NETWORK id=%d", id);

		ssid = wpa_config_get_network(wpa_s->conf, id);
		if (ssid == NULL) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find "
				   "network id=%d", id);
			return -1;
		}
		if (ssid->disabled == 2) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE: Cannot use "
				   "SELECT_NETWORK with persistent P2P group");
			return -1;
		}
	}

	pos = os_strstr(cmd, " freq=");
	if (pos) {
		int *freqs = freq_range_to_channel_list(wpa_s, pos + 6);
		if (freqs) {
			wpa_s->scan_req = MANUAL_SCAN_REQ;
			os_free(wpa_s->manual_scan_freqs);
			wpa_s->manual_scan_freqs = freqs;
		}
	}

	wpa_supplicant_select_network(wpa_s, ssid);

	return 0;
}


static int wpa_supplicant_ctrl_iface_enable_network(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int id;
	struct wpa_ssid *ssid;

	/* cmd: "<network id>" or "all" */
	if (os_strcmp(cmd, "all") == 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: ENABLE_NETWORK all");
		ssid = NULL;
	} else {
		id = atoi(cmd);
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: ENABLE_NETWORK id=%d", id);

		ssid = wpa_config_get_network(wpa_s->conf, id);
		if (ssid == NULL) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find "
				   "network id=%d", id);
			return -1;
		}
		if (ssid->disabled == 2) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE: Cannot use "
				   "ENABLE_NETWORK with persistent P2P group");
			return -1;
		}

		if (os_strstr(cmd, " no-connect")) {
			ssid->disabled = 0;
			return 0;
		}
	}
	wpa_supplicant_enable_network(wpa_s, ssid);

	return 0;
}


static int wpa_supplicant_ctrl_iface_disable_network(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int id;
	struct wpa_ssid *ssid;

	/* cmd: "<network id>" or "all" */
	if (os_strcmp(cmd, "all") == 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: DISABLE_NETWORK all");
		ssid = NULL;
	} else {
		id = atoi(cmd);
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: DISABLE_NETWORK id=%d", id);

		ssid = wpa_config_get_network(wpa_s->conf, id);
		if (ssid == NULL) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find "
				   "network id=%d", id);
			return -1;
		}
		if (ssid->disabled == 2) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE: Cannot use "
				   "DISABLE_NETWORK with persistent P2P "
				   "group");
			return -1;
		}
	}
	wpa_supplicant_disable_network(wpa_s, ssid);

	return 0;
}


static int wpa_supplicant_ctrl_iface_add_network(
	struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	struct wpa_ssid *ssid;
	int ret;

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: ADD_NETWORK");

	ssid = wpa_config_add_network(wpa_s->conf);
	if (ssid == NULL)
		return -1;

	wpas_notify_network_added(wpa_s, ssid);

	ssid->disabled = 1;
	wpa_config_set_network_defaults(ssid);

	ret = os_snprintf(buf, buflen, "%d\n", ssid->id);
	if (ret < 0 || (size_t) ret >= buflen)
		return -1;
	return ret;
}


static int wpa_supplicant_ctrl_iface_remove_network(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int id;
	struct wpa_ssid *ssid;
	int was_disabled;

	/* cmd: "<network id>" or "all" */
	if (os_strcmp(cmd, "all") == 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_NETWORK all");
		if (wpa_s->sched_scanning)
			wpa_supplicant_cancel_sched_scan(wpa_s);

		eapol_sm_invalidate_cached_session(wpa_s->eapol);
		if (wpa_s->current_ssid) {
#ifdef CONFIG_SME
			wpa_s->sme.prev_bssid_set = 0;
#endif /* CONFIG_SME */
			wpa_sm_set_config(wpa_s->wpa, NULL);
			eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
			wpa_supplicant_deauthenticate(
				wpa_s, WLAN_REASON_DEAUTH_LEAVING);
		}
		ssid = wpa_s->conf->ssid;
		while (ssid) {
			struct wpa_ssid *remove_ssid = ssid;
			id = ssid->id;
			ssid = ssid->next;
			wpas_notify_network_removed(wpa_s, remove_ssid);
			wpa_config_remove_network(wpa_s->conf, id);
		}
		return 0;
	}

	id = atoi(cmd);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_NETWORK id=%d", id);

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid)
		wpas_notify_network_removed(wpa_s, ssid);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find network "
			   "id=%d", id);
		return -1;
	}

	if (ssid == wpa_s->current_ssid || wpa_s->current_ssid == NULL) {
#ifdef CONFIG_SME
		wpa_s->sme.prev_bssid_set = 0;
#endif /* CONFIG_SME */
		/*
		 * Invalidate the EAP session cache if the current or
		 * previously used network is removed.
		 */
		eapol_sm_invalidate_cached_session(wpa_s->eapol);
	}

	if (ssid == wpa_s->current_ssid) {
		wpa_sm_set_config(wpa_s->wpa, NULL);
		eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);

		wpa_supplicant_deauthenticate(wpa_s,
					      WLAN_REASON_DEAUTH_LEAVING);
	}

	was_disabled = ssid->disabled;

	if (wpa_config_remove_network(wpa_s->conf, id) < 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Not able to remove the "
			   "network id=%d", id);
		return -1;
	}

	if (!was_disabled && wpa_s->sched_scanning) {
		wpa_printf(MSG_DEBUG, "Stop ongoing sched_scan to remove "
			   "network from filters");
		wpa_supplicant_cancel_sched_scan(wpa_s);
		wpa_supplicant_req_scan(wpa_s, 0, 0);
	}

	return 0;
}


static int wpa_supplicant_ctrl_iface_update_network(
	struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
	char *name, char *value)
{
	if (wpa_config_set(ssid, name, value, 0) < 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Failed to set network "
			   "variable '%s'", name);
		return -1;
	}

	if (os_strcmp(name, "bssid") != 0 &&
	    os_strcmp(name, "priority") != 0)
		wpa_sm_pmksa_cache_flush(wpa_s->wpa, ssid);

	if (wpa_s->current_ssid == ssid || wpa_s->current_ssid == NULL) {
		/*
		 * Invalidate the EAP session cache if anything in the current
		 * or previously used configuration changes.
		 */
		eapol_sm_invalidate_cached_session(wpa_s->eapol);
	}

	if ((os_strcmp(name, "psk") == 0 &&
	     value[0] == '"' && ssid->ssid_len) ||
	    (os_strcmp(name, "ssid") == 0 && ssid->passphrase))
		wpa_config_update_psk(ssid);
	else if (os_strcmp(name, "priority") == 0)
		wpa_config_update_prio_list(wpa_s->conf);

	return 0;
}


static int wpa_supplicant_ctrl_iface_set_network(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int id;
	struct wpa_ssid *ssid;
	char *name, *value;

	/* cmd: "<network id> <variable name> <value>" */
	name = os_strchr(cmd, ' ');
	if (name == NULL)
		return -1;
	*name++ = '\0';

	value = os_strchr(name, ' ');
	if (value == NULL)
		return -1;
	*value++ = '\0';

	id = atoi(cmd);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: SET_NETWORK id=%d name='%s'",
		   id, name);
	wpa_hexdump_ascii_key(MSG_DEBUG, "CTRL_IFACE: value",
			      (u8 *) value, os_strlen(value));

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find network "
			   "id=%d", id);
		return -1;
	}

	return wpa_supplicant_ctrl_iface_update_network(wpa_s, ssid, name,
							value);
}


static int wpa_supplicant_ctrl_iface_get_network(
	struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen)
{
	int id;
	size_t res;
	struct wpa_ssid *ssid;
	char *name, *value;

	/* cmd: "<network id> <variable name>" */
	name = os_strchr(cmd, ' ');
	if (name == NULL || buflen == 0)
		return -1;
	*name++ = '\0';

	id = atoi(cmd);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: GET_NETWORK id=%d name='%s'",
		   id, name);

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find network "
			   "id=%d", id);
		return -1;
	}

	value = wpa_config_get_no_key(ssid, name);
	if (value == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Failed to get network "
			   "variable '%s'", name);
		return -1;
	}

	res = os_strlcpy(buf, value, buflen);
	if (res >= buflen) {
		os_free(value);
		return -1;
	}

	os_free(value);

	return res;
}


static int wpa_supplicant_ctrl_iface_dup_network(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	struct wpa_ssid *ssid_s, *ssid_d;
	char *name, *id, *value;
	int id_s, id_d, ret;

	/* cmd: "<src network id> <dst network id> <variable name>" */
	id = os_strchr(cmd, ' ');
	if (id == NULL)
		return -1;
	*id++ = '\0';

	name = os_strchr(id, ' ');
	if (name == NULL)
		return -1;
	*name++ = '\0';

	id_s = atoi(cmd);
	id_d = atoi(id);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: DUP_NETWORK id=%d -> %d name='%s'",
		   id_s, id_d, name);

	ssid_s = wpa_config_get_network(wpa_s->conf, id_s);
	if (ssid_s == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find "
			   "network id=%d", id_s);
		return -1;
	}

	ssid_d = wpa_config_get_network(wpa_s->conf, id_d);
	if (ssid_d == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find "
			   "network id=%d", id_s);
		return -1;
	}

	value = wpa_config_get(ssid_s, name);
	if (value == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Failed to get network "
			   "variable '%s'", name);
		return -1;
	}

	ret = wpa_supplicant_ctrl_iface_update_network(wpa_s, ssid_d, name,
						       value);

	os_free(value);

	return ret;
}


static int wpa_supplicant_ctrl_iface_list_creds(struct wpa_supplicant *wpa_s,
						char *buf, size_t buflen)
{
	char *pos, *end;
	struct wpa_cred *cred;
	int ret;

	pos = buf;
	end = buf + buflen;
	ret = os_snprintf(pos, end - pos,
			  "cred id / realm / username / domain / imsi\n");
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;

	cred = wpa_s->conf->cred;
	while (cred) {
		ret = os_snprintf(pos, end - pos, "%d\t%s\t%s\t%s\t%s\n",
				  cred->id, cred->realm ? cred->realm : "",
				  cred->username ? cred->username : "",
				  cred->domain ? cred->domain[0] : "",
				  cred->imsi ? cred->imsi : "");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;

		cred = cred->next;
	}

	return pos - buf;
}


static int wpa_supplicant_ctrl_iface_add_cred(struct wpa_supplicant *wpa_s,
					      char *buf, size_t buflen)
{
	struct wpa_cred *cred;
	int ret;

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: ADD_CRED");

	cred = wpa_config_add_cred(wpa_s->conf);
	if (cred == NULL)
		return -1;

	wpa_msg(wpa_s, MSG_INFO, CRED_ADDED "%d", cred->id);

	ret = os_snprintf(buf, buflen, "%d\n", cred->id);
	if (ret < 0 || (size_t) ret >= buflen)
		return -1;
	return ret;
}


static int wpas_ctrl_remove_cred(struct wpa_supplicant *wpa_s,
				 struct wpa_cred *cred)
{
	struct wpa_ssid *ssid;
	char str[20];
	int id;

	if (cred == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find cred");
		return -1;
	}

	id = cred->id;
	if (wpa_config_remove_cred(wpa_s->conf, id) < 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find cred");
		return -1;
	}

	wpa_msg(wpa_s, MSG_INFO, CRED_REMOVED "%d", id);

	/* Remove any network entry created based on the removed credential */
	ssid = wpa_s->conf->ssid;
	while (ssid) {
		if (ssid->parent_cred == cred) {
			wpa_printf(MSG_DEBUG, "Remove network id %d since it "
				   "used the removed credential", ssid->id);
			os_snprintf(str, sizeof(str), "%d", ssid->id);
			ssid = ssid->next;
			wpa_supplicant_ctrl_iface_remove_network(wpa_s, str);
		} else
			ssid = ssid->next;
	}

	return 0;
}


static int wpa_supplicant_ctrl_iface_remove_cred(struct wpa_supplicant *wpa_s,
						 char *cmd)
{
	int id;
	struct wpa_cred *cred, *prev;

	/* cmd: "<cred id>", "all", "sp_fqdn=<FQDN>", or
	 * "provisioning_sp=<FQDN> */
	if (os_strcmp(cmd, "all") == 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_CRED all");
		cred = wpa_s->conf->cred;
		while (cred) {
			prev = cred;
			cred = cred->next;
			wpas_ctrl_remove_cred(wpa_s, prev);
		}
		return 0;
	}

	if (os_strncmp(cmd, "sp_fqdn=", 8) == 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_CRED SP FQDN '%s'",
			   cmd + 8);
		cred = wpa_s->conf->cred;
		while (cred) {
			prev = cred;
			cred = cred->next;
			if (prev->domain) {
				size_t i;
				for (i = 0; i < prev->num_domain; i++) {
					if (os_strcmp(prev->domain[i], cmd + 8)
					    != 0)
						continue;
					wpas_ctrl_remove_cred(wpa_s, prev);
					break;
				}
			}
		}
		return 0;
	}

	if (os_strncmp(cmd, "provisioning_sp=", 16) == 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_CRED provisioning SP FQDN '%s'",
			   cmd + 16);
		cred = wpa_s->conf->cred;
		while (cred) {
			prev = cred;
			cred = cred->next;
			if (prev->provisioning_sp &&
			    os_strcmp(prev->provisioning_sp, cmd + 16) == 0)
				wpas_ctrl_remove_cred(wpa_s, prev);
		}
		return 0;
	}

	id = atoi(cmd);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_CRED id=%d", id);

	cred = wpa_config_get_cred(wpa_s->conf, id);
	return wpas_ctrl_remove_cred(wpa_s, cred);
}


static int wpa_supplicant_ctrl_iface_set_cred(struct wpa_supplicant *wpa_s,
					      char *cmd)
{
	int id;
	struct wpa_cred *cred;
	char *name, *value;

	/* cmd: "<cred id> <variable name> <value>" */
	name = os_strchr(cmd, ' ');
	if (name == NULL)
		return -1;
	*name++ = '\0';

	value = os_strchr(name, ' ');
	if (value == NULL)
		return -1;
	*value++ = '\0';

	id = atoi(cmd);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: SET_CRED id=%d name='%s'",
		   id, name);
	wpa_hexdump_ascii_key(MSG_DEBUG, "CTRL_IFACE: value",
			      (u8 *) value, os_strlen(value));

	cred = wpa_config_get_cred(wpa_s->conf, id);
	if (cred == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find cred id=%d",
			   id);
		return -1;
	}

	if (wpa_config_set_cred(cred, name, value, 0) < 0) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Failed to set cred "
			   "variable '%s'", name);
		return -1;
	}

	wpa_msg(wpa_s, MSG_INFO, CRED_MODIFIED "%d %s", cred->id, name);

	return 0;
}


static int wpa_supplicant_ctrl_iface_get_cred(struct wpa_supplicant *wpa_s,
					      char *cmd, char *buf,
					      size_t buflen)
{
	int id;
	size_t res;
	struct wpa_cred *cred;
	char *name, *value;

	/* cmd: "<cred id> <variable name>" */
	name = os_strchr(cmd, ' ');
	if (name == NULL)
		return -1;
	*name++ = '\0';

	id = atoi(cmd);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: GET_CRED id=%d name='%s'",
		   id, name);

	cred = wpa_config_get_cred(wpa_s->conf, id);
	if (cred == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find cred id=%d",
			   id);
		return -1;
	}

	value = wpa_config_get_cred_no_key(cred, name);
	if (value == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Failed to get cred variable '%s'",
			   name);
		return -1;
	}

	res = os_strlcpy(buf, value, buflen);
	if (res >= buflen) {
		os_free(value);
		return -1;
	}

	os_free(value);

	return res;
}


#ifndef CONFIG_NO_CONFIG_WRITE
static int wpa_supplicant_ctrl_iface_save_config(struct wpa_supplicant *wpa_s)
{
	int ret;

	if (!wpa_s->conf->update_config) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Not allowed "
			   "to update configuration (update_config=0)");
		return -1;
	}

	ret = wpa_config_write(wpa_s->confname, wpa_s->conf);
	if (ret) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Failed to "
			   "update configuration");
	} else {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Configuration"
			   " updated");
	}

	return ret;
}
#endif /* CONFIG_NO_CONFIG_WRITE */


struct cipher_info {
	unsigned int capa;
	const char *name;
	int group_only;
};

static const struct cipher_info ciphers[] = {
	{ WPA_DRIVER_CAPA_ENC_CCMP_256, "CCMP-256", 0 },
	{ WPA_DRIVER_CAPA_ENC_GCMP_256, "GCMP-256", 0 },
	{ WPA_DRIVER_CAPA_ENC_CCMP, "CCMP", 0 },
	{ WPA_DRIVER_CAPA_ENC_GCMP, "GCMP", 0 },
	{ WPA_DRIVER_CAPA_ENC_TKIP, "TKIP", 0 },
	{ WPA_DRIVER_CAPA_KEY_MGMT_WPA_NONE, "NONE", 0 },
	{ WPA_DRIVER_CAPA_ENC_WEP104, "WEP104", 1 },
	{ WPA_DRIVER_CAPA_ENC_WEP40, "WEP40", 1 }
};


static int ctrl_iface_get_capability_pairwise(int res, char *strict,
					      struct wpa_driver_capa *capa,
					      char *buf, size_t buflen)
{
	int ret;
	char *pos, *end;
	size_t len;
	unsigned int i;

	pos = buf;
	end = pos + buflen;

	if (res < 0) {
		if (strict)
			return 0;
		len = os_strlcpy(buf, "CCMP TKIP NONE", buflen);
		if (len >= buflen)
			return -1;
		return len;
	}

	for (i = 0; i < ARRAY_SIZE(ciphers); i++) {
		if (!ciphers[i].group_only && capa->enc & ciphers[i].capa) {
			ret = os_snprintf(pos, end - pos, "%s%s",
					  pos == buf ? "" : " ",
					  ciphers[i].name);
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;
		}
	}

	return pos - buf;
}


static int ctrl_iface_get_capability_group(int res, char *strict,
					   struct wpa_driver_capa *capa,
					   char *buf, size_t buflen)
{
	int ret;
	char *pos, *end;
	size_t len;
	unsigned int i;

	pos = buf;
	end = pos + buflen;

	if (res < 0) {
		if (strict)
			return 0;
		len = os_strlcpy(buf, "CCMP TKIP WEP104 WEP40", buflen);
		if (len >= buflen)
			return -1;
		return len;
	}

	for (i = 0; i < ARRAY_SIZE(ciphers); i++) {
		if (capa->enc & ciphers[i].capa) {
			ret = os_snprintf(pos, end - pos, "%s%s",
					  pos == buf ? "" : " ",
					  ciphers[i].name);
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;
		}
	}

	return pos - buf;
}


static int ctrl_iface_get_capability_key_mgmt(int res, char *strict,
					      struct wpa_driver_capa *capa,
					      char *buf, size_t buflen)
{
	int ret;
	char *pos, *end;
	size_t len;

	pos = buf;
	end = pos + buflen;

	if (res < 0) {
		if (strict)
			return 0;
		len = os_strlcpy(buf, "WPA-PSK WPA-EAP IEEE8021X WPA-NONE "
				 "NONE", buflen);
		if (len >= buflen)
			return -1;
		return len;
	}

	ret = os_snprintf(pos, end - pos, "NONE IEEE8021X");
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;

	if (capa->key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA |
			      WPA_DRIVER_CAPA_KEY_MGMT_WPA2)) {
		ret = os_snprintf(pos, end - pos, " WPA-EAP");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	if (capa->key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
			      WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK)) {
		ret = os_snprintf(pos, end - pos, " WPA-PSK");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	if (capa->key_mgmt & WPA_DRIVER_CAPA_KEY_MGMT_WPA_NONE) {
		ret = os_snprintf(pos, end - pos, " WPA-NONE");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


static int ctrl_iface_get_capability_proto(int res, char *strict,
					   struct wpa_driver_capa *capa,
					   char *buf, size_t buflen)
{
	int ret;
	char *pos, *end;
	size_t len;

	pos = buf;
	end = pos + buflen;

	if (res < 0) {
		if (strict)
			return 0;
		len = os_strlcpy(buf, "RSN WPA", buflen);
		if (len >= buflen)
			return -1;
		return len;
	}

	if (capa->key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
			      WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK)) {
		ret = os_snprintf(pos, end - pos, "%sRSN",
				  pos == buf ? "" : " ");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	if (capa->key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA |
			      WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK)) {
		ret = os_snprintf(pos, end - pos, "%sWPA",
				  pos == buf ? "" : " ");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


static int ctrl_iface_get_capability_auth_alg(int res, char *strict,
					      struct wpa_driver_capa *capa,
					      char *buf, size_t buflen)
{
	int ret;
	char *pos, *end;
	size_t len;

	pos = buf;
	end = pos + buflen;

	if (res < 0) {
		if (strict)
			return 0;
		len = os_strlcpy(buf, "OPEN SHARED LEAP", buflen);
		if (len >= buflen)
			return -1;
		return len;
	}

	if (capa->auth & (WPA_DRIVER_AUTH_OPEN)) {
		ret = os_snprintf(pos, end - pos, "%sOPEN",
				  pos == buf ? "" : " ");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	if (capa->auth & (WPA_DRIVER_AUTH_SHARED)) {
		ret = os_snprintf(pos, end - pos, "%sSHARED",
				  pos == buf ? "" : " ");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	if (capa->auth & (WPA_DRIVER_AUTH_LEAP)) {
		ret = os_snprintf(pos, end - pos, "%sLEAP",
				  pos == buf ? "" : " ");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


static int ctrl_iface_get_capability_modes(int res, char *strict,
					   struct wpa_driver_capa *capa,
					   char *buf, size_t buflen)
{
	int ret;
	char *pos, *end;
	size_t len;

	pos = buf;
	end = pos + buflen;

	if (res < 0) {
		if (strict)
			return 0;
		len = os_strlcpy(buf, "IBSS AP", buflen);
		if (len >= buflen)
			return -1;
		return len;
	}

	if (capa->flags & WPA_DRIVER_FLAGS_IBSS) {
		ret = os_snprintf(pos, end - pos, "%sIBSS",
				  pos == buf ? "" : " ");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	if (capa->flags & WPA_DRIVER_FLAGS_AP) {
		ret = os_snprintf(pos, end - pos, "%sAP",
				  pos == buf ? "" : " ");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


static int ctrl_iface_get_capability_channels(struct wpa_supplicant *wpa_s,
					      char *buf, size_t buflen)
{
	struct hostapd_channel_data *chnl;
	int ret, i, j;
	char *pos, *end, *hmode;

	pos = buf;
	end = pos + buflen;

	for (j = 0; j < wpa_s->hw.num_modes; j++) {
		switch (wpa_s->hw.modes[j].mode) {
		case HOSTAPD_MODE_IEEE80211B:
			hmode = "B";
			break;
		case HOSTAPD_MODE_IEEE80211G:
			hmode = "G";
			break;
		case HOSTAPD_MODE_IEEE80211A:
			hmode = "A";
			break;
		case HOSTAPD_MODE_IEEE80211AD:
			hmode = "AD";
			break;
		default:
			continue;
		}
		ret = os_snprintf(pos, end - pos, "Mode[%s] Channels:", hmode);
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
		chnl = wpa_s->hw.modes[j].channels;
		for (i = 0; i < wpa_s->hw.modes[j].num_channels; i++) {
			if (chnl[i].flag & HOSTAPD_CHAN_DISABLED)
				continue;
			ret = os_snprintf(pos, end - pos, " %d", chnl[i].chan);
			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;
		}
		ret = os_snprintf(pos, end - pos, "\n");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


static int ctrl_iface_get_capability_freq(struct wpa_supplicant *wpa_s,
					  char *buf, size_t buflen)
{
	struct hostapd_channel_data *chnl;
	int ret, i, j;
	char *pos, *end, *hmode;

	pos = buf;
	end = pos + buflen;

	for (j = 0; j < wpa_s->hw.num_modes; j++) {
		switch (wpa_s->hw.modes[j].mode) {
		case HOSTAPD_MODE_IEEE80211B:
			hmode = "B";
			break;
		case HOSTAPD_MODE_IEEE80211G:
			hmode = "G";
			break;
		case HOSTAPD_MODE_IEEE80211A:
			hmode = "A";
			break;
		case HOSTAPD_MODE_IEEE80211AD:
			hmode = "AD";
			break;
		default:
			continue;
		}
		ret = os_snprintf(pos, end - pos, "Mode[%s] Channels:\n",
				  hmode);
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
		chnl = wpa_s->hw.modes[j].channels;
		for (i = 0; i < wpa_s->hw.modes[j].num_channels; i++) {
			if (chnl[i].flag & HOSTAPD_CHAN_DISABLED)
				continue;
			ret = os_snprintf(pos, end - pos, " %d = %d MHz%s%s\n",
					  chnl[i].chan, chnl[i].freq,
					  chnl[i].flag & HOSTAPD_CHAN_NO_IBSS ?
					  " (NO_IBSS)" : "",
					  chnl[i].flag & HOSTAPD_CHAN_RADAR ?
					  " (DFS)" : "");

			if (ret < 0 || ret >= end - pos)
				return pos - buf;
			pos += ret;
		}
		ret = os_snprintf(pos, end - pos, "\n");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


static int wpa_supplicant_ctrl_iface_get_capability(
	struct wpa_supplicant *wpa_s, const char *_field, char *buf,
	size_t buflen)
{
	struct wpa_driver_capa capa;
	int res;
	char *strict;
	char field[30];
	size_t len;

	/* Determine whether or not strict checking was requested */
	len = os_strlcpy(field, _field, sizeof(field));
	if (len >= sizeof(field))
		return -1;
	strict = os_strchr(field, ' ');
	if (strict != NULL) {
		*strict++ = '\0';
		if (os_strcmp(strict, "strict") != 0)
			return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: GET_CAPABILITY '%s' %s",
		field, strict ? strict : "");

	if (os_strcmp(field, "eap") == 0) {
		return eap_get_names(buf, buflen);
	}

	res = wpa_drv_get_capa(wpa_s, &capa);

	if (os_strcmp(field, "pairwise") == 0)
		return ctrl_iface_get_capability_pairwise(res, strict, &capa,
							  buf, buflen);

	if (os_strcmp(field, "group") == 0)
		return ctrl_iface_get_capability_group(res, strict, &capa,
						       buf, buflen);

	if (os_strcmp(field, "key_mgmt") == 0)
		return ctrl_iface_get_capability_key_mgmt(res, strict, &capa,
							  buf, buflen);

	if (os_strcmp(field, "proto") == 0)
		return ctrl_iface_get_capability_proto(res, strict, &capa,
						       buf, buflen);

	if (os_strcmp(field, "auth_alg") == 0)
		return ctrl_iface_get_capability_auth_alg(res, strict, &capa,
							  buf, buflen);

	if (os_strcmp(field, "modes") == 0)
		return ctrl_iface_get_capability_modes(res, strict, &capa,
						       buf, buflen);

	if (os_strcmp(field, "channels") == 0)
		return ctrl_iface_get_capability_channels(wpa_s, buf, buflen);

	if (os_strcmp(field, "freq") == 0)
		return ctrl_iface_get_capability_freq(wpa_s, buf, buflen);

#ifdef CONFIG_TDLS
	if (os_strcmp(field, "tdls") == 0)
		return ctrl_iface_get_capability_tdls(wpa_s, buf, buflen);
#endif /* CONFIG_TDLS */

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: Unknown GET_CAPABILITY field '%s'",
		   field);

	return -1;
}


#ifdef CONFIG_INTERWORKING
static char * anqp_add_hex(char *pos, char *end, const char *title,
			   struct wpabuf *data)
{
	char *start = pos;
	size_t i;
	int ret;
	const u8 *d;

	if (data == NULL)
		return start;

	ret = os_snprintf(pos, end - pos, "%s=", title);
	if (ret < 0 || ret >= end - pos)
		return start;
	pos += ret;

	d = wpabuf_head_u8(data);
	for (i = 0; i < wpabuf_len(data); i++) {
		ret = os_snprintf(pos, end - pos, "%02x", *d++);
		if (ret < 0 || ret >= end - pos)
			return start;
		pos += ret;
	}

	ret = os_snprintf(pos, end - pos, "\n");
	if (ret < 0 || ret >= end - pos)
		return start;
	pos += ret;

	return pos;
}
#endif /* CONFIG_INTERWORKING */


static int print_bss_info(struct wpa_supplicant *wpa_s, struct wpa_bss *bss,
			  unsigned long mask, char *buf, size_t buflen)
{
	size_t i;
	int ret;
	char *pos, *end;
	const u8 *ie, *ie2;

	pos = buf;
	end = buf + buflen;

	if (mask & WPA_BSS_MASK_ID) {
		ret = os_snprintf(pos, end - pos, "id=%u\n", bss->id);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_BSSID) {
		ret = os_snprintf(pos, end - pos, "bssid=" MACSTR "\n",
				  MAC2STR(bss->bssid));
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_FREQ) {
		ret = os_snprintf(pos, end - pos, "freq=%d\n", bss->freq);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_BEACON_INT) {
		ret = os_snprintf(pos, end - pos, "beacon_int=%d\n",
				  bss->beacon_int);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_CAPABILITIES) {
		ret = os_snprintf(pos, end - pos, "capabilities=0x%04x\n",
				  bss->caps);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_QUAL) {
		ret = os_snprintf(pos, end - pos, "qual=%d\n", bss->qual);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_NOISE) {
		ret = os_snprintf(pos, end - pos, "noise=%d\n", bss->noise);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_LEVEL) {
		ret = os_snprintf(pos, end - pos, "level=%d\n", bss->level);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_TSF) {
		ret = os_snprintf(pos, end - pos, "tsf=%016llu\n",
				  (unsigned long long) bss->tsf);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_AGE) {
		struct os_reltime now;

		os_get_reltime(&now);
		ret = os_snprintf(pos, end - pos, "age=%d\n",
				  (int) (now.sec - bss->last_update.sec));
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_IE) {
		ret = os_snprintf(pos, end - pos, "ie=");
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;

		ie = (const u8 *) (bss + 1);
		for (i = 0; i < bss->ie_len; i++) {
			ret = os_snprintf(pos, end - pos, "%02x", *ie++);
			if (ret < 0 || ret >= end - pos)
				return 0;
			pos += ret;
		}

		ret = os_snprintf(pos, end - pos, "\n");
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_FLAGS) {
		ret = os_snprintf(pos, end - pos, "flags=");
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;

		ie = wpa_bss_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE);
		if (ie)
			pos = wpa_supplicant_ie_txt(pos, end, "WPA", ie,
						    2 + ie[1]);
		ie2 = wpa_bss_get_ie(bss, WLAN_EID_RSN);
		if (ie2)
			pos = wpa_supplicant_ie_txt(pos, end, "WPA2", ie2,
						    2 + ie2[1]);
		pos = wpa_supplicant_wps_ie_txt(wpa_s, pos, end, bss);
		if (!ie && !ie2 && bss->caps & IEEE80211_CAP_PRIVACY) {
			ret = os_snprintf(pos, end - pos, "[WEP]");
			if (ret < 0 || ret >= end - pos)
				return 0;
			pos += ret;
		}
		if (bss_is_dmg(bss)) {
			const char *s;
			ret = os_snprintf(pos, end - pos, "[DMG]");
			if (ret < 0 || ret >= end - pos)
				return 0;
			pos += ret;
			switch (bss->caps & IEEE80211_CAP_DMG_MASK) {
			case IEEE80211_CAP_DMG_IBSS:
				s = "[IBSS]";
				break;
			case IEEE80211_CAP_DMG_AP:
				s = "[ESS]";
				break;
			case IEEE80211_CAP_DMG_PBSS:
				s = "[PBSS]";
				break;
			default:
				s = "";
				break;
			}
			ret = os_snprintf(pos, end - pos, "%s", s);
			if (ret < 0 || ret >= end - pos)
				return 0;
			pos += ret;
		} else {
			if (bss->caps & IEEE80211_CAP_IBSS) {
				ret = os_snprintf(pos, end - pos, "[IBSS]");
				if (ret < 0 || ret >= end - pos)
					return 0;
				pos += ret;
			}
			if (bss->caps & IEEE80211_CAP_ESS) {
				ret = os_snprintf(pos, end - pos, "[ESS]");
				if (ret < 0 || ret >= end - pos)
					return 0;
				pos += ret;
			}
		}
		if (wpa_bss_get_vendor_ie(bss, P2P_IE_VENDOR_TYPE) ||
		    wpa_bss_get_vendor_ie_beacon(bss, P2P_IE_VENDOR_TYPE)) {
			ret = os_snprintf(pos, end - pos, "[P2P]");
			if (ret < 0 || ret >= end - pos)
				return 0;
			pos += ret;
		}
#ifdef CONFIG_HS20
		if (wpa_bss_get_vendor_ie(bss, HS20_IE_VENDOR_TYPE)) {
			ret = os_snprintf(pos, end - pos, "[HS20]");
			if (ret < 0 || ret >= end - pos)
				return 0;
			pos += ret;
		}
#endif /* CONFIG_HS20 */

		ret = os_snprintf(pos, end - pos, "\n");
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	if (mask & WPA_BSS_MASK_SSID) {
		ret = os_snprintf(pos, end - pos, "ssid=%s\n",
				  wpa_ssid_txt(bss->ssid, bss->ssid_len));
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

#ifdef CONFIG_WPS
	if (mask & WPA_BSS_MASK_WPS_SCAN) {
		ie = (const u8 *) (bss + 1);
		ret = wpas_wps_scan_result_text(ie, bss->ie_len, pos, end);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}
#endif /* CONFIG_WPS */

#ifdef CONFIG_P2P
	if (mask & WPA_BSS_MASK_P2P_SCAN) {
		ie = (const u8 *) (bss + 1);
		ret = wpas_p2p_scan_result_text(ie, bss->ie_len, pos, end);
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}
#endif /* CONFIG_P2P */

#ifdef CONFIG_WIFI_DISPLAY
	if (mask & WPA_BSS_MASK_WIFI_DISPLAY) {
		struct wpabuf *wfd;
		ie = (const u8 *) (bss + 1);
		wfd = ieee802_11_vendor_ie_concat(ie, bss->ie_len,
						  WFD_IE_VENDOR_TYPE);
		if (wfd) {
			ret = os_snprintf(pos, end - pos, "wfd_subelems=");
			if (ret < 0 || ret >= end - pos) {
				wpabuf_free(wfd);
				return 0;
			}
			pos += ret;

			pos += wpa_snprintf_hex(pos, end - pos,
						wpabuf_head(wfd),
						wpabuf_len(wfd));
			wpabuf_free(wfd);

			ret = os_snprintf(pos, end - pos, "\n");
			if (ret < 0 || ret >= end - pos)
				return 0;
			pos += ret;
		}
	}
#endif /* CONFIG_WIFI_DISPLAY */

#ifdef CONFIG_INTERWORKING
	if ((mask & WPA_BSS_MASK_INTERNETW) && bss->anqp) {
		struct wpa_bss_anqp *anqp = bss->anqp;
		pos = anqp_add_hex(pos, end, "anqp_venue_name",
				   anqp->venue_name);
		pos = anqp_add_hex(pos, end, "anqp_network_auth_type",
				   anqp->network_auth_type);
		pos = anqp_add_hex(pos, end, "anqp_roaming_consortium",
				   anqp->roaming_consortium);
		pos = anqp_add_hex(pos, end, "anqp_ip_addr_type_availability",
				   anqp->ip_addr_type_availability);
		pos = anqp_add_hex(pos, end, "anqp_nai_realm",
				   anqp->nai_realm);
		pos = anqp_add_hex(pos, end, "anqp_3gpp", anqp->anqp_3gpp);
		pos = anqp_add_hex(pos, end, "anqp_domain_name",
				   anqp->domain_name);
#ifdef CONFIG_HS20
		pos = anqp_add_hex(pos, end, "hs20_operator_friendly_name",
				   anqp->hs20_operator_friendly_name);
		pos = anqp_add_hex(pos, end, "hs20_wan_metrics",
				   anqp->hs20_wan_metrics);
		pos = anqp_add_hex(pos, end, "hs20_connection_capability",
				   anqp->hs20_connection_capability);
		pos = anqp_add_hex(pos, end, "hs20_operating_class",
				   anqp->hs20_operating_class);
		pos = anqp_add_hex(pos, end, "hs20_osu_providers_list",
				   anqp->hs20_osu_providers_list);
#endif /* CONFIG_HS20 */
	}
#endif /* CONFIG_INTERWORKING */

	if (mask & WPA_BSS_MASK_DELIM) {
		ret = os_snprintf(pos, end - pos, "====\n");
		if (ret < 0 || ret >= end - pos)
			return 0;
		pos += ret;
	}

	return pos - buf;
}


static int wpa_supplicant_ctrl_iface_bss(struct wpa_supplicant *wpa_s,
					 const char *cmd, char *buf,
					 size_t buflen)
{
	u8 bssid[ETH_ALEN];
	size_t i;
	struct wpa_bss *bss;
	struct wpa_bss *bsslast = NULL;
	struct dl_list *next;
	int ret = 0;
	int len;
	char *ctmp;
	unsigned long mask = WPA_BSS_MASK_ALL;

	if (os_strncmp(cmd, "RANGE=", 6) == 0) {
		if (os_strncmp(cmd + 6, "ALL", 3) == 0) {
			bss = dl_list_first(&wpa_s->bss_id, struct wpa_bss,
					    list_id);
			bsslast = dl_list_last(&wpa_s->bss_id, struct wpa_bss,
					       list_id);
		} else { /* N1-N2 */
			unsigned int id1, id2;

			if ((ctmp = os_strchr(cmd + 6, '-')) == NULL) {
				wpa_printf(MSG_INFO, "Wrong BSS range "
					   "format");
				return 0;
			}

			if (*(cmd + 6) == '-')
				id1 = 0;
			else
				id1 = atoi(cmd + 6);
			ctmp++;
			if (*ctmp >= '0' && *ctmp <= '9')
				id2 = atoi(ctmp);
			else
				id2 = (unsigned int) -1;
			bss = wpa_bss_get_id_range(wpa_s, id1, id2);
			if (id2 == (unsigned int) -1)
				bsslast = dl_list_last(&wpa_s->bss_id,
						       struct wpa_bss,
						       list_id);
			else {
				bsslast = wpa_bss_get_id(wpa_s, id2);
				if (bsslast == NULL && bss && id2 > id1) {
					struct wpa_bss *tmp = bss;
					for (;;) {
						next = tmp->list_id.next;
						if (next == &wpa_s->bss_id)
							break;
						tmp = dl_list_entry(
							next, struct wpa_bss,
							list_id);
						if (tmp->id > id2)
							break;
						bsslast = tmp;
					}
				}
			}
		}
	} else if (os_strncmp(cmd, "FIRST", 5) == 0)
		bss = dl_list_first(&wpa_s->bss_id, struct wpa_bss, list_id);
	else if (os_strncmp(cmd, "LAST", 4) == 0)
		bss = dl_list_last(&wpa_s->bss_id, struct wpa_bss, list_id);
	else if (os_strncmp(cmd, "ID-", 3) == 0) {
		i = atoi(cmd + 3);
		bss = wpa_bss_get_id(wpa_s, i);
	} else if (os_strncmp(cmd, "NEXT-", 5) == 0) {
		i = atoi(cmd + 5);
		bss = wpa_bss_get_id(wpa_s, i);
		if (bss) {
			next = bss->list_id.next;
			if (next == &wpa_s->bss_id)
				bss = NULL;
			else
				bss = dl_list_entry(next, struct wpa_bss,
						    list_id);
		}
#ifdef CONFIG_P2P
	} else if (os_strncmp(cmd, "p2p_dev_addr=", 13) == 0) {
		if (hwaddr_aton(cmd + 13, bssid) == 0)
			bss = wpa_bss_get_p2p_dev_addr(wpa_s, bssid);
		else
			bss = NULL;
#endif /* CONFIG_P2P */
	} else if (hwaddr_aton(cmd, bssid) == 0)
		bss = wpa_bss_get_bssid(wpa_s, bssid);
	else {
		struct wpa_bss *tmp;
		i = atoi(cmd);
		bss = NULL;
		dl_list_for_each(tmp, &wpa_s->bss_id, struct wpa_bss, list_id)
		{
			if (i-- == 0) {
				bss = tmp;
				break;
			}
		}
	}

	if ((ctmp = os_strstr(cmd, "MASK=")) != NULL) {
		mask = strtoul(ctmp + 5, NULL, 0x10);
		if (mask == 0)
			mask = WPA_BSS_MASK_ALL;
	}

	if (bss == NULL)
		return 0;

	if (bsslast == NULL)
		bsslast = bss;
	do {
		len = print_bss_info(wpa_s, bss, mask, buf, buflen);
		ret += len;
		buf += len;
		buflen -= len;
		if (bss == bsslast) {
			if ((mask & WPA_BSS_MASK_DELIM) && len &&
			    (bss == dl_list_last(&wpa_s->bss_id,
						 struct wpa_bss, list_id)))
				os_snprintf(buf - 5, 5, "####\n");
			break;
		}
		next = bss->list_id.next;
		if (next == &wpa_s->bss_id)
			break;
		bss = dl_list_entry(next, struct wpa_bss, list_id);
	} while (bss && len);

	return ret;
}


static int wpa_supplicant_ctrl_iface_ap_scan(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int ap_scan = atoi(cmd);
	return wpa_supplicant_set_ap_scan(wpa_s, ap_scan);
}


static int wpa_supplicant_ctrl_iface_scan_interval(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int scan_int = atoi(cmd);
	return wpa_supplicant_set_scan_interval(wpa_s, scan_int);
}


static int wpa_supplicant_ctrl_iface_bss_expire_age(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int expire_age = atoi(cmd);
	return wpa_supplicant_set_bss_expiration_age(wpa_s, expire_age);
}


static int wpa_supplicant_ctrl_iface_bss_expire_count(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int expire_count = atoi(cmd);
	return wpa_supplicant_set_bss_expiration_count(wpa_s, expire_count);
}


static int wpa_supplicant_ctrl_iface_bss_flush(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	int flush_age = atoi(cmd);

	if (flush_age == 0)
		wpa_bss_flush(wpa_s);
	else
		wpa_bss_flush_by_age(wpa_s, flush_age);
	return 0;
}


#ifdef CONFIG_TESTING_OPTIONS
static void wpa_supplicant_ctrl_iface_drop_sa(struct wpa_supplicant *wpa_s)
{
	wpa_printf(MSG_DEBUG, "Dropping SA without deauthentication");
	/* MLME-DELETEKEYS.request */
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, NULL, 0, 0, NULL, 0, NULL, 0);
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, NULL, 1, 0, NULL, 0, NULL, 0);
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, NULL, 2, 0, NULL, 0, NULL, 0);
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, NULL, 3, 0, NULL, 0, NULL, 0);
#ifdef CONFIG_IEEE80211W
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, NULL, 4, 0, NULL, 0, NULL, 0);
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, NULL, 5, 0, NULL, 0, NULL, 0);
#endif /* CONFIG_IEEE80211W */

	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, wpa_s->bssid, 0, 0, NULL, 0, NULL,
			0);
	/* MLME-SETPROTECTION.request(None) */
	wpa_drv_mlme_setprotection(wpa_s, wpa_s->bssid,
				   MLME_SETPROTECTION_PROTECT_TYPE_NONE,
				   MLME_SETPROTECTION_KEY_TYPE_PAIRWISE);
	wpa_sm_drop_sa(wpa_s->wpa);
}
#endif /* CONFIG_TESTING_OPTIONS */


static int wpa_supplicant_ctrl_iface_roam(struct wpa_supplicant *wpa_s,
					  char *addr)
{
#ifdef CONFIG_NO_SCAN_PROCESSING
	return -1;
#else /* CONFIG_NO_SCAN_PROCESSING */
	u8 bssid[ETH_ALEN];
	struct wpa_bss *bss;
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (hwaddr_aton(addr, bssid)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE ROAM: invalid "
			   "address '%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE ROAM " MACSTR, MAC2STR(bssid));

	if (!ssid) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE ROAM: No network "
			   "configuration known for the target AP");
		return -1;
	}

	bss = wpa_bss_get(wpa_s, bssid, ssid->ssid, ssid->ssid_len);
	if (!bss) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE ROAM: Target AP not found "
			   "from BSS table");
		return -1;
	}

	/*
	 * TODO: Find best network configuration block from configuration to
	 * allow roaming to other networks
	 */

	wpa_s->reassociate = 1;
	wpa_supplicant_connect(wpa_s, bss, ssid);

	return 0;
#endif /* CONFIG_NO_SCAN_PROCESSING */
}


#ifdef CONFIG_P2P
static int p2p_ctrl_find(struct wpa_supplicant *wpa_s, char *cmd)
{
	unsigned int timeout = atoi(cmd);
	enum p2p_discovery_type type = P2P_FIND_START_WITH_FULL;
	u8 dev_id[ETH_ALEN], *_dev_id = NULL;
	u8 dev_type[WPS_DEV_TYPE_LEN], *_dev_type = NULL;
	char *pos;
	unsigned int search_delay;

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		wpa_dbg(wpa_s, MSG_INFO,
			"Reject P2P_FIND since interface is disabled");
		return -1;
	}
	if (os_strstr(cmd, "type=social"))
		type = P2P_FIND_ONLY_SOCIAL;
	else if (os_strstr(cmd, "type=progressive"))
		type = P2P_FIND_PROGRESSIVE;

	pos = os_strstr(cmd, "dev_id=");
	if (pos) {
		pos += 7;
		if (hwaddr_aton(pos, dev_id))
			return -1;
		_dev_id = dev_id;
	}

	pos = os_strstr(cmd, "dev_type=");
	if (pos) {
		pos += 9;
		if (wps_dev_type_str2bin(pos, dev_type) < 0)
			return -1;
		_dev_type = dev_type;
	}

	pos = os_strstr(cmd, "delay=");
	if (pos) {
		pos += 6;
		search_delay = atoi(pos);
	} else
		search_delay = wpas_p2p_search_delay(wpa_s);

	return wpas_p2p_find(wpa_s, timeout, type, _dev_type != NULL, _dev_type,
			     _dev_id, search_delay);
}


static int p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd,
			    char *buf, size_t buflen)
{
	u8 addr[ETH_ALEN];
	char *pos, *pos2;
	char *pin = NULL;
	enum p2p_wps_method wps_method;
	int new_pin;
	int ret;
	int persistent_group, persistent_id = -1;
	int join;
	int auth;
	int automatic;
	int go_intent = -1;
	int freq = 0;
	int pd;
	int ht40, vht;

	/* <addr> <"pbc" | "pin" | PIN> [label|display|keypad]
	 * [persistent|persistent=<network id>]
	 * [join] [auth] [go_intent=<0..15>] [freq=<in MHz>] [provdisc]
	 * [ht40] [vht] */

	if (hwaddr_aton(cmd, addr))
		return -1;

	pos = cmd + 17;
	if (*pos != ' ')
		return -1;
	pos++;

	persistent_group = os_strstr(pos, " persistent") != NULL;
	pos2 = os_strstr(pos, " persistent=");
	if (pos2) {
		struct wpa_ssid *ssid;
		persistent_id = atoi(pos2 + 12);
		ssid = wpa_config_get_network(wpa_s->conf, persistent_id);
		if (ssid == NULL || ssid->disabled != 2 ||
		    ssid->mode != WPAS_MODE_P2P_GO) {
			wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find "
				   "SSID id=%d for persistent P2P group (GO)",
				   persistent_id);
			return -1;
		}
	}
	join = os_strstr(pos, " join") != NULL;
	auth = os_strstr(pos, " auth") != NULL;
	automatic = os_strstr(pos, " auto") != NULL;
	pd = os_strstr(pos, " provdisc") != NULL;
	vht = (os_strstr(cmd, " vht") != NULL) || wpa_s->conf->p2p_go_vht;
	ht40 = (os_strstr(cmd, " ht40") != NULL) || wpa_s->conf->p2p_go_ht40 ||
		vht;

	pos2 = os_strstr(pos, " go_intent=");
	if (pos2) {
		pos2 += 11;
		go_intent = atoi(pos2);
		if (go_intent < 0 || go_intent > 15)
			return -1;
	}

	pos2 = os_strstr(pos, " freq=");
	if (pos2) {
		pos2 += 6;
		freq = atoi(pos2);
		if (freq <= 0)
			return -1;
	}

	if (os_strncmp(pos, "pin", 3) == 0) {
		/* Request random PIN (to be displayed) and enable the PIN */
		wps_method = WPS_PIN_DISPLAY;
	} else if (os_strncmp(pos, "pbc", 3) == 0) {
		wps_method = WPS_PBC;
	} else {
		pin = pos;
		pos = os_strchr(pin, ' ');
		wps_method = WPS_PIN_KEYPAD;
		if (pos) {
			*pos++ = '\0';
			if (os_strncmp(pos, "display", 7) == 0)
				wps_method = WPS_PIN_DISPLAY;
		}
		if (!wps_pin_str_valid(pin)) {
			os_memcpy(buf, "FAIL-INVALID-PIN\n", 17);
			return 17;
		}
	}

	new_pin = wpas_p2p_connect(wpa_s, addr, pin, wps_method,
				   persistent_group, automatic, join,
				   auth, go_intent, freq, persistent_id, pd,
				   ht40, vht);
	if (new_pin == -2) {
		os_memcpy(buf, "FAIL-CHANNEL-UNAVAILABLE\n", 25);
		return 25;
	}
	if (new_pin == -3) {
		os_memcpy(buf, "FAIL-CHANNEL-UNSUPPORTED\n", 25);
		return 25;
	}
	if (new_pin < 0)
		return -1;
	if (wps_method == WPS_PIN_DISPLAY && pin == NULL) {
		ret = os_snprintf(buf, buflen, "%08d", new_pin);
		if (ret < 0 || (size_t) ret >= buflen)
			return -1;
		return ret;
	}

	os_memcpy(buf, "OK\n", 3);
	return 3;
}


static int p2p_ctrl_listen(struct wpa_supplicant *wpa_s, char *cmd)
{
	unsigned int timeout = atoi(cmd);
	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		wpa_dbg(wpa_s, MSG_INFO,
			"Reject P2P_LISTEN since interface is disabled");
		return -1;
	}
	return wpas_p2p_listen(wpa_s, timeout);
}


static int p2p_ctrl_prov_disc(struct wpa_supplicant *wpa_s, char *cmd)
{
	u8 addr[ETH_ALEN];
	char *pos;
	enum wpas_p2p_prov_disc_use use = WPAS_P2P_PD_FOR_GO_NEG;

	/* <addr> <config method> [join|auto] */

	if (hwaddr_aton(cmd, addr))
		return -1;

	pos = cmd + 17;
	if (*pos != ' ')
		return -1;
	pos++;

	if (os_strstr(pos, " join") != NULL)
		use = WPAS_P2P_PD_FOR_JOIN;
	else if (os_strstr(pos, " auto") != NULL)
		use = WPAS_P2P_PD_AUTO;

	return wpas_p2p_prov_disc(wpa_s, addr, pos, use);
}


static int p2p_get_passphrase(struct wpa_supplicant *wpa_s, char *buf,
			      size_t buflen)
{
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (ssid == NULL || ssid->mode != WPAS_MODE_P2P_GO ||
	    ssid->passphrase == NULL)
		return -1;

	os_strlcpy(buf, ssid->passphrase, buflen);
	return os_strlen(buf);
}


static int p2p_ctrl_serv_disc_req(struct wpa_supplicant *wpa_s, char *cmd,
				  char *buf, size_t buflen)
{
	u64 ref;
	int res;
	u8 dst_buf[ETH_ALEN], *dst;
	struct wpabuf *tlvs;
	char *pos;
	size_t len;

	if (hwaddr_aton(cmd, dst_buf))
		return -1;
	dst = dst_buf;
	if (dst[0] == 0 && dst[1] == 0 && dst[2] == 0 &&
	    dst[3] == 0 && dst[4] == 0 && dst[5] == 0)
		dst = NULL;
	pos = cmd + 17;
	if (*pos != ' ')
		return -1;
	pos++;

	if (os_strncmp(pos, "upnp ", 5) == 0) {
		u8 version;
		pos += 5;
		if (hexstr2bin(pos, &version, 1) < 0)
			return -1;
		pos += 2;
		if (*pos != ' ')
			return -1;
		pos++;
		ref = wpas_p2p_sd_request_upnp(wpa_s, dst, version, pos);
#ifdef CONFIG_WIFI_DISPLAY
	} else if (os_strncmp(pos, "wifi-display ", 13) == 0) {
		ref = wpas_p2p_sd_request_wifi_display(wpa_s, dst, pos + 13);
#endif /* CONFIG_WIFI_DISPLAY */
	} else {
		len = os_strlen(pos);
		if (len & 1)
			return -1;
		len /= 2;
		tlvs = wpabuf_alloc(len);
		if (tlvs == NULL)
			return -1;
		if (hexstr2bin(pos, wpabuf_put(tlvs, len), len) < 0) {
			wpabuf_free(tlvs);
			return -1;
		}

		ref = wpas_p2p_sd_request(wpa_s, dst, tlvs);
		wpabuf_free(tlvs);
	}
	if (ref == 0)
		return -1;
	res = os_snprintf(buf, buflen, "%llx", (long long unsigned) ref);
	if (res < 0 || (unsigned) res >= buflen)
		return -1;
	return res;
}


static int p2p_ctrl_serv_disc_cancel_req(struct wpa_supplicant *wpa_s,
					 char *cmd)
{
	long long unsigned val;
	u64 req;
	if (sscanf(cmd, "%llx", &val) != 1)
		return -1;
	req = val;
	return wpas_p2p_sd_cancel_request(wpa_s, req);
}


static int p2p_ctrl_serv_disc_resp(struct wpa_supplicant *wpa_s, char *cmd)
{
	int freq;
	u8 dst[ETH_ALEN];
	u8 dialog_token;
	struct wpabuf *resp_tlvs;
	char *pos, *pos2;
	size_t len;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';
	freq = atoi(cmd);
	if (freq == 0)
		return -1;

	if (hwaddr_aton(pos, dst))
		return -1;
	pos += 17;
	if (*pos != ' ')
		return -1;
	pos++;

	pos2 = os_strchr(pos, ' ');
	if (pos2 == NULL)
		return -1;
	*pos2++ = '\0';
	dialog_token = atoi(pos);

	len = os_strlen(pos2);
	if (len & 1)
		return -1;
	len /= 2;
	resp_tlvs = wpabuf_alloc(len);
	if (resp_tlvs == NULL)
		return -1;
	if (hexstr2bin(pos2, wpabuf_put(resp_tlvs, len), len) < 0) {
		wpabuf_free(resp_tlvs);
		return -1;
	}

	wpas_p2p_sd_response(wpa_s, freq, dst, dialog_token, resp_tlvs);
	wpabuf_free(resp_tlvs);
	return 0;
}


static int p2p_ctrl_serv_disc_external(struct wpa_supplicant *wpa_s,
				       char *cmd)
{
	if (os_strcmp(cmd, "0") && os_strcmp(cmd, "1"))
		return -1;
	wpa_s->p2p_sd_over_ctrl_iface = atoi(cmd);
	return 0;
}


static int p2p_ctrl_service_add_bonjour(struct wpa_supplicant *wpa_s,
					char *cmd)
{
	char *pos;
	size_t len;
	struct wpabuf *query, *resp;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';

	len = os_strlen(cmd);
	if (len & 1)
		return -1;
	len /= 2;
	query = wpabuf_alloc(len);
	if (query == NULL)
		return -1;
	if (hexstr2bin(cmd, wpabuf_put(query, len), len) < 0) {
		wpabuf_free(query);
		return -1;
	}

	len = os_strlen(pos);
	if (len & 1) {
		wpabuf_free(query);
		return -1;
	}
	len /= 2;
	resp = wpabuf_alloc(len);
	if (resp == NULL) {
		wpabuf_free(query);
		return -1;
	}
	if (hexstr2bin(pos, wpabuf_put(resp, len), len) < 0) {
		wpabuf_free(query);
		wpabuf_free(resp);
		return -1;
	}

	if (wpas_p2p_service_add_bonjour(wpa_s, query, resp) < 0) {
		wpabuf_free(query);
		wpabuf_free(resp);
		return -1;
	}
	return 0;
}


static int p2p_ctrl_service_add_upnp(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos;
	u8 version;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';

	if (hexstr2bin(cmd, &version, 1) < 0)
		return -1;

	return wpas_p2p_service_add_upnp(wpa_s, version, pos);
}


static int p2p_ctrl_service_add(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';

	if (os_strcmp(cmd, "bonjour") == 0)
		return p2p_ctrl_service_add_bonjour(wpa_s, pos);
	if (os_strcmp(cmd, "upnp") == 0)
		return p2p_ctrl_service_add_upnp(wpa_s, pos);
	wpa_printf(MSG_DEBUG, "Unknown service '%s'", cmd);
	return -1;
}


static int p2p_ctrl_service_del_bonjour(struct wpa_supplicant *wpa_s,
					char *cmd)
{
	size_t len;
	struct wpabuf *query;
	int ret;

	len = os_strlen(cmd);
	if (len & 1)
		return -1;
	len /= 2;
	query = wpabuf_alloc(len);
	if (query == NULL)
		return -1;
	if (hexstr2bin(cmd, wpabuf_put(query, len), len) < 0) {
		wpabuf_free(query);
		return -1;
	}

	ret = wpas_p2p_service_del_bonjour(wpa_s, query);
	wpabuf_free(query);
	return ret;
}


static int p2p_ctrl_service_del_upnp(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos;
	u8 version;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';

	if (hexstr2bin(cmd, &version, 1) < 0)
		return -1;

	return wpas_p2p_service_del_upnp(wpa_s, version, pos);
}


static int p2p_ctrl_service_del(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos;

	pos = os_strchr(cmd, ' ');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';

	if (os_strcmp(cmd, "bonjour") == 0)
		return p2p_ctrl_service_del_bonjour(wpa_s, pos);
	if (os_strcmp(cmd, "upnp") == 0)
		return p2p_ctrl_service_del_upnp(wpa_s, pos);
	wpa_printf(MSG_DEBUG, "Unknown service '%s'", cmd);
	return -1;
}


static int p2p_ctrl_reject(struct wpa_supplicant *wpa_s, char *cmd)
{
	u8 addr[ETH_ALEN];

	/* <addr> */

	if (hwaddr_aton(cmd, addr))
		return -1;

	return wpas_p2p_reject(wpa_s, addr);
}


static int p2p_ctrl_invite_persistent(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos;
	int id;
	struct wpa_ssid *ssid;
	u8 *_peer = NULL, peer[ETH_ALEN];
	int freq = 0, pref_freq = 0;
	int ht40, vht;

	id = atoi(cmd);
	pos = os_strstr(cmd, " peer=");
	if (pos) {
		pos += 6;
		if (hwaddr_aton(pos, peer))
			return -1;
		_peer = peer;
	}
	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL || ssid->disabled != 2) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find SSID id=%d "
			   "for persistent P2P group",
			   id);
		return -1;
	}

	pos = os_strstr(cmd, " freq=");
	if (pos) {
		pos += 6;
		freq = atoi(pos);
		if (freq <= 0)
			return -1;
	}

	pos = os_strstr(cmd, " pref=");
	if (pos) {
		pos += 6;
		pref_freq = atoi(pos);
		if (pref_freq <= 0)
			return -1;
	}

	vht = (os_strstr(cmd, " vht") != NULL) || wpa_s->conf->p2p_go_vht;
	ht40 = (os_strstr(cmd, " ht40") != NULL) || wpa_s->conf->p2p_go_ht40 ||
		vht;

	return wpas_p2p_invite(wpa_s, _peer, ssid, NULL, freq, ht40, vht,
			       pref_freq);
}


static int p2p_ctrl_invite_group(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos;
	u8 peer[ETH_ALEN], go_dev_addr[ETH_ALEN], *go_dev = NULL;

	pos = os_strstr(cmd, " peer=");
	if (!pos)
		return -1;

	*pos = '\0';
	pos += 6;
	if (hwaddr_aton(pos, peer)) {
		wpa_printf(MSG_DEBUG, "P2P: Invalid MAC address '%s'", pos);
		return -1;
	}

	pos = os_strstr(pos, " go_dev_addr=");
	if (pos) {
		pos += 13;
		if (hwaddr_aton(pos, go_dev_addr)) {
			wpa_printf(MSG_DEBUG, "P2P: Invalid MAC address '%s'",
				   pos);
			return -1;
		}
		go_dev = go_dev_addr;
	}

	return wpas_p2p_invite_group(wpa_s, cmd, peer, go_dev);
}


static int p2p_ctrl_invite(struct wpa_supplicant *wpa_s, char *cmd)
{
	if (os_strncmp(cmd, "persistent=", 11) == 0)
		return p2p_ctrl_invite_persistent(wpa_s, cmd + 11);
	if (os_strncmp(cmd, "group=", 6) == 0)
		return p2p_ctrl_invite_group(wpa_s, cmd + 6);

	return -1;
}


static int p2p_ctrl_group_add_persistent(struct wpa_supplicant *wpa_s,
					 char *cmd, int freq, int ht40,
					 int vht)
{
	int id;
	struct wpa_ssid *ssid;

	id = atoi(cmd);
	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL || ssid->disabled != 2) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find SSID id=%d "
			   "for persistent P2P group",
			   id);
		return -1;
	}

	return wpas_p2p_group_add_persistent(wpa_s, ssid, 0, freq, 0, ht40, vht,
					     NULL, 0);
}


static int p2p_ctrl_group_add(struct wpa_supplicant *wpa_s, char *cmd)
{
	int freq = 0, ht40, vht;
	char *pos;

	pos = os_strstr(cmd, "freq=");
	if (pos)
		freq = atoi(pos + 5);

	vht = (os_strstr(cmd, "vht") != NULL) || wpa_s->conf->p2p_go_vht;
	ht40 = (os_strstr(cmd, "ht40") != NULL) || wpa_s->conf->p2p_go_ht40 ||
		vht;

	if (os_strncmp(cmd, "persistent=", 11) == 0)
		return p2p_ctrl_group_add_persistent(wpa_s, cmd + 11, freq,
						     ht40, vht);
	if (os_strcmp(cmd, "persistent") == 0 ||
	    os_strncmp(cmd, "persistent ", 11) == 0)
		return wpas_p2p_group_add(wpa_s, 1, freq, ht40, vht);
	if (os_strncmp(cmd, "freq=", 5) == 0)
		return wpas_p2p_group_add(wpa_s, 0, freq, ht40, vht);
	if (ht40)
		return wpas_p2p_group_add(wpa_s, 0, freq, ht40, vht);

	wpa_printf(MSG_DEBUG, "CTRL: Invalid P2P_GROUP_ADD parameters '%s'",
		   cmd);
	return -1;
}


static int p2p_ctrl_peer(struct wpa_supplicant *wpa_s, char *cmd,
			 char *buf, size_t buflen)
{
	u8 addr[ETH_ALEN], *addr_ptr;
	int next, res;
	const struct p2p_peer_info *info;
	char *pos, *end;
	char devtype[WPS_DEV_TYPE_BUFSIZE];
	struct wpa_ssid *ssid;
	size_t i;

	if (!wpa_s->global->p2p)
		return -1;

	if (os_strcmp(cmd, "FIRST") == 0) {
		addr_ptr = NULL;
		next = 0;
	} else if (os_strncmp(cmd, "NEXT-", 5) == 0) {
		if (hwaddr_aton(cmd + 5, addr) < 0)
			return -1;
		addr_ptr = addr;
		next = 1;
	} else {
		if (hwaddr_aton(cmd, addr) < 0)
			return -1;
		addr_ptr = addr;
		next = 0;
	}

	info = p2p_get_peer_info(wpa_s->global->p2p, addr_ptr, next);
	if (info == NULL)
		return -1;

	pos = buf;
	end = buf + buflen;

	res = os_snprintf(pos, end - pos, MACSTR "\n"
			  "pri_dev_type=%s\n"
			  "device_name=%s\n"
			  "manufacturer=%s\n"
			  "model_name=%s\n"
			  "model_number=%s\n"
			  "serial_number=%s\n"
			  "config_methods=0x%x\n"
			  "dev_capab=0x%x\n"
			  "group_capab=0x%x\n"
			  "level=%d\n",
			  MAC2STR(info->p2p_device_addr),
			  wps_dev_type_bin2str(info->pri_dev_type,
					       devtype, sizeof(devtype)),
			  info->device_name,
			  info->manufacturer,
			  info->model_name,
			  info->model_number,
			  info->serial_number,
			  info->config_methods,
			  info->dev_capab,
			  info->group_capab,
			  info->level);
	if (res < 0 || res >= end - pos)
		return pos - buf;
	pos += res;

	for (i = 0; i < info->wps_sec_dev_type_list_len / WPS_DEV_TYPE_LEN; i++)
	{
		const u8 *t;
		t = &info->wps_sec_dev_type_list[i * WPS_DEV_TYPE_LEN];
		res = os_snprintf(pos, end - pos, "sec_dev_type=%s\n",
				  wps_dev_type_bin2str(t, devtype,
						       sizeof(devtype)));
		if (res < 0 || res >= end - pos)
			return pos - buf;
		pos += res;
	}

	ssid = wpas_p2p_get_persistent(wpa_s, info->p2p_device_addr, NULL, 0);
	if (ssid) {
		res = os_snprintf(pos, end - pos, "persistent=%d\n", ssid->id);
		if (res < 0 || res >= end - pos)
			return pos - buf;
		pos += res;
	}

	res = p2p_get_peer_info_txt(info, pos, end - pos);
	if (res < 0)
		return pos - buf;
	pos += res;

	return pos - buf;
}


static int p2p_ctrl_disallow_freq(struct wpa_supplicant *wpa_s,
				  const char *param)
{
	unsigned int i;

	if (wpa_s->global->p2p == NULL)
		return -1;

	if (freq_range_list_parse(&wpa_s->global->p2p_disallow_freq, param) < 0)
		return -1;

	for (i = 0; i < wpa_s->global->p2p_disallow_freq.num; i++) {
		struct wpa_freq_range *freq;
		freq = &wpa_s->global->p2p_disallow_freq.range[i];
		wpa_printf(MSG_DEBUG, "P2P: Disallowed frequency range %u-%u",
			   freq->min, freq->max);
	}

	wpas_p2p_update_channel_list(wpa_s);
	return 0;
}


static int p2p_ctrl_set(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *param;

	if (wpa_s->global->p2p == NULL)
		return -1;

	param = os_strchr(cmd, ' ');
	if (param == NULL)
		return -1;
	*param++ = '\0';

	if (os_strcmp(cmd, "discoverability") == 0) {
		p2p_set_client_discoverability(wpa_s->global->p2p,
					       atoi(param));
		return 0;
	}

	if (os_strcmp(cmd, "managed") == 0) {
		p2p_set_managed_oper(wpa_s->global->p2p, atoi(param));
		return 0;
	}

	if (os_strcmp(cmd, "listen_channel") == 0) {
		return p2p_set_listen_channel(wpa_s->global->p2p, 81,
					      atoi(param));
	}

	if (os_strcmp(cmd, "ssid_postfix") == 0) {
		return p2p_set_ssid_postfix(wpa_s->global->p2p, (u8 *) param,
					    os_strlen(param));
	}

	if (os_strcmp(cmd, "noa") == 0) {
		char *pos;
		int count, start, duration;
		/* GO NoA parameters: count,start_offset(ms),duration(ms) */
		count = atoi(param);
		pos = os_strchr(param, ',');
		if (pos == NULL)
			return -1;
		pos++;
		start = atoi(pos);
		pos = os_strchr(pos, ',');
		if (pos == NULL)
			return -1;
		pos++;
		duration = atoi(pos);
		if (count < 0 || count > 255 || start < 0 || duration < 0)
			return -1;
		if (count == 0 && duration > 0)
			return -1;
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: P2P_SET GO NoA: count=%d "
			   "start=%d duration=%d", count, start, duration);
		return wpas_p2p_set_noa(wpa_s, count, start, duration);
	}

	if (os_strcmp(cmd, "ps") == 0)
		return wpa_drv_set_p2p_powersave(wpa_s, atoi(param), -1, -1);

	if (os_strcmp(cmd, "oppps") == 0)
		return wpa_drv_set_p2p_powersave(wpa_s, -1, atoi(param), -1);

	if (os_strcmp(cmd, "ctwindow") == 0)
		return wpa_drv_set_p2p_powersave(wpa_s, -1, -1, atoi(param));

	if (os_strcmp(cmd, "disabled") == 0) {
		wpa_s->global->p2p_disabled = atoi(param);
		wpa_printf(MSG_DEBUG, "P2P functionality %s",
			   wpa_s->global->p2p_disabled ?
			   "disabled" : "enabled");
		if (wpa_s->global->p2p_disabled) {
			wpas_p2p_stop_find(wpa_s);
			os_memset(wpa_s->p2p_auth_invite, 0, ETH_ALEN);
			p2p_flush(wpa_s->global->p2p);
		}
		return 0;
	}

	if (os_strcmp(cmd, "conc_pref") == 0) {
		if (os_strcmp(param, "sta") == 0)
			wpa_s->global->conc_pref = WPA_CONC_PREF_STA;
		else if (os_strcmp(param, "p2p") == 0)
			wpa_s->global->conc_pref = WPA_CONC_PREF_P2P;
		else {
			wpa_printf(MSG_INFO, "Invalid conc_pref value");
			return -1;
		}
		wpa_printf(MSG_DEBUG, "Single channel concurrency preference: "
			   "%s", param);
		return 0;
	}

	if (os_strcmp(cmd, "force_long_sd") == 0) {
		wpa_s->force_long_sd = atoi(param);
		return 0;
	}

	if (os_strcmp(cmd, "peer_filter") == 0) {
		u8 addr[ETH_ALEN];
		if (hwaddr_aton(param, addr))
			return -1;
		p2p_set_peer_filter(wpa_s->global->p2p, addr);
		return 0;
	}

	if (os_strcmp(cmd, "cross_connect") == 0)
		return wpas_p2p_set_cross_connect(wpa_s, atoi(param));

	if (os_strcmp(cmd, "go_apsd") == 0) {
		if (os_strcmp(param, "disable") == 0)
			wpa_s->set_ap_uapsd = 0;
		else {
			wpa_s->set_ap_uapsd = 1;
			wpa_s->ap_uapsd = atoi(param);
		}
		return 0;
	}

	if (os_strcmp(cmd, "client_apsd") == 0) {
		if (os_strcmp(param, "disable") == 0)
			wpa_s->set_sta_uapsd = 0;
		else {
			int be, bk, vi, vo;
			char *pos;
			/* format: BE,BK,VI,VO;max SP Length */
			be = atoi(param);
			pos = os_strchr(param, ',');
			if (pos == NULL)
				return -1;
			pos++;
			bk = atoi(pos);
			pos = os_strchr(pos, ',');
			if (pos == NULL)
				return -1;
			pos++;
			vi = atoi(pos);
			pos = os_strchr(pos, ',');
			if (pos == NULL)
				return -1;
			pos++;
			vo = atoi(pos);
			/* ignore max SP Length for now */

			wpa_s->set_sta_uapsd = 1;
			wpa_s->sta_uapsd = 0;
			if (be)
				wpa_s->sta_uapsd |= BIT(0);
			if (bk)
				wpa_s->sta_uapsd |= BIT(1);
			if (vi)
				wpa_s->sta_uapsd |= BIT(2);
			if (vo)
				wpa_s->sta_uapsd |= BIT(3);
		}
		return 0;
	}

	if (os_strcmp(cmd, "disallow_freq") == 0)
		return p2p_ctrl_disallow_freq(wpa_s, param);

	if (os_strcmp(cmd, "disc_int") == 0) {
		int min_disc_int, max_disc_int, max_disc_tu;
		char *pos;

		pos = param;

		min_disc_int = atoi(pos);
		pos = os_strchr(pos, ' ');
		if (pos == NULL)
			return -1;
		*pos++ = '\0';

		max_disc_int = atoi(pos);
		pos = os_strchr(pos, ' ');
		if (pos == NULL)
			return -1;
		*pos++ = '\0';

		max_disc_tu = atoi(pos);

		return p2p_set_disc_int(wpa_s->global->p2p, min_disc_int,
					max_disc_int, max_disc_tu);
	}

	if (os_strcmp(cmd, "per_sta_psk") == 0) {
		wpa_s->global->p2p_per_sta_psk = !!atoi(param);
		return 0;
	}

#ifdef CONFIG_WPS_NFC
	if (os_strcmp(cmd, "nfc_tag") == 0)
		return wpas_p2p_nfc_tag_enabled(wpa_s, !!atoi(param));
#endif /* CONFIG_WPS_NFC */

	if (os_strcmp(cmd, "disable_ip_addr_req") == 0) {
		wpa_s->p2p_disable_ip_addr_req = !!atoi(param);
		return 0;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: Unknown P2P_SET field value '%s'",
		   cmd);

	return -1;
}


static void p2p_ctrl_flush(struct wpa_supplicant *wpa_s)
{
	os_memset(wpa_s->p2p_auth_invite, 0, ETH_ALEN);
	wpa_s->force_long_sd = 0;
	if (wpa_s->global->p2p)
		p2p_flush(wpa_s->global->p2p);
}


static int p2p_ctrl_presence_req(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos, *pos2;
	unsigned int dur1 = 0, int1 = 0, dur2 = 0, int2 = 0;

	if (cmd[0]) {
		pos = os_strchr(cmd, ' ');
		if (pos == NULL)
			return -1;
		*pos++ = '\0';
		dur1 = atoi(cmd);

		pos2 = os_strchr(pos, ' ');
		if (pos2)
			*pos2++ = '\0';
		int1 = atoi(pos);
	} else
		pos2 = NULL;

	if (pos2) {
		pos = os_strchr(pos2, ' ');
		if (pos == NULL)
			return -1;
		*pos++ = '\0';
		dur2 = atoi(pos2);
		int2 = atoi(pos);
	}

	return wpas_p2p_presence_req(wpa_s, dur1, int1, dur2, int2);
}


static int p2p_ctrl_ext_listen(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos;
	unsigned int period = 0, interval = 0;

	if (cmd[0]) {
		pos = os_strchr(cmd, ' ');
		if (pos == NULL)
			return -1;
		*pos++ = '\0';
		period = atoi(cmd);
		interval = atoi(pos);
	}

	return wpas_p2p_ext_listen(wpa_s, period, interval);
}


static int p2p_ctrl_remove_client(struct wpa_supplicant *wpa_s, const char *cmd)
{
	const char *pos;
	u8 peer[ETH_ALEN];
	int iface_addr = 0;

	pos = cmd;
	if (os_strncmp(pos, "iface=", 6) == 0) {
		iface_addr = 1;
		pos += 6;
	}
	if (hwaddr_aton(pos, peer))
		return -1;

	wpas_p2p_remove_client(wpa_s, peer, iface_addr);
	return 0;
}

#endif /* CONFIG_P2P */


static int * freq_range_to_channel_list(struct wpa_supplicant *wpa_s, char *val)
{
	struct wpa_freq_range_list ranges;
	int *freqs = NULL;
	struct hostapd_hw_modes *mode;
	u16 i;

	if (wpa_s->hw.modes == NULL)
		return NULL;

	os_memset(&ranges, 0, sizeof(ranges));
	if (freq_range_list_parse(&ranges, val) < 0)
		return NULL;

	for (i = 0; i < wpa_s->hw.num_modes; i++) {
		int j;

		mode = &wpa_s->hw.modes[i];
		for (j = 0; j < mode->num_channels; j++) {
			unsigned int freq;

			if (mode->channels[j].flag & HOSTAPD_CHAN_DISABLED)
				continue;

			freq = mode->channels[j].freq;
			if (!freq_range_list_includes(&ranges, freq))
				continue;

			int_array_add_unique(&freqs, freq);
		}
	}

	os_free(ranges.range);
	return freqs;
}


#ifdef CONFIG_INTERWORKING

static int ctrl_interworking_select(struct wpa_supplicant *wpa_s, char *param)
{
	int auto_sel = 0;
	int *freqs = NULL;

	if (param) {
		char *pos;

		auto_sel = os_strstr(param, "auto") != NULL;

		pos = os_strstr(param, "freq=");
		if (pos) {
			freqs = freq_range_to_channel_list(wpa_s, pos + 5);
			if (freqs == NULL)
				return -1;
		}

	}

	return interworking_select(wpa_s, auto_sel, freqs);
}


static int ctrl_interworking_connect(struct wpa_supplicant *wpa_s, char *dst)
{
	u8 bssid[ETH_ALEN];
	struct wpa_bss *bss;

	if (hwaddr_aton(dst, bssid)) {
		wpa_printf(MSG_DEBUG, "Invalid BSSID '%s'", dst);
		return -1;
	}

	bss = wpa_bss_get_bssid(wpa_s, bssid);
	if (bss == NULL) {
		wpa_printf(MSG_DEBUG, "Could not find BSS " MACSTR,
			   MAC2STR(bssid));
		return -1;
	}

	return interworking_connect(wpa_s, bss);
}


static int get_anqp(struct wpa_supplicant *wpa_s, char *dst)
{
	u8 dst_addr[ETH_ALEN];
	int used;
	char *pos;
#define MAX_ANQP_INFO_ID 100
	u16 id[MAX_ANQP_INFO_ID];
	size_t num_id = 0;
	u32 subtypes = 0;

	used = hwaddr_aton2(dst, dst_addr);
	if (used < 0)
		return -1;
	pos = dst + used;
	while (num_id < MAX_ANQP_INFO_ID) {
		if (os_strncmp(pos, "hs20:", 5) == 0) {
#ifdef CONFIG_HS20
			int num = atoi(pos + 5);
			if (num <= 0 || num > 31)
				return -1;
			subtypes |= BIT(num);
#else /* CONFIG_HS20 */
			return -1;
#endif /* CONFIG_HS20 */
		} else {
			id[num_id] = atoi(pos);
			if (id[num_id])
				num_id++;
		}
		pos = os_strchr(pos + 1, ',');
		if (pos == NULL)
			break;
		pos++;
	}

	if (num_id == 0)
		return -1;

	return anqp_send_req(wpa_s, dst_addr, id, num_id, subtypes);
}


static int gas_request(struct wpa_supplicant *wpa_s, char *cmd)
{
	u8 dst_addr[ETH_ALEN];
	struct wpabuf *advproto, *query = NULL;
	int used, ret = -1;
	char *pos, *end;
	size_t len;

	used = hwaddr_aton2(cmd, dst_addr);
	if (used < 0)
		return -1;

	pos = cmd + used;
	while (*pos == ' ')
		pos++;

	/* Advertisement Protocol ID */
	end = os_strchr(pos, ' ');
	if (end)
		len = end - pos;
	else
		len = os_strlen(pos);
	if (len & 0x01)
		return -1;
	len /= 2;
	if (len == 0)
		return -1;
	advproto = wpabuf_alloc(len);
	if (advproto == NULL)
		return -1;
	if (hexstr2bin(pos, wpabuf_put(advproto, len), len) < 0)
		goto fail;

	if (end) {
		/* Optional Query Request */
		pos = end + 1;
		while (*pos == ' ')
			pos++;

		len = os_strlen(pos);
		if (len) {
			if (len & 0x01)
				goto fail;
			len /= 2;
			if (len == 0)
				goto fail;
			query = wpabuf_alloc(len);
			if (query == NULL)
				goto fail;
			if (hexstr2bin(pos, wpabuf_put(query, len), len) < 0)
				goto fail;
		}
	}

	ret = gas_send_request(wpa_s, dst_addr, advproto, query);

fail:
	wpabuf_free(advproto);
	wpabuf_free(query);

	return ret;
}


static int gas_response_get(struct wpa_supplicant *wpa_s, char *cmd, char *buf,
			    size_t buflen)
{
	u8 addr[ETH_ALEN];
	int dialog_token;
	int used;
	char *pos;
	size_t resp_len, start, requested_len;
	struct wpabuf *resp;
	int ret;

	used = hwaddr_aton2(cmd, addr);
	if (used < 0)
		return -1;

	pos = cmd + used;
	while (*pos == ' ')
		pos++;
	dialog_token = atoi(pos);

	if (wpa_s->last_gas_resp &&
	    os_memcmp(addr, wpa_s->last_gas_addr, ETH_ALEN) == 0 &&
	    dialog_token == wpa_s->last_gas_dialog_token)
		resp = wpa_s->last_gas_resp;
	else if (wpa_s->prev_gas_resp &&
		 os_memcmp(addr, wpa_s->prev_gas_addr, ETH_ALEN) == 0 &&
		 dialog_token == wpa_s->prev_gas_dialog_token)
		resp = wpa_s->prev_gas_resp;
	else
		return -1;

	resp_len = wpabuf_len(resp);
	start = 0;
	requested_len = resp_len;

	pos = os_strchr(pos, ' ');
	if (pos) {
		start = atoi(pos);
		if (start > resp_len)
			return os_snprintf(buf, buflen, "FAIL-Invalid range");
		pos = os_strchr(pos, ',');
		if (pos == NULL)
			return -1;
		pos++;
		requested_len = atoi(pos);
		if (start + requested_len > resp_len)
			return os_snprintf(buf, buflen, "FAIL-Invalid range");
	}

	if (requested_len * 2 + 1 > buflen)
		return os_snprintf(buf, buflen, "FAIL-Too long response");

	ret = wpa_snprintf_hex(buf, buflen, wpabuf_head_u8(resp) + start,
			       requested_len);

	if (start + requested_len == resp_len) {
		/*
		 * Free memory by dropping the response after it has been
		 * fetched.
		 */
		if (resp == wpa_s->prev_gas_resp) {
			wpabuf_free(wpa_s->prev_gas_resp);
			wpa_s->prev_gas_resp = NULL;
		} else {
			wpabuf_free(wpa_s->last_gas_resp);
			wpa_s->last_gas_resp = NULL;
		}
	}

	return ret;
}
#endif /* CONFIG_INTERWORKING */


#ifdef CONFIG_HS20

static int get_hs20_anqp(struct wpa_supplicant *wpa_s, char *dst)
{
	u8 dst_addr[ETH_ALEN];
	int used;
	char *pos;
	u32 subtypes = 0;

	used = hwaddr_aton2(dst, dst_addr);
	if (used < 0)
		return -1;
	pos = dst + used;
	for (;;) {
		int num = atoi(pos);
		if (num <= 0 || num > 31)
			return -1;
		subtypes |= BIT(num);
		pos = os_strchr(pos + 1, ',');
		if (pos == NULL)
			break;
		pos++;
	}

	if (subtypes == 0)
		return -1;

	return hs20_anqp_send_req(wpa_s, dst_addr, subtypes, NULL, 0);
}


static int hs20_nai_home_realm_list(struct wpa_supplicant *wpa_s,
				    const u8 *addr, const char *realm)
{
	u8 *buf;
	size_t rlen, len;
	int ret;

	rlen = os_strlen(realm);
	len = 3 + rlen;
	buf = os_malloc(len);
	if (buf == NULL)
		return -1;
	buf[0] = 1; /* NAI Home Realm Count */
	buf[1] = 0; /* Formatted in accordance with RFC 4282 */
	buf[2] = rlen;
	os_memcpy(buf + 3, realm, rlen);

	ret = hs20_anqp_send_req(wpa_s, addr,
				 BIT(HS20_STYPE_NAI_HOME_REALM_QUERY),
				 buf, len);

	os_free(buf);

	return ret;
}


static int hs20_get_nai_home_realm_list(struct wpa_supplicant *wpa_s,
					char *dst)
{
	struct wpa_cred *cred = wpa_s->conf->cred;
	u8 dst_addr[ETH_ALEN];
	int used;
	u8 *buf;
	size_t len;
	int ret;

	used = hwaddr_aton2(dst, dst_addr);
	if (used < 0)
		return -1;

	while (dst[used] == ' ')
		used++;
	if (os_strncmp(dst + used, "realm=", 6) == 0)
		return hs20_nai_home_realm_list(wpa_s, dst_addr,
						dst + used + 6);

	len = os_strlen(dst + used);

	if (len == 0 && cred && cred->realm)
		return hs20_nai_home_realm_list(wpa_s, dst_addr, cred->realm);

	if (len % 1)
		return -1;
	len /= 2;
	buf = os_malloc(len);
	if (buf == NULL)
		return -1;
	if (hexstr2bin(dst + used, buf, len) < 0) {
		os_free(buf);
		return -1;
	}

	ret = hs20_anqp_send_req(wpa_s, dst_addr,
				 BIT(HS20_STYPE_NAI_HOME_REALM_QUERY),
				 buf, len);
	os_free(buf);

	return ret;
}


static int hs20_icon_request(struct wpa_supplicant *wpa_s, char *cmd)
{
	u8 dst_addr[ETH_ALEN];
	int used;
	char *icon;

	used = hwaddr_aton2(cmd, dst_addr);
	if (used < 0)
		return -1;

	while (cmd[used] == ' ')
		used++;
	icon = &cmd[used];

	wpa_s->fetch_osu_icon_in_progress = 0;
	return hs20_anqp_send_req(wpa_s, dst_addr, BIT(HS20_STYPE_ICON_REQUEST),
				  (u8 *) icon, os_strlen(icon));
}

#endif /* CONFIG_HS20 */


static int wpa_supplicant_ctrl_iface_sta_autoconnect(
	struct wpa_supplicant *wpa_s, char *cmd)
{
	wpa_s->auto_reconnect_disabled = atoi(cmd) == 0 ? 1 : 0;
	return 0;
}


#ifdef CONFIG_AUTOSCAN

static int wpa_supplicant_ctrl_iface_autoscan(struct wpa_supplicant *wpa_s,
					      char *cmd)
{
	enum wpa_states state = wpa_s->wpa_state;
	char *new_params = NULL;

	if (os_strlen(cmd) > 0) {
		new_params = os_strdup(cmd);
		if (new_params == NULL)
			return -1;
	}

	os_free(wpa_s->conf->autoscan);
	wpa_s->conf->autoscan = new_params;

	if (wpa_s->conf->autoscan == NULL)
		autoscan_deinit(wpa_s);
	else if (state == WPA_DISCONNECTED || state == WPA_INACTIVE)
		autoscan_init(wpa_s, 1);
	else if (state == WPA_SCANNING)
		wpa_supplicant_reinit_autoscan(wpa_s);

	return 0;
}

#endif /* CONFIG_AUTOSCAN */


#ifdef CONFIG_WNM

static int wpas_ctrl_iface_wnm_sleep(struct wpa_supplicant *wpa_s, char *cmd)
{
	int enter;
	int intval = 0;
	char *pos;
	int ret;
	struct wpabuf *tfs_req = NULL;

	if (os_strncmp(cmd, "enter", 5) == 0)
		enter = 1;
	else if (os_strncmp(cmd, "exit", 4) == 0)
		enter = 0;
	else
		return -1;

	pos = os_strstr(cmd, " interval=");
	if (pos)
		intval = atoi(pos + 10);

	pos = os_strstr(cmd, " tfs_req=");
	if (pos) {
		char *end;
		size_t len;
		pos += 9;
		end = os_strchr(pos, ' ');
		if (end)
			len = end - pos;
		else
			len = os_strlen(pos);
		if (len & 1)
			return -1;
		len /= 2;
		tfs_req = wpabuf_alloc(len);
		if (tfs_req == NULL)
			return -1;
		if (hexstr2bin(pos, wpabuf_put(tfs_req, len), len) < 0) {
			wpabuf_free(tfs_req);
			return -1;
		}
	}

	ret = ieee802_11_send_wnmsleep_req(wpa_s, enter ? WNM_SLEEP_MODE_ENTER :
					   WNM_SLEEP_MODE_EXIT, intval,
					   tfs_req);
	wpabuf_free(tfs_req);

	return ret;
}


static int wpas_ctrl_iface_wnm_bss_query(struct wpa_supplicant *wpa_s, char *cmd)
{
	int query_reason;

	query_reason = atoi(cmd);

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: WNM_BSS_QUERY query_reason=%d",
		   query_reason);

	return wnm_send_bss_transition_mgmt_query(wpa_s, query_reason);
}

#endif /* CONFIG_WNM */


/* Get string representation of channel width */
static const char * channel_width_name(enum chan_width width)
{
	switch (width) {
	case CHAN_WIDTH_20_NOHT:
		return "20 MHz (no HT)";
	case CHAN_WIDTH_20:
		return "20 MHz";
	case CHAN_WIDTH_40:
		return "40 MHz";
	case CHAN_WIDTH_80:
		return "80 MHz";
	case CHAN_WIDTH_80P80:
		return "80+80 MHz";
	case CHAN_WIDTH_160:
		return "160 MHz";
	default:
		return "unknown";
	}
}


static int wpa_supplicant_signal_poll(struct wpa_supplicant *wpa_s, char *buf,
				      size_t buflen)
{
	struct wpa_signal_info si;
	int ret;
	char *pos, *end;

	ret = wpa_drv_signal_poll(wpa_s, &si);
	if (ret)
		return -1;

	pos = buf;
	end = buf + buflen;

	ret = os_snprintf(pos, end - pos, "RSSI=%d\nLINKSPEED=%d\n"
			  "NOISE=%d\nFREQUENCY=%u\n",
			  si.current_signal, si.current_txrate / 1000,
			  si.current_noise, si.frequency);
	if (ret < 0 || ret > end - pos)
		return -1;
	pos += ret;

	if (si.chanwidth != CHAN_WIDTH_UNKNOWN) {
		ret = os_snprintf(pos, end - pos, "WIDTH=%s\n",
				  channel_width_name(si.chanwidth));
		if (ret < 0 || ret > end - pos)
			return -1;
		pos += ret;
	}

	if (si.center_frq1 > 0 && si.center_frq2 > 0) {
		ret = os_snprintf(pos, end - pos,
				  "CENTER_FRQ1=%d\nCENTER_FRQ2=%d\n",
				  si.center_frq1, si.center_frq2);
		if (ret < 0 || ret > end - pos)
			return -1;
		pos += ret;
	}

	if (si.avg_signal) {
		ret = os_snprintf(pos, end - pos,
				  "AVG_RSSI=%d\n", si.avg_signal);
		if (ret < 0 || ret >= end - pos)
			return -1;
		pos += ret;
	}

	return pos - buf;
}


static int wpa_supplicant_pktcnt_poll(struct wpa_supplicant *wpa_s, char *buf,
				      size_t buflen)
{
	struct hostap_sta_driver_data sta;
	int ret;

	ret = wpa_drv_pktcnt_poll(wpa_s, &sta);
	if (ret)
		return -1;

	ret = os_snprintf(buf, buflen, "TXGOOD=%lu\nTXBAD=%lu\nRXGOOD=%lu\n",
			  sta.tx_packets, sta.tx_retry_failed, sta.rx_packets);
	if (ret < 0 || (size_t) ret > buflen)
		return -1;
	return ret;
}


#ifdef ANDROID
static int wpa_supplicant_driver_cmd(struct wpa_supplicant *wpa_s, char *cmd,
				     char *buf, size_t buflen)
{
	int ret;

	ret = wpa_drv_driver_cmd(wpa_s, cmd, buf, buflen);
	if (ret == 0) {
		if (os_strncasecmp(cmd, "COUNTRY", 7) == 0) {
			struct p2p_data *p2p = wpa_s->global->p2p;
			if (p2p) {
				char country[3];
				country[0] = cmd[8];
				country[1] = cmd[9];
				country[2] = 0x04;
				p2p_set_country(p2p, country);
			}
		}
		ret = os_snprintf(buf, buflen, "%s\n", "OK");
	}
	return ret;
}
#endif /* ANDROID */


static int wpa_supplicant_vendor_cmd(struct wpa_supplicant *wpa_s, char *cmd,
				     char *buf, size_t buflen)
{
	int ret;
	char *pos;
	u8 *data = NULL;
	unsigned int vendor_id, subcmd;
	struct wpabuf *reply;
	size_t data_len = 0;

	/* cmd: <vendor id> <subcommand id> [<hex formatted data>] */
	vendor_id = strtoul(cmd, &pos, 16);
	if (!isblank(*pos))
		return -EINVAL;

	subcmd = strtoul(pos, &pos, 10);

	if (*pos != '\0') {
		if (!isblank(*pos++))
			return -EINVAL;
		data_len = os_strlen(pos);
	}

	if (data_len) {
		data_len /= 2;
		data = os_malloc(data_len);
		if (!data)
			return -1;

		if (hexstr2bin(pos, data, data_len)) {
			wpa_printf(MSG_DEBUG,
				   "Vendor command: wrong parameter format");
			os_free(data);
			return -EINVAL;
		}
	}

	reply = wpabuf_alloc((buflen - 1) / 2);
	if (!reply) {
		os_free(data);
		return -1;
	}

	ret = wpa_drv_vendor_cmd(wpa_s, vendor_id, subcmd, data, data_len,
				 reply);

	if (ret == 0)
		ret = wpa_snprintf_hex(buf, buflen, wpabuf_head_u8(reply),
				       wpabuf_len(reply));

	wpabuf_free(reply);
	os_free(data);

	return ret;
}


static void wpa_supplicant_ctrl_iface_flush(struct wpa_supplicant *wpa_s)
{
	wpa_dbg(wpa_s, MSG_DEBUG, "Flush all wpa_supplicant state");

#ifdef CONFIG_P2P
	wpas_p2p_cancel(wpa_s);
	wpas_p2p_stop_find(wpa_s);
	p2p_ctrl_flush(wpa_s);
	wpas_p2p_group_remove(wpa_s, "*");
	wpas_p2p_service_flush(wpa_s);
	wpa_s->global->p2p_disabled = 0;
	wpa_s->global->p2p_per_sta_psk = 0;
	wpa_s->conf->num_sec_device_types = 0;
	wpa_s->p2p_disable_ip_addr_req = 0;
	os_free(wpa_s->global->p2p_go_avoid_freq.range);
	wpa_s->global->p2p_go_avoid_freq.range = NULL;
#endif /* CONFIG_P2P */

#ifdef CONFIG_WPS_TESTING
	wps_version_number = 0x20;
	wps_testing_dummy_cred = 0;
	wps_corrupt_pkhash = 0;
#endif /* CONFIG_WPS_TESTING */
#ifdef CONFIG_WPS
	wpa_s->wps_fragment_size = 0;
	wpas_wps_cancel(wpa_s);
#endif /* CONFIG_WPS */
	wpa_s->after_wps = 0;
	wpa_s->known_wps_freq = 0;

#ifdef CONFIG_TDLS
#ifdef CONFIG_TDLS_TESTING
	extern unsigned int tdls_testing;
	tdls_testing = 0;
#endif /* CONFIG_TDLS_TESTING */
	wpa_drv_tdls_oper(wpa_s, TDLS_ENABLE, NULL);
	wpa_tdls_enable(wpa_s->wpa, 1);
#endif /* CONFIG_TDLS */

	eloop_cancel_timeout(wpa_supplicant_stop_countermeasures, wpa_s, NULL);
	wpa_supplicant_stop_countermeasures(wpa_s, NULL);

	wpa_s->no_keep_alive = 0;

	os_free(wpa_s->disallow_aps_bssid);
	wpa_s->disallow_aps_bssid = NULL;
	wpa_s->disallow_aps_bssid_count = 0;
	os_free(wpa_s->disallow_aps_ssid);
	wpa_s->disallow_aps_ssid = NULL;
	wpa_s->disallow_aps_ssid_count = 0;

	wpa_s->set_sta_uapsd = 0;
	wpa_s->sta_uapsd = 0;

	wpa_drv_radio_disable(wpa_s, 0);

	wpa_bss_flush(wpa_s);
	wpa_blacklist_clear(wpa_s);
	wpa_s->extra_blacklist_count = 0;
	wpa_supplicant_ctrl_iface_remove_network(wpa_s, "all");
	wpa_supplicant_ctrl_iface_remove_cred(wpa_s, "all");
	wpa_config_flush_blobs(wpa_s->conf);
	wpa_s->conf->auto_interworking = 0;
	wpa_s->conf->okc = 0;

	wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_LIFETIME, 43200);
	wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_REAUTH_THRESHOLD, 70);
	wpa_sm_set_param(wpa_s->wpa, RSNA_SA_TIMEOUT, 60);
	eapol_sm_notify_logoff(wpa_s->eapol, FALSE);

	radio_remove_works(wpa_s, NULL, 1);

	wpa_s->next_ssid = NULL;

#ifdef CONFIG_INTERWORKING
	hs20_cancel_fetch_osu(wpa_s);
#endif /* CONFIG_INTERWORKING */

	wpa_s->ext_mgmt_frame_handling = 0;
}


static int wpas_ctrl_radio_work_show(struct wpa_supplicant *wpa_s,
				     char *buf, size_t buflen)
{
	struct wpa_radio_work *work;
	char *pos, *end;
	struct os_reltime now, diff;

	pos = buf;
	end = buf + buflen;

	os_get_reltime(&now);

	dl_list_for_each(work, &wpa_s->radio->work, struct wpa_radio_work, list)
	{
		int ret;

		os_reltime_sub(&now, &work->time, &diff);
		ret = os_snprintf(pos, end - pos, "%s@%s:%u:%u:%ld.%06ld\n",
				  work->type, work->wpa_s->ifname, work->freq,
				  work->started, diff.sec, diff.usec);
		if (ret < 0 || ret >= end - pos)
			break;
		pos += ret;
	}

	return pos - buf;
}


static void wpas_ctrl_radio_work_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_radio_work *work = eloop_ctx;
	struct wpa_external_work *ework = work->ctx;

	wpa_dbg(work->wpa_s, MSG_DEBUG,
		"Timing out external radio work %u (%s)",
		ework->id, work->type);
	wpa_msg(work->wpa_s, MSG_INFO, EXT_RADIO_WORK_TIMEOUT "%u", ework->id);
	radio_work_done(work);
	os_free(ework);
}


static void wpas_ctrl_radio_work_cb(struct wpa_radio_work *work, int deinit)
{
	struct wpa_external_work *ework = work->ctx;

	if (deinit) {
		if (work->started)
			eloop_cancel_timeout(wpas_ctrl_radio_work_timeout,
					     work, NULL);

		os_free(ework);
		return;
	}

	wpa_dbg(work->wpa_s, MSG_DEBUG, "Starting external radio work %u (%s)",
		ework->id, ework->type);
	wpa_msg(work->wpa_s, MSG_INFO, EXT_RADIO_WORK_START "%u", ework->id);
	if (!ework->timeout)
		ework->timeout = 10;
	eloop_register_timeout(ework->timeout, 0, wpas_ctrl_radio_work_timeout,
			       work, NULL);
}


static int wpas_ctrl_radio_work_add(struct wpa_supplicant *wpa_s, char *cmd,
				    char *buf, size_t buflen)
{
	struct wpa_external_work *ework;
	char *pos, *pos2;
	size_t type_len;
	int ret;
	unsigned int freq = 0;

	/* format: <name> [freq=<MHz>] [timeout=<seconds>] */

	ework = os_zalloc(sizeof(*ework));
	if (ework == NULL)
		return -1;

	pos = os_strchr(cmd, ' ');
	if (pos) {
		type_len = pos - cmd;
		pos++;

		pos2 = os_strstr(pos, "freq=");
		if (pos2)
			freq = atoi(pos2 + 5);

		pos2 = os_strstr(pos, "timeout=");
		if (pos2)
			ework->timeout = atoi(pos2 + 8);
	} else {
		type_len = os_strlen(cmd);
	}
	if (4 + type_len >= sizeof(ework->type))
		type_len = sizeof(ework->type) - 4 - 1;
	os_strlcpy(ework->type, "ext:", sizeof(ework->type));
	os_memcpy(ework->type + 4, cmd, type_len);
	ework->type[4 + type_len] = '\0';

	wpa_s->ext_work_id++;
	if (wpa_s->ext_work_id == 0)
		wpa_s->ext_work_id++;
	ework->id = wpa_s->ext_work_id;

	if (radio_add_work(wpa_s, freq, ework->type, 0, wpas_ctrl_radio_work_cb,
			   ework) < 0) {
		os_free(ework);
		return -1;
	}

	ret = os_snprintf(buf, buflen, "%u", ework->id);
	if (ret < 0 || (size_t) ret >= buflen)
		return -1;
	return ret;
}


static int wpas_ctrl_radio_work_done(struct wpa_supplicant *wpa_s, char *cmd)
{
	struct wpa_radio_work *work;
	unsigned int id = atoi(cmd);

	dl_list_for_each(work, &wpa_s->radio->work, struct wpa_radio_work, list)
	{
		struct wpa_external_work *ework;

		if (os_strncmp(work->type, "ext:", 4) != 0)
			continue;
		ework = work->ctx;
		if (id && ework->id != id)
			continue;
		wpa_dbg(wpa_s, MSG_DEBUG,
			"Completed external radio work %u (%s)",
			ework->id, ework->type);
		eloop_cancel_timeout(wpas_ctrl_radio_work_timeout, work, NULL);
		radio_work_done(work);
		os_free(ework);
		return 3; /* "OK\n" */
	}

	return -1;
}


static int wpas_ctrl_radio_work(struct wpa_supplicant *wpa_s, char *cmd,
				char *buf, size_t buflen)
{
	if (os_strcmp(cmd, "show") == 0)
		return wpas_ctrl_radio_work_show(wpa_s, buf, buflen);
	if (os_strncmp(cmd, "add ", 4) == 0)
		return wpas_ctrl_radio_work_add(wpa_s, cmd + 4, buf, buflen);
	if (os_strncmp(cmd, "done ", 5) == 0)
		return wpas_ctrl_radio_work_done(wpa_s, cmd + 4);
	return -1;
}


void wpas_ctrl_radio_work_flush(struct wpa_supplicant *wpa_s)
{
	struct wpa_radio_work *work, *tmp;

	if (!wpa_s || !wpa_s->radio)
		return;

	dl_list_for_each_safe(work, tmp, &wpa_s->radio->work,
			      struct wpa_radio_work, list) {
		struct wpa_external_work *ework;

		if (os_strncmp(work->type, "ext:", 4) != 0)
			continue;
		ework = work->ctx;
		wpa_dbg(wpa_s, MSG_DEBUG,
			"Flushing%s external radio work %u (%s)",
			work->started ? " started" : "", ework->id,
			ework->type);
		if (work->started)
			eloop_cancel_timeout(wpas_ctrl_radio_work_timeout,
					     work, NULL);
		radio_work_done(work);
		os_free(ework);
	}
}


static void wpas_ctrl_eapol_response(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	eapol_sm_notify_ctrl_response(wpa_s->eapol);
}


static int set_scan_freqs(struct wpa_supplicant *wpa_s, char *val)
{
	int *freqs = NULL;

	freqs = freq_range_to_channel_list(wpa_s, val);
	if (freqs == NULL)
		return -1;

	os_free(wpa_s->manual_scan_freqs);
	wpa_s->manual_scan_freqs = freqs;

	return 0;
}


static void wpas_ctrl_scan(struct wpa_supplicant *wpa_s, char *params,
			   char *reply, int reply_size, int *reply_len)
{
	char *pos;

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		*reply_len = -1;
		return;
	}

	wpa_s->manual_scan_passive = 0;
	wpa_s->manual_scan_use_id = 0;
	wpa_s->manual_scan_only_new = 0;

	if (params) {
		if (os_strncasecmp(params, "TYPE=ONLY", 9) == 0)
			wpa_s->scan_res_handler = scan_only_handler;

		pos = os_strstr(params, "freq=");
		if (pos && set_scan_freqs(wpa_s, pos + 5) < 0) {
			*reply_len = -1;
			return;
		}

		pos = os_strstr(params, "passive=");
		if (pos)
			wpa_s->manual_scan_passive = !!atoi(pos + 8);

		pos = os_strstr(params, "use_id=");
		if (pos)
			wpa_s->manual_scan_use_id = atoi(pos + 7);

		pos = os_strstr(params, "only_new=1");
		if (pos)
			wpa_s->manual_scan_only_new = 1;
	} else {
		os_free(wpa_s->manual_scan_freqs);
		wpa_s->manual_scan_freqs = NULL;
		if (wpa_s->scan_res_handler == scan_only_handler)
			wpa_s->scan_res_handler = NULL;
	}

	if (!wpa_s->sched_scanning && !wpa_s->scanning &&
	    ((wpa_s->wpa_state <= WPA_SCANNING) ||
	     (wpa_s->wpa_state == WPA_COMPLETED))) {
		wpa_s->normal_scans = 0;
		wpa_s->scan_req = MANUAL_SCAN_REQ;
		wpa_s->after_wps = 0;
		wpa_s->known_wps_freq = 0;
		wpa_supplicant_req_scan(wpa_s, 0, 0);
		if (wpa_s->manual_scan_use_id) {
			wpa_s->manual_scan_id++;
			wpa_dbg(wpa_s, MSG_DEBUG, "Assigned scan id %u",
				wpa_s->manual_scan_id);
			*reply_len = os_snprintf(reply, reply_size, "%u\n",
						 wpa_s->manual_scan_id);
		}
	} else if (wpa_s->sched_scanning) {
		wpa_printf(MSG_DEBUG, "Stop ongoing sched_scan to allow requested full scan to proceed");
		wpa_supplicant_cancel_sched_scan(wpa_s);
		wpa_s->scan_req = MANUAL_SCAN_REQ;
		wpa_supplicant_req_scan(wpa_s, 0, 0);
		if (wpa_s->manual_scan_use_id) {
			wpa_s->manual_scan_id++;
			*reply_len = os_snprintf(reply, reply_size, "%u\n",
						 wpa_s->manual_scan_id);
			wpa_dbg(wpa_s, MSG_DEBUG, "Assigned scan id %u",
				wpa_s->manual_scan_id);
		}
	} else {
		wpa_printf(MSG_DEBUG, "Ongoing scan action - reject new request");
		*reply_len = os_snprintf(reply, reply_size, "FAIL-BUSY\n");
	}
}


#ifdef CONFIG_TESTING_OPTIONS

static void wpas_ctrl_iface_mgmt_tx_cb(struct wpa_supplicant *wpa_s,
				       unsigned int freq, const u8 *dst,
				       const u8 *src, const u8 *bssid,
				       const u8 *data, size_t data_len,
				       enum offchannel_send_action_result
				       result)
{
	wpa_msg(wpa_s, MSG_INFO, "MGMT-TX-STATUS freq=%u dst=" MACSTR
		" src=" MACSTR " bssid=" MACSTR " result=%s",
		freq, MAC2STR(dst), MAC2STR(src), MAC2STR(bssid),
		result == OFFCHANNEL_SEND_ACTION_SUCCESS ?
		"SUCCESS" : (result == OFFCHANNEL_SEND_ACTION_NO_ACK ?
			     "NO_ACK" : "FAILED"));
}


static int wpas_ctrl_iface_mgmt_tx(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos, *param;
	size_t len;
	u8 *buf, da[ETH_ALEN], bssid[ETH_ALEN];
	int res, used;
	int freq = 0, no_cck = 0, wait_time = 0;

	/* <DA> <BSSID> [freq=<MHz>] [wait_time=<ms>] [no_cck=1]
	 *    <action=Action frame payload> */

	wpa_printf(MSG_DEBUG, "External MGMT TX: %s", cmd);

	pos = cmd;
	used = hwaddr_aton2(pos, da);
	if (used < 0)
		return -1;
	pos += used;
	while (*pos == ' ')
		pos++;
	used = hwaddr_aton2(pos, bssid);
	if (used < 0)
		return -1;
	pos += used;

	param = os_strstr(pos, " freq=");
	if (param) {
		param += 6;
		freq = atoi(param);
	}

	param = os_strstr(pos, " no_cck=");
	if (param) {
		param += 8;
		no_cck = atoi(param);
	}

	param = os_strstr(pos, " wait_time=");
	if (param) {
		param += 11;
		wait_time = atoi(param);
	}

	param = os_strstr(pos, " action=");
	if (param == NULL)
		return -1;
	param += 8;

	len = os_strlen(param);
	if (len & 1)
		return -1;
	len /= 2;

	buf = os_malloc(len);
	if (buf == NULL)
		return -1;

	if (hexstr2bin(param, buf, len) < 0) {
		os_free(buf);
		return -1;
	}

	res = offchannel_send_action(wpa_s, freq, da, wpa_s->own_addr, bssid,
				     buf, len, wait_time,
				     wpas_ctrl_iface_mgmt_tx_cb, no_cck);
	os_free(buf);
	return res;
}


static void wpas_ctrl_iface_mgmt_tx_done(struct wpa_supplicant *wpa_s)
{
	wpa_printf(MSG_DEBUG, "External MGMT TX - done waiting");
	offchannel_send_action_done(wpa_s);
}


static int wpas_ctrl_iface_driver_event(struct wpa_supplicant *wpa_s, char *cmd)
{
	char *pos, *param;
	union wpa_event_data event;
	enum wpa_event_type ev;

	/* <event name> [parameters..] */

	wpa_dbg(wpa_s, MSG_DEBUG, "Testing - external driver event: %s", cmd);

	pos = cmd;
	param = os_strchr(pos, ' ');
	if (param)
		*param++ = '\0';

	os_memset(&event, 0, sizeof(event));

	if (os_strcmp(cmd, "INTERFACE_ENABLED") == 0) {
		ev = EVENT_INTERFACE_ENABLED;
	} else if (os_strcmp(cmd, "INTERFACE_DISABLED") == 0) {
		ev = EVENT_INTERFACE_DISABLED;
	} else if (os_strcmp(cmd, "AVOID_FREQUENCIES") == 0) {
		ev = EVENT_AVOID_FREQUENCIES;
		if (param == NULL)
			param = "";
		if (freq_range_list_parse(&event.freq_range, param) < 0)
			return -1;
		wpa_supplicant_event(wpa_s, ev, &event);
		os_free(event.freq_range.range);
		return 0;
	} else {
		wpa_dbg(wpa_s, MSG_DEBUG, "Testing - unknown driver event: %s",
			cmd);
		return -1;
	}

	wpa_supplicant_event(wpa_s, ev, &event);

	return 0;
}

#endif /* CONFIG_TESTING_OPTIONS */


char * wpa_supplicant_ctrl_iface_process(struct wpa_supplicant *wpa_s,
					 char *buf, size_t *resp_len)
{
	char *reply;
	const int reply_size = 4096;
	int reply_len;

	if (os_strncmp(buf, WPA_CTRL_RSP, os_strlen(WPA_CTRL_RSP)) == 0 ||
	    os_strncmp(buf, "SET_NETWORK ", 12) == 0) {
		if (wpa_debug_show_keys)
			wpa_dbg(wpa_s, MSG_DEBUG,
				"Control interface command '%s'", buf);
		else
			wpa_dbg(wpa_s, MSG_DEBUG,
				"Control interface command '%s [REMOVED]'",
				os_strncmp(buf, WPA_CTRL_RSP,
					   os_strlen(WPA_CTRL_RSP)) == 0 ?
				WPA_CTRL_RSP : "SET_NETWORK");
	} else if (os_strncmp(buf, "WPS_NFC_TAG_READ", 16) == 0 ||
		   os_strncmp(buf, "NFC_REPORT_HANDOVER", 19) == 0) {
		wpa_hexdump_ascii_key(MSG_DEBUG, "RX ctrl_iface",
				      (const u8 *) buf, os_strlen(buf));
	} else {
		int level = MSG_DEBUG;
		if (os_strcmp(buf, "PING") == 0)
			level = MSG_EXCESSIVE;
		wpa_dbg(wpa_s, level, "Control interface command '%s'", buf);
	}

	reply = os_malloc(reply_size);
	if (reply == NULL) {
		*resp_len = 1;
		return NULL;
	}

	os_memcpy(reply, "OK\n", 3);
	reply_len = 3;

	if (os_strcmp(buf, "PING") == 0) {
		os_memcpy(reply, "PONG\n", 5);
		reply_len = 5;
	} else if (os_strcmp(buf, "IFNAME") == 0) {
		reply_len = os_strlen(wpa_s->ifname);
		os_memcpy(reply, wpa_s->ifname, reply_len);
	} else if (os_strncmp(buf, "RELOG", 5) == 0) {
		if (wpa_debug_reopen_file() < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "NOTE ", 5) == 0) {
		wpa_printf(MSG_INFO, "NOTE: %s", buf + 5);
	} else if (os_strcmp(buf, "MIB") == 0) {
		reply_len = wpa_sm_get_mib(wpa_s->wpa, reply, reply_size);
		if (reply_len >= 0) {
			int res;
			res = eapol_sm_get_mib(wpa_s->eapol, reply + reply_len,
					       reply_size - reply_len);
			if (res < 0)
				reply_len = -1;
			else
				reply_len += res;
		}
	} else if (os_strncmp(buf, "STATUS", 6) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_status(
			wpa_s, buf + 6, reply, reply_size);
	} else if (os_strcmp(buf, "PMKSA") == 0) {
		reply_len = wpa_sm_pmksa_cache_list(wpa_s->wpa, reply,
						    reply_size);
	} else if (os_strncmp(buf, "SET ", 4) == 0) {
		if (wpa_supplicant_ctrl_iface_set(wpa_s, buf + 4))
			reply_len = -1;
	} else if (os_strncmp(buf, "GET ", 4) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_get(wpa_s, buf + 4,
							  reply, reply_size);
	} else if (os_strcmp(buf, "LOGON") == 0) {
		eapol_sm_notify_logoff(wpa_s->eapol, FALSE);
	} else if (os_strcmp(buf, "LOGOFF") == 0) {
		eapol_sm_notify_logoff(wpa_s->eapol, TRUE);
	} else if (os_strcmp(buf, "REASSOCIATE") == 0) {
		if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED)
			reply_len = -1;
		else
			wpas_request_connection(wpa_s);
	} else if (os_strcmp(buf, "REATTACH") == 0) {
		if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED ||
		    !wpa_s->current_ssid)
			reply_len = -1;
		else {
			wpa_s->reattach = 1;
			wpas_request_connection(wpa_s);
		}
	} else if (os_strcmp(buf, "RECONNECT") == 0) {
		if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED)
			reply_len = -1;
		else if (wpa_s->disconnected)
			wpas_request_connection(wpa_s);
#ifdef IEEE8021X_EAPOL
	} else if (os_strncmp(buf, "PREAUTH ", 8) == 0) {
		if (wpa_supplicant_ctrl_iface_preauth(wpa_s, buf + 8))
			reply_len = -1;
#endif /* IEEE8021X_EAPOL */
#ifdef CONFIG_PEERKEY
	} else if (os_strncmp(buf, "STKSTART ", 9) == 0) {
		if (wpa_supplicant_ctrl_iface_stkstart(wpa_s, buf + 9))
			reply_len = -1;
#endif /* CONFIG_PEERKEY */
#ifdef CONFIG_IEEE80211R
	} else if (os_strncmp(buf, "FT_DS ", 6) == 0) {
		if (wpa_supplicant_ctrl_iface_ft_ds(wpa_s, buf + 6))
			reply_len = -1;
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_WPS
	} else if (os_strcmp(buf, "WPS_PBC") == 0) {
		int res = wpa_supplicant_ctrl_iface_wps_pbc(wpa_s, NULL);
		if (res == -2) {
			os_memcpy(reply, "FAIL-PBC-OVERLAP\n", 17);
			reply_len = 17;
		} else if (res)
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_PBC ", 8) == 0) {
		int res = wpa_supplicant_ctrl_iface_wps_pbc(wpa_s, buf + 8);
		if (res == -2) {
			os_memcpy(reply, "FAIL-PBC-OVERLAP\n", 17);
			reply_len = 17;
		} else if (res)
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_PIN ", 8) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_wps_pin(wpa_s, buf + 8,
							      reply,
							      reply_size);
	} else if (os_strncmp(buf, "WPS_CHECK_PIN ", 14) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_wps_check_pin(
			wpa_s, buf + 14, reply, reply_size);
	} else if (os_strcmp(buf, "WPS_CANCEL") == 0) {
		if (wpas_wps_cancel(wpa_s))
			reply_len = -1;
#ifdef CONFIG_WPS_NFC
	} else if (os_strcmp(buf, "WPS_NFC") == 0) {
		if (wpa_supplicant_ctrl_iface_wps_nfc(wpa_s, NULL))
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_NFC ", 8) == 0) {
		if (wpa_supplicant_ctrl_iface_wps_nfc(wpa_s, buf + 8))
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_NFC_CONFIG_TOKEN ", 21) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_wps_nfc_config_token(
			wpa_s, buf + 21, reply, reply_size);
	} else if (os_strncmp(buf, "WPS_NFC_TOKEN ", 14) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_wps_nfc_token(
			wpa_s, buf + 14, reply, reply_size);
	} else if (os_strncmp(buf, "WPS_NFC_TAG_READ ", 17) == 0) {
		if (wpa_supplicant_ctrl_iface_wps_nfc_tag_read(wpa_s,
							       buf + 17))
			reply_len = -1;
	} else if (os_strncmp(buf, "NFC_GET_HANDOVER_REQ ", 21) == 0) {
		reply_len = wpas_ctrl_nfc_get_handover_req(
			wpa_s, buf + 21, reply, reply_size);
	} else if (os_strncmp(buf, "NFC_GET_HANDOVER_SEL ", 21) == 0) {
		reply_len = wpas_ctrl_nfc_get_handover_sel(
			wpa_s, buf + 21, reply, reply_size);
	} else if (os_strncmp(buf, "NFC_REPORT_HANDOVER ", 20) == 0) {
		if (wpas_ctrl_nfc_report_handover(wpa_s, buf + 20))
			reply_len = -1;
#endif /* CONFIG_WPS_NFC */
	} else if (os_strncmp(buf, "WPS_REG ", 8) == 0) {
		if (wpa_supplicant_ctrl_iface_wps_reg(wpa_s, buf + 8))
			reply_len = -1;
#ifdef CONFIG_AP
	} else if (os_strncmp(buf, "WPS_AP_PIN ", 11) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_wps_ap_pin(
			wpa_s, buf + 11, reply, reply_size);
#endif /* CONFIG_AP */
#ifdef CONFIG_WPS_ER
	} else if (os_strcmp(buf, "WPS_ER_START") == 0) {
		if (wpas_wps_er_start(wpa_s, NULL))
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_ER_START ", 13) == 0) {
		if (wpas_wps_er_start(wpa_s, buf + 13))
			reply_len = -1;
	} else if (os_strcmp(buf, "WPS_ER_STOP") == 0) {
		if (wpas_wps_er_stop(wpa_s))
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_ER_PIN ", 11) == 0) {
		if (wpa_supplicant_ctrl_iface_wps_er_pin(wpa_s, buf + 11))
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_ER_PBC ", 11) == 0) {
		int ret = wpas_wps_er_pbc(wpa_s, buf + 11);
		if (ret == -2) {
			os_memcpy(reply, "FAIL-PBC-OVERLAP\n", 17);
			reply_len = 17;
		} else if (ret == -3) {
			os_memcpy(reply, "FAIL-UNKNOWN-UUID\n", 18);
			reply_len = 18;
		} else if (ret == -4) {
			os_memcpy(reply, "FAIL-NO-AP-SETTINGS\n", 20);
			reply_len = 20;
		} else if (ret)
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_ER_LEARN ", 13) == 0) {
		if (wpa_supplicant_ctrl_iface_wps_er_learn(wpa_s, buf + 13))
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_ER_SET_CONFIG ", 18) == 0) {
		if (wpa_supplicant_ctrl_iface_wps_er_set_config(wpa_s,
								buf + 18))
			reply_len = -1;
	} else if (os_strncmp(buf, "WPS_ER_CONFIG ", 14) == 0) {
		if (wpa_supplicant_ctrl_iface_wps_er_config(wpa_s, buf + 14))
			reply_len = -1;
#ifdef CONFIG_WPS_NFC
	} else if (os_strncmp(buf, "WPS_ER_NFC_CONFIG_TOKEN ", 24) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_wps_er_nfc_config_token(
			wpa_s, buf + 24, reply, reply_size);
#endif /* CONFIG_WPS_NFC */
#endif /* CONFIG_WPS_ER */
#endif /* CONFIG_WPS */
#ifdef CONFIG_IBSS_RSN
	} else if (os_strncmp(buf, "IBSS_RSN ", 9) == 0) {
		if (wpa_supplicant_ctrl_iface_ibss_rsn(wpa_s, buf + 9))
			reply_len = -1;
#endif /* CONFIG_IBSS_RSN */
#ifdef CONFIG_P2P
	} else if (os_strncmp(buf, "P2P_FIND ", 9) == 0) {
		if (p2p_ctrl_find(wpa_s, buf + 9))
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_FIND") == 0) {
		if (p2p_ctrl_find(wpa_s, ""))
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_STOP_FIND") == 0) {
		wpas_p2p_stop_find(wpa_s);
	} else if (os_strncmp(buf, "P2P_CONNECT ", 12) == 0) {
		reply_len = p2p_ctrl_connect(wpa_s, buf + 12, reply,
					     reply_size);
	} else if (os_strncmp(buf, "P2P_LISTEN ", 11) == 0) {
		if (p2p_ctrl_listen(wpa_s, buf + 11))
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_LISTEN") == 0) {
		if (p2p_ctrl_listen(wpa_s, ""))
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_GROUP_REMOVE ", 17) == 0) {
		if (wpas_p2p_group_remove(wpa_s, buf + 17))
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_GROUP_ADD") == 0) {
		if (wpas_p2p_group_add(wpa_s, 0, 0, 0, 0))
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_GROUP_ADD ", 14) == 0) {
		if (p2p_ctrl_group_add(wpa_s, buf + 14))
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_PROV_DISC ", 14) == 0) {
		if (p2p_ctrl_prov_disc(wpa_s, buf + 14))
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_GET_PASSPHRASE") == 0) {
		reply_len = p2p_get_passphrase(wpa_s, reply, reply_size);
	} else if (os_strncmp(buf, "P2P_SERV_DISC_REQ ", 18) == 0) {
		reply_len = p2p_ctrl_serv_disc_req(wpa_s, buf + 18, reply,
						   reply_size);
	} else if (os_strncmp(buf, "P2P_SERV_DISC_CANCEL_REQ ", 25) == 0) {
		if (p2p_ctrl_serv_disc_cancel_req(wpa_s, buf + 25) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_SERV_DISC_RESP ", 19) == 0) {
		if (p2p_ctrl_serv_disc_resp(wpa_s, buf + 19) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_SERVICE_UPDATE") == 0) {
		wpas_p2p_sd_service_update(wpa_s);
	} else if (os_strncmp(buf, "P2P_SERV_DISC_EXTERNAL ", 23) == 0) {
		if (p2p_ctrl_serv_disc_external(wpa_s, buf + 23) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_SERVICE_FLUSH") == 0) {
		wpas_p2p_service_flush(wpa_s);
	} else if (os_strncmp(buf, "P2P_SERVICE_ADD ", 16) == 0) {
		if (p2p_ctrl_service_add(wpa_s, buf + 16) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_SERVICE_DEL ", 16) == 0) {
		if (p2p_ctrl_service_del(wpa_s, buf + 16) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_REJECT ", 11) == 0) {
		if (p2p_ctrl_reject(wpa_s, buf + 11) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_INVITE ", 11) == 0) {
		if (p2p_ctrl_invite(wpa_s, buf + 11) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_PEER ", 9) == 0) {
		reply_len = p2p_ctrl_peer(wpa_s, buf + 9, reply,
					      reply_size);
	} else if (os_strncmp(buf, "P2P_SET ", 8) == 0) {
		if (p2p_ctrl_set(wpa_s, buf + 8) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_FLUSH") == 0) {
		p2p_ctrl_flush(wpa_s);
	} else if (os_strncmp(buf, "P2P_UNAUTHORIZE ", 16) == 0) {
		if (wpas_p2p_unauthorize(wpa_s, buf + 16) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_CANCEL") == 0) {
		if (wpas_p2p_cancel(wpa_s))
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_PRESENCE_REQ ", 17) == 0) {
		if (p2p_ctrl_presence_req(wpa_s, buf + 17) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_PRESENCE_REQ") == 0) {
		if (p2p_ctrl_presence_req(wpa_s, "") < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_EXT_LISTEN ", 15) == 0) {
		if (p2p_ctrl_ext_listen(wpa_s, buf + 15) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "P2P_EXT_LISTEN") == 0) {
		if (p2p_ctrl_ext_listen(wpa_s, "") < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "P2P_REMOVE_CLIENT ", 18) == 0) {
		if (p2p_ctrl_remove_client(wpa_s, buf + 18) < 0)
			reply_len = -1;
#endif /* CONFIG_P2P */
#ifdef CONFIG_WIFI_DISPLAY
	} else if (os_strncmp(buf, "WFD_SUBELEM_SET ", 16) == 0) {
		if (wifi_display_subelem_set(wpa_s->global, buf + 16) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "WFD_SUBELEM_GET ", 16) == 0) {
		reply_len = wifi_display_subelem_get(wpa_s->global, buf + 16,
						     reply, reply_size);
#endif /* CONFIG_WIFI_DISPLAY */
#ifdef CONFIG_INTERWORKING
	} else if (os_strcmp(buf, "FETCH_ANQP") == 0) {
		if (interworking_fetch_anqp(wpa_s) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "STOP_FETCH_ANQP") == 0) {
		interworking_stop_fetch_anqp(wpa_s);
	} else if (os_strcmp(buf, "INTERWORKING_SELECT") == 0) {
		if (ctrl_interworking_select(wpa_s, NULL) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "INTERWORKING_SELECT ", 20) == 0) {
		if (ctrl_interworking_select(wpa_s, buf + 20) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "INTERWORKING_CONNECT ", 21) == 0) {
		if (ctrl_interworking_connect(wpa_s, buf + 21) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "ANQP_GET ", 9) == 0) {
		if (get_anqp(wpa_s, buf + 9) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "GAS_REQUEST ", 12) == 0) {
		if (gas_request(wpa_s, buf + 12) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "GAS_RESPONSE_GET ", 17) == 0) {
		reply_len = gas_response_get(wpa_s, buf + 17, reply,
					     reply_size);
#endif /* CONFIG_INTERWORKING */
#ifdef CONFIG_HS20
	} else if (os_strncmp(buf, "HS20_ANQP_GET ", 14) == 0) {
		if (get_hs20_anqp(wpa_s, buf + 14) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "HS20_GET_NAI_HOME_REALM_LIST ", 29) == 0) {
		if (hs20_get_nai_home_realm_list(wpa_s, buf + 29) < 0)
			reply_len = -1;
	} else if (os_strncmp(buf, "HS20_ICON_REQUEST ", 18) == 0) {
		if (hs20_icon_request(wpa_s, buf + 18) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "FETCH_OSU") == 0) {
		if (hs20_fetch_osu(wpa_s) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "CANCEL_FETCH_OSU") == 0) {
		hs20_cancel_fetch_osu(wpa_s);
#endif /* CONFIG_HS20 */
	} else if (os_strncmp(buf, WPA_CTRL_RSP, os_strlen(WPA_CTRL_RSP)) == 0)
	{
		if (wpa_supplicant_ctrl_iface_ctrl_rsp(
			    wpa_s, buf + os_strlen(WPA_CTRL_RSP)))
			reply_len = -1;
		else {
			/*
			 * Notify response from timeout to allow the control
			 * interface response to be sent first.
			 */
			eloop_register_timeout(0, 0, wpas_ctrl_eapol_response,
					       wpa_s, NULL);
		}
	} else if (os_strcmp(buf, "RECONFIGURE") == 0) {
		if (wpa_supplicant_reload_configuration(wpa_s))
			reply_len = -1;
	} else if (os_strcmp(buf, "TERMINATE") == 0) {
		wpa_supplicant_terminate_proc(wpa_s->global);
	} else if (os_strncmp(buf, "BSSID ", 6) == 0) {
		if (wpa_supplicant_ctrl_iface_bssid(wpa_s, buf + 6))
			reply_len = -1;
	} else if (os_strncmp(buf, "BLACKLIST", 9) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_blacklist(
			wpa_s, buf + 9, reply, reply_size);
	} else if (os_strncmp(buf, "LOG_LEVEL", 9) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_log_level(
			wpa_s, buf + 9, reply, reply_size);
	} else if (os_strcmp(buf, "LIST_NETWORKS") == 0) {
		reply_len = wpa_supplicant_ctrl_iface_list_networks(
			wpa_s, reply, reply_size);
	} else if (os_strcmp(buf, "DISCONNECT") == 0) {
#ifdef CONFIG_SME
		wpa_s->sme.prev_bssid_set = 0;
#endif /* CONFIG_SME */
		wpa_s->reassociate = 0;
		wpa_s->disconnected = 1;
		wpa_supplicant_cancel_sched_scan(wpa_s);
		wpa_supplicant_cancel_scan(wpa_s);
		wpa_supplicant_deauthenticate(wpa_s,
					      WLAN_REASON_DEAUTH_LEAVING);
	} else if (os_strcmp(buf, "SCAN") == 0) {
		wpas_ctrl_scan(wpa_s, NULL, reply, reply_size, &reply_len);
	} else if (os_strncmp(buf, "SCAN ", 5) == 0) {
		wpas_ctrl_scan(wpa_s, buf + 5, reply, reply_size, &reply_len);
	} else if (os_strcmp(buf, "SCAN_RESULTS") == 0) {
		reply_len = wpa_supplicant_ctrl_iface_scan_results(
			wpa_s, reply, reply_size);
	} else if (os_strncmp(buf, "SELECT_NETWORK ", 15) == 0) {
		if (wpa_supplicant_ctrl_iface_select_network(wpa_s, buf + 15))
			reply_len = -1;
	} else if (os_strncmp(buf, "ENABLE_NETWORK ", 15) == 0) {
		if (wpa_supplicant_ctrl_iface_enable_network(wpa_s, buf + 15))
			reply_len = -1;
	} else if (os_strncmp(buf, "DISABLE_NETWORK ", 16) == 0) {
		if (wpa_supplicant_ctrl_iface_disable_network(wpa_s, buf + 16))
			reply_len = -1;
	} else if (os_strcmp(buf, "ADD_NETWORK") == 0) {
		reply_len = wpa_supplicant_ctrl_iface_add_network(
			wpa_s, reply, reply_size);
	} else if (os_strncmp(buf, "REMOVE_NETWORK ", 15) == 0) {
		if (wpa_supplicant_ctrl_iface_remove_network(wpa_s, buf + 15))
			reply_len = -1;
	} else if (os_strncmp(buf, "SET_NETWORK ", 12) == 0) {
		if (wpa_supplicant_ctrl_iface_set_network(wpa_s, buf + 12))
			reply_len = -1;
	} else if (os_strncmp(buf, "GET_NETWORK ", 12) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_get_network(
			wpa_s, buf + 12, reply, reply_size);
	} else if (os_strncmp(buf, "DUP_NETWORK ", 12) == 0) {
		if (wpa_supplicant_ctrl_iface_dup_network(wpa_s, buf + 12))
			reply_len = -1;
	} else if (os_strcmp(buf, "LIST_CREDS") == 0) {
		reply_len = wpa_supplicant_ctrl_iface_list_creds(
			wpa_s, reply, reply_size);
	} else if (os_strcmp(buf, "ADD_CRED") == 0) {
		reply_len = wpa_supplicant_ctrl_iface_add_cred(
			wpa_s, reply, reply_size);
	} else if (os_strncmp(buf, "REMOVE_CRED ", 12) == 0) {
		if (wpa_supplicant_ctrl_iface_remove_cred(wpa_s, buf + 12))
			reply_len = -1;
	} else if (os_strncmp(buf, "SET_CRED ", 9) == 0) {
		if (wpa_supplicant_ctrl_iface_set_cred(wpa_s, buf + 9))
			reply_len = -1;
	} else if (os_strncmp(buf, "GET_CRED ", 9) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_get_cred(wpa_s, buf + 9,
							       reply,
							       reply_size);
#ifndef CONFIG_NO_CONFIG_WRITE
	} else if (os_strcmp(buf, "SAVE_CONFIG") == 0) {
		if (wpa_supplicant_ctrl_iface_save_config(wpa_s))
			reply_len = -1;
#endif /* CONFIG_NO_CONFIG_WRITE */
	} else if (os_strncmp(buf, "GET_CAPABILITY ", 15) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_get_capability(
			wpa_s, buf + 15, reply, reply_size);
	} else if (os_strncmp(buf, "AP_SCAN ", 8) == 0) {
		if (wpa_supplicant_ctrl_iface_ap_scan(wpa_s, buf + 8))
			reply_len = -1;
	} else if (os_strncmp(buf, "SCAN_INTERVAL ", 14) == 0) {
		if (wpa_supplicant_ctrl_iface_scan_interval(wpa_s, buf + 14))
			reply_len = -1;
	} else if (os_strcmp(buf, "INTERFACE_LIST") == 0) {
		reply_len = wpa_supplicant_global_iface_list(
			wpa_s->global, reply, reply_size);
	} else if (os_strcmp(buf, "INTERFACES") == 0) {
		reply_len = wpa_supplicant_global_iface_interfaces(
			wpa_s->global, reply, reply_size);
	} else if (os_strncmp(buf, "BSS ", 4) == 0) {
		reply_len = wpa_supplicant_ctrl_iface_bss(
			wpa_s, buf + 4, reply, reply_size);
#ifdef CONFIG_AP
	} else if (os_strcmp(buf, "STA-FIRST") == 0) {
		reply_len = ap_ctrl_iface_sta_first(wpa_s, reply, reply_size);
	} else if (os_strncmp(buf, "STA ", 4) == 0) {
		reply_len = ap_ctrl_iface_sta(wpa_s, buf + 4, reply,
					      reply_size);
	} else if (os_strncmp(buf, "STA-NEXT ", 9) == 0) {
		reply_len = ap_ctrl_iface_sta_next(wpa_s, buf + 9, reply,
						   reply_size);
	} else if (os_strncmp(buf, "DEAUTHENTICATE ", 15) == 0) {
		if (ap_ctrl_iface_sta_deauthenticate(wpa_s, buf + 15))
			reply_len = -1;
	} else if (os_strncmp(buf, "DISASSOCIATE ", 13) == 0) {
		if (ap_ctrl_iface_sta_disassociate(wpa_s, buf + 13))
			reply_len = -1;
	} else if (os_strncmp(buf, "CHAN_SWITCH ", 12) == 0) {
		if (ap_ctrl_iface_chanswitch(wpa_s, buf + 12))
			reply_len = -1;
#endif /* CONFIG_AP */
	} else if (os_strcmp(buf, "SUSPEND") == 0) {
		wpas_notify_suspend(wpa_s->global);
	} else if (os_strcmp(buf, "RESUME") == 0) {
		wpas_notify_resume(wpa_s->global);
#ifdef CONFIG_TESTING_OPTIONS
	} else if (os_strcmp(buf, "DROP_SA") == 0) {
		wpa_supplicant_ctrl_iface_drop_sa(wpa_s);
#endif /* CONFIG_TESTING_OPTIONS */
	} else if (os_strncmp(buf, "ROAM ", 5) == 0) {
		if (wpa_supplicant_ctrl_iface_roam(wpa_s, buf + 5))
			reply_len = -1;
	} else if (os_strncmp(buf, "STA_AUTOCONNECT ", 16) == 0) {
		if (wpa_supplicant_ctrl_iface_sta_autoconnect(wpa_s, buf + 16))
			reply_len = -1;
	} else if (os_strncmp(buf, "BSS_EXPIRE_AGE ", 15) == 0) {
		if (wpa_supplicant_ctrl_iface_bss_expire_age(wpa_s, buf + 15))
			reply_len = -1;
	} else if (os_strncmp(buf, "BSS_EXPIRE_COUNT ", 17) == 0) {
		if (wpa_supplicant_ctrl_iface_bss_expire_count(wpa_s,
							       buf + 17))
			reply_len = -1;
	} else if (os_strncmp(buf, "BSS_FLUSH ", 10) == 0) {
		if (wpa_supplicant_ctrl_iface_bss_flush(wpa_s, buf + 10))
			reply_len = -1;
#ifdef CONFIG_TDLS
	} else if (os_strncmp(buf, "TDLS_DISCOVER ", 14) == 0) {
		if (wpa_supplicant_ctrl_iface_tdls_discover(wpa_s, buf + 14))
			reply_len = -1;
	} else if (os_strncmp(buf, "TDLS_SETUP ", 11) == 0) {
		if (wpa_supplicant_ctrl_iface_tdls_setup(wpa_s, buf + 11))
			reply_len = -1;
	} else if (os_strncmp(buf, "TDLS_TEARDOWN ", 14) == 0) {
		if (wpa_supplicant_ctrl_iface_tdls_teardown(wpa_s, buf + 14))
			reply_len = -1;
#endif /* CONFIG_TDLS */
	} else if (os_strncmp(buf, "SIGNAL_POLL", 11) == 0) {
		reply_len = wpa_supplicant_signal_poll(wpa_s, reply,
						       reply_size);
	} else if (os_strncmp(buf, "PKTCNT_POLL", 11) == 0) {
		reply_len = wpa_supplicant_pktcnt_poll(wpa_s, reply,
						       reply_size);
#ifdef CONFIG_AUTOSCAN
	} else if (os_strncmp(buf, "AUTOSCAN ", 9) == 0) {
		if (wpa_supplicant_ctrl_iface_autoscan(wpa_s, buf + 9))
			reply_len = -1;
#endif /* CONFIG_AUTOSCAN */
#ifdef ANDROID
	} else if (os_strncmp(buf, "DRIVER ", 7) == 0) {
		reply_len = wpa_supplicant_driver_cmd(wpa_s, buf + 7, reply,
						      reply_size);
#endif /* ANDROID */
	} else if (os_strncmp(buf, "VENDOR ", 7) == 0) {
		reply_len = wpa_supplicant_vendor_cmd(wpa_s, buf + 7, reply,
						      reply_size);
	} else if (os_strcmp(buf, "REAUTHENTICATE") == 0) {
		pmksa_cache_clear_current(wpa_s->wpa);
		eapol_sm_request_reauth(wpa_s->eapol);
#ifdef CONFIG_WNM
	} else if (os_strncmp(buf, "WNM_SLEEP ", 10) == 0) {
		if (wpas_ctrl_iface_wnm_sleep(wpa_s, buf + 10))
			reply_len = -1;
	} else if (os_strncmp(buf, "WNM_BSS_QUERY ", 10) == 0) {
		if (wpas_ctrl_iface_wnm_bss_query(wpa_s, buf + 10))
				reply_len = -1;
#endif /* CONFIG_WNM */
	} else if (os_strcmp(buf, "FLUSH") == 0) {
		wpa_supplicant_ctrl_iface_flush(wpa_s);
	} else if (os_strncmp(buf, "RADIO_WORK ", 11) == 0) {
		reply_len = wpas_ctrl_radio_work(wpa_s, buf + 11, reply,
						 reply_size);
#ifdef CONFIG_TESTING_OPTIONS
	} else if (os_strncmp(buf, "MGMT_TX ", 8) == 0) {
		if (wpas_ctrl_iface_mgmt_tx(wpa_s, buf + 8) < 0)
			reply_len = -1;
	} else if (os_strcmp(buf, "MGMT_TX_DONE") == 0) {
		wpas_ctrl_iface_mgmt_tx_done(wpa_s);
	} else if (os_strncmp(buf, "DRIVER_EVENT ", 13) == 0) {
		if (wpas_ctrl_iface_driver_event(wpa_s, buf + 13) < 0)
			reply_len = -1;
#endif /* CONFIG_TESTING_OPTIONS */
	} else {
		os_memcpy(reply, "UNKNOWN COMMAND\n", 16);
		reply_len = 16;
	}

	if (reply_len < 0) {
		os_memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}

	*resp_len = reply_len;
	return reply;
}


static int wpa_supplicant_global_iface_add(struct wpa_global *global,
					   char *cmd)
{
	struct wpa_interface iface;
	char *pos;

	/*
	 * <ifname>TAB<confname>TAB<driver>TAB<ctrl_interface>TAB<driver_param>
	 * TAB<bridge_ifname>
	 */
	wpa_printf(MSG_DEBUG, "CTRL_IFACE GLOBAL INTERFACE_ADD '%s'", cmd);

	os_memset(&iface, 0, sizeof(iface));

	do {
		iface.ifname = pos = cmd;
		pos = os_strchr(pos, '\t');
		if (pos)
			*pos++ = '\0';
		if (iface.ifname[0] == '\0')
			return -1;
		if (pos == NULL)
			break;

		iface.confname = pos;
		pos = os_strchr(pos, '\t');
		if (pos)
			*pos++ = '\0';
		if (iface.confname[0] == '\0')
			iface.confname = NULL;
		if (pos == NULL)
			break;

		iface.driver = pos;
		pos = os_strchr(pos, '\t');
		if (pos)
			*pos++ = '\0';
		if (iface.driver[0] == '\0')
			iface.driver = NULL;
		if (pos == NULL)
			break;

		iface.ctrl_interface = pos;
		pos = os_strchr(pos, '\t');
		if (pos)
			*pos++ = '\0';
		if (iface.ctrl_interface[0] == '\0')
			iface.ctrl_interface = NULL;
		if (pos == NULL)
			break;

		iface.driver_param = pos;
		pos = os_strchr(pos, '\t');
		if (pos)
			*pos++ = '\0';
		if (iface.driver_param[0] == '\0')
			iface.driver_param = NULL;
		if (pos == NULL)
			break;

		iface.bridge_ifname = pos;
		pos = os_strchr(pos, '\t');
		if (pos)
			*pos++ = '\0';
		if (iface.bridge_ifname[0] == '\0')
			iface.bridge_ifname = NULL;
		if (pos == NULL)
			break;
	} while (0);

	if (wpa_supplicant_get_iface(global, iface.ifname))
		return -1;

	return wpa_supplicant_add_iface(global, &iface) ? 0 : -1;
}


static int wpa_supplicant_global_iface_remove(struct wpa_global *global,
					      char *cmd)
{
	struct wpa_supplicant *wpa_s;

	wpa_printf(MSG_DEBUG, "CTRL_IFACE GLOBAL INTERFACE_REMOVE '%s'", cmd);

	wpa_s = wpa_supplicant_get_iface(global, cmd);
	if (wpa_s == NULL)
		return -1;
	return wpa_supplicant_remove_iface(global, wpa_s, 0);
}


static void wpa_free_iface_info(struct wpa_interface_info *iface)
{
	struct wpa_interface_info *prev;

	while (iface) {
		prev = iface;
		iface = iface->next;

		os_free(prev->ifname);
		os_free(prev->desc);
		os_free(prev);
	}
}


static int wpa_supplicant_global_iface_list(struct wpa_global *global,
					    char *buf, int len)
{
	int i, res;
	struct wpa_interface_info *iface = NULL, *last = NULL, *tmp;
	char *pos, *end;

	for (i = 0; wpa_drivers[i]; i++) {
		struct wpa_driver_ops *drv = wpa_drivers[i];
		if (drv->get_interfaces == NULL)
			continue;
		tmp = drv->get_interfaces(global->drv_priv[i]);
		if (tmp == NULL)
			continue;

		if (last == NULL)
			iface = last = tmp;
		else
			last->next = tmp;
		while (last->next)
			last = last->next;
	}

	pos = buf;
	end = buf + len;
	for (tmp = iface; tmp; tmp = tmp->next) {
		res = os_snprintf(pos, end - pos, "%s\t%s\t%s\n",
				  tmp->drv_name, tmp->ifname,
				  tmp->desc ? tmp->desc : "");
		if (res < 0 || res >= end - pos) {
			*pos = '\0';
			break;
		}
		pos += res;
	}

	wpa_free_iface_info(iface);

	return pos - buf;
}


static int wpa_supplicant_global_iface_interfaces(struct wpa_global *global,
						  char *buf, int len)
{
	int res;
	char *pos, *end;
	struct wpa_supplicant *wpa_s;

	wpa_s = global->ifaces;
	pos = buf;
	end = buf + len;

	while (wpa_s) {
		res = os_snprintf(pos, end - pos, "%s\n", wpa_s->ifname);
		if (res < 0 || res >= end - pos) {
			*pos = '\0';
			break;
		}
		pos += res;
		wpa_s = wpa_s->next;
	}
	return pos - buf;
}


static char * wpas_global_ctrl_iface_ifname(struct wpa_global *global,
					    const char *ifname,
					    char *cmd, size_t *resp_len)
{
	struct wpa_supplicant *wpa_s;

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		if (os_strcmp(ifname, wpa_s->ifname) == 0)
			break;
	}

	if (wpa_s == NULL) {
		char *resp = os_strdup("FAIL-NO-IFNAME-MATCH\n");
		if (resp)
			*resp_len = os_strlen(resp);
		else
			*resp_len = 1;
		return resp;
	}

	return wpa_supplicant_ctrl_iface_process(wpa_s, cmd, resp_len);
}


static char * wpas_global_ctrl_iface_redir_p2p(struct wpa_global *global,
					       char *buf, size_t *resp_len)
{
#ifdef CONFIG_P2P
	static const char * cmd[] = {
		"LIST_NETWORKS",
		"P2P_FIND",
		"P2P_STOP_FIND",
		"P2P_LISTEN",
		"P2P_GROUP_ADD",
		"P2P_GET_PASSPHRASE",
		"P2P_SERVICE_UPDATE",
		"P2P_SERVICE_FLUSH",
		"P2P_FLUSH",
		"P2P_CANCEL",
		"P2P_PRESENCE_REQ",
		"P2P_EXT_LISTEN",
		NULL
	};
	static const char * prefix[] = {
#ifdef ANDROID
		"DRIVER ",
#endif /* ANDROID */
		"GET_NETWORK ",
		"REMOVE_NETWORK ",
		"P2P_FIND ",
		"P2P_CONNECT ",
		"P2P_LISTEN ",
		"P2P_GROUP_REMOVE ",
		"P2P_GROUP_ADD ",
		"P2P_PROV_DISC ",
		"P2P_SERV_DISC_REQ ",
		"P2P_SERV_DISC_CANCEL_REQ ",
		"P2P_SERV_DISC_RESP ",
		"P2P_SERV_DISC_EXTERNAL ",
		"P2P_SERVICE_ADD ",
		"P2P_SERVICE_DEL ",
		"P2P_REJECT ",
		"P2P_INVITE ",
		"P2P_PEER ",
		"P2P_SET ",
		"P2P_UNAUTHORIZE ",
		"P2P_PRESENCE_REQ ",
		"P2P_EXT_LISTEN ",
		"P2P_REMOVE_CLIENT ",
		"NFC_GET_HANDOVER_SEL ",
		"NFC_GET_HANDOVER_REQ ",
		"NFC_REPORT_HANDOVER ",
		NULL
	};
	int found = 0;
	int i;

	if (global->p2p_init_wpa_s == NULL)
		return NULL;

	for (i = 0; !found && cmd[i]; i++) {
		if (os_strcmp(buf, cmd[i]) == 0)
			found = 1;
	}

	for (i = 0; !found && prefix[i]; i++) {
		if (os_strncmp(buf, prefix[i], os_strlen(prefix[i])) == 0)
			found = 1;
	}

	if (found)
		return wpa_supplicant_ctrl_iface_process(global->p2p_init_wpa_s,
							 buf, resp_len);
#endif /* CONFIG_P2P */
	return NULL;
}


static char * wpas_global_ctrl_iface_redir_wfd(struct wpa_global *global,
					       char *buf, size_t *resp_len)
{
#ifdef CONFIG_WIFI_DISPLAY
	if (global->p2p_init_wpa_s == NULL)
		return NULL;
	if (os_strncmp(buf, "WFD_SUBELEM_SET ", 16) == 0 ||
	    os_strncmp(buf, "WFD_SUBELEM_GET ", 16) == 0)
		return wpa_supplicant_ctrl_iface_process(global->p2p_init_wpa_s,
							 buf, resp_len);
#endif /* CONFIG_WIFI_DISPLAY */
	return NULL;
}


static char * wpas_global_ctrl_iface_redir(struct wpa_global *global,
					   char *buf, size_t *resp_len)
{
	char *ret;

	ret = wpas_global_ctrl_iface_redir_p2p(global, buf, resp_len);
	if (ret)
		return ret;

	ret = wpas_global_ctrl_iface_redir_wfd(global, buf, resp_len);
	if (ret)
		return ret;

	return NULL;
}


static int wpas_global_ctrl_iface_set(struct wpa_global *global, char *cmd)
{
	char *value;

	value = os_strchr(cmd, ' ');
	if (value == NULL)
		return -1;
	*value++ = '\0';

	wpa_printf(MSG_DEBUG, "GLOBAL_CTRL_IFACE SET '%s'='%s'", cmd, value);

#ifdef CONFIG_WIFI_DISPLAY
	if (os_strcasecmp(cmd, "wifi_display") == 0) {
		wifi_display_enable(global, !!atoi(value));
		return 0;
	}
#endif /* CONFIG_WIFI_DISPLAY */

	/* Restore cmd to its original value to allow redirection */
	value[-1] = ' ';

	return -1;
}


#ifndef CONFIG_NO_CONFIG_WRITE
static int wpas_global_ctrl_iface_save_config(struct wpa_global *global)
{
	int ret = 0, saved = 0;
	struct wpa_supplicant *wpa_s;

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		if (!wpa_s->conf->update_config) {
			wpa_dbg(wpa_s, MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Not allowed to update configuration (update_config=0)");
			continue;
		}

		if (wpa_config_write(wpa_s->confname, wpa_s->conf)) {
			wpa_dbg(wpa_s, MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Failed to update configuration");
			ret = 1;
		} else {
			wpa_dbg(wpa_s, MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Configuration updated");
			saved++;
		}
	}

	if (!saved && !ret) {
		wpa_dbg(wpa_s, MSG_DEBUG,
			"CTRL_IFACE: SAVE_CONFIG - No configuration files could be updated");
		ret = 1;
	}

	return ret;
}
#endif /* CONFIG_NO_CONFIG_WRITE */


static int wpas_global_ctrl_iface_status(struct wpa_global *global,
					 char *buf, size_t buflen)
{
	char *pos, *end;
	int ret;
	struct wpa_supplicant *wpa_s;

	pos = buf;
	end = buf + buflen;

#ifdef CONFIG_P2P
	if (global->p2p && !global->p2p_disabled) {
		ret = os_snprintf(pos, end - pos, "p2p_device_address=" MACSTR
				  "\n"
				  "p2p_state=%s\n",
				  MAC2STR(global->p2p_dev_addr),
				  p2p_get_state_txt(global->p2p));
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	} else if (global->p2p) {
		ret = os_snprintf(pos, end - pos, "p2p_state=DISABLED\n");
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}
#endif /* CONFIG_P2P */

#ifdef CONFIG_WIFI_DISPLAY
	ret = os_snprintf(pos, end - pos, "wifi_display=%d\n",
			  !!global->wifi_display);
	if (ret < 0 || ret >= end - pos)
		return pos - buf;
	pos += ret;
#endif /* CONFIG_WIFI_DISPLAY */

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		ret = os_snprintf(pos, end - pos, "ifname=%s\n"
				  "address=" MACSTR "\n",
				  wpa_s->ifname, MAC2STR(wpa_s->own_addr));
		if (ret < 0 || ret >= end - pos)
			return pos - buf;
		pos += ret;
	}

	return pos - buf;
}


char * wpa_supplicant_global_ctrl_iface_process(struct wpa_global *global,
						char *buf, size_t *resp_len)
{
	char *reply;
	const int reply_size = 2048;
	int reply_len;
	int level = MSG_DEBUG;

	if (os_strncmp(buf, "IFNAME=", 7) == 0) {
		char *pos = os_strchr(buf + 7, ' ');
		if (pos) {
			*pos++ = '\0';
			return wpas_global_ctrl_iface_ifname(global,
							     buf + 7, pos,
							     resp_len);
		}
	}

	reply = wpas_global_ctrl_iface_redir(global, buf, resp_len);
	if (reply)
		return reply;

	if (os_strcmp(buf, "PING") == 0)
		level = MSG_EXCESSIVE;
	wpa_hexdump_ascii(level, "RX global ctrl_iface",
			  (const u8 *) buf, os_strlen(buf));

	reply = os_malloc(reply_size);
	if (reply == NULL) {
		*resp_len = 1;
		return NULL;
	}

	os_memcpy(reply, "OK\n", 3);
	reply_len = 3;

	if (os_strcmp(buf, "PING") == 0) {
		os_memcpy(reply, "PONG\n", 5);
		reply_len = 5;
	} else if (os_strncmp(buf, "INTERFACE_ADD ", 14) == 0) {
		if (wpa_supplicant_global_iface_add(global, buf + 14))
			reply_len = -1;
	} else if (os_strncmp(buf, "INTERFACE_REMOVE ", 17) == 0) {
		if (wpa_supplicant_global_iface_remove(global, buf + 17))
			reply_len = -1;
	} else if (os_strcmp(buf, "INTERFACE_LIST") == 0) {
		reply_len = wpa_supplicant_global_iface_list(
			global, reply, reply_size);
	} else if (os_strcmp(buf, "INTERFACES") == 0) {
		reply_len = wpa_supplicant_global_iface_interfaces(
			global, reply, reply_size);
	} else if (os_strcmp(buf, "TERMINATE") == 0) {
		wpa_supplicant_terminate_proc(global);
	} else if (os_strcmp(buf, "SUSPEND") == 0) {
		wpas_notify_suspend(global);
	} else if (os_strcmp(buf, "RESUME") == 0) {
		wpas_notify_resume(global);
	} else if (os_strncmp(buf, "SET ", 4) == 0) {
		if (wpas_global_ctrl_iface_set(global, buf + 4)) {
#ifdef CONFIG_P2P
			if (global->p2p_init_wpa_s) {
				os_free(reply);
				/* Check if P2P redirection would work for this
				 * command. */
				return wpa_supplicant_ctrl_iface_process(
					global->p2p_init_wpa_s,
					buf, resp_len);
			}
#endif /* CONFIG_P2P */
			reply_len = -1;
		}
#ifndef CONFIG_NO_CONFIG_WRITE
	} else if (os_strcmp(buf, "SAVE_CONFIG") == 0) {
		if (wpas_global_ctrl_iface_save_config(global))
			reply_len = -1;
#endif /* CONFIG_NO_CONFIG_WRITE */
	} else if (os_strcmp(buf, "STATUS") == 0) {
		reply_len = wpas_global_ctrl_iface_status(global, reply,
							  reply_size);
#ifdef CONFIG_MODULE_TESTS
	} else if (os_strcmp(buf, "MODULE_TESTS") == 0) {
		int wpas_module_tests(void);
		if (wpas_module_tests() < 0)
			reply_len = -1;
#endif /* CONFIG_MODULE_TESTS */
	} else {
		os_memcpy(reply, "UNKNOWN COMMAND\n", 16);
		reply_len = 16;
	}

	if (reply_len < 0) {
		os_memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}

	*resp_len = reply_len;
	return reply;
}
