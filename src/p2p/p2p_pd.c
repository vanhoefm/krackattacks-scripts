/*
 * Wi-Fi Direct - P2P provision discovery
 * Copyright (c) 2009-2010, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "wps/wps_defs.h"
#include "p2p_i.h"
#include "p2p.h"


/*
 * Number of retries to attempt for provision discovery requests
 * in case the peer is not listening.
 */
#define MAX_PROV_DISC_REQ_RETRIES 120


static void p2p_build_wps_ie_config_methods(struct wpabuf *buf,
					    u16 config_methods)
{
	u8 *len;
	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	len = wpabuf_put(buf, 1);
	wpabuf_put_be32(buf, WPS_DEV_OUI_WFA);

	/* Config Methods */
	wpabuf_put_be16(buf, ATTR_CONFIG_METHODS);
	wpabuf_put_be16(buf, 2);
	wpabuf_put_be16(buf, config_methods);

	p2p_buf_update_ie_hdr(buf, len);
}


static void p2ps_add_new_group_info(struct p2p_data *p2p, struct wpabuf *buf)
{
	int found;
	u8 intended_addr[ETH_ALEN];
	u8 ssid[32];
	size_t ssid_len;
	int group_iface;

	if (!p2p->cfg->get_go_info)
		return;

	found = p2p->cfg->get_go_info(
		p2p->cfg->cb_ctx, intended_addr, ssid,
		&ssid_len, &group_iface);
	if (found) {
		p2p_buf_add_group_id(buf, p2p->cfg->dev_addr,
				     ssid, ssid_len);
		p2p_buf_add_intended_addr(buf, intended_addr);
	} else {
		if (!p2p->ssid_set) {
			p2p_build_ssid(p2p, p2p->ssid, &p2p->ssid_len);
			p2p->ssid_set = 1;
		}

		/* Add pre-composed P2P Group ID */
		p2p_buf_add_group_id(buf, p2p->cfg->dev_addr,
				     p2p->ssid, p2p->ssid_len);

		if (group_iface)
			p2p_buf_add_intended_addr(
				buf, p2p->intended_addr);
		else
			p2p_buf_add_intended_addr(
				buf, p2p->cfg->dev_addr);
	}
}


static void p2ps_add_pd_req_attrs(struct p2p_data *p2p, struct p2p_device *dev,
				  struct wpabuf *buf, u16 config_methods)
{
	struct p2ps_provision *prov = p2p->p2ps_prov;
	u8 feat_cap_mask[] = { 1, 0 };
	int shared_group = 0;
	u8 ssid[32];
	size_t ssid_len;
	u8 go_dev_addr[ETH_ALEN];

	/* If we might be explicite group owner, add GO details */
	if (prov->conncap & (P2PS_SETUP_GROUP_OWNER |
			     P2PS_SETUP_NEW))
		p2ps_add_new_group_info(p2p, buf);

	if (prov->status >= 0)
		p2p_buf_add_status(buf, (u8) prov->status);
	else
		prov->method = config_methods;

	if (p2p->cfg->get_persistent_group) {
		shared_group = p2p->cfg->get_persistent_group(
			p2p->cfg->cb_ctx, dev->info.p2p_device_addr, NULL, 0,
			go_dev_addr, ssid, &ssid_len);
	}

	/* Add Operating Channel if conncap includes GO */
	if (shared_group ||
	    (prov->conncap & (P2PS_SETUP_GROUP_OWNER |
			      P2PS_SETUP_NEW))) {
		u8 tmp;

		p2p_go_select_channel(p2p, dev, &tmp);

		if (p2p->op_reg_class && p2p->op_channel)
			p2p_buf_add_operating_channel(buf, p2p->cfg->country,
						      p2p->op_reg_class,
						      p2p->op_channel);
		else
			p2p_buf_add_operating_channel(buf, p2p->cfg->country,
						      p2p->cfg->op_reg_class,
						      p2p->cfg->op_channel);
	}

	p2p_buf_add_channel_list(buf, p2p->cfg->country, &p2p->cfg->channels);

	if (prov->info[0])
		p2p_buf_add_session_info(buf, prov->info);

	p2p_buf_add_connection_capability(buf, prov->conncap);

	p2p_buf_add_advertisement_id(buf, prov->adv_id, prov->adv_mac);

	if (shared_group || prov->conncap == P2PS_SETUP_NEW ||
	    prov->conncap ==
	    (P2PS_SETUP_GROUP_OWNER | P2PS_SETUP_NEW) ||
	    prov->conncap ==
	    (P2PS_SETUP_GROUP_OWNER | P2PS_SETUP_CLIENT)) {
		/* Add Config Timeout */
		p2p_buf_add_config_timeout(buf, p2p->go_timeout,
					   p2p->client_timeout);
	}

	p2p_buf_add_listen_channel(buf, p2p->cfg->country, p2p->cfg->reg_class,
				   p2p->cfg->channel);

	p2p_buf_add_session_id(buf, prov->session_id, prov->session_mac);

	p2p_buf_add_feature_capability(buf, sizeof(feat_cap_mask),
				       feat_cap_mask);

	if (shared_group)
		p2p_buf_add_persistent_group_info(buf, go_dev_addr,
						  ssid, ssid_len);
}


static struct wpabuf * p2p_build_prov_disc_req(struct p2p_data *p2p,
					       struct p2p_device *dev,
					       int join)
{
	struct wpabuf *buf;
	u8 *len;
	size_t extra = 0;
	u8 dialog_token = dev->dialog_token;
	u16 config_methods = dev->req_config_methods;
	struct p2p_device *go = join ? dev : NULL;

#ifdef CONFIG_WIFI_DISPLAY
	if (p2p->wfd_ie_prov_disc_req)
		extra = wpabuf_len(p2p->wfd_ie_prov_disc_req);
#endif /* CONFIG_WIFI_DISPLAY */

	if (p2p->vendor_elem && p2p->vendor_elem[VENDOR_ELEM_P2P_PD_REQ])
		extra += wpabuf_len(p2p->vendor_elem[VENDOR_ELEM_P2P_PD_REQ]);

	if (p2p->p2ps_prov)
		extra += os_strlen(p2p->p2ps_prov->info) + 1 +
			sizeof(struct p2ps_provision);

	buf = wpabuf_alloc(1000 + extra);
	if (buf == NULL)
		return NULL;

	p2p_buf_add_public_action_hdr(buf, P2P_PROV_DISC_REQ, dialog_token);

	len = p2p_buf_add_ie_hdr(buf);
	p2p_buf_add_capability(buf, p2p->dev_capab &
			       ~P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY, 0);
	p2p_buf_add_device_info(buf, p2p, NULL);
	if (p2p->p2ps_prov) {
		p2ps_add_pd_req_attrs(p2p, dev, buf, config_methods);
	} else if (go) {
		p2p_buf_add_group_id(buf, go->info.p2p_device_addr,
				     go->oper_ssid, go->oper_ssid_len);
	}
	p2p_buf_update_ie_hdr(buf, len);

	/* WPS IE with Config Methods attribute */
	p2p_build_wps_ie_config_methods(buf, config_methods);

#ifdef CONFIG_WIFI_DISPLAY
	if (p2p->wfd_ie_prov_disc_req)
		wpabuf_put_buf(buf, p2p->wfd_ie_prov_disc_req);
#endif /* CONFIG_WIFI_DISPLAY */

	if (p2p->vendor_elem && p2p->vendor_elem[VENDOR_ELEM_P2P_PD_REQ])
		wpabuf_put_buf(buf, p2p->vendor_elem[VENDOR_ELEM_P2P_PD_REQ]);

	return buf;
}


static struct wpabuf * p2p_build_prov_disc_resp(struct p2p_data *p2p,
						u8 dialog_token,
						u16 config_methods,
						const u8 *group_id,
						size_t group_id_len)
{
	struct wpabuf *buf;
	size_t extra = 0;

#ifdef CONFIG_WIFI_DISPLAY
	struct wpabuf *wfd_ie = p2p->wfd_ie_prov_disc_resp;
	if (wfd_ie && group_id) {
		size_t i;
		for (i = 0; i < p2p->num_groups; i++) {
			struct p2p_group *g = p2p->groups[i];
			struct wpabuf *ie;
			if (!p2p_group_is_group_id_match(g, group_id,
							 group_id_len))
				continue;
			ie = p2p_group_get_wfd_ie(g);
			if (ie) {
				wfd_ie = ie;
				break;
			}
		}
	}
	if (wfd_ie)
		extra = wpabuf_len(wfd_ie);
#endif /* CONFIG_WIFI_DISPLAY */

	if (p2p->vendor_elem && p2p->vendor_elem[VENDOR_ELEM_P2P_PD_RESP])
		extra += wpabuf_len(p2p->vendor_elem[VENDOR_ELEM_P2P_PD_RESP]);

	buf = wpabuf_alloc(100 + extra);
	if (buf == NULL)
		return NULL;

	p2p_buf_add_public_action_hdr(buf, P2P_PROV_DISC_RESP, dialog_token);

	/* WPS IE with Config Methods attribute */
	p2p_build_wps_ie_config_methods(buf, config_methods);

#ifdef CONFIG_WIFI_DISPLAY
	if (wfd_ie)
		wpabuf_put_buf(buf, wfd_ie);
#endif /* CONFIG_WIFI_DISPLAY */

	if (p2p->vendor_elem && p2p->vendor_elem[VENDOR_ELEM_P2P_PD_RESP])
		wpabuf_put_buf(buf, p2p->vendor_elem[VENDOR_ELEM_P2P_PD_RESP]);

	return buf;
}


void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
			       const u8 *data, size_t len, int rx_freq)
{
	struct p2p_message msg;
	struct p2p_device *dev;
	int freq;
	int reject = 1;
	struct wpabuf *resp;

	if (p2p_parse(data, len, &msg))
		return;

	p2p_dbg(p2p, "Received Provision Discovery Request from " MACSTR
		" with config methods 0x%x (freq=%d)",
		MAC2STR(sa), msg.wps_config_methods, rx_freq);

	dev = p2p_get_device(p2p, sa);
	if (dev == NULL || (dev->flags & P2P_DEV_PROBE_REQ_ONLY)) {
		p2p_dbg(p2p, "Provision Discovery Request from unknown peer "
			MACSTR, MAC2STR(sa));

		if (p2p_add_device(p2p, sa, rx_freq, NULL, 0, data + 1, len - 1,
				   0)) {
			p2p_dbg(p2p, "Provision Discovery Request add device failed "
				MACSTR, MAC2STR(sa));
		}
	} else if (msg.wfd_subelems) {
		wpabuf_free(dev->info.wfd_subelems);
		dev->info.wfd_subelems = wpabuf_dup(msg.wfd_subelems);
	}

	if (!(msg.wps_config_methods &
	      (WPS_CONFIG_DISPLAY | WPS_CONFIG_KEYPAD |
	       WPS_CONFIG_PUSHBUTTON))) {
		p2p_dbg(p2p, "Unsupported Config Methods in Provision Discovery Request");
		goto out;
	}

	if (msg.group_id) {
		size_t i;
		for (i = 0; i < p2p->num_groups; i++) {
			if (p2p_group_is_group_id_match(p2p->groups[i],
							msg.group_id,
							msg.group_id_len))
				break;
		}
		if (i == p2p->num_groups) {
			p2p_dbg(p2p, "PD request for unknown P2P Group ID - reject");
			goto out;
		}
	}

	if (dev)
		dev->flags &= ~(P2P_DEV_PD_PEER_DISPLAY |
				P2P_DEV_PD_PEER_KEYPAD);
	if (msg.wps_config_methods & WPS_CONFIG_DISPLAY) {
		p2p_dbg(p2p, "Peer " MACSTR
			" requested us to show a PIN on display", MAC2STR(sa));
		if (dev)
			dev->flags |= P2P_DEV_PD_PEER_KEYPAD;
	} else if (msg.wps_config_methods & WPS_CONFIG_KEYPAD) {
		p2p_dbg(p2p, "Peer " MACSTR
			" requested us to write its PIN using keypad",
			MAC2STR(sa));
		if (dev)
			dev->flags |= P2P_DEV_PD_PEER_DISPLAY;
	}

	reject = 0;

out:
	resp = p2p_build_prov_disc_resp(p2p, msg.dialog_token,
					reject ? 0 : msg.wps_config_methods,
					msg.group_id, msg.group_id_len);
	if (resp == NULL) {
		p2p_parse_free(&msg);
		return;
	}
	p2p_dbg(p2p, "Sending Provision Discovery Response");
	if (rx_freq > 0)
		freq = rx_freq;
	else
		freq = p2p_channel_to_freq(p2p->cfg->reg_class,
					   p2p->cfg->channel);
	if (freq < 0) {
		p2p_dbg(p2p, "Unknown regulatory class/channel");
		wpabuf_free(resp);
		p2p_parse_free(&msg);
		return;
	}
	p2p->pending_action_state = P2P_NO_PENDING_ACTION;
	if (p2p_send_action(p2p, freq, sa, p2p->cfg->dev_addr,
			    p2p->cfg->dev_addr,
			    wpabuf_head(resp), wpabuf_len(resp), 200) < 0) {
		p2p_dbg(p2p, "Failed to send Action frame");
	} else
		p2p->send_action_in_progress = 1;

	wpabuf_free(resp);

	if (!reject && p2p->cfg->prov_disc_req) {
		const u8 *dev_addr = sa;
		if (msg.p2p_device_addr)
			dev_addr = msg.p2p_device_addr;
		p2p->cfg->prov_disc_req(p2p->cfg->cb_ctx, sa,
					msg.wps_config_methods,
					dev_addr, msg.pri_dev_type,
					msg.device_name, msg.config_methods,
					msg.capability ? msg.capability[0] : 0,
					msg.capability ? msg.capability[1] :
					0,
					msg.group_id, msg.group_id_len);
	}
	p2p_parse_free(&msg);
}


void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
				const u8 *data, size_t len)
{
	struct p2p_message msg;
	struct p2p_device *dev;
	u16 report_config_methods = 0, req_config_methods;
	int success = 0;

	if (p2p_parse(data, len, &msg))
		return;

	p2p_dbg(p2p, "Received Provision Discovery Response from " MACSTR
		" with config methods 0x%x",
		MAC2STR(sa), msg.wps_config_methods);

	dev = p2p_get_device(p2p, sa);
	if (dev == NULL || !dev->req_config_methods) {
		p2p_dbg(p2p, "Ignore Provision Discovery Response from " MACSTR
			" with no pending request", MAC2STR(sa));
		p2p_parse_free(&msg);
		return;
	}

	if (dev->dialog_token != msg.dialog_token) {
		p2p_dbg(p2p, "Ignore Provision Discovery Response with unexpected Dialog Token %u (expected %u)",
			msg.dialog_token, dev->dialog_token);
		p2p_parse_free(&msg);
		return;
	}

	if (p2p->pending_action_state == P2P_PENDING_PD) {
		os_memset(p2p->pending_pd_devaddr, 0, ETH_ALEN);
		p2p->pending_action_state = P2P_NO_PENDING_ACTION;
	}

	/*
	 * Use a local copy of the requested config methods since
	 * p2p_reset_pending_pd() can clear this in the peer entry.
	 */
	req_config_methods = dev->req_config_methods;

	/*
	 * If the response is from the peer to whom a user initiated request
	 * was sent earlier, we reset that state info here.
	 */
	if (p2p->user_initiated_pd &&
	    os_memcmp(p2p->pending_pd_devaddr, sa, ETH_ALEN) == 0)
		p2p_reset_pending_pd(p2p);

	if (msg.wps_config_methods != req_config_methods) {
		p2p_dbg(p2p, "Peer rejected our Provision Discovery Request (received config_methods 0x%x expected 0x%x",
			msg.wps_config_methods, req_config_methods);
		if (p2p->cfg->prov_disc_fail)
			p2p->cfg->prov_disc_fail(p2p->cfg->cb_ctx, sa,
						 P2P_PROV_DISC_REJECTED);
		p2p_parse_free(&msg);
		goto out;
	}

	report_config_methods = req_config_methods;
	dev->flags &= ~(P2P_DEV_PD_PEER_DISPLAY |
			P2P_DEV_PD_PEER_KEYPAD);
	if (req_config_methods & WPS_CONFIG_DISPLAY) {
		p2p_dbg(p2p, "Peer " MACSTR
			" accepted to show a PIN on display", MAC2STR(sa));
		dev->flags |= P2P_DEV_PD_PEER_DISPLAY;
	} else if (msg.wps_config_methods & WPS_CONFIG_KEYPAD) {
		p2p_dbg(p2p, "Peer " MACSTR
			" accepted to write our PIN using keypad",
			MAC2STR(sa));
		dev->flags |= P2P_DEV_PD_PEER_KEYPAD;
	}

	/* Store the provisioning info */
	dev->wps_prov_info = msg.wps_config_methods;

	p2p_parse_free(&msg);
	success = 1;

out:
	dev->req_config_methods = 0;
	p2p->cfg->send_action_done(p2p->cfg->cb_ctx);
	if (dev->flags & P2P_DEV_PD_BEFORE_GO_NEG) {
		p2p_dbg(p2p, "Start GO Neg after the PD-before-GO-Neg workaround with "
			MACSTR, MAC2STR(dev->info.p2p_device_addr));
		dev->flags &= ~P2P_DEV_PD_BEFORE_GO_NEG;
		p2p_connect_send(p2p, dev);
		return;
	}
	if (success && p2p->cfg->prov_disc_resp)
		p2p->cfg->prov_disc_resp(p2p->cfg->cb_ctx, sa,
					 report_config_methods);

	if (p2p->state == P2P_PD_DURING_FIND) {
		p2p_clear_timeout(p2p);
		p2p_continue_find(p2p);
	}
}


int p2p_send_prov_disc_req(struct p2p_data *p2p, struct p2p_device *dev,
			   int join, int force_freq)
{
	struct wpabuf *req;
	int freq;

	if (force_freq > 0)
		freq = force_freq;
	else
		freq = dev->listen_freq > 0 ? dev->listen_freq :
			dev->oper_freq;
	if (freq <= 0) {
		p2p_dbg(p2p, "No Listen/Operating frequency known for the peer "
			MACSTR " to send Provision Discovery Request",
			MAC2STR(dev->info.p2p_device_addr));
		return -1;
	}

	if (dev->flags & P2P_DEV_GROUP_CLIENT_ONLY) {
		if (!(dev->info.dev_capab &
		      P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY)) {
			p2p_dbg(p2p, "Cannot use PD with P2P Device " MACSTR
				" that is in a group and is not discoverable",
				MAC2STR(dev->info.p2p_device_addr));
			return -1;
		}
		/* TODO: use device discoverability request through GO */
	}

	if (p2p->p2ps_prov) {
		if (p2p->p2ps_prov->status == P2P_SC_SUCCESS_DEFERRED) {
			if (p2p->p2ps_prov->method == WPS_CONFIG_DISPLAY)
				dev->req_config_methods = WPS_CONFIG_KEYPAD;
			else if (p2p->p2ps_prov->method == WPS_CONFIG_KEYPAD)
				dev->req_config_methods = WPS_CONFIG_DISPLAY;
			else
				dev->req_config_methods = WPS_CONFIG_P2PS;
		} else {
			/* Order of preference, based on peer's capabilities */
			if (p2p->p2ps_prov->method)
				dev->req_config_methods =
					p2p->p2ps_prov->method;
			else if (dev->info.config_methods & WPS_CONFIG_P2PS)
				dev->req_config_methods = WPS_CONFIG_P2PS;
			else if (dev->info.config_methods & WPS_CONFIG_DISPLAY)
				dev->req_config_methods = WPS_CONFIG_DISPLAY;
			else
				dev->req_config_methods = WPS_CONFIG_KEYPAD;
		}
		p2p_dbg(p2p,
			"Building PD Request based on P2PS config method 0x%x status %d --> req_config_methods 0x%x",
			p2p->p2ps_prov->method, p2p->p2ps_prov->status,
			dev->req_config_methods);
	}

	req = p2p_build_prov_disc_req(p2p, dev, join);
	if (req == NULL)
		return -1;

	if (p2p->state != P2P_IDLE)
		p2p_stop_listen_for_freq(p2p, freq);
	p2p->pending_action_state = P2P_PENDING_PD;
	if (p2p_send_action(p2p, freq, dev->info.p2p_device_addr,
			    p2p->cfg->dev_addr, dev->info.p2p_device_addr,
			    wpabuf_head(req), wpabuf_len(req), 200) < 0) {
		p2p_dbg(p2p, "Failed to send Action frame");
		wpabuf_free(req);
		return -1;
	}

	os_memcpy(p2p->pending_pd_devaddr, dev->info.p2p_device_addr, ETH_ALEN);

	wpabuf_free(req);
	return 0;
}


int p2p_prov_disc_req(struct p2p_data *p2p, const u8 *peer_addr,
		      struct p2ps_provision *p2ps_prov,
		      u16 config_methods, int join, int force_freq,
		      int user_initiated_pd)
{
	struct p2p_device *dev;

	dev = p2p_get_device(p2p, peer_addr);
	if (dev == NULL)
		dev = p2p_get_device_interface(p2p, peer_addr);
	if (dev == NULL || (dev->flags & P2P_DEV_PROBE_REQ_ONLY)) {
		p2p_dbg(p2p, "Provision Discovery Request destination " MACSTR
			" not yet known", MAC2STR(peer_addr));
		os_free(p2ps_prov);
		return -1;
	}

	p2p_dbg(p2p, "Provision Discovery Request with " MACSTR
		" (config methods 0x%x)",
		MAC2STR(peer_addr), config_methods);
	if (config_methods == 0 && !p2ps_prov) {
		os_free(p2ps_prov);
		return -1;
	}

	if (p2ps_prov && p2ps_prov->status == P2P_SC_SUCCESS_DEFERRED &&
	    p2p->p2ps_prov) {
		/* Use cached method from deferred provisioning */
		p2ps_prov->method = p2p->p2ps_prov->method;
	}

	/* Reset provisioning info */
	dev->wps_prov_info = 0;
	os_free(p2p->p2ps_prov);
	p2p->p2ps_prov = p2ps_prov;

	dev->req_config_methods = config_methods;
	if (join)
		dev->flags |= P2P_DEV_PD_FOR_JOIN;
	else
		dev->flags &= ~P2P_DEV_PD_FOR_JOIN;

	if (p2p->state != P2P_IDLE && p2p->state != P2P_SEARCH &&
	    p2p->state != P2P_LISTEN_ONLY) {
		p2p_dbg(p2p, "Busy with other operations; postpone Provision Discovery Request with "
			MACSTR " (config methods 0x%x)",
			MAC2STR(peer_addr), config_methods);
		return 0;
	}

	p2p->user_initiated_pd = user_initiated_pd;
	p2p->pd_force_freq = force_freq;

	if (p2p->user_initiated_pd)
		p2p->pd_retries = MAX_PROV_DISC_REQ_RETRIES;

	/*
	 * Assign dialog token here to use the same value in each retry within
	 * the same PD exchange.
	 */
	dev->dialog_token++;
	if (dev->dialog_token == 0)
		dev->dialog_token = 1;

	return p2p_send_prov_disc_req(p2p, dev, join, force_freq);
}


void p2p_reset_pending_pd(struct p2p_data *p2p)
{
	struct p2p_device *dev;

	dl_list_for_each(dev, &p2p->devices, struct p2p_device, list) {
		if (os_memcmp(p2p->pending_pd_devaddr,
			      dev->info.p2p_device_addr, ETH_ALEN))
			continue;
		if (!dev->req_config_methods)
			continue;
		if (dev->flags & P2P_DEV_PD_FOR_JOIN)
			continue;
		/* Reset the config methods of the device */
		dev->req_config_methods = 0;
	}

	p2p->user_initiated_pd = 0;
	os_memset(p2p->pending_pd_devaddr, 0, ETH_ALEN);
	p2p->pd_retries = 0;
	p2p->pd_force_freq = 0;
}
