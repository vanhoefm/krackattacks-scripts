/*
 * WPA Supplicant - driver interaction with Linux nl80211/cfg80211
 * Copyright (c) 2003-2008, Jouni Malinen <j@w1.fi>
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
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "nl80211_copy.h"
#include "wireless_copy.h"

#include "common.h"
#include "driver.h"
#include "eloop.h"
#include "ieee802_11_defs.h"

#ifdef CONFIG_AP

#include <netpacket/packet.h>
#include <linux/filter.h>
#include "radiotap.h"
#include "radiotap_iter.h"
#include "../hostapd/driver.h"
#include "../hostapd/hostapd_defs.h"

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

#endif /* CONFIG_AP */

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP   0x10000         /* driver signals L1 up         */
#endif
#ifndef IFF_DORMANT
#define IFF_DORMANT    0x20000         /* driver signals dormant       */
#endif

#ifndef IF_OPER_DORMANT
#define IF_OPER_DORMANT 5
#endif
#ifndef IF_OPER_UP
#define IF_OPER_UP 6
#endif


struct wpa_driver_nl80211_data {
	void *ctx;
	int link_event_sock;
	int ioctl_sock;
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	int if_removed;
	struct wpa_driver_capa capa;
	int has_capability;

	int operstate;

	int scan_complete_events;

	struct nl_handle *nl_handle;
	struct nl_cache *nl_cache;
	struct nl_cb *nl_cb;
	struct genl_family *nl80211;

	u8 bssid[ETH_ALEN];
	int associated;
	u8 ssid[32];
	size_t ssid_len;

#ifdef CONFIG_AP
	int beacon_int;
	unsigned int beacon_set:1;
	int monitor_sock;
	int monitor_ifidx;
#endif /* CONFIG_AP */
};


static void wpa_driver_nl80211_scan_timeout(void *eloop_ctx,
					    void *timeout_ctx);
static int wpa_driver_nl80211_set_mode(struct wpa_driver_nl80211_data *drv,
				       int mode);
static int
wpa_driver_nl80211_finish_drv_init(struct wpa_driver_nl80211_data *drv);

#ifdef CONFIG_AP
static void nl80211_remove_iface(struct wpa_driver_nl80211_data *drv,
				 int ifidx);
#endif /* CONFIG_AP */


/* nl80211 code */
static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}

static int send_and_recv_msgs(struct wpa_driver_nl80211_data *drv,
			      struct nl_msg *msg,
			      int (*valid_handler)(struct nl_msg *, void *),
			      void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;

	cb = nl_cb_clone(drv->nl_cb);
	if (!cb)
		goto out;

	err = nl_send_auto_complete(drv->nl_handle, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0)
		nl_recvmsgs(drv->nl_handle, cb);
 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}


struct family_data {
	const char *group;
	int id;
};


static int family_handler(struct nl_msg *msg, void *arg)
{
	struct family_data *res = arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int i;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
		struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
		nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
			  nla_len(mcgrp), NULL);
		if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
		    os_strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
			       res->group,
			       nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
			continue;
		res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	};

	return NL_SKIP;
}


static int nl_get_multicast_id(struct wpa_driver_nl80211_data *drv,
			       const char *family, const char *group)
{
	struct nl_msg *msg;
	int ret = -1;
	struct family_data res = { group, -ENOENT };

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(drv->nl_handle, "nlctrl"),
		    0, 0, CTRL_CMD_GETFAMILY, 0);
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = send_and_recv_msgs(drv, msg, family_handler, &res);
	msg = NULL;
	if (ret == 0)
		ret = res.id;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}


static int wpa_driver_nl80211_send_oper_ifla(
	struct wpa_driver_nl80211_data *drv,
	int linkmode, int operstate)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifinfo;
		char opts[16];
	} req;
	struct rtattr *rta;
	static int nl_seq;
	ssize_t ret;

	os_memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_type = RTM_SETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_seq = ++nl_seq;
	req.hdr.nlmsg_pid = 0;

	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_type = 0;
	req.ifinfo.ifi_index = drv->ifindex;
	req.ifinfo.ifi_flags = 0;
	req.ifinfo.ifi_change = 0;

	if (linkmode != -1) {
		rta = (struct rtattr *)
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len));
		rta->rta_type = IFLA_LINKMODE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = linkmode;
		req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) +
			RTA_LENGTH(sizeof(char));
	}
	if (operstate != -1) {
		rta = (struct rtattr *)
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len));
		rta->rta_type = IFLA_OPERSTATE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = operstate;
		req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) +
			RTA_LENGTH(sizeof(char));
	}

	wpa_printf(MSG_DEBUG, "WEXT: Operstate: linkmode=%d, operstate=%d",
		   linkmode, operstate);

	ret = send(drv->link_event_sock, &req, req.hdr.nlmsg_len, 0);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "WEXT: Sending operstate IFLA failed: "
			   "%s (assume operstate is not supported)",
			   strerror(errno));
	}

	return ret < 0 ? -1 : 0;
}


static int wpa_driver_nl80211_set_auth_param(
	struct wpa_driver_nl80211_data *drv, int idx, u32 value)
{
	struct iwreq iwr;
	int ret = 0;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.param.flags = idx & IW_AUTH_INDEX;
	iwr.u.param.value = value;

	if (ioctl(drv->ioctl_sock, SIOCSIWAUTH, &iwr) < 0) {
		if (errno != EOPNOTSUPP) {
			wpa_printf(MSG_DEBUG, "WEXT: SIOCSIWAUTH(param %d "
				   "value 0x%x) failed: %s)",
				   idx, value, strerror(errno));
		}
		ret = errno == EOPNOTSUPP ? -2 : -1;
	}

	return ret;
}


static int wpa_driver_nl80211_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_nl80211_data *drv = priv;
	if (!drv->associated)
		return -1;
	os_memcpy(bssid, drv->bssid, ETH_ALEN);
	return 0;
}


static int wpa_driver_nl80211_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_nl80211_data *drv = priv;
	if (!drv->associated)
		return -1;
	os_memcpy(ssid, drv->ssid, drv->ssid_len);
	return drv->ssid_len;
}


static void wpa_driver_nl80211_event_link(struct wpa_driver_nl80211_data *drv,
					  void *ctx, char *buf, size_t len,
					  int del)
{
	union wpa_event_data event;

	os_memset(&event, 0, sizeof(event));
	if (len > sizeof(event.interface_status.ifname))
		len = sizeof(event.interface_status.ifname) - 1;
	os_memcpy(event.interface_status.ifname, buf, len);
	event.interface_status.ievent = del ? EVENT_INTERFACE_REMOVED :
		EVENT_INTERFACE_ADDED;

	wpa_printf(MSG_DEBUG, "RTM_%sLINK, IFLA_IFNAME: Interface '%s' %s",
		   del ? "DEL" : "NEW",
		   event.interface_status.ifname,
		   del ? "removed" : "added");

	if (os_strcmp(drv->ifname, event.interface_status.ifname) == 0) {
		if (del)
			drv->if_removed = 1;
		else
			drv->if_removed = 0;
	}

	wpa_supplicant_event(ctx, EVENT_INTERFACE_STATUS, &event);
}


static int wpa_driver_nl80211_own_ifname(struct wpa_driver_nl80211_data *drv,
					 struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	int attrlen, _nlmsg_len, rta_len;
	struct rtattr *attr;

	ifi = NLMSG_DATA(h);

	_nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - _nlmsg_len;
	if (attrlen < 0)
		return 0;

	attr = (struct rtattr *) (((char *) ifi) + _nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_IFNAME) {
			if (os_strcmp(((char *) attr) + rta_len, drv->ifname)
			    == 0)
				return 1;
			else
				break;
		}
		attr = RTA_NEXT(attr, attrlen);
	}

	return 0;
}


static int wpa_driver_nl80211_own_ifindex(struct wpa_driver_nl80211_data *drv,
					  int ifindex, struct nlmsghdr *h)
{
	if (drv->ifindex == ifindex)
		return 1;

	if (drv->if_removed && wpa_driver_nl80211_own_ifname(drv, h)) {
		drv->ifindex = if_nametoindex(drv->ifname);
		wpa_printf(MSG_DEBUG, "nl80211: Update ifindex for a removed "
			   "interface");
		wpa_driver_nl80211_finish_drv_init(drv);
		return 1;
	}

	return 0;
}


static void wpa_driver_nl80211_event_rtm_newlink(struct wpa_driver_nl80211_data *drv,
					      void *ctx, struct nlmsghdr *h,
					      size_t len)
{
	struct ifinfomsg *ifi;
	int attrlen, _nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	if (!wpa_driver_nl80211_own_ifindex(drv, ifi->ifi_index, h)) {
		wpa_printf(MSG_DEBUG, "Ignore event for foreign ifindex %d",
			   ifi->ifi_index);
		return;
	}

	wpa_printf(MSG_DEBUG, "RTM_NEWLINK: operstate=%d ifi_flags=0x%x "
		   "(%s%s%s%s)",
		   drv->operstate, ifi->ifi_flags,
		   (ifi->ifi_flags & IFF_UP) ? "[UP]" : "",
		   (ifi->ifi_flags & IFF_RUNNING) ? "[RUNNING]" : "",
		   (ifi->ifi_flags & IFF_LOWER_UP) ? "[LOWER_UP]" : "",
		   (ifi->ifi_flags & IFF_DORMANT) ? "[DORMANT]" : "");
	/*
	 * Some drivers send the association event before the operup event--in
	 * this case, lifting operstate in wpa_driver_nl80211_set_operstate()
	 * fails. This will hit us when wpa_supplicant does not need to do
	 * IEEE 802.1X authentication
	 */
	if (drv->operstate == 1 &&
	    (ifi->ifi_flags & (IFF_LOWER_UP | IFF_DORMANT)) == IFF_LOWER_UP &&
	    !(ifi->ifi_flags & IFF_RUNNING))
		wpa_driver_nl80211_send_oper_ifla(drv, -1, IF_OPER_UP);

	_nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - _nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + _nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_IFNAME) {
			wpa_driver_nl80211_event_link(
				drv, ctx,
				((char *) attr) + rta_len,
				attr->rta_len - rta_len, 0);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void wpa_driver_nl80211_event_rtm_dellink(struct wpa_driver_nl80211_data *drv,
					      void *ctx, struct nlmsghdr *h,
					      size_t len)
{
	struct ifinfomsg *ifi;
	int attrlen, _nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	_nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - _nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + _nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_IFNAME) {
			wpa_driver_nl80211_event_link(
				drv, ctx,
				((char *) attr) + rta_len,
				attr->rta_len - rta_len, 1);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void wpa_driver_nl80211_event_receive_link(int sock, void *eloop_ctx,
						  void *sock_ctx)
{
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	int max_events = 10;

try_again:
	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("recvfrom(netlink)");
		return;
	}

	h = (struct nlmsghdr *) buf;
	while (left >= (int) sizeof(*h)) {
		int len, plen;

		len = h->nlmsg_len;
		plen = len - sizeof(*h);
		if (len > left || plen < 0) {
			wpa_printf(MSG_DEBUG, "Malformed netlink message: "
				   "len=%d left=%d plen=%d",
				   len, left, plen);
			break;
		}

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			wpa_driver_nl80211_event_rtm_newlink(eloop_ctx, sock_ctx,
							  h, plen);
			break;
		case RTM_DELLINK:
			wpa_driver_nl80211_event_rtm_dellink(eloop_ctx, sock_ctx,
							  h, plen);
			break;
		}

		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "%d extra bytes in the end of netlink "
			   "message", left);
	}

	if (--max_events > 0) {
		/*
		 * Try to receive all events in one eloop call in order to
		 * limit race condition on cases where AssocInfo event, Assoc
		 * event, and EAPOL frames are received more or less at the
		 * same time. We want to process the event messages first
		 * before starting EAPOL processing.
		 */
		goto try_again;
	}
}


static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}


static void mlme_event_auth(struct wpa_driver_nl80211_data *drv,
			    const u8 *frame, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	union wpa_event_data event;

	mgmt = (const struct ieee80211_mgmt *) frame;
	if (len < 24 + sizeof(mgmt->u.auth)) {
		wpa_printf(MSG_DEBUG, "nl80211: Too short association event "
			   "frame");
		return;
	}

	os_memset(&event, 0, sizeof(event));
	os_memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
	event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
	event.auth.status_code = le_to_host16(mgmt->u.auth.status_code);
	if (len > 24 + sizeof(mgmt->u.auth)) {
		event.auth.ies = mgmt->u.auth.variable;
		event.auth.ies_len = len - 24 - sizeof(mgmt->u.auth);
	}

	wpa_supplicant_event(drv->ctx, EVENT_AUTH, &event);
}


static void mlme_event_assoc(struct wpa_driver_nl80211_data *drv,
			    const u8 *frame, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	union wpa_event_data event;
	u16 status;

	mgmt = (const struct ieee80211_mgmt *) frame;
	if (len < 24 + sizeof(mgmt->u.assoc_resp)) {
		wpa_printf(MSG_DEBUG, "nl80211: Too short association event "
			   "frame");
		return;
	}

	status = le_to_host16(mgmt->u.assoc_resp.status_code);
	if (status != WLAN_STATUS_SUCCESS) {
		os_memset(&event, 0, sizeof(event));
		if (len > 24 + sizeof(mgmt->u.assoc_resp)) {
			event.assoc_reject.resp_ies =
				(u8 *) mgmt->u.assoc_resp.variable;
			event.assoc_reject.resp_ies_len =
				len - 24 - sizeof(mgmt->u.assoc_resp);
		}
		event.assoc_reject.status_code = status;

		wpa_supplicant_event(drv->ctx, EVENT_ASSOC_REJECT, &event);
		return;
	}

	drv->associated = 1;
	os_memcpy(drv->bssid, mgmt->sa, ETH_ALEN);

	os_memset(&event, 0, sizeof(event));
	if (len > 24 + sizeof(mgmt->u.assoc_resp)) {
		event.assoc_info.resp_ies = (u8 *) mgmt->u.assoc_resp.variable;
		event.assoc_info.resp_ies_len =
			len - 24 - sizeof(mgmt->u.assoc_resp);
	}

	wpa_supplicant_event(drv->ctx, EVENT_ASSOC, &event);
}


static void mlme_event(struct wpa_driver_nl80211_data *drv,
		       enum nl80211_commands cmd, struct nlattr *frame)
{
	if (frame == NULL) {
		wpa_printf(MSG_DEBUG, "nl80211: MLME event %d without frame "
			   "data", cmd);
		return;
	}

	wpa_printf(MSG_DEBUG, "nl80211: MLME event %d", cmd);
	wpa_hexdump(MSG_MSGDUMP, "nl80211: MLME event frame",
		    nla_data(frame), nla_len(frame));

	switch (cmd) {
	case NL80211_CMD_AUTHENTICATE:
		mlme_event_auth(drv, nla_data(frame), nla_len(frame));
		break;
	case NL80211_CMD_ASSOCIATE:
		mlme_event_assoc(drv, nla_data(frame), nla_len(frame));
		break;
	case NL80211_CMD_DEAUTHENTICATE:
		drv->associated = 0;
		wpa_supplicant_event(drv->ctx, EVENT_DEAUTH, NULL);
		break;
	case NL80211_CMD_DISASSOCIATE:
		drv->associated = 0;
		wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);
		break;
	default:
		break;
	}
}


static int process_event(struct nl_msg *msg, void *arg)
{
	struct wpa_driver_nl80211_data *drv = arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_IFINDEX]) {
		int ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
		if (ifindex != drv->ifindex) {
			wpa_printf(MSG_DEBUG, "nl80211: Ignored event (cmd=%d)"
				   " for foreign interface (ifindex %d)",
				   gnlh->cmd, ifindex);
			return NL_SKIP;
		}
	}

	switch (gnlh->cmd) {
	case NL80211_CMD_NEW_SCAN_RESULTS:
		wpa_printf(MSG_DEBUG, "nl80211: New scan results available");
		drv->scan_complete_events = 1;
		eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv,
				     drv->ctx);
		wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);
		break;
	case NL80211_CMD_SCAN_ABORTED:
		wpa_printf(MSG_DEBUG, "nl80211: Scan aborted");
		/*
		 * Need to indicate that scan results are available in order
		 * not to make wpa_supplicant stop its scanning.
		 */
		eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv,
				     drv->ctx);
		wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);
		break;
	case NL80211_CMD_AUTHENTICATE:
	case NL80211_CMD_ASSOCIATE:
	case NL80211_CMD_DEAUTHENTICATE:
	case NL80211_CMD_DISASSOCIATE:
		mlme_event(drv, gnlh->cmd, tb[NL80211_ATTR_FRAME]);
		break;
	default:
		wpa_printf(MSG_DEBUG, "nl80211: Ignored unknown event "
			   "(cmd=%d)", gnlh->cmd);
		break;
	}

	return NL_SKIP;
}


static void wpa_driver_nl80211_event_receive(int sock, void *eloop_ctx,
					     void *sock_ctx)
{
	struct nl_cb *cb;
	struct wpa_driver_nl80211_data *drv = eloop_ctx;

	wpa_printf(MSG_DEBUG, "nl80211: Event message available");

	cb = nl_cb_clone(drv->nl_cb);
	if (!cb)
		return;
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, process_event, drv);
	nl_recvmsgs(drv->nl_handle, cb);
	nl_cb_put(cb);
}


static int wpa_driver_nl80211_get_ifflags_ifname(struct wpa_driver_nl80211_data *drv,
					      const char *ifname, int *flags)
{
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}
	*flags = ifr.ifr_flags & 0xffff;
	return 0;
}


/**
 * wpa_driver_nl80211_get_ifflags - Get interface flags (SIOCGIFFLAGS)
 * @drv: driver_nl80211 private data
 * @flags: Pointer to returned flags value
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_nl80211_get_ifflags(struct wpa_driver_nl80211_data *drv,
					  int *flags)
{
	return wpa_driver_nl80211_get_ifflags_ifname(drv, drv->ifname, flags);
}


static int wpa_driver_nl80211_set_ifflags_ifname(
	struct wpa_driver_nl80211_data *drv,
	const char *ifname, int flags)
{
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = flags & 0xffff;
	if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
		perror("SIOCSIFFLAGS");
		return -1;
	}
	return 0;
}


/**
 * wpa_driver_nl80211_set_ifflags - Set interface flags (SIOCSIFFLAGS)
 * @drv: driver_nl80211 private data
 * @flags: New value for flags
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_nl80211_set_ifflags(struct wpa_driver_nl80211_data *drv,
					  int flags)
{
	return wpa_driver_nl80211_set_ifflags_ifname(drv, drv->ifname, flags);
}


/**
 * wpa_driver_nl80211_set_country - ask nl80211 to set the regulatory domain
 * @priv: driver_nl80211 private data
 * @alpha2_arg: country to which to switch to
 * Returns: 0 on success, -1 on failure
 *
 * This asks nl80211 to set the regulatory domain for given
 * country ISO / IEC alpha2.
 */
static int wpa_driver_nl80211_set_country(void *priv, const char *alpha2_arg)
{
	struct wpa_driver_nl80211_data *drv = priv;
	char alpha2[3];
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		goto nla_put_failure;

	alpha2[0] = alpha2_arg[0];
	alpha2[1] = alpha2_arg[1];
	alpha2[2] = '\0';

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, NL80211_CMD_REQ_SET_REG, 0);

	NLA_PUT_STRING(msg, NL80211_ATTR_REG_ALPHA2, alpha2);
	if (send_and_recv_msgs(drv, msg, NULL, NULL))
		return -EINVAL;
	return 0;
nla_put_failure:
	return -EINVAL;
}


struct wiphy_info_data {
	int max_scan_ssids;
	int ap_supported;
};


static int wiphy_info_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct wiphy_info_data *info = arg;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_MAX_NUM_SCAN_SSIDS])
		info->max_scan_ssids =
			nla_get_u8(tb[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]);

	if (tb[NL80211_ATTR_SUPPORTED_IFTYPES]) {
		struct nlattr *nl_mode;
		int i;
		nla_for_each_nested(nl_mode,
				    tb[NL80211_ATTR_SUPPORTED_IFTYPES], i) {
			if (nl_mode->nla_type == NL80211_IFTYPE_AP) {
				info->ap_supported = 1;
				break;
			}
		}
	}

	return NL_SKIP;
}


static int wpa_driver_nl80211_get_info(struct wpa_driver_nl80211_data *drv,
				       struct wiphy_info_data *info)
{
	struct nl_msg *msg;

	os_memset(info, 0, sizeof(*info));
	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, NL80211_CMD_GET_WIPHY, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);

	if (send_and_recv_msgs(drv, msg, wiphy_info_handler, info) == 0)
		return 0;
	msg = NULL;
nla_put_failure:
	nlmsg_free(msg);
	return -1;
}


static void wpa_driver_nl80211_capa(struct wpa_driver_nl80211_data *drv)
{
	struct wiphy_info_data info;
	if (wpa_driver_nl80211_get_info(drv, &info))
		return;
	drv->has_capability = 1;
	/* For now, assume TKIP, CCMP, WPA, WPA2 are supported */
	drv->capa.key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
	drv->capa.enc = WPA_DRIVER_CAPA_ENC_WEP40 |
		WPA_DRIVER_CAPA_ENC_WEP104 |
		WPA_DRIVER_CAPA_ENC_TKIP |
		WPA_DRIVER_CAPA_ENC_CCMP;

	drv->capa.max_scan_ssids = info.max_scan_ssids;
	if (info.ap_supported)
		drv->capa.flags |= WPA_DRIVER_FLAGS_AP;
}


/**
 * wpa_driver_nl80211_init - Initialize nl80211 driver interface
 * @ctx: context to be used when calling wpa_supplicant functions,
 * e.g., wpa_supplicant_event()
 * @ifname: interface name, e.g., wlan0
 * Returns: Pointer to private data, %NULL on failure
 */
static void * wpa_driver_nl80211_init(void *ctx, const char *ifname)
{
	int s, ret;
	struct sockaddr_nl local;
	struct wpa_driver_nl80211_data *drv;

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	drv->ctx = ctx;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
#ifdef CONFIG_AP
	drv->monitor_ifidx = -1;
	drv->monitor_sock = -1;
#endif /* CONFIG_AP */

	drv->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (drv->nl_cb == NULL) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to allocate netlink "
			   "callbacks");
		goto err1;
	}

	drv->nl_handle = nl_handle_alloc_cb(drv->nl_cb);
	if (drv->nl_handle == NULL) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to allocate netlink "
			   "callbacks");
		goto err2;
	}

	if (genl_connect(drv->nl_handle)) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to connect to generic "
			   "netlink");
		goto err3;
	}

	drv->nl_cache = genl_ctrl_alloc_cache(drv->nl_handle);
	if (drv->nl_cache == NULL) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to allocate generic "
			   "netlink cache");
		goto err3;
	}

	drv->nl80211 = genl_ctrl_search_by_name(drv->nl_cache, "nl80211");
	if (drv->nl80211 == NULL) {
		wpa_printf(MSG_ERROR, "nl80211: 'nl80211' generic netlink not "
			   "found");
		goto err4;
	}

	ret = nl_get_multicast_id(drv, "nl80211", "scan");
	if (ret >= 0)
		ret = nl_socket_add_membership(drv->nl_handle, ret);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "nl80211: Could not add multicast "
			   "membership for scan events: %d (%s)",
			   ret, strerror(-ret));
		goto err4;
	}

	ret = nl_get_multicast_id(drv, "nl80211", "mlme");
	if (ret >= 0)
		ret = nl_socket_add_membership(drv->nl_handle, ret);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "nl80211: Could not add multicast "
			   "membership for mlme events: %d (%s)",
			   ret, strerror(-ret));
		goto err4;
	}
	drv->capa.flags |= WPA_DRIVER_FLAGS_SME;

	eloop_register_read_sock(nl_socket_get_fd(drv->nl_handle),
				 wpa_driver_nl80211_event_receive, drv, ctx);

	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket(PF_INET,SOCK_DGRAM)");
		goto err5;
	}

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		goto err6;
	}

	os_memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		goto err6;
	}

	eloop_register_read_sock(s, wpa_driver_nl80211_event_receive_link, drv,
				 ctx);
	drv->link_event_sock = s;

	if (wpa_driver_nl80211_finish_drv_init(drv))
		goto err7;

	return drv;

err7:
	eloop_unregister_read_sock(drv->link_event_sock);
	close(drv->link_event_sock);
err6:
	close(drv->ioctl_sock);
err5:
	genl_family_put(drv->nl80211);
err4:
	nl_cache_free(drv->nl_cache);
err3:
	nl_handle_destroy(drv->nl_handle);
err2:
	nl_cb_put(drv->nl_cb);
err1:
	os_free(drv);
	return NULL;
}


static int
wpa_driver_nl80211_finish_drv_init(struct wpa_driver_nl80211_data *drv)
{
	int flags;

	drv->ifindex = if_nametoindex(drv->ifname);

	if (wpa_driver_nl80211_set_mode(drv, 0) < 0) {
		wpa_printf(MSG_DEBUG, "nl80211: Could not configure driver to "
			   "use managed mode");
	}

	if (wpa_driver_nl80211_get_ifflags(drv, &flags) != 0) {
		wpa_printf(MSG_ERROR, "Could not get interface '%s' flags",
			   drv->ifname);
		return -1;
	}
	if (!(flags & IFF_UP)) {
		if (wpa_driver_nl80211_set_ifflags(drv, flags | IFF_UP) != 0) {
			wpa_printf(MSG_ERROR, "Could not set interface '%s' "
				   "UP", drv->ifname);
			return -1;
		}
	}

	wpa_driver_nl80211_capa(drv);

	wpa_driver_nl80211_send_oper_ifla(drv, 1, IF_OPER_DORMANT);

	return 0;
}


/**
 * wpa_driver_nl80211_deinit - Deinitialize nl80211 driver interface
 * @priv: Pointer to private nl80211 data from wpa_driver_nl80211_init()
 *
 * Shut down driver interface and processing of driver events. Free
 * private data buffer if one was allocated in wpa_driver_nl80211_init().
 */
static void wpa_driver_nl80211_deinit(void *priv)
{
	struct wpa_driver_nl80211_data *drv = priv;
	int flags;

#ifdef CONFIG_AP
	if (drv->monitor_ifidx >= 0)
		nl80211_remove_iface(drv, drv->monitor_ifidx);
	if (drv->monitor_sock >= 0) {
		eloop_unregister_read_sock(drv->monitor_sock);
		close(drv->monitor_sock);
	}
#endif /* CONFIG_AP */

	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);

	wpa_driver_nl80211_set_auth_param(drv, IW_AUTH_DROP_UNENCRYPTED, 0);

	wpa_driver_nl80211_send_oper_ifla(priv, 0, IF_OPER_UP);

	eloop_unregister_read_sock(drv->link_event_sock);

	if (wpa_driver_nl80211_get_ifflags(drv, &flags) == 0)
		(void) wpa_driver_nl80211_set_ifflags(drv, flags & ~IFF_UP);
	wpa_driver_nl80211_set_mode(drv, 0);

	close(drv->link_event_sock);
	close(drv->ioctl_sock);

	eloop_unregister_read_sock(nl_socket_get_fd(drv->nl_handle));
	genl_family_put(drv->nl80211);
	nl_cache_free(drv->nl_cache);
	nl_handle_destroy(drv->nl_handle);
	nl_cb_put(drv->nl_cb);

	os_free(drv);
}


/**
 * wpa_driver_nl80211_scan_timeout - Scan timeout to report scan completion
 * @eloop_ctx: Unused
 * @timeout_ctx: ctx argument given to wpa_driver_nl80211_init()
 *
 * This function can be used as registered timeout when starting a scan to
 * generate a scan completed event if the driver does not report this.
 */
static void wpa_driver_nl80211_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}


/**
 * wpa_driver_nl80211_scan - Request the driver to initiate scan
 * @priv: Pointer to private wext data from wpa_driver_nl80211_init()
 * @params: Scan parameters
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_nl80211_scan(void *priv,
				   struct wpa_driver_scan_params *params)
{
	struct wpa_driver_nl80211_data *drv = priv;
	int ret = 0, timeout;
	struct nl_msg *msg, *ssids, *freqs;
	size_t i;

	msg = nlmsg_alloc();
	ssids = nlmsg_alloc();
	freqs = nlmsg_alloc();
	if (!msg || !ssids || !freqs) {
		nlmsg_free(msg);
		nlmsg_free(ssids);
		nlmsg_free(freqs);
		return -1;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, 0,
		    NL80211_CMD_TRIGGER_SCAN, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);

	for (i = 0; i < params->num_ssids; i++) {
		NLA_PUT(ssids, i + 1, params->ssids[i].ssid_len,
			params->ssids[i].ssid);
	}
	if (params->num_ssids)
		nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);

	if (params->extra_ies) {
		NLA_PUT(msg, NL80211_ATTR_IE, params->extra_ies_len,
			params->extra_ies);
	}

	if (params->freqs) {
		for (i = 0; params->freqs[i]; i++)
			NLA_PUT_U32(freqs, i + 1, params->freqs[i]);
		nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);
	}

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Scan trigger failed: ret=%d "
			   "(%s)", ret, strerror(-ret));
		goto nla_put_failure;
	}

	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	timeout = 10;
	if (drv->scan_complete_events) {
		/*
		 * The driver seems to deliver events to notify when scan is
		 * complete, so use longer timeout to avoid race conditions
		 * with scanning and following association request.
		 */
		timeout = 30;
	}
	wpa_printf(MSG_DEBUG, "Scan requested (ret=%d) - scan timeout %d "
		   "seconds", ret, timeout);
	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(timeout, 0, wpa_driver_nl80211_scan_timeout,
			       drv, drv->ctx);

nla_put_failure:
	nlmsg_free(ssids);
	nlmsg_free(msg);
	nlmsg_free(freqs);
	return ret;
}


static int bss_info_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_BSSID] = { .type = NLA_UNSPEC },
		[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_BSS_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { .type = NLA_UNSPEC },
		[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
	};
	struct wpa_scan_results *res = arg;
	struct wpa_scan_res **tmp;
	struct wpa_scan_res *r;
	const u8 *ie;
	size_t ie_len;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[NL80211_ATTR_BSS])
		return NL_SKIP;
	if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
			     bss_policy))
		return NL_SKIP;
	if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
		ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	} else {
		ie = NULL;
		ie_len = 0;
	}

	r = os_zalloc(sizeof(*r) + ie_len);
	if (r == NULL)
		return NL_SKIP;
	if (bss[NL80211_BSS_BSSID])
		os_memcpy(r->bssid, nla_data(bss[NL80211_BSS_BSSID]),
			  ETH_ALEN);
	if (bss[NL80211_BSS_FREQUENCY])
		r->freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
	if (bss[NL80211_BSS_BEACON_INTERVAL])
		r->beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
	if (bss[NL80211_BSS_CAPABILITY])
		r->caps = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
	r->flags |= WPA_SCAN_NOISE_INVALID;
	if (bss[NL80211_BSS_SIGNAL_MBM]) {
		r->level = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
		r->level /= 100; /* mBm to dBm */
		r->flags |= WPA_SCAN_LEVEL_DBM | WPA_SCAN_QUAL_INVALID;
	} else if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
		r->level = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
		r->flags |= WPA_SCAN_LEVEL_INVALID;
	} else
		r->flags |= WPA_SCAN_LEVEL_INVALID | WPA_SCAN_QUAL_INVALID;
	if (bss[NL80211_BSS_TSF])
		r->tsf = nla_get_u64(bss[NL80211_BSS_TSF]);
	r->ie_len = ie_len;
	if (ie)
		os_memcpy(r + 1, ie, ie_len);

	tmp = os_realloc(res->res,
			 (res->num + 1) * sizeof(struct wpa_scan_res *));
	if (tmp == NULL) {
		os_free(r);
		return NL_SKIP;
	}
	tmp[res->num++] = r;
	res->res = tmp;

	return NL_SKIP;
}


/**
 * wpa_driver_nl80211_get_scan_results - Fetch the latest scan results
 * @priv: Pointer to private wext data from wpa_driver_nl80211_init()
 * Returns: Scan results on success, -1 on failure
 */
static struct wpa_scan_results *
wpa_driver_nl80211_get_scan_results(void *priv)
{
	struct wpa_driver_nl80211_data *drv = priv;
	struct nl_msg *msg;
	struct wpa_scan_results *res;
	int ret;

	res = os_zalloc(sizeof(*res));
	if (res == NULL)
		return 0;
	msg = nlmsg_alloc();
	if (!msg)
		goto nla_put_failure;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, NLM_F_DUMP,
		    NL80211_CMD_GET_SCAN, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);

	ret = send_and_recv_msgs(drv, msg, bss_info_handler, res);
	msg = NULL;
	if (ret == 0) {
		wpa_printf(MSG_DEBUG, "Received scan results (%lu BSSes)",
			   (unsigned long) res->num);
		return res;
	}
	wpa_printf(MSG_DEBUG, "nl80211: Scan result fetch failed: ret=%d "
		   "(%s)", ret, strerror(-ret));
nla_put_failure:
	nlmsg_free(msg);
	wpa_scan_results_free(res);
	return NULL;
}


static int wpa_driver_nl80211_set_key(void *priv, wpa_alg alg,
				      const u8 *addr, int key_idx,
				      int set_tx, const u8 *seq,
				      size_t seq_len,
				      const u8 *key, size_t key_len)
{
	struct wpa_driver_nl80211_data *drv = priv;
	int err;
	struct nl_msg *msg;

	wpa_printf(MSG_DEBUG, "%s: alg=%d addr=%p key_idx=%d set_tx=%d "
		   "seq_len=%lu key_len=%lu",
		   __func__, alg, addr, key_idx, set_tx,
		   (unsigned long) seq_len, (unsigned long) key_len);

	msg = nlmsg_alloc();
	if (msg == NULL)
		return -1;

	if (alg == WPA_ALG_NONE) {
		genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, 0,
			    NL80211_CMD_DEL_KEY, 0);
	} else {
		genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, 0,
			    NL80211_CMD_NEW_KEY, 0);
		NLA_PUT(msg, NL80211_ATTR_KEY_DATA, key_len, key);
		switch (alg) {
		case WPA_ALG_WEP:
			if (key_len == 5)
				NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER,
					    0x000FAC01);
			else
				NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER,
					    0x000FAC05);
			break;
		case WPA_ALG_TKIP:
			NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER, 0x000FAC02);
			break;
		case WPA_ALG_CCMP:
			NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER, 0x000FAC04);
			break;
#ifdef CONFIG_IEEE80211W
		case WPA_ALG_IGTK:
			NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER, 0x000FAC06);
			break;
#endif /* CONFIG_IEEE80211W */
		default:
			nlmsg_free(msg);
			return -1;
		}
	}

	if (addr && os_memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) != 0)
	{
		wpa_printf(MSG_DEBUG, "   addr=" MACSTR, MAC2STR(addr));
		NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
	}
	NLA_PUT_U8(msg, NL80211_ATTR_KEY_IDX, key_idx);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);

	err = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (err) {
		wpa_printf(MSG_DEBUG, "nl80211: set_key failed; err=%d", err);
		return -1;
	}

	if (set_tx && alg != WPA_ALG_NONE) {
		msg = nlmsg_alloc();
		if (msg == NULL)
			return -1;

		genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
			    0, NL80211_CMD_SET_KEY, 0);
		NLA_PUT_U8(msg, NL80211_ATTR_KEY_IDX, key_idx);
		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
		NLA_PUT_FLAG(msg, NL80211_ATTR_KEY_DEFAULT);

		err = send_and_recv_msgs(drv, msg, NULL, NULL);
		if (err) {
			wpa_printf(MSG_DEBUG, "nl80211: set default key "
				   "failed; err=%d", err);
			return -1;
		}
	}

	return 0;

nla_put_failure:
	return -ENOBUFS;
}


static int wpa_driver_nl80211_mlme(struct wpa_driver_nl80211_data *drv,
				   const u8 *addr, int cmd, u16 reason_code)
{
	int ret = -1;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, 0, cmd, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
	NLA_PUT_U16(msg, NL80211_ATTR_REASON_CODE, reason_code);
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: MLME command failed: ret=%d "
			   "(%s)", ret, strerror(-ret));
		goto nla_put_failure;
	}
	ret = 0;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}


static int wpa_driver_nl80211_deauthenticate(void *priv, const u8 *addr,
					     int reason_code)
{
	struct wpa_driver_nl80211_data *drv = priv;
	wpa_printf(MSG_DEBUG, "%s", __func__);
	return wpa_driver_nl80211_mlme(drv, addr, NL80211_CMD_DEAUTHENTICATE,
				       reason_code);
}


static int wpa_driver_nl80211_disassociate(void *priv, const u8 *addr,
					   int reason_code)
{
	struct wpa_driver_nl80211_data *drv = priv;
	wpa_printf(MSG_DEBUG, "%s", __func__);
	return wpa_driver_nl80211_mlme(drv, addr, NL80211_CMD_DISASSOCIATE,
				       reason_code);
}


static int wpa_driver_nl80211_authenticate(
	void *priv, struct wpa_driver_auth_params *params)
{
	struct wpa_driver_nl80211_data *drv = priv;
	int ret = -1;
	struct nl_msg *msg;
	enum nl80211_auth_type type;

	drv->associated = 0;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	wpa_printf(MSG_DEBUG, "nl80211: Authenticate (ifindex=%d)",
		   drv->ifindex);
	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, 0,
		    NL80211_CMD_AUTHENTICATE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
	if (params->bssid) {
		wpa_printf(MSG_DEBUG, "  * bssid=" MACSTR,
			   MAC2STR(params->bssid));
		NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, params->bssid);
	}
	if (params->freq) {
		wpa_printf(MSG_DEBUG, "  * freq=%d", params->freq);
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, params->freq);
	}
	if (params->ssid) {
		wpa_hexdump_ascii(MSG_DEBUG, "  * SSID",
				  params->ssid, params->ssid_len);
		NLA_PUT(msg, NL80211_ATTR_SSID, params->ssid_len,
			params->ssid);
	}
	wpa_hexdump(MSG_DEBUG, "  * IEs", params->ie, params->ie_len);
	if (params->ie)
		NLA_PUT(msg, NL80211_ATTR_IE, params->ie_len, params->ie);
	/*
	 * TODO: if multiple auth_alg options enabled, try them one by one if
	 * the AP rejects authentication due to unknown auth alg
	 */
	if (params->auth_alg & AUTH_ALG_OPEN_SYSTEM)
		type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	else if (params->auth_alg & AUTH_ALG_SHARED_KEY)
		type = NL80211_AUTHTYPE_SHARED_KEY;
	else if (params->auth_alg & AUTH_ALG_LEAP)
		type = NL80211_AUTHTYPE_NETWORK_EAP;
	else if (params->auth_alg & AUTH_ALG_FT)
		type = NL80211_AUTHTYPE_FT;
	else
		goto nla_put_failure;
	wpa_printf(MSG_DEBUG, "  * Auth Type %d", type);
	NLA_PUT_U32(msg, NL80211_ATTR_AUTH_TYPE, type);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: MLME command failed: ret=%d "
			   "(%s)", ret, strerror(-ret));
		goto nla_put_failure;
	}
	ret = 0;
	wpa_printf(MSG_DEBUG, "nl80211: Authentication request send "
		   "successfully");

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}


#ifdef CONFIG_AP
static int wpa_driver_nl80211_set_beacon(void *priv,
					 const u8 *head, size_t head_len,
					 const u8 *tail, size_t tail_len,
					 int dtim_period)
{
	struct wpa_driver_nl80211_data *drv = priv;
	struct nl_msg *msg;
	u8 cmd = NL80211_CMD_NEW_BEACON;
	int ret;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	wpa_printf(MSG_DEBUG, "nl80211: Set beacon (beacon_set=%d)",
		   drv->beacon_set);
	if (drv->beacon_set)
		cmd = NL80211_CMD_SET_BEACON;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, cmd, 0);
	NLA_PUT(msg, NL80211_ATTR_BEACON_HEAD, head_len, head);
	NLA_PUT(msg, NL80211_ATTR_BEACON_TAIL, tail_len, tail);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
	if (!drv->beacon_int)
		drv->beacon_int = 100;
	NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, drv->beacon_int);
	NLA_PUT_U32(msg, NL80211_ATTR_DTIM_PERIOD, dtim_period);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Beacon set failed: %d (%s)",
			   ret, strerror(-ret));
	} else
		drv->beacon_set = 1;
	return ret;
 nla_put_failure:
	return -ENOBUFS;
}


static int wpa_driver_nl80211_set_beacon_int(void *priv, int value)
{
	struct wpa_driver_nl80211_data *drv = priv;
	struct nl_msg *msg;

	drv->beacon_int = value;

	if (!drv->beacon_set)
		return 0;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	wpa_printf(MSG_DEBUG, "nl80211: Set beacon interval %d "
		   "(beacon_set=%d)", value, drv->beacon_set);
	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, NL80211_CMD_SET_BEACON, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);

	NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, value);

	return send_and_recv_msgs(drv, msg, NULL, NULL);
 nla_put_failure:
	return -ENOBUFS;
}


static int wpa_driver_nl80211_set_freq2(
	struct wpa_driver_nl80211_data *drv,
	struct wpa_driver_associate_params *params)
{
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, 0,
		    NL80211_CMD_SET_WIPHY, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);

	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, params->freq);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (ret == 0)
		return 0;
	wpa_printf(MSG_DEBUG, "nl80211: MLME Failed to set channel (freq=%d): "
		   "%d (%s)", params->freq, ret, strerror(-ret));
nla_put_failure:
	return -1;
}


static void nl80211_remove_iface(struct wpa_driver_nl80211_data *drv,
				 int ifidx)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		goto nla_put_failure;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, NL80211_CMD_DEL_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);

	if (send_and_recv_msgs(drv, msg, NULL, NULL) == 0)
		return;
 nla_put_failure:
	wpa_printf(MSG_ERROR, "Failed to remove interface (ifidx=%d).\n",
		   ifidx);
}


static int nl80211_create_iface(struct wpa_driver_nl80211_data *drv,
				const char *ifname, enum nl80211_iftype iftype)
{
	struct nl_msg *msg, *flags = NULL;
	int ifidx;
	int ret = -ENOBUFS;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, ifname);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, iftype);

	if (iftype == NL80211_IFTYPE_MONITOR) {
		int err;

		flags = nlmsg_alloc();
		if (!flags)
			goto nla_put_failure;

		NLA_PUT_FLAG(flags, NL80211_MNTR_FLAG_COOK_FRAMES);

		err = nla_put_nested(msg, NL80211_ATTR_MNTR_FLAGS, flags);

		nlmsg_free(flags);

		if (err)
			goto nla_put_failure;
	}

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (ret) {
 nla_put_failure:
		wpa_printf(MSG_ERROR, "Failed to create interface %s.",
			   ifname);
		return ret;
	}

	ifidx = if_nametoindex(ifname);

	if (ifidx <= 0)
		return -1;

	return ifidx;
}


enum ieee80211_msg_type {
	ieee80211_msg_normal = 0,
	ieee80211_msg_tx_callback_ack = 1,
	ieee80211_msg_tx_callback_fail = 2,
};


void ap_tx_status(void *ctx, const u8 *addr,
		  const u8 *buf, size_t len, int ack);
void ap_rx_from_unknown_sta(void *ctx, const u8 *addr);
void ap_mgmt_rx(void *ctx, u8 *buf, size_t len, u16 stype,
		struct hostapd_frame_info *fi);
void ap_mgmt_tx_cb(void *ctx, u8 *buf, size_t len, u16 stype, int ok);


static void handle_tx_callback(void *ctx, u8 *buf, size_t len, int ok)
{
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		wpa_printf(MSG_DEBUG, "MGMT (TX callback) %s",
			   ok ? "ACK" : "fail");
		ap_mgmt_tx_cb(ctx, buf, len, stype, ok);
		break;
	case WLAN_FC_TYPE_CTRL:
		wpa_printf(MSG_DEBUG, "CTRL (TX callback) %s",
			   ok ? "ACK" : "fail");
		break;
	case WLAN_FC_TYPE_DATA:
		ap_tx_status(ctx, hdr->addr1, buf, len, ok);
		break;
	default:
		wpa_printf(MSG_DEBUG, "unknown TX callback frame type %d",
			   type);
		break;
	}
}


static void handle_frame(struct wpa_driver_nl80211_data *drv,
			 u8 *buf, size_t len,
			 struct hostapd_frame_info *hfi,
			 enum ieee80211_msg_type msg_type)
{
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;
	size_t data_len = len;

	/*
	 * PS-Poll frames are 16 bytes. All other frames are
	 * 24 bytes or longer.
	 */
	if (len < 16)
		return;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_DATA:
		if (len < 24)
			return;
		switch (fc & (WLAN_FC_FROMDS | WLAN_FC_TODS)) {
		case WLAN_FC_TODS:
			break;
		case WLAN_FC_FROMDS:
			break;
		default:
			/* discard */
			return;
		}
		break;
	case WLAN_FC_TYPE_CTRL:
		/* discard non-ps-poll frames */
		if (stype != WLAN_FC_STYPE_PSPOLL)
			return;
		break;
	case WLAN_FC_TYPE_MGMT:
		break;
	default:
		/* discard */
		return;
	}

	switch (msg_type) {
	case ieee80211_msg_normal:
		/* continue processing */
		break;
	case ieee80211_msg_tx_callback_ack:
		handle_tx_callback(drv->ctx, buf, data_len, 1);
		return;
	case ieee80211_msg_tx_callback_fail:
		handle_tx_callback(drv->ctx, buf, data_len, 0);
		return;
	}

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		if (stype != WLAN_FC_STYPE_BEACON &&
		    stype != WLAN_FC_STYPE_PROBE_REQ)
			wpa_printf(MSG_MSGDUMP, "MGMT");
		ap_mgmt_rx(drv->ctx, buf, data_len, stype, hfi);
		break;
	case WLAN_FC_TYPE_CTRL:
		/* can only get here with PS-Poll frames */
		wpa_printf(MSG_DEBUG, "CTRL");
		ap_rx_from_unknown_sta(drv->ctx, hdr->addr2);
		break;
	case WLAN_FC_TYPE_DATA:
		ap_rx_from_unknown_sta(drv->ctx, hdr->addr2);
		break;
	}
}


static void handle_monitor_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wpa_driver_nl80211_data *drv = eloop_ctx;
	int len;
	unsigned char buf[3000];
	struct ieee80211_radiotap_iterator iter;
	int ret;
	struct hostapd_frame_info hfi;
	int injected = 0, failed = 0, msg_type, rxflags = 0;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv");
		return;
	}

	if (ieee80211_radiotap_iterator_init(&iter, (void*)buf, len)) {
		printf("received invalid radiotap frame\n");
		return;
	}

	memset(&hfi, 0, sizeof(hfi));

	while (1) {
		ret = ieee80211_radiotap_iterator_next(&iter);
		if (ret == -ENOENT)
			break;
		if (ret) {
			printf("received invalid radiotap frame (%d)\n", ret);
			return;
		}
		switch (iter.this_arg_index) {
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iter.this_arg & IEEE80211_RADIOTAP_F_FCS)
				len -= 4;
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			rxflags = 1;
			break;
		case IEEE80211_RADIOTAP_TX_FLAGS:
			injected = 1;
			failed = le_to_host16((*(uint16_t *) iter.this_arg)) &
					IEEE80211_RADIOTAP_F_TX_FAIL;
			break;
		case IEEE80211_RADIOTAP_DATA_RETRIES:
			break;
		case IEEE80211_RADIOTAP_CHANNEL:
			/* TODO convert from freq/flags to channel number
			hfi.channel = XXX;
			hfi.phytype = XXX;
			 */
			break;
		case IEEE80211_RADIOTAP_RATE:
			hfi.datarate = *iter.this_arg * 5;
			break;
		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			hfi.ssi_signal = *iter.this_arg;
			break;
		}
	}

	if (rxflags && injected)
		return;

	if (!injected)
		msg_type = ieee80211_msg_normal;
	else if (failed)
		msg_type = ieee80211_msg_tx_callback_fail;
	else
		msg_type = ieee80211_msg_tx_callback_ack;

	handle_frame(drv, buf + iter.max_length,
		     len - iter.max_length, &hfi, msg_type);
}


/*
 * we post-process the filter code later and rewrite
 * this to the offset to the last instruction
 */
#define PASS	0xFF
#define FAIL	0xFE

static struct sock_filter msock_filter_insns[] = {
	/*
	 * do a little-endian load of the radiotap length field
	 */
	/* load lower byte into A */
	BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, 2),
	/* put it into X (== index register) */
	BPF_STMT(BPF_MISC| BPF_TAX, 0),
	/* load upper byte into A */
	BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, 3),
	/* left-shift it by 8 */
	BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 8),
	/* or with X */
	BPF_STMT(BPF_ALU | BPF_OR | BPF_X, 0),
	/* put result into X */
	BPF_STMT(BPF_MISC| BPF_TAX, 0),

	/*
	 * Allow management frames through, this also gives us those
	 * management frames that we sent ourselves with status
	 */
	/* load the lower byte of the IEEE 802.11 frame control field */
	BPF_STMT(BPF_LD  | BPF_B | BPF_IND, 0),
	/* mask off frame type and version */
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF),
	/* accept frame if it's both 0, fall through otherwise */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, PASS, 0),

	/*
	 * TODO: add a bit to radiotap RX flags that indicates
	 * that the sending station is not associated, then
	 * add a filter here that filters on our DA and that flag
	 * to allow us to deauth frames to that bad station.
	 *
	 * Not a regression -- we didn't do it before either.
	 */

#if 0
	/*
	 * drop non-data frames, WDS frames
	 */
	/* load the lower byte of the frame control field */
	BPF_STMT(BPF_LD   | BPF_B | BPF_IND, 0),
	/* mask off QoS bit */
	BPF_STMT(BPF_ALU  | BPF_AND | BPF_K, 0x0c),
	/* drop non-data frames */
	BPF_JUMP(BPF_JMP  | BPF_JEQ | BPF_K, 8, 0, FAIL),
	/* load the upper byte of the frame control field */
	BPF_STMT(BPF_LD   | BPF_B | BPF_IND, 0),
	/* mask off toDS/fromDS */
	BPF_STMT(BPF_ALU  | BPF_AND | BPF_K, 0x03),
	/* drop WDS frames */
	BPF_JUMP(BPF_JMP  | BPF_JEQ | BPF_K, 3, FAIL, 0),
#endif

	/*
	 * add header length to index
	 */
	/* load the lower byte of the frame control field */
	BPF_STMT(BPF_LD   | BPF_B | BPF_IND, 0),
	/* mask off QoS bit */
	BPF_STMT(BPF_ALU  | BPF_AND | BPF_K, 0x80),
	/* right shift it by 6 to give 0 or 2 */
	BPF_STMT(BPF_ALU  | BPF_RSH | BPF_K, 6),
	/* add data frame header length */
	BPF_STMT(BPF_ALU  | BPF_ADD | BPF_K, 24),
	/* add index, was start of 802.11 header */
	BPF_STMT(BPF_ALU  | BPF_ADD | BPF_X, 0),
	/* move to index, now start of LL header */
	BPF_STMT(BPF_MISC | BPF_TAX, 0),

	/*
	 * Accept empty data frames, we use those for
	 * polling activity.
	 */
	BPF_STMT(BPF_LD  | BPF_W | BPF_LEN, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_X, 0, PASS, 0),

	/*
	 * Accept EAPOL frames
	 */
	BPF_STMT(BPF_LD  | BPF_W | BPF_IND, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA0300, 0, FAIL),
	BPF_STMT(BPF_LD  | BPF_W | BPF_IND, 4),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0000888E, PASS, FAIL),

	/* keep these last two statements or change the code below */
	/* return 0 == "DROP" */
	BPF_STMT(BPF_RET | BPF_K, 0),
	/* return ~0 == "keep all" */
	BPF_STMT(BPF_RET | BPF_K, ~0),
};

static struct sock_fprog msock_filter = {
	.len = sizeof(msock_filter_insns)/sizeof(msock_filter_insns[0]),
	.filter = msock_filter_insns,
};


static int add_monitor_filter(int s)
{
	int idx;

	/* rewrite all PASS/FAIL jump offsets */
	for (idx = 0; idx < msock_filter.len; idx++) {
		struct sock_filter *insn = &msock_filter_insns[idx];

		if (BPF_CLASS(insn->code) == BPF_JMP) {
			if (insn->code == (BPF_JMP|BPF_JA)) {
				if (insn->k == PASS)
					insn->k = msock_filter.len - idx - 2;
				else if (insn->k == FAIL)
					insn->k = msock_filter.len - idx - 3;
			}

			if (insn->jt == PASS)
				insn->jt = msock_filter.len - idx - 2;
			else if (insn->jt == FAIL)
				insn->jt = msock_filter.len - idx - 3;

			if (insn->jf == PASS)
				insn->jf = msock_filter.len - idx - 2;
			else if (insn->jf == FAIL)
				insn->jf = msock_filter.len - idx - 3;
		}
	}

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER,
		       &msock_filter, sizeof(msock_filter))) {
		perror("SO_ATTACH_FILTER");
		return -1;
	}

	return 0;
}


static int
nl80211_create_monitor_interface(struct wpa_driver_nl80211_data *drv)
{
	char buf[IFNAMSIZ];
	struct sockaddr_ll ll;
	int optval;
	socklen_t optlen;
	int flags;

	snprintf(buf, IFNAMSIZ, "mon.%s", drv->ifname);
	buf[IFNAMSIZ - 1] = '\0';

	drv->monitor_ifidx =
		nl80211_create_iface(drv, buf, NL80211_IFTYPE_MONITOR);

	if (drv->monitor_ifidx < 0)
		return -1;

	if (wpa_driver_nl80211_get_ifflags_ifname(drv, buf, &flags) != 0) {
		wpa_printf(MSG_ERROR, "Could not get interface '%s' flags",
			   buf);
		goto error;
	}
	if (!(flags & IFF_UP)) {
		if (wpa_driver_nl80211_set_ifflags_ifname(drv, buf,
							  flags | IFF_UP) != 0)
		{
			wpa_printf(MSG_ERROR, "Could not set interface '%s' "
				   "UP", buf);
			goto error;
		}
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = drv->monitor_ifidx;
	drv->monitor_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (drv->monitor_sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		goto error;
	}

	if (add_monitor_filter(drv->monitor_sock)) {
		wpa_printf(MSG_INFO, "Failed to set socket filter for monitor "
			   "interface; do filtering in user space");
		/* This works, but will cost in performance. */
	}

	if (bind(drv->monitor_sock, (struct sockaddr *) &ll,
		 sizeof(ll)) < 0) {
		perror("monitor socket bind");
		goto error;
	}

	optlen = sizeof(optval);
	optval = 20;
	if (setsockopt
	    (drv->monitor_sock, SOL_SOCKET, SO_PRIORITY, &optval, optlen)) {
		perror("Failed to set socket priority");
		goto error;
	}

	if (eloop_register_read_sock(drv->monitor_sock, handle_monitor_read,
				     drv, NULL)) {
		printf("Could not register monitor read socket\n");
		goto error;
	}

	return 0;
 error:
	nl80211_remove_iface(drv, drv->monitor_ifidx);
	return -1;
}


static int wpa_driver_nl80211_ap(struct wpa_driver_nl80211_data *drv,
				 struct wpa_driver_associate_params *params)
{
	if (drv->monitor_ifidx < 0 &&
	    nl80211_create_monitor_interface(drv))
		return -1;

	if (wpa_driver_nl80211_set_mode(drv, params->mode) ||
	    wpa_driver_nl80211_set_freq2(drv, params)) {
		nl80211_remove_iface(drv, drv->monitor_ifidx);
		drv->monitor_ifidx = -1;
		return -1;
	}

	/* TODO: setup monitor interface (and add code somewhere to remove this
	 * when AP mode is stopped; associate with mode != 2 or drv_deinit) */

	return 0;
}
#endif /* CONFIG_AP */


static int wpa_driver_nl80211_associate(
	void *priv, struct wpa_driver_associate_params *params)
{
	struct wpa_driver_nl80211_data *drv = priv;
	int ret = -1;
	struct nl_msg *msg;

#ifdef CONFIG_AP
	if (params->mode == 2)
		return wpa_driver_nl80211_ap(drv, params);
#endif /* CONFIG_AP */

	wpa_driver_nl80211_set_auth_param(drv, IW_AUTH_DROP_UNENCRYPTED,
					  params->drop_unencrypted);

	drv->associated = 0;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	wpa_printf(MSG_DEBUG, "nl80211: Associate (ifindex=%d)",
		   drv->ifindex);
	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0, 0,
		    NL80211_CMD_ASSOCIATE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
	if (params->bssid) {
		wpa_printf(MSG_DEBUG, "  * bssid=" MACSTR,
			   MAC2STR(params->bssid));
		NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, params->bssid);
	}
	if (params->freq) {
		wpa_printf(MSG_DEBUG, "  * freq=%d", params->freq);
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, params->freq);
	}
	if (params->ssid) {
		wpa_hexdump_ascii(MSG_DEBUG, "  * SSID",
				  params->ssid, params->ssid_len);
		NLA_PUT(msg, NL80211_ATTR_SSID, params->ssid_len,
			params->ssid);
		if (params->ssid_len > sizeof(drv->ssid))
			goto nla_put_failure;
		os_memcpy(drv->ssid, params->ssid, params->ssid_len);
		drv->ssid_len = params->ssid_len;
	}
	wpa_hexdump(MSG_DEBUG, "  * IEs", params->wpa_ie, params->wpa_ie_len);
	if (params->wpa_ie)
		NLA_PUT(msg, NL80211_ATTR_IE, params->wpa_ie_len,
			params->wpa_ie);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: MLME command failed: ret=%d "
			   "(%s)", ret, strerror(-ret));
		goto nla_put_failure;
	}
	ret = 0;
	wpa_printf(MSG_DEBUG, "nl80211: Association request send "
		   "successfully");

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}


/**
 * wpa_driver_nl80211_set_mode - Set wireless mode (infra/adhoc)
 * @drv: Pointer to private driver data from wpa_driver_nl80211_init()
 * @mode: 0 = infra/BSS (associate with an AP), 1 = adhoc/IBSS
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_nl80211_set_mode(struct wpa_driver_nl80211_data *drv,
				       int mode)
{
	int ret = -1, flags;
	struct nl_msg *msg;
	int nlmode;

	switch (mode) {
	case 0:
		nlmode = NL80211_IFTYPE_STATION;
		break;
	case 1:
		nlmode = NL80211_IFTYPE_ADHOC;
		break;
	case 2:
		nlmode = NL80211_IFTYPE_AP;
		break;
	default:
		return -1;
	}

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, NL80211_CMD_SET_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, nlmode);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (!ret)
		return 0;
	else
		goto try_again;

nla_put_failure:
	wpa_printf(MSG_ERROR, "nl80211: Failed to set interface mode: %d (%s)",
		   ret, strerror(-ret));
	return -1;

try_again:
	/* mac80211 doesn't allow mode changes while the device is up, so
	 * take the device down, try to set the mode again, and bring the
	 * device back up.
	 */
	if (wpa_driver_nl80211_get_ifflags(drv, &flags) == 0) {
		(void) wpa_driver_nl80211_set_ifflags(drv, flags & ~IFF_UP);

		/* Try to set the mode again while the interface is down */
		msg = nlmsg_alloc();
		if (!msg)
			return -1;

		genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
			    0, NL80211_CMD_SET_INTERFACE, 0);
		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
		NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, nlmode);
		ret = send_and_recv_msgs(drv, msg, NULL, NULL);
		if (ret) {
			wpa_printf(MSG_ERROR, "Failed to set interface %s "
				   "mode(try_again): %d (%s)",
				   drv->ifname, ret, strerror(-ret));
		}

		/* Ignore return value of get_ifflags to ensure that the device
		 * is always up like it was before this function was called.
		 */
		(void) wpa_driver_nl80211_get_ifflags(drv, &flags);
		(void) wpa_driver_nl80211_set_ifflags(drv, flags | IFF_UP);
	}

	return ret;
}


static int wpa_driver_nl80211_get_capa(void *priv,
				       struct wpa_driver_capa *capa)
{
	struct wpa_driver_nl80211_data *drv = priv;
	if (!drv->has_capability)
		return -1;
	os_memcpy(capa, &drv->capa, sizeof(*capa));
	return 0;
}


static int wpa_driver_nl80211_set_operstate(void *priv, int state)
{
	struct wpa_driver_nl80211_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: operstate %d->%d (%s)",
		   __func__, drv->operstate, state, state ? "UP" : "DORMANT");
	drv->operstate = state;
	return wpa_driver_nl80211_send_oper_ifla(
		drv, -1, state ? IF_OPER_UP : IF_OPER_DORMANT);
}


const struct wpa_driver_ops wpa_driver_nl80211_ops = {
	.name = "nl80211",
	.desc = "Linux nl80211/cfg80211",
	.get_bssid = wpa_driver_nl80211_get_bssid,
	.get_ssid = wpa_driver_nl80211_get_ssid,
	.set_key = wpa_driver_nl80211_set_key,
	.scan2 = wpa_driver_nl80211_scan,
	.get_scan_results2 = wpa_driver_nl80211_get_scan_results,
	.deauthenticate = wpa_driver_nl80211_deauthenticate,
	.disassociate = wpa_driver_nl80211_disassociate,
	.authenticate = wpa_driver_nl80211_authenticate,
	.associate = wpa_driver_nl80211_associate,
	.init = wpa_driver_nl80211_init,
	.deinit = wpa_driver_nl80211_deinit,
	.get_capa = wpa_driver_nl80211_get_capa,
	.set_operstate = wpa_driver_nl80211_set_operstate,
	.set_country = wpa_driver_nl80211_set_country,
#ifdef CONFIG_AP
	.set_beacon = wpa_driver_nl80211_set_beacon,
	.set_beacon_int = wpa_driver_nl80211_set_beacon_int,
#endif /* CONFIG_AP */
};
