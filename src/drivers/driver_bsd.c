/*
 * WPA Supplicant - driver interaction with BSD net80211 layer
 * Copyright (c) 2004, Sam Leffler <sam@errno.com>
 * Copyright (c) 2004, 2Wire, Inc
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

#include "common.h"
#include "driver.h"
#include "eloop.h"
#include "ieee802_11_defs.h"

#include <net/if.h>

#ifdef __NetBSD__
#include <net/if_ether.h>
#define COMPAT_FREEBSD_NET80211
#else
#include <net/ethernet.h>
#endif
#include <net/route.h>

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_crypto.h>
#include <net80211/ieee80211_ioctl.h>
#if __FreeBSD__
#include <net80211/ieee80211_freebsd.h>
#endif
#if __NetBSD__
#include <net80211/ieee80211_netbsd.h>
#endif

#ifdef HOSTAPD

/*
 * Avoid conflicts with hostapd definitions by undefining couple of defines
 * from net80211 header files.
 */
#undef RSN_VERSION
#undef WPA_VERSION
#undef WPA_OUI_TYPE

#include "l2_packet/l2_packet.h"
#include "../../hostapd/hostapd.h"
#include "../../hostapd/config.h"
#include "../../hostapd/eapol_sm.h"
#include "../../hostapd/sta_flags.h"

struct bsd_driver_data {
	struct hostapd_data *hapd;		/* back pointer */

	char	iface[IFNAMSIZ + 1];
	struct l2_packet_data *sock_xmit;	/* raw packet xmit socket */
	int	ioctl_sock;			/* socket for ioctl() use */
	int	wext_sock;			/* socket for wireless events */
};

static int bsd_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
			  int reason_code);

static int
set80211var(struct bsd_driver_data *drv, int op, const void *arg, int arg_len)
{
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	os_strlcpy(ireq.i_name, drv->iface, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_len = arg_len;
	ireq.i_data = (void *) arg;

	if (ioctl(drv->ioctl_sock, SIOCS80211, &ireq) < 0) {
		perror("ioctl[SIOCS80211]");
		return -1;
	}
	return 0;
}

static int
get80211var(struct bsd_driver_data *drv, int op, void *arg, int arg_len)
{
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	os_strlcpy(ireq.i_name, drv->iface, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_len = arg_len;
	ireq.i_data = arg;

	if (ioctl(drv->ioctl_sock, SIOCG80211, &ireq) < 0) {
		perror("ioctl[SIOCG80211]");
		return -1;
	}
	return ireq.i_len;
}

static int
set80211param(struct bsd_driver_data *drv, int op, int arg)
{
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	os_strlcpy(ireq.i_name, drv->iface, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_val = arg;

	if (ioctl(drv->ioctl_sock, SIOCS80211, &ireq) < 0) {
		perror("ioctl[SIOCS80211]");
		return -1;
	}
	return 0;
}

static const char *
ether_sprintf(const u8 *addr)
{
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
	return buf;
}

/*
 * Configure WPA parameters.
 */
static int
bsd_configure_wpa(struct bsd_driver_data *drv)
{
	static const char *ciphernames[] =
		{ "WEP", "TKIP", "AES-OCB", "AES-CCM", "CKIP", "NONE" };
	struct hostapd_data *hapd = drv->hapd;
	struct hostapd_bss_config *conf = hapd->conf;
	int v;

	switch (conf->wpa_group) {
	case WPA_CIPHER_CCMP:
		v = IEEE80211_CIPHER_AES_CCM;
		break;
	case WPA_CIPHER_TKIP:
		v = IEEE80211_CIPHER_TKIP;
		break;
	case WPA_CIPHER_WEP104:
		v = IEEE80211_CIPHER_WEP;
		break;
	case WPA_CIPHER_WEP40:
		v = IEEE80211_CIPHER_WEP;
		break;
	case WPA_CIPHER_NONE:
		v = IEEE80211_CIPHER_NONE;
		break;
	default:
		printf("Unknown group key cipher %u\n",
			conf->wpa_group);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "%s: group key cipher=%s (%u)",
		   __func__, ciphernames[v], v);
	if (set80211param(drv, IEEE80211_IOC_MCASTCIPHER, v)) {
		printf("Unable to set group key cipher to %u (%s)\n",
			v, ciphernames[v]);
		return -1;
	}
	if (v == IEEE80211_CIPHER_WEP) {
		/* key length is done only for specific ciphers */
		v = (conf->wpa_group == WPA_CIPHER_WEP104 ? 13 : 5);
		if (set80211param(drv, IEEE80211_IOC_MCASTKEYLEN, v)) {
			printf("Unable to set group key length to %u\n", v);
			return -1;
		}
	}

	v = 0;
	if (conf->wpa_pairwise & WPA_CIPHER_CCMP)
		v |= 1<<IEEE80211_CIPHER_AES_CCM;
	if (conf->wpa_pairwise & WPA_CIPHER_TKIP)
		v |= 1<<IEEE80211_CIPHER_TKIP;
	if (conf->wpa_pairwise & WPA_CIPHER_NONE)
		v |= 1<<IEEE80211_CIPHER_NONE;
	wpa_printf(MSG_DEBUG, "%s: pairwise key ciphers=0x%x", __func__, v);
	if (set80211param(drv, IEEE80211_IOC_UCASTCIPHERS, v)) {
		printf("Unable to set pairwise key ciphers to 0x%x\n", v);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s: key management algorithms=0x%x",
		   __func__, conf->wpa_key_mgmt);
	if (set80211param(drv, IEEE80211_IOC_KEYMGTALGS, conf->wpa_key_mgmt)) {
		printf("Unable to set key management algorithms to 0x%x\n",
			conf->wpa_key_mgmt);
		return -1;
	}

	v = 0;
	if (conf->rsn_preauth)
		v |= BIT(0);
	wpa_printf(MSG_DEBUG, "%s: rsn capabilities=0x%x",
		   __func__, conf->rsn_preauth);
	if (set80211param(drv, IEEE80211_IOC_RSNCAPS, v)) {
		printf("Unable to set RSN capabilities to 0x%x\n", v);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s: enable WPA= 0x%x", __func__, conf->wpa);
	if (set80211param(drv, IEEE80211_IOC_WPA, conf->wpa)) {
		printf("Unable to set WPA to %u\n", conf->wpa);
		return -1;
	}
	return 0;
}


static int
bsd_set_iface_flags(void *priv, int dev_up)
{
	struct bsd_driver_data *drv = priv;
	struct ifreq ifr;

	wpa_printf(MSG_DEBUG, "%s: dev_up=%d", __func__, dev_up);

	if (drv->ioctl_sock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}

	if (dev_up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		return -1;
	}

	if (dev_up) {
		memset(&ifr, 0, sizeof(ifr));
		os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);
		ifr.ifr_mtu = HOSTAPD_MTU;
		if (ioctl(drv->ioctl_sock, SIOCSIFMTU, &ifr) != 0) {
			perror("ioctl[SIOCSIFMTU]");
			printf("Setting MTU failed - trying to survive with "
			       "current value\n");
		}
	}

	return 0;
}

static int
bsd_set_ieee8021x(const char *ifname, void *priv, int enabled)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct hostapd_bss_config *conf = hapd->conf;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);

	if (!enabled) {
		/* XXX restore state */
		return set80211param(priv, IEEE80211_IOC_AUTHMODE,
			IEEE80211_AUTH_AUTO);
	}
	if (!conf->wpa && !conf->ieee802_1x) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
			HOSTAPD_LEVEL_WARNING, "No 802.1X or WPA enabled!");
		return -1;
	}
	if (conf->wpa && bsd_configure_wpa(drv) != 0) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
			HOSTAPD_LEVEL_WARNING, "Error configuring WPA state!");
		return -1;
	}
	if (set80211param(priv, IEEE80211_IOC_AUTHMODE,
		(conf->wpa ?  IEEE80211_AUTH_WPA : IEEE80211_AUTH_8021X))) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
			HOSTAPD_LEVEL_WARNING, "Error enabling WPA/802.1X!");
		return -1;
	}
	return bsd_set_iface_flags(priv, 1);
}

static int
bsd_set_privacy(const char *ifname, void *priv, int enabled)
{
	struct bsd_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);

	return set80211param(drv, IEEE80211_IOC_PRIVACY, enabled);
}

static int
bsd_set_sta_authorized(void *priv, const u8 *addr, int authorized)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s authorized=%d",
		   __func__, ether_sprintf(addr), authorized);

	if (authorized)
		mlme.im_op = IEEE80211_MLME_AUTHORIZE;
	else
		mlme.im_op = IEEE80211_MLME_UNAUTHORIZE;
	mlme.im_reason = 0;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(drv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
bsd_sta_set_flags(void *priv, const u8 *addr, int total_flags, int flags_or,
		  int flags_and)
{
	/* For now, only support setting Authorized flag */
	if (flags_or & WLAN_STA_AUTHORIZED)
		return bsd_set_sta_authorized(priv, addr, 1);
	if (!(flags_and & WLAN_STA_AUTHORIZED))
		return bsd_set_sta_authorized(priv, addr, 0);
	return 0;
}

static int
bsd_del_key(void *priv, const u8 *addr, int key_idx)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_del_key wk;

	wpa_printf(MSG_DEBUG, "%s: addr=%s key_idx=%d",
		   __func__, ether_sprintf(addr), key_idx);

	memset(&wk, 0, sizeof(wk));
	if (addr != NULL) {
		memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.idk_keyix = (u_int8_t) IEEE80211_KEYIX_NONE;	/* XXX */
	} else {
		wk.idk_keyix = key_idx;
	}

	return set80211var(drv, IEEE80211_IOC_DELKEY, &wk, sizeof(wk));
}

static int
bsd_set_key(const char *ifname, void *priv, wpa_alg alg,
	    const u8 *addr, int key_idx, int set_tx, const u8 *seq,
	    size_t seq_len, const u8 *key, size_t key_len)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_key wk;
	u_int8_t cipher;

	if (alg == WPA_ALG_NONE)
		return bsd_del_key(drv, addr, key_idx);

	wpa_printf(MSG_DEBUG, "%s: alg=%d addr=%s key_idx=%d",
		   __func__, alg, ether_sprintf(addr), key_idx);

	if (alg == WPA_ALG_WEP)
		cipher = IEEE80211_CIPHER_WEP;
	else if (alg == WPA_ALG_TKIP)
		cipher = IEEE80211_CIPHER_TKIP;
	else if (alg == WPA_ALG_CCMP)
		cipher = IEEE80211_CIPHER_AES_CCM;
	else {
		printf("%s: unknown/unsupported algorithm %d\n",
			__func__, alg);
		return -1;
	}

	if (key_len > sizeof(wk.ik_keydata)) {
		printf("%s: key length %d too big\n", __func__, key_len);
		return -3;
	}

	memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	wk.ik_flags = IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT;
	if (addr == NULL) {
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_keyix = key_idx;
		wk.ik_flags |= IEEE80211_KEY_DEFAULT;
	} else {
		memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.ik_keyix = IEEE80211_KEYIX_NONE;
	}
	wk.ik_keylen = key_len;
	memcpy(wk.ik_keydata, key, key_len);

	return set80211var(drv, IEEE80211_IOC_WPAKEY, &wk, sizeof(wk));
}


static int
bsd_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx,
	       u8 *seq)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_key wk;

	wpa_printf(MSG_DEBUG, "%s: addr=%s idx=%d",
		   __func__, ether_sprintf(addr), idx);

	memset(&wk, 0, sizeof(wk));
	if (addr == NULL)
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
	else
		memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
	wk.ik_keyix = idx;

	if (get80211var(drv, IEEE80211_IOC_WPAKEY, &wk, sizeof(wk)) < 0) {
		printf("Failed to get encryption.\n");
		return -1;
	}

#ifdef WORDS_BIGENDIAN
	{
		/*
		 * wk.ik_keytsc is in host byte order (big endian), need to
		 * swap it to match with the byte order used in WPA.
		 */
		int i;
		u8 tmp[WPA_KEY_RSC_LEN];
		memcpy(tmp, &wk.ik_keytsc, sizeof(wk.ik_keytsc));
		for (i = 0; i < WPA_KEY_RSC_LEN; i++) {
			seq[i] = tmp[WPA_KEY_RSC_LEN - i - 1];
		}
	}
#else /* WORDS_BIGENDIAN */
	memcpy(seq, &wk.ik_keytsc, sizeof(wk.ik_keytsc));
#endif /* WORDS_BIGENDIAN */
	return 0;
}


static int 
bsd_flush(void *priv)
{
	u8 allsta[IEEE80211_ADDR_LEN];

	memset(allsta, 0xff, IEEE80211_ADDR_LEN);
	return bsd_sta_deauth(priv, NULL, allsta, IEEE80211_REASON_AUTH_LEAVE);
}


static int
bsd_read_sta_driver_data(void *priv, struct hostap_sta_driver_data *data,
			 const u8 *addr)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_sta_stats stats;

	memcpy(stats.is_u.macaddr, addr, IEEE80211_ADDR_LEN);
	if (get80211var(drv, IEEE80211_IOC_STA_STATS, &stats, sizeof(stats)) > 0) {
		/* XXX? do packets counts include non-data frames? */
		data->rx_packets = stats.is_stats.ns_rx_data;
		data->rx_bytes = stats.is_stats.ns_rx_bytes;
		data->tx_packets = stats.is_stats.ns_tx_data;
		data->tx_bytes = stats.is_stats.ns_tx_bytes;
	}
	return 0;
}

static int
bsd_set_opt_ie(const char *ifname, void *priv, const u8 *ie, size_t ie_len)
{
	/*
	 * Do nothing; we setup parameters at startup that define the
	 * contents of the beacon information element.
	 */
	return 0;
}

static int
bsd_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, int reason_code)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d",
		   __func__, ether_sprintf(addr), reason_code);

	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(drv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
bsd_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
		 int reason_code)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d",
		   __func__, ether_sprintf(addr), reason_code);

	mlme.im_op = IEEE80211_MLME_DISASSOC;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(drv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
bsd_new_sta(struct bsd_driver_data *drv, u8 addr[IEEE80211_ADDR_LEN])
{
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_wpaie ie;
	int ielen = 0;
	u8 *iebuf = NULL;

	/*
	 * Fetch and validate any negotiated WPA/RSN parameters.
	 */
	memset(&ie, 0, sizeof(ie));
	memcpy(ie.wpa_macaddr, addr, IEEE80211_ADDR_LEN);
	if (get80211var(drv, IEEE80211_IOC_WPAIE, &ie, sizeof(ie)) < 0) {
		printf("Failed to get WPA/RSN information element.\n");
		goto no_ie;
	}
	iebuf = ie.wpa_ie;
	ielen = ie.wpa_ie[1];
	if (ielen == 0)
		iebuf = NULL;
	else
		ielen += 2;

no_ie:
	return hostapd_notif_assoc(hapd, addr, iebuf, ielen);
}

static void
bsd_wireless_event_receive(int sock, void *ctx, void *sock_ctx)
{
	struct bsd_driver_data *drv = ctx;
	struct hostapd_data *hapd = drv->hapd;
	char buf[2048];
	struct if_announcemsghdr *ifan;
	struct rt_msghdr *rtm;
	struct ieee80211_michael_event *mic;
	struct ieee80211_join_event *join;
	struct ieee80211_leave_event *leave;
	int n;

	n = read(sock, buf, sizeof(buf));
	if (n < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("read(PF_ROUTE)");
		return;
	}

	rtm = (struct rt_msghdr *) buf;
	if (rtm->rtm_version != RTM_VERSION) {
		wpa_printf(MSG_DEBUG, "Routing message version %d not "
			"understood\n", rtm->rtm_version);
		return;
	}
	ifan = (struct if_announcemsghdr *) rtm;
	switch (rtm->rtm_type) {
	case RTM_IEEE80211:
		switch (ifan->ifan_what) {
		case RTM_IEEE80211_ASSOC:
		case RTM_IEEE80211_REASSOC:
		case RTM_IEEE80211_DISASSOC:
		case RTM_IEEE80211_SCAN:
			break;
		case RTM_IEEE80211_LEAVE:
			leave = (struct ieee80211_leave_event *) &ifan[1];
			hostapd_notif_disassoc(drv->hapd, leave->iev_addr);
			break;
		case RTM_IEEE80211_JOIN:
#ifdef RTM_IEEE80211_REJOIN
		case RTM_IEEE80211_REJOIN:
#endif
			join = (struct ieee80211_join_event *) &ifan[1];
			bsd_new_sta(drv, join->iev_addr);
			break;
		case RTM_IEEE80211_REPLAY:
			/* ignore */
			break;
		case RTM_IEEE80211_MICHAEL:
			mic = (struct ieee80211_michael_event *) &ifan[1];
			wpa_printf(MSG_DEBUG,
				"Michael MIC failure wireless event: "
				"keyix=%u src_addr=" MACSTR, mic->iev_keyix,
				MAC2STR(mic->iev_src));
			hostapd_michael_mic_failure(hapd, mic->iev_src);
			break;
		}
		break;
	}
}

static int
bsd_wireless_event_init(struct bsd_driver_data *drv)
{
	int s;

	drv->wext_sock = -1;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		perror("socket(PF_ROUTE,SOCK_RAW)");
		return -1;
	}
	eloop_register_read_sock(s, bsd_wireless_event_receive, drv, NULL);
	drv->wext_sock = s;

	return 0;
}

static void
bsd_wireless_event_deinit(struct bsd_driver_data *drv)
{
	if (drv->wext_sock < 0)
		return;
	eloop_unregister_read_sock(drv->wext_sock);
	close(drv->wext_sock);
}


static int
bsd_send_eapol(void *priv, const u8 *addr, const u8 *data, size_t data_len,
	       int encrypt, const u8 *own_addr)
{
	struct bsd_driver_data *drv = priv;
	unsigned char buf[3000];
	unsigned char *bp = buf;
	struct l2_ethhdr *eth;
	size_t len;
	int status;

	/*
	 * Prepend the Etherent header.  If the caller left us
	 * space at the front we could just insert it but since
	 * we don't know we copy to a local buffer.  Given the frequency
	 * and size of frames this probably doesn't matter.
	 */
	len = data_len + sizeof(struct l2_ethhdr);
	if (len > sizeof(buf)) {
		bp = malloc(len);
		if (bp == NULL) {
			printf("EAPOL frame discarded, cannot malloc temp "
				"buffer of size %u!\n", len);
			return -1;
		}
	}
	eth = (struct l2_ethhdr *) bp;
	memcpy(eth->h_dest, addr, ETH_ALEN);
	memcpy(eth->h_source, own_addr, ETH_ALEN);
	eth->h_proto = htons(ETH_P_EAPOL);
	memcpy(eth+1, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

	status = l2_packet_send(drv->sock_xmit, addr, ETH_P_EAPOL, bp, len);

	if (bp != buf)
		free(bp);
	return status;
}

static void
handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct bsd_driver_data *drv = ctx;
	hostapd_eapol_receive(drv->hapd, src_addr,
			      buf + sizeof(struct l2_ethhdr),
			      len - sizeof(struct l2_ethhdr));
}

static int
bsd_get_ssid(const char *ifname, void *priv, u8 *buf, int len)
{
	struct bsd_driver_data *drv = priv;
	int ssid_len = get80211var(drv, IEEE80211_IOC_SSID, buf, len);

	wpa_printf(MSG_DEBUG, "%s: ssid=\"%.*s\"", __func__, ssid_len, buf);

	return ssid_len;
}

static int
bsd_set_ssid(const char *ifname, void *priv, const u8 *buf, int len)
{
	struct bsd_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: ssid=\"%.*s\"", __func__, len, buf);

	return set80211var(drv, IEEE80211_IOC_SSID, buf, len);
}

static void *
bsd_init(struct hostapd_data *hapd, struct wpa_init_params *params)
{
	struct bsd_driver_data *drv;

	drv = os_zalloc(sizeof(struct bsd_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for bsd driver data\n");
		goto bad;
	}

	drv->hapd = hapd;
	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		goto bad;
	}
	memcpy(drv->iface, params->ifname, sizeof(drv->iface));

	drv->sock_xmit = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL,
					handle_read, drv, 1);
	if (drv->sock_xmit == NULL)
		goto bad;
	if (l2_packet_get_own_addr(drv->sock_xmit, params->own_addr))
		goto bad;

	bsd_set_iface_flags(drv, 0);	/* mark down during setup */
	if (bsd_wireless_event_init(drv))
		goto bad;

	return drv;
bad:
	if (drv->sock_xmit != NULL)
		l2_packet_deinit(drv->sock_xmit);
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	if (drv != NULL)
		free(drv);
	return NULL;
}


static void
bsd_deinit(void *priv)
{
	struct bsd_driver_data *drv = priv;

	bsd_wireless_event_deinit(drv);
	(void) bsd_set_iface_flags(drv, 0);
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	if (drv->sock_xmit != NULL)
		l2_packet_deinit(drv->sock_xmit);
	free(drv);
}

const struct wpa_driver_ops wpa_driver_bsd_ops = {
	.name			= "bsd",
	.hapd_init		= bsd_init,
	.hapd_deinit		= bsd_deinit,
	.set_ieee8021x		= bsd_set_ieee8021x,
	.set_privacy		= bsd_set_privacy,
	.hapd_set_key		= bsd_set_key,
	.get_seqnum		= bsd_get_seqnum,
	.flush			= bsd_flush,
	.set_generic_elem	= bsd_set_opt_ie,
	.sta_set_flags		= bsd_sta_set_flags,
	.read_sta_data		= bsd_read_sta_driver_data,
	.hapd_send_eapol	= bsd_send_eapol,
	.sta_disassoc		= bsd_sta_disassoc,
	.sta_deauth		= bsd_sta_deauth,
	.hapd_set_ssid		= bsd_set_ssid,
	.hapd_get_ssid		= bsd_get_ssid,
};

#else /* HOSTAPD */

struct wpa_driver_bsd_data {
	int	sock;			/* open socket for 802.11 ioctls */
	int	route;			/* routing socket for events */
	char	ifname[IFNAMSIZ+1];	/* interface name */
	unsigned int ifindex;		/* interface index */
	void	*ctx;
	int	prev_roaming;		/* roaming state to restore on deinit */
	int	prev_privacy;		/* privacy state to restore on deinit */
	int	prev_wpa;		/* wpa state to restore on deinit */
};

static int
set80211var(struct wpa_driver_bsd_data *drv, int op, const void *arg, int arg_len)
{
	struct ieee80211req ireq;

	os_memset(&ireq, 0, sizeof(ireq));
	os_strlcpy(ireq.i_name, drv->ifname, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_len = arg_len;
	ireq.i_data = (void *) arg;

	if (ioctl(drv->sock, SIOCS80211, &ireq) < 0) {
		fprintf(stderr, "ioctl[SIOCS80211, op %u, len %u]: %s\n",
			op, arg_len, strerror(errno));
		return -1;
	}
	return 0;
}

static int
get80211var(struct wpa_driver_bsd_data *drv, int op, void *arg, int arg_len)
{
	struct ieee80211req ireq;

	os_memset(&ireq, 0, sizeof(ireq));
	os_strlcpy(ireq.i_name, drv->ifname, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_len = arg_len;
	ireq.i_data = arg;

	if (ioctl(drv->sock, SIOCG80211, &ireq) < 0) {
		fprintf(stderr, "ioctl[SIOCG80211, op %u, len %u]: %s\n",
			op, arg_len, strerror(errno));
		return -1;
	}
	return ireq.i_len;
}

static int
set80211param(struct wpa_driver_bsd_data *drv, int op, int arg)
{
	struct ieee80211req ireq;

	os_memset(&ireq, 0, sizeof(ireq));
	os_strlcpy(ireq.i_name, drv->ifname, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_val = arg;

	if (ioctl(drv->sock, SIOCS80211, &ireq) < 0) {
		fprintf(stderr, "ioctl[SIOCS80211, op %u, arg 0x%x]: %s\n",
			op, arg, strerror(errno));
		return -1;
	}
	return 0;
}

static int
get80211param(struct wpa_driver_bsd_data *drv, int op)
{
	struct ieee80211req ireq;

	os_memset(&ireq, 0, sizeof(ireq));
	os_strlcpy(ireq.i_name, drv->ifname, IFNAMSIZ);
	ireq.i_type = op;

	if (ioctl(drv->sock, SIOCG80211, &ireq) < 0) {
		fprintf(stderr, "ioctl[SIOCG80211, op %u]: %s\n",
			op, strerror(errno));
		return -1;
	}
	return ireq.i_val;
}

static int
getifflags(struct wpa_driver_bsd_data *drv, int *flags)
{
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->ifname, sizeof(ifr.ifr_name));
	if (ioctl(drv->sock, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		perror("SIOCGIFFLAGS");
		return errno;
	}
	*flags = ifr.ifr_flags & 0xffff;
	return 0;
}

static int
setifflags(struct wpa_driver_bsd_data *drv, int flags)
{
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->ifname, sizeof(ifr.ifr_name));
	ifr.ifr_flags = flags & 0xffff;
	if (ioctl(drv->sock, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		perror("SIOCSIFFLAGS");
		return errno;
	}
	return 0;
}

static int
wpa_driver_bsd_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_bsd_data *drv = priv;

	return get80211var(drv, IEEE80211_IOC_BSSID,
		bssid, IEEE80211_ADDR_LEN) < 0 ? -1 : 0;
}

#if 0
static int
wpa_driver_bsd_set_bssid(void *priv, const char *bssid)
{
	struct wpa_driver_bsd_data *drv = priv;

	return set80211var(drv, IEEE80211_IOC_BSSID,
		bssid, IEEE80211_ADDR_LEN);
}
#endif

static int
wpa_driver_bsd_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_bsd_data *drv = priv;

	return get80211var(drv, IEEE80211_IOC_SSID,
		ssid, IEEE80211_NWID_LEN);
}

static int
wpa_driver_bsd_set_ssid(void *priv, const u8 *ssid,
			     size_t ssid_len)
{
	struct wpa_driver_bsd_data *drv = priv;

	return set80211var(drv, IEEE80211_IOC_SSID, ssid, ssid_len);
}

static int
wpa_driver_bsd_set_wpa_ie(struct wpa_driver_bsd_data *drv,
	const u8 *wpa_ie, size_t wpa_ie_len)
{
	return set80211var(drv, IEEE80211_IOC_OPTIE, wpa_ie, wpa_ie_len);
}

static int
wpa_driver_bsd_set_wpa_internal(void *priv, int wpa, int privacy)
{
	struct wpa_driver_bsd_data *drv = priv;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s: wpa=%d privacy=%d",
		__FUNCTION__, wpa, privacy);

	if (!wpa && wpa_driver_bsd_set_wpa_ie(drv, NULL, 0) < 0)
		ret = -1;
	if (set80211param(drv, IEEE80211_IOC_PRIVACY, privacy) < 0)
		ret = -1;
	if (set80211param(drv, IEEE80211_IOC_WPA, wpa) < 0)
		ret = -1;

	return ret;
}

static int
wpa_driver_bsd_set_wpa(void *priv, int enabled)
{
	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);

	return wpa_driver_bsd_set_wpa_internal(priv, enabled ? 3 : 0, enabled);
}

static int
wpa_driver_bsd_del_key(struct wpa_driver_bsd_data *drv, int key_idx,
		       const unsigned char *addr)
{
	struct ieee80211req_del_key wk;

	os_memset(&wk, 0, sizeof(wk));
	if (addr != NULL &&
	    bcmp(addr, "\xff\xff\xff\xff\xff\xff", IEEE80211_ADDR_LEN) != 0) {
		struct ether_addr ea;

		os_memcpy(&ea, addr, IEEE80211_ADDR_LEN);
		wpa_printf(MSG_DEBUG, "%s: addr=%s keyidx=%d",
			__func__, ether_ntoa(&ea), key_idx);
		os_memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.idk_keyix = (uint8_t) IEEE80211_KEYIX_NONE;
	} else {
		wpa_printf(MSG_DEBUG, "%s: keyidx=%d", __func__, key_idx);
		wk.idk_keyix = key_idx;
	}
	return set80211var(drv, IEEE80211_IOC_DELKEY, &wk, sizeof(wk));
}

static int
wpa_driver_bsd_set_key(void *priv, wpa_alg alg,
		       const unsigned char *addr, int key_idx, int set_tx,
		       const u8 *seq, size_t seq_len,
		       const u8 *key, size_t key_len)
{
	struct wpa_driver_bsd_data *drv = priv;
	struct ieee80211req_key wk;
	struct ether_addr ea;
	char *alg_name;
	u_int8_t cipher;

	if (alg == WPA_ALG_NONE)
		return wpa_driver_bsd_del_key(drv, key_idx, addr);

	switch (alg) {
	case WPA_ALG_WEP:
		alg_name = "WEP";
		cipher = IEEE80211_CIPHER_WEP;
		break;
	case WPA_ALG_TKIP:
		alg_name = "TKIP";
		cipher = IEEE80211_CIPHER_TKIP;
		break;
	case WPA_ALG_CCMP:
		alg_name = "CCMP";
		cipher = IEEE80211_CIPHER_AES_CCM;
		break;
	default:
		wpa_printf(MSG_DEBUG, "%s: unknown/unsupported algorithm %d",
			__func__, alg);
		return -1;
	}

	os_memcpy(&ea, addr, IEEE80211_ADDR_LEN);
	wpa_printf(MSG_DEBUG,
		"%s: alg=%s addr=%s key_idx=%d set_tx=%d seq_len=%zu key_len=%zu",
		__func__, alg_name, ether_ntoa(&ea), key_idx, set_tx,
		seq_len, key_len);

	if (seq_len > sizeof(u_int64_t)) {
		wpa_printf(MSG_DEBUG, "%s: seq_len %zu too big",
			__func__, seq_len);
		return -2;
	}
	if (key_len > sizeof(wk.ik_keydata)) {
		wpa_printf(MSG_DEBUG, "%s: key length %zu too big",
			__func__, key_len);
		return -3;
	}

	os_memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	wk.ik_flags = IEEE80211_KEY_RECV;
	if (set_tx)
		wk.ik_flags |= IEEE80211_KEY_XMIT;
	os_memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
	/*
	 * Deduce whether group/global or unicast key by checking
	 * the address (yech).  Note also that we can only mark global
	 * keys default; doing this for a unicast key is an error.
	 */
	if (bcmp(addr, "\xff\xff\xff\xff\xff\xff", IEEE80211_ADDR_LEN) == 0) {
		wk.ik_flags |= IEEE80211_KEY_GROUP;
		wk.ik_keyix = key_idx;
	} else {
		wk.ik_keyix = (key_idx == 0 ? IEEE80211_KEYIX_NONE : key_idx);
	}
	if (wk.ik_keyix != IEEE80211_KEYIX_NONE && set_tx)
		wk.ik_flags |= IEEE80211_KEY_DEFAULT;
	wk.ik_keylen = key_len;
	os_memcpy(&wk.ik_keyrsc, seq, seq_len);
	os_memcpy(wk.ik_keydata, key, key_len);

	return set80211var(drv, IEEE80211_IOC_WPAKEY, &wk, sizeof(wk));
}

static int
wpa_driver_bsd_set_countermeasures(void *priv, int enabled)
{
	struct wpa_driver_bsd_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);
	return set80211param(drv, IEEE80211_IOC_COUNTERMEASURES, enabled);
}


static int
wpa_driver_bsd_set_drop_unencrypted(void *priv, int enabled)
{
	struct wpa_driver_bsd_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);
	return set80211param(drv, IEEE80211_IOC_DROPUNENCRYPTED, enabled);
}

static int
wpa_driver_bsd_deauthenticate(void *priv, const u8 *addr, int reason_code)
{
	struct wpa_driver_bsd_data *drv = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s", __func__);
	os_memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(drv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
wpa_driver_bsd_disassociate(void *priv, const u8 *addr, int reason_code)
{
	struct wpa_driver_bsd_data *drv = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s", __func__);
	os_memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_DISASSOC;
	mlme.im_reason = reason_code;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(drv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
wpa_driver_bsd_associate(void *priv, struct wpa_driver_associate_params *params)
{
	struct wpa_driver_bsd_data *drv = priv;
	struct ieee80211req_mlme mlme;
	int privacy;

	wpa_printf(MSG_DEBUG,
		"%s: ssid '%.*s' wpa ie len %u pairwise %u group %u key mgmt %u"
		, __func__
		, params->ssid_len, params->ssid
		, params->wpa_ie_len
		, params->pairwise_suite
		, params->group_suite
		, params->key_mgmt_suite
	);

	/* XXX error handling is wrong but unclear what to do... */
	if (wpa_driver_bsd_set_wpa_ie(drv, params->wpa_ie, params->wpa_ie_len) < 0)
		return -1;
#ifndef NEW_FREEBSD_MLME_ASSOC
	if (wpa_driver_bsd_set_ssid(drv, params->ssid, params->ssid_len) < 0)
		return -1;
#endif

	privacy = !(params->pairwise_suite == CIPHER_NONE &&
	    params->group_suite == CIPHER_NONE &&
	    params->key_mgmt_suite == KEY_MGMT_NONE &&
	    params->wpa_ie_len == 0);
	wpa_printf(MSG_DEBUG, "%s: set PRIVACY %u", __func__, privacy);

	if (set80211param(drv, IEEE80211_IOC_PRIVACY, privacy) < 0)
		return -1;

	if (params->wpa_ie_len &&
	    set80211param(drv, IEEE80211_IOC_WPA,
			  params->wpa_ie[0] == WLAN_EID_RSN ? 2 : 1) < 0)
		return -1;

	os_memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_ASSOC;
#ifdef NEW_FREEBSD_MLME_ASSOC
	if (params->ssid != NULL)
		os_memcpy(mlme.im_ssid, params->ssid, params->ssid_len);
	mlme.im_ssid_len = params->ssid_len;
#endif
	if (params->bssid != NULL)
		os_memcpy(mlme.im_macaddr, params->bssid, IEEE80211_ADDR_LEN);
	if (set80211var(drv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme)) < 0)
		return -1;
	return 0;
}

static int
wpa_driver_bsd_set_auth_alg(void *priv, int auth_alg)
{
	struct wpa_driver_bsd_data *drv = priv;
	int authmode;

	if ((auth_alg & AUTH_ALG_OPEN_SYSTEM) &&
	    (auth_alg & AUTH_ALG_SHARED_KEY))
		authmode = IEEE80211_AUTH_AUTO;
	else if (auth_alg & AUTH_ALG_SHARED_KEY)
		authmode = IEEE80211_AUTH_SHARED;
	else
		authmode = IEEE80211_AUTH_OPEN;

	return set80211param(drv, IEEE80211_IOC_AUTHMODE, authmode);
}

static int
wpa_driver_bsd_scan(void *priv, const u8 *ssid, size_t ssid_len)
{
	struct wpa_driver_bsd_data *drv = priv;
	int flags;

	/* NB: interface must be marked UP to do a scan */
	if (getifflags(drv, &flags) != 0 || setifflags(drv, flags | IFF_UP) != 0)
		return -1;

	/* set desired ssid before scan */
	if (wpa_driver_bsd_set_ssid(drv, ssid, ssid_len) < 0)
		return -1;

	/* NB: net80211 delivers a scan complete event so no need to poll */
	return set80211param(drv, IEEE80211_IOC_SCAN_REQ, 0);
}

static void
wpa_driver_bsd_event_receive(int sock, void *ctx, void *sock_ctx)
{
	struct wpa_driver_bsd_data *drv = sock_ctx;
	char buf[2048];
	struct if_announcemsghdr *ifan;
	struct if_msghdr *ifm;
	struct rt_msghdr *rtm;
	union wpa_event_data event;
	struct ieee80211_michael_event *mic;
	int n;

	n = read(sock, buf, sizeof(buf));
	if (n < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("read(PF_ROUTE)");
		return;
	}

	rtm = (struct rt_msghdr *) buf;
	if (rtm->rtm_version != RTM_VERSION) {
		wpa_printf(MSG_DEBUG, "Routing message version %d not "
			"understood\n", rtm->rtm_version);
		return;
	}
	os_memset(&event, 0, sizeof(event));
	switch (rtm->rtm_type) {
	case RTM_IFANNOUNCE:
		ifan = (struct if_announcemsghdr *) rtm;
		if (ifan->ifan_index != drv->ifindex)
			break;
		strlcpy(event.interface_status.ifname, drv->ifname,
			sizeof(event.interface_status.ifname));
		switch (ifan->ifan_what) {
		case IFAN_DEPARTURE:
			event.interface_status.ievent = EVENT_INTERFACE_REMOVED;
		default:
			return;
		}
		wpa_printf(MSG_DEBUG, "RTM_IFANNOUNCE: Interface '%s' %s",
			   event.interface_status.ifname,
			   ifan->ifan_what == IFAN_DEPARTURE ?
				"removed" : "added");
		wpa_supplicant_event(ctx, EVENT_INTERFACE_STATUS, &event);
		break;
	case RTM_IEEE80211:
		ifan = (struct if_announcemsghdr *) rtm;
		if (ifan->ifan_index != drv->ifindex)
			break;
		switch (ifan->ifan_what) {
		case RTM_IEEE80211_ASSOC:
		case RTM_IEEE80211_REASSOC:
			wpa_supplicant_event(ctx, EVENT_ASSOC, NULL);
			break;
		case RTM_IEEE80211_DISASSOC:
			wpa_supplicant_event(ctx, EVENT_DISASSOC, NULL);
			break;
		case RTM_IEEE80211_SCAN:
			wpa_supplicant_event(ctx, EVENT_SCAN_RESULTS, NULL);
			break;
		case RTM_IEEE80211_REPLAY:
			/* ignore */
			break;
		case RTM_IEEE80211_MICHAEL:
			mic = (struct ieee80211_michael_event *) &ifan[1];
			wpa_printf(MSG_DEBUG,
				"Michael MIC failure wireless event: "
				"keyix=%u src_addr=" MACSTR, mic->iev_keyix,
				MAC2STR(mic->iev_src));

			os_memset(&event, 0, sizeof(event));
			event.michael_mic_failure.unicast =
				!IEEE80211_IS_MULTICAST(mic->iev_dst);
			wpa_supplicant_event(ctx, EVENT_MICHAEL_MIC_FAILURE,
				&event);
			break;
		}
		break;
	case RTM_IFINFO:
		ifm = (struct if_msghdr *) rtm;
		if (ifm->ifm_index != drv->ifindex)
			break;
		if ((rtm->rtm_flags & RTF_UP) == 0) {
			strlcpy(event.interface_status.ifname, drv->ifname,
				sizeof(event.interface_status.ifname));
			event.interface_status.ievent = EVENT_INTERFACE_REMOVED;
			wpa_printf(MSG_DEBUG, "RTM_IFINFO: Interface '%s' DOWN",
				   event.interface_status.ifname);
			wpa_supplicant_event(ctx, EVENT_INTERFACE_STATUS, &event);
		}
		break;
	}
}

/* Compare function for sorting scan results. Return >0 if @b is consider
 * better. */
static int
wpa_scan_result_compar(const void *a, const void *b)
{
	const struct wpa_scan_result *wa = a;
	const struct wpa_scan_result *wb = b;

	/* WPA/WPA2 support preferred */
	if ((wb->wpa_ie_len || wb->rsn_ie_len) &&
	    !(wa->wpa_ie_len || wa->rsn_ie_len))
		return 1;
	if (!(wb->wpa_ie_len || wb->rsn_ie_len) &&
	    (wa->wpa_ie_len || wa->rsn_ie_len))
		return -1;

	/* privacy support preferred */
	if ((wa->caps & IEEE80211_CAPINFO_PRIVACY) &&
	    (wb->caps & IEEE80211_CAPINFO_PRIVACY) == 0)
		return 1;
	if ((wa->caps & IEEE80211_CAPINFO_PRIVACY) == 0 &&
	    (wb->caps & IEEE80211_CAPINFO_PRIVACY))
		return -1;

	/* best/max rate preferred if signal level close enough XXX */
	if (wa->maxrate != wb->maxrate && abs(wb->level - wa->level) < 5)
		return wb->maxrate - wa->maxrate;

	/* use freq for channel preference */

	/* all things being equal, use signal level */
	return wb->level - wa->level;
}

static int
getmaxrate(uint8_t rates[15], uint8_t nrates)
{
	int i, maxrate = -1;

	for (i = 0; i < nrates; i++) {
		int rate = rates[i] & IEEE80211_RATE_VAL;
		if (rate > maxrate)
			rate = maxrate;
	}
	return maxrate;
}

/* unalligned little endian access */     
#define LE_READ_4(p)					\
	((u_int32_t)					\
	 ((((const u_int8_t *)(p))[0]      ) |		\
	  (((const u_int8_t *)(p))[1] <<  8) |		\
	  (((const u_int8_t *)(p))[2] << 16) |		\
	  (((const u_int8_t *)(p))[3] << 24)))

static int __inline
iswpaoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((WPA_OUI_TYPE<<24)|WPA_OUI);
}

static int
wpa_driver_bsd_get_scan_results(void *priv,
				     struct wpa_scan_result *results,
				     size_t max_size)
{
#define	min(a,b)	((a)>(b)?(b):(a))
	struct wpa_driver_bsd_data *drv = priv;
	uint8_t buf[24*1024];
	uint8_t *cp, *vp;
	struct ieee80211req_scan_result *sr;
	struct wpa_scan_result *wsr;
	int len, ielen;

	os_memset(results, 0, max_size * sizeof(struct wpa_scan_result));

	len = get80211var(drv, IEEE80211_IOC_SCAN_RESULTS, buf, sizeof(buf));
	if (len < 0)
		return -1;
	cp = buf;
	wsr = results;
	while (len >= sizeof(struct ieee80211req_scan_result)) {
		sr = (struct ieee80211req_scan_result *) cp;
		os_memcpy(wsr->bssid, sr->isr_bssid, IEEE80211_ADDR_LEN);
		wsr->ssid_len = sr->isr_ssid_len;
		wsr->freq = sr->isr_freq;
		wsr->noise = sr->isr_noise;
		wsr->qual = sr->isr_rssi;
		wsr->level = 0;		/* XXX? */
		wsr->caps = sr->isr_capinfo;
		wsr->maxrate = getmaxrate(sr->isr_rates, sr->isr_nrates);
		vp = (u_int8_t *)(sr+1);
		os_memcpy(wsr->ssid, vp, sr->isr_ssid_len);
		if (sr->isr_ie_len > 0) {
			vp += sr->isr_ssid_len;
			ielen = sr->isr_ie_len;
			while (ielen > 0) {
				switch (vp[0]) {
				case IEEE80211_ELEMID_VENDOR:
					if (!iswpaoui(vp))
						break;
					wsr->wpa_ie_len =
					    min(2+vp[1], SSID_MAX_WPA_IE_LEN);
					os_memcpy(wsr->wpa_ie, vp,
						  wsr->wpa_ie_len);
					break;
				case IEEE80211_ELEMID_RSN:
					wsr->rsn_ie_len =
					    min(2+vp[1], SSID_MAX_WPA_IE_LEN);
					os_memcpy(wsr->rsn_ie, vp,
						  wsr->rsn_ie_len);
					break;
				}
				ielen -= 2+vp[1];
				vp += 2+vp[1];
			}
		}

		cp += sr->isr_len, len -= sr->isr_len;
		wsr++;
	}
	qsort(results, wsr - results, sizeof(struct wpa_scan_result),
	      wpa_scan_result_compar);

	wpa_printf(MSG_DEBUG, "Received %d bytes of scan results (%d BSSes)",
		   len, wsr - results);

	return wsr - results;
#undef min
}

static void *
wpa_driver_bsd_init(void *ctx, const char *ifname)
{
#define	GETPARAM(drv, param, v) \
	(((v) = get80211param(drv, param)) != -1)
	struct wpa_driver_bsd_data *drv;

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	/*
	 * NB: We require the interface name be mappable to an index.
	 *     This implies we do not support having wpa_supplicant
	 *     wait for an interface to appear.  This seems ok; that
	 *     doesn't belong here; it's really the job of devd.
	 */
	drv->ifindex = if_nametoindex(ifname);
	if (drv->ifindex == 0) {
		wpa_printf(MSG_DEBUG, "%s: interface %s does not exist",
			   __func__, ifname);
		goto fail1;
	}
	drv->sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->sock < 0)
		goto fail1;
	drv->route = socket(PF_ROUTE, SOCK_RAW, 0);
	if (drv->route < 0)
		goto fail;
	eloop_register_read_sock(drv->route,
		wpa_driver_bsd_event_receive, ctx, drv);

	drv->ctx = ctx;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));

	if (!GETPARAM(drv, IEEE80211_IOC_ROAMING, drv->prev_roaming)) {
		wpa_printf(MSG_DEBUG, "%s: failed to get roaming state: %s",
			__func__, strerror(errno));
		goto fail;
	}
	if (!GETPARAM(drv, IEEE80211_IOC_PRIVACY, drv->prev_privacy)) {
		wpa_printf(MSG_DEBUG, "%s: failed to get privacy state: %s",
			__func__, strerror(errno));
		goto fail;
	}
	if (!GETPARAM(drv, IEEE80211_IOC_WPA, drv->prev_wpa)) {
		wpa_printf(MSG_DEBUG, "%s: failed to get wpa state: %s",
			__func__, strerror(errno));
		goto fail;
	}
	if (set80211param(drv, IEEE80211_IOC_ROAMING, IEEE80211_ROAMING_MANUAL) < 0) {
		wpa_printf(MSG_DEBUG, "%s: failed to set wpa_supplicant-based "
			   "roaming: %s", __func__, strerror(errno));
		goto fail;
	}

	if (set80211param(drv, IEEE80211_IOC_WPA, 1+2) < 0) {
		wpa_printf(MSG_DEBUG, "%s: failed to enable WPA support %s",
			   __func__, strerror(errno));
		goto fail;
	}

	return drv;
fail:
	close(drv->sock);
fail1:
	os_free(drv);
	return NULL;
#undef GETPARAM
}

static void
wpa_driver_bsd_deinit(void *priv)
{
	struct wpa_driver_bsd_data *drv = priv;
	int flags;

	eloop_unregister_read_sock(drv->route);

	/* NB: mark interface down */
	if (getifflags(drv, &flags) == 0)
		(void) setifflags(drv, flags &~ IFF_UP);

	wpa_driver_bsd_set_wpa_internal(drv, drv->prev_wpa, drv->prev_privacy);
	if (set80211param(drv, IEEE80211_IOC_ROAMING, drv->prev_roaming) < 0)
		wpa_printf(MSG_DEBUG, "%s: failed to restore roaming state",
			__func__);

	(void) close(drv->route);		/* ioctl socket */
	(void) close(drv->sock);		/* event socket */
	os_free(drv);
}


const struct wpa_driver_ops wpa_driver_bsd_ops = {
	.name			= "bsd",
	.desc			= "BSD 802.11 support (Atheros, etc.)",
	.init			= wpa_driver_bsd_init,
	.deinit			= wpa_driver_bsd_deinit,
	.get_bssid		= wpa_driver_bsd_get_bssid,
	.get_ssid		= wpa_driver_bsd_get_ssid,
	.set_wpa		= wpa_driver_bsd_set_wpa,
	.set_key		= wpa_driver_bsd_set_key,
	.set_countermeasures	= wpa_driver_bsd_set_countermeasures,
	.set_drop_unencrypted	= wpa_driver_bsd_set_drop_unencrypted,
	.scan			= wpa_driver_bsd_scan,
	.get_scan_results	= wpa_driver_bsd_get_scan_results,
	.deauthenticate		= wpa_driver_bsd_deauthenticate,
	.disassociate		= wpa_driver_bsd_disassociate,
	.associate		= wpa_driver_bsd_associate,
	.set_auth_alg		= wpa_driver_bsd_set_auth_alg,
};

#endif /* HOSTAPD */
