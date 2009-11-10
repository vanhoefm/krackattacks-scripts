/*
 * WPA Supplicant - driver interaction with Linux Prism54.org driver
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004, Luis R. Rodriguez <mcgrof@ruslug.rutgers.edu>
 * Copyright (c) 2004, Bell Kin <bell_kin@pek.com.tw>
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

#include "wireless_copy.h"
#include "common.h"
#include "driver.h"
#include "driver_wext.h"
#include "driver_hostap.h"

#ifdef HOSTAPD

#include <net/if_arp.h>
#include <netpacket/packet.h>

#include "driver.h"
#include "eloop.h"
#include "prism54.h"
#include "radius/radius.h"
#include "../../hostapd/hostapd.h"
#include "../../hostapd/config.h"
#include "../../hostapd/ieee802_1x.h"
#include "../../hostapd/ieee802_11.h"
#include "../../hostapd/wpa.h"
#include "../../hostapd/sta_info.h"
#include "../../hostapd/accounting.h"


const int PIM_BUF_SIZE = 4096;

struct prism54_driver_data {
	struct hostapd_data *hapd;
	char iface[IFNAMSIZ + 1];
	int sock; /* raw packet socket for 802.3 access */
	int pim_sock; /* socket for pimfor packet */
	char macs[2007][6];
};


static int mac_id_refresh(struct prism54_driver_data *data, int id, char *mac)
{
	if (id < 0 || id > 2006) {
		return -1;
	}
	memcpy(&data->macs[id][0], mac, ETH_ALEN);
	return 0;
}


static char * mac_id_get(struct prism54_driver_data *data, int id)
{
	if (id < 0 || id > 2006) {
		return NULL;
	}
	return &data->macs[id][0];
}


/* wait for a specific pimfor, timeout in 10ms resolution */
/* pim_sock must be non-block to prevent dead lock from no response */
/* or same response type in series */
static int prism54_waitpim(void *priv, unsigned long oid, void *buf, int len,
			   int timeout)
{
	struct prism54_driver_data *drv = priv;
	struct timeval tv, stv, ctv;
	fd_set pfd;
	int rlen;
	pimdev_hdr *pkt;

	pkt = malloc(8192);
	if (pkt == NULL)
		return -1;

	FD_ZERO(&pfd);
	gettimeofday(&stv, NULL);
	do {
		FD_SET(drv->pim_sock, &pfd);
		tv.tv_sec = 0;
		tv.tv_usec = 10000;
		if (select(drv->pim_sock + 1, &pfd, NULL, NULL, &tv)) {
			rlen = recv(drv->pim_sock, pkt, 8192, 0);
			if (rlen > 0) {
				if (pkt->oid == htonl(oid)) {
					if (rlen <= len) {
						if (buf != NULL) {
							memcpy(buf, pkt, rlen);
						}
						free(pkt);
						return rlen;
					} else {
						printf("buffer too small\n");
						free(pkt);
						return -1;
					}
				} else {
					gettimeofday(&ctv, NULL);
					continue;
				}
			}
		}
		gettimeofday(&ctv, NULL);
	} while (((ctv.tv_sec - stv.tv_sec) * 100 +
		  (ctv.tv_usec - stv.tv_usec) / 10000) > timeout);
	free(pkt);
	return 0;
}


/* send an eapol packet */
static int prism54_send_eapol(void *priv, const u8 *addr,
			      const u8 *data, size_t data_len, int encrypt,
			      const u8 *own_addr)
{
	struct prism54_driver_data *drv = priv;
	ieee802_3_hdr *hdr;
	size_t len;
	u8 *pos;
	int res;

	len = sizeof(*hdr) + data_len;
	hdr = os_zalloc(len);
	if (hdr == NULL) {
		printf("malloc() failed for prism54_send_data(len=%lu)\n",
		       (unsigned long) len);
		return -1;
	}

	memcpy(&hdr->da[0], addr, ETH_ALEN);
	memcpy(&hdr->sa[0], own_addr, ETH_ALEN);
	hdr->type = htons(ETH_P_PAE);
	pos = (u8 *) (hdr + 1);
	memcpy(pos, data, data_len);

	res = send(drv->sock, hdr, len, 0);
	free(hdr);

	if (res < 0) {
		perror("hostapd_send_eapol: send");
		printf("hostapd_send_eapol - packet len: %lu - failed\n",
		       (unsigned long) len);
	}

	return res;
}


/* open data channel(auth-1) or eapol only(unauth-0) */
static int prism54_set_sta_authorized(void *priv, const u8 *addr,
				      int authorized)
{
	struct prism54_driver_data *drv = priv;
	pimdev_hdr *hdr;
	char *pos;

	hdr = os_zalloc(sizeof(*hdr) + ETH_ALEN);
	if (hdr == NULL)
		return -1;
	hdr->op = htonl(PIMOP_SET);
	if (authorized) {
		hdr->oid = htonl(DOT11_OID_EAPAUTHSTA);
	} else {
		hdr->oid = htonl(DOT11_OID_EAPUNAUTHSTA);
	}
	pos = (char *) (hdr + 1);
	memcpy(pos, addr, ETH_ALEN);
	send(drv->pim_sock, hdr, sizeof(*hdr) + ETH_ALEN, 0);
	prism54_waitpim(priv, hdr->oid, hdr, sizeof(*hdr) + ETH_ALEN, 10);
	free(hdr);
	return 0;
}


static int
prism54_sta_set_flags(void *priv, const u8 *addr, int total_flags,
		      int flags_or, int flags_and)
{
	/* For now, only support setting Authorized flag */
	if (flags_or & WLAN_STA_AUTHORIZED)
		return prism54_set_sta_authorized(priv, addr, 1);
	if (flags_and & WLAN_STA_AUTHORIZED)
		return prism54_set_sta_authorized(priv, addr, 0);
	return 0;
}


static int prism54_set_key(const char *ifname, void *priv, wpa_alg alg,
			   const u8 *addr, int key_idx, int set_tx,
			   const u8 *seq, size_t seq_len,
			   const u8 *key, size_t key_len)
{
	struct prism54_driver_data *drv = priv;
	pimdev_hdr *hdr;
	struct obj_stakey *keys;
	u8 *buf;
	size_t blen;
	int ret = 0;

	blen = sizeof(struct obj_stakey) + sizeof(pimdev_hdr);
	hdr = os_zalloc(blen);
	if (hdr == NULL) {
		printf("memory low\n");
		return -1;
	}
	keys = (struct obj_stakey *) &hdr[1];
	if (!addr) {
		memset(&keys->address[0], 0xff, ETH_ALEN);
	} else {
		memcpy(&keys->address[0], addr, ETH_ALEN);
	}
	switch (alg) {
	case WPA_ALG_WEP:
		keys->type = DOT11_PRIV_WEP;
		break;
	case WPA_ALG_TKIP:
		keys->type = DOT11_PRIV_TKIP;
		break;
	case WPA_ALG_NONE:
		/* the only way to clear the key is to deauth it */
		/* and prism54 is capable to receive unencrypted packet */
		/* so we do nothing here */
		free(hdr);
		return 0;
	default:
		printf("bad auth type: %d\n", alg);
		free(hdr);
		return -1;
	}
	buf = (u8 *) &keys->key[0];
	keys->length = key_len;
	keys->keyid = key_idx;
	keys->options = htons(DOT11_STAKEY_OPTION_DEFAULTKEY);
	keys->reserved = 0;

	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_STAKEY);

	memcpy(buf, key, key_len);
	
	ret = send(drv->pim_sock, hdr, blen, 0);
	if (ret < 0) {
		free(hdr);
		return ret;
	}
	prism54_waitpim(priv, hdr->oid, hdr, blen, 10);

	free(hdr);

	return 0;
}


/* get TKIP station sequence counter, prism54 is only 6 bytes */
static int prism54_get_seqnum(const char *ifname, void *priv, const u8 *addr,
			      int idx, u8 *seq)
{
	struct prism54_driver_data *drv = priv;
	struct obj_stasc *stasc;
	pimdev_hdr *hdr;
	size_t blen;
	int ret = 0;

	blen = sizeof(*stasc) + sizeof(*hdr);
	hdr = os_zalloc(blen);
	if (hdr == NULL)
		return -1;

	stasc = (struct obj_stasc *) &hdr[1];
	
	if (addr == NULL)
		memset(&stasc->address[0], 0xff, ETH_ALEN);
	else
		memcpy(&stasc->address[0], addr, ETH_ALEN);

	hdr->oid = htonl(DOT11_OID_STASC);
	hdr->op = htonl(PIMOP_GET);
	stasc->keyid = idx;
	if (send(drv->pim_sock,hdr,blen,0) <= 0) {
		free(hdr);
		return -1;
	}
	if (prism54_waitpim(priv, DOT11_OID_STASC, hdr, blen, 10) <= 0) {
		ret = -1;
	} else {
		if (hdr->op == (int) htonl(PIMOP_RESPONSE)) {
			memcpy(seq + 2, &stasc->sc_high, ETH_ALEN);
			memset(seq, 0, 2);
		} else {
			ret = -1;
		}
	}
	free(hdr);

	return ret;
}


/* include unencrypted, set mlme autolevel to extended */
static int prism54_init_1x(void *priv)
{
	struct prism54_driver_data *drv = priv;
	pimdev_hdr *hdr;
	unsigned long *ul;
	int blen = sizeof(*hdr) + sizeof(*ul);

	hdr = os_zalloc(blen);
	if (hdr == NULL)
		return -1;

	ul = (unsigned long *) &hdr[1];
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_EXUNENCRYPTED);
	*ul = htonl(DOT11_BOOL_TRUE); /* not accept */
	send(drv->pim_sock, hdr, blen, 0);
	prism54_waitpim(priv, DOT11_OID_EXUNENCRYPTED, hdr, blen, 10);
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_MLMEAUTOLEVEL);
	*ul = htonl(DOT11_MLME_EXTENDED);
	send(drv->pim_sock, hdr, blen, 0);
	prism54_waitpim(priv, DOT11_OID_MLMEAUTOLEVEL, hdr, blen, 10);
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_DOT1XENABLE);
	*ul = htonl(DOT11_BOOL_TRUE);
	send(drv->pim_sock, hdr, blen, 0);
	prism54_waitpim(priv, DOT11_OID_DOT1XENABLE, hdr, blen, 10);
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_AUTHENABLE);
	*ul = htonl(DOT11_AUTH_OS); /* OS */
	send(drv->pim_sock, hdr, blen, 0);
	prism54_waitpim(priv, DOT11_OID_AUTHENABLE, hdr, blen, 10);
	free(hdr);
	return 0;
}


static int prism54_set_privacy_invoked(const char *ifname, void *priv,
				       int flag)
{
	struct prism54_driver_data *drv = priv;
	pimdev_hdr *hdr;
	unsigned long *ul;
	int ret;
	int blen = sizeof(*hdr) + sizeof(*ul);
	hdr = os_zalloc(blen);
	if (hdr == NULL)
		return -1;
	ul = (unsigned long *) &hdr[1];
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_PRIVACYINVOKED);
	if (flag) {
		*ul = htonl(DOT11_BOOL_TRUE); /* has privacy */
	} else {
		*ul = 0;
	}
	ret = send(drv->pim_sock, hdr, blen, 0);
	if (ret >= 0) {
		ret = prism54_waitpim(priv, DOT11_OID_PRIVACYINVOKED, hdr,
				      blen, 10);
	}
	free(hdr);
	return ret;
}

 
static int prism54_ioctl_setiwessid(const char *ifname, void *priv,
				    const u8 *buf, int len)
{
#if 0
	struct prism54_driver_data *drv = priv;
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.essid.flags = 1; /* SSID active */
	iwr.u.essid.pointer = (caddr_t) buf;
	iwr.u.essid.length = len + 1;

	if (ioctl(drv->pim_sock, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		printf("len=%d\n", len);
		return -1;
	}
#endif
	return 0;
}


/* kick all stations */
/* does not work during init, but at least it won't crash firmware */
static int prism54_flush(void *priv)
{
	struct prism54_driver_data *drv = priv;
	struct obj_mlmeex *mlme;
	pimdev_hdr *hdr;
	int ret;
	unsigned int i;
	long *nsta;
	int blen = sizeof(*hdr) + sizeof(*mlme);
	char *mac_id;

	hdr = os_zalloc(blen);
	if (hdr == NULL)
		return -1;

	mlme = (struct obj_mlmeex *) &hdr[1];
	nsta = (long *) &hdr[1];
	hdr->op = htonl(PIMOP_GET);
	hdr->oid = htonl(DOT11_OID_CLIENTS);
	ret = send(drv->pim_sock, hdr, sizeof(*hdr) + sizeof(long), 0);
	ret = prism54_waitpim(priv, DOT11_OID_CLIENTS, hdr, blen, 10);
	if ((ret < 0) || (hdr->op != (int) htonl(PIMOP_RESPONSE)) ||
	    (le_to_host32(*nsta) > 2007)) {
		free(hdr);
		return 0;
	}
	for (i = 0; i < le_to_host32(*nsta); i++) {
		mlme->id = -1;
		mac_id = mac_id_get(drv, i);
		if (mac_id)
			memcpy(&mlme->address[0], mac_id, ETH_ALEN);
		mlme->code = host_to_le16(WLAN_REASON_UNSPECIFIED);
		mlme->state = htons(DOT11_STATE_NONE);
		mlme->size = 0;
		hdr->op = htonl(PIMOP_SET);
		hdr->oid = htonl(DOT11_OID_DISASSOCIATEEX);
		ret = send(drv->pim_sock, hdr, blen, 0);
		prism54_waitpim(priv, DOT11_OID_DISASSOCIATEEX, hdr, blen,
				100);
	}
	for (i = 0; i < le_to_host32(*nsta); i++) {
		mlme->id = -1;
		mac_id = mac_id_get(drv, i);
		if (mac_id)
			memcpy(&mlme->address[0], mac_id, ETH_ALEN);
		mlme->code = host_to_le16(WLAN_REASON_UNSPECIFIED);
		mlme->state = htons(DOT11_STATE_NONE);
		mlme->size = 0;
		hdr->op = htonl(PIMOP_SET);
		hdr->oid = htonl(DOT11_OID_DEAUTHENTICATEEX);
		ret = send(drv->pim_sock, hdr, blen, 0);
		prism54_waitpim(priv, DOT11_OID_DEAUTHENTICATEEX, hdr, blen,
				100);
	}
	free(hdr);
	return 0;
}


static int prism54_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
			      int reason)
{
	struct prism54_driver_data *drv = priv;
	pimdev_hdr *hdr;
	struct obj_mlmeex *mlme;
	int ret;
	int blen = sizeof(*hdr) + sizeof(*mlme);
	hdr = os_zalloc(blen);
	if (hdr == NULL)
		return -1;
	mlme = (struct obj_mlmeex *) &hdr[1];
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_DEAUTHENTICATEEX);
	memcpy(&mlme->address[0], addr, ETH_ALEN);
	mlme->id = -1;
	mlme->state = htons(DOT11_STATE_NONE);
	mlme->code = host_to_le16(reason);
	mlme->size = 0;
	ret = send(drv->pim_sock, hdr, blen, 0);
	prism54_waitpim(priv, DOT11_OID_DEAUTHENTICATEEX, hdr, blen, 10);
	free(hdr);
	return ret;
}


static int prism54_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
				int reason)
{
	struct prism54_driver_data *drv = priv;
        pimdev_hdr *hdr;
        struct obj_mlmeex *mlme;
	int ret;
        int blen = sizeof(*hdr) + sizeof(*mlme);
        hdr = os_zalloc(blen);
	if (hdr == NULL)
		return -1;
        mlme = (struct obj_mlmeex *) &hdr[1];
        hdr->op = htonl(PIMOP_SET);
        hdr->oid = htonl(DOT11_OID_DISASSOCIATEEX);
        memcpy(&mlme->address[0], addr, ETH_ALEN);
        mlme->id = -1;
        mlme->state = htons(DOT11_STATE_NONE);
        mlme->code = host_to_le16(reason);
	mlme->size = 0;
        ret = send(drv->pim_sock, hdr, blen, 0);
        prism54_waitpim(priv, DOT11_OID_DISASSOCIATEEX, hdr, blen, 10);
        free(hdr);
        return ret;
}


static int prism54_get_inact_sec(void *priv, const u8 *addr)
{
	struct prism54_driver_data *drv = priv;
	pimdev_hdr *hdr;
	struct obj_sta *sta;
	int blen = sizeof(*hdr) + sizeof(*sta);
	int ret;

	hdr = os_zalloc(blen);
	if (hdr == NULL)
		return -1;
	hdr->op = htonl(PIMOP_GET);
	hdr->oid = htonl(DOT11_OID_CLIENTFIND);
	sta = (struct obj_sta *) &hdr[1];
	memcpy(&sta->address[0], addr, ETH_ALEN);
	ret = send(drv->pim_sock, hdr, blen, 0);
	ret = prism54_waitpim(priv, DOT11_OID_CLIENTFIND, hdr, blen, 10);
	if (ret != blen) {
		printf("get_inact_sec: bad return %d\n", ret);
		free(hdr);
		return -1;
	}
	if (hdr->op != (int) htonl(PIMOP_RESPONSE)) {
		printf("get_inact_sec: bad resp\n");
		free(hdr);
		return -1;
	}
	free(hdr);
	return le_to_host16(sta->age);
}


/* set attachments */
static int prism54_set_generic_elem(const char *ifname, void *priv,
				    const u8 *elem, size_t elem_len)
{
	struct prism54_driver_data *drv = priv;
	pimdev_hdr *hdr;
	char *pos;
	struct obj_attachment_hdr *attach;
	size_t blen = sizeof(*hdr) + sizeof(*attach) + elem_len;
	hdr = os_zalloc(blen);
	if (hdr == NULL) {
		printf("%s: memory low\n", __func__);
		return -1;
	}
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_ATTACHMENT);
	attach = (struct obj_attachment_hdr *)&hdr[1];
	attach->type = DOT11_PKT_BEACON;
	attach->id = -1;
	attach->size = host_to_le16((short)elem_len);
	pos = ((char*) attach) + sizeof(*attach);
	if (elem)
		memcpy(pos, elem, elem_len);
	send(drv->pim_sock, hdr, blen, 0);
	attach->type = DOT11_PKT_PROBE_RESP;
	send(drv->pim_sock, hdr, blen, 0);
	free(hdr);
	return 0;
}


/* tell the card to auth the sta */
static void prism54_handle_probe(struct prism54_driver_data *drv,
				 void *buf, size_t len)
{
	struct obj_mlmeex *mlme;
	pimdev_hdr *hdr;
	struct sta_info *sta;
	hdr = (pimdev_hdr *)buf;
	mlme = (struct obj_mlmeex *) &hdr[1];
	sta = ap_get_sta(drv->hapd, (u8 *) &mlme->address[0]);
	if (sta != NULL) {
		if (sta->flags & (WLAN_STA_AUTH | WLAN_STA_ASSOC))
			return;
	}
	if (len < sizeof(*mlme)) {
		printf("bad probe packet\n");
		return;
	}
	mlme->state = htons(DOT11_STATE_AUTHING);
	mlme->code = 0;
	hdr->op = htonl(PIMOP_SET);
	hdr->oid = htonl(DOT11_OID_AUTHENTICATEEX);
	mlme->size = 0;
	send(drv->pim_sock, hdr, sizeof(*hdr)+sizeof(*mlme), 0);
}


static void prism54_handle_deauth(struct prism54_driver_data *drv,
				  void *buf, size_t len)
{
	struct obj_mlme *mlme;
	pimdev_hdr *hdr;
	struct sta_info *sta;
	char *mac_id;

	hdr = (pimdev_hdr *) buf;
	mlme = (struct obj_mlme *) &hdr[1];
	sta = ap_get_sta(drv->hapd, (u8 *) &mlme->address[0]);
	mac_id = mac_id_get(drv, mlme->id);
	if (sta == NULL || mac_id == NULL)
		return;
	memcpy(&mlme->address[0], mac_id, ETH_ALEN);
	sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
	wpa_auth_sm_event(sta->wpa_sm, WPA_DEAUTH);
	sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
	ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
	ap_free_sta(drv->hapd, sta);
}


static void prism54_handle_disassoc(struct prism54_driver_data *drv,
				    void *buf, size_t len)
{
	struct obj_mlme *mlme;
	pimdev_hdr *hdr;
	struct sta_info *sta;
	char *mac_id;

	hdr = (pimdev_hdr *) buf;
	mlme = (struct obj_mlme *) &hdr[1];
	mac_id = mac_id_get(drv, mlme->id);
	if (mac_id == NULL)
		return;
	memcpy(&mlme->address[0], mac_id, ETH_ALEN);
	sta = ap_get_sta(drv->hapd, (u8 *) &mlme->address[0]);
	if (sta == NULL) {
		return;
	}
	sta->flags &= ~WLAN_STA_ASSOC;
	wpa_auth_sm_event(sta->wpa_sm, WPA_DISASSOC);
	sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
	ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
	accounting_sta_stop(drv->hapd, sta);
	ieee802_1x_free_station(sta);
}


/* to auth it, just allow it now, later for os/sk */
static void prism54_handle_auth(struct prism54_driver_data *drv,
				void *buf, size_t len)
{
	struct obj_mlmeex *mlme;
	pimdev_hdr *hdr;
	struct sta_info *sta;
	int resp;

	hdr = (pimdev_hdr *) buf;
	mlme = (struct obj_mlmeex *) &hdr[1];
	if (len < sizeof(*mlme)) {
		printf("bad auth packet\n");
		return;
	}

	if (mlme->state == htons(DOT11_STATE_AUTHING)) {
		sta = ap_sta_add(drv->hapd, (u8 *) &mlme->address[0]);
		if (drv->hapd->tkip_countermeasures) {
			resp = WLAN_REASON_MICHAEL_MIC_FAILURE;
			goto fail;
		}
		mac_id_refresh(drv, mlme->id, &mlme->address[0]);
		if (!sta) {
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
		}
		sta->flags &= ~WLAN_STA_PREAUTH;
		
		ieee802_1x_notify_pre_auth(sta->eapol_sm, 0);
		sta->flags |= WLAN_STA_AUTH;
		wpa_auth_sm_event(sta->wpa_sm, WPA_AUTH);
		mlme->code = 0;
		mlme->state=htons(DOT11_STATE_AUTH);
		hdr->op = htonl(PIMOP_SET);
		hdr->oid = htonl(DOT11_OID_AUTHENTICATEEX);
		mlme->size = 0;
		sta->timeout_next = STA_NULLFUNC;
		send(drv->pim_sock, hdr, sizeof(*hdr) + sizeof(*mlme), 0);
	}
	return;

fail:
	printf("auth fail: %x\n", resp);
	mlme->code = host_to_le16(resp);
	mlme->size = 0;
	if (sta)
		sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
	hdr->oid = htonl(DOT11_OID_DEAUTHENTICATEEX);
	hdr->op = htonl(PIMOP_SET);
	send(drv->pim_sock, hdr, sizeof(*hdr)+sizeof(*mlme), 0);
}


/* do the wpa thing */
static void prism54_handle_assoc(struct prism54_driver_data *drv,
				 void *buf, size_t len)
{
	pimdev_hdr *hdr;
	struct obj_mlmeex *mlme;
	struct ieee802_11_elems elems;
	struct sta_info *sta;
	u8 *wpa_ie;
	u8 *cb;
	int ieofs = 0;
	size_t wpa_ie_len;
	int resp, new_assoc;
	char *mac_id;

	resp = 0;
	hdr = (pimdev_hdr *) buf;
	mlme = (struct obj_mlmeex *) &hdr[1];
	switch (ntohl(hdr->oid)) {
		case DOT11_OID_ASSOCIATE:
		case DOT11_OID_REASSOCIATE:
			mlme->size = 0;
		default:
			break;
	}
	if ((mlme->state == (int) htonl(DOT11_STATE_ASSOCING)) ||
	    (mlme->state == (int) htonl(DOT11_STATE_REASSOCING))) {
		if (len < sizeof(pimdev_hdr) + sizeof(struct obj_mlme)) {
			printf("bad assoc packet\n");
			return;
		}
		mac_id = mac_id_get(drv, mlme->id);
		if (mac_id == NULL)
			return;
		memcpy(&mlme->address[0], mac_id, ETH_ALEN);
		sta = ap_get_sta(drv->hapd, (u8 *) &mlme->address[0]);
		if (sta == NULL) {
			printf("cannot get sta\n");
			return;
		}
		cb = (u8 *) &mlme->data[0];
		if (hdr->oid == htonl(DOT11_OID_ASSOCIATEEX)) {
			ieofs = 4;
		} else if (hdr->oid == htonl(DOT11_OID_REASSOCIATEEX)) {
			ieofs = 10;
		}
		if (le_to_host16(mlme->size) <= ieofs) {
			printf("attach too small\n");
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
		}
		if (ieee802_11_parse_elems(cb + ieofs,
					   le_to_host16(mlme->size) - ieofs,
					   &elems, 1) == ParseFailed) {
			printf("STA " MACSTR " sent invalid association "
			       "request\n", MAC2STR(sta->addr));
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
		}
		if ((drv->hapd->conf->wpa & WPA_PROTO_RSN) &&
		    elems.rsn_ie) {
			wpa_ie = elems.rsn_ie;
			wpa_ie_len = elems.rsn_ie_len;
		} else if ((drv->hapd->conf->wpa & WPA_PROTO_WPA) &&
			   elems.wpa_ie) {
			wpa_ie = elems.wpa_ie;
			wpa_ie_len = elems.wpa_ie_len;
		} else {
			wpa_ie = NULL;
			wpa_ie_len = 0;
		}
		if (drv->hapd->conf->wpa && wpa_ie == NULL) {
			printf("STA " MACSTR ": No WPA/RSN IE in association "
			       "request\n", MAC2STR(sta->addr));
			resp = WLAN_STATUS_INVALID_IE;
			goto fail;
		}
		if (drv->hapd->conf->wpa) {
			int res;
			wpa_ie -= 2;
			wpa_ie_len += 2;
			if (sta->wpa_sm == NULL)
				sta->wpa_sm = wpa_auth_sta_init(
					drv->hapd->wpa_auth, sta->addr);
			if (sta->wpa_sm == NULL) {
				printf("Failed to initialize WPA state "
				       "machine\n");
				resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
				goto fail;
			}
			res = wpa_validate_wpa_ie(drv->hapd->wpa_auth,
						  sta->wpa_sm,
						  wpa_ie, wpa_ie_len,
						  NULL, 0);
			if (res == WPA_INVALID_GROUP)
				resp = WLAN_STATUS_GROUP_CIPHER_NOT_VALID;
			else if (res == WPA_INVALID_PAIRWISE)
				resp = WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID;
			else if (res == WPA_INVALID_AKMP)
				resp = WLAN_STATUS_AKMP_NOT_VALID;
			else if (res == WPA_ALLOC_FAIL)
				resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			else if (res != WPA_IE_OK)
				resp = WLAN_STATUS_INVALID_IE;
			if (resp != WLAN_STATUS_SUCCESS)
				goto fail;
		}
		hdr->oid = (hdr->oid == htonl(DOT11_OID_ASSOCIATEEX)) ?
			htonl(DOT11_OID_ASSOCIATEEX) :
			htonl(DOT11_OID_REASSOCIATEEX);
		hdr->op = htonl(PIMOP_SET);
		mlme->code = 0;
		mlme->state = htons(DOT11_STATE_ASSOC);
		mlme->size = 0;
		send(drv->pim_sock, hdr, sizeof(*hdr) + sizeof(*mlme), 0);
		return;
	} else if (mlme->state==htons(DOT11_STATE_ASSOC)) {
		if (len < sizeof(pimdev_hdr) + sizeof(struct obj_mlme)) {
			printf("bad assoc packet\n");
			return;
		}
		mac_id = mac_id_get(drv, mlme->id);
		if (mac_id == NULL)
			return;
		memcpy(&mlme->address[0], mac_id, ETH_ALEN);
		sta = ap_get_sta(drv->hapd, (u8 *) &mlme->address[0]);
		if (sta == NULL) {
			printf("cannot get sta\n");
			return;
		}
		new_assoc = (sta->flags & WLAN_STA_ASSOC) == 0;
		sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
		wpa_auth_sm_event(sta->wpa_sm, WPA_ASSOC);
		hostapd_new_assoc_sta(drv->hapd, sta, !new_assoc);
		ieee802_1x_notify_port_enabled(sta->eapol_sm, 1);
		sta->timeout_next = STA_NULLFUNC;
		return;
	}
	return;

fail:
	printf("Prism54: assoc fail: %x\n", resp);
	mlme->code = host_to_le16(resp);
	mlme->size = 0;
	mlme->state = htons(DOT11_STATE_ASSOCING);
	hdr->oid = htonl(DOT11_OID_DISASSOCIATEEX);
	hdr->op = htonl(PIMOP_SET);
	sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
	send(drv->pim_sock, hdr, sizeof(*hdr) + sizeof(*mlme), 0);
}


static void handle_pim(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct prism54_driver_data *drv = eloop_ctx;
	int len;
	pimdev_hdr *hdr;

	hdr = malloc(PIM_BUF_SIZE);
	if (hdr == NULL)
		return;
	len = recv(sock, hdr, PIM_BUF_SIZE, 0);
	if (len < 0) {
		perror("recv");
		free(hdr);
		return;
	}
	if (len < 8) {
		printf("handle_pim: too short (%d)\n", len);
		free(hdr);
		return;
	}

	if (hdr->op != (int) htonl(PIMOP_TRAP)) {
		free(hdr);
		return;
	}
	switch (ntohl(hdr->oid)) {
		case DOT11_OID_PROBE:
			prism54_handle_probe(drv, hdr, len);
			break;
		case DOT11_OID_DEAUTHENTICATEEX:
		case DOT11_OID_DEAUTHENTICATE:
			prism54_handle_deauth(drv, hdr, len);
			break;
		case DOT11_OID_DISASSOCIATEEX:
		case DOT11_OID_DISASSOCIATE:
			prism54_handle_disassoc(drv, hdr, len);
			break;
		case DOT11_OID_AUTHENTICATEEX:
		case DOT11_OID_AUTHENTICATE:
			prism54_handle_auth(drv, hdr, len);
			break;
		case DOT11_OID_ASSOCIATEEX:
		case DOT11_OID_REASSOCIATEEX:
		case DOT11_OID_ASSOCIATE:
		case DOT11_OID_REASSOCIATE:
			prism54_handle_assoc(drv, hdr, len);
		default:
			break;
	}

	free(hdr);
}


static void handle_802_3(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct hostapd_data *hapd = (struct hostapd_data *) eloop_ctx;
	int len;
	ieee802_3_hdr *hdr;

	hdr = malloc(PIM_BUF_SIZE);
	if (hdr == NULL)
		return;
	len = recv(sock, hdr, PIM_BUF_SIZE, 0);
	if (len < 0) {
		perror("recv");
		free(hdr);
		return;
	}
        if (len < 14) {
                wpa_printf(MSG_MSGDUMP, "handle_802_3: too short (%d)", len);
		free(hdr);
                return;
        }
        if (hdr->type == htons(ETH_P_PAE)) {
                hostapd_eapol_receive(hapd, (u8 *) &hdr->sa[0], (u8 *) &hdr[1],
				      len - sizeof(*hdr));
        }
	free(hdr);
}


static int prism54_init_sockets(struct prism54_driver_data *drv,
				struct wpa_init_params *params)
{
	struct ifreq ifr;
	struct sockaddr_ll addr;

	drv->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if (drv->sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return -1;
	}

	if (eloop_register_read_sock(drv->sock, handle_802_3, drv->hapd, NULL))
	{
		printf("Could not register read socket\n");
		return -1;
	}

        memset(&ifr, 0, sizeof(ifr));
	if (params->num_bridge && params->bridge[0]) {
		printf("opening bridge: %s\n", params->bridge[0]);
		os_strlcpy(ifr.ifr_name, params->bridge[0],
			   sizeof(ifr.ifr_name));
	} else {
		os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
	}
        if (ioctl(drv->sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
        }

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	addr.sll_protocol = htons(ETH_P_PAE);
	wpa_printf(MSG_DEBUG, "Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (bind(drv->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

        memset(&ifr, 0, sizeof(ifr));
        os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
        if (ioctl(drv->sock, SIOCGIFHWADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		return -1;
        }

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		printf("Invalid HW-addr family 0x%04x\n",
		       ifr.ifr_hwaddr.sa_family);
		return -1;
	}
	memcpy(params->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	drv->pim_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (drv->pim_sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return -1;
	}

	if (eloop_register_read_sock(drv->pim_sock, handle_pim, drv, NULL)) {
		printf("Could not register read socket\n");
		return -1;
	}

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%sap", drv->iface);
        if (ioctl(drv->pim_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
        }

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	addr.sll_protocol = htons(ETH_P_ALL);
	wpa_printf(MSG_DEBUG, "Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (bind(drv->pim_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

	return 0;
}


static void * prism54_driver_init(struct hostapd_data *hapd,
				  struct wpa_init_params *params)
{
	struct prism54_driver_data *drv;

	drv = os_zalloc(sizeof(struct prism54_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for hostapd Prism54 driver "
		       "data\n");
		return NULL;
	}

	drv->hapd = hapd;
	drv->pim_sock = drv->sock = -1;
	memcpy(drv->iface, params->ifname, sizeof(drv->iface));

	if (prism54_init_sockets(drv, params)) {
		free(drv);
		return NULL;
	}
	prism54_init_1x(drv);
	/* must clean previous elems */
	prism54_set_generic_elem(drv->iface, drv, NULL, 0);

	return drv;
}


static void prism54_driver_deinit(void *priv)
{
	struct prism54_driver_data *drv = priv;

	if (drv->pim_sock >= 0)
		close(drv->pim_sock);

	if (drv->sock >= 0)
		close(drv->sock);
	
	free(drv);
}

#else /* HOSTAPD */

struct wpa_driver_prism54_data {
	void *wext; /* private data for driver_wext */
	void *ctx;
	char ifname[IFNAMSIZ + 1];
	int sock;
};

#define PRISM54_SET_WPA    		SIOCIWFIRSTPRIV+12
#define PRISM54_HOSTAPD    		SIOCIWFIRSTPRIV+25
#define PRISM54_DROP_UNENCRYPTED	SIOCIWFIRSTPRIV+26

static void show_set_key_error(struct prism2_hostapd_param *);

static int hostapd_ioctl_prism54(struct wpa_driver_prism54_data *drv,
				 struct prism2_hostapd_param *param,
				 int len, int show_err)
{
	struct iwreq iwr;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = len;

	if (ioctl(drv->sock, PRISM54_HOSTAPD, &iwr) < 0) {
		int ret = errno;
		if (show_err) 
			perror("ioctl[PRISM54_HOSTAPD]");
		return ret;
	}

	return 0;
}


static int wpa_driver_prism54_set_wpa_ie(struct wpa_driver_prism54_data *drv,
					 const u8 *wpa_ie,
					 size_t wpa_ie_len)
{
	struct prism2_hostapd_param *param;
	int res;
	size_t blen = PRISM2_HOSTAPD_GENERIC_ELEMENT_HDR_LEN + wpa_ie_len;
	if (blen < sizeof(*param))
		blen = sizeof(*param);

	param = os_zalloc(blen);
	if (param == NULL)
		return -1;
	
	param->cmd = PRISM2_HOSTAPD_SET_GENERIC_ELEMENT;
	param->u.generic_elem.len = wpa_ie_len;
	os_memcpy(param->u.generic_elem.data, wpa_ie, wpa_ie_len);
	res = hostapd_ioctl_prism54(drv, param, blen, 1);

	os_free(param);

	return res;
}


/* This is called at wpa_supplicant daemon init time */
static int wpa_driver_prism54_set_wpa(void *priv, int enabled)
{
	struct wpa_driver_prism54_data *drv = priv;
	struct prism2_hostapd_param *param;
	int res;
	size_t blen = PRISM2_HOSTAPD_GENERIC_ELEMENT_HDR_LEN;
	if (blen < sizeof(*param))
		blen = sizeof(*param);

	param = os_zalloc(blen);
	if (param == NULL)
		return -1;

	param->cmd = PRISM54_SET_WPA;
	param->u.generic_elem.len = 0;
	res = hostapd_ioctl_prism54(drv, param, blen, 1);

	os_free(param);

	return res;
}


static int wpa_driver_prism54_set_key(void *priv, wpa_alg alg,
				      const u8 *addr, int key_idx, int set_tx,
				      const u8 *seq, size_t seq_len,
				      const u8 *key, size_t key_len)
{
	struct wpa_driver_prism54_data *drv = priv;
	struct prism2_hostapd_param *param;
	u8 *buf;
	size_t blen;
	int ret = 0;
	char *alg_name;

	switch (alg) {
	case WPA_ALG_NONE:
		alg_name = "none";
		return -1;
		break;
	case WPA_ALG_WEP:
		alg_name = "WEP";
		return -1;
		break;
	case WPA_ALG_TKIP:
		alg_name = "TKIP";
		break;
	case WPA_ALG_CCMP:
		alg_name = "CCMP";
		return -1;
		break;
	default:
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s: alg=%s key_idx=%d set_tx=%d seq_len=%lu "
		   "key_len=%lu", __FUNCTION__, alg_name, key_idx, set_tx,
		   (unsigned long) seq_len, (unsigned long) key_len);

	if (seq_len > 8)
		return -2;

	blen = sizeof(*param) + key_len;
	buf = os_zalloc(blen);
	if (buf == NULL)
		return -1;

	param = (struct prism2_hostapd_param *) buf;
	param->cmd = PRISM2_SET_ENCRYPTION;
	/* TODO: In theory, STA in client mode can use five keys; four default
	 * keys for receiving (with keyidx 0..3) and one individual key for
	 * both transmitting and receiving (keyidx 0) _unicast_ packets. Now,
	 * keyidx 0 is reserved for this unicast use and default keys can only
	 * use keyidx 1..3 (i.e., default key with keyidx 0 is not supported).
	 * This should be fine for more or less all cases, but for completeness
	 * sake, the driver could be enhanced to support the missing key. */
#if 0
	if (addr == NULL)
		os_memset(param->sta_addr, 0xff, ETH_ALEN);
	else
		os_memcpy(param->sta_addr, addr, ETH_ALEN);
#else
	os_memset(param->sta_addr, 0xff, ETH_ALEN);
#endif
	os_strlcpy((char *) param->u.crypt.alg, alg_name,
		   HOSTAP_CRYPT_ALG_NAME_LEN);
	param->u.crypt.flags = set_tx ? HOSTAP_CRYPT_FLAG_SET_TX_KEY : 0;
	param->u.crypt.idx = key_idx;
	os_memcpy(param->u.crypt.seq, seq, seq_len);
	param->u.crypt.key_len = key_len;
	os_memcpy((u8 *) (param + 1), key, key_len);

	if (hostapd_ioctl_prism54(drv, param, blen, 1)) {
		wpa_printf(MSG_WARNING, "Failed to set encryption.");
		show_set_key_error(param);
		ret = -1;
	}
	os_free(buf);

	return ret;
}


static int wpa_driver_prism54_set_countermeasures(void *priv,
						 int enabled)
{
	/* FIX */
	printf("wpa_driver_prism54_set_countermeasures - not yet "
	       "implemented\n");
	return 0;
}


static int wpa_driver_prism54_set_drop_unencrypted(void *priv,
						  int enabled)
{
	struct wpa_driver_prism54_data *drv = priv;
	struct prism2_hostapd_param *param;
	int res;
	size_t blen = PRISM2_HOSTAPD_GENERIC_ELEMENT_HDR_LEN;
	if (blen < sizeof(*param))
		blen = sizeof(*param);

	param = os_zalloc(blen);
	if (param == NULL)
		return -1;

	param->cmd = PRISM54_DROP_UNENCRYPTED;
	param->u.generic_elem.len = 0;
	res = hostapd_ioctl_prism54(drv, param, blen, 1);

	os_free(param);

	return res;
}


static int wpa_driver_prism54_deauthenticate(void *priv, const u8 *addr,
					     int reason_code)
{
	/* FIX */
	printf("wpa_driver_prism54_deauthenticate - not yet implemented\n");
	return 0;
}


static int wpa_driver_prism54_disassociate(void *priv, const u8 *addr,
					   int reason_code)
{
	/* FIX */
	printf("wpa_driver_prism54_disassociate - not yet implemented\n");
	return 0;
}


static int
wpa_driver_prism54_associate(void *priv,
			     struct wpa_driver_associate_params *params)
{
	struct wpa_driver_prism54_data *drv = priv;
	int ret = 0;

	if (wpa_driver_prism54_set_wpa_ie(drv, params->wpa_ie,
					  params->wpa_ie_len) < 0)
		ret = -1;
	if (wpa_driver_wext_set_freq(drv->wext, params->freq) < 0)
		ret = -1;
	if (wpa_driver_wext_set_ssid(drv->wext, params->ssid,
				     params->ssid_len) < 0)
		ret = -1;
	if (wpa_driver_wext_set_bssid(drv->wext, params->bssid) < 0)
		ret = -1;

	return ret;
}

static void show_set_key_error(struct prism2_hostapd_param *param)
{
	switch (param->u.crypt.err) {
	case HOSTAP_CRYPT_ERR_UNKNOWN_ALG:
		wpa_printf(MSG_INFO, "Unknown algorithm '%s'.",
			   param->u.crypt.alg);
		wpa_printf(MSG_INFO, "You may need to load kernel module to "
			   "register that algorithm.");
		wpa_printf(MSG_INFO, "E.g., 'modprobe hostap_crypt_wep' for "
			   "WEP.");
		break;
	case HOSTAP_CRYPT_ERR_UNKNOWN_ADDR:
		wpa_printf(MSG_INFO, "Unknown address " MACSTR ".",
			   MAC2STR(param->sta_addr));
		break;
	case HOSTAP_CRYPT_ERR_CRYPT_INIT_FAILED:
		wpa_printf(MSG_INFO, "Crypt algorithm initialization failed.");
		break;
	case HOSTAP_CRYPT_ERR_KEY_SET_FAILED:
		wpa_printf(MSG_INFO, "Key setting failed.");
		break;
	case HOSTAP_CRYPT_ERR_TX_KEY_SET_FAILED:
		wpa_printf(MSG_INFO, "TX key index setting failed.");
		break;
	case HOSTAP_CRYPT_ERR_CARD_CONF_FAILED:
		wpa_printf(MSG_INFO, "Card configuration failed.");
		break;
	}
}


static int wpa_driver_prism54_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_prism54_data *drv = priv;
	return wpa_driver_wext_get_bssid(drv->wext, bssid);
}


static int wpa_driver_prism54_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_prism54_data *drv = priv;
	return wpa_driver_wext_get_ssid(drv->wext, ssid);
}


static int wpa_driver_prism54_scan(void *priv, const u8 *ssid, size_t ssid_len)
{
	struct wpa_driver_prism54_data *drv = priv;
	return wpa_driver_wext_scan(drv->wext, ssid, ssid_len);
}


static struct wpa_scan_results *
wpa_driver_prism54_get_scan_results(void *priv)
{
	struct wpa_driver_prism54_data *drv = priv;
	return wpa_driver_wext_get_scan_results(drv->wext);
}


static int wpa_driver_prism54_set_operstate(void *priv, int state)
{
	struct wpa_driver_prism54_data *drv = priv;
	return wpa_driver_wext_set_operstate(drv->wext, state);
}


static void * wpa_driver_prism54_init(void *ctx, const char *ifname)
{
	struct wpa_driver_prism54_data *drv;

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	drv->wext = wpa_driver_wext_init(ctx, ifname);
	if (drv->wext == NULL) {
		os_free(drv);
		return NULL;
	}

	drv->ctx = ctx;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
	drv->sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->sock < 0) {
		wpa_driver_wext_deinit(drv->wext);
		os_free(drv);
		return NULL;
	}

	return drv;
}


static void wpa_driver_prism54_deinit(void *priv)
{
	struct wpa_driver_prism54_data *drv = priv;
	wpa_driver_wext_deinit(drv->wext);
	close(drv->sock);
	os_free(drv);
}

#endif /* HOSTAPD */


const struct wpa_driver_ops wpa_driver_prism54_ops = {
	.name = "prism54",
	.desc = "Prism54.org driver (Intersil Prism GT/Duette/Indigo)",
#ifdef HOSTAPD
	.hapd_init = prism54_driver_init,
	.hapd_deinit = prism54_driver_deinit,
	/* .set_ieee8021x = prism54_init_1x, */
	.set_privacy = prism54_set_privacy_invoked,
	.hapd_set_key = prism54_set_key,
	.get_seqnum = prism54_get_seqnum,
	.flush = prism54_flush,
	.set_generic_elem = prism54_set_generic_elem,
	.hapd_send_eapol = prism54_send_eapol,
	.sta_set_flags = prism54_sta_set_flags,
	.sta_deauth = prism54_sta_deauth,
	.sta_disassoc = prism54_sta_disassoc,
	.hapd_set_ssid = prism54_ioctl_setiwessid,
	.get_inact_sec = prism54_get_inact_sec,
#else /* HOSTAPD */
	.get_bssid = wpa_driver_prism54_get_bssid,
	.get_ssid = wpa_driver_prism54_get_ssid,
	.set_wpa = wpa_driver_prism54_set_wpa,
	.set_key = wpa_driver_prism54_set_key,
	.set_countermeasures = wpa_driver_prism54_set_countermeasures,
	.set_drop_unencrypted = wpa_driver_prism54_set_drop_unencrypted,
	.scan = wpa_driver_prism54_scan,
	.get_scan_results2 = wpa_driver_prism54_get_scan_results,
	.deauthenticate = wpa_driver_prism54_deauthenticate,
	.disassociate = wpa_driver_prism54_disassociate,
	.associate = wpa_driver_prism54_associate,
	.init = wpa_driver_prism54_init,
	.deinit = wpa_driver_prism54_deinit,
	.set_operstate = wpa_driver_prism54_set_operstate,
#endif /* HOSTAPD */
};
