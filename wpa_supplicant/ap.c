/*
 * WPA Supplicant - Basic AP mode support routines
 * Copyright (c) 2003-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2009, Atheros Communications
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
#include "../hostapd/hostapd.h"
#include "eap_common/eap_defs.h"
#include "eap_server/eap_methods.h"
#include "eap_common/eap_wsc_common.h"


int hostapd_reload_config(struct hostapd_iface *iface)
{
	/* TODO */
	return -1;
}


int hostapd_maclist_found(struct mac_acl_entry *list, int num_entries,
			  const u8 *addr, int *vlan_id)
{
	int start, end, middle, res;

	start = 0;
	end = num_entries - 1;

	while (start <= end) {
		middle = (start + end) / 2;
		res = os_memcmp(list[middle].addr, addr, ETH_ALEN);
		if (res == 0) {
			if (vlan_id)
				*vlan_id = list[middle].vlan_id;
			return 1;
		}
		if (res < 0)
			start = middle + 1;
		else
			end = middle - 1;
	}

	return 0;
}


int hostapd_rate_found(int *list, int rate)
{
	int i;

	if (list == NULL)
		return 0;

	for (i = 0; list[i] >= 0; i++)
		if (list[i] == rate)
			return 1;

	return 0;
}


const char * hostapd_get_vlan_id_ifname(struct hostapd_vlan *vlan, int vlan_id)
{
	return NULL;
}


int hostapd_for_each_interface(int (*cb)(struct hostapd_iface *iface,
					 void *ctx), void *ctx)
{
	/* TODO */
	return 0;
}


const struct hostapd_eap_user *
hostapd_get_eap_user(const struct hostapd_bss_config *conf, const u8 *identity,
		     size_t identity_len, int phase2)
{
	struct hostapd_eap_user *user = conf->eap_user;

#ifdef CONFIG_WPS
	if (conf->wps_state && identity_len == WSC_ID_ENROLLEE_LEN &&
	    os_memcmp(identity, WSC_ID_ENROLLEE, WSC_ID_ENROLLEE_LEN) == 0) {
		static struct hostapd_eap_user wsc_enrollee;
		os_memset(&wsc_enrollee, 0, sizeof(wsc_enrollee));
		wsc_enrollee.methods[0].method = eap_server_get_type(
			"WSC", &wsc_enrollee.methods[0].vendor);
		return &wsc_enrollee;
	}

	if (conf->wps_state && conf->ap_pin &&
	    identity_len == WSC_ID_REGISTRAR_LEN &&
	    os_memcmp(identity, WSC_ID_REGISTRAR, WSC_ID_REGISTRAR_LEN) == 0) {
		static struct hostapd_eap_user wsc_registrar;
		os_memset(&wsc_registrar, 0, sizeof(wsc_registrar));
		wsc_registrar.methods[0].method = eap_server_get_type(
			"WSC", &wsc_registrar.methods[0].vendor);
		wsc_registrar.password = (u8 *) conf->ap_pin;
		wsc_registrar.password_len = os_strlen(conf->ap_pin);
		return &wsc_registrar;
	}
#endif /* CONFIG_WPS */

	while (user) {
		if (!phase2 && user->identity == NULL) {
			/* Wildcard match */
			break;
		}

		if (user->phase2 == !!phase2 && user->wildcard_prefix &&
		    identity_len >= user->identity_len &&
		    os_memcmp(user->identity, identity, user->identity_len) ==
		    0) {
			/* Wildcard prefix match */
			break;
		}

		if (user->phase2 == !!phase2 &&
		    user->identity_len == identity_len &&
		    os_memcmp(user->identity, identity, identity_len) == 0)
			break;
		user = user->next;
	}

	return user;
}
