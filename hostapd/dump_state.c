/*
 * hostapd / State dump
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <time.h>

#include "utils/common.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "eapol_auth/eapol_auth_sm_i.h"
#include "eap_server/eap.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"
#include "ap/sta_info.h"
#include "dump_state.h"
#include "ap/ap_drv_ops.h"


static void ieee802_1x_dump_state(FILE *f, struct sta_info *sta)
{
	struct eapol_state_machine *sm = sta->eapol_sm;
	char buf[4096];
	int res;

	if (sm == NULL)
		return;
	res = eapol_auth_dump_state(sm, buf, sizeof(buf));
	if (res > 0)
		fprintf(f, "%s", buf);
}


/**
 * hostapd_dump_state - SIGUSR1 handler to dump hostapd state to a text file
 */
static void hostapd_dump_state(struct hostapd_data *hapd)
{
	FILE *f;
	time_t now;
	struct sta_info *sta;

	if (!hapd->conf->dump_log_name) {
		wpa_printf(MSG_DEBUG, "Dump file not defined - ignoring dump "
			   "request");
		return;
	}

	wpa_printf(MSG_DEBUG, "Dumping hostapd state to '%s'",
		   hapd->conf->dump_log_name);
	f = fopen(hapd->conf->dump_log_name, "w");
	if (f == NULL) {
		wpa_printf(MSG_WARNING, "Could not open dump file '%s' for "
			   "writing.", hapd->conf->dump_log_name);
		return;
	}

	time(&now);
	fprintf(f, "hostapd state dump - %s", ctime(&now));

	for (sta = hapd->sta_list; sta != NULL; sta = sta->next) {
		fprintf(f, "\nSTA=" MACSTR "\n", MAC2STR(sta->addr));
		ieee802_1x_dump_state(f, sta);
	}

	fclose(f);
}


int handle_dump_state_iface(struct hostapd_iface *iface, void *ctx)
{
	size_t i;

	for (i = 0; i < iface->num_bss; i++)
		hostapd_dump_state(iface->bss[i]);

	return 0;
}
