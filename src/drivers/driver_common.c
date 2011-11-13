/*
 * Common driver-related functions
 * Copyright (c) 2003-2011, Jouni Malinen <j@w1.fi>
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
#include "utils/common.h"
#include "driver.h"

void wpa_scan_results_free(struct wpa_scan_results *res)
{
	size_t i;

	if (res == NULL)
		return;

	for (i = 0; i < res->num; i++)
		os_free(res->res[i]);
	os_free(res->res);
	os_free(res);
}


const char * event_to_string(enum wpa_event_type event)
{
	switch (event) {
	case EVENT_ASSOC: return "ASSOC";
	case EVENT_DISASSOC: return "DISASSOC";
	case EVENT_MICHAEL_MIC_FAILURE: return "MICHAEL_MIC_FAILURE";
	case EVENT_SCAN_RESULTS: return "SCAN_RESULTS";
	case EVENT_ASSOCINFO: return "ASSOCINFO";
	case EVENT_INTERFACE_STATUS: return "INTERFACE_STATUS";
	case EVENT_PMKID_CANDIDATE: return "PMKID_CANDIDATE";
	case EVENT_STKSTART: return "STKSTART";
	case EVENT_TDLS: return "TDLS";
	case EVENT_FT_RESPONSE: return "FT_RESPONSE";
	case EVENT_IBSS_RSN_START: return "IBSS_RSN_START";
	case EVENT_AUTH: return "AUTH";
	case EVENT_DEAUTH: return "DEAUTH";
	case EVENT_ASSOC_REJECT: return "ASSOC_REJECT";
	case EVENT_AUTH_TIMED_OUT: return "AUTH_TIMED_OUT";
	case EVENT_ASSOC_TIMED_OUT: return "ASSOC_TIMED_OUT";
	case EVENT_FT_RRB_RX: return "FT_RRB_RX";
	case EVENT_WPS_BUTTON_PUSHED: return "WPS_BUTTON_PUSHED";
	case EVENT_TX_STATUS: return "TX_STATUS";
	case EVENT_RX_FROM_UNKNOWN: return "RX_FROM_UNKNOWN";
	case EVENT_RX_MGMT: return "RX_MGMT";
	case EVENT_RX_ACTION: return "RX_ACTION";
	case EVENT_REMAIN_ON_CHANNEL: return "REMAIN_ON_CHANNEL";
	case EVENT_CANCEL_REMAIN_ON_CHANNEL: return "CANCEL_ROC";
	case EVENT_MLME_RX: return "MLME_RX";
	case EVENT_RX_PROBE_REQ: return "RX_PROBE_REQ";
	case EVENT_NEW_STA: return "NEW_STA";
	case EVENT_EAPOL_RX: return "EAPOL_RX";
	case EVENT_SIGNAL_CHANGE: return "SIGNAL_CHANGE";
	case EVENT_INTERFACE_ENABLED: return "IFACE_ENABLED";
	case EVENT_INTERFACE_DISABLED: return "IFACE_DISABLED";
	case EVENT_CHANNEL_LIST_CHANGED: return "CHANNEL_LIST_CHANGED";
	case EVENT_INTERFACE_UNAVAILABLE: return "INTERFACE_UNAVAILABLE";
	case EVENT_BEST_CHANNEL: return "BEST_CHANNEL";
	case EVENT_UNPROT_DEAUTH: return "UNPROT_DEAUTH";
	case EVENT_UNPROT_DISASSOC: return "UNPROT_DISASSOC";
	case EVENT_STATION_LOW_ACK: return "STA_LOW_ACK";
	case EVENT_P2P_DEV_FOUND: return "P2P_DEV_FOUND";
	case EVENT_P2P_GO_NEG_REQ_RX: return "P2P_GO_NEG_REQ_RX";
	case EVENT_P2P_GO_NEG_COMPLETED: return "P2P_GO_NEG_COMPLETED";
	case EVENT_P2P_PROV_DISC_REQUEST: return "P2P_PROV_DISC_REQUEST";
	case EVENT_P2P_PROV_DISC_RESPONSE: return "P2P_PROV_DISC_RESPONSE";
	case EVENT_P2P_SD_REQUEST: return "P2P_SD_REQUEST";
	case EVENT_P2P_SD_RESPONSE: return "P2P_SD_RESPONSE";
	case EVENT_IBSS_PEER_LOST: return "IBSS_PEER_LOST";
	case EVENT_DRIVER_GTK_REKEY: return "DRIVER_GTK_REKEY";
	case EVENT_SCHED_SCAN_STOPPED: return "SCHED_SCAN_STOPPED";
	case EVENT_DRIVER_CLIENT_POLL_OK: return "CLIENT_POLL_OK";
	}

	return "UNKNOWN";
}
