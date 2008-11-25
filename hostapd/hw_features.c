/*
 * hostapd / Hardware feature query and different modes
 * Copyright 2002-2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2008, Jouni Malinen <j@w1.fi>
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

#include "hostapd.h"
#include "hw_features.h"
#include "driver.h"
#include "config.h"


void hostapd_free_hw_features(struct hostapd_hw_modes *hw_features,
			      size_t num_hw_features)
{
	size_t i;

	if (hw_features == NULL)
		return;

	for (i = 0; i < num_hw_features; i++) {
		os_free(hw_features[i].channels);
		os_free(hw_features[i].rates);
	}

	os_free(hw_features);
}


int hostapd_get_hw_features(struct hostapd_iface *iface)
{
	struct hostapd_data *hapd = iface->bss[0];
	int ret = 0, i, j;
	u16 num_modes, flags;
	struct hostapd_hw_modes *modes;

	if (hostapd_drv_none(hapd))
		return -1;
	modes = hostapd_get_hw_feature_data(hapd, &num_modes, &flags);
	if (modes == NULL) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "Fetching hardware channel/rate support not "
			       "supported.");
		return -1;
	}

	iface->hw_flags = flags;

	hostapd_free_hw_features(iface->hw_features, iface->num_hw_features);
	iface->hw_features = modes;
	iface->num_hw_features = num_modes;

	for (i = 0; i < num_modes; i++) {
		struct hostapd_hw_modes *feature = &modes[i];
		/* set flag for channels we can use in current regulatory
		 * domain */
		for (j = 0; j < feature->num_channels; j++) {
			/*
			 * Disable all channels that are marked not to allow
			 * IBSS operation or active scanning. In addition,
			 * disable all channels that require radar detection,
			 * since that (in addition to full DFS) is not yet
			 * supported.
			 */
			if (feature->channels[j].flag &
			    (HOSTAPD_CHAN_NO_IBSS |
			     HOSTAPD_CHAN_PASSIVE_SCAN |
			     HOSTAPD_CHAN_RADAR))
				feature->channels[j].flag |=
					HOSTAPD_CHAN_DISABLED;
			if (feature->channels[j].flag & HOSTAPD_CHAN_DISABLED)
				continue;
			wpa_printf(MSG_MSGDUMP, "Allowed channel: mode=%d "
				   "chan=%d freq=%d MHz max_tx_power=%d dBm",
				   feature->mode,
				   feature->channels[j].chan,
				   feature->channels[j].freq,
				   feature->channels[j].max_tx_power);
		}
	}

	return ret;
}


static int hostapd_prepare_rates(struct hostapd_data *hapd,
				 struct hostapd_hw_modes *mode)
{
	int i, num_basic_rates = 0;
	int basic_rates_a[] = { 60, 120, 240, -1 };
	int basic_rates_b[] = { 10, 20, -1 };
	int basic_rates_g[] = { 10, 20, 55, 110, -1 };
	int *basic_rates;

	if (hapd->iconf->basic_rates)
		basic_rates = hapd->iconf->basic_rates;
	else switch (mode->mode) {
	case HOSTAPD_MODE_IEEE80211A:
		basic_rates = basic_rates_a;
		break;
	case HOSTAPD_MODE_IEEE80211B:
		basic_rates = basic_rates_b;
		break;
	case HOSTAPD_MODE_IEEE80211G:
		basic_rates = basic_rates_g;
		break;
	default:
		return -1;
	}

	if (hostapd_set_rate_sets(hapd, hapd->iconf->supported_rates,
				  basic_rates, mode->mode)) {
		wpa_printf(MSG_ERROR, "Failed to update rate sets in kernel "
			   "module");
	}

	os_free(hapd->iface->current_rates);
	hapd->iface->num_rates = 0;

	hapd->iface->current_rates =
		os_malloc(mode->num_rates * sizeof(struct hostapd_rate_data));
	if (!hapd->iface->current_rates) {
		wpa_printf(MSG_ERROR, "Failed to allocate memory for rate "
			   "table.");
		return -1;
	}

	for (i = 0; i < mode->num_rates; i++) {
		struct hostapd_rate_data *rate;

		if (hapd->iconf->supported_rates &&
		    !hostapd_rate_found(hapd->iconf->supported_rates,
					mode->rates[i].rate))
			continue;

		rate = &hapd->iface->current_rates[hapd->iface->num_rates];
		os_memcpy(rate, &mode->rates[i],
			  sizeof(struct hostapd_rate_data));
		if (hostapd_rate_found(basic_rates, rate->rate)) {
			rate->flags |= HOSTAPD_RATE_BASIC;
			num_basic_rates++;
		} else
			rate->flags &= ~HOSTAPD_RATE_BASIC;
		wpa_printf(MSG_DEBUG, "RATE[%d] rate=%d flags=0x%x",
			   hapd->iface->num_rates, rate->rate, rate->flags);
		hapd->iface->num_rates++;
	}

	if (hapd->iface->num_rates == 0 || num_basic_rates == 0) {
		wpa_printf(MSG_ERROR, "No rates remaining in supported/basic "
			   "rate sets (%d,%d).",
			   hapd->iface->num_rates, num_basic_rates);
		return -1;
	}

	return 0;
}


/**
 * hostapd_select_hw_mode - Select the hardware mode
 * @iface: Pointer to interface data.
 * Returns: 0 on success, -1 on failure
 *
 * Sets up the hardware mode, channel, rates, and passive scanning
 * based on the configuration.
 */
int hostapd_select_hw_mode(struct hostapd_iface *iface)
{
	int i, j, ok, ret;

	if (iface->num_hw_features < 1)
		return -1;

	iface->current_mode = NULL;
	for (i = 0; i < iface->num_hw_features; i++) {
		struct hostapd_hw_modes *mode = &iface->hw_features[i];
		if (mode->mode == (int) iface->conf->hw_mode) {
			iface->current_mode = mode;
			break;
		}
	}

	if (iface->current_mode == NULL) {
		wpa_printf(MSG_ERROR, "Hardware does not support configured "
			   "mode");
		hostapd_logger(iface->bss[0], NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_WARNING,
			       "Hardware does not support configured mode "
			       "(%d)", (int) iface->conf->hw_mode);
		return -1;
	}

	ok = 0;
	for (j = 0; j < iface->current_mode->num_channels; j++) {
		struct hostapd_channel_data *chan =
			&iface->current_mode->channels[j];
		if (!(chan->flag & HOSTAPD_CHAN_DISABLED) &&
		    (chan->chan == iface->conf->channel)) {
			ok = 1;
			break;
		}
	}
	if (ok == 0 && iface->conf->channel != 0) {
		hostapd_logger(iface->bss[0], NULL,
			       HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_WARNING,
			       "Configured channel (%d) not found from the "
			       "channel list of current mode (%d) %s",
			       iface->conf->channel,
			       iface->current_mode->mode,
			       hostapd_hw_mode_txt(iface->current_mode->mode));
		iface->current_mode = NULL;
	}

	if (iface->current_mode == NULL) {
		hostapd_logger(iface->bss[0], NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_WARNING,
			       "Hardware does not support configured channel");
		return -1;
	}

	if (hostapd_prepare_rates(iface->bss[0], iface->current_mode)) {
		wpa_printf(MSG_ERROR, "Failed to prepare rates table.");
		hostapd_logger(iface->bss[0], NULL, HOSTAPD_MODULE_IEEE80211,
					   HOSTAPD_LEVEL_WARNING,
					   "Failed to prepare rates table.");
		return -1;
	}

	ret = hostapd_passive_scan(iface->bss[0], 0,
				   iface->conf->passive_scan_mode,
				   iface->conf->passive_scan_interval,
				   iface->conf->passive_scan_listen,
				   NULL, NULL);
	if (ret) {
		if (ret == -1) {
			wpa_printf(MSG_DEBUG, "Passive scanning not "
				   "supported");
		} else {
			wpa_printf(MSG_ERROR, "Could not set passive "
				   "scanning: %s", strerror(ret));
		}
		ret = 0;
	}

	return ret;
}


const char * hostapd_hw_mode_txt(int mode)
{
	switch (mode) {
	case HOSTAPD_MODE_IEEE80211A:
		return "IEEE 802.11a";
	case HOSTAPD_MODE_IEEE80211B:
		return "IEEE 802.11b";
	case HOSTAPD_MODE_IEEE80211G:
		return "IEEE 802.11g";
	default:
		return "UNKNOWN";
	}
}


int hostapd_hw_get_freq(struct hostapd_data *hapd, int chan)
{
	int i;

	if (!hapd->iface->current_mode)
		return 0;

	for (i = 0; i < hapd->iface->current_mode->num_channels; i++) {
		struct hostapd_channel_data *ch =
			&hapd->iface->current_mode->channels[i];
		if (ch->chan == chan)
			return ch->freq;
	}

	return 0;
}


int hostapd_hw_get_channel(struct hostapd_data *hapd, int freq)
{
	int i;

	if (!hapd->iface->current_mode)
		return 0;

	for (i = 0; i < hapd->iface->current_mode->num_channels; i++) {
		struct hostapd_channel_data *ch =
			&hapd->iface->current_mode->channels[i];
		if (ch->freq == freq)
			return ch->chan;
	}

	return 0;
}
