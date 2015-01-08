/*
 * Common hostapd/wpa_supplicant HW features
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2015, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "defs.h"
#include "hw_features_common.h"


struct hostapd_channel_data * hw_get_channel_chan(struct hostapd_hw_modes *mode,
						  int chan, int *freq)
{
	int i;

	if (freq)
		*freq = 0;

	if (!mode)
		return NULL;

	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *ch = &mode->channels[i];
		if (ch->chan == chan) {
			if (freq)
				*freq = ch->freq;
			return ch;
		}
	}

	return NULL;
}


struct hostapd_channel_data * hw_get_channel_freq(struct hostapd_hw_modes *mode,
						  int freq, int *chan)
{
	int i;

	if (chan)
		*chan = 0;

	if (!mode)
		return NULL;

	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *ch = &mode->channels[i];
		if (ch->freq == freq) {
			if (chan)
				*chan = ch->chan;
			return ch;
		}
	}

	return NULL;
}


int hw_get_freq(struct hostapd_hw_modes *mode, int chan)
{
	int freq;

	hw_get_channel_chan(mode, chan, &freq);

	return freq;
}


int hw_get_chan(struct hostapd_hw_modes *mode, int freq)
{
	int chan;

	hw_get_channel_freq(mode, freq, &chan);

	return chan;
}


int allowed_ht40_channel_pair(struct hostapd_hw_modes *mode, int pri_chan,
			      int sec_chan)
{
	int ok, j, first;
	int allowed[] = { 36, 44, 52, 60, 100, 108, 116, 124, 132, 149, 157,
			  184, 192 };
	size_t k;

	if (pri_chan == sec_chan || !sec_chan)
		return 1; /* HT40 not used */

	wpa_printf(MSG_DEBUG,
		   "HT40: control channel: %d  secondary channel: %d",
		   pri_chan, sec_chan);

	/* Verify that HT40 secondary channel is an allowed 20 MHz
	 * channel */
	ok = 0;
	for (j = 0; j < mode->num_channels; j++) {
		struct hostapd_channel_data *chan = &mode->channels[j];
		if (!(chan->flag & HOSTAPD_CHAN_DISABLED) &&
		    chan->chan == sec_chan) {
			ok = 1;
			break;
		}
	}
	if (!ok) {
		wpa_printf(MSG_ERROR, "HT40 secondary channel %d not allowed",
			   sec_chan);
		return 0;
	}

	/*
	 * Verify that HT40 primary,secondary channel pair is allowed per
	 * IEEE 802.11n Annex J. This is only needed for 5 GHz band since
	 * 2.4 GHz rules allow all cases where the secondary channel fits into
	 * the list of allowed channels (already checked above).
	 */
	if (mode->mode != HOSTAPD_MODE_IEEE80211A)
		return 1;

	first = pri_chan < sec_chan ? pri_chan : sec_chan;

	ok = 0;
	for (k = 0; k < ARRAY_SIZE(allowed); k++) {
		if (first == allowed[k]) {
			ok = 1;
			break;
		}
	}
	if (!ok) {
		wpa_printf(MSG_ERROR, "HT40 channel pair (%d, %d) not allowed",
			   pri_chan, sec_chan);
		return 0;
	}

	return 1;
}
