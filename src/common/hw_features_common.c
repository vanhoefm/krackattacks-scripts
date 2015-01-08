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
