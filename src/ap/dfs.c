/*
 * DFS - Dynamic Frequency Selection
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "hostapd.h"
#include "hw_features.h"
#include "ap_drv_ops.h"
#include "drivers/driver.h"
#include "dfs.h"


static int hostapd_dfs_find_channel(struct hostapd_data *hapd,
				    struct hostapd_channel_data **ret_chan,
				    int idx)
{
	struct hostapd_hw_modes *mode;
	struct hostapd_channel_data *chan;
	int i, channel_idx = 0;

	mode = hapd->iface->current_mode;

	for (i = 0; i < mode->num_channels; i++) {
		chan = &mode->channels[i];

		if (chan->flag & HOSTAPD_CHAN_DISABLED)
			continue;

		if (chan->flag & HOSTAPD_CHAN_RADAR &&
		    chan->flag & HOSTAPD_CHAN_DFS_UNAVAILABLE)
			continue;

		if (ret_chan && idx == channel_idx) {
			wpa_printf(MSG_DEBUG, "Selected ch. #%d", chan->chan);
			*ret_chan = chan;
			return idx;
		}
		channel_idx++;
	}
	return channel_idx;
}


struct hostapd_channel_data * hostapd_dfs_get_valid_channel(
	struct hostapd_data *hapd)
{
	struct hostapd_hw_modes *mode;
	struct hostapd_channel_data *chan = NULL;
	int channel_idx, new_channel_idx;
	u32 _rand;

	wpa_printf(MSG_DEBUG, "DFS: Selecting random channel");

	if (hapd->iface->current_mode == NULL)
		return NULL;

	mode = hapd->iface->current_mode;
	if (mode->mode != HOSTAPD_MODE_IEEE80211A)
		return NULL;

	/* get random available channel */
	channel_idx = hostapd_dfs_find_channel(hapd, NULL, 0);
	if (channel_idx > 0) {
		os_get_random((u8 *) &_rand, sizeof(_rand));
		new_channel_idx = _rand % channel_idx;
		hostapd_dfs_find_channel(hapd, &chan, new_channel_idx);
	}

	return chan;
}


int ieee802_11_set_dfs_state(struct hostapd_data *hapd, int freq, u32 state)
{
	struct hostapd_hw_modes *mode;
	struct hostapd_channel_data *chan = NULL;
	int i;

	mode = hapd->iface->current_mode;
	if (mode == NULL)
		return 0;

	if (mode->mode != HOSTAPD_MODE_IEEE80211A) {
		wpa_printf(MSG_WARNING, "current_mode != IEEE80211A");
		return 0;
	}

	for (i = 0; i < hapd->iface->current_mode->num_channels; i++) {
		chan = &hapd->iface->current_mode->channels[i];
		if (chan->freq == freq) {
			if (chan->flag & HOSTAPD_CHAN_RADAR) {
				chan->flag &= ~HOSTAPD_CHAN_DFS_MASK;
				chan->flag |= state;
				return 1; /* Channel found */
			}
		}
	}
	wpa_printf(MSG_WARNING, "Can't set DFS state for freq %d MHz", freq);
	return 0;
}


/*
 * Main DFS handler
 * 1 - continue channel/ap setup
 * 0 - channel/ap setup will be continued after CAC
 * -1 - hit critical error
 */
int hostapd_handle_dfs(struct hostapd_data *hapd)
{
	int flags;
	struct hostapd_channel_data *channel;

	/* Handle DFS channel */
check_dfs_chan_again:
	flags = hostapd_hw_get_channel_flag(hapd, hapd->iconf->channel);
	if (flags & HOSTAPD_CHAN_RADAR) {
		switch (flags & HOSTAPD_CHAN_DFS_MASK) {
		case HOSTAPD_CHAN_DFS_USABLE:
			wpa_printf(MSG_DEBUG, "DFS start CAC on %d MHz",
				   hapd->iface->freq);
			if (hostapd_start_dfs_cac(hapd,
						  hapd->iface->freq,
						  flags)) {
				wpa_printf(MSG_DEBUG, "DFS start_dfs_cac() failed");
				return -1;
			}
			/* Continue initialisation after CAC */
			return 0;
		case HOSTAPD_CHAN_DFS_UNAVAILABLE:
			wpa_printf(MSG_DEBUG, "HOSTAPD_CHAN_DFS_UNAVAILABLE, get new chan");
			/* find other channel here */
			channel = hostapd_dfs_get_valid_channel(hapd);
			if (!channel) {
				wpa_printf(MSG_ERROR, "could not get valid channel");
				return -1;
			}
			hapd->iconf->channel = channel->chan;
			hapd->iface->freq = channel->freq;
			goto check_dfs_chan_again;
		case HOSTAPD_CHAN_DFS_AVAILABLE:
			/* We don't need CAC here */
			wpa_printf(MSG_DEBUG, "HOSTAPD_CHAN_DFS_AVAILABLE, skip CAC");
			break;
		default:
			break;
		}
	}

	return 1;
}


int ieee802_11_complete_cac(struct hostapd_data *hapd, int success, int freq)
{
	struct hostapd_channel_data *channel;
	int err = 1;

	if (success) {
		/* Complete iface/ap configuration */
		ieee802_11_set_dfs_state(hapd, freq,
					 HOSTAPD_CHAN_DFS_AVAILABLE);
		hostapd_setup_interface_complete(hapd->iface, 0);
	} else {
		/* Switch to new channel */
		ieee802_11_set_dfs_state(hapd, freq,
					 HOSTAPD_CHAN_DFS_UNAVAILABLE);
		channel = hostapd_dfs_get_valid_channel(hapd);
		if (channel) {
			hapd->iconf->channel = channel->chan;
			hapd->iface->freq = channel->freq;
			err = 0;
		} else
			wpa_printf(MSG_ERROR, "No valid channel available");

		hostapd_setup_interface_complete(hapd->iface, err);
	}

	return 0;
}


int ieee802_11_start_channel_switch(struct hostapd_data *hapd)
{
	struct hostapd_channel_data *channel;
	int err = 1;

	wpa_printf(MSG_DEBUG, "%s called", __func__);
	channel = hostapd_dfs_get_valid_channel(hapd);
	if (channel) {
		hapd->iconf->channel = channel->chan;
		hapd->iface->freq = channel->freq;
		err = 0;
	}

	hapd->driver->stop_ap(hapd->drv_priv);

	hostapd_setup_interface_complete(hapd->iface, err);
	return 0;
}
