/*
 * Common hostapd/wpa_supplicant HW features
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2015, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HW_FEATURES_COMMON_H
#define HW_FEATURES_COMMON_H

#include "drivers/driver.h"

struct hostapd_channel_data * hw_get_channel_chan(struct hostapd_hw_modes *mode,
						  int chan, int *freq);
struct hostapd_channel_data * hw_get_channel_freq(struct hostapd_hw_modes *mode,
						  int freq, int *chan);

int hw_get_freq(struct hostapd_hw_modes *mode, int chan);
int hw_get_chan(struct hostapd_hw_modes *mode, int freq);

int allowed_ht40_channel_pair(struct hostapd_hw_modes *mode, int pri_chan,
			      int sec_chan);
void get_pri_sec_chan(struct wpa_scan_res *bss, int *pri_chan, int *sec_chan);

#endif /* HW_FEATURES_COMMON_H */
