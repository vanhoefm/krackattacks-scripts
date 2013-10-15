/*
 * DFS - Dynamic Frequency Selection
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef DFS_H
#define DFS_H

struct hostapd_channel_data * hostapd_dfs_get_valid_channel(
	struct hostapd_data *hapd);
int ieee802_11_complete_cac(struct hostapd_data *hapd, int success, int freq);
int ieee802_11_set_dfs_state(struct hostapd_data *hapd, int freq, u32 state);
int ieee802_11_start_channel_switch(struct hostapd_data *hapd);
int hostapd_handle_dfs(struct hostapd_data *hapd);

#endif /* DFS_H */
