/*
 * wpa_supplicant - DPP
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DPP_SUPPLICANT_H
#define DPP_SUPPLICANT_H

int wpas_dpp_qr_code(struct wpa_supplicant *wpa_s, const char *cmd);
int wpas_dpp_bootstrap_gen(struct wpa_supplicant *wpa_s, const char *cmd);
int wpas_dpp_bootstrap_remove(struct wpa_supplicant *wpa_s, const char *id);
const char * wpas_dpp_bootstrap_get_uri(struct wpa_supplicant *wpa_s,
					unsigned int id);
int wpas_dpp_init(struct wpa_supplicant *wpa_s);
void wpas_dpp_deinit(struct wpa_supplicant *wpa_s);

#endif /* DPP_SUPPLICANT_H */
