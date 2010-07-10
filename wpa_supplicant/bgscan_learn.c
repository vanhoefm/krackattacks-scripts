/*
 * WPA Supplicant - background scan and roaming module: learn
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
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
#include "eloop.h"
#include "drivers/driver.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "bgscan.h"

struct bgscan_learn_data {
	struct wpa_supplicant *wpa_s;
	const struct wpa_ssid *ssid;
	int scan_interval;
	int signal_threshold;
	int short_interval; /* use if signal < threshold */
	int long_interval; /* use if signal > threshold */
	struct os_time last_bgscan;
	char *fname;
};


static int bgscan_learn_load(struct bgscan_learn_data *data)
{
	FILE *f;
	char buf[128];

	if (data->fname == NULL)
		return 0;

	f = fopen(data->fname, "r");
	if (f == NULL)
		return 0;

	wpa_printf(MSG_DEBUG, "bgscan learn: Loading data from %s",
		   data->fname);

	if (fgets(buf, sizeof(buf), f) == NULL ||
	    os_strncmp(buf, "wpa_supplicant-bgscan-learn\n", 28) != 0) {
		wpa_printf(MSG_INFO, "bgscan learn: Invalid data file %s",
			   data->fname);
		fclose(f);
		return -1;
	}

	fclose(f);
	return 0;
}


static void bgscan_learn_save(struct bgscan_learn_data *data)
{
	FILE *f;

	if (data->fname == NULL)
		return;

	wpa_printf(MSG_DEBUG, "bgscan learn: Saving data to %s",
		   data->fname);

	f = fopen(data->fname, "w");
	if (f == NULL)
		return;
	fprintf(f, "wpa_supplicant-bgscan-learn\n");

	fclose(f);
}


static void bgscan_learn_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_learn_data *data = eloop_ctx;
	struct wpa_supplicant *wpa_s = data->wpa_s;
	struct wpa_driver_scan_params params;

	os_memset(&params, 0, sizeof(params));
	params.num_ssids = 1;
	params.ssids[0].ssid = data->ssid->ssid;
	params.ssids[0].ssid_len = data->ssid->ssid_len;
	params.freqs = data->ssid->scan_freq;

	/*
	 * A more advanced bgscan module would learn about most like channels
	 * over time and request scans only for some channels (probing others
	 * every now and then) to reduce effect on the data connection.
	 */

	wpa_printf(MSG_DEBUG, "bgscan learn: Request a background scan");
	if (wpa_supplicant_trigger_scan(wpa_s, &params)) {
		wpa_printf(MSG_DEBUG, "bgscan learn: Failed to trigger scan");
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_learn_timeout, data, NULL);
	} else
		os_get_time(&data->last_bgscan);
}


static int bgscan_learn_get_params(struct bgscan_learn_data *data,
				   const char *params)
{
	const char *pos;

	if (params == NULL)
		return 0;

	data->short_interval = atoi(params);

	pos = os_strchr(params, ':');
	if (pos == NULL)
		return 0;
	pos++;
	data->signal_threshold = atoi(pos);
	pos = os_strchr(pos, ':');
	if (pos == NULL) {
		wpa_printf(MSG_ERROR, "bgscan learn: Missing scan interval "
			   "for high signal");
		return -1;
	}
	pos++;
	data->long_interval = atoi(pos);
	pos = os_strchr(pos, ':');
	if (pos) {
		pos++;
		data->fname = os_strdup(pos);
	}

	return 0;
}


static void * bgscan_learn_init(struct wpa_supplicant *wpa_s,
				const char *params,
				const struct wpa_ssid *ssid)
{
	struct bgscan_learn_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->wpa_s = wpa_s;
	data->ssid = ssid;
	if (bgscan_learn_get_params(data, params) < 0) {
		os_free(data->fname);
		os_free(data);
		return NULL;
	}
	if (data->short_interval <= 0)
		data->short_interval = 30;
	if (data->long_interval <= 0)
		data->long_interval = 30;

	if (bgscan_learn_load(data) < 0) {
		os_free(data->fname);
		os_free(data);
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "bgscan learn: Signal strength threshold %d  "
		   "Short bgscan interval %d  Long bgscan interval %d",
		   data->signal_threshold, data->short_interval,
		   data->long_interval);

	if (data->signal_threshold &&
	    wpa_drv_signal_monitor(wpa_s, data->signal_threshold, 4) < 0) {
		wpa_printf(MSG_ERROR, "bgscan learn: Failed to enable "
			   "signal strength monitoring");
	}

	data->scan_interval = data->short_interval;
	eloop_register_timeout(data->scan_interval, 0, bgscan_learn_timeout,
			       data, NULL);
	return data;
}


static void bgscan_learn_deinit(void *priv)
{
	struct bgscan_learn_data *data = priv;
	bgscan_learn_save(data);
	eloop_cancel_timeout(bgscan_learn_timeout, data, NULL);
	if (data->signal_threshold)
		wpa_drv_signal_monitor(data->wpa_s, 0, 0);
	os_free(data->fname);
	os_free(data);
}


static int bgscan_learn_notify_scan(void *priv,
				    struct wpa_scan_results *scan_res)
{
	struct bgscan_learn_data *data = priv;

	wpa_printf(MSG_DEBUG, "bgscan learn: scan result notification");

	eloop_cancel_timeout(bgscan_learn_timeout, data, NULL);
	eloop_register_timeout(data->scan_interval, 0, bgscan_learn_timeout,
			       data, NULL);

	/*
	 * A more advanced bgscan could process scan results internally, select
	 * the BSS and request roam if needed. This sample uses the existing
	 * BSS/ESS selection routine. Change this to return 1 if selection is
	 * done inside the bgscan module.
	 */

	return 0;
}


static void bgscan_learn_notify_beacon_loss(void *priv)
{
	wpa_printf(MSG_DEBUG, "bgscan learn: beacon loss");
	/* TODO: speed up background scanning */
}


static void bgscan_learn_notify_signal_change(void *priv, int above)
{
	struct bgscan_learn_data *data = priv;

	if (data->short_interval == data->long_interval ||
	    data->signal_threshold == 0)
		return;

	wpa_printf(MSG_DEBUG, "bgscan learn: signal level changed "
		   "(above=%d)", above);
	if (data->scan_interval == data->long_interval && !above) {
		wpa_printf(MSG_DEBUG, "bgscan learn: Trigger immediate scan "
			   "and start using short bgscan interval");
		data->scan_interval = data->short_interval;
		eloop_cancel_timeout(bgscan_learn_timeout, data, NULL);
		eloop_register_timeout(0, 0, bgscan_learn_timeout, data,
				       NULL);
	} else if (data->scan_interval == data->short_interval && above) {
		wpa_printf(MSG_DEBUG, "bgscan learn: Start using long bgscan "
			   "interval");
		data->scan_interval = data->long_interval;
		eloop_cancel_timeout(bgscan_learn_timeout, data, NULL);
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_learn_timeout, data, NULL);
	} else if (!above) {
		struct os_time now;
		/*
		 * Signal dropped further 4 dB. Request a new scan if we have
		 * not yet scanned in a while.
		 */
		os_get_time(&now);
		if (now.sec > data->last_bgscan.sec + 10) {
			wpa_printf(MSG_DEBUG, "bgscan learn: Trigger "
				   "immediate scan");
			eloop_cancel_timeout(bgscan_learn_timeout, data,
					     NULL);
			eloop_register_timeout(0, 0, bgscan_learn_timeout,
					       data, NULL);
		}
	}
}


const struct bgscan_ops bgscan_learn_ops = {
	.name = "learn",
	.init = bgscan_learn_init,
	.deinit = bgscan_learn_deinit,
	.notify_scan = bgscan_learn_notify_scan,
	.notify_beacon_loss = bgscan_learn_notify_beacon_loss,
	.notify_signal_change = bgscan_learn_notify_signal_change,
};
