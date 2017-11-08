/*
 * hostapd - Management frame fuzzer
 * Copyright (c) 2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "ap/hostapd.h"
#include "ap/ieee802_11.h"
#include "ap/sta_info.h"


const struct wpa_driver_ops *const wpa_drivers[] =
{
	NULL
};


struct arg_ctx {
	const char *fname;
	struct hostapd_iface iface;
	struct hostapd_data hapd;
	struct wpa_driver_ops driver;
	struct hostapd_config iconf;
	struct hostapd_bss_config conf;
};


static void test_send_mgmt(void *eloop_data, void *user_ctx)
{
	struct arg_ctx *ctx = eloop_data;
	char *data;
	size_t len;
	struct hostapd_frame_info fi;

	wpa_printf(MSG_INFO, "ap-mgmt-fuzzer: Send '%s'", ctx->fname);

	data = os_readfile(ctx->fname, &len);
	if (!data) {
		wpa_printf(MSG_ERROR, "Could not read '%s'", ctx->fname);
		goto out;
	}

	wpa_hexdump(MSG_MSGDUMP, "fuzzer - WNM", data, len);

	os_memset(&fi, 0, sizeof(fi));
	ieee802_11_mgmt(&ctx->hapd, (u8 *) data, len, &fi);

out:
	os_free(data);
	eloop_terminate();
}


static int init_hapd(struct arg_ctx *ctx)
{
	struct hostapd_data *hapd = &ctx->hapd;
	struct sta_info *sta;

	hapd->driver = &ctx->driver;
	os_memcpy(hapd->own_addr, "\x02\x00\x00\x00\x03\x00", ETH_ALEN);
	hapd->iface = &ctx->iface;
	hapd->iface->conf = hostapd_config_defaults();;
	if (!hapd->iface->conf)
		return -1;
	hapd->iconf = hapd->iface->conf;
	hapd->conf = hapd->iconf->bss[0];
	hostapd_config_defaults_bss(hapd->conf);

	sta = ap_sta_add(hapd, (u8 *) "\x02\x00\x00\x00\x00\x00");
	if (sta)
		sta->flags |= WLAN_STA_ASSOC | WLAN_STA_WMM;

	return 0;
}


int main(int argc, char *argv[])
{
	struct arg_ctx ctx;
	int ret = -1;

	if (argc < 2) {
		printf("usage: %s <file>\n", argv[0]);
		return -1;
	}

	if (os_program_init())
		return -1;

	wpa_debug_level = 0;
	wpa_debug_show_keys = 1;

	if (eloop_init()) {
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
		return -1;
	}

	os_memset(&ctx, 0, sizeof(ctx));
	ctx.fname = argv[1];
	if (init_hapd(&ctx))
		goto fail;

	eloop_register_timeout(0, 0, test_send_mgmt, &ctx, NULL);

	wpa_printf(MSG_DEBUG, "Starting eloop");
	eloop_run();
	wpa_printf(MSG_DEBUG, "eloop done");
	hostapd_free_stas(&ctx.hapd);

	ret = 0;
fail:
	hostapd_config_free(ctx.hapd.iconf);
	eloop_destroy();
	os_program_deinit();

	return ret;
}
