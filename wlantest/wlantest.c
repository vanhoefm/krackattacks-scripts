/*
 * wlantest - IEEE 802.11 protocol monitoring and testing tool
 * Copyright (c) 2010-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "wlantest.h"


extern int wpa_debug_level;
extern int wpa_debug_show_keys;


static void wlantest_terminate(int sig, void *signal_ctx)
{
	eloop_terminate();
}


static void usage(void)
{
	printf("wlantest [-cddhqq] [-i<ifname>] [-r<pcap file>] "
	       "[-p<passphrase>]\n"
		"         [-I<wired ifname>] [-R<wired pcap file>] "
	       "[-P<RADIUS shared secret>]\n"
		"         [-w<write pcap file>] [-f<MSK/PMK file>]\n");
}


static void passphrase_deinit(struct wlantest_passphrase *p)
{
	dl_list_del(&p->list);
	os_free(p);
}


static void secret_deinit(struct wlantest_radius_secret *r)
{
	dl_list_del(&r->list);
	os_free(r);
}


static void wlantest_init(struct wlantest *wt)
{
	int i;
	os_memset(wt, 0, sizeof(*wt));
	wt->monitor_sock = -1;
	wt->ctrl_sock = -1;
	for (i = 0; i < MAX_CTRL_CONNECTIONS; i++)
		wt->ctrl_socks[i] = -1;
	dl_list_init(&wt->passphrase);
	dl_list_init(&wt->bss);
	dl_list_init(&wt->secret);
	dl_list_init(&wt->radius);
	dl_list_init(&wt->pmk);
	dl_list_init(&wt->wep);
}


void radius_deinit(struct wlantest_radius *r)
{
	dl_list_del(&r->list);
	os_free(r);
}


static void wlantest_deinit(struct wlantest *wt)
{
	struct wlantest_passphrase *p, *pn;
	struct wlantest_radius_secret *s, *sn;
	struct wlantest_radius *r, *rn;
	struct wlantest_pmk *pmk, *np;
	struct wlantest_wep *wep, *nw;

	if (wt->ctrl_sock >= 0)
		ctrl_deinit(wt);
	if (wt->monitor_sock >= 0)
		monitor_deinit(wt);
	bss_flush(wt);
	dl_list_for_each_safe(p, pn, &wt->passphrase,
			      struct wlantest_passphrase, list)
		passphrase_deinit(p);
	dl_list_for_each_safe(s, sn, &wt->secret,
			      struct wlantest_radius_secret, list)
		secret_deinit(s);
	dl_list_for_each_safe(r, rn, &wt->radius, struct wlantest_radius, list)
		radius_deinit(r);
	dl_list_for_each_safe(pmk, np, &wt->pmk, struct wlantest_pmk, list)
		pmk_deinit(pmk);
	dl_list_for_each_safe(wep, nw, &wt->wep, struct wlantest_wep, list)
		os_free(wep);
	write_pcap_deinit(wt);
}


static void add_passphrase(struct wlantest *wt, const char *passphrase)
{
	struct wlantest_passphrase *p;
	size_t len = os_strlen(passphrase);

	if (len < 8 || len > 63)
		return;
	p = os_zalloc(sizeof(*p));
	if (p == NULL)
		return;
	os_memcpy(p->passphrase, passphrase, len);
	dl_list_add(&wt->passphrase, &p->list);
}


static void add_secret(struct wlantest *wt, const char *secret)
{
	struct wlantest_radius_secret *s;
	size_t len = os_strlen(secret);

	if (len >= MAX_RADIUS_SECRET_LEN)
		return;
	s = os_zalloc(sizeof(*s));
	if (s == NULL)
		return;
	os_memcpy(s->secret, secret, len);
	dl_list_add(&wt->secret, &s->list);
}


static int add_pmk_file(struct wlantest *wt, const char *pmk_file)
{
	FILE *f;
	u8 pmk[32];
	char buf[300], *pos;
	struct wlantest_pmk *p;

	f = fopen(pmk_file, "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "Could not open '%s'", pmk_file);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		pos = buf;
		while (*pos && *pos != '\r' && *pos != '\n')
			pos++;
		*pos = '\0';
		if (pos - buf < 2 * 32)
			continue;
		if (hexstr2bin(buf, pmk, 32) < 0)
			continue;
		p = os_zalloc(sizeof(*p));
		if (p == NULL)
			break;
		os_memcpy(p->pmk, pmk, 32);
		dl_list_add(&wt->pmk, &p->list);
		wpa_hexdump(MSG_DEBUG, "Added PMK from file", pmk, 32);
	}

	fclose(f);
	return 0;
}


int add_wep(struct wlantest *wt, const char *key)
{
	struct wlantest_wep *w;
	size_t len = os_strlen(key);

	if (len != 2 * 5 && len != 2 * 13) {
		wpa_printf(MSG_INFO, "Invalid WEP key '%s'", key);
		return -1;
	}
	w = os_zalloc(sizeof(*w));
	if (w == NULL)
		return -1;
	if (hexstr2bin(key, w->key, len / 2) < 0) {
		os_free(w);
		wpa_printf(MSG_INFO, "Invalid WEP key '%s'", key);
		return -1;
	}
	w->key_len = len / 2;
	dl_list_add(&wt->wep, &w->list);
	return 0;
}


int main(int argc, char *argv[])
{
	int c;
	const char *read_file = NULL;
	const char *read_wired_file = NULL;
	const char *write_file = NULL;
	const char *ifname = NULL;
	const char *ifname_wired = NULL;
	struct wlantest wt;
	int ctrl_iface = 0;

	wpa_debug_level = MSG_INFO;
	wpa_debug_show_keys = 1;

	if (os_program_init())
		return -1;

	wlantest_init(&wt);

	for (;;) {
		c = getopt(argc, argv, "cdf:hi:I:p:P:qr:R:w:W:");
		if (c < 0)
			break;
		switch (c) {
		case 'c':
			ctrl_iface = 1;
			break;
		case 'd':
			if (wpa_debug_level > 0)
				wpa_debug_level--;
			break;
		case 'f':
			if (add_pmk_file(&wt, optarg) < 0)
				return -1;
			break;
		case 'h':
			usage();
			return 0;
		case 'i':
			ifname = optarg;
			break;
		case 'I':
			ifname_wired = optarg;
			break;
		case 'p':
			add_passphrase(&wt, optarg);
			break;
		case 'P':
			add_secret(&wt, optarg);
			break;
		case 'q':
			wpa_debug_level++;
			break;
		case 'r':
			read_file = optarg;
			break;
		case 'R':
			read_wired_file = optarg;
			break;
		case 'w':
			write_file = optarg;
			break;
		case 'W':
			if (add_wep(&wt, optarg) < 0)
				return -1;
			break;
		default:
			usage();
			return -1;
		}
	}

	if (ifname == NULL && ifname_wired == NULL &&
	    read_file == NULL && read_wired_file == NULL) {
		usage();
		return 0;
	}

	if (eloop_init())
		return -1;

	if (write_file && write_pcap_init(&wt, write_file) < 0)
		return -1;

	if (read_wired_file && read_wired_cap_file(&wt, read_wired_file) < 0)
		return -1;

	if (read_file && read_cap_file(&wt, read_file) < 0)
		return -1;

	if (ifname && monitor_init(&wt, ifname) < 0)
		return -1;

	if (ifname_wired && monitor_init_wired(&wt, ifname_wired) < 0)
		return -1;

	if (ctrl_iface && ctrl_init(&wt) < 0)
		return -1;

	eloop_register_signal_terminate(wlantest_terminate, &wt);

	eloop_run();

	wpa_printf(MSG_INFO, "Processed: rx_mgmt=%u rx_ctrl=%u rx_data=%u "
		   "fcs_error=%u",
		   wt.rx_mgmt, wt.rx_ctrl, wt.rx_data, wt.fcs_error);

	wlantest_deinit(&wt);

	eloop_destroy();
	os_program_deinit();

	return 0;
}
