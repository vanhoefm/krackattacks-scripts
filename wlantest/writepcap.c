/*
 * PCAP capture file writer
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <pcap.h>
#include <pcap-bpf.h>

#include "utils/common.h"
#include "wlantest.h"


int write_pcap_init(struct wlantest *wt, const char *fname)
{
	wt->write_pcap = pcap_open_dead(DLT_IEEE802_11_RADIO, 4000);
	if (wt->write_pcap == NULL)
		return -1;
	wt->write_pcap_dumper = pcap_dump_open(wt->write_pcap, fname);
	if (wt->write_pcap_dumper == NULL) {
		pcap_close(wt->write_pcap);
		wt->write_pcap = NULL;
		return -1;
	}

	wpa_printf(MSG_DEBUG, "Writing PCAP dump to '%s'", fname);

	return 0;
}


void write_pcap_deinit(struct wlantest *wt)
{
	if (wt->write_pcap_dumper) {
		pcap_dump_close(wt->write_pcap_dumper);
		wt->write_pcap_dumper = NULL;
	}
	if (wt->write_pcap) {
		pcap_close(wt->write_pcap);
		wt->write_pcap = NULL;
	}
}


void write_pcap_captured(struct wlantest *wt, const u8 *buf, size_t len)
{
	struct pcap_pkthdr h;

	if (!wt->write_pcap_dumper)
		return;

	os_memset(&h, 0, sizeof(h));
	gettimeofday(&wt->write_pcap_time, NULL);
	h.ts = wt->write_pcap_time;
	h.caplen = len;
	h.len = len;
	pcap_dump(wt->write_pcap_dumper, &h, buf);
}


void write_pcap_decrypted(struct wlantest *wt, const u8 *buf1, size_t len1,
			  const u8 *buf2, size_t len2)
{
	struct pcap_pkthdr h;
	u8 rtap[] = {
		0x00 /* rev */,
		0x00 /* pad */,
		0x08, 0x00, /* header len */
		0x00, 0x00, 0x00, 0x00 /* present flags */
	};
	u8 *buf;
	size_t len;

	if (!wt->write_pcap_dumper)
		return;

	os_memset(&h, 0, sizeof(h));
	h.ts = wt->write_pcap_time;
	len = sizeof(rtap) + len1 + len2;
	buf = os_malloc(len);
	if (buf == NULL)
		return;
	os_memcpy(buf, rtap, sizeof(rtap));
	if (buf1) {
		os_memcpy(buf + sizeof(rtap), buf1, len1);
		buf[sizeof(rtap) + 1] &= ~0x40; /* Clear Protected flag */
	}
	if (buf2)
		os_memcpy(buf + sizeof(rtap) + len1, buf2, len2);
	h.caplen = len;
	h.len = len;
	pcap_dump(wt->write_pcap_dumper, &h, buf);
	os_free(buf);
}
