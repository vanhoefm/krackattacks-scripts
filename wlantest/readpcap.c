/*
 * PCAP capture file reader
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <pcap.h>

#include "utils/common.h"
#include "wlantest.h"


int read_cap_file(struct wlantest *wt, const char *fname)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	unsigned int count = 0;
	struct pcap_pkthdr *hdr;
	const u_char *data;
	int res;
	int dlt;

	pcap = pcap_open_offline(fname, errbuf);
	if (pcap == NULL) {
		wpa_printf(MSG_ERROR, "Failed to read pcap file '%s': %s",
			   fname, errbuf);
		return -1;
	}
	dlt = pcap_datalink(pcap);
	if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_PRISM_HEADER &&
	    dlt != DLT_IEEE802_11) {
		wpa_printf(MSG_ERROR, "Unsupported pcap datalink type: %d",
			   dlt);
		pcap_close(pcap);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "pcap datalink type: %d", dlt);

	for (;;) {
		res = pcap_next_ex(pcap, &hdr, &data);
		if (res == -2)
			break; /* No more packets */
		if (res == -1) {
			wpa_printf(MSG_INFO, "pcap_next_ex failure: %s",
				   pcap_geterr(pcap));
			break;
		}
		if (res != 1) {
			wpa_printf(MSG_INFO, "Unexpected pcap_next_ex return "
				   "value %d", res);
			break;
		}

		/* Packet was read without problems */
		wpa_printf(MSG_EXCESSIVE, "pcap hdr: ts=%d.%06d "
			   "len=%u/%u",
			   (int) hdr->ts.tv_sec, (int) hdr->ts.tv_usec,
			   hdr->caplen, hdr->len);
		if (wt->write_pcap_dumper) {
			wt->write_pcap_time = hdr->ts;
			pcap_dump(wt->write_pcap_dumper, hdr, data);
		}
		if (hdr->caplen < hdr->len) {
			wpa_printf(MSG_DEBUG, "pcap: Dropped incomplete frame "
				   "(%u/%u captured)",
				   hdr->caplen, hdr->len);
			continue;
		}
		count++;
		switch (dlt) {
		case DLT_IEEE802_11_RADIO:
			wlantest_process(wt, data, hdr->caplen);
			break;
		case DLT_PRISM_HEADER:
			wlantest_process_prism(wt, data, hdr->caplen);
			break;
		case DLT_IEEE802_11:
			wlantest_process_80211(wt, data, hdr->caplen);
		}
	}

	pcap_close(pcap);

	wpa_printf(MSG_DEBUG, "Read %s: %u packets", fname, count);

	return 0;
}


int read_wired_cap_file(struct wlantest *wt, const char *fname)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	unsigned int count = 0;
	struct pcap_pkthdr *hdr;
	const u_char *data;
	int res;

	pcap = pcap_open_offline(fname, errbuf);
	if (pcap == NULL) {
		wpa_printf(MSG_ERROR, "Failed to read pcap file '%s': %s",
			   fname, errbuf);
		return -1;
	}

	for (;;) {
		res = pcap_next_ex(pcap, &hdr, &data);
		if (res == -2)
			break; /* No more packets */
		if (res == -1) {
			wpa_printf(MSG_INFO, "pcap_next_ex failure: %s",
				   pcap_geterr(pcap));
			break;
		}
		if (res != 1) {
			wpa_printf(MSG_INFO, "Unexpected pcap_next_ex return "
				   "value %d", res);
			break;
		}

		/* Packet was read without problems */
		wpa_printf(MSG_EXCESSIVE, "pcap hdr: ts=%d.%06d "
			   "len=%u/%u",
			   (int) hdr->ts.tv_sec, (int) hdr->ts.tv_usec,
			   hdr->caplen, hdr->len);
		if (hdr->caplen < hdr->len) {
			wpa_printf(MSG_DEBUG, "pcap: Dropped incomplete frame "
				   "(%u/%u captured)",
				   hdr->caplen, hdr->len);
			continue;
		}
		count++;
		wlantest_process_wired(wt, data, hdr->caplen);
	}

	pcap_close(pcap);

	wpa_printf(MSG_DEBUG, "Read %s: %u packets", fname, count);

	return 0;
}
