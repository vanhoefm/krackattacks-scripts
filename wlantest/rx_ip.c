/*
 * Received Data frame processing for IPv4 packets
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "utils/common.h"
#include "wlantest.h"


static void ping_update(struct wlantest_sta *sta, int req, u32 src, u32 dst,
			u16 id, u16 seq)
{
	if (req) {
		sta->icmp_echo_req_src = src;
		sta->icmp_echo_req_dst = dst;
		sta->icmp_echo_req_id = id;
		sta->icmp_echo_req_seq = seq;
		return;
	}

	if (sta->icmp_echo_req_src == dst &&
	    sta->icmp_echo_req_dst == src &&
	    sta->icmp_echo_req_id == id &&
	    sta->icmp_echo_req_seq == seq) {
		sta->counters[WLANTEST_STA_COUNTER_PING_OK]++;
		if (sta->counters[WLANTEST_STA_COUNTER_ASSOCREQ_TX] == 0 &&
		    sta->counters[WLANTEST_STA_COUNTER_REASSOCREQ_TX] == 0)
			sta->counters[
				WLANTEST_STA_COUNTER_PING_OK_FIRST_ASSOC]++;
		wpa_printf(MSG_DEBUG, "ICMP echo (ping) match for STA " MACSTR,
			   MAC2STR(sta->addr));
	}
}


static void rx_data_icmp(struct wlantest *wt, const u8 *bssid,
			 const u8 *sta_addr, u32 dst, u32 src,
			 const u8 *data, size_t len, const u8 *peer_addr)
{
	struct in_addr addr;
	char buf[20];
	const struct icmphdr *hdr;
	u16 id, seq;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta;

	hdr = (const struct icmphdr *) data;
	if (len < 4)
		return;

	/* TODO: check hdr->checksum */

	if (hdr->type != ICMP_ECHOREPLY && hdr->type != ICMP_ECHO)
		return;
	if (len < 8)
		return;

	id = ntohs(hdr->un.echo.id);
	seq = ntohs(hdr->un.echo.sequence);

	addr.s_addr = dst;
	snprintf(buf, sizeof(buf), "%s", inet_ntoa(addr));
	addr.s_addr = src;
	wpa_printf(MSG_DEBUG, "ICMP echo %s %s -> %s id=%04x seq=%u len=%u%s",
		   hdr->type == ICMP_ECHO ? "request" : "response",
		   inet_ntoa(addr), buf, id, seq, (unsigned) len - 8,
		   peer_addr ? " [DL]" : "");

	bss = bss_find(wt, bssid);
	if (bss == NULL) {
		wpa_printf(MSG_INFO, "No BSS " MACSTR " known for ICMP packet",
			   MAC2STR(bssid));
		return;
	}

	if (sta_addr == NULL)
		return; /* FromDS broadcast ping */

	sta = sta_find(bss, sta_addr);
	if (sta == NULL) {
		wpa_printf(MSG_INFO, "No STA " MACSTR " known for ICMP packet",
			   MAC2STR(sta_addr));
		return;
	}

	ping_update(sta, hdr->type == ICMP_ECHO, src, dst, id, seq);
	if (peer_addr && (sta = sta_find(bss, peer_addr)))
		ping_update(sta, hdr->type == ICMP_ECHO, src, dst, id, seq);
}


void rx_data_ip(struct wlantest *wt, const u8 *bssid, const u8 *sta_addr,
		const u8 *dst, const u8 *src, const u8 *data, size_t len,
		const u8 *peer_addr)
{
	const struct iphdr *ip;
	const u8 *payload;
	size_t plen;
	u16 frag_off, tot_len;

	ip = (const struct iphdr *) data;
	if (len < sizeof(*ip))
		return;
	if (ip->version != 4) {
		wpa_printf(MSG_DEBUG, "Unexpected IP protocol version %u in "
			   "IPv4 packet (bssid=" MACSTR " str=" MACSTR
			   " dst=" MACSTR ")", ip->version, MAC2STR(bssid),
			   MAC2STR(src), MAC2STR(dst));
		return;
	}
	if (ip->ihl * 4 < sizeof(*ip)) {
		wpa_printf(MSG_DEBUG, "Unexpected IP header length %u in "
			   "IPv4 packet (bssid=" MACSTR " str=" MACSTR
			   " dst=" MACSTR ")", ip->ihl, MAC2STR(bssid),
			   MAC2STR(src), MAC2STR(dst));
		return;
	}
	if (ip->ihl * 4 > len) {
		wpa_printf(MSG_DEBUG, "Truncated IP header (ihl=%u len=%u) in "
			   "IPv4 packet (bssid=" MACSTR " str=" MACSTR
			   " dst=" MACSTR ")", ip->ihl, (unsigned) len,
			   MAC2STR(bssid), MAC2STR(src), MAC2STR(dst));
		return;
	}

	/* TODO: check header checksum in ip->check */

	frag_off = be_to_host16(ip->frag_off);
	if (frag_off & 0x1fff) {
		wpa_printf(MSG_EXCESSIVE, "IP fragment reassembly not yet "
			   "supported");
		return;
	}

	tot_len = be_to_host16(ip->tot_len);
	if (tot_len > len)
		return;
	if (tot_len < len)
		len = tot_len;

	payload = data + 4 * ip->ihl;
	plen = len - 4 * ip->ihl;

	switch (ip->protocol) {
	case IPPROTO_ICMP:
		rx_data_icmp(wt, bssid, sta_addr, ip->daddr, ip->saddr,
			     payload, plen, peer_addr);
		break;
	}
}
