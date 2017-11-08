/*
 * hwsim_test - Data connectivity test for mac80211_hwsim
 * Copyright (c) 2009, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define HWSIM_ETHERTYPE ETHERTYPE_IP
#define HWSIM_PACKETLEN 1500

static unsigned char addr1[ETH_ALEN], addr2[ETH_ALEN], bcast[ETH_ALEN];

static u_int16_t checksum(const void *buf, size_t len)
{
	size_t i;
	u_int32_t sum = 0;
	const u_int16_t *pos = buf;

	for (i = 0; i < len / 2; i++)
		sum += *pos++;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum ^ 0xffff;
}


static void tx(int s, const char *ifname, int ifindex,
	       const unsigned char *src, const unsigned char *dst,
	       u_int8_t tos)
{
	char buf[HWSIM_PACKETLEN], *pos;
	struct ether_header *eth;
	struct iphdr *ip;
	int i;

	printf("TX: %s(ifindex=%d) " MACSTR " -> " MACSTR "\n",
	       ifname, ifindex, MAC2STR(src), MAC2STR(dst));

	eth = (struct ether_header *) buf;
	memcpy(eth->ether_dhost, dst, ETH_ALEN);
	memcpy(eth->ether_shost, src, ETH_ALEN);
	eth->ether_type = htons(HWSIM_ETHERTYPE);
	ip = (struct iphdr *) (eth + 1);
	memset(ip, 0, sizeof(*ip));
	ip->ihl = 5;
	ip->version = 4;
	ip->ttl = 64;
	ip->tos = tos;
	ip->tot_len = htons(HWSIM_PACKETLEN - sizeof(*eth));
	ip->protocol = 1;
	ip->saddr = htonl(192 << 24 | 168 << 16 | 1 << 8 | 1);
	ip->daddr = htonl(192 << 24 | 168 << 16 | 1 << 8 | 2);
	ip->check = checksum(ip, sizeof(*ip));
	pos = (char *) (ip + 1);
	for (i = 0; i < sizeof(buf) - sizeof(*eth) - sizeof(*ip); i++)
		*pos++ = i;

	if (send(s, buf, sizeof(buf), 0) < 0)
		perror("send");
}


struct rx_result {
	unsigned int rx_unicast1:1;
	unsigned int rx_broadcast1:1;
	unsigned int rx_unicast2:1;
	unsigned int rx_broadcast2:1;
};


static void rx(int s, int iface, const char *ifname, int ifindex,
	       struct rx_result *res)
{
	char buf[HWSIM_PACKETLEN + 1], *pos;
	struct ether_header *eth;
	struct iphdr *ip;
	int len, i;

	len = recv(s, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv");
		return;
	}
	eth = (struct ether_header *) buf;

	printf("RX: %s(ifindex=%d) " MACSTR " -> " MACSTR " (len=%d)\n",
	       ifname, ifindex,
	       MAC2STR(eth->ether_shost), MAC2STR(eth->ether_dhost), len);

	if (len != HWSIM_PACKETLEN) {
		printf("Ignore frame with unexpected RX length (%d)\n", len);
		return;
	}

	ip = (struct iphdr *) (eth + 1);
	pos = (char *) (ip + 1);
	for (i = 0; i < sizeof(buf) - 1 - sizeof(*eth) - sizeof(*ip); i++) {
		if ((unsigned char) *pos != (unsigned char) i) {
			printf("Ignore frame with unexpected contents\n");
			printf("i=%d received=0x%x expected=0x%x\n",
			       i, (unsigned char) *pos, (unsigned char) i);
			return;
		}
		pos++;
	}

	if (iface == 1 &&
		   memcmp(eth->ether_dhost, addr1, ETH_ALEN) == 0 &&
		   memcmp(eth->ether_shost, addr2, ETH_ALEN) == 0)
		res->rx_unicast1 = 1;
	else if (iface == 1 &&
		   memcmp(eth->ether_dhost, bcast, ETH_ALEN) == 0 &&
		   memcmp(eth->ether_shost, addr2, ETH_ALEN) == 0)
		res->rx_broadcast1 = 1;
	else if (iface == 2 &&
		   memcmp(eth->ether_dhost, addr2, ETH_ALEN) == 0 &&
		   memcmp(eth->ether_shost, addr1, ETH_ALEN) == 0)
		res->rx_unicast2 = 1;
	else if (iface == 2 &&
		   memcmp(eth->ether_dhost, bcast, ETH_ALEN) == 0 &&
		   memcmp(eth->ether_shost, addr1, ETH_ALEN) == 0)
		res->rx_broadcast2 = 1;
}


static void usage(void)
{
	fprintf(stderr, "usage: hwsim_test [-D<DSCP>] [-t<tos>] <ifname1> <ifname2>\n");
}


int main(int argc, char *argv[])
{
	int s1 = -1, s2 = -1, ret = -1, c;
	struct ifreq ifr;
	int ifindex1, ifindex2;
	struct sockaddr_ll ll;
	fd_set rfds;
	struct timeval tv;
	struct rx_result res;
	char *s_ifname, *d_ifname, *end;
	int tos = 0;

	for (;;) {
		c = getopt(argc, argv, "D:t:");
		if (c < 0)
			break;
		switch (c) {
		case 'D':
			tos = strtol(optarg, &end, 0) << 2;
			if (*end) {
				usage();
				return -1;
			}
			break;
		case 't':
			tos = strtol(optarg, &end, 0);
			if (*end) {
				usage();
				return -1;
			}
			break;
		default:
			usage();
			return -1;
		}
	}

	if (optind != argc - 2) {
		usage();
		return -1;
	}

	s_ifname = argv[optind];
	d_ifname = argv[optind + 1];

	memset(bcast, 0xff, ETH_ALEN);

	s1 = socket(PF_PACKET, SOCK_RAW, htons(HWSIM_ETHERTYPE));
	if (s1 < 0) {
		perror("socket");
		goto fail;
	}

	s2 = socket(PF_PACKET, SOCK_RAW, htons(HWSIM_ETHERTYPE));
	if (s2 < 0) {
		perror("socket");
		goto fail;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, s_ifname, sizeof(ifr.ifr_name));
	if (ioctl(s1, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl[SIOCGIFINDEX]");
		goto fail;
	}
	ifindex1 = ifr.ifr_ifindex;
	if (ioctl(s1, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl[SIOCGIFHWADDR]");
		goto fail;
	}
	memcpy(addr1, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, d_ifname, sizeof(ifr.ifr_name));
	if (ioctl(s2, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl[SIOCGIFINDEX]");
		goto fail;
	}
	ifindex2 = ifr.ifr_ifindex;
	if (ioctl(s2, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl[SIOCGIFHWADDR]");
		goto fail;
	}
	memcpy(addr2, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifindex1;
	ll.sll_protocol = htons(HWSIM_ETHERTYPE);
	if (bind(s1, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		perror("bind");
		goto fail;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifindex2;
	ll.sll_protocol = htons(HWSIM_ETHERTYPE);
	if (bind(s2, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		perror("bind");
		goto fail;
	}

	tx(s1, s_ifname, ifindex1, addr1, addr2, tos);
	tx(s1, s_ifname, ifindex1, addr1, bcast, tos);
	tx(s2, d_ifname, ifindex2, addr2, addr1, tos);
	tx(s2, d_ifname, ifindex2, addr2, bcast, tos);

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	memset(&res, 0, sizeof(res));
	for (;;) {
		int r;
		FD_ZERO(&rfds);
		FD_SET(s1, &rfds);
		FD_SET(s2, &rfds);

		r = select(s2 + 1, &rfds, NULL, NULL, &tv);
		if (r < 0) {
			perror("select");
			goto fail;
		}

		if (r == 0)
			break; /* timeout */

		if (FD_ISSET(s1, &rfds))
			rx(s1, 1, s_ifname, ifindex1, &res);
		if (FD_ISSET(s2, &rfds))
			rx(s2, 2, d_ifname, ifindex2, &res);

		if (res.rx_unicast1 && res.rx_broadcast1 &&
		    res.rx_unicast2 && res.rx_broadcast2) {
			ret = 0;
			break;
		}
	}

	if (ret) {
		printf("Did not receive all expected frames:\n"
		       "rx_unicast1=%u rx_broadcast1=%u "
		       "rx_unicast2=%u rx_broadcast2=%u\n",
		       res.rx_unicast1, res.rx_broadcast1,
		       res.rx_unicast2, res.rx_broadcast2);
	} else {
		printf("Both unicast and broadcast working in both "
		       "directions\n");
	}

fail:
	close(s1);
	close(s2);

	return ret;
}
