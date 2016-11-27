/*
 * Common functions for Wired Ethernet driver interfaces
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004, Gunter Burchardt <tira@isx.de>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "driver.h"
#include "driver_wired_common.h"

#include <sys/ioctl.h>
#include <net/if.h>
#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <net/if.h>
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
#include <net/if_dl.h>
#include <net/if_media.h>
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__) */
#ifdef __sun__
#include <sys/sockio.h>
#endif /* __sun__ */


int driver_wired_get_ifflags(const char *ifname, int *flags)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOCGIFFLAGS]: %s",
			   strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	*flags = ifr.ifr_flags & 0xffff;
	return 0;
}


int driver_wired_set_ifflags(const char *ifname, int flags)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = flags & 0xffff;
	if (ioctl(s, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOCSIFFLAGS]: %s",
			   strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	return 0;
}


int driver_wired_multi(const char *ifname, const u8 *addr, int add)
{
	struct ifreq ifr;
	int s;

#ifdef __sun__
	return -1;
#endif /* __sun__ */

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		wpa_printf(MSG_ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
#ifdef __linux__
	ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
	os_memcpy(ifr.ifr_hwaddr.sa_data, addr, ETH_ALEN);
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
	{
		struct sockaddr_dl *dlp;

		dlp = (struct sockaddr_dl *) &ifr.ifr_addr;
		dlp->sdl_len = sizeof(struct sockaddr_dl);
		dlp->sdl_family = AF_LINK;
		dlp->sdl_index = 0;
		dlp->sdl_nlen = 0;
		dlp->sdl_alen = ETH_ALEN;
		dlp->sdl_slen = 0;
		os_memcpy(LLADDR(dlp), addr, ETH_ALEN);
	}
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(FreeBSD_kernel__) */
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	{
		struct sockaddr *sap;

		sap = (struct sockaddr *) &ifr.ifr_addr;
		sap->sa_len = sizeof(struct sockaddr);
		sap->sa_family = AF_UNSPEC;
		os_memcpy(sap->sa_data, addr, ETH_ALEN);
	}
#endif /* defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__) */

	if (ioctl(s, add ? SIOCADDMULTI : SIOCDELMULTI, (caddr_t) &ifr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOC{ADD/DEL}MULTI]: %s",
			   strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	return 0;
}


int wired_multicast_membership(int sock, int ifindex, const u8 *addr, int add)
{
#ifdef __linux__
	struct packet_mreq mreq;

	if (sock < 0)
		return -1;

	os_memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	os_memcpy(mreq.mr_address, addr, ETH_ALEN);

	if (setsockopt(sock, SOL_PACKET,
		       add ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
		       &mreq, sizeof(mreq)) < 0) {
		wpa_printf(MSG_ERROR, "setsockopt: %s", strerror(errno));
		return -1;
	}
	return 0;
#else /* __linux__ */
	return -1;
#endif /* __linux__ */
}
