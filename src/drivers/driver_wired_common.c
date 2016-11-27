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
