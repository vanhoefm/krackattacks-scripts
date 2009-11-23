/*
 * hostapd / Initialization and configuration
 * Host AP kernel driver
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
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

#ifndef HOSTAPD_DEFS_H
#define HOSTAPD_DEFS_H

/* MTU to be set for the wlan#ap device; this is mainly needed for IEEE 802.1X
 * frames that might be longer than normal default MTU and they are not
 * fragmented */
#define HOSTAPD_MTU 2290

#endif /* HOSTAPD_DEFS_H */
