/*
 * wlantest control interface
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
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

#ifndef WLANTEST_CTRL_H
#define WLANTEST_CTRL_H

#define WLANTEST_SOCK_NAME "w1.fi.wlantest"
#define WLANTEST_CTRL_MAX_CMD_LEN 1000
#define WLANTEST_CTRL_MAX_RESP_LEN 1000

enum wlantest_ctrl_cmd {
	WLANTEST_CTRL_SUCCESS,
	WLANTEST_CTRL_FAILURE,
	WLANTEST_CTRL_INVALID_CMD,
	WLANTEST_CTRL_UNKNOWN_CMD,
	WLANTEST_CTRL_PING,
	WLANTEST_CTRL_TERMINATE,
	WLANTEST_CTRL_LIST_BSS,
	WLANTEST_CTRL_LIST_STA,
	WLANTEST_CTRL_FLUSH,
};

enum wlantest_ctrl_attr {
	WLANTEST_ATTR_BSSID,
	WLANTEST_ATTR_STA_ADDR,
};

#endif /* WLANTEST_CTRL_H */
