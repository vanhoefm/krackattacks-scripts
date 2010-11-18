/*
 * wlantest controller
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

#include "utils/includes.h"
#include <sys/un.h>

#include "utils/common.h"
#include "wlantest_ctrl.h"


static u8 * attr_get(u8 *buf, size_t buflen, enum wlantest_ctrl_attr attr,
		     size_t *len)
{
	u8 *pos = buf;

	while (pos + 8 <= buf + buflen) {
		enum wlantest_ctrl_attr a;
		size_t alen;
		a = WPA_GET_BE32(pos);
		pos += 4;
		alen = WPA_GET_BE32(pos);
		pos += 4;
		if (pos + alen > buf + buflen) {
			printf("Invalid control message attribute\n");
			return NULL;
		}
		if (a == attr) {
			*len = alen;
			return pos;
		}
		pos += alen;
	}

	return NULL;
}


static int cmd_send_and_recv(int s, const u8 *cmd, size_t cmd_len,
			     u8 *resp, size_t max_resp_len)
{
	int res;
	enum wlantest_ctrl_cmd cmd_resp;

	if (send(s, cmd, cmd_len, 0) < 0)
		return -1;
	res = recv(s, resp, max_resp_len, 0);
	if (res < 4)
		return -1;

	cmd_resp = WPA_GET_BE32(resp);
	if (cmd_resp == WLANTEST_CTRL_SUCCESS)
		return res;

	if (cmd_resp == WLANTEST_CTRL_UNKNOWN_CMD)
		printf("Unknown command\n");
	else if (cmd_resp == WLANTEST_CTRL_INVALID_CMD)
		printf("Invalid command\n");

	return -1;
}


static int cmd_simple(int s, enum wlantest_ctrl_cmd cmd)
{
	u8 buf[4];
	int res;
	WPA_PUT_BE32(buf, cmd);
	res = cmd_send_and_recv(s, buf, sizeof(buf), buf, sizeof(buf));
	return res < 0 ? -1 : 0;
}


static int cmd_ping(int s, int argc, char *argv[])
{
	int res = cmd_simple(s, WLANTEST_CTRL_PING);
	if (res == 0)
		printf("PONG\n");
	return res == 0;
}


static int cmd_terminate(int s, int argc, char *argv[])
{
	return cmd_simple(s, WLANTEST_CTRL_TERMINATE);
}


static int cmd_list_bss(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[4];
	u8 *bssid;
	size_t len;
	int rlen, i;

	WPA_PUT_BE32(buf, WLANTEST_CTRL_LIST_BSS);
	rlen = cmd_send_and_recv(s, buf, sizeof(buf), resp, sizeof(resp));
	if (rlen < 0)
		return -1;

	bssid = attr_get(resp + 4, rlen - 4, WLANTEST_ATTR_BSSID, &len);
	if (bssid == NULL)
		return -1;

	for (i = 0; i < len / ETH_ALEN; i++)
		printf(MACSTR " ", MAC2STR(bssid + ETH_ALEN * i));
	printf("\n");

	return 0;
}


static int cmd_list_sta(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[100], *pos;
	u8 *addr;
	size_t len;
	int rlen, i;

	if (argc < 1) {
		printf("list_sta needs one argument: BSSID\n");
		return -1;
	}

	pos = buf;
	WPA_PUT_BE32(pos, WLANTEST_CTRL_LIST_STA);
	pos += 4;
	WPA_PUT_BE32(pos, WLANTEST_ATTR_BSSID);
	pos += 4;
	WPA_PUT_BE32(pos, ETH_ALEN);
	pos += 4;
	if (hwaddr_aton(argv[0], pos) < 0) {
		printf("Invalid BSSID '%s'\n", argv[0]);
		return -1;
	}
	pos += ETH_ALEN;

	rlen = cmd_send_and_recv(s, buf, pos - buf, resp, sizeof(resp));
	if (rlen < 0)
		return -1;

	addr = attr_get(resp + 4, rlen - 4, WLANTEST_ATTR_STA_ADDR, &len);
	if (addr == NULL)
		return -1;

	for (i = 0; i < len / ETH_ALEN; i++)
		printf(MACSTR " ", MAC2STR(addr + ETH_ALEN * i));
	printf("\n");

	return 0;
}


static int cmd_flush(int s, int argc, char *argv[])
{
	return cmd_simple(s, WLANTEST_CTRL_FLUSH);
}


struct wlantest_cli_cmd {
	const char *cmd;
	int (*handler)(int s, int argc, char *argv[]);
	const char *usage;
};

static const struct wlantest_cli_cmd wlantest_cli_commands[] = {
	{ "ping", cmd_ping, "= test connection to wlantest" },
	{ "terminate", cmd_terminate, "= terminate wlantest" },
	{ "list_bss", cmd_list_bss, "= get BSS list" },
	{ "list_sta", cmd_list_sta, "<BSSID> = get STA list" },
	{ "flush", cmd_flush, "= drop all collected BSS data" },
	{ NULL, NULL, NULL }
};


static int ctrl_command(int s, int argc, char *argv[])
{
	const struct wlantest_cli_cmd *cmd, *match = NULL;
	int count = 0;
	int ret = 0;

	for (cmd = wlantest_cli_commands; cmd->cmd; cmd++) {
		if (os_strncasecmp(cmd->cmd, argv[0], os_strlen(argv[0])) == 0)
		{
			match = cmd;
			if (os_strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* exact match */
				count = 1;
				break;
			}
			count++;
		}
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		for (cmd = wlantest_cli_commands; cmd->cmd; cmd++) {
			if (os_strncasecmp(cmd->cmd, argv[0],
					   os_strlen(argv[0])) == 0) {
				printf(" %s", cmd->cmd);
			}
		}
		printf("\n");
		ret = 1;
	} else if (count == 0) {
		printf("Unknown command '%s'\n", argv[0]);
		ret = 1;
	} else {
		ret = match->handler(s, argc - 1, &argv[1]);
	}

	return ret;
}


int main(int argc, char *argv[])
{
	int s;
	struct sockaddr_un addr;
	int ret = 0;

	s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path + 1, WLANTEST_SOCK_NAME,
		   sizeof(addr.sun_path) - 1);
	if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		close(s);
		return -1;
	}

	if (argc > 1) {
		ret = ctrl_command(s, argc - 1, &argv[1]);
		if (ret < 0)
			printf("FAIL\n");
	} else {
		/* TODO: interactive */
	}

	close(s);
	return ret;
}
