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


static int cmd_simple(int s, enum wlantest_ctrl_cmd cmd)
{
	char buf[4];
	int res;
	enum wlantest_ctrl_cmd resp;

	WPA_PUT_BE32(buf, cmd);
	if (send(s, buf, 4, 0) < 0)
		return -1;
	res = recv(s, buf, sizeof(buf), 0);
	if (res < 4)
		return -1;

	resp = WPA_GET_BE32(buf);
	if (resp == WLANTEST_CTRL_SUCCESS)
		printf("OK\n");
	else if (resp == WLANTEST_CTRL_FAILURE)
		printf("FAIL\n");
	else if (resp == WLANTEST_CTRL_UNKNOWN_CMD)
		printf("Unknown command\n");

	return resp == WLANTEST_CTRL_SUCCESS ? 0 : -1;
}


static int cmd_ping(int s, int argc, char *argv[])
{
	return cmd_simple(s, WLANTEST_CTRL_PING) == 0;
}


static int cmd_terminate(int s, int argc, char *argv[])
{
	return cmd_simple(s, WLANTEST_CTRL_TERMINATE);
}


struct wlantest_cli_cmd {
	const char *cmd;
	int (*handler)(int s, int argc, char *argv[]);
	const char *usage;
};

static const struct wlantest_cli_cmd wlantest_cli_commands[] = {
	{ "ping", cmd_ping, "= test connection to wlantest" },
	{ "terminate", cmd_terminate, "= terminate wlantest" },
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
			cmd++;
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
