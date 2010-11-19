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


static u8 * attr_hdr_add(u8 *pos, u8 *end, enum wlantest_ctrl_attr attr,
			 size_t len)
{
	if (pos == NULL || end - pos < 8 + len)
		return NULL;
	WPA_PUT_BE32(pos, attr);
	pos += 4;
	WPA_PUT_BE32(pos, len);
	pos += 4;
	return pos;
}


static u8 * attr_add_str(u8 *pos, u8 *end, enum wlantest_ctrl_attr attr,
			 const char *str)
{
	size_t len = os_strlen(str);

	if (pos == NULL || end - pos < 8 + len)
		return NULL;
	WPA_PUT_BE32(pos, attr);
	pos += 4;
	WPA_PUT_BE32(pos, len);
	pos += 4;
	os_memcpy(pos, str, len);
	pos += len;
	return pos;
}


static u8 * attr_add_be32(u8 *pos, u8 *end, enum wlantest_ctrl_attr attr,
			  u32 val)
{
	if (pos == NULL || end - pos < 12)
		return NULL;
	WPA_PUT_BE32(pos, attr);
	pos += 4;
	WPA_PUT_BE32(pos, 4);
	pos += 4;
	WPA_PUT_BE32(pos, val);
	pos += 4;
	return pos;
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


static int cmd_clear_sta_counters(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[100], *pos;
	int rlen;

	if (argc < 2) {
		printf("clear_sta_counters needs two arguments: BSSID and "
		       "STA address\n");
		return -1;
	}

	pos = buf;
	WPA_PUT_BE32(pos, WLANTEST_CTRL_CLEAR_STA_COUNTERS);
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

	WPA_PUT_BE32(pos, WLANTEST_ATTR_STA_ADDR);
	pos += 4;
	WPA_PUT_BE32(pos, ETH_ALEN);
	pos += 4;
	if (hwaddr_aton(argv[1], pos) < 0) {
		printf("Invalid STA address '%s'\n", argv[1]);
		return -1;
	}
	pos += ETH_ALEN;

	rlen = cmd_send_and_recv(s, buf, pos - buf, resp, sizeof(resp));
	if (rlen < 0)
		return -1;
	printf("OK\n");
	return 0;
}


static int cmd_clear_bss_counters(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[100], *pos;
	int rlen;

	if (argc < 1) {
		printf("clear_bss_counters needs one argument: BSSID\n");
		return -1;
	}

	pos = buf;
	WPA_PUT_BE32(pos, WLANTEST_CTRL_CLEAR_BSS_COUNTERS);
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
	printf("OK\n");
	return 0;
}


struct sta_counters {
	const char *name;
	enum wlantest_sta_counter num;
};

static const struct sta_counters sta_counters[] = {
	{ "auth_tx", WLANTEST_STA_COUNTER_AUTH_TX },
	{ "auth_rx", WLANTEST_STA_COUNTER_AUTH_RX },
	{ "assocreq_tx", WLANTEST_STA_COUNTER_ASSOCREQ_TX },
	{ "reassocreq_tx", WLANTEST_STA_COUNTER_REASSOCREQ_TX },
	{ "ptk_learned", WLANTEST_STA_COUNTER_PTK_LEARNED },
	{ "valid_deauth_tx", WLANTEST_STA_COUNTER_VALID_DEAUTH_TX },
	{ "valid_deauth_rx", WLANTEST_STA_COUNTER_VALID_DEAUTH_RX },
	{ "invalid_deauth_tx", WLANTEST_STA_COUNTER_INVALID_DEAUTH_TX },
	{ "invalid_deauth_rx", WLANTEST_STA_COUNTER_INVALID_DEAUTH_RX },
	{ "valid_disassoc_tx", WLANTEST_STA_COUNTER_VALID_DISASSOC_TX },
	{ "valid_disassoc_rx", WLANTEST_STA_COUNTER_VALID_DISASSOC_RX },
	{ "invalid_disassoc_tx", WLANTEST_STA_COUNTER_INVALID_DISASSOC_TX },
	{ "invalid_disassoc_rx", WLANTEST_STA_COUNTER_INVALID_DISASSOC_RX },
	{ "valid_saqueryreq_tx", WLANTEST_STA_COUNTER_VALID_SAQUERYREQ_TX },
	{ "valid_saqueryreq_rx", WLANTEST_STA_COUNTER_VALID_SAQUERYREQ_RX },
	{ "invalid_saqueryreq_tx",
	  WLANTEST_STA_COUNTER_INVALID_SAQUERYREQ_TX },
	{ "invalid_saqueryreq_rx",
	  WLANTEST_STA_COUNTER_INVALID_SAQUERYREQ_RX },
	{ "valid_saqueryresp_tx", WLANTEST_STA_COUNTER_VALID_SAQUERYRESP_TX },
	{ "valid_saqueryresp_rx", WLANTEST_STA_COUNTER_VALID_SAQUERYRESP_RX },
	{ "invalid_saqueryresp_tx",
	  WLANTEST_STA_COUNTER_INVALID_SAQUERYRESP_TX },
	{ "invalid_saqueryresp_rx",
	  WLANTEST_STA_COUNTER_INVALID_SAQUERYRESP_RX },
	{ NULL, 0 }
};

static int cmd_get_sta_counter(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[100], *end, *pos;
	int rlen, i;
	size_t len;

	if (argc != 3) {
		printf("get_sta_counter needs at three arguments: "
		       "counter name, BSSID, and STA address\n");
		return -1;
	}

	pos = buf;
	end = buf + sizeof(buf);
	WPA_PUT_BE32(pos, WLANTEST_CTRL_GET_STA_COUNTER);
	pos += 4;

	for (i = 0; sta_counters[i].name; i++) {
		if (os_strcasecmp(sta_counters[i].name, argv[0]) == 0)
			break;
	}
	if (sta_counters[i].name == NULL) {
		printf("Unknown STA counter '%s'\n", argv[0]);
		printf("Counters:");
		for (i = 0; sta_counters[i].name; i++)
			printf(" %s", sta_counters[i].name);
		printf("\n");
		return -1;
	}

	pos = attr_add_be32(pos, end, WLANTEST_ATTR_STA_COUNTER,
			    sta_counters[i].num);
	pos = attr_hdr_add(pos, end, WLANTEST_ATTR_BSSID, ETH_ALEN);
	if (hwaddr_aton(argv[1], pos) < 0) {
		printf("Invalid BSSID '%s'\n", argv[1]);
		return -1;
	}
	pos += ETH_ALEN;

	pos = attr_hdr_add(pos, end, WLANTEST_ATTR_STA_ADDR, ETH_ALEN);
	if (hwaddr_aton(argv[2], pos) < 0) {
		printf("Invalid STA address '%s'\n", argv[2]);
		return -1;
	}
	pos += ETH_ALEN;

	rlen = cmd_send_and_recv(s, buf, pos - buf, resp, sizeof(resp));
	if (rlen < 0)
		return -1;

	pos = attr_get(resp + 4, rlen - 4, WLANTEST_ATTR_COUNTER, &len);
	if (pos == NULL || len != 4)
		return -1;
	printf("%u\n", WPA_GET_BE32(pos));
	return 0;
}


struct bss_counters {
	const char *name;
	enum wlantest_bss_counter num;
};

static const struct bss_counters bss_counters[] = {
	{ "valid_bip_mmie", WLANTEST_BSS_COUNTER_VALID_BIP_MMIE },
	{ "invalid_bip_mmie", WLANTEST_BSS_COUNTER_INVALID_BIP_MMIE },
	{ "missing_bip_mmie", WLANTEST_BSS_COUNTER_MISSING_BIP_MMIE },
	{ NULL, 0 }
};

static int cmd_get_bss_counter(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[100], *end, *pos;
	int rlen, i;
	size_t len;

	if (argc != 2) {
		printf("get_bss_counter needs at three arguments: "
		       "counter name and BSSID\n");
		return -1;
	}

	pos = buf;
	end = buf + sizeof(buf);
	WPA_PUT_BE32(pos, WLANTEST_CTRL_GET_BSS_COUNTER);
	pos += 4;

	for (i = 0; bss_counters[i].name; i++) {
		if (os_strcasecmp(bss_counters[i].name, argv[0]) == 0)
			break;
	}
	if (bss_counters[i].name == NULL) {
		printf("Unknown BSS counter '%s'\n", argv[0]);
		printf("Counters:");
		for (i = 0; bss_counters[i].name; i++)
			printf(" %s", bss_counters[i].name);
		printf("\n");
		return -1;
	}

	pos = attr_add_be32(pos, end, WLANTEST_ATTR_BSS_COUNTER,
			    bss_counters[i].num);
	pos = attr_hdr_add(pos, end, WLANTEST_ATTR_BSSID, ETH_ALEN);
	if (hwaddr_aton(argv[1], pos) < 0) {
		printf("Invalid BSSID '%s'\n", argv[1]);
		return -1;
	}
	pos += ETH_ALEN;

	rlen = cmd_send_and_recv(s, buf, pos - buf, resp, sizeof(resp));
	if (rlen < 0)
		return -1;

	pos = attr_get(resp + 4, rlen - 4, WLANTEST_ATTR_COUNTER, &len);
	if (pos == NULL || len != 4)
		return -1;
	printf("%u\n", WPA_GET_BE32(pos));
	return 0;
}


struct inject_frames {
	const char *name;
	enum wlantest_inject_frame frame;
};

static const struct inject_frames inject_frames[] = {
	{ "auth", WLANTEST_FRAME_AUTH },
	{ "assocreq", WLANTEST_FRAME_ASSOCREQ },
	{ "reassocreq", WLANTEST_FRAME_REASSOCREQ },
	{ "deauth", WLANTEST_FRAME_DEAUTH },
	{ "disassoc", WLANTEST_FRAME_DISASSOC },
	{ "saqueryreq", WLANTEST_FRAME_SAQUERYREQ },
	{ NULL, 0 }
};

static int cmd_inject(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[100], *end, *pos;
	int rlen, i;
	enum wlantest_inject_protection prot;

	/* <frame> <prot> <sender> <BSSID> <STA/ff:ff:ff:ff:ff:ff> */

	if (argc < 5) {
		printf("inject needs five arguments: frame, protection, "
		       "sender, BSSID, STA/ff:ff:ff:ff:ff:ff\n");
		return -1;
	}

	pos = buf;
	end = buf + sizeof(buf);
	WPA_PUT_BE32(pos, WLANTEST_CTRL_INJECT);
	pos += 4;

	for (i = 0; inject_frames[i].name; i++) {
		if (os_strcasecmp(inject_frames[i].name, argv[0]) == 0)
			break;
	}
	if (inject_frames[i].name == NULL) {
		printf("Unknown inject frame '%s'\n", argv[0]);
		printf("Frames:");
		for (i = 0; inject_frames[i].name; i++)
			printf(" %s", inject_frames[i].name);
		printf("\n");
		return -1;
	}

	pos = attr_add_be32(pos, end, WLANTEST_ATTR_INJECT_FRAME,
			    inject_frames[i].frame);

	if (os_strcasecmp(argv[1], "normal") == 0)
		prot = WLANTEST_INJECT_NORMAL;
	else if (os_strcasecmp(argv[1], "protected") == 0)
		prot = WLANTEST_INJECT_PROTECTED;
	else if (os_strcasecmp(argv[1], "unprotected") == 0)
		prot = WLANTEST_INJECT_UNPROTECTED;
	else if (os_strcasecmp(argv[1], "incorrect") == 0)
		prot = WLANTEST_INJECT_INCORRECT_KEY;
	else {
		printf("Unknown protection type '%s'\n", argv[1]);
		printf("Protection types: normal protected unprotected "
		       "incorrect\n");
		return -1;
	}
	pos = attr_add_be32(pos, end, WLANTEST_ATTR_INJECT_PROTECTION, prot);

	if (os_strcasecmp(argv[2], "ap") == 0) {
		pos = attr_add_be32(pos, end, WLANTEST_ATTR_INJECT_SENDER_AP,
				    1);
	} else if (os_strcasecmp(argv[2], "sta") == 0) {
		pos = attr_add_be32(pos, end, WLANTEST_ATTR_INJECT_SENDER_AP,
				    0);
	} else {
		printf("Unknown sender '%s'\n", argv[2]);
		printf("Sender types: ap sta\n");
		return -1;
	}

	pos = attr_hdr_add(pos, end, WLANTEST_ATTR_BSSID, ETH_ALEN);
	if (hwaddr_aton(argv[3], pos) < 0) {
		printf("Invalid BSSID '%s'\n", argv[3]);
		return -1;
	}
	pos += ETH_ALEN;

	pos = attr_hdr_add(pos, end, WLANTEST_ATTR_STA_ADDR, ETH_ALEN);
	if (hwaddr_aton(argv[4], pos) < 0) {
		printf("Invalid STA '%s'\n", argv[4]);
		return -1;
	}
	pos += ETH_ALEN;

	rlen = cmd_send_and_recv(s, buf, pos - buf, resp, sizeof(resp));
	if (rlen < 0)
		return -1;
	printf("OK\n");
	return 0;
}


static int cmd_version(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[4];
	char *version;
	size_t len;
	int rlen, i;

	WPA_PUT_BE32(buf, WLANTEST_CTRL_VERSION);
	rlen = cmd_send_and_recv(s, buf, sizeof(buf), resp, sizeof(resp));
	if (rlen < 0)
		return -1;

	version = (char *) attr_get(resp + 4, rlen - 4, WLANTEST_ATTR_VERSION,
				    &len);
	if (version == NULL)
		return -1;

	for (i = 0; i < len; i++)
		putchar(version[i]);
	printf("\n");

	return 0;
}


static int cmd_add_passphrase(int s, int argc, char *argv[])
{
	u8 resp[WLANTEST_CTRL_MAX_RESP_LEN];
	u8 buf[100], *pos, *end;
	size_t len;
	int rlen;

	if (argc < 1) {
		printf("add_passphrase needs one argument: passphrase\n");
		return -1;
	}

	len = os_strlen(argv[0]);
	if (len < 8 || len > 63) {
		printf("Invalid passphrase '%s'\n", argv[0]);
		return -1;
	}
	pos = buf;
	end = buf + sizeof(buf);
	WPA_PUT_BE32(pos, WLANTEST_CTRL_ADD_PASSPHRASE);
	pos += 4;
	pos = attr_add_str(pos, end, WLANTEST_ATTR_PASSPHRASE,
			   argv[0]);
	if (argc > 1) {
		pos = attr_hdr_add(pos, end, WLANTEST_ATTR_BSSID, ETH_ALEN);
		if (hwaddr_aton(argv[1], pos) < 0) {
			printf("Invalid BSSID '%s'\n", argv[3]);
			return -1;
		}
		pos += ETH_ALEN;
	}

	rlen = cmd_send_and_recv(s, buf, pos - buf, resp, sizeof(resp));
	if (rlen < 0)
		return -1;
	return 0;
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
	{ "clear_sta_counters", cmd_clear_sta_counters,
	  "<BSSID> <STA> = clear STA counters" },
	{ "clear_bss_counters", cmd_clear_bss_counters,
	  "<BSSID> = clear BSS counters" },
	{ "get_sta_counter", cmd_get_sta_counter,
	  "<counter> <BSSID> <STA> = get STA counter value" },
	{ "get_bss_counter", cmd_get_bss_counter,
	  "<counter> <BSSID> = get BSS counter value" },
	{ "inject", cmd_inject,
	  "<frame> <prot> <sender> <BSSID> <STA/ff:ff:ff:ff:ff:ff>" },
	{ "version", cmd_version, "= get wlantest version" },
	{ "add_passphrase", cmd_add_passphrase,
	  "<passphrase> = add a known passphrase" },
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
