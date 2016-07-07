/*
 * Common hostapd/wpa_supplicant command line interface functions
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "utils/common.h"
#include "common/cli.h"


void cli_txt_list_free(struct cli_txt_entry *e)
{
	dl_list_del(&e->list);
	os_free(e->txt);
	os_free(e);
}


void cli_txt_list_flush(struct dl_list *list)
{
	struct cli_txt_entry *e;

	while ((e = dl_list_first(list, struct cli_txt_entry, list)))
		cli_txt_list_free(e);
}


struct cli_txt_entry * cli_txt_list_get(struct dl_list *txt_list,
					const char *txt)
{
	struct cli_txt_entry *e;

	dl_list_for_each(e, txt_list, struct cli_txt_entry, list) {
		if (os_strcmp(e->txt, txt) == 0)
			return e;
	}
	return NULL;
}


void cli_txt_list_del(struct dl_list *txt_list, const char *txt)
{
	struct cli_txt_entry *e;

	e = cli_txt_list_get(txt_list, txt);
	if (e)
		cli_txt_list_free(e);
}


void cli_txt_list_del_addr(struct dl_list *txt_list, const char *txt)
{
	u8 addr[ETH_ALEN];
	char buf[18];

	if (hwaddr_aton(txt, addr) < 0)
		return;
	os_snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	cli_txt_list_del(txt_list, buf);
}


void cli_txt_list_del_word(struct dl_list *txt_list, const char *txt,
			   int separator)
{
	const char *end;
	char *buf;

	end = os_strchr(txt, separator);
	if (end == NULL)
		end = txt + os_strlen(txt);
	buf = dup_binstr(txt, end - txt);
	if (buf == NULL)
		return;
	cli_txt_list_del(txt_list, buf);
	os_free(buf);
}


int cli_txt_list_add(struct dl_list *txt_list, const char *txt)
{
	struct cli_txt_entry *e;

	e = cli_txt_list_get(txt_list, txt);
	if (e)
		return 0;
	e = os_zalloc(sizeof(*e));
	if (e == NULL)
		return -1;
	e->txt = os_strdup(txt);
	if (e->txt == NULL) {
		os_free(e);
		return -1;
	}
	dl_list_add(txt_list, &e->list);
	return 0;
}


int cli_txt_list_add_addr(struct dl_list *txt_list, const char *txt)
{
	u8 addr[ETH_ALEN];
	char buf[18];

	if (hwaddr_aton(txt, addr) < 0)
		return -1;
	os_snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	return cli_txt_list_add(txt_list, buf);
}


int cli_txt_list_add_word(struct dl_list *txt_list, const char *txt,
			  int separator)
{
	const char *end;
	char *buf;
	int ret;

	end = os_strchr(txt, separator);
	if (end == NULL)
		end = txt + os_strlen(txt);
	buf = dup_binstr(txt, end - txt);
	if (buf == NULL)
		return -1;
	ret = cli_txt_list_add(txt_list, buf);
	os_free(buf);
	return ret;
}


char ** cli_txt_list_array(struct dl_list *txt_list)
{
	unsigned int i, count = dl_list_len(txt_list);
	char **res;
	struct cli_txt_entry *e;

	res = os_calloc(count + 1, sizeof(char *));
	if (res == NULL)
		return NULL;

	i = 0;
	dl_list_for_each(e, txt_list, struct cli_txt_entry, list) {
		res[i] = os_strdup(e->txt);
		if (res[i] == NULL)
			break;
		i++;
	}

	return res;
}
