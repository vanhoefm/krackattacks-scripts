/*
 * Command line editing and history
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

#include "includes.h"
#include <termios.h>

#include "common.h"
#include "eloop.h"
#include "edit.h"

#define CMD_BUF_LEN 256
static char cmdbuf[CMD_BUF_LEN];
static int cmdbuf_pos = 0;
static int cmdbuf_len = 0;
#define CMD_HISTORY_LEN 20
static char history_buf[CMD_HISTORY_LEN][CMD_BUF_LEN];
static int history_pos = 0;
static int history_current = 0;

static void *edit_cb_ctx;
static void (*edit_cmd_cb)(void *ctx, char *cmd);
static void (*edit_eof_cb)(void *ctx);
static char ** (*edit_completion_cb)(void *ctx, const char *cmd, int pos) =
	NULL;

static struct termios prevt, newt;


void edit_clear_line(void)
{
	int i;
	putchar('\r');
	for (i = 0; i < cmdbuf_len + 2; i++)
		putchar(' ');
}


static void move_start(void)
{
	cmdbuf_pos = 0;
	edit_redraw();
}


static void move_end(void)
{
	cmdbuf_pos = cmdbuf_len;
	edit_redraw();
}


static void move_left(void)
{
	if (cmdbuf_pos > 0) {
		cmdbuf_pos--;
		edit_redraw();
	}
}


static void move_right(void)
{
	if (cmdbuf_pos < cmdbuf_len) {
		cmdbuf_pos++;
		edit_redraw();
	}
}


static void move_word_left(void)
{
	while (cmdbuf_pos > 0 && cmdbuf[cmdbuf_pos - 1] == ' ')
		cmdbuf_pos--;
	while (cmdbuf_pos > 0 && cmdbuf[cmdbuf_pos - 1] != ' ')
		cmdbuf_pos--;
	edit_redraw();
}


static void move_word_right(void)
{
	while (cmdbuf_pos < cmdbuf_len && cmdbuf[cmdbuf_pos] == ' ')
		cmdbuf_pos++;
	while (cmdbuf_pos < cmdbuf_len && cmdbuf[cmdbuf_pos] != ' ')
		cmdbuf_pos++;
	edit_redraw();
}


static void delete_left(void)
{
	if (cmdbuf_pos == 0)
		return;

	edit_clear_line();
	os_memmove(cmdbuf + cmdbuf_pos - 1, cmdbuf + cmdbuf_pos,
		   cmdbuf_len - cmdbuf_pos);
	cmdbuf_pos--;
	cmdbuf_len--;
	edit_redraw();
}


static void delete_current(void)
{
	if (cmdbuf_pos == cmdbuf_len)
		return;

	edit_clear_line();
	os_memmove(cmdbuf + cmdbuf_pos, cmdbuf + cmdbuf_pos + 1,
		   cmdbuf_len - cmdbuf_pos);
	cmdbuf_len--;
	edit_redraw();
}


static void delete_word(void)
{
	edit_clear_line();
	while (cmdbuf_len > 0 && cmdbuf[cmdbuf_len - 1] == ' ')
		cmdbuf_len--;
	while (cmdbuf_len > 0 && cmdbuf[cmdbuf_len - 1] != ' ')
		cmdbuf_len--;
	if (cmdbuf_pos > cmdbuf_len)
		cmdbuf_pos = cmdbuf_len;
	edit_redraw();
}


static void clear_left(void)
{
	if (cmdbuf_pos == 0)
		return;

	edit_clear_line();
	os_memmove(cmdbuf, cmdbuf + cmdbuf_pos, cmdbuf_len - cmdbuf_pos);
	cmdbuf_len -= cmdbuf_pos;
	cmdbuf_pos = 0;
	edit_redraw();
}


static void clear_right(void)
{
	if (cmdbuf_pos == cmdbuf_len)
		return;

	edit_clear_line();
	cmdbuf_len = cmdbuf_pos;
	edit_redraw();
}


static void history_add(const char *str)
{
	int prev;

	if (str[0] == '\0')
		return;

	if (history_pos == 0)
		prev = CMD_HISTORY_LEN - 1;
	else
		prev = history_pos - 1;
	if (os_strcmp(history_buf[prev], str) == 0)
		return;

	os_strlcpy(history_buf[history_pos], str, CMD_BUF_LEN);
	history_pos++;
	if (history_pos == CMD_HISTORY_LEN)
		history_pos = 0;
	history_current = history_pos;
}


static void history_prev(void)
{
	int pos;

	if (history_current == (history_pos + 1) % CMD_HISTORY_LEN)
		return;

	pos = history_current;

	if (history_current == history_pos && cmdbuf_len) {
		cmdbuf[cmdbuf_len] = '\0';
		history_add(cmdbuf);
	}

	if (pos > 0)
		pos--;
	else
		pos = CMD_HISTORY_LEN - 1;
	if (history_buf[pos][0] == '\0')
		return;
	history_current = pos;

	edit_clear_line();
	cmdbuf_len = cmdbuf_pos = os_strlen(history_buf[history_current]);
	os_memcpy(cmdbuf, history_buf[history_current], cmdbuf_len);
	edit_redraw();
}


static void history_next(void)
{
	if (history_current == history_pos)
		return;

	history_current++;
	if (history_current == CMD_HISTORY_LEN)
	    history_current = 0;

	edit_clear_line();
	cmdbuf_len = cmdbuf_pos = os_strlen(history_buf[history_current]);
	os_memcpy(cmdbuf, history_buf[history_current], cmdbuf_len);
	edit_redraw();
}


static void history_debug_dump(void)
{
	int p;
	edit_clear_line();
	printf("\r");
	p = (history_pos + 1) % CMD_HISTORY_LEN;
	for (;;) {
		printf("[%d%s%s] %s\n",
		       p, p == history_current ? "C" : "",
		       p == history_pos ? "P" : "", history_buf[p]);
		if (p == history_pos)
			break;
		p++;
		if (p == CMD_HISTORY_LEN)
			p = 0;
	}
	edit_redraw();
}


static void insert_char(int c)
{
	if (c < 32 && c > 255) {
		printf("[%d]\n", c);
		edit_redraw();
		return;
	}

	if (cmdbuf_len >= (int) sizeof(cmdbuf) - 1)
		return;
	if (cmdbuf_len == cmdbuf_pos) {
		cmdbuf[cmdbuf_pos++] = c;
		cmdbuf_len++;
		putchar(c);
		fflush(stdout);
	} else {
		os_memmove(cmdbuf + cmdbuf_pos + 1, cmdbuf + cmdbuf_pos,
			   cmdbuf_len - cmdbuf_pos);
		cmdbuf[cmdbuf_pos++] = c;
		cmdbuf_len++;
		edit_redraw();
	}
}


static void process_cmd(void)
{

	if (cmdbuf_len == 0) {
		printf("\n> ");
		fflush(stdout);
		return;
	}
	printf("\n");
	cmdbuf[cmdbuf_len] = '\0';
	history_add(cmdbuf);
	cmdbuf_pos = 0;
	cmdbuf_len = 0;
	edit_cmd_cb(edit_cb_ctx, cmdbuf);
	printf("> ");
	fflush(stdout);
}


static void free_completions(char **c)
{
	int i;
	if (c == NULL)
		return;
	for (i = 0; c[i]; i++)
		os_free(c[i]);
	os_free(c);
}


static int filter_strings(char **c, char *str, size_t len)
{
	int i, j;

	for (i = 0, j = 0; c[j]; j++) {
		if (os_strncasecmp(c[j], str, len) == 0) {
			if (i != j) {
				c[i] = c[j];
				c[j] = NULL;
			}
			i++;
		} else {
			os_free(c[j]);
			c[j] = NULL;
		}
	}
	c[i] = NULL;
	return i;
}


static int common_len(const char *a, const char *b)
{
	int len = 0;
	while (a[len] && a[len] == b[len])
		len++;
	return len;
}


static int max_common_length(char **c)
{
	int len, i;

	len = os_strlen(c[0]);
	for (i = 1; c[i]; i++) {
		int same = common_len(c[0], c[i]);
		if (same < len)
			len = same;
	}

	return len;
}


static void complete(int list)
{
	char **c;
	int i, len, count;
	int start, end;
	int room, plen, add_space;

	if (edit_completion_cb == NULL)
		return;

	cmdbuf[cmdbuf_len] = '\0';
	c = edit_completion_cb(edit_cb_ctx, cmdbuf, cmdbuf_pos);
	if (c == NULL)
		return;

	end = cmdbuf_pos;
	start = end;
	while (start > 0 && cmdbuf[start - 1] != ' ')
		start--;
	plen = end - start;

	count = filter_strings(c, &cmdbuf[start], plen);
	if (count == 0) {
		free_completions(c);
		return;
	}

	len = max_common_length(c);
	if (len < plen) {
		if (list) {
			edit_clear_line();
			printf("\r");
			for (i = 0; c[i]; i++)
				printf("%s%s", i > 0 ? " " : "", c[i]);
			printf("\n");
			edit_redraw();
		}
		free_completions(c);
		return;
	}
	len -= plen;

	room = sizeof(cmdbuf) - 1 - cmdbuf_len;
	if (room < len)
		len = room;
	add_space = count == 1 && len < room;

	os_memmove(cmdbuf + cmdbuf_pos + len + add_space, cmdbuf + cmdbuf_pos,
		   cmdbuf_len - cmdbuf_pos);
	os_memcpy(&cmdbuf[cmdbuf_pos - plen], c[0], plen + len);
	if (add_space)
		cmdbuf[cmdbuf_pos + len] = ' ';

	cmdbuf_pos += len + add_space;
	cmdbuf_len += len + add_space;

	edit_redraw();

	free_completions(c);
}


static void edit_read_char(int sock, void *eloop_ctx, void *sock_ctx)
{
	int c;
	unsigned char buf[1];
	int res;
	static int esc = -1;
	static char esc_buf[6];
	static int last_tab = 0;

	res = read(sock, buf, 1);
	if (res < 0)
		perror("read");
	if (res <= 0) {
		edit_eof_cb(edit_cb_ctx);
		return;
	}
	c = buf[0];
	if (c != 9)
		last_tab = 0;

	if (esc >= 0) {
		if (esc == 5) {
			printf("{ESC%s}[0]\n", esc_buf);
			edit_redraw();
			esc = -1;
		} else {
			esc_buf[esc++] = c;
			esc_buf[esc] = '\0';
			if (esc == 1)
				return;
		}
	}

	if (esc == 2 && esc_buf[0] == '[' && c >= 'A' && c <= 'Z') {
		switch (c) {
		case 'A': /* up */
			history_prev();
			break;
		case 'B': /* down */
			history_next();
			break;
		case 'C': /* right */
			move_right();
			break;
		case 'D': /* left */
			move_left();
			break;
		default:
			printf("{ESC%s}[1]\n", esc_buf);
			edit_redraw();
			break;
		}
		esc = -1;
		return;
	}

	if (esc > 1 && esc_buf[0] == '[') {
		if ((c >= '0' && c <= '9') || c == ';')
			return;

		if (esc_buf[1] == '1' && esc_buf[2] == ';' &&
		    esc_buf[3] == '5') {
			switch (esc_buf[4]) {
			case 'A': /* Ctrl-Up */
			case 'B': /* Ctrl-Down */
				break;
			case 'C': /* Ctrl-Right */
				move_word_right();
				break;
			case 'D': /* Ctrl-Left */
				move_word_left();
				break;
			default:
				printf("{ESC%s}[2]\n", esc_buf);
				edit_redraw();
				break;
			}
			esc = -1;
			return;
		}

		switch (c) {
		case '~':
			switch (atoi(&esc_buf[1])) {
			case 2: /* Insert */
				break;
			case 3: /* Delete */
				delete_current();
				break;
			case 5: /* Page Up */
			case 6: /* Page Down */
			case 15: /* F5 */
			case 17: /* F6 */
			case 18: /* F7 */
			case 19: /* F8 */
			case 20: /* F9 */
			case 21: /* F10 */
			case 23: /* F11 */
			case 24: /* F12 */
				break;
			default:
				printf("{ESC%s}[3]\n", esc_buf);
				edit_redraw();
				break;
			}
			break;
		default:
			printf("{ESC%s}[4]\n", esc_buf);
			edit_redraw();
			break;
		}

		esc = -1;
		return;
	}

	if (esc > 1 && esc_buf[0] == 'O') {
		switch (esc_buf[1]) {
		case 'F': /* end */
			move_end();
			break;
		case 'H': /* home */
			move_start();
			break;
		case 'P': /* F1 */
			history_debug_dump();
			break;
		case 'Q': /* F2 */
		case 'R': /* F3 */
		case 'S': /* F4 */
			break;
		default:
			printf("{ESC%s}[5]\n", esc_buf);
			edit_redraw();
			break;
		}
		esc = -1;
		return;
	}

	if (esc > 1) {
		printf("{ESC%s}[6]\n", esc_buf);
		edit_redraw();
		esc = -1;
		return;
	}

	switch (c) {
	case 1: /* ^A */
		move_start();
		break;
	case 4: /* ^D */
		if (cmdbuf_len > 0) {
			delete_current();
			return;
		}
		printf("\n");
		edit_eof_cb(edit_cb_ctx);
		break;
	case 5: /* ^E */
		move_end();
		break;
	case 8: /* ^H = BS */
		delete_left();
		break;
	case 9: /* ^I = TAB */
		complete(last_tab);
		last_tab = 1;
		break;
	case 10: /* NL */
	case 13: /* CR */
		process_cmd();
		break;
	case 11: /* ^K */
		clear_right();
		break;
	case 12: /* ^L */
		edit_clear_line();
		edit_redraw();
		break;
	case 14: /* ^N */
		history_next();
		break;
	case 16: /* ^P */
		history_prev();
		break;
	case 18: /* ^R */
		/* TODO: search history */
		break;
	case 21: /* ^U */
		clear_left();
		break;
	case 23: /* ^W */
		delete_word();
		break;
	case 27: /* ESC */
		esc = 0;
		break;
	case 127: /* DEL */
		delete_left();
		break;
	default:
		insert_char(c);
		break;
	}
}


int edit_init(void (*cmd_cb)(void *ctx, char *cmd),
	      void (*eof_cb)(void *ctx),
	      void *ctx)
{
	os_memset(history_buf, 0, sizeof(history_buf));

	edit_cb_ctx = ctx;
	edit_cmd_cb = cmd_cb;
	edit_eof_cb = eof_cb;

	tcgetattr(STDIN_FILENO, &prevt);
	newt = prevt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	eloop_register_read_sock(STDIN_FILENO, edit_read_char, NULL, NULL);

	printf("> ");
	fflush(stdout);

	return 0;
}


void edit_deinit(void)
{
	eloop_unregister_read_sock(STDIN_FILENO);
	tcsetattr(STDIN_FILENO, TCSANOW, &prevt);
}


void edit_redraw(void)
{
	char tmp;
	cmdbuf[cmdbuf_len] = '\0';
	printf("\r> %s", cmdbuf);
	if (cmdbuf_pos != cmdbuf_len) {
		tmp = cmdbuf[cmdbuf_pos];
		cmdbuf[cmdbuf_pos] = '\0';
		printf("\r> %s", cmdbuf);
		cmdbuf[cmdbuf_pos] = tmp;
	}
	fflush(stdout);
}


void edit_set_filter_history_cb(int (*cb)(void *ctx, const char *cmd))
{
}


void edit_set_completion_cb(char ** (*cb)(void *ctx, const char *cmd, int pos))
{
	edit_completion_cb = cb;
}
