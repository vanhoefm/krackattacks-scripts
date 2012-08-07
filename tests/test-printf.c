/*
 * printf format routines - test program
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/os.h"
#include "utils/common.h"


struct test_data {
	u8 *data;
	size_t len;
	char *encoded;
};

static const struct test_data tests[] = {
	{ (u8 *) "abcde", 5, "abcde" },
	{ (u8 *) "a\0b\nc\ed\re\tf", 11, "a\\0b\\nc\\ed\\re\\tf" },
	{ (u8 *) "\x00\x31\x00\x32\x00\x39", 6, "\\x001\\0002\\09" },
	{ (u8 *) "\n\n\n", 3, "\n\12\x0a" },
	{ (u8 *) "\303\245\303\244\303\266\303\205\303\204\303\226", 12,
	  "\\xc3\\xa5\xc3\\xa4\\xc3\\xb6\\xc3\\x85\\xc3\\x84\\xc3\\x96" },
	{ (u8 *) "\303\245\303\244\303\266\303\205\303\204\303\226", 12,
	  "\\303\\245\\303\\244\\303\\266\\303\\205\\303\\204\\303\\226" },
	{ (u8 *) "\xe5\xe4\xf6\xc5\xc4\xd6", 6,
	  "\\xe5\\xe4\\xf6\\xc5\\xc4\\xd6" },
	{ NULL, 0, NULL }
};


static void print_hex(const u8 *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		printf(" %02x", data[i]);
}


int main(int argc, char *argv[])
{
	int i;
	size_t binlen;
	char buf[100];
	u8 bin[100];
	int errors = 0;

	for (i = 0; tests[i].data; i++) {
		const struct test_data *test = &tests[i];
		printf("%d:", i);
		print_hex(test->data, test->len);
		printf_encode(buf, sizeof(buf), test->data, test->len);
		printf(" -> \"%s\"\n", buf);

		binlen = printf_decode(bin, sizeof(bin), buf);
		if (binlen != test->len ||
		    os_memcmp(bin, test->data, binlen) != 0) {
			printf("Error in decoding#1:");
			print_hex(bin, binlen);
			printf("\n");
			errors++;
		}

		binlen = printf_decode(bin, sizeof(bin), test->encoded);
		if (binlen != test->len ||
		    os_memcmp(bin, test->data, binlen) != 0) {
			printf("Error in decoding#2:");
			print_hex(bin, binlen);
			printf("\n");
			errors++;
		}
	}

	if (errors) {
		printf("%d test(s) failed\n", errors);
		return -1;
	}

	return 0;
}
