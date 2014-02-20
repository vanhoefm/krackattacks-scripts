/*
 * wpa_supplicant module tests
 * Copyright (c) 2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"

int wpas_module_tests(void)
{
	int ret = 0;

	wpa_printf(MSG_INFO, "wpa_supplicant module tests");

#ifdef CONFIG_WPS
	{
		int wps_module_tests(void);
		if (wps_module_tests() < 0)
			ret = -1;
	}
#endif /* CONFIG_WPS */

	return ret;
}
