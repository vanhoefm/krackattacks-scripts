/*
 * Backtrace debugging
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
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

#include "common.h"
#include "trace.h"

#ifdef WPA_TRACE

void wpa_trace_dump_func(const char *title, void **btrace, int btrace_num)
{
	char **sym;
	int i;

	wpa_printf(MSG_INFO, "WPA_TRACE: %s - START", title);
	sym = backtrace_symbols(btrace, btrace_num);
	for (i = 0; i < btrace_num; i++)
		wpa_printf(MSG_INFO, "[%d]: %p: %s",
			   i, btrace[i], sym ? sym[i] : "");
	os_free(sym);
	wpa_printf(MSG_INFO, "WPA_TRACE: %s - END", title);
}


void wpa_trace_show(const char *title)
{
	struct info {
		WPA_TRACE_INFO
	} info;
	wpa_trace_record(&info);
	wpa_trace_dump(title, &info);
}

#endif /* WPA_TRACE */
