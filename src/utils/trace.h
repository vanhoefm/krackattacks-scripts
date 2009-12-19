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

#ifndef TRACE_H
#define TRACE_H

#define WPA_TRACE_LEN 16

#ifdef WPA_TRACE
#include <execinfo.h>

#define WPA_TRACE_INFO void *btrace[WPA_TRACE_LEN]; int btrace_num;
#define wpa_trace_dump(title, ptr) \
	wpa_trace_dump_func((title), (ptr)->btrace, (ptr)->btrace_num)
void wpa_trace_dump_func(const char *title, void **btrace, int btrace_num);
#define wpa_trace_record(ptr) \
	(ptr)->btrace_num = backtrace((ptr)->btrace, WPA_TRACE_LEN)
void wpa_trace_show(const char *title);

#else /* WPA_TRACE */

#define WPA_TRACE_INFO
#define wpa_trace_dump(title, ptr) do { } while (0)
#define wpa_trace_record(ptr) do { } while (0)
#define wpa_trace_show(title) do { } while (0)

#endif /* WPA_TRACE */

#endif /* TRACE_H */
