/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "supplicant.h"

namespace wpa_supplicant_binder {

Supplicant::Supplicant(struct wpa_global *global)
	: wpa_global_(global)
{
}

} /* namespace wpa_supplicant_binder */
