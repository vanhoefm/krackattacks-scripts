/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <binder/IServiceManager.h>

#include "binder_manager.h"

extern "C" {
#include "utils/includes.h"
#include "utils/common.h"
}

namespace wpa_supplicant_binder {

const char BinderManager::kBinderServiceName[] = "fi.w1.wpa_supplicant";
BinderManager *BinderManager::instance_ = NULL;


BinderManager * BinderManager::getInstance()
{
	if (!instance_)
		instance_ = new BinderManager();
	return instance_;
}


void BinderManager::destroyInstance()
{
	if (instance_)
		delete instance_;
	instance_ = NULL;
}


int BinderManager::registerBinderService(struct wpa_global *global)
{
	/* Create the main binder service object and register with
	 * system service manager. */
	supplicant_object_ = new Supplicant(global);
	android::String16 service_name(kBinderServiceName);
	android::defaultServiceManager()->addService(
		service_name,
		android::IInterface::asBinder(supplicant_object_));
	return 0;
}

} /* namespace wpa_supplicant_binder */
