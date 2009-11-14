/*
 * WPA Supplicant / dbus-based control interface
 * Copyright (c) 2006, Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
 * Copyright (c) 2009, Witold Sowa <witold.sowa@gmail.com>
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

#ifndef WPA_DBUS_CTRL_H
#define WPA_DBUS_CTRL_H

#include <dbus/dbus.h>

struct ctrl_iface_dbus_new_priv {
	DBusConnection *con;
	int should_dispatch;
	void *application_data;

	u32 next_objid;
};

typedef DBusMessage * (* WPADBusMethodHandler)(DBusMessage *message,
					       void *user_data);
typedef void (* WPADBusArgumentFreeFunction)(void *handler_arg);

typedef DBusMessage * (* WPADBusPropertyAccessor)(DBusMessage *message,
						  void *user_data);

struct wpa_dbus_object_desc {
	DBusConnection *connection;
	struct wpa_dbus_method_desc *methods;
	struct wpa_dbus_signal_desc *signals;
	struct wpa_dbus_property_desc *properties;
};

enum dbus_prop_access { R, W, RW };

enum dbus_arg_direction { ARG_IN, ARG_OUT };

struct wpa_dbus_argument {
	char *name;
	char *type;
	enum dbus_arg_direction dir;
};

#define END_ARGS { NULL, NULL, ARG_IN }

#ifdef CONFIG_CTRL_IFACE_DBUS_NEW

#ifndef SIGPOLL
#ifdef SIGIO
/*
 * If we do not have SIGPOLL, try to use SIGIO instead. This is needed for
 * FreeBSD.
 */
#define SIGPOLL SIGIO
#endif
#endif

#define WPAS_DBUS_OBJECT_PATH_MAX 150
#define WPAS_DBUS_INTERFACE_MAX 150
#define WPAS_DBUS_METHOD_SIGNAL_PROP_MAX 50

#define WPA_DBUS_INTROSPECTION_INTERFACE "org.freedesktop.DBus.Introspectable"
#define WPA_DBUS_INTROSPECTION_METHOD "Introspect"
#define WPA_DBUS_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define WPA_DBUS_PROPERTIES_GET "Get"
#define WPA_DBUS_PROPERTIES_SET "Set"
#define WPA_DBUS_PROPERTIES_GETALL "GetAll"

void free_dbus_object_desc(struct wpa_dbus_object_desc *obj_dsc);

struct ctrl_iface_dbus_new_priv *
wpa_dbus_ctrl_iface_init(void *application_data, char *dbus_path,
			 char *dbus_service,
			 struct wpa_dbus_object_desc *obj_desc);

void wpa_dbus_ctrl_iface_deinit(struct ctrl_iface_dbus_new_priv *iface);

int wpa_dbus_register_object_per_iface(
	struct ctrl_iface_dbus_new_priv *ctrl_iface,
	const char *path, const char *ifname,
	struct wpa_dbus_object_desc *obj_desc);

int wpa_dbus_unregister_object_per_iface(
	struct ctrl_iface_dbus_new_priv *ctrl_iface,
	const char *path);

int wpa_dbus_method_register(struct wpa_dbus_object_desc *obj_dsc,
			     const char *dbus_interface,
			     const char *dbus_method,
			     WPADBusMethodHandler method_handler,
			     void *handler_argument,
			     WPADBusArgumentFreeFunction argument_free_func,
			     const struct wpa_dbus_argument args[]);

int wpa_dbus_signal_register(struct wpa_dbus_object_desc *obj_dsc,
			     const char *dbus_interface,
			     const char *dbus_signal,
			     const struct wpa_dbus_argument args[]);

int wpa_dbus_property_register(
	struct wpa_dbus_object_desc *obj_dsc,
	const char *dbus_interface, const char *dbus_property,
	const char *type,
	WPADBusPropertyAccessor getter,
	WPADBusPropertyAccessor setter,
	void *user_data,
	WPADBusArgumentFreeFunction user_data_free_func,
	enum dbus_prop_access _access);

void wpa_dbus_signal_property_changed(struct ctrl_iface_dbus_new_priv *iface,
				      WPADBusPropertyAccessor property_getter,
				      void *getter_arg,
				      const char *path,
				      const char *interface_name,
				      const char *property_name);

/* Methods internal to the dbus control interface */
u32 wpa_dbus_next_objid(struct ctrl_iface_dbus_new_priv *iface);


#else /* CONFIG_CTRL_IFACE_DBUS_NEW */

static inline void wpa_dbus_signal_property_changed(
	struct ctrl_iface_dbus_new_priv *iface,
	WPADBusPropertyAccessor property_getter, void *getter_arg,
	const char *path, const char *interface_name,
	const char *property_name)
{
}

#endif /* CONFIG_CTRL_IFACE_DBUS_NEW */

#endif /* WPA_DBUS_CTRL_H */
