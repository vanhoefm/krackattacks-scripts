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

typedef DBusMessage * (* WPADBusMethodHandler)(DBusMessage *message,
					       void *user_data);
typedef void (* WPADBusArgumentFreeFunction)(void *handler_arg);

typedef DBusMessage * (* WPADBusPropertyAccessor)(DBusMessage *message,
						  const void *user_data);

struct wpa_dbus_object_desc {
	DBusConnection *connection;

	/* list of methods, properties and signals registered with object */
	struct wpa_dbus_method_desc *methods;
	struct wpa_dbus_signal_desc *signals;
	struct wpa_dbus_property_desc *properties;

	/* argument for method handlers and properties
	 * getter and setter functions */
	void *user_data;
	/* function used to free above argument */
	WPADBusArgumentFreeFunction user_data_free_func;
};

enum dbus_prop_access { R, W, RW };

enum dbus_arg_direction { ARG_IN, ARG_OUT };

struct wpa_dbus_argument {
	char *name;
	char *type;
	enum dbus_arg_direction dir;
};

#define END_ARGS { NULL, NULL, ARG_IN }

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

int wpa_dbus_ctrl_iface_init(struct wpas_dbus_priv *iface, char *dbus_path,
			     char *dbus_service,
			     struct wpa_dbus_object_desc *obj_desc);

int wpa_dbus_register_object_per_iface(
	struct wpas_dbus_priv *ctrl_iface,
	const char *path, const char *ifname,
	struct wpa_dbus_object_desc *obj_desc);

int wpa_dbus_unregister_object_per_iface(
	struct wpas_dbus_priv *ctrl_iface,
	const char *path);

int wpa_dbus_method_register(struct wpa_dbus_object_desc *obj_dsc,
			     const char *dbus_interface,
			     const char *dbus_method,
			     WPADBusMethodHandler method_handler,
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
	enum dbus_prop_access _access);

void wpa_dbus_signal_property_changed(struct wpas_dbus_priv *iface,
				      WPADBusPropertyAccessor property_getter,
				      void *getter_arg,
				      const char *path,
				      const char *interface_name,
				      const char *property_name);

void wpa_dbus_get_object_properties(struct wpas_dbus_priv *iface,
				    const char *path, const char *interface,
				    DBusMessageIter *dict_iter);

#endif /* WPA_DBUS_CTRL_H */
