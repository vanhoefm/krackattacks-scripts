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

#include "includes.h"

#include "common.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "ctrl_iface_dbus_new_helpers.h"
#include "ctrl_iface_dbus_new.h"
#include "ctrl_iface_dbus_new_handlers.h"
#include "notify.h"
#include "eap_peer/eap_methods.h"
#include "dbus_dict_helpers.h"
#include "ieee802_11_defs.h"
#include "wpas_glue.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "wps_supplicant.h"

extern int wpa_debug_level;
extern int wpa_debug_show_keys;
extern int wpa_debug_timestamp;


/**
 * wpas_dbus_new_decompose_object_path - Decompose an interface object path into parts
 * @path: The dbus object path
 * @network: (out) the configured network this object path refers to, if any
 * @bssid: (out) the scanned bssid this object path refers to, if any
 * Returns: The object path of the network interface this path refers to
 *
 * For a given object path, decomposes the object path into object id, network,
 * and BSSID parts, if those parts exist.
 */
static char * wpas_dbus_new_decompose_object_path(const char *path,
						  char **network,
						  char **bssid)
{
	const unsigned int dev_path_prefix_len =
		strlen(WPAS_DBUS_NEW_PATH_INTERFACES "/");
	char *obj_path_only;
	char *next_sep;

	/* Be a bit paranoid about path */
	if (!path || os_strncmp(path, WPAS_DBUS_NEW_PATH_INTERFACES "/",
				dev_path_prefix_len))
		return NULL;

	/* Ensure there's something at the end of the path */
	if ((path + dev_path_prefix_len)[0] == '\0')
		return NULL;

	obj_path_only = os_strdup(path);
	if (obj_path_only == NULL)
		return NULL;

	next_sep = os_strchr(obj_path_only + dev_path_prefix_len, '/');
	if (next_sep != NULL) {
		const char *net_part = os_strstr(
			next_sep, WPAS_DBUS_NEW_NETWORKS_PART "/");
		const char *bssid_part = os_strstr(
			next_sep, WPAS_DBUS_NEW_BSSIDS_PART "/");

		if (network && net_part) {
			/* Deal with a request for a configured network */
			const char *net_name = net_part +
				os_strlen(WPAS_DBUS_NEW_NETWORKS_PART "/");
			*network = NULL;
			if (os_strlen(net_name))
				*network = os_strdup(net_name);
		} else if (bssid && bssid_part) {
			/* Deal with a request for a scanned BSSID */
			const char *bssid_name = bssid_part +
				os_strlen(WPAS_DBUS_NEW_BSSIDS_PART "/");
			if (strlen(bssid_name))
				*bssid = os_strdup(bssid_name);
			else
				*bssid = NULL;
		}

		/* Cut off interface object path before "/" */
		*next_sep = '\0';
	}

	return obj_path_only;
}


/**
 * wpas_dbus_error_unknown_error - Return a new InvalidArgs error message
 * @message: Pointer to incoming dbus message this error refers to
 * @arg: Optional string appended to error message
 * Returns: a dbus error message
 *
 * Convenience function to create and return an UnknownError
 */
static DBusMessage * wpas_dbus_error_unknown_error(DBusMessage *message,
						   const char *arg)
{
	return dbus_message_new_error(message, WPAS_DBUS_ERROR_UNKNOWN_ERROR,
				      arg);
}


/**
 * wpas_dbus_error_iface_unknown - Return a new invalid interface error message
 * @message: Pointer to incoming dbus message this error refers to
 * Returns: A dbus error message
 *
 * Convenience function to create and return an invalid interface error
 */
static DBusMessage * wpas_dbus_error_iface_unknown(DBusMessage *message)
{
	return dbus_message_new_error(message, WPAS_DBUS_ERROR_IFACE_UNKNOWN,
				      "wpa_supplicant knows nothing about "
				      "this interface.");
}


/**
 * wpas_dbus_error_network_unknown - Return a new NetworkUnknown error message
 * @message: Pointer to incoming dbus message this error refers to
 * Returns: a dbus error message
 *
 * Convenience function to create and return an invalid network error
 */
static DBusMessage * wpas_dbus_error_network_unknown(DBusMessage *message)
{
	return dbus_message_new_error(message, WPAS_DBUS_ERROR_NETWORK_UNKNOWN,
				      "There is no such a network in this "
				      "interface.");
}


/**
 * wpas_dbus_error_invald_args - Return a new InvalidArgs error message
 * @message: Pointer to incoming dbus message this error refers to
 * Returns: a dbus error message
 *
 * Convenience function to create and return an invalid options error
 */
static DBusMessage * wpas_dbus_error_invald_args(DBusMessage *message,
						 const char *arg)
{
	DBusMessage *reply;

	reply = dbus_message_new_error(message, WPAS_DBUS_ERROR_INVALID_ARGS,
				       "Did not receive correct message "
				       "arguments.");
	if (arg != NULL)
		dbus_message_append_args(reply, DBUS_TYPE_STRING, &arg,
					 DBUS_TYPE_INVALID);

	return reply;
}


static void free_wpa_interface(struct wpa_interface *iface)
{
	os_free((char *) iface->driver);
	os_free((char *) iface->driver_param);
	os_free((char *) iface->confname);
	os_free((char *) iface->bridge_ifname);
}


static const char *dont_quote[] = {
	"key_mgmt", "proto", "pairwise", "auth_alg", "group", "eap",
	"opensc_engine_path", "pkcs11_engine_path", "pkcs11_module_path",
	"bssid", NULL
};

static dbus_bool_t should_quote_opt(const char *key)
{
	int i = 0;
	while (dont_quote[i] != NULL) {
		if (os_strcmp(key, dont_quote[i]) == 0)
			return FALSE;
		i++;
	}
	return TRUE;
}

static struct wpa_scan_res * find_scan_result(struct bss_handler_args *bss)
{
	struct wpa_scan_results *results = bss->wpa_s->scan_res;
	size_t i;
	for (i = 0; i < results->num; i++) {
		if (!os_memcmp(results->res[i]->bssid, bss->bssid, ETH_ALEN))
			return results->res[i];
	}
	return NULL;
}


/**
 * get_iface_by_dbus_path - Get a new network interface
 * @global: Pointer to global data from wpa_supplicant_init()
 * @path: Pointer to a dbus object path representing an interface
 * Returns: Pointer to the interface or %NULL if not found
 */
static struct wpa_supplicant * get_iface_by_dbus_path(
	struct wpa_global *global, const char *path)
{
	struct wpa_supplicant *wpa_s;

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		if (os_strcmp(wpa_s->dbus_new_path, path) == 0)
			return wpa_s;
	}
	return NULL;
}


/**
 * set_network_properties - Set properties of a configured network
 * @message: Pointer to incoming dbus message
 * @ssid: wpa_ssid structure for a configured network
 * @iter: DBus message iterator containing dictionary of network
 * properties to set.
 * Returns: NULL when succeed or DBus error on failure
 *
 * Sets network configuration with parameters given id DBus dictionary
 */
static DBusMessage * set_network_properties(DBusMessage *message,
					    struct wpa_ssid *ssid,
					    DBusMessageIter *iter)
{

	struct wpa_dbus_dict_entry entry = { .type = DBUS_TYPE_STRING };
	DBusMessage *reply = NULL;
	DBusMessageIter	iter_dict;

	if (!wpa_dbus_dict_open_read(iter, &iter_dict)) {
		reply = wpas_dbus_error_invald_args(message, NULL);
		goto out;
	}

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		char *value = NULL;
		size_t size = 50;
		int ret;
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry)) {
			reply = wpas_dbus_error_invald_args(message, NULL);
			goto out;
		}
		if (entry.type == DBUS_TYPE_ARRAY &&
		    entry.array_type == DBUS_TYPE_BYTE) {
			if (entry.array_len <= 0)
				goto error;

			size = entry.array_len * 2 + 1;
			value = os_zalloc(size);
			if (value == NULL)
				goto error;

			ret = wpa_snprintf_hex(value, size,
					       (u8 *) entry.bytearray_value,
					       entry.array_len);
			if (ret <= 0)
				goto error;
		} else {
			if (entry.type == DBUS_TYPE_STRING) {
				if (should_quote_opt(entry.key)) {
					size = os_strlen(entry.str_value);
					if (size <= 0)
						goto error;

					size += 3;
					value = os_zalloc(size);
					if (value == NULL)
						goto error;

					ret = os_snprintf(value, size,
							  "\"%s\"",
							  entry.str_value);
					if (ret < 0 ||
					    (size_t) ret != (size - 1))
						goto error;
				} else {
					value = os_strdup(entry.str_value);
					if (value == NULL)
						goto error;
				}
			} else {
				if (entry.type == DBUS_TYPE_UINT32) {
					value = os_zalloc(size);
					if (value == NULL)
						goto error;

					ret = os_snprintf(value, size, "%u",
							  entry.uint32_value);
					if (ret <= 0)
						goto error;
				} else {
					if (entry.type == DBUS_TYPE_INT32) {
						value = os_zalloc(size);
						if (value == NULL)
							goto error;

						ret = os_snprintf(
							value, size, "%d",
							entry.int32_value);
						if (ret <= 0)
							goto error;
					} else
						goto error;
				}
			}
		}

		if (wpa_config_set(ssid, entry.key, value, 0) < 0)
			goto error;

		if ((os_strcmp(entry.key, "psk") == 0 &&
		     value[0] == '"' && ssid->ssid_len) ||
		    (strcmp(entry.key, "ssid") == 0 && ssid->passphrase))
			wpa_config_update_psk(ssid);

		os_free(value);
		wpa_dbus_dict_entry_clear(&entry);
		continue;

	error:
		os_free(value);
		reply = wpas_dbus_error_invald_args(message, entry.key);
		wpa_dbus_dict_entry_clear(&entry);
		break;
	}
out:
	return reply;
}


/**
 * wpas_dbus_handler_create_interface - Request registration of a network iface
 * @message: Pointer to incoming dbus message
 * @global: %wpa_supplicant global data structure
 * Returns: The object path of the new interface object,
 *          or a dbus error message with more information
 *
 * Handler function for "addInterface" method call. Handles requests
 * by dbus clients to register a network interface that wpa_supplicant
 * will manage.
 */
DBusMessage * wpas_dbus_handler_create_interface(DBusMessage *message,
						 struct wpa_global *global)
{
	struct wpa_interface iface;
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;

	os_memset(&iface, 0, sizeof(iface));

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;
	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;
		if (!strcmp(entry.key, "Driver") &&
		    (entry.type == DBUS_TYPE_STRING)) {
			iface.driver = strdup(entry.str_value);
			if (iface.driver == NULL)
				goto error;
		} else if (!strcmp(entry.key, "Ifname") &&
			   (entry.type == DBUS_TYPE_STRING)) {
			iface.ifname = strdup(entry.str_value);
			if (iface.ifname == NULL)
				goto error;
		} else if (!strcmp(entry.key, "BridgeIfname") &&
			   (entry.type == DBUS_TYPE_STRING)) {
			iface.bridge_ifname = strdup(entry.str_value);
			if (iface.bridge_ifname == NULL)
				goto error;
		} else {
			wpa_dbus_dict_entry_clear(&entry);
			goto error;
		}
		wpa_dbus_dict_entry_clear(&entry);
	}

	/*
	 * Try to get the wpa_supplicant record for this iface, return
	 * an error if we already control it.
	 */
	if (wpa_supplicant_get_iface(global, iface.ifname) != NULL) {
		reply = dbus_message_new_error(message,
					       WPAS_DBUS_ERROR_IFACE_EXISTS,
					       "wpa_supplicant already "
					       "controls this interface.");
	} else {
		struct wpa_supplicant *wpa_s;
		/* Otherwise, have wpa_supplicant attach to it. */
		if ((wpa_s = wpa_supplicant_add_iface(global, &iface))) {
			const char *path = wpas_dbus_get_path(wpa_s);
			reply = dbus_message_new_method_return(message);
			dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH,
			                         &path, DBUS_TYPE_INVALID);
		} else {
			reply = wpas_dbus_error_unknown_error(
				message, "wpa_supplicant couldn't grab this "
				"interface.");
		}
	}
	free_wpa_interface(&iface);
	return reply;

error:
	free_wpa_interface(&iface);
	return wpas_dbus_error_invald_args(message, NULL);
}


/**
 * wpas_dbus_handler_remove_interface - Request deregistration of an interface
 * @message: Pointer to incoming dbus message
 * @global: wpa_supplicant global data structure
 * Returns: a dbus message containing a UINT32 indicating success (1) or
 *          failure (0), or returns a dbus error message with more information
 *
 * Handler function for "removeInterface" method call.  Handles requests
 * by dbus clients to deregister a network interface that wpa_supplicant
 * currently manages.
 */
DBusMessage * wpas_dbus_handler_remove_interface(DBusMessage *message,
						 struct wpa_global *global)
{
	struct wpa_supplicant *wpa_s;
	char *path;
	DBusMessage *reply = NULL;

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &path,
			      DBUS_TYPE_INVALID);

	wpa_s = get_iface_by_dbus_path(global, path);
	if (wpa_s == NULL)
		reply = wpas_dbus_error_iface_unknown(message);
	else if (wpa_supplicant_remove_iface(global, wpa_s)) {
		reply = wpas_dbus_error_unknown_error(
			message, "wpa_supplicant couldn't remove this "
			"interface.");
	}

	return reply;
}


/**
 * wpas_dbus_handler_get_interface - Get the object path for an interface name
 * @message: Pointer to incoming dbus message
 * @global: %wpa_supplicant global data structure
 * Returns: The object path of the interface object,
 *          or a dbus error message with more information
 *
 * Handler function for "getInterface" method call.
 */
DBusMessage * wpas_dbus_handler_get_interface(DBusMessage *message,
					      struct wpa_global *global)
{
	DBusMessage *reply = NULL;
	const char *ifname;
	const char *path;
	struct wpa_supplicant *wpa_s;

	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &ifname,
			      DBUS_TYPE_INVALID);

	wpa_s = wpa_supplicant_get_iface(global, ifname);
	if (wpa_s == NULL)
		return wpas_dbus_error_iface_unknown(message);

	path = wpas_dbus_get_path(wpa_s);
	if (path == NULL) {
		wpa_printf(MSG_ERROR, "wpas_dbus_handler_get_interface[dbus]: "
			   "interface has no dbus object path set");
		return wpas_dbus_error_unknown_error(message, "path not set");
	}

	reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		perror("wpas_dbus_handler_get_interface[dbus]: out of memory "
		       "when creating reply");
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);
	}
	if (!dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
				      DBUS_TYPE_INVALID)) {
		perror("wpas_dbus_handler_get_interface[dbus]: out of memory "
		       "when appending argument to reply");
		dbus_message_unref(reply);
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);
	}

	return reply;
}


/**
 * wpas_dbus_getter_debug_params - Get the debug params
 * @message: Pointer to incoming dbus message
 * @global: %wpa_supplicant global data structure
 * Returns: DBus message with struct containing debug params.
 *
 * Getter for "DebugParams" property.
 */
DBusMessage * wpas_dbus_getter_debug_params(DBusMessage *message,
					    struct wpa_global *global)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, struct_iter;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_getter_network_properties[dbus] out of "
		       "memory when trying to initialize return message");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "(ibb)", &variant_iter)) {
		perror("wpas_dbus_getter_debug_params[dbus] out of memory "
		       "when trying to open variant");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_STRUCT,
					      NULL, &struct_iter)) {
		perror("wpas_dbus_getter_debug_params[dbus] out of memory "
		       "when trying to open struct");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_INT32,
					    &wpa_debug_level)) {
		perror("wpas_dbus_getter_debug_params[dbus] out of memory "
		       "when trying to append value to struct");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_BOOLEAN,
					    &wpa_debug_timestamp)) {
		perror("wpas_dbus_getter_debug_params[dbus] out of memory "
		       "when trying to append value to struct");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_BOOLEAN,
					    &wpa_debug_show_keys)) {
		perror("wpas_dbus_getter_debug_params[dbus] out of memory "
		       "when trying to append value to struct");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_close_container(&variant_iter, &struct_iter)) {
		perror("wpas_dbus_getter_debug_params[dbus] out of memory "
		       "when trying to close struct");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_close_container(&iter, &variant_iter)) {
		perror("wpas_dbus_getter_debug_params[dbus] out of memory "
		       "when trying to close variant");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_setter_debugparams - Set the debug params
 * @message: Pointer to incoming dbus message
 * @global: %wpa_supplicant global data structure
 * Returns: NULL indicating success or a dbus error message with more
 * information
 *
 * Setter for "DebugParams" property.
 */
DBusMessage * wpas_dbus_setter_debug_params(DBusMessage *message,
					    struct wpa_global *global)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, struct_iter;
	int debug_level;
	dbus_bool_t debug_timestamp;
	dbus_bool_t debug_show_keys;

	if (!dbus_message_iter_init(message, &iter)) {
		perror("wpas_dbus_handler_add_blob[dbus] out of memory when "
		       "trying to initialize message iterator");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}
	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);

	dbus_message_iter_recurse(&iter, &variant_iter);

	if (dbus_message_iter_get_arg_type(&variant_iter) != DBUS_TYPE_STRUCT)
	{
		reply = wpas_dbus_error_invald_args(
			message, "Argument must by a structure");
		goto out;
	}

	dbus_message_iter_recurse(&variant_iter, &struct_iter);


	if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_INT32) {
		reply = wpas_dbus_error_invald_args(
			message, "First struct argument must by an INT32");
		goto out;
	}

	dbus_message_iter_get_basic(&struct_iter, &debug_level);
	if (!dbus_message_iter_next(&struct_iter)) {
		reply = wpas_dbus_error_invald_args(
			message, "Not enough elements in struct");
		goto out;
	}

	if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_BOOLEAN)
	{
		reply = wpas_dbus_error_invald_args(
			message, "Second struct argument must by a boolean");
		goto out;
	}
	dbus_message_iter_get_basic(&struct_iter, &debug_timestamp);
	if (!dbus_message_iter_next(&struct_iter)) {
		reply = wpas_dbus_error_invald_args(
			message, "Not enough elements in struct");
		goto out;
	}

	if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_BOOLEAN)
	{
		reply = wpas_dbus_error_invald_args(
			message, "Third struct argument must by an boolean");
		goto out;
	}
	dbus_message_iter_get_basic(&struct_iter, &debug_show_keys);

	if (wpa_supplicant_set_debug_params(global, debug_level,
					    debug_timestamp ? 1 : 0,
					    debug_show_keys ? 1 : 0)) {
		reply = wpas_dbus_error_invald_args(
			message, "Wrong debug level value");
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_getter_interfaces - Request registered interfaces list
 * @message: Pointer to incoming dbus message
 * @global: %wpa_supplicant global data structure
 * Returns: The object paths array containing registered interfaces
 * objects paths or DBus error on failure
 *
 * Getter for "Interfaces" property. Handles requests
 * by dbus clients to return list of registered interfaces objects
 * paths
 */
DBusMessage * wpas_dbus_getter_interfaces(DBusMessage *message,
					  struct wpa_global *global)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, array_iter;
	const char *path;
	struct wpa_supplicant *wpa_s;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_getter_interfaces[dbus] out of memory "
		       "when trying to initialize return message");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "ao", &variant_iter)) {
		perror("wpas_dbus_getter_interfaces[dbus] out of memory "
		       "when trying to open variant");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}
	if (!dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
					      "o", &array_iter)) {
		perror("wpas_dbus_getter_interfaces[dbus] out of memory "
		       "when trying to open array");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		path = wpas_dbus_get_path(wpa_s);
		if (!dbus_message_iter_append_basic(&array_iter,
						    DBUS_TYPE_OBJECT_PATH,
						    &path)) {
			perror("wpas_dbus_getter_interfaces[dbus] out of "
			       "memory when trying to append interface path");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}
	}

	if (!dbus_message_iter_close_container(&variant_iter, &array_iter)) {
		perror("wpas_dbus_getter_interfaces[dbus] out of memory "
		       "when trying to close array");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}
	if (!dbus_message_iter_close_container(&iter, &variant_iter)) {
		perror("wpas_dbus_getter_interfaces[dbus] out of memory "
		       "when trying to close variant");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_getter_eap_methods - Request supported EAP methods list
 * @message: Pointer to incoming dbus message
 * @nothing: not used argument. may be NULL or anything else
 * Returns: The object paths array containing supported EAP methods
 * represented by strings or DBus error on failure
 *
 * Getter for "EapMethods" property. Handles requests
 * by dbus clients to return list of strings with supported EAP methods
 */
DBusMessage * wpas_dbus_getter_eap_methods(DBusMessage *message, void *nothing)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, array_iter;
	char **eap_methods;
	size_t num_items;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_getter_eap_methods[dbus] out of memory "
		       "when trying to initialize return message");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "as", &variant_iter)) {
		perror("wpas_dbus_getter_eap_methods[dbus] out of memory "
		       "when trying to open variant");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
					      "s", &array_iter)) {
		perror("wpas_dbus_getter_eap_methods[dbus] out of memory "
		       "when trying to open variant");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	eap_methods = eap_get_names_as_string_array(&num_items);
	if (eap_methods) {
		size_t i;
		int err = 0;
		for (i = 0; i < num_items; i++) {
			if (!dbus_message_iter_append_basic(&array_iter,
							    DBUS_TYPE_STRING,
							    &(eap_methods[i])))
				err = 1;
			os_free(eap_methods[i]);
		}
		os_free(eap_methods);

		if (err) {
			wpa_printf(MSG_ERROR, "wpas_dbus_getter_eap_methods"
				   "[dbus] out of memory when adding to "
				   "array");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}
	}

	if (!dbus_message_iter_close_container(&variant_iter, &array_iter)) {
		perror("wpas_dbus_getter_eap_methods[dbus] "
		       "out of memory when trying to close array");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
			goto out;
	}
	if (!dbus_message_iter_close_container(&iter, &variant_iter)) {
		perror("wpas_dbus_getter_eap_methods[dbus] "
		       "out of memory when trying to close variant");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_handler_scan - Request a wireless scan on an interface
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: NULL indicating success or DBus error message on failure
 *
 * Handler function for "Scan" method call of a network device. Requests
 * that wpa_supplicant perform a wireless scan as soon as possible
 * on a particular wireless interface.
 */
DBusMessage * wpas_dbus_handler_scan(DBusMessage *message,
				     struct wpa_supplicant *wpa_s)
{
	DBusMessage * reply = NULL;
	DBusMessageIter iter, dict_iter, entry_iter, variant_iter,
		array_iter, sub_array_iter;
	char *key, *val, *type = NULL;
	int len;
	int freqs_num = 0;
	int ssids_num = 0;
	int ies_len = 0;

	struct wpa_driver_scan_params params;

	os_memset(&params, 0, sizeof(params));

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_recurse(&iter, &dict_iter);

	while (dbus_message_iter_get_arg_type(&dict_iter) ==
			DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(&dict_iter, &entry_iter);
		dbus_message_iter_get_basic(&entry_iter, &key);
		dbus_message_iter_next(&entry_iter);
		dbus_message_iter_recurse(&entry_iter, &variant_iter);

		if (!os_strcmp(key, "Type")) {
			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_STRING) {
				wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan"
					   "[dbus]: Type must be a string");
				reply = wpas_dbus_error_invald_args(
					message, "Wrong Type value type. "
					"String required");
				goto out;
			}

			dbus_message_iter_get_basic(&variant_iter, &type);

		} else if (!strcmp(key, "SSIDs")) {
			struct wpa_driver_scan_ssid *ssids = params.ssids;

			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_ARRAY) {

				wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan"
					   "[dbus]: ssids must be an array of "
					   "arrays of bytes");
				reply = wpas_dbus_error_invald_args(
					message,
					"Wrong SSIDs value type. "
					"Array of arrays of bytes required");
				goto out;
			}

			dbus_message_iter_recurse(&variant_iter, &array_iter);

			if (dbus_message_iter_get_arg_type(&array_iter) !=
			    DBUS_TYPE_ARRAY ||
			    dbus_message_iter_get_element_type(&array_iter) !=
			    DBUS_TYPE_BYTE) {
				wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan"
					   "[dbus]: ssids must be an array of "
					   "arrays of bytes");
				reply = wpas_dbus_error_invald_args(
					message,
					"Wrong SSIDs value type. "
					"Array of arrays of bytes required");
				goto out;
			}

			while (dbus_message_iter_get_arg_type(&array_iter) ==
			       DBUS_TYPE_ARRAY) {
				if (ssids_num >= WPAS_MAX_SCAN_SSIDS) {
					wpa_printf(MSG_DEBUG,
						   "wpas_dbus_handler_scan"
						   "[dbus]: To many ssids "
						   "specified on scan dbus "
						   "call");
					reply = wpas_dbus_error_invald_args(
						message,
						"To many ssids specified. "
						"Specify at most four");
					goto out;
				}

				dbus_message_iter_recurse(&array_iter,
							  &sub_array_iter);


				dbus_message_iter_get_fixed_array(
					&sub_array_iter, &val, &len);

				if (len == 0) {
					dbus_message_iter_next(&array_iter);
					continue;
				}

				ssids[ssids_num].ssid =
					os_malloc(sizeof(u8) * len);
				if (!ssids[ssids_num].ssid) {
					wpa_printf(MSG_DEBUG,
						   "wpas_dbus_handler_scan"
						   "[dbus]: out of memory. "
						   "Cannot allocate memory "
						   "for SSID");
					reply = dbus_message_new_error(
						message,
						DBUS_ERROR_NO_MEMORY, NULL);
					goto out;
				}
				os_memcpy((void *) ssids[ssids_num].ssid, val,
					  sizeof(u8) * len);
				ssids[ssids_num].ssid_len = len;

				dbus_message_iter_next(&array_iter);
				ssids_num++;;
			}

			params.num_ssids = ssids_num;
		} else if (!strcmp(key, "IEs")) {
			u8 *ies = NULL;

			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_ARRAY) {

				wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan"
					   "[dbus]: ies must be an array of "
					   "arrays of bytes");
				reply = wpas_dbus_error_invald_args(
					message,
					"Wrong IEs value type. "
					"Array of arrays of bytes required");
				goto out;
			}

			dbus_message_iter_recurse(&variant_iter, &array_iter);

			if (dbus_message_iter_get_arg_type(&array_iter) !=
			    DBUS_TYPE_ARRAY ||
			    dbus_message_iter_get_element_type(&array_iter) !=
			    DBUS_TYPE_BYTE) {
				wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan"
					   "[dbus]: ies must be an array of "
					   "arrays of bytes");
				reply = wpas_dbus_error_invald_args(
					message, "Wrong IEs value type. Array "
					"required");
				goto out;
			}

			while (dbus_message_iter_get_arg_type(&array_iter) ==
			       DBUS_TYPE_ARRAY) {
				dbus_message_iter_recurse(&array_iter,
							  &sub_array_iter);

				dbus_message_iter_get_fixed_array(
					&sub_array_iter, &val, &len);

				if (len == 0) {
					dbus_message_iter_next(&array_iter);
					continue;
				}

				ies = os_realloc(ies, ies_len + len);
				if (!ies) {
					wpa_printf(MSG_DEBUG,
						   "wpas_dbus_handler_scan"
						   "[dbus]: out of memory. "
						   "Cannot allocate memory "
						   "for IE");
					reply = dbus_message_new_error(
						message,
						DBUS_ERROR_NO_MEMORY, NULL);
					goto out;
				}
				os_memcpy(ies + ies_len, val,
					  sizeof(u8) * len);
				ies_len += len;

				dbus_message_iter_next(&array_iter);
			}

			params.extra_ies = ies;
			params.extra_ies_len = ies_len;
		} else if (!strcmp(key, "Channels")) {
			int *freqs = NULL;

			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_ARRAY) {

				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_scan[dbus]: "
					   "Channels must be an array of "
					   "structs");
				reply = wpas_dbus_error_invald_args(
					message,
					"Wrong Channels value type. "
					"Array of structs required");
				goto out;
			}

			dbus_message_iter_recurse(&variant_iter, &array_iter);

			if (dbus_message_iter_get_arg_type(&array_iter) !=
			    DBUS_TYPE_STRUCT) {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_scan[dbus]: "
					   "Channels must be an array of "
					   "structs");
				reply = wpas_dbus_error_invald_args(
					message,
					"Wrong Channels value type. "
					"Array of structs required");
				goto out;
			}

			while (dbus_message_iter_get_arg_type(&array_iter) ==
			       DBUS_TYPE_STRUCT) {
				int freq, width;

				dbus_message_iter_recurse(&array_iter,
							  &sub_array_iter);

				if (dbus_message_iter_get_arg_type(
					    &sub_array_iter) !=
				    DBUS_TYPE_UINT32) {
					wpa_printf(MSG_DEBUG,
						   "wpas_dbus_handler_scan"
						   "[dbus]: Channel must by "
						   "specified by struct of "
						   "two UINT32s %c",
						   dbus_message_iter_get_arg_type(&sub_array_iter));
					reply = wpas_dbus_error_invald_args(
						message,
						"Wrong Channel struct. Two "
						"UINT32s required");
					os_free(freqs);
					goto out;
				}
				dbus_message_iter_get_basic(&sub_array_iter,
							    &freq);

				if (!dbus_message_iter_next(&sub_array_iter) ||
				    dbus_message_iter_get_arg_type(
					    &sub_array_iter) !=
				    DBUS_TYPE_UINT32) {
					wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan[dbus]: "
						   "Channel must by specified by struct of "
						   "two UINT32s");
					reply = wpas_dbus_error_invald_args(message,
									    "Wrong Channel struct. Two UINT32s required");
					os_free(freqs);
					goto out;
				}

				dbus_message_iter_get_basic(&sub_array_iter, &width);

#define FREQS_ALLOC_CHUNK 32
				if (freqs_num % FREQS_ALLOC_CHUNK == 0) {
					freqs = os_realloc(freqs,
							   sizeof(int) * (freqs_num + FREQS_ALLOC_CHUNK));
				}
				if (!freqs) {
					wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan[dbus]: "
						   "out of memory. can't allocate memory for freqs");
					reply = dbus_message_new_error(
						message,
						DBUS_ERROR_NO_MEMORY, NULL);
					goto out;
				}

				freqs[freqs_num] = freq;

				freqs_num++;
				dbus_message_iter_next(&array_iter);
			}

			freqs = os_realloc(freqs,
					   sizeof(int) * (freqs_num + 1));
			if (!freqs) {
				wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan[dbus]: "
					   "out of memory. can't allocate memory for freqs");
				reply = dbus_message_new_error(
					message, DBUS_ERROR_NO_MEMORY, NULL);
				goto out;
			}
			freqs[freqs_num] = 0;

			params.freqs = freqs;
		} else {
			wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan[dbus]: "
				   "Unknown argument %s", key);
			reply = wpas_dbus_error_invald_args(
				message,
				"Wrong Channel struct. Two UINT32s required");
			goto out;
		}

		dbus_message_iter_next(&dict_iter);
	}

	if (!type) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan[dbus]: "
			   "Scan type not specified");
		reply = wpas_dbus_error_invald_args(message, key);
		goto out;
	}

	if (!strcmp(type, "passive")) {
		if (ssids_num || ies_len) {
			wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan[dbus]: "
				   "SSIDs or IEs specified for passive scan.");
			reply = wpas_dbus_error_invald_args(
				message, "You can specify only Channels in "
				"passive scan");
			goto out;
		} else if (freqs_num > 0) {
			/* wildcard ssid */
			params.num_ssids++;
			wpa_supplicant_trigger_scan(wpa_s, &params);
		} else {
			wpa_s->scan_req = 2;
			wpa_supplicant_req_scan(wpa_s, 0, 0);
		}
	} else if (!strcmp(type, "active")) {
		wpa_supplicant_trigger_scan(wpa_s, &params);
	} else {
		wpa_printf(MSG_DEBUG, "wpas_dbus_handler_scan[dbus]: "
			   "Unknown scan type: %s", type);
		reply = wpas_dbus_error_invald_args(message,
						    "Wrong scan type");
		goto out;
	}

out:
	os_free((u8 *) params.extra_ies);
	os_free(params.freqs);
	return reply;
}


/*
 * wpas_dbus_handler_disconnect - Terminate the current connection
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: NotConnected DBus error message if already not connected
 * or NULL otherwise.
 *
 * Handler function for "Disconnect" method call of network interface.
 */
DBusMessage * wpas_dbus_handler_disconnect(DBusMessage *message,
					   struct wpa_supplicant *wpa_s)
{
	if (wpa_s->current_ssid != NULL) {
		wpa_s->disconnected = 1;
		wpa_supplicant_disassociate(wpa_s, WLAN_REASON_DEAUTH_LEAVING);

		return NULL;
	}

	return dbus_message_new_error(message, WPAS_DBUS_ERROR_NOT_CONNECTED,
				      "This interface is not connected");
}


/**
 * wpas_dbus_new_iface_add_network - Add a new configured network
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing the object path of the new network
 *
 * Handler function for "AddNetwork" method call of a network interface.
 */
DBusMessage * wpas_dbus_handler_add_network(DBusMessage *message,
					    struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter	iter;
	struct wpa_ssid *ssid = NULL;
	char *path = NULL;

	path = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
	if (path == NULL) {
		perror("wpas_dbus_handler_add_network[dbus]: out of "
		       "memory.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}

	dbus_message_iter_init(message, &iter);

	ssid = wpa_config_add_network(wpa_s->conf);
	if (ssid == NULL) {
		wpa_printf(MSG_ERROR, "wpas_dbus_handler_add_network[dbus]: "
			   "can't add new interface.");
		reply = wpas_dbus_error_unknown_error(
			message,
			"wpa_supplicant could not add "
			"a network on this interface.");
		goto err;
	}
	wpas_notify_network_added(wpa_s, ssid);
	ssid->disabled = 1;
	wpa_config_set_network_defaults(ssid);

	reply = set_network_properties(message, ssid, &iter);
	if (reply) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_handler_add_network[dbus]:"
			   "control interface couldn't set network "
			   "properties");
		goto err;
	}

	/* Construct the object path for this network. */
	os_snprintf(path, WPAS_DBUS_OBJECT_PATH_MAX,
		    "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%d",
		    wpas_dbus_get_path(wpa_s),
		    ssid->id);

	reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		perror("wpas_dbus_handler_add_network[dbus]: out of memory "
		       "when creating reply");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}
	if (!dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
				      DBUS_TYPE_INVALID)) {
		perror("wpas_dbus_handler_add_network[dbus]: out of memory "
		       "when appending argument to reply");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}

	os_free(path);
	return reply;

err:
	if (ssid) {
		wpas_notify_network_removed(wpa_s, ssid);
		wpa_config_remove_network(wpa_s->conf, ssid->id);
	}
	os_free(path);
	return reply;
}


/**
 * wpas_dbus_handler_remove_network - Remove a configured network
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: NULL on success or dbus error on failure
 *
 * Handler function for "RemoveNetwork" method call of a network interface.
 */
DBusMessage * wpas_dbus_handler_remove_network(DBusMessage *message,
					       struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	const char *op;
	char *iface = NULL, *net_id = NULL;
	int id;
	struct wpa_ssid *ssid;

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &op,
			      DBUS_TYPE_INVALID);

	/* Extract the network ID and ensure the network */
	/* is actually a child of this interface */
	iface = wpas_dbus_new_decompose_object_path(op, &net_id, NULL);
	if (iface == NULL || strcmp(iface, wpas_dbus_get_path(wpa_s)) != 0) {
		reply = wpas_dbus_error_invald_args(message, op);
		goto out;
	}

	id = strtoul(net_id, NULL, 10);
	if (errno == EINVAL) {
		reply = wpas_dbus_error_invald_args(message, op);
		goto out;
	}

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL) {
		reply = wpas_dbus_error_network_unknown(message);
		goto out;
	}

	wpas_notify_network_removed(wpa_s, ssid);

	if (wpa_config_remove_network(wpa_s->conf, id) < 0) {
		wpa_printf(MSG_ERROR,
			   "wpas_dbus_handler_remove_network[dbus]: "
			   "error occurred when removing network %d", id);
		reply = wpas_dbus_error_unknown_error(
			message, "error removing the specified network on "
			"this interface.");
		goto out;
	}

	if (ssid == wpa_s->current_ssid)
		wpa_supplicant_disassociate(wpa_s, WLAN_REASON_DEAUTH_LEAVING);

out:
	os_free(iface);
	os_free(net_id);
	return reply;
}


/**
 * wpas_dbus_handler_select_network - Attempt association with a network
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: NULL on success or dbus error on failure
 *
 * Handler function for "SelectNetwork" method call of network interface.
 */
DBusMessage * wpas_dbus_handler_select_network(DBusMessage *message,
					       struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	const char *op;
	char *iface = NULL, *net_id = NULL;
	int id;
	struct wpa_ssid *ssid;

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &op,
			      DBUS_TYPE_INVALID);

	/* Extract the network ID and ensure the network */
	/* is actually a child of this interface */
	iface = wpas_dbus_new_decompose_object_path(op, &net_id, NULL);
	if (iface == NULL || strcmp(iface, wpas_dbus_get_path(wpa_s)) != 0) {
		reply = wpas_dbus_error_invald_args(message, op);
		goto out;
	}

	id = strtoul(net_id, NULL, 10);
	if (errno == EINVAL) {
		reply = wpas_dbus_error_invald_args(message, op);
		goto out;
	}

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL) {
		reply = wpas_dbus_error_network_unknown(message);
		goto out;
	}

	/* Finally, associate with the network */
	wpa_supplicant_select_network(wpa_s, ssid);

out:
	os_free(iface);
	os_free(net_id);
	return reply;
}


/**
 * wpas_dbus_handler_add_blob - Store named binary blob (ie, for certificates)
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: A dbus message containing an error on failure or NULL on success
 *
 * Asks wpa_supplicant to internally store a binary blobs.
 */
DBusMessage * wpas_dbus_handler_add_blob(DBusMessage *message,
					 struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter	iter, array_iter;

	char *blob_name;
	u8 *blob_data;
	int blob_len;
	struct wpa_config_blob *blob = NULL;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_get_basic(&iter, &blob_name);

	if (wpa_config_get_blob(wpa_s->conf, blob_name)) {
		return dbus_message_new_error(message,
					      WPAS_DBUS_ERROR_BLOB_EXISTS,
					      NULL);
	}

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &array_iter);

	dbus_message_iter_get_fixed_array(&array_iter, &blob_data, &blob_len);

	blob = os_zalloc(sizeof(*blob));
	if (!blob) {
		perror("wpas_dbus_handler_add_blob[dbus] out of memory when "
		       "trying to allocate blob struct");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}

	blob->data = os_malloc(blob_len);
	if (!blob->data) {
		perror("wpas_dbus_handler_add_blob[dbus] out of memory when "
		       "trying to allocate blob data");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}
	os_memcpy(blob->data, blob_data, blob_len);

	blob->len = blob_len;
	blob->name = strdup(blob_name);
	if (!blob->name) {
		perror("wpas_dbus_handler_add_blob[dbus] out of memory when "
		       "trying to copy blob name");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}

	wpa_config_set_blob(wpa_s->conf, blob);
	wpas_notify_blob_added(wpa_s, blob->name);

	return reply;

err:
	if (blob) {
		os_free(blob->name);
		os_free(blob->data);
		os_free(blob);
	}
	return reply;
}


/**
 * wpas_dbus_handler_get_blob - Get named binary blob (ie, for certificates)
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: A dbus message containing array of bytes (blob)
 *
 * Gets one wpa_supplicant's binary blobs.
 */
DBusMessage * wpas_dbus_handler_get_blob(DBusMessage *message,
					 struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter	iter, array_iter;

	char *blob_name;
	const struct wpa_config_blob *blob;

	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &blob_name,
			      DBUS_TYPE_INVALID);

	blob = wpa_config_get_blob(wpa_s->conf, blob_name);
	if (!blob) {
		return dbus_message_new_error(message,
					      WPAS_DBUS_ERROR_BLOB_UNKNOWN,
					      "Blob id not set");
	}

	reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_handler_get_blob[dbus] out of memory when "
		       "trying to allocate return message");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_BYTE_AS_STRING,
					      &array_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_handler_get_blob[dbus] out of memory when "
		       "trying to open array");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_append_fixed_array(&array_iter, DBUS_TYPE_BYTE,
						  &(blob->data), blob->len)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_handler_get_blob[dbus] out of memory when "
		       "trying to append data to array");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_close_container(&iter, &array_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_handler_get_blob[dbus] out of memory when "
		       "trying to close array");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_remove_handler_remove_blob - Remove named binary blob
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: NULL on success or dbus error
 *
 * Asks wpa_supplicant to internally remove a binary blobs.
 */
DBusMessage * wpas_dbus_handler_remove_blob(DBusMessage *message,
					    struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	char *blob_name;

	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &blob_name,
			      DBUS_TYPE_INVALID);

	if (wpa_config_remove_blob(wpa_s->conf, blob_name)) {
		return dbus_message_new_error(message,
					      WPAS_DBUS_ERROR_BLOB_UNKNOWN,
					      "Blob id not set");
	}
	wpas_notify_blob_removed(wpa_s, blob_name);

	return reply;

}


/**
 * wpas_dbus_getter_capabilities - Return interface capabilities
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing a dict of strings
 *
 * Getter for "Capabilities" property of an interface.
 */
DBusMessage * wpas_dbus_getter_capabilities(DBusMessage *message,
					    struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	struct wpa_driver_capa capa;
	int res;
	DBusMessageIter iter, iter_dict;
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array,
		variant_iter;
	const char *scans[] = { "active", "passive", "ssid" };
	const char *modes[] = { "infrastructure", "ad-hoc", "ap" };
	int n = sizeof(modes) / sizeof(char *);

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (!reply)
		goto nomem;

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "a{sv}", &variant_iter))
		goto nomem;

	if (!wpa_dbus_dict_open_write(&variant_iter, &iter_dict))
		goto nomem;

	res = wpa_drv_get_capa(wpa_s, &capa);

	/***** pairwise cipher */
	if (res < 0) {
		const char *args[] = {"ccmp", "tkip", "none"};
		if (!wpa_dbus_dict_append_string_array(
			    &iter_dict, "Pairwise", args,
			    sizeof(args) / sizeof(char*)))
			goto nomem;
	} else {
		if (!wpa_dbus_dict_begin_string_array(&iter_dict, "Pairwise",
						      &iter_dict_entry,
						      &iter_dict_val,
						      &iter_array))
			goto nomem;

		if (capa.enc & WPA_DRIVER_CAPA_ENC_CCMP) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "ccmp"))
				goto nomem;
		}

		if (capa.enc & WPA_DRIVER_CAPA_ENC_TKIP) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "tkip"))
				goto nomem;
		}

		if (capa.key_mgmt & WPA_DRIVER_CAPA_KEY_MGMT_WPA_NONE) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "none"))
				goto nomem;
		}

		if (!wpa_dbus_dict_end_string_array(&iter_dict,
						    &iter_dict_entry,
						    &iter_dict_val,
						    &iter_array))
			goto nomem;
	}

	/***** group cipher */
	if (res < 0) {
		const char *args[] = {
			"ccmp", "tkip", "wep104", "wep40"
		};
		if (!wpa_dbus_dict_append_string_array(
			    &iter_dict, "Group", args,
			    sizeof(args) / sizeof(char*)))
			goto nomem;
	} else {
		if (!wpa_dbus_dict_begin_string_array(&iter_dict, "Group",
						      &iter_dict_entry,
						      &iter_dict_val,
						      &iter_array))
			goto nomem;

		if (capa.enc & WPA_DRIVER_CAPA_ENC_CCMP) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "ccmp"))
				goto nomem;
		}

		if (capa.enc & WPA_DRIVER_CAPA_ENC_TKIP) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "tkip"))
				goto nomem;
		}

		if (capa.enc & WPA_DRIVER_CAPA_ENC_WEP104) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "wep104"))
				goto nomem;
		}

		if (capa.enc & WPA_DRIVER_CAPA_ENC_WEP40) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "wep40"))
				goto nomem;
		}

		if (!wpa_dbus_dict_end_string_array(&iter_dict,
						    &iter_dict_entry,
						    &iter_dict_val,
						    &iter_array))
			goto nomem;
	}

	/***** key management */
	if (res < 0) {
		const char *args[] = {
			"wpa-psk", "wpa-eap", "ieee8021x", "wpa-none",
#ifdef CONFIG_WPS
			"wps",
#endif /* CONFIG_WPS */
			"none"
		};
		if (!wpa_dbus_dict_append_string_array(
			    &iter_dict, "KeyMgmt", args,
			    sizeof(args) / sizeof(char*)))
			goto nomem;
	} else {
		if (!wpa_dbus_dict_begin_string_array(&iter_dict, "KeyMgmt",
						      &iter_dict_entry,
						      &iter_dict_val,
						      &iter_array))
			goto nomem;

		if (!wpa_dbus_dict_string_array_add_element(&iter_array,
							    "none"))
			goto nomem;

		if (!wpa_dbus_dict_string_array_add_element(&iter_array,
							    "ieee8021x"))
			goto nomem;

		if (capa.key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA |
				     WPA_DRIVER_CAPA_KEY_MGMT_WPA2)) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "wpa-eap"))
				goto nomem;
		}

		if (capa.key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
				     WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK)) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "wpa-psk"))
				goto nomem;
		}

		if (capa.key_mgmt & WPA_DRIVER_CAPA_KEY_MGMT_WPA_NONE) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "wpa-none"))
				goto nomem;
		}


#ifdef CONFIG_WPS
		if (!wpa_dbus_dict_string_array_add_element(&iter_array,
							    "wps"))
			goto nomem;
#endif /* CONFIG_WPS */

		if (!wpa_dbus_dict_end_string_array(&iter_dict,
						    &iter_dict_entry,
						    &iter_dict_val,
						    &iter_array))
			goto nomem;
	}

	/***** WPA protocol */
	if (res < 0) {
		const char *args[] = { "rsn", "wpa" };
		if (!wpa_dbus_dict_append_string_array(
			    &iter_dict, "Protocol", args,
			    sizeof(args) / sizeof(char*)))
			goto nomem;
	} else {
		if (!wpa_dbus_dict_begin_string_array(&iter_dict, "Protocol",
						      &iter_dict_entry,
						      &iter_dict_val,
						      &iter_array))
			goto nomem;

		if (capa.key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
				     WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK)) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "rsn"))
				goto nomem;
		}

		if (capa.key_mgmt & (WPA_DRIVER_CAPA_KEY_MGMT_WPA |
				     WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK)) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "wpa"))
				goto nomem;
		}

		if (!wpa_dbus_dict_end_string_array(&iter_dict,
						    &iter_dict_entry,
						    &iter_dict_val,
						    &iter_array))
			goto nomem;
	}

	/***** auth alg */
	if (res < 0) {
		const char *args[] = { "open", "shared", "leap" };
		if (!wpa_dbus_dict_append_string_array(
			    &iter_dict, "AuthAlg", args,
			    sizeof(args) / sizeof(char*)))
			goto nomem;
	} else {
		if (!wpa_dbus_dict_begin_string_array(&iter_dict, "AuthAlg",
						      &iter_dict_entry,
						      &iter_dict_val,
						      &iter_array))
			goto nomem;

		if (capa.auth & (WPA_DRIVER_AUTH_OPEN)) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "open"))
				goto nomem;
		}

		if (capa.auth & (WPA_DRIVER_AUTH_SHARED)) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "shared"))
				goto nomem;
		}

		if (capa.auth & (WPA_DRIVER_AUTH_LEAP)) {
			if (!wpa_dbus_dict_string_array_add_element(
				    &iter_array, "leap"))
				goto nomem;
		}

		if (!wpa_dbus_dict_end_string_array(&iter_dict,
						    &iter_dict_entry,
						    &iter_dict_val,
						    &iter_array))
			goto nomem;
	}

	/***** Scan */
	if (!wpa_dbus_dict_append_string_array(&iter_dict, "Scan", scans,
					       sizeof(scans) / sizeof(char *)))
		goto nomem;

	/***** Modes */
	if (res < 0 || !(capa.flags & WPA_DRIVER_FLAGS_AP))
		n--; /* exclude ap mode if it is not supported by the driver */
	if (!wpa_dbus_dict_append_string_array(&iter_dict, "Modes", modes, n))
		goto nomem;

	if (!wpa_dbus_dict_close_write(&variant_iter, &iter_dict))
		goto nomem;
	if (!dbus_message_iter_close_container(&iter, &variant_iter))
		goto nomem;

	return reply;

nomem:
	if (reply)
		dbus_message_unref(reply);

	return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}


/**
 * wpas_dbus_getter_state - Get interface state
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing a STRING representing the current
 *          interface state
 *
 * Getter for "State" property.
 */
DBusMessage * wpas_dbus_getter_state(DBusMessage *message,
				     struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	const char *str_state;
	char *state_ls, *tmp;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "s", &variant_iter)) {
			perror("wpas_dbus_getter_state[dbus] out of memory "
			       "when trying to open variant");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		str_state = wpa_supplicant_state_txt(wpa_s->wpa_state);

		/* make state string lowercase to fit new DBus API convention
		 */
		state_ls = tmp = os_strdup(str_state);
		if (!tmp) {
			perror("wpas_dbus_getter_state[dbus] out of memory "
					"when trying read state");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}
		while (*tmp) {
			*tmp = tolower(*tmp);
			tmp++;
		}

		if (!dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_STRING,
						    &state_ls)) {
			perror("wpas_dbus_getter_state[dbus] out of memory "
			       "when trying append state");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto err;
		}
		if (!dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_state[dbus] out of memory "
			       "when trying close variant");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto err;
		}
	err:
		os_free(state_ls);
	}

out:
	return reply;
}

/**
 * wpas_dbus_new_iface_get_scanning - Get interface scanning state
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing whether the interface is scanning
 *
 * Getter for "scanning" property.
 */
DBusMessage * wpas_dbus_getter_scanning(DBusMessage *message,
					struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	dbus_bool_t scanning = wpa_s->scanning ? TRUE : FALSE;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "b", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_BOOLEAN,
						    &scanning) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_scanning[dbus]: out of "
			       "memory to put scanning state into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_scanning[dbus]: out of "
		       "memory to return scanning state.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	return reply;
}


/**
 * wpas_dbus_getter_ap_scan - Control roaming mode
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A message containong value of ap_scan variable
 *
 * Getter function for "ApScan" property.
 */
DBusMessage * wpas_dbus_getter_ap_scan(DBusMessage *message,
				       struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	dbus_uint32_t ap_scan = wpa_s->conf->ap_scan;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "u", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_UINT32,
						    &ap_scan) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_ap_scan[dbus]: out of "
			       "memory to put scanning state into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_ap_scan[dbus]: out of "
		       "memory to return scanning state.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	return reply;
}


/**
 * wpas_dbus_setter_ap_scan - Control roaming mode
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: NULL
 *
 * Setter function for "ApScan" property.
 */
DBusMessage * wpas_dbus_setter_ap_scan(DBusMessage *message,
				       struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	dbus_uint32_t ap_scan;

	if (!dbus_message_iter_init(message, &iter)) {
		perror("wpas_dbus_getter_ap_scan[dbus]: out of "
		       "memory to return scanning state.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	/* omit first and second argument and get value from third*/
	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &variant_iter);

	if (dbus_message_iter_get_arg_type(&variant_iter) != DBUS_TYPE_UINT32)
	{
		reply = wpas_dbus_error_invald_args(message,
						    "UINT32 required");
		goto out;
	}
	dbus_message_iter_get_basic(&variant_iter, &ap_scan);

	if (wpa_supplicant_set_ap_scan(wpa_s, ap_scan)) {
		reply = wpas_dbus_error_invald_args(
			message,
			"ap_scan must equal 0, 1 or 2");
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_getter_ifname - Get interface name
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing a name of network interface
 * associated with with wpa_s
 *
 * Getter for "Ifname" property.
 */
DBusMessage * wpas_dbus_getter_ifname(DBusMessage *message,
				      struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	const char *ifname = NULL;

	ifname = wpa_s->ifname;
	if (ifname == NULL) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_getter_ifname[dbus]: "
			   "wpa_s has no interface name set"");");
		return wpas_dbus_error_unknown_error(message,
						     "ifname not set");
	}

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "s", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_STRING,
						    &ifname) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_ifname[dbus]: out of "
			       "memory to put ifname into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_ifname[dbus]: out of "
		       "memory to return ifname state.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	return reply;
}


/**
 * wpas_dbus_getter_driver - Get interface name
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing a name of network interface
 * driver associated with with wpa_s
 *
 * Getter for "Driver" property.
 */
DBusMessage * wpas_dbus_getter_driver(DBusMessage *message,
				      struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	const char *driver = NULL;

	if (wpa_s->driver == NULL || wpa_s->driver->name == NULL) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_getter_driver[dbus]: "
			   "wpa_s has no driver set"");");
		return wpas_dbus_error_unknown_error(message, NULL);
	}

	driver = wpa_s->driver->name;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "s", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_STRING,
						    &driver) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_driver[dbus]: out of "
			       "memory to put driver into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_driver[dbus]: out of "
		       "memory to return driver.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	return reply;
}


/**
 * wpas_dbus_getter_current_bss - Get current bss object path
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing a DBus object path to
 * current BSS
 *
 * Getter for "CurrentBSS" property.
 */
DBusMessage * wpas_dbus_getter_current_bss(DBusMessage *message,
					   struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	const char *path = wpas_dbus_get_path(wpa_s);
	char *bss_obj_path = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
	int is_bssid_known = 0;

	if (bss_obj_path == NULL) {
		perror("wpas_dbus_getter_current_bss[dbus]: out of "
		       "memory to allocate result argument.");
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);
	}

	if (!is_zero_ether_addr(wpa_s->bssid)) {
		size_t i;
		for (i = 0; i < wpa_s->scan_res->num; i++) {
			struct wpa_scan_res *res = wpa_s->scan_res->res[i];
			if (!os_memcmp(wpa_s->bssid, res->bssid, ETH_ALEN)) {
				is_bssid_known = 1;
				break;
			}
		}
	}

	if (is_bssid_known)
		os_snprintf(bss_obj_path, WPAS_DBUS_OBJECT_PATH_MAX,
			    "%s/" WPAS_DBUS_NEW_BSSIDS_PART "/"
			    WPAS_DBUS_BSSID_FORMAT,
			    path, MAC2STR(wpa_s->bssid));
	else
		os_snprintf(bss_obj_path, WPAS_DBUS_OBJECT_PATH_MAX, "/");

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "o", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_OBJECT_PATH,
						    &bss_obj_path) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_current_bss[dbus]: out of "
			       "memory to put path into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_current_bss[dbus]: out of "
		       "memory when creating reply.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	os_free(bss_obj_path);
	return reply;
}


/**
 * wpas_dbus_getter_current_network - Get current network object path
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing a DBus object path to
 * current network
 *
 * Getter for "CurrentNetwork" property.
 */
DBusMessage * wpas_dbus_getter_current_network(DBusMessage *message,
					       struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	const char *path = wpas_dbus_get_path(wpa_s);
	char *net_obj_path = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);

	if (net_obj_path == NULL) {
		perror("wpas_dbus_getter_current_network[dbus]: out of "
		       "memory to allocate result argument.");
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);
	}

	if (wpa_s->current_ssid)
		os_snprintf(net_obj_path, WPAS_DBUS_OBJECT_PATH_MAX,
			    "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%u", path,
			    wpa_s->current_ssid->id);
	else
		os_snprintf(net_obj_path, WPAS_DBUS_OBJECT_PATH_MAX, "/");

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "o", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_OBJECT_PATH,
						    &net_obj_path) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_current_network[dbus]: out "
			       "of memory to put path into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_current_network[dbus]: out of "
		       "memory when creating reply.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	os_free(net_obj_path);
	return reply;
}


/**
 * wpas_dbus_getter_bridge_ifname - Get interface name
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing a name of bridge network
 * interface associated with with wpa_s
 *
 * Getter for "BridgeIfname" property.
 */
DBusMessage * wpas_dbus_getter_bridge_ifname(DBusMessage *message,
					     struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	const char *bridge_ifname = NULL;

	bridge_ifname = wpa_s->bridge_ifname;
	if (bridge_ifname == NULL) {
		wpa_printf(MSG_ERROR, "wpas_dbus_getter_bridge_ifname[dbus]: "
			   "wpa_s has no bridge interface name set"");");
		return wpas_dbus_error_unknown_error(message, NULL);
	}

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "s", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_STRING,
						    &bridge_ifname) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {
			perror("wpas_dbus_getter_bridge_ifname[dbus]: out of "
			       "memory to put bridge ifname into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_bridge_ifname[dbus]: out of "
		       "memory to return bridge ifname.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	return reply;
}


/**
 * wpas_dbus_getter_bsss - Get array of BSSs objects
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: a dbus message containing an array of all known BSS objects
 * dbus paths
 *
 * Getter for "BSSs" property.
 */
DBusMessage * wpas_dbus_getter_bsss(DBusMessage *message,
				    struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, array_iter;
	size_t i;

	/* Ensure we've actually got scan results to return */
	if (wpa_s->scan_res == NULL &&
	    wpa_supplicant_get_scan_results(wpa_s) < 0) {
		wpa_printf(MSG_ERROR, "wpas_dbus_getter_bsss[dbus]: "
			   "An error occurred getting scan results.");
		return wpas_dbus_error_unknown_error(message, NULL);
	}

	/* Create and initialize the return message */
	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		perror("wpas_dbus_getter_bsss[dbus]: out of "
		       "memory to create return message.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "ao", &variant_iter) ||
	    !dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_OBJECT_PATH_AS_STRING,
					      &array_iter)) {
		perror("wpas_dbus_getter_bsss[dbus]: out of "
		       "memory to open container.");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	/* Loop through scan results and append each result's object path */
	for (i = 0; i < wpa_s->scan_res->num; i++) {
		struct wpa_scan_res *res = wpa_s->scan_res->res[i];
		char *path;

		path = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
		if (path == NULL) {
			perror("wpas_dbus_getter_bsss[dbus]: out of "
			       "memory.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}
		/* Construct the object path for this BSS. Note that ':'
		 * is not a valid character in dbus object paths.
		 */
		os_snprintf(path, WPAS_DBUS_OBJECT_PATH_MAX,
			    "%s/" WPAS_DBUS_NEW_BSSIDS_PART "/"
			    WPAS_DBUS_BSSID_FORMAT,
			    wpas_dbus_get_path(wpa_s),
			    MAC2STR(res->bssid));
		dbus_message_iter_append_basic(&array_iter,
					       DBUS_TYPE_OBJECT_PATH, &path);
		os_free(path);
	}

	if (!dbus_message_iter_close_container(&variant_iter, &array_iter) ||
	    !dbus_message_iter_close_container(&iter, &variant_iter)) {
		perror("wpas_dbus_getter_bsss[dbus]: out of "
		       "memory to close container.");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_getter_networks - Get array of networks objects
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: a dbus message containing an array of all configured
 * networks dbus object paths.
 *
 * Getter for "Networks" property.
 */
DBusMessage * wpas_dbus_getter_networks(DBusMessage *message,
					struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, array_iter;
	struct wpa_ssid *ssid;

	if (wpa_s->conf == NULL) {
		wpa_printf(MSG_ERROR, "wpas_dbus_getter_networks[dbus]: "
			   "An error occurred getting networks list.");
		return wpas_dbus_error_unknown_error(message, NULL);
	}

	/* Create and initialize the return message */
	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		perror("wpas_dbus_getter_networks[dbus]: out of "
		       "memory to create return message.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "ao", &variant_iter) ||
	    !dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_OBJECT_PATH_AS_STRING,
					      &array_iter)) {
		perror("wpas_dbus_getter_networks[dbus]: out of "
		       "memory to open container.");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	/* Loop through configured networks and append object path if each */
	for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next) {
		char *path;

		path = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
		if (path == NULL) {
			perror("wpas_dbus_getter_networks[dbus]: out of "
			       "memory.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		/* Construct the object path for this network. */
		os_snprintf(path, WPAS_DBUS_OBJECT_PATH_MAX,
			    "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%d",
			    wpas_dbus_get_path(wpa_s), ssid->id);
		dbus_message_iter_append_basic(&array_iter,
					       DBUS_TYPE_OBJECT_PATH, &path);
		os_free(path);
	}

	if (!dbus_message_iter_close_container(&variant_iter, &array_iter) ||
	    !dbus_message_iter_close_container(&iter, &variant_iter)) {
		perror("wpas_dbus_getter_networks[dbus]: out of "
		       "memory to close container.");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_getter_blobs - Get all blobs defined for this interface
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: a dbus message containing a dictionary of pairs (blob_name, blob)
 *
 * Getter for "Blobs" property.
 */
DBusMessage * wpas_dbus_getter_blobs(DBusMessage *message,
				     struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, dict_iter, entry_iter, array_iter;
	struct wpa_config_blob *blob;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_getter_blobs[dbus] out of memory when "
		       "trying to initialize return message");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "a{say}", &variant_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_getter_blobs[dbus] out of memory when "
		       "trying to open variant");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
					      "{say}", &dict_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_getter_blobs[dbus] out of memory when "
		       "trying to open dictionary");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	blob = wpa_s->conf->blobs;
	while (blob) {
		if (!dbus_message_iter_open_container(&dict_iter,
						      DBUS_TYPE_DICT_ENTRY,
						      NULL, &entry_iter)) {
			dbus_message_unref(reply);
			perror("wpas_dbus_getter_blobs[dbus] out of memory "
			       "when trying to open entry");
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		if (!dbus_message_iter_append_basic(&entry_iter,
						    DBUS_TYPE_STRING,
						    &(blob->name))) {
			dbus_message_unref(reply);
			perror("wpas_dbus_getter_blobs[dbus] out of memory "
			       "when trying to append blob name");
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		if (!dbus_message_iter_open_container(&entry_iter,
						      DBUS_TYPE_ARRAY,
						      DBUS_TYPE_BYTE_AS_STRING,
						      &array_iter)) {
			dbus_message_unref(reply);
			perror("wpas_dbus_getter_blobs[dbus] out of memory "
			       "when trying to open array");
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		if (!dbus_message_iter_append_fixed_array(&array_iter,
							  DBUS_TYPE_BYTE,
							  &(blob->data),
							  blob->len)) {
			dbus_message_unref(reply);
			perror("wpas_dbus_getter_blobs[dbus] out of memory "
			       "when trying to append blob data");
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		if (!dbus_message_iter_close_container(&entry_iter,
						       &array_iter)) {
			dbus_message_unref(reply);
			perror("wpas_dbus_getter_blobs[dbus] out of memory "
			       "when trying to close array");
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		if (!dbus_message_iter_close_container(&dict_iter,
						       &entry_iter)) {
			dbus_message_unref(reply);
			perror("wpas_dbus_getter_blobs[dbus] out of memory "
			       "when trying to close entry");
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}

		blob = blob->next;
	}

	if (!dbus_message_iter_close_container(&variant_iter, &dict_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_getter_blobs[dbus] out of memory when "
		       "trying to close dictionary");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_close_container(&iter, &variant_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_getter_blobs[dbus] out of memory when "
		       "trying to close variant");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_getter_bss_properties - Return the properties of a scanned bss
 * @message: Pointer to incoming dbus message
 * @bss: a pair of interface describing structure and bss' bssid
 * Returns: a dbus message containing the properties for the requested bss
 *
 * Getter for "Properties" property.
 */
DBusMessage * wpas_dbus_getter_bss_properties(DBusMessage *message,
					      struct bss_handler_args *bss)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, iter_dict, variant_iter;
	const u8 *ie;
	struct wpa_scan_res *res = find_scan_result(bss);

	if (res == NULL)
		return NULL;

	/* Dump the properties into a dbus message */
	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (!reply)
		goto error;

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "a{sv}", &variant_iter))
		goto error;

	if (!wpa_dbus_dict_open_write(&variant_iter, &iter_dict))
		goto error;

	if (!wpa_dbus_dict_append_byte_array(&iter_dict, "BSSID",
					     (const char *) res->bssid,
					     ETH_ALEN))
		goto error;

	ie = wpa_scan_get_ie(res, WLAN_EID_SSID);
	if (ie) {
		if (!wpa_dbus_dict_append_byte_array(&iter_dict, "SSID",
						     (const char *) (ie + 2),
						     ie[1]))
		goto error;
	}

	ie = wpa_scan_get_vendor_ie(res, WPA_IE_VENDOR_TYPE);
	if (ie) {
		if (!wpa_dbus_dict_append_byte_array(&iter_dict, "WPAIE",
						     (const char *) ie,
						     ie[1] + 2))
			goto error;
	}

	ie = wpa_scan_get_ie(res, WLAN_EID_RSN);
	if (ie) {
		if (!wpa_dbus_dict_append_byte_array(&iter_dict, "RSNIE",
						     (const char *) ie,
						     ie[1] + 2))
			goto error;
	}

	ie = wpa_scan_get_vendor_ie(res, WPS_IE_VENDOR_TYPE);
	if (ie) {
		if (!wpa_dbus_dict_append_byte_array(&iter_dict, "WPSIE",
						     (const char *) ie,
						     ie[1] + 2))
			goto error;
	}

	if (res->freq) {
		if (!wpa_dbus_dict_append_int32(&iter_dict, "Frequency",
						res->freq))
			goto error;
	}
	if (!wpa_dbus_dict_append_uint16(&iter_dict, "Capabilities",
					 res->caps))
		goto error;
	if (!(res->flags & WPA_SCAN_QUAL_INVALID) &&
	    !wpa_dbus_dict_append_int32(&iter_dict, "Quality", res->qual))
		goto error;
	if (!(res->flags & WPA_SCAN_NOISE_INVALID) &&
	    !wpa_dbus_dict_append_int32(&iter_dict, "Noise", res->noise))
		goto error;
	if (!(res->flags & WPA_SCAN_LEVEL_INVALID) &&
	    !wpa_dbus_dict_append_int32(&iter_dict, "Level", res->level))
		goto error;
	if (!wpa_dbus_dict_append_int32(&iter_dict, "MaxRate",
					wpa_scan_get_max_rate(res) * 500000))
		goto error;

	if (!wpa_dbus_dict_close_write(&iter, &iter_dict))
		goto error;

	return reply;

error:
	if (reply)
		dbus_message_unref(reply);
	return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}


/**
 * wpas_dbus_getter_enabled - Check whether network is enabled or disabled
 * @message: Pointer to incoming dbus message
 * @wpas_dbus_setter_enabled: wpa_supplicant structure for a network interface
 * and wpa_ssid structure for a configured network
 * Returns: DBus message with boolean indicating state of configured network
 * or DBus error on failure
 *
 * Getter for "enabled" property of a configured network.
 */
DBusMessage * wpas_dbus_getter_enabled(DBusMessage *message,
				       struct network_handler_args *net)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;

	dbus_bool_t enabled = net->ssid->disabled ? FALSE : TRUE;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_getter_enabled[dbus] out of memory when "
		       "trying to initialize return message");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "b", &variant_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_getter_enabled[dbus] out of memory when "
		       "trying to open variant");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_append_basic(&variant_iter,
					    DBUS_TYPE_BOOLEAN, &enabled)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_getter_enabled[dbus] out of memory when "
		       "trying to append value");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_close_container(&iter, &variant_iter)) {
		dbus_message_unref(reply);
		perror("wpas_dbus_getter_blobs[dbus] out of memory when "
		       "trying to close variant");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_setter_enabled - Mark a configured network as enabled or disabled
 * @message: Pointer to incoming dbus message
 * @wpas_dbus_setter_enabled: wpa_supplicant structure for a network interface
 * and wpa_ssid structure for a configured network
 * Returns: NULL indicating success or DBus error on failure
 *
 * Setter for "Enabled" property of a configured network.
 */
DBusMessage * wpas_dbus_setter_enabled(DBusMessage *message,
				       struct network_handler_args *net)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;

	struct wpa_supplicant *wpa_s;
	struct wpa_ssid *ssid;

	dbus_bool_t enable;

	if (!dbus_message_iter_init(message, &iter)) {
		perror("wpas_dbus_setter_enabled[dbus] out of memory when "
		       "trying to init iterator");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);

	dbus_message_iter_recurse(&iter, &variant_iter);
	if (dbus_message_iter_get_arg_type(&variant_iter) !=
	    DBUS_TYPE_BOOLEAN) {
		perror("wpas_dbus_setter_enabled[dbus] "
		       "variant content should be boolean");
		reply = dbus_message_new_error(message,
					       DBUS_ERROR_INVALID_ARGS,
					       "value should be a boolean");
		goto out;
	}
	dbus_message_iter_get_basic(&variant_iter, &enable);

	wpa_s = net->wpa_s;
	ssid = net->ssid;

	if (enable)
		wpa_supplicant_enable_network(wpa_s, ssid);
	else
		wpa_supplicant_disable_network(wpa_s, ssid);

out:
	return reply;
}


/**
 * wpas_dbus_getter_network_properties - Get options for a configured network
 * @message: Pointer to incoming dbus message
 * @net: wpa_supplicant structure for a network interface and
 * wpa_ssid structure for a configured network
 * Returns: DBus message with network properties or DBus error on failure
 *
 * Getter for "Properties" property of a configured network.
 */
DBusMessage * wpas_dbus_getter_network_properties(
	DBusMessage *message, struct network_handler_args *net)
{
	DBusMessage *reply = NULL;
	DBusMessageIter	iter, variant_iter, dict_iter;
	char **iterator;
	char **props = wpa_config_get_all(net->ssid, 0);
	if (!props) {
		perror("wpas_dbus_getter_network_properties[dbus] couldn't "
		       "read network properties. out of memory.");
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);
	}

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_getter_network_properties[dbus] out of "
		       "memory when trying to initialize return message");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
			"a{sv}", &variant_iter)) {
		perror("wpas_dbus_getter_network_properties[dbus] out of "
		       "memory when trying to open variant container");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!wpa_dbus_dict_open_write(&variant_iter, &dict_iter)) {
		perror("wpas_dbus_getter_network_properties[dbus] out of "
		       "memory when trying to open dict");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	iterator = props;
	while (*iterator) {
		if (!wpa_dbus_dict_append_string(&dict_iter, *iterator,
						 *(iterator + 1))) {
			perror("wpas_dbus_getter_network_properties[dbus] out "
			       "of memory when trying to add entry");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}
		iterator += 2;
	}


	if (!wpa_dbus_dict_close_write(&variant_iter, &dict_iter)) {
		perror("wpas_dbus_getter_network_properties[dbus] out of "
		       "memory when trying to close dictionary");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (!dbus_message_iter_close_container(&iter, &variant_iter)) {
		perror("wpas_dbus_getter_network_properties[dbus] out of "
		       "memory when trying to close variant container");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	iterator = props;
	while (*iterator) {
		os_free(*iterator);
		iterator++;
	}
	os_free(props);
	return reply;
}


/**
 * wpas_dbus_setter_network_properties - Set options for a configured network
 * @message: Pointer to incoming dbus message
 * @net: wpa_supplicant structure for a network interface and
 * wpa_ssid structure for a configured network
 * Returns: NULL indicating success or DBus error on failure
 *
 * Setter for "Properties" property of a configured network.
 */
DBusMessage * wpas_dbus_setter_network_properties(
	DBusMessage *message, struct network_handler_args *net)
{
	struct wpa_ssid *ssid = net->ssid;

	DBusMessage *reply = NULL;
	DBusMessageIter	iter, variant_iter;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);

	dbus_message_iter_recurse(&iter, &variant_iter);

	reply = set_network_properties(message, ssid, &variant_iter);
	if (reply)
		wpa_printf(MSG_DEBUG, "dbus control interface couldn't set "
			   "network properties");

	return reply;
}


#ifdef CONFIG_WPS

/**
 * wpas_dbus_handler_wps_start - Start WPS configuration
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: DBus message dictionary on success or DBus error on failure
 *
 * Handler for "Start" method call. DBus dictionary argument contains
 * information about role (enrollee or registrar), authorization method
 * (pin or push button) and optionally pin and bssid. Returned message
 * has a dictionary argument which may contain newly generated pin (optional).
 */
DBusMessage * wpas_dbus_handler_wps_start(DBusMessage *message,
					  struct wpa_supplicant *wpa_s)
{
	DBusMessage * reply = NULL;
	DBusMessageIter iter, dict_iter, entry_iter, variant_iter, array_iter;

	char *key, *val;

	int role = 0; /* 0 - not set, 1 - enrollee, 2 - registrar */
	int type = 0; /* 0 - not set, 1 - pin,      2 - pbc       */
	u8 *bssid = NULL;
	char *pin = NULL, npin[9] = { '\0' };
	int len, ret;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_recurse(&iter, &dict_iter);
	while (dbus_message_iter_get_arg_type(&dict_iter) ==
	       DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(&dict_iter, &entry_iter);

		dbus_message_iter_get_basic(&entry_iter, &key);
		dbus_message_iter_next(&entry_iter);

		if (os_strcmp(key, "Role") == 0) {
			dbus_message_iter_recurse(&entry_iter, &variant_iter);
			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_STRING) {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_wps_start"
					   "[dbus]: "
					   "wrong Role type. string required");
				reply = wpas_dbus_error_invald_args(
					message, "Role must be a string");
				goto out;
			}
			dbus_message_iter_get_basic(&variant_iter, &val);
			if (os_strcmp(val, "enrollee") == 0)
				role = 1;
			else if (os_strcmp(val, "registrar") == 0)
				role = 2;
			else {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_wps_start[dbus]: "
					   "unknown role %s", val);
				reply = wpas_dbus_error_invald_args(message, val);
				goto out;
			}
		} else if (strcmp(key, "Type") == 0) {
			dbus_message_iter_recurse(&entry_iter, &variant_iter);
			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_STRING) {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_wps_start[dbus]: "
					   "wrong Type type. string required");
				reply = wpas_dbus_error_invald_args(
					message, "Type must be a string");
				goto out;
			}
			dbus_message_iter_get_basic(&variant_iter, &val);
			if (os_strcmp(val, "pin") == 0)
				type = 1;
			else if (os_strcmp(val, "pbc") == 0)
				type = 2;
			else {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_wps_start[dbus]: "
					   "unknown type %s", val);
				reply = wpas_dbus_error_invald_args(message,
								    val);
				goto out;
			}
		} else if (strcmp(key, "Bssid") == 0) {
			dbus_message_iter_recurse(&entry_iter, &variant_iter);
			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_ARRAY ||
			    dbus_message_iter_get_element_type(&variant_iter) !=
			    DBUS_TYPE_ARRAY) {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_wps_start[dbus]: "
					   "wrong Bssid type. byte array required");
				reply = wpas_dbus_error_invald_args(
					message, "Bssid must be a byte array");
				goto out;
			}
			dbus_message_iter_recurse(&variant_iter, &array_iter);
			dbus_message_iter_get_fixed_array(&array_iter, &bssid,
							  &len);
			if (len != ETH_ALEN) {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_wps_start[dbus]: "
					   "wrong Bssid length %d", len);
				reply = wpas_dbus_error_invald_args(
					message, "Bssid is wrong length");
				goto out;
			}
		}
		else if (os_strcmp(key, "Pin") == 0) {
			dbus_message_iter_recurse(&entry_iter, &variant_iter);
			if (dbus_message_iter_get_arg_type(&variant_iter) !=
			    DBUS_TYPE_STRING) {
				wpa_printf(MSG_DEBUG,
					   "wpas_dbus_handler_wps_start[dbus]: "
					   "wrong Pin type. string required");
				reply = wpas_dbus_error_invald_args(
					message, "Pin must be a string");
				goto out;
			}
			dbus_message_iter_get_basic(&variant_iter, &pin);
		} else {
			wpa_printf(MSG_DEBUG,
				   "wpas_dbus_handler_wps_start[dbus]: "
				   "unknown key %s", key);
			reply = wpas_dbus_error_invald_args(message, key);
			goto out;
		}

		dbus_message_iter_next(&dict_iter);
	}

	if (role == 0) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_handler_wps_start[dbus]: "
			   "Role not specified");
		reply = wpas_dbus_error_invald_args(message,
						    "Role not specified");
		goto out;
	}
	else if (role == 1 && type == 0) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_handler_wps_start[dbus]: "
			   "Type not specified");
		reply = wpas_dbus_error_invald_args(message,
						    "Type not specified");
		goto out;
	}
	else if (role == 2 && pin == NULL) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_handler_wps_start[dbus]: "
			   "Pin required for registrar role.");
		reply = wpas_dbus_error_invald_args(
			message, "Pin required for registrar role.");
		goto out;
	}

	if (role == 2)
		ret = wpas_wps_start_reg(wpa_s, bssid, pin, NULL);
	else if (type == 1) {
		ret = wpas_wps_start_pin(wpa_s, bssid, pin);
		if (ret > 0)
			os_snprintf(npin, sizeof(npin), "%08d", ret);
	} else
		ret = wpas_wps_start_pbc(wpa_s, bssid);

	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "wpas_dbus_handler_wps_start[dbus]: "
			   "wpas_wps_failed in role %s and key %s.",
			   (role == 1 ? "enrollee" : "registrar"),
			   (type == 0 ? "" : (type == 1 ? "pin" : "pbc")));
		reply = wpas_dbus_error_unknown_error(message,
						      "wps start failed");
		goto out;
	}

	reply = dbus_message_new_method_return(message);
	if (!reply) {
		perror("wpas_dbus_handler_wps_start[dbus]: out of memory "
		       "when creating reply");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!wpa_dbus_dict_open_write(&iter, &dict_iter)) {
		perror("wpas_dbus_handler_wps_start[dbus]: out of memory "
		       "when opening dictionary");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	if (os_strlen(npin) > 0) {
		if (!wpa_dbus_dict_append_string(&dict_iter, "Pin", npin)) {
			perror("wpas_dbus_handler_wps_start[dbus]: "
			       "out of memory when appending pin");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}
	}

	if (!wpa_dbus_dict_close_write(&iter, &dict_iter)) {
		perror("wpas_dbus_handler_wps_start[dbus]: out of memory "
		       "when closing dictionary");
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

out:
	return reply;
}


/**
 * wpas_dbus_getter_process_credentials - Check if credentials are processed
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: DBus message with a boolean on success or DBus error on failure
 *
 * Getter for "ProcessCredentials" property. Returns returned boolean will be
 * true if wps_cred_processing configuration field is not equal to 1 or false
 * if otherwise.
 */
DBusMessage * wpas_dbus_getter_process_credentials(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	dbus_bool_t process = (wpa_s->conf->wps_cred_processing != 1);

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (reply != NULL) {
		dbus_message_iter_init_append(reply, &iter);
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						      "b", &variant_iter) ||
		    !dbus_message_iter_append_basic(&variant_iter,
						    DBUS_TYPE_BOOLEAN,
						    &process) ||
		    !dbus_message_iter_close_container(&iter, &variant_iter)) {

			perror("wpas_dbus_getter_process_credentials[dbus]: "
			       "out of memory to put value into message.");
			dbus_message_unref(reply);
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
		}
	} else {
		perror("wpas_dbus_getter_process_credentials[dbus]: out of "
		       "memory to create reply message.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	return reply;
}


/**
 * wpas_dbus_setter_process_credentials - Set credentials_processed conf param
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: NULL on success or DBus error on failure
 *
 * Setter for "ProcessCredentials" property. Sets credentials_processed on 2
 * if boolean argument is true or on 1 if otherwise.
 */
DBusMessage * wpas_dbus_setter_process_credentials(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	dbus_bool_t process_credentials, old_pc;

	if (!dbus_message_iter_init(message, &iter)) {
		perror("wpas_dbus_getter_ap_scan[dbus]: out of "
		       "memory to return scanning state.");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto out;
	}

	/* omit first and second argument and get value from third*/
	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &variant_iter);

	if (dbus_message_iter_get_arg_type(&variant_iter) != DBUS_TYPE_BOOLEAN)
	{
		reply = wpas_dbus_error_invald_args(message,
						    "BOOLEAN required");
		goto out;
	}
	dbus_message_iter_get_basic(&variant_iter, &process_credentials);

	old_pc = (wpa_s->conf->wps_cred_processing != 1);
	wpa_s->conf->wps_cred_processing = (process_credentials ? 2 : 1);

	if ((wpa_s->conf->wps_cred_processing != 1) != old_pc)
		wpa_dbus_signal_property_changed(
			wpa_s->global->dbus_new_ctrl_iface,
			(WPADBusPropertyAccessor)
			wpas_dbus_getter_process_credentials,
			wpa_s, wpas_dbus_get_path(wpa_s),
			WPAS_DBUS_NEW_IFACE_WPS,
			"ProcessCredentials");

out:
	return reply;
}

#endif /* CONFIG_WPS */
