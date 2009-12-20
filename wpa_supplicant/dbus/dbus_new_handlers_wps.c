/*
 * WPA Supplicant / dbus-based control interface (WPS)
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
#include "../config.h"
#include "../wpa_supplicant_i.h"
#include "../wps_supplicant.h"
#include "ctrl_iface_dbus_new_helpers.h"
#include "ctrl_iface_dbus_new.h"
#include "ctrl_iface_dbus_new_handlers.h"
#include "dbus_dict_helpers.h"

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
