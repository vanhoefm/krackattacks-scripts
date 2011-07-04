/*
 * WPA Supplicant / dbus-based control interface (P2P)
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

#include "utils/includes.h"
#include "common.h"
#include "../config.h"
#include "../wpa_supplicant_i.h"
#include "../wps_supplicant.h"
#include "../notify.h"
#include "dbus_new_helpers.h"
#include "dbus_new.h"
#include "dbus_new_handlers.h"
#include "dbus_new_handlers_p2p.h"
#include "dbus_dict_helpers.h"
#include "p2p/p2p.h"
#include "common/ieee802_11_defs.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"
#include "ap/wps_hostapd.h"

#include "../p2p_supplicant.h"

/**
 * Parses out the mac address from the peer object path.
 * @peer_path - object path of the form
 *	/fi/w1/wpa_supplicant1/Interfaces/n/Peers/00112233445566 (no colons)
 * @addr - out param must be of ETH_ALEN size
 * Returns 0 if valid (including MAC), -1 otherwise
 */
static int parse_peer_object_path(char *peer_path, u8 addr[ETH_ALEN])
{
	char *p;

	if (!peer_path)
		return -1;
	p = strrchr(peer_path, '/');
	if (!p)
		return -1;
	p++;
	return hwaddr_compact_aton(p, addr);
}


/**
 * wpas_dbus_error_persistent_group_unknown - Return a new PersistentGroupUnknown
 * error message
 * @message: Pointer to incoming dbus message this error refers to
 * Returns: a dbus error message
 *
 * Convenience function to create and return an invalid persistent group error.
 */
static DBusMessage * wpas_dbus_error_persistent_group_unknown(
	DBusMessage *message)
{
	return dbus_message_new_error(message, WPAS_DBUS_ERROR_NETWORK_UNKNOWN,
				      "There is no such persistent group in "
				      "this P2P device.");
}


DBusMessage *wpas_dbus_handler_p2p_find(DBusMessage * message,
					struct wpa_supplicant * wpa_s)
{
	struct wpa_dbus_dict_entry entry;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter iter_dict;
	unsigned int timeout = 0;
	unsigned int searchonly = 0;
	enum p2p_discovery_type type = P2P_FIND_ONLY_SOCIAL;
	int num_req_dev_types = 0;
	unsigned int i;
	u8 *req_dev_types = NULL;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;

		if (!os_strcmp(entry.key, "Timeout") &&
		    (entry.type == DBUS_TYPE_INT32)) {
			timeout = entry.uint32_value;
		} else if (!os_strcmp(entry.key, "SearchOnly") &&
			   (entry.type == DBUS_TYPE_BOOLEAN)) {
			searchonly = (entry.bool_value == TRUE) ? 1 : 0;
		} else if (os_strcmp(entry.key, "RequestedDeviceTypes") == 0) {
			if ((entry.type != DBUS_TYPE_ARRAY) ||
			    (entry.array_type != WPAS_DBUS_TYPE_BINARRAY))
				goto error_clear;

			req_dev_types =
				os_malloc(WPS_DEV_TYPE_LEN * entry.array_len);
			if (!req_dev_types)
				goto error_clear;

			for (i = 0; i < entry.array_len; i++) {
				if (wpabuf_len(entry.binarray_value[i]) !=
							WPS_DEV_TYPE_LEN)
					goto error_clear;
				os_memcpy(req_dev_types + i * WPS_DEV_TYPE_LEN,
					  wpabuf_head(entry.binarray_value[i]),
					  WPS_DEV_TYPE_LEN);
			}

			num_req_dev_types = entry.array_len;
		} else
			goto error_clear;
		wpa_dbus_dict_entry_clear(&entry);
	}

	wpas_p2p_find(wpa_s, timeout, type, num_req_dev_types, req_dev_types);
	return reply;

error_clear:
	os_free(req_dev_types);
	wpa_dbus_dict_entry_clear(&entry);
error:
	reply = wpas_dbus_error_invalid_args(message, entry.key);
	return reply;
}

DBusMessage *wpas_dbus_handler_p2p_stop_find(DBusMessage * message,
					     struct wpa_supplicant * wpa_s)
{
	wpas_p2p_stop_find(wpa_s);
	return NULL;
}

DBusMessage *wpas_dbus_handler_p2p_rejectpeer(DBusMessage * message,
					      struct wpa_supplicant * wpa_s)
{
	DBusMessageIter iter;
	char *peer_object_path = NULL;
	u8 peer_addr[ETH_ALEN];

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_get_basic(&iter, &peer_object_path);

	if (parse_peer_object_path(peer_object_path, peer_addr) < 0)
		return wpas_dbus_error_invalid_args(message, NULL);

	if (wpas_p2p_reject(wpa_s, peer_addr) < 0)
		return wpas_dbus_error_unknown_error(message,
				"Failed to call wpas_p2p_reject method.");

	return NULL;
}

DBusMessage *wpas_dbus_handler_p2p_listen(DBusMessage * message,
					  struct wpa_supplicant * wpa_s)
{
	dbus_int32_t timeout = 0;

	if (!dbus_message_get_args(message, NULL, DBUS_TYPE_INT32, &timeout,
				   DBUS_TYPE_INVALID))
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);

	if (wpas_p2p_listen(wpa_s, (unsigned int)timeout))
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);

	return NULL;
}

DBusMessage *wpas_dbus_handler_p2p_extendedlisten(DBusMessage * message,
						  struct wpa_supplicant * wpa_s)
{
	unsigned int period = 0, interval = 0;
	struct wpa_dbus_dict_entry entry;
	DBusMessageIter iter;
	DBusMessageIter iter_dict;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;

		if (!strcmp(entry.key, "period") &&
		    (entry.type == DBUS_TYPE_INT32))
			period = entry.uint32_value;
		else if (!strcmp(entry.key, "interval") &&
			 (entry.type == DBUS_TYPE_INT32))
			interval = entry.uint32_value;
		else
			goto error_clear;
		wpa_dbus_dict_entry_clear(&entry);
	}

	if (wpas_p2p_ext_listen(wpa_s, period, interval))
		return wpas_dbus_error_unknown_error(message,
					"failed to initiate a p2p_ext_listen.");

	return NULL;

error_clear:
	wpa_dbus_dict_entry_clear(&entry);
error:
	return wpas_dbus_error_invalid_args(message, entry.key);
}

DBusMessage *wpas_dbus_handler_p2p_presence_request(DBusMessage * message,
						    struct wpa_supplicant *
						    wpa_s)
{
	unsigned int dur1 = 0, int1 = 0, dur2 = 0, int2 = 0;
	struct wpa_dbus_dict_entry entry;
	DBusMessageIter iter;
	DBusMessageIter iter_dict;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;

		if (!strcmp(entry.key, "duration1") &&
		    (entry.type == DBUS_TYPE_INT32))
			dur1 = entry.uint32_value;
		else if (!strcmp(entry.key, "interval1") &&
			 entry.type == DBUS_TYPE_INT32)
			int1 = entry.uint32_value;
		else if (!strcmp(entry.key, "duration2") &&
			 entry.type == DBUS_TYPE_INT32)
			dur2 = entry.uint32_value;
		else if (!strcmp(entry.key, "interval2") &&
			 entry.type == DBUS_TYPE_INT32)
			int2 = entry.uint32_value;
		else
			goto error_clear;

		wpa_dbus_dict_entry_clear(&entry);
	}
	if (wpas_p2p_presence_req(wpa_s, dur1, int1, dur2, int2) < 0)
		return wpas_dbus_error_unknown_error(message,
				"Failed to invoke presence request.");

	return NULL;

error_clear:
	wpa_dbus_dict_entry_clear(&entry);
error:
	return wpas_dbus_error_invalid_args(message, entry.key);
}

DBusMessage *wpas_dbus_handler_p2p_group_add(DBusMessage * message,
					     struct wpa_supplicant * wpa_s)
{
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;
	char *pg_object_path = NULL;
	int persistent_group = 0;
	int freq = 0;
	char *iface = NULL;
	char *net_id_str = NULL;
	unsigned int group_id = 0;
	struct wpa_ssid *ssid;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto inv_args;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto inv_args;

		if (!strcmp(entry.key, "persistent") &&
		    (entry.type == DBUS_TYPE_BOOLEAN)) {
			persistent_group = (entry.bool_value == TRUE) ? 1 : 0;
		} else if (!strcmp(entry.key, "frequency") &&
			   (entry.type == DBUS_TYPE_INT32)) {
			freq = entry.int32_value;
			if (freq <= 0)
				goto inv_args_clear;
		} else if (!strcmp(entry.key, "persistent_group_object") &&
			   entry.type == DBUS_TYPE_OBJECT_PATH)
			pg_object_path = os_strdup(entry.str_value);
		else
			goto inv_args_clear;

		wpa_dbus_dict_entry_clear(&entry);
	}

	if (pg_object_path != NULL) {
		/*
		 * A persistent group Object Path is defined meaning we want
		 * to re-invoke a persistent group.
		 */

		iface = wpas_dbus_new_decompose_object_path(pg_object_path, 1,
							    &net_id_str, NULL);
		if (iface == NULL ||
		    os_strcmp(iface, wpa_s->dbus_new_path) != 0) {
			reply =
			    wpas_dbus_error_invalid_args(message,
							 pg_object_path);
			goto out;
		}

		group_id = strtoul(net_id_str, NULL, 10);
		if (errno == EINVAL) {
			reply = wpas_dbus_error_invalid_args(
						message, pg_object_path);
			goto out;
		}

		/* Get the SSID structure form the persistant group id */
		ssid = wpa_config_get_network(wpa_s->conf, group_id);
		if (ssid == NULL || ssid->disabled != 2)
			goto inv_args;

		if (wpas_p2p_group_add_persistent(wpa_s, ssid, 0, freq)) {
			reply = wpas_dbus_error_unknown_error(message,
							      "Failed to reinvoke a persistent group");
			goto out;
		}
	} else if (wpas_p2p_group_add(wpa_s, persistent_group, freq))
		goto inv_args;

out:
	os_free(pg_object_path);
	os_free(net_id_str);
	os_free(iface);
	return reply;
inv_args_clear:
	wpa_dbus_dict_entry_clear(&entry);
inv_args:
	reply = wpas_dbus_error_invalid_args(message, NULL);
	goto out;
}

DBusMessage *wpas_dbus_handler_p2p_disconnect(DBusMessage *message,
					      struct wpa_supplicant *wpa_s)
{
	if (wpas_p2p_disconnect(wpa_s))
		return wpas_dbus_error_unknown_error(message,
						"failed to disconnect");

	return NULL;
}

DBusMessage *wpas_dbus_handler_p2p_flush(DBusMessage * message,
					 struct wpa_supplicant * wpa_s)
{
	os_memset(wpa_s->p2p_auth_invite, 0, ETH_ALEN);
	wpa_s->force_long_sd = 0;
	p2p_flush(wpa_s->global->p2p);

	return NULL;
}

DBusMessage *wpas_dbus_handler_p2p_connect(DBusMessage * message,
					   struct wpa_supplicant * wpa_s)
{
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;
	char *peer_object_path = NULL;
	int persistent_group = 0;
	int join = 0;
	int authorize_only = 0;
	int go_intent = -1;
	int freq = 0;
	u8 addr[ETH_ALEN];
	char *pin = NULL;
	enum p2p_wps_method wps_method = WPS_NOT_READY;
	int new_pin;
	char *err_msg = NULL;
	char *iface = NULL;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto inv_args;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto inv_args;

		if (!strcmp(entry.key, "peer") &&
		    (entry.type == DBUS_TYPE_OBJECT_PATH)) {
			peer_object_path = os_strdup(entry.str_value);
		} else if (!strcmp(entry.key, "persistent") &&
			   (entry.type == DBUS_TYPE_BOOLEAN)) {
			persistent_group = (entry.bool_value == TRUE) ? 1 : 0;
		} else if (!strcmp(entry.key, "join") &&
			   (entry.type == DBUS_TYPE_BOOLEAN)) {
			join = (entry.bool_value == TRUE) ? 1 : 0;
		} else if (!strcmp(entry.key, "authorize_only") &&
			   (entry.type == DBUS_TYPE_BOOLEAN)) {
			authorize_only = (entry.bool_value == TRUE) ? 1 : 0;
		} else if (!strcmp(entry.key, "frequency") &&
			   (entry.type == DBUS_TYPE_INT32)) {
			freq = entry.int32_value;
			if (freq <= 0)
				goto inv_args_clear;
		} else if (!strcmp(entry.key, "go_intent") &&
			   (entry.type == DBUS_TYPE_INT32)) {
			go_intent = entry.int32_value;
			if ((go_intent < 0) || (go_intent > 15))
				goto inv_args_clear;
		} else if (!strcmp(entry.key, "wps_method") &&
			   (entry.type == DBUS_TYPE_STRING)) {
			if (!strcmp(entry.str_value, "pbc"))
				wps_method = WPS_PBC;
			else if (!strcmp(entry.str_value, "pin"))
				wps_method = WPS_PIN_DISPLAY;
			else if (!strcmp(entry.str_value, "label"))
				wps_method = WPS_PIN_LABEL;
			else if (!strcmp(entry.str_value, "display"))
				wps_method = WPS_PIN_DISPLAY;
			else if (!strcmp(entry.str_value, "keypad"))
				wps_method = WPS_PIN_KEYPAD;
			else
				goto inv_args_clear;
		} else if (!strcmp(entry.key, "pin") &&
			   (entry.type == DBUS_TYPE_STRING)) {
			pin = os_strdup(entry.str_value);
		} else
			goto inv_args_clear;

		wpa_dbus_dict_entry_clear(&entry);
	}

	if (!peer_object_path || (wps_method == WPS_NOT_READY) ||
	    (parse_peer_object_path(peer_object_path, addr) < 0) ||
	    (p2p_get_peer_info(wpa_s->global->p2p, addr, 0, NULL, 0) < 0)) {
		reply = wpas_dbus_error_invalid_args(message, NULL);
		goto inv_args;
	}

	/*
	 * Validate the wps_method specified and the pin value.
	 */
	if ((!pin || !pin[0]) &&
	    ((wps_method == WPS_PIN_LABEL) || (wps_method == WPS_PIN_KEYPAD)))
		goto inv_args;

	new_pin = wpas_p2p_connect(wpa_s, addr, pin, wps_method,
				   persistent_group, join, authorize_only,
				   go_intent, freq);

	if (new_pin >= 0) {
		reply = dbus_message_new_method_return(message);
		dbus_message_append_args(reply, DBUS_TYPE_INT32,
					 &new_pin, DBUS_TYPE_INVALID);
	} else {
		switch (new_pin) {
		case -2:
			err_msg = "connect failed due to"
					" channel unavailability.";
			iface = WPAS_DBUS_ERROR_CONNECT_CHANNEL_UNAVAILABLE;
			break;

		case -3:
			err_msg = "connect failed due to"
					" unsupported channel.";
			iface = WPAS_DBUS_ERROR_CONNECT_CHANNEL_UNSUPPORTED;
			break;

		default:
			err_msg = "connect failed due to"
					" unspecified error.";
			iface = WPAS_DBUS_ERROR_CONNECT_UNSPECIFIED_ERROR;
			break;
		}
		/*
		 * TODO::
		 * Do we need specialized errors corresponding to above
		 * error conditions as against just returning a different
		 * error message?
		 */
		reply = dbus_message_new_error(message, iface, err_msg);
	}

out:
	os_free(peer_object_path);
	os_free(pin);
	return reply;
inv_args_clear:
	wpa_dbus_dict_entry_clear(&entry);
inv_args:
	reply = wpas_dbus_error_invalid_args(message, NULL);
	goto out;
}

DBusMessage *wpas_dbus_handler_p2p_invite(DBusMessage * message,
					  struct wpa_supplicant *wpa_s)
{
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;
	char *peer_object_path = NULL;
	char *pg_object_path = NULL;
	char *iface = NULL;
	char *net_id_str = NULL;
	u8 peer_addr[ETH_ALEN];
	unsigned int group_id = 0;
	int persistent = 0;
	struct wpa_ssid *ssid;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto err;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto err;

		if (!strcmp(entry.key, "peer") &&
		    (entry.type == DBUS_TYPE_OBJECT_PATH)) {
			peer_object_path = os_strdup(entry.str_value);
			wpa_dbus_dict_entry_clear(&entry);
		} else if (!strcmp(entry.key, "persistent_group_object") &&
			   (entry.type == DBUS_TYPE_OBJECT_PATH)) {
			pg_object_path = os_strdup(entry.str_value);
			persistent = 1;
			wpa_dbus_dict_entry_clear(&entry);
		} else {
			wpa_dbus_dict_entry_clear(&entry);
			goto err;
		}
	}

	if (!peer_object_path ||
	    (parse_peer_object_path(peer_object_path, peer_addr) < 0) ||
	    (p2p_get_peer_info(wpa_s->global->p2p,
			       peer_addr, 0, NULL, 0) < 0)) {
		goto err;
	}

	if (persistent) {
		/*
		 * A group ID is defined meaning we want to re-invoke a
		 * persisatnt group
		 */

		iface = wpas_dbus_new_decompose_object_path(pg_object_path, 1,
							    &net_id_str, NULL);
		if (iface == NULL ||
		    os_strcmp(iface, wpa_s->dbus_new_path) != 0) {
			reply =
			    wpas_dbus_error_invalid_args(message,
							 pg_object_path);
			goto out;
		}

		group_id = strtoul(net_id_str, NULL, 10);
		if (errno == EINVAL) {
			reply = wpas_dbus_error_invalid_args(
						message, pg_object_path);
			goto out;
		}

		/* Get the SSID structure form the persistant group id */
		ssid = wpa_config_get_network(wpa_s->conf, group_id);
		if (ssid == NULL || ssid->disabled != 2)
			goto err;

		if (wpas_p2p_invite(wpa_s, peer_addr, ssid, NULL) < 0) {
			reply = wpas_dbus_error_unknown_error(
					message,
					"Failed to reinvoke a persistent group");
			goto out;
		}
	} else {
		/*
		 * No group ID means propose to a peer to join my active group
		 */
		if (wpas_p2p_invite_group(wpa_s, wpa_s->ifname,
					 peer_addr, NULL)) {
			reply = wpas_dbus_error_unknown_error(
					message,
					"Failed to join to an active group");
			goto out;
		}
	}

out:
	os_free(pg_object_path);
	os_free(peer_object_path);
	return reply;

err:
	reply = wpas_dbus_error_invalid_args(message, NULL);
	goto out;
}

DBusMessage *wpas_dbus_handler_p2p_prov_disc_req(DBusMessage * message,
						 struct wpa_supplicant *wpa_s)
{
	DBusMessageIter iter;
	char *peer_object_path = NULL;
	char *config_method = NULL;
	u8 peer_addr[ETH_ALEN];

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_get_basic(&iter, &peer_object_path);

	if (parse_peer_object_path(peer_object_path, peer_addr) < 0)
		return wpas_dbus_error_invalid_args(message, NULL);

	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &config_method);

	/*
	 * Validation checks on config_method are being duplicated here
	 * to be able to return invalid args reply since the error code
	 * from p2p module are not granular enough (yet).
	 */
	if (os_strcmp(config_method, "display") &&
	    os_strcmp(config_method, "keypad") &&
	    os_strcmp(config_method, "pbc") &&
	    os_strcmp(config_method, "pushbutton"))
		return wpas_dbus_error_invalid_args(message, NULL);

	if (wpas_p2p_prov_disc(wpa_s, peer_addr, config_method) < 0)
		return wpas_dbus_error_unknown_error(message,
				"Failed to send provision discovery request");

	return NULL;
}

/*
 * P2P Device property accessor methods.
 */

DBusMessage *wpas_dbus_getter_p2p_device_properties(DBusMessage * message,
						    struct wpa_supplicant *
						    wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, dict_iter;
	DBusMessageIter iter_secdev_dict_entry, iter_secdev_dict_val,
		iter_secdev_dict_array;
	const char *dev_name;
	int num_vendor_extensions = 0;
	int i;
	const struct wpabuf *vendor_ext[P2P_MAX_WPS_VENDOR_EXT];

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (!reply)
		goto err_no_mem;

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "a{sv}", &variant_iter) ||
	    !wpa_dbus_dict_open_write(&variant_iter, &dict_iter))
		goto err_no_mem;

	/* DeviceName */
	dev_name = wpa_s->conf->device_name;
	if (dev_name &&
	    !wpa_dbus_dict_append_string(&dict_iter, "DeviceName", dev_name))
		goto err_no_mem;

	/* Primary device type */
	if (!wpa_dbus_dict_append_byte_array(&dict_iter, "PrimaryDeviceType",
	    				     (char *)wpa_s->conf->device_type,
	    				     WPS_DEV_TYPE_LEN))
		goto err_no_mem;

	/* Secondary device types */
	if (wpa_s->conf->num_sec_device_types) {
		if (!wpa_dbus_dict_begin_array(&dict_iter,
					       "SecondaryDeviceTypes",
					       DBUS_TYPE_ARRAY_AS_STRING
					       DBUS_TYPE_BYTE_AS_STRING,
					       &iter_secdev_dict_entry,
					       &iter_secdev_dict_val,
					       &iter_secdev_dict_array))
			goto err_no_mem;

		for (i = 0; i < wpa_s->conf->num_sec_device_types; i++)
			wpa_dbus_dict_bin_array_add_element(
				&iter_secdev_dict_array,
				wpa_s->conf->sec_device_type[i],
				WPS_DEV_TYPE_LEN);

		if (!wpa_dbus_dict_end_array(&dict_iter,
					     &iter_secdev_dict_entry,
					     &iter_secdev_dict_val,
					     &iter_secdev_dict_array))
			goto err_no_mem;
	}

	/* Vendor Extensions */
	for (i = 0; i < P2P_MAX_WPS_VENDOR_EXT; i++) {
		if (wpa_s->conf->wps_vendor_ext[i] == NULL)
			continue;
		vendor_ext[num_vendor_extensions++] =
			wpa_s->conf->wps_vendor_ext[i];
	}

	if (num_vendor_extensions &&
	    !wpa_dbus_dict_append_wpabuf_array(&dict_iter,
					       "VendorExtension",
					       vendor_ext,
					       num_vendor_extensions))
		goto err_no_mem;

	/* GO Intent */
	if (!wpa_dbus_dict_append_uint32(&dict_iter, "GOIntent",
					 wpa_s->conf->p2p_go_intent))
		goto err_no_mem;

	/* Persistant Reconnect */
	if (!wpa_dbus_dict_append_bool(&dict_iter, "PersistantReconnect",
				       wpa_s->conf->persistent_reconnect))
		goto err_no_mem;

	/* Listen Reg Class */
	if (!wpa_dbus_dict_append_uint32(&dict_iter, "ListenRegClass",
					 wpa_s->conf->p2p_listen_reg_class))
		goto err_no_mem;

	/* Listen Channel */
	if (!wpa_dbus_dict_append_uint32(&dict_iter, "ListenChannel",
					 wpa_s->conf->p2p_listen_channel))
		goto err_no_mem;

	/* Oper Reg Class */
	if (!wpa_dbus_dict_append_uint32(&dict_iter, "OperRegClass",
					 wpa_s->conf->p2p_oper_reg_class))
		goto err_no_mem;

	/* Oper Channel */
	if (!wpa_dbus_dict_append_uint32(&dict_iter, "OperChannel",
					 wpa_s->conf->p2p_oper_channel))
		goto err_no_mem;

	/* SSID Postfix */
	if (wpa_s->conf->p2p_ssid_postfix &&
	    !wpa_dbus_dict_append_string(&dict_iter, "SsidPostfix",
					 wpa_s->conf->p2p_ssid_postfix))
		goto err_no_mem;

	/* Intra Bss */
	if (!wpa_dbus_dict_append_bool(&dict_iter, "IntraBss",
				       wpa_s->conf->p2p_intra_bss))
		goto err_no_mem;

	/* Group Idle */
	if (!wpa_dbus_dict_append_uint32(&dict_iter, "GroupIdle",
					 wpa_s->conf->p2p_group_idle))
		goto err_no_mem;

	/* Dissasociation low ack */
	if (!wpa_dbus_dict_append_uint32(&dict_iter, "disassoc_low_ack",
					 wpa_s->conf->disassoc_low_ack))
		goto err_no_mem;

	if (!wpa_dbus_dict_close_write(&variant_iter, &dict_iter) ||
	    !dbus_message_iter_close_container(&iter, &variant_iter))
		goto err_no_mem;

	return reply;
err_no_mem:
	dbus_message_unref(reply);
	return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}

DBusMessage *wpas_dbus_setter_p2p_device_properties(DBusMessage * message,
						    struct wpa_supplicant *
						    wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	struct wpa_dbus_dict_entry entry = {.type = DBUS_TYPE_STRING };
	DBusMessageIter iter_dict;
	unsigned int i;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);

	dbus_message_iter_recurse(&iter, &variant_iter);

	if (!wpa_dbus_dict_open_read(&variant_iter, &iter_dict))
		return wpas_dbus_error_invalid_args(message, NULL);

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			return wpas_dbus_error_invalid_args(message, NULL);

		if (os_strcmp(entry.key, "DeviceName") == 0) {
			char *devname;

			if (entry.type != DBUS_TYPE_STRING)
				goto error_clear;

			devname = os_strdup(entry.str_value);
			if (devname == NULL)
				goto err_no_mem_clear;

			os_free(wpa_s->conf->device_name);
			wpa_s->conf->device_name = devname;

			wpa_s->conf->changed_parameters |=
							CFG_CHANGED_DEVICE_NAME;
		} else if (os_strcmp(entry.key, "PrimaryDeviceType") == 0) {
			if (entry.type != DBUS_TYPE_ARRAY ||
			    entry.array_type != DBUS_TYPE_BYTE ||
			    entry.array_len != WPS_DEV_TYPE_LEN)
				goto error_clear;

			os_memcpy(wpa_s->conf->device_type,
				  entry.bytearray_value,
				  WPS_DEV_TYPE_LEN);
			wpa_s->conf->changed_parameters |=
				CFG_CHANGED_DEVICE_TYPE;
		} else if (os_strcmp(entry.key, "SecondaryDeviceTypes") == 0) {
			if (entry.type != DBUS_TYPE_ARRAY ||
			    entry.array_type != WPAS_DBUS_TYPE_BINARRAY ||
			    entry.array_len > MAX_SEC_DEVICE_TYPES)
				goto error;

			for (i = 0; i < entry.array_len; i++)
				if (wpabuf_len(entry.binarray_value[i]) != WPS_DEV_TYPE_LEN)
					goto err_no_mem_clear;
			for (i = 0; i < entry.array_len; i++)
				os_memcpy(wpa_s->conf->sec_device_type[i],
					  wpabuf_head(entry.binarray_value[i]),
					  WPS_DEV_TYPE_LEN);
			wpa_s->conf->num_sec_device_types = entry.array_len;
			wpa_s->conf->changed_parameters |=
					CFG_CHANGED_SEC_DEVICE_TYPE;
		} else if (os_strcmp(entry.key, "VendorExtension") == 0) {
			if ((entry.type != DBUS_TYPE_ARRAY) ||
			    (entry.array_type != WPAS_DBUS_TYPE_BINARRAY) ||
			    (entry.array_len > P2P_MAX_WPS_VENDOR_EXT))
				goto error_clear;

			wpa_s->conf->changed_parameters |=
					CFG_CHANGED_VENDOR_EXTENSION;

			for (i = 0; i < P2P_MAX_WPS_VENDOR_EXT; i++) {
				wpabuf_free(wpa_s->conf->wps_vendor_ext[i]);
				if (i < entry.array_len) {
					wpa_s->conf->wps_vendor_ext[i] =
						entry.binarray_value[i];
					entry.binarray_value[i] = NULL;
				} else
					wpa_s->conf->wps_vendor_ext[i] = NULL;
			}
		} else if ((os_strcmp(entry.key, "GOIntent") == 0) &&
			   (entry.type == DBUS_TYPE_UINT32) &&
			   (entry.uint32_value <= 15))
			wpa_s->conf->p2p_go_intent = entry.uint32_value;

		else if ((os_strcmp(entry.key, "PersistantReconnect") == 0) &&
			 (entry.type == DBUS_TYPE_BOOLEAN))
			wpa_s->conf->persistent_reconnect = entry.bool_value;

		else if ((os_strcmp(entry.key, "ListenRegClass") == 0) &&
			 (entry.type == DBUS_TYPE_UINT32)) {
			wpa_s->conf->p2p_listen_reg_class = entry.uint32_value;
			wpa_s->conf->changed_parameters |=
				CFG_CHANGED_P2P_LISTEN_CHANNEL;
		} else if ((os_strcmp(entry.key, "ListenChannel") == 0) &&
			   (entry.type == DBUS_TYPE_UINT32)) {
			wpa_s->conf->p2p_listen_channel = entry.uint32_value;
			wpa_s->conf->changed_parameters |=
				CFG_CHANGED_P2P_LISTEN_CHANNEL;
		} else if ((os_strcmp(entry.key, "OperRegClass") == 0) &&
			   (entry.type == DBUS_TYPE_UINT32)) {
			wpa_s->conf->p2p_oper_reg_class = entry.uint32_value;
			wpa_s->conf->changed_parameters |=
				CFG_CHANGED_P2P_OPER_CHANNEL;
		} else if ((os_strcmp(entry.key, "OperChannel") == 0) &&
			   (entry.type == DBUS_TYPE_UINT32)) {
			wpa_s->conf->p2p_oper_channel = entry.uint32_value;
			wpa_s->conf->changed_parameters |=
				CFG_CHANGED_P2P_OPER_CHANNEL;
		} else if (os_strcmp(entry.key, "SsidPostfix") == 0) {
			char *postfix;

			if (entry.type != DBUS_TYPE_STRING)
				goto error_clear;

			postfix = os_strdup(entry.str_value);
			if (!postfix)
				goto err_no_mem_clear;

			os_free(wpa_s->conf->p2p_ssid_postfix);
			wpa_s->conf->p2p_ssid_postfix = postfix;

			wpa_s->conf->changed_parameters |=
					CFG_CHANGED_P2P_SSID_POSTFIX;
		} else if ((os_strcmp(entry.key, "IntraBss") == 0) &&
			   (entry.type == DBUS_TYPE_BOOLEAN)) {
			wpa_s->conf->p2p_intra_bss = entry.bool_value;
			wpa_s->conf->changed_parameters |=
						      CFG_CHANGED_P2P_INTRA_BSS;
		} else if ((os_strcmp(entry.key, "GroupIdle") == 0) &&
			   (entry.type == DBUS_TYPE_UINT32))
			wpa_s->conf->p2p_group_idle = entry.uint32_value;
		else if (os_strcmp(entry.key, "disassoc_low_ack") == 0 &&
			 entry.type == DBUS_TYPE_UINT32)
			wpa_s->conf->disassoc_low_ack = entry.uint32_value;
		else
			goto error_clear;

		wpa_dbus_dict_entry_clear(&entry);
	}

	if (wpa_s->conf->changed_parameters) {
		/* Some changed parameters requires to update config*/
		wpa_supplicant_update_config(wpa_s);
	}

	return reply;

 error_clear:
	wpa_dbus_dict_entry_clear(&entry);
 error:
	reply = wpas_dbus_error_invalid_args(message, entry.key);
	wpa_dbus_dict_entry_clear(&entry);

	return reply;
 err_no_mem_clear:
	wpa_dbus_dict_entry_clear(&entry);
	return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}

DBusMessage *wpas_dbus_getter_p2p_peers(DBusMessage * message,
					struct wpa_supplicant * wpa_s)
{
	DBusMessage *reply = NULL;
	struct p2p_data *p2p = wpa_s->global->p2p;
	int next = 0, i = 0;
	int num = 0, out_of_mem = 0;
	const u8 *addr;
	const struct p2p_peer_info *peer_info = NULL;

	struct dl_list peer_objpath_list;
	struct peer_objpath_node {
		struct dl_list list;
		char path[WPAS_DBUS_OBJECT_PATH_MAX];
	} *node, *tmp;

	char **peer_obj_paths = NULL;

	dl_list_init(&peer_objpath_list);

	/* Get the first peer info */
	peer_info = p2p_get_peer_found(p2p, NULL, next);

	/* Get next and accumulate them */
	next = 1;
	while (peer_info != NULL) {
		node = os_zalloc(sizeof(struct peer_objpath_node));
		if (!node) {
			out_of_mem = 1;
			goto error;
		}

		addr = peer_info->p2p_device_addr;
		os_snprintf(node->path, WPAS_DBUS_OBJECT_PATH_MAX,
			    "%s/" WPAS_DBUS_NEW_P2P_PEERS_PART
			    "/" COMPACT_MACSTR,
			    wpa_s->dbus_new_path, MAC2STR(addr));
		dl_list_add_tail(&peer_objpath_list, &node->list);
		num++;

		peer_info = p2p_get_peer_found(p2p, addr, next);
	}

	/*
	 * Now construct the peer object paths in a form suitable for
	 * array_property_getter helper below.
	 */
	peer_obj_paths = os_zalloc(num * sizeof(char *));

	if (!peer_obj_paths) {
		out_of_mem = 1;
		goto error;
	}

	dl_list_for_each_safe(node, tmp, &peer_objpath_list,
			      struct peer_objpath_node, list)
		peer_obj_paths[i++] = node->path;

	reply = wpas_dbus_simple_array_property_getter(message,
						       DBUS_TYPE_OBJECT_PATH,
						       peer_obj_paths, num);

error:
	if (peer_obj_paths)
		os_free(peer_obj_paths);

	dl_list_for_each_safe(node, tmp, &peer_objpath_list,
			      struct peer_objpath_node, list) {
		dl_list_del(&node->list);
		os_free(node);
	}
	if (out_of_mem)
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);

	return reply;
}

enum wpas_p2p_role {
	WPAS_P2P_ROLE_DEVICE,
	WPAS_P2P_ROLE_GO,
	WPAS_P2P_ROLE_CLIENT,
};

static enum wpas_p2p_role wpas_get_p2p_role(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (!ssid)
		return WPAS_P2P_ROLE_DEVICE;
	if (wpa_s->wpa_state != WPA_COMPLETED)
		return WPAS_P2P_ROLE_DEVICE;

	switch (ssid->mode) {
	case WPAS_MODE_P2P_GO:
	case WPAS_MODE_P2P_GROUP_FORMATION:
		return WPAS_P2P_ROLE_GO;
	case WPAS_MODE_INFRA:
		if (ssid->p2p_group)
			return WPAS_P2P_ROLE_CLIENT;
		return WPAS_P2P_ROLE_DEVICE;
	default:
		return WPAS_P2P_ROLE_DEVICE;
	}
}

DBusMessage *wpas_dbus_getter_p2p_role(DBusMessage * message,
				       struct wpa_supplicant * wpa_s)
{
	char *str;

	switch (wpas_get_p2p_role(wpa_s)) {
	case WPAS_P2P_ROLE_GO:
		str = "GO";
		break;
	case WPAS_P2P_ROLE_CLIENT:
		str = "client";
		break;
	default:
		str = "device";
	}

	return wpas_dbus_simple_property_getter(message, DBUS_TYPE_STRING,
						&str);
}

DBusMessage *wpas_dbus_getter_p2p_group(DBusMessage * message,
					struct wpa_supplicant * wpa_s)
{
	if (wpa_s->dbus_groupobj_path == NULL)
		return NULL;

	return wpas_dbus_simple_property_getter(message,
						DBUS_TYPE_OBJECT_PATH,
						&wpa_s->dbus_groupobj_path);
}

DBusMessage *wpas_dbus_getter_p2p_peergo(DBusMessage * message,
					 struct wpa_supplicant * wpa_s)
{
	char go_peer_obj_path[WPAS_DBUS_OBJECT_PATH_MAX], *path;

	if (wpas_get_p2p_role(wpa_s) != WPAS_P2P_ROLE_CLIENT)
		return NULL;

	os_snprintf(go_peer_obj_path, WPAS_DBUS_OBJECT_PATH_MAX,
		    "%s/" WPAS_DBUS_NEW_P2P_PEERS_PART "/" COMPACT_MACSTR,
		    wpa_s->dbus_new_path, MAC2STR(wpa_s->go_dev_addr));
	path = go_peer_obj_path;
	return wpas_dbus_simple_property_getter(message,
						DBUS_TYPE_OBJECT_PATH, &path);
}

/*
 * Peer object properties accessor methods
 */

DBusMessage *wpas_dbus_getter_p2p_peer_properties(DBusMessage * message,
						  struct peer_handler_args *
						  peer_args)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, dict_iter;
	const struct p2p_peer_info *info = NULL;
	char devtype[WPS_DEV_TYPE_BUFSIZE];

	/* get the peer info */
	info = p2p_get_peer_found(peer_args->wpa_s->global->p2p,
				  peer_args->p2p_device_addr, 0);
	if (info == NULL)
		return NULL;

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (!reply)
		goto err_no_mem;

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "a{sv}", &variant_iter) ||
	    !wpa_dbus_dict_open_write(&variant_iter, &dict_iter))
		goto err_no_mem;

	/* Fill out the dictionary */
	wps_dev_type_bin2str(info->pri_dev_type, devtype, sizeof(devtype));
	if (!wpa_dbus_dict_append_string(&dict_iter, "DeviceName",
					 info->device_name))
		goto err_no_mem;
	if (!wpa_dbus_dict_append_string(&dict_iter, "PrimaryDeviceType",
					 devtype))
		goto err_no_mem;
	if (!wpa_dbus_dict_append_uint16(&dict_iter, "config_method",
					 info->config_methods))
		goto err_no_mem;
	if (!wpa_dbus_dict_append_int32(&dict_iter, "level",
					 info->level))
		goto err_no_mem;
	if (!wpa_dbus_dict_append_byte(&dict_iter, "devicecapability",
				       info->dev_capab))
		goto err_no_mem;
	if (!wpa_dbus_dict_append_byte(&dict_iter, "groupcapability",
				       info->group_capab))
		goto err_no_mem;

	if (info->wps_sec_dev_type_list_len) {
		char *sec_dev_types[MAX_SEC_DEVICE_TYPES];
		u8 *sec_dev_type_list = NULL;
		char secdevtype[WPS_DEV_TYPE_BUFSIZE];
		int num_sec_dev_types = 0;
		int i;

		sec_dev_type_list = os_zalloc(info->wps_sec_dev_type_list_len);

		if (sec_dev_type_list == NULL)
			goto err_no_mem;

		os_memcpy(sec_dev_type_list, info->wps_sec_dev_type_list,
			  info->wps_sec_dev_type_list_len);

		for (i = 0; i < MAX_SEC_DEVICE_TYPES &&
		       i < (int) (info->wps_sec_dev_type_list_len /
				  WPS_DEV_TYPE_LEN);
		     i++) {
			sec_dev_types[i] = os_zalloc(sizeof(secdevtype));

			if (!sec_dev_types[i] ||
			    wps_dev_type_bin2str(
					&sec_dev_type_list[i *
							   WPS_DEV_TYPE_LEN],
					sec_dev_types[i],
					sizeof(secdevtype)) == NULL) {
				while (--i >= 0)
					os_free(sec_dev_types[i]);
				os_free(sec_dev_type_list);
				goto err_no_mem;
			}

			num_sec_dev_types++;
		}

		os_free(sec_dev_type_list);

		if (num_sec_dev_types) {
			if (!wpa_dbus_dict_append_string_array(&dict_iter,
						"SecondaryDeviceTypes",
						(const char **)sec_dev_types,
						num_sec_dev_types)) {
				for (i = 0; i < num_sec_dev_types; i++)
					os_free(sec_dev_types[i]);
				goto err_no_mem;
			}

			for (i = 0; i < num_sec_dev_types; i++)
				os_free(sec_dev_types[i]);
		}
	}

	{
		/* Add WPS vendor extensions attribute */
		const struct wpabuf *vendor_extension[P2P_MAX_WPS_VENDOR_EXT];
		int i, num = 0;

		for (i = 0; i < P2P_MAX_WPS_VENDOR_EXT; i++) {
			if (info->wps_vendor_ext[i] == NULL)
				continue;
			vendor_extension[num] = info->wps_vendor_ext[i];
			num++;
		}

		if (!wpa_dbus_dict_append_wpabuf_array(
					&dict_iter, "VendorExtension",
					vendor_extension, num))
			goto err_no_mem;
	}

	if (!wpa_dbus_dict_close_write(&variant_iter, &dict_iter) ||
	    !dbus_message_iter_close_container(&iter, &variant_iter))
		goto err_no_mem;

	return reply;
err_no_mem:
	dbus_message_unref(reply);
	return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}

DBusMessage *wpas_dbus_getter_p2p_peer_ies(DBusMessage * message,
					   struct peer_handler_args * peer_args)
{
	return NULL;
}


/**
 * wpas_dbus_getter_persistent_groups - Get array of peristent group objects
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: a dbus message containing an array of all persistent group
 * dbus object paths.
 *
 * Getter for "Networks" property.
 */
DBusMessage * wpas_dbus_getter_persistent_groups(DBusMessage *message,
						 struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	struct wpa_ssid *ssid;
	char **paths;
	unsigned int i = 0, num = 0;

	if (wpa_s->conf == NULL) {
		wpa_printf(MSG_ERROR, "dbus: %s: "
			   "An error occurred getting persistent groups list",
			   __func__);
		return wpas_dbus_error_unknown_error(message, NULL);
	}

	for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next)
		if (network_is_persistent_group(ssid))
			num++;

	paths = os_zalloc(num * sizeof(char *));
	if (!paths) {
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					      NULL);
	}

	/* Loop through configured networks and append object path of each */
	for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next) {
		if (!network_is_persistent_group(ssid))
			continue;
		paths[i] = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
		if (paths[i] == NULL) {
			reply = dbus_message_new_error(message,
						       DBUS_ERROR_NO_MEMORY,
						       NULL);
			goto out;
		}
		/* Construct the object path for this network. */
		os_snprintf(paths[i++], WPAS_DBUS_OBJECT_PATH_MAX,
			    "%s/" WPAS_DBUS_NEW_PERSISTENT_GROUPS_PART "/%d",
			    wpa_s->dbus_new_path, ssid->id);
	}

	reply = wpas_dbus_simple_array_property_getter(message,
						       DBUS_TYPE_OBJECT_PATH,
						       paths, num);

out:
	while (i)
		os_free(paths[--i]);
	os_free(paths);
	return reply;
}


/**
 * wpas_dbus_getter_persistent_group_properties - Get options for a persistent
 *	group
 * @message: Pointer to incoming dbus message
 * @net: wpa_supplicant structure for a network interface and
 * wpa_ssid structure for a configured persistent group (internally network)
 * Returns: DBus message with network properties or DBus error on failure
 *
 * Getter for "Properties" property of a persistent group.
 */
DBusMessage * wpas_dbus_getter_persistent_group_properties(
	DBusMessage *message, struct network_handler_args *net)
{
	/*
	 * Leveraging the fact that persistent group object is still
	 * represented in same manner as network within.
	 */
	return wpas_dbus_getter_network_properties(message, net);
}


/**
 * wpas_dbus_setter_persistent_group_properties - Get options for a persistent
 *	group
 * @message: Pointer to incoming dbus message
 * @net: wpa_supplicant structure for a network interface and
 * wpa_ssid structure for a configured persistent group (internally network)
 * Returns: DBus message with network properties or DBus error on failure
 *
 * Setter for "Properties" property of a persistent group.
 */
DBusMessage * wpas_dbus_setter_persistent_group_properties(
	DBusMessage *message, struct network_handler_args *net)
{
	struct wpa_ssid *ssid = net->ssid;
	DBusMessage *reply = NULL;
	DBusMessageIter	iter, variant_iter;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);

	dbus_message_iter_recurse(&iter, &variant_iter);

	/*
	 * Leveraging the fact that persistent group object is still
	 * represented in same manner as network within.
	 */
	reply = set_network_properties(message, net->wpa_s, ssid,
				       &variant_iter);
	if (reply)
		wpa_printf(MSG_DEBUG, "dbus control interface couldn't set "
			   "persistent group properties");

	return reply;
}


/**
 * wpas_dbus_new_iface_add_persistent_group - Add a new configured
 *	persistent_group
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: A dbus message containing the object path of the new
 * persistent group
 *
 * Handler function for "AddPersistentGroup" method call of a P2P Device
 * interface.
 */
DBusMessage * wpas_dbus_handler_add_persistent_group(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter	iter;
	struct wpa_ssid *ssid = NULL;
	char path_buf[WPAS_DBUS_OBJECT_PATH_MAX], *path = path_buf;

	dbus_message_iter_init(message, &iter);

	ssid = wpa_config_add_network(wpa_s->conf);
	if (ssid == NULL) {
		wpa_printf(MSG_ERROR, "dbus: %s: "
			   "Cannot add new persistent group", __func__);
		reply = wpas_dbus_error_unknown_error(
			message,
			"wpa_supplicant could not add "
			"a persistent group on this interface.");
		goto err;
	}

	/* Mark the ssid as being a persistent group before the notification */
	ssid->disabled = 2;
	ssid->p2p_persistent_group = 1;
	wpas_notify_persistent_group_added(wpa_s, ssid);

	wpa_config_set_network_defaults(ssid);

	reply = set_network_properties(message, wpa_s, ssid, &iter);
	if (reply) {
		wpa_printf(MSG_DEBUG, "dbus: %s: "
			   "Control interface could not set persistent group "
			   "properties", __func__);
		goto err;
	}

	/* Construct the object path for this network. */
	os_snprintf(path, WPAS_DBUS_OBJECT_PATH_MAX,
		    "%s/" WPAS_DBUS_NEW_PERSISTENT_GROUPS_PART "/%d",
		    wpa_s->dbus_new_path, ssid->id);

	reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}
	if (!dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
				      DBUS_TYPE_INVALID)) {
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
		goto err;
	}

	return reply;

err:
	if (ssid) {
		wpas_notify_persistent_group_removed(wpa_s, ssid);
		wpa_config_remove_network(wpa_s->conf, ssid->id);
	}
	return reply;
}


/**
 * wpas_dbus_handler_remove_persistent_group - Remove a configured persistent
 *	group
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: NULL on success or dbus error on failure
 *
 * Handler function for "RemovePersistentGroup" method call of a P2P Device
 * interface.
 */
DBusMessage * wpas_dbus_handler_remove_persistent_group(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	const char *op;
	char *iface = NULL, *persistent_group_id = NULL;
	int id;
	struct wpa_ssid *ssid;

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &op,
			      DBUS_TYPE_INVALID);

	/*
	 * Extract the network ID and ensure the network is actually a child of
	 * this interface.
	 */
	iface = wpas_dbus_new_decompose_object_path(op, 1,
						    &persistent_group_id,
						    NULL);
	if (iface == NULL || os_strcmp(iface, wpa_s->dbus_new_path) != 0) {
		reply = wpas_dbus_error_invalid_args(message, op);
		goto out;
	}

	id = strtoul(persistent_group_id, NULL, 10);
	if (errno == EINVAL) {
		reply = wpas_dbus_error_invalid_args(message, op);
		goto out;
	}

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (ssid == NULL) {
		reply = wpas_dbus_error_persistent_group_unknown(message);
		goto out;
	}

	wpas_notify_persistent_group_removed(wpa_s, ssid);

	if (wpa_config_remove_network(wpa_s->conf, id) < 0) {
		wpa_printf(MSG_ERROR, "dbus: %s: "
			   "error occurred when removing persistent group %d",
			   __func__, id);
		reply = wpas_dbus_error_unknown_error(
			message,
			"error removing the specified persistent group on "
			"this interface.");
		goto out;
	}

out:
	os_free(iface);
	os_free(persistent_group_id);
	return reply;
}


static void remove_persistent_group(struct wpa_supplicant *wpa_s,
				    struct wpa_ssid *ssid)
{
	wpas_notify_persistent_group_removed(wpa_s, ssid);

	if (wpa_config_remove_network(wpa_s->conf, ssid->id) < 0) {
		wpa_printf(MSG_ERROR, "dbus: %s: "
			   "error occurred when removing persistent group %d",
			   __func__, ssid->id);
		return;
	}
}


/**
 * wpas_dbus_handler_remove_all_persistent_groups - Remove all configured
 * persistent groups
 * @message: Pointer to incoming dbus message
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: NULL on success or dbus error on failure
 *
 * Handler function for "RemoveAllPersistentGroups" method call of a
 * P2P Device interface.
 */
DBusMessage * wpas_dbus_handler_remove_all_persistent_groups(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid, *next;
	struct wpa_config *config;

	config = wpa_s->conf;
	ssid = config->ssid;
	while (ssid) {
		next = ssid->next;
		if (network_is_persistent_group(ssid))
			remove_persistent_group(wpa_s, ssid);
		ssid = next;
	}
	return NULL;
}


/*
 * Group object properties accessor methods
 */

DBusMessage *wpas_dbus_getter_p2p_group_members(DBusMessage * message,
						struct wpa_supplicant * wpa_s)
{
	DBusMessage *reply = NULL;
	struct wpa_ssid *ssid;
	unsigned int num_members;
	char **paths;
	unsigned int i;
	void *next = NULL;
	const u8 *addr;

	/* Ensure we are a GO */
	if (wpa_s->wpa_state != WPA_COMPLETED)
		goto out;

	ssid = wpa_s->conf->ssid;
	/* At present WPAS P2P_GO mode only applicable for p2p_go */
	if (ssid->mode != WPAS_MODE_P2P_GO &&
	    ssid->mode != WPAS_MODE_AP &&
	    ssid->mode != WPAS_MODE_P2P_GROUP_FORMATION)
		goto out;

	num_members = p2p_get_group_num_members(wpa_s->p2p_group);

	paths = os_zalloc(num_members * sizeof(char *));
	if (!paths)
		goto out_of_memory;

	i = 0;
	while ((addr = p2p_iterate_group_members(wpa_s->p2p_group, &next))) {
		paths[i] = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
		if (!paths[i])
			goto out_of_memory;
		os_snprintf(paths[i], WPAS_DBUS_OBJECT_PATH_MAX,
			    "%s/" WPAS_DBUS_NEW_P2P_GROUPMEMBERS_PART
			    "/" COMPACT_MACSTR,
			    wpa_s->dbus_groupobj_path, MAC2STR(addr));
		i++;
	}

	reply = wpas_dbus_simple_array_property_getter(message,
						       DBUS_TYPE_OBJECT_PATH,
						       paths, num_members);

out_free:
	for (i = 0; i < num_members; i++)
		os_free(paths[i]);
	os_free(paths);
out:
	return reply;
out_of_memory:
	reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
	goto out_free;
}


DBusMessage *wpas_dbus_getter_p2p_group_properties(
	DBusMessage *message,
	struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter, dict_iter;
	struct hostapd_data *hapd = wpa_s->ap_iface->bss[0];
	const struct wpabuf *vendor_ext[MAX_WPS_VENDOR_EXTENSIONS];
	int num_vendor_ext = 0;
	int i;

	if (!hapd) {
		reply = dbus_message_new_error(message, DBUS_ERROR_FAILED,
					       NULL);
		return reply;
	}

	if (message == NULL)
		reply = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);
	else
		reply = dbus_message_new_method_return(message);

	if (!reply)
		goto err_no_mem;

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					      "a{sv}", &variant_iter) ||
	    !wpa_dbus_dict_open_write(&variant_iter, &dict_iter))
		goto err_no_mem;

	/* Parse WPS Vendor Extensions sent in Beacon/Probe Response */
	for (i = 0; i < MAX_WPS_VENDOR_EXTENSIONS; i++) {
		if (hapd->conf->wps_vendor_ext[i] == NULL)
			continue;
		vendor_ext[num_vendor_ext++] = hapd->conf->wps_vendor_ext[i];
	}

	if (!wpa_dbus_dict_append_wpabuf_array(&dict_iter,
					       "WPSVendorExtensions",
					       vendor_ext, num_vendor_ext))
		goto err_no_mem;

	if (!wpa_dbus_dict_close_write(&variant_iter, &dict_iter) ||
	    !dbus_message_iter_close_container(&iter, &variant_iter))
		goto err_no_mem;

	return reply;

err_no_mem:
	dbus_message_unref(reply);
	return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}

DBusMessage *wpas_dbus_setter_p2p_group_properties(
	DBusMessage *message,
	struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;
	struct wpa_dbus_dict_entry entry = {.type = DBUS_TYPE_STRING };
	DBusMessageIter iter_dict;
	unsigned int i;

	struct hostapd_data *hapd = wpa_s->ap_iface->bss[0];

	if (!hapd)
		goto error;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_next(&iter);
	dbus_message_iter_next(&iter);

	dbus_message_iter_recurse(&iter, &variant_iter);

	if (!wpa_dbus_dict_open_read(&variant_iter, &iter_dict))
		return wpas_dbus_error_invalid_args(message, NULL);

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry)) {
			reply = wpas_dbus_error_invalid_args(message, NULL);
			break;
		}

		if (os_strcmp(entry.key, "WPSVendorExtensions") == 0) {
			if (entry.type != DBUS_TYPE_ARRAY ||
			    entry.array_type != WPAS_DBUS_TYPE_BINARRAY ||
			    entry.array_len > MAX_WPS_VENDOR_EXTENSIONS)
				goto error;

			for (i = 0; i < MAX_WPS_VENDOR_EXTENSIONS; i++) {
				if (i < entry.array_len) {
					hapd->conf->wps_vendor_ext[i] =
						entry.binarray_value[i];
					entry.binarray_value[i] = NULL;
				} else
					hapd->conf->wps_vendor_ext[i] = NULL;
			}

			hostapd_update_wps(hapd);
		} else
			goto error;

		wpa_dbus_dict_entry_clear(&entry);
	}

	return reply;

error:
	reply = wpas_dbus_error_invalid_args(message, entry.key);
	wpa_dbus_dict_entry_clear(&entry);

	return reply;
}

DBusMessage *wpas_dbus_handler_p2p_add_service(DBusMessage * message,
					       struct wpa_supplicant * wpa_s)
{
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;
	int upnp = 0;
	int bonjour = 0;
	char *service = NULL;
	struct wpabuf *query = NULL;
	struct wpabuf *resp = NULL;
	u8 version = 0;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;

	if (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;

		if (!strcmp(entry.key, "service_type") &&
		    (entry.type == DBUS_TYPE_STRING)) {
			if (!strcmp(entry.str_value, "upnp"))
				upnp = 1;
			else if (!strcmp(entry.str_value, "bonjour"))
				bonjour = 1;
			else
				goto error_clear;
			wpa_dbus_dict_entry_clear(&entry);
		}
	}

	if (upnp == 1) {
		while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
			if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
				goto error;

			if (!strcmp(entry.key, "version") &&
			    entry.type == DBUS_TYPE_INT32)
				version = entry.uint32_value;
			else if (!strcmp(entry.key, "service") &&
				 entry.type == DBUS_TYPE_STRING)
				service = os_strdup(entry.str_value);
			wpa_dbus_dict_entry_clear(&entry);
		}
		if (version <= 0 || service == NULL)
			goto error;

		if (wpas_p2p_service_add_upnp(wpa_s, version, service) != 0)
			goto error;

		os_free(service);
	} else if (bonjour == 1) {
		while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
			if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
				goto error;

			if (!strcmp(entry.key, "query")) {
				if ((entry.type != DBUS_TYPE_ARRAY) ||
				    (entry.array_type != DBUS_TYPE_BYTE))
					goto error_clear;
				query = wpabuf_alloc_copy(entry.bytearray_value,
							  entry.array_len);
			} else if (!strcmp(entry.key, "response")) {
				if ((entry.type != DBUS_TYPE_ARRAY) ||
				    (entry.array_type != DBUS_TYPE_BYTE))
					goto error_clear;
				resp = wpabuf_alloc_copy(entry.bytearray_value,
							 entry.array_len);
			}

			wpa_dbus_dict_entry_clear(&entry);
		}

		if (query == NULL || resp == NULL)
			goto error;

		if (wpas_p2p_service_add_bonjour(wpa_s, query, resp) < 0) {
			wpabuf_free(query);
			wpabuf_free(resp);
			goto error;
		}
	} else
		goto error;

	return reply;
error_clear:
	wpa_dbus_dict_entry_clear(&entry);
error:
	return wpas_dbus_error_invalid_args(message, NULL);
}

DBusMessage *wpas_dbus_handler_p2p_delete_service(DBusMessage * message,
						  struct wpa_supplicant * wpa_s)
{
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;
	int upnp = 0;
	int bonjour = 0;
	int ret = 0;
	char *service = NULL;
	struct wpabuf *query = NULL;
	u8 version = 0;

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;

	if (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;

		if (!strcmp(entry.key, "service_type") &&
		    (entry.type == DBUS_TYPE_STRING)) {
			if (!strcmp(entry.str_value, "upnp"))
				upnp = 1;
			else if (!strcmp(entry.str_value, "bonjour"))
				bonjour = 1;
			else
				goto error_clear;
			wpa_dbus_dict_entry_clear(&entry);
		}
	}
	if (upnp == 1) {
		while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
			if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
				goto error;
			if (!strcmp(entry.key, "version") &&
			    entry.type == DBUS_TYPE_INT32)
				version = entry.uint32_value;
			else if (!strcmp(entry.key, "service") &&
				 entry.type == DBUS_TYPE_STRING)
				service = os_strdup(entry.str_value);
			else
				goto error_clear;

			wpa_dbus_dict_entry_clear(&entry);
		}

		if (version <= 0 || service == NULL)
			goto error;

		ret = wpas_p2p_service_del_upnp(wpa_s, version, service);
		os_free(service);
		if (ret != 0)
			goto error;
	} else if (bonjour == 1) {
		while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
			if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
				goto error;

			if (!strcmp(entry.key, "query")) {
				if ((entry.type != DBUS_TYPE_ARRAY) ||
				    (entry.array_type != DBUS_TYPE_BYTE))
					goto error_clear;
				query = wpabuf_alloc_copy(entry.bytearray_value,
							  entry.array_len);
			} else
				goto error_clear;

			wpa_dbus_dict_entry_clear(&entry);
		}

		if (query == NULL)
			goto error;

		ret = wpas_p2p_service_del_bonjour(wpa_s, query);
		if (ret != 0)
			goto error;
		wpabuf_free(query);
	} else
		goto error;

	return reply;
error_clear:
	wpa_dbus_dict_entry_clear(&entry);
error:
	return wpas_dbus_error_invalid_args(message, NULL);
}

DBusMessage *wpas_dbus_handler_p2p_flush_service(DBusMessage * message,
						 struct wpa_supplicant * wpa_s)
{
	wpas_p2p_service_flush(wpa_s);
	return NULL;
}

DBusMessage *wpas_dbus_handler_p2p_service_sd_req(DBusMessage * message,
						  struct wpa_supplicant * wpa_s)
{
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;
	int upnp = 0;
	char *service = NULL;
	char *peer_object_path = NULL;
	struct wpabuf *tlv = NULL;
	u8 version = 0;
	u64 ref = 0;
	u8 addr[ETH_ALEN];

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;
		if (!strcmp(entry.key, "peer_object") &&
		    entry.type == DBUS_TYPE_OBJECT_PATH) {
			peer_object_path = os_strdup(entry.str_value);
		} else if (!strcmp(entry.key, "service_type") &&
			   entry.type == DBUS_TYPE_STRING) {
			if (!strcmp(entry.str_value, "upnp"))
				upnp = 1;
			else
				goto error_clear;
		} else if (!strcmp(entry.key, "version") &&
			   entry.type == DBUS_TYPE_INT32) {
			version = entry.uint32_value;
		} else if (!strcmp(entry.key, "service") &&
			   entry.type == DBUS_TYPE_STRING) {
			service = os_strdup(entry.str_value);
		} else if (!strcmp(entry.key, "tlv")) {
			if (entry.type != DBUS_TYPE_ARRAY ||
			    entry.array_type != DBUS_TYPE_BYTE)
				goto error_clear;
			tlv = wpabuf_alloc_copy(entry.bytearray_value,
						entry.array_len);
		} else
			goto error_clear;

		wpa_dbus_dict_entry_clear(&entry);
	}

	if (!peer_object_path ||
	    (parse_peer_object_path(peer_object_path, addr) < 0) ||
	    (p2p_get_peer_info(wpa_s->global->p2p, addr, 0, NULL, 0) < 0))
		goto error;

	if (upnp == 1) {
		if (version <= 0 || service == NULL)
			goto error;

		ref = (unsigned long)wpas_p2p_sd_request_upnp(wpa_s, addr,
							      version, service);
	} else {
		if (tlv == NULL)
			goto error;
		ref = (unsigned long)wpas_p2p_sd_request(wpa_s, addr, tlv);
		wpabuf_free(tlv);
	}

	if (ref != 0) {
		reply = dbus_message_new_method_return(message);
		dbus_message_append_args(reply, DBUS_TYPE_UINT64,
					 &ref, DBUS_TYPE_INVALID);
	} else {
		reply = wpas_dbus_error_unknown_error(message,
				"Unable to send SD request");
	}
out:
	os_free(service);
	os_free(peer_object_path);
	return reply;
error_clear:
	wpa_dbus_dict_entry_clear(&entry);
error:
	if (tlv)
		wpabuf_free(tlv);
	reply = wpas_dbus_error_invalid_args(message, NULL);
	goto out;
}

DBusMessage *wpas_dbus_handler_p2p_service_sd_res(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	DBusMessageIter iter_dict;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct wpa_dbus_dict_entry entry;
	char *peer_object_path = NULL;
	struct wpabuf *tlv = NULL;
	int freq = 0;
	int dlg_tok = 0;
	u8 addr[ETH_ALEN];

	dbus_message_iter_init(message, &iter);

	if (!wpa_dbus_dict_open_read(&iter, &iter_dict))
		goto error;

	while (wpa_dbus_dict_has_dict_entry(&iter_dict)) {
		if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
			goto error;

		if (!strcmp(entry.key, "peer_object") &&
		    entry.type == DBUS_TYPE_OBJECT_PATH) {
			peer_object_path = os_strdup(entry.str_value);
		} else if (!strcmp(entry.key, "frequency") &&
			   entry.type == DBUS_TYPE_INT32) {
			freq = entry.uint32_value;
		} else if (!strcmp(entry.key, "dialog_token") &&
			   entry.type == DBUS_TYPE_UINT32) {
			dlg_tok = entry.uint32_value;
		} else if (!strcmp(entry.key, "tlvs")) {
			if (entry.type != DBUS_TYPE_ARRAY ||
			    entry.array_type != DBUS_TYPE_BYTE)
				goto error_clear;
			tlv = wpabuf_alloc_copy(entry.bytearray_value,
						entry.array_len);
		} else
			goto error_clear;

		wpa_dbus_dict_entry_clear(&entry);
	}
	if (!peer_object_path ||
	    (parse_peer_object_path(peer_object_path, addr) < 0) ||
	    (p2p_get_peer_info(wpa_s->global->p2p, addr, 0, NULL, 0) < 0))
		goto error;

	if (tlv == NULL)
		goto error;

	wpas_p2p_sd_response(wpa_s, freq, addr, (u8) dlg_tok, tlv);
	wpabuf_free(tlv);
out:
	os_free(peer_object_path);
	return reply;
error_clear:
	wpa_dbus_dict_entry_clear(&entry);
error:
	reply = wpas_dbus_error_invalid_args(message, NULL);
	goto out;
}

DBusMessage *wpas_dbus_handler_p2p_service_sd_cancel_req(DBusMessage * message, struct wpa_supplicant
							 *wpa_s)
{
	DBusMessageIter iter;
	u64 req = 0;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_get_basic(&iter, &req);

	if (req == 0)
		goto error;

	if (!wpas_p2p_sd_cancel_request(wpa_s, (void *)(unsigned long)req))
		goto error;

	return NULL;
error:
	return wpas_dbus_error_invalid_args(message, NULL);
}

DBusMessage *wpas_dbus_handler_p2p_service_update(DBusMessage * message,
						  struct wpa_supplicant * wpa_s)
{
	wpas_p2p_sd_service_update(wpa_s);
	return NULL;
}

DBusMessage *wpas_dbus_handler_p2p_serv_disc_external(DBusMessage * message,
						      struct wpa_supplicant *
						      wpa_s)
{
	DBusMessageIter iter;
	int ext = 0;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_get_basic(&iter, &ext);

	wpa_s->p2p_sd_over_ctrl_iface = ext;

	return NULL;

}
