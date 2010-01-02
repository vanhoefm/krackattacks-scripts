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
#include "dbus_common.h"
#include "dbus_common_i.h"
#include "dbus_new_helpers.h"


/**
 * recursive_iter_copy - Reads arguments from one iterator and
 * writes to another recursively
 * @from: iterator to read from
 * @to: iterator to write to
 *
 * Copies one iterator's elements to another. If any element in
 * iterator is of container type, its content is copied recursively
 */
static void recursive_iter_copy(DBusMessageIter *from, DBusMessageIter *to)
{

	char *subtype = NULL;
	int type;

	/* iterate over iterator to copy */
	while ((type = dbus_message_iter_get_arg_type(from)) !=
	       DBUS_TYPE_INVALID) {

		/* simply copy basic type entries */
		if (dbus_type_is_basic(type)) {
			if (dbus_type_is_fixed(type)) {
				/*
				 * According to DBus documentation all
				 * fixed-length types are guaranteed to fit
				 * 8 bytes
				 */
				dbus_uint64_t v;
				dbus_message_iter_get_basic(from, &v);
				dbus_message_iter_append_basic(to, type, &v);
			} else {
				char *v;
				dbus_message_iter_get_basic(from, &v);
				dbus_message_iter_append_basic(to, type, &v);
			}
		} else {
			/* recursively copy container type entries */
			DBusMessageIter write_subiter, read_subiter;

			dbus_message_iter_recurse(from, &read_subiter);

			if (type == DBUS_TYPE_VARIANT ||
			    type == DBUS_TYPE_ARRAY) {
				subtype = dbus_message_iter_get_signature(
					&read_subiter);
			}

			dbus_message_iter_open_container(to, type, subtype,
							 &write_subiter);

			recursive_iter_copy(&read_subiter, &write_subiter);

			dbus_message_iter_close_container(to, &write_subiter);
			if (subtype)
				dbus_free(subtype);
		}

		dbus_message_iter_next(from);
	}
}


static unsigned int fill_dict_with_properties(
	DBusMessageIter *dict_iter, struct wpa_dbus_property_desc *props,
	const char *interface, const void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter entry_iter, ret_iter;
	unsigned int counter = 0;
	struct wpa_dbus_property_desc *property_dsc;

	for (property_dsc = props; property_dsc;
	     property_dsc = property_dsc->next) {
		if (!os_strncmp(property_dsc->dbus_interface, interface,
				WPAS_DBUS_INTERFACE_MAX) &&
		    property_dsc->access != W && property_dsc->getter) {
			reply = property_dsc->getter(NULL, user_data);
			if (!reply)
				continue;

			if (dbus_message_get_type(reply) ==
			    DBUS_MESSAGE_TYPE_ERROR) {
				dbus_message_unref(reply);
				continue;
			}

			dbus_message_iter_init(reply, &ret_iter);

			dbus_message_iter_open_container(dict_iter,
							 DBUS_TYPE_DICT_ENTRY,
							 NULL, &entry_iter);
			dbus_message_iter_append_basic(
				&entry_iter, DBUS_TYPE_STRING,
				&(property_dsc->dbus_property));

			recursive_iter_copy(&ret_iter, &entry_iter);

			dbus_message_iter_close_container(dict_iter,
							  &entry_iter);
			dbus_message_unref(reply);
			counter++;
		}
	}

	return counter;
}


/**
 * get_all_properties - Responds for GetAll properties calls on object
 * @message: Message with GetAll call
 * @interface: interface name which properties will be returned
 * @property_dsc: list of object's properties
 * Returns: Message with dict of variants as argument with properties values
 *
 * Iterates over all properties registered with object and execute getters
 * of those, which are readable and which interface matches interface
 * specified as argument. Returned message contains one dict argument
 * with properties names as keys and theirs values as values.
 */
static DBusMessage * get_all_properties(
	DBusMessage *message, char *interface,
	struct wpa_dbus_object_desc *obj_dsc)
{
	/* Create and initialize the return message */
	DBusMessage *reply = dbus_message_new_method_return(message);
	DBusMessageIter iter, dict_iter;
	int props_num;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_VARIANT_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					 &dict_iter);

	props_num = fill_dict_with_properties(&dict_iter,obj_dsc->properties,
					      interface, obj_dsc->user_data);

	dbus_message_iter_close_container(&iter, &dict_iter);

	if (props_num == 0) {
		dbus_message_unref(reply);
		reply = dbus_message_new_error(message,
					       DBUS_ERROR_INVALID_ARGS,
					       "No readable properties in "
					       "this interface");
	}

	return reply;
}


static int is_signature_correct(DBusMessage *message,
				struct wpa_dbus_method_desc *method_dsc)
{
	/* According to DBus documentation max length of signature is 255 */
#define MAX_SIG_LEN 256
	char registered_sig[MAX_SIG_LEN], *pos;
	const char *sig = dbus_message_get_signature(message);
	int i, ret;

	pos = registered_sig;
	*pos = '\0';

	for (i = 0; i < method_dsc->args_num; i++) {
		struct wpa_dbus_argument arg = method_dsc->args[i];
		if (arg.dir == ARG_IN) {
			size_t blen = registered_sig + MAX_SIG_LEN - pos;
			ret = os_snprintf(pos, blen, "%s", arg.type);
			if (ret < 0 || (size_t) ret >= blen)
				return 0;
			pos += ret;
		}
	}

	return !os_strncmp(registered_sig, sig, MAX_SIG_LEN);
}


static DBusMessage * properties_get_all(DBusMessage *message, char *interface,
					struct wpa_dbus_object_desc *obj_dsc)
{
	if (os_strcmp(dbus_message_get_signature(message), "s") != 0)
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      NULL);

	return get_all_properties(message, interface, obj_dsc);
}


static DBusMessage * properties_get(DBusMessage *message,
				    struct wpa_dbus_property_desc *dsc,
				    void *user_data)
{
	if (os_strcmp(dbus_message_get_signature(message), "ss"))
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      NULL);

	if (dsc->access != W && dsc->getter)
		return dsc->getter(message, user_data);

	return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				      "Property is write-only");
}


static DBusMessage * properties_set(DBusMessage *message,
				    struct wpa_dbus_property_desc *dsc,
				    void *user_data)
{
	if (os_strcmp(dbus_message_get_signature(message), "ssv"))
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      NULL);

	if (dsc->access != R && dsc->setter)
		return dsc->setter(message, user_data);

	return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				      "Property is read-only");
}


static DBusMessage *
properties_get_or_set(DBusMessage *message, DBusMessageIter *iter,
		      char *interface,
		      struct wpa_dbus_object_desc *obj_dsc)
{
	struct wpa_dbus_property_desc *property_dsc;
	char *property;
	const char *method;

	method = dbus_message_get_member(message);
	property_dsc = obj_dsc->properties;

	/* Second argument: property name (DBUS_TYPE_STRING) */
	if (!dbus_message_iter_next(iter) ||
	    dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      NULL);
	}
	dbus_message_iter_get_basic(iter, &property);

	while (property_dsc) {
		/* compare property names and
		 * interfaces */
		if (!os_strncmp(property_dsc->dbus_property, property,
				WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) &&
		    !os_strncmp(property_dsc->dbus_interface, interface,
				WPAS_DBUS_INTERFACE_MAX))
			break;

		property_dsc = property_dsc->next;
	}
	if (property_dsc == NULL) {
		wpa_printf(MSG_DEBUG, "no property handler for %s.%s on %s",
			   interface, property,
			   dbus_message_get_path(message));
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      "No such property");
	}

	if (os_strncmp(WPA_DBUS_PROPERTIES_GET, method,
		       WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) == 0)
		return properties_get(message, property_dsc,
				      obj_dsc->user_data);

	return properties_set(message, property_dsc, obj_dsc->user_data);
}


static DBusMessage * properties_handler(DBusMessage *message,
					struct wpa_dbus_object_desc *obj_dsc)
{
	DBusMessageIter iter;
	char *interface;
	const char *method;

	method = dbus_message_get_member(message);
	dbus_message_iter_init(message, &iter);

	if (!os_strncmp(WPA_DBUS_PROPERTIES_GET, method,
			WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) ||
	    !os_strncmp(WPA_DBUS_PROPERTIES_SET, method,
			WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) ||
	    !os_strncmp(WPA_DBUS_PROPERTIES_GETALL, method,
			WPAS_DBUS_METHOD_SIGNAL_PROP_MAX)) {
		/* First argument: interface name (DBUS_TYPE_STRING) */
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		{
			return dbus_message_new_error(message,
						      DBUS_ERROR_INVALID_ARGS,
						      NULL);
		}

		dbus_message_iter_get_basic(&iter, &interface);

		if (!os_strncmp(WPA_DBUS_PROPERTIES_GETALL, method,
				WPAS_DBUS_METHOD_SIGNAL_PROP_MAX)) {
			/* GetAll */
			return properties_get_all(message, interface, obj_dsc);
		}
		/* Get or Set */
		return properties_get_or_set(message, &iter, interface,
					     obj_dsc);
	}
	return dbus_message_new_error(message, DBUS_ERROR_UNKNOWN_METHOD,
				      NULL);
}


static DBusMessage * msg_method_handler(DBusMessage *message,
					struct wpa_dbus_object_desc *obj_dsc)
{
	struct wpa_dbus_method_desc *method_dsc = obj_dsc->methods;
	const char *method;
	const char *msg_interface;

	method = dbus_message_get_member(message);
	msg_interface = dbus_message_get_interface(message);

	/* try match call to any registered method */
	while (method_dsc) {
		/* compare method names and interfaces */
		if (!os_strncmp(method_dsc->dbus_method, method,
				WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) &&
		    !os_strncmp(method_dsc->dbus_interface, msg_interface,
				WPAS_DBUS_INTERFACE_MAX))
			break;

		method_dsc = method_dsc->next;
	}
	if (method_dsc == NULL) {
		wpa_printf(MSG_DEBUG, "no method handler for %s.%s on %s",
			   msg_interface, method,
			   dbus_message_get_path(message));
		return dbus_message_new_error(message,
					      DBUS_ERROR_UNKNOWN_METHOD, NULL);
	}

	if (!is_signature_correct(message, method_dsc)) {
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      NULL);
	}

	return method_dsc->method_handler(message,
					  obj_dsc->user_data);
}


/**
 * message_handler - Handles incoming DBus messages
 * @connection: DBus connection on which message was received
 * @message: Received message
 * @user_data: pointer to description of object to which message was sent
 * Returns: Returns information whether message was handled or not
 *
 * Reads message interface and method name, then checks if they matches one
 * of the special cases i.e. introspection call or properties get/getall/set
 * methods and handles it. Else it iterates over registered methods list
 * and tries to match method's name and interface to those read from message
 * If appropriate method was found its handler function is called and
 * response is sent. Otherwise, the DBUS_ERROR_UNKNOWN_METHOD error message
 * will be sent.
 */
static DBusHandlerResult message_handler(DBusConnection *connection,
					 DBusMessage *message, void *user_data)
{
	struct wpa_dbus_object_desc *obj_dsc = user_data;
	const char *method;
	const char *path;
	const char *msg_interface;
	DBusMessage *reply;

	/* get method, interface and path the message is addressed to */
	method = dbus_message_get_member(message);
	path = dbus_message_get_path(message);
	msg_interface = dbus_message_get_interface(message);
	if (!method || !path || !msg_interface)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	wpa_printf(MSG_MSGDUMP, "dbus: %s.%s (%s)",
		   msg_interface, method, path);

	/* if message is introspection method call */
	if (!os_strncmp(WPA_DBUS_INTROSPECTION_METHOD, method,
			WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) &&
	    !os_strncmp(WPA_DBUS_INTROSPECTION_INTERFACE, msg_interface,
			WPAS_DBUS_INTERFACE_MAX)) {
#ifdef CONFIG_CTRL_IFACE_DBUS_INTRO
		reply = wpa_dbus_introspect(message, obj_dsc);
#else /* CONFIG_CTRL_IFACE_DBUS_INTRO */
		reply = dbus_message_new_error(
			message, DBUS_ERROR_UNKNOWN_METHOD,
			"wpa_supplicant was compiled without "
			"introspection support.");
#endif /* CONFIG_CTRL_IFACE_DBUS_INTRO */
	} else if (!os_strncmp(WPA_DBUS_PROPERTIES_INTERFACE, msg_interface,
			     WPAS_DBUS_INTERFACE_MAX)) {
		/* if message is properties method call */
		reply = properties_handler(message, obj_dsc);
	} else {
		reply = msg_method_handler(message, obj_dsc);
	}

	/* If handler succeed returning NULL, reply empty message */
	if (!reply)
		reply = dbus_message_new_method_return(message);
	if (reply) {
		if (!dbus_message_get_no_reply(message))
			dbus_connection_send(connection, reply, NULL);
		dbus_message_unref(reply);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}


/**
 * free_dbus_object_desc - Frees object description data structure
 * @connection: DBus connection
 * @obj_dsc: Object description to free
 *
 * Frees each of properties, methods and signals description lists and
 * the object description structure itself.
 */
void free_dbus_object_desc(struct wpa_dbus_object_desc *obj_dsc)
{
	struct wpa_dbus_method_desc *method_dsc, *tmp_met_dsc;
	struct wpa_dbus_signal_desc *signal_dsc, *tmp_sig_dsc;
	struct wpa_dbus_property_desc *property_dsc, *tmp_prop_dsc;
	int i;

	if (!obj_dsc)
		return;

	/* free methods */
	method_dsc = obj_dsc->methods;

	while (method_dsc) {
		tmp_met_dsc = method_dsc;
		method_dsc = method_dsc->next;

		os_free(tmp_met_dsc->dbus_interface);
		os_free(tmp_met_dsc->dbus_method);

		for (i = 0; i < tmp_met_dsc->args_num; i++) {
			os_free(tmp_met_dsc->args[i].name);
			os_free(tmp_met_dsc->args[i].type);
		}

		os_free(tmp_met_dsc);
	}

	/* free signals */
	signal_dsc = obj_dsc->signals;

	while (signal_dsc) {
		tmp_sig_dsc = signal_dsc;
		signal_dsc = signal_dsc->next;

		os_free(tmp_sig_dsc->dbus_interface);
		os_free(tmp_sig_dsc->dbus_signal);

		for (i = 0; i < tmp_sig_dsc->args_num; i++) {
			os_free(tmp_sig_dsc->args[i].name);
			os_free(tmp_sig_dsc->args[i].type);
		}

		os_free(tmp_sig_dsc);
	}

	/* free properties */
	property_dsc = obj_dsc->properties;

	while (property_dsc) {
		tmp_prop_dsc = property_dsc;
		property_dsc = property_dsc->next;

		os_free(tmp_prop_dsc->dbus_interface);
		os_free(tmp_prop_dsc->dbus_property);
		os_free(tmp_prop_dsc->type);

		os_free(tmp_prop_dsc);
	}

	/* free handler's argument */
	if (obj_dsc->user_data_free_func)
		obj_dsc->user_data_free_func(obj_dsc->user_data);

	os_free(obj_dsc);
}


static void free_dbus_object_desc_cb(DBusConnection *connection, void *obj_dsc)
{
	free_dbus_object_desc(obj_dsc);
}

/**
 * wpa_dbus_ctrl_iface_init - Initialize dbus control interface
 * @application_data: Pointer to application specific data structure
 * @dbus_path: DBus path to interface object
 * @dbus_service: DBus service name to register with
 * @messageHandler: a pointer to function which will handle dbus messages
 * coming on interface
 * Returns: 0 on success, -1 on failure
 *
 * Initialize the dbus control interface and start receiving commands from
 * external programs over the bus.
 */
int wpa_dbus_ctrl_iface_init(struct wpas_dbus_priv *iface,
			     char *dbus_path, char *dbus_service,
			     struct wpa_dbus_object_desc *obj_desc)
{
	DBusError error;
	int ret = -1;
	DBusObjectPathVTable wpa_vtable = {
		&free_dbus_object_desc_cb, &message_handler,
		NULL, NULL, NULL, NULL
	};

	obj_desc->connection = iface->con;

	/* Register the message handler for the global dbus interface */
	if (!dbus_connection_register_object_path(iface->con,
						  dbus_path, &wpa_vtable,
						  obj_desc)) {
		wpa_printf(MSG_ERROR, "dbus: Could not set up message "
			   "handler");
		return -1;
	}

	/* Register our service with the message bus */
	dbus_error_init(&error);
	switch (dbus_bus_request_name(iface->con, dbus_service,
				      0, &error)) {
	case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER:
		ret = 0;
		break;
	case DBUS_REQUEST_NAME_REPLY_EXISTS:
	case DBUS_REQUEST_NAME_REPLY_IN_QUEUE:
	case DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER:
		wpa_printf(MSG_ERROR, "dbus: Could not request service name: "
			   "already registered");
		break;
	default:
		wpa_printf(MSG_ERROR, "dbus: Could not request service name: "
			   "%s %s", error.name, error.message);
		break;
	}
	dbus_error_free(&error);

	if (ret != 0)
		return -1;

	wpa_printf(MSG_DEBUG, "Providing DBus service '%s'.", dbus_service);

	return 0;
}


/**
 * wpa_dbus_register_object_per_iface - Register a new object with dbus
 * @ctrl_iface: pointer to dbus private data
 * @path: DBus path to object
 * @ifname: interface name
 * @obj_desc: description of object's methods, signals and properties
 * Returns: 0 on success, -1 on error
 *
 * Registers a new interface with dbus and assigns it a dbus object path.
 */
int wpa_dbus_register_object_per_iface(
	struct wpas_dbus_priv *ctrl_iface,
	const char *path, const char *ifname,
	struct wpa_dbus_object_desc *obj_desc)
{
	DBusConnection *con;

	DBusObjectPathVTable vtable = {
		&free_dbus_object_desc_cb, &message_handler,
		NULL, NULL, NULL, NULL
	};

	/* Do nothing if the control interface is not turned on */
	if (ctrl_iface == NULL)
		return 0;

	con = ctrl_iface->con;
	obj_desc->connection = con;

	/* Register the message handler for the interface functions */
	if (!dbus_connection_register_object_path(con, path, &vtable,
						  obj_desc)) {
		wpa_printf(MSG_ERROR, "dbus: Could not set up message "
			   "handler for interface %s object %s", ifname, path);
		return -1;
	}

	return 0;
}


/**
 * wpa_dbus_unregister_object_per_iface - Unregisters DBus object
 * @ctrl_iface: Pointer to dbus private data
 * @path: DBus path to object which will be unregistered
 * Returns: Zero on success and -1 on failure
 *
 * Unregisters DBus object given by its path
 */
int wpa_dbus_unregister_object_per_iface(
	struct wpas_dbus_priv *ctrl_iface, const char *path)
{
	DBusConnection *con = ctrl_iface->con;
	if (!dbus_connection_unregister_object_path(con, path))
		return -1;

	return 0;
}


/**
 * wpa_dbus_method_register - Registers DBus method for given object
 * @obj_dsc: Object description for which a method will be registered
 * @dbus_interface: DBus interface under which method will be registered
 * @dbus_method: a name the method will be registered with
 * @method_handler: a function which will be called to handle this method call
 * @args: method arguments list
 * Returns: Zero on success and -1 on failure
 *
 * Registers DBus method under given name and interface for the object.
 * Method calls will be handled with given handling function.
 * Handler function is required to return a DBusMessage pointer which
 * will be response to method call. Any method call before being handled
 * must have registered appropriate handler by using this function.
 */
int wpa_dbus_method_register(struct wpa_dbus_object_desc *obj_dsc,
			     const char *dbus_interface,
			     const char *dbus_method,
			     WPADBusMethodHandler method_handler,
			     const struct wpa_dbus_argument args[])
{
	struct wpa_dbus_method_desc *method_dsc = obj_dsc->methods;
	struct wpa_dbus_method_desc *prev_desc;
	int args_num = 0;
	int i, error;

	prev_desc = NULL;
	while (method_dsc) {
		prev_desc = method_dsc;
		method_dsc = method_dsc->next;
	}

	/* count args */
	if (args) {
		while (args[args_num].name && args[args_num].type)
			args_num++;
	}

	method_dsc = os_zalloc(sizeof(struct wpa_dbus_method_desc) +
			       args_num * sizeof(struct wpa_dbus_argument));
	if (!method_dsc)
		goto err;

	if (prev_desc == NULL)
		obj_dsc->methods = method_dsc;
	else
		prev_desc->next = method_dsc;

	/* copy interface name */
	method_dsc->dbus_interface = os_strdup(dbus_interface);
	if (!method_dsc->dbus_interface)
		goto err;

	/* copy method name */
	method_dsc->dbus_method = os_strdup(dbus_method);
	if (!method_dsc->dbus_method)
		goto err;

	/* copy arguments */
	error = 0;
	method_dsc->args_num = args_num;
	for (i = 0; i < args_num; i++) {
		method_dsc->args[i].name = os_strdup(args[i].name);
		if (!method_dsc->args[i].name) {
			error = 1;
			continue;
		}

		method_dsc->args[i].type = os_strdup(args[i].type);
		if (!method_dsc->args[i].type) {
			error = 1;
			continue;
		}

		method_dsc->args[i].dir = args[i].dir;
	}
	if (error)
		goto err;

	method_dsc->method_handler = method_handler;
	method_dsc->next = NULL;

	return 0;

err:
	wpa_printf(MSG_WARNING, "Failed to register dbus method %s in "
		   "interface %s", dbus_method, dbus_interface);
	if (method_dsc) {
		os_free(method_dsc->dbus_interface);
		os_free(method_dsc->dbus_method);
		for (i = 0; i < method_dsc->args_num; i++) {
			os_free(method_dsc->args[i].name);
			os_free(method_dsc->args[i].type);
		}

		if (prev_desc == NULL)
			obj_dsc->methods = NULL;
		else
			prev_desc->next = NULL;

		os_free(method_dsc);
	}

	return -1;
}


/**
 * wpa_dbus_signal_register - Registers DBus signal for given object
 * @obj_dsc: Object description for which a signal will be registered
 * @dbus_interface: DBus interface under which signal will be registered
 * @dbus_signal: a name the signal will be registered with
 * @args: signal arguments list
 * Returns: Zero on success and -1 on failure
 *
 * Registers DBus signal under given name and interface for the object.
 * Signal registration is NOT required in order to send signals, but not
 * registered signals will not be respected in introspection data
 * therefore it is highly recommended to register every signal before
 * using it.
 */
int wpa_dbus_signal_register(struct wpa_dbus_object_desc *obj_dsc,
			     const char *dbus_interface,
			     const char *dbus_signal,
			     const struct wpa_dbus_argument args[])
{

	struct wpa_dbus_signal_desc *signal_dsc = obj_dsc->signals;
	struct wpa_dbus_signal_desc *prev_desc;
	int args_num = 0;
	int i, error = 0;

	prev_desc = NULL;
	while (signal_dsc) {
		prev_desc = signal_dsc;
		signal_dsc = signal_dsc->next;
	}

	/* count args */
	if (args) {
		while (args[args_num].name && args[args_num].type)
			args_num++;
	}

	signal_dsc = os_zalloc(sizeof(struct wpa_dbus_signal_desc) +
			       args_num * sizeof(struct wpa_dbus_argument));
	if (!signal_dsc)
		goto err;

	if (prev_desc == NULL)
		obj_dsc->signals = signal_dsc;
	else
		prev_desc->next = signal_dsc;

	/* copy interface name */
	signal_dsc->dbus_interface = os_strdup(dbus_interface);
	if (!signal_dsc->dbus_interface)
		goto err;

	/* copy signal name */
	signal_dsc->dbus_signal = os_strdup(dbus_signal);
	if (!signal_dsc->dbus_signal)
		goto err;

	/* copy arguments */
	signal_dsc->args_num = args_num;
	for (i = 0; i < args_num; i++) {
		signal_dsc->args[i].name = os_strdup(args[i].name);
		if (!signal_dsc->args[i].name) {
			error = 1;
			continue;
		}

		signal_dsc->args[i].type = os_strdup(args[i].type);
		if (!signal_dsc->args[i].type) {
			error = 1;
			continue;
		}
	}
	if (error)
		goto err;

	signal_dsc->next = NULL;

	return 0;

err:
	wpa_printf(MSG_WARNING, "Failed to register dbus signal %s in "
		   "interface %s", dbus_signal, dbus_interface);
	if (signal_dsc) {
		os_free(signal_dsc->dbus_interface);
		os_free(signal_dsc->dbus_signal);
		for (i = 0; i < signal_dsc->args_num; i++) {
			os_free(signal_dsc->args[i].name);
			os_free(signal_dsc->args[i].type);
		}

		if (prev_desc == NULL)
			obj_dsc->signals = NULL;
		else
			prev_desc->next = NULL;

		os_free(signal_dsc);
	}

	return -1;
}


/**
 * wpa_dbus_property_register - Registers DBus property for given object
 * @obj_dsc: Object description for which a property will be registered
 * @dbus_interface: DBus interface under which method will be registered
 * @dbus_property: a name the property will be registered with
 * @type: a property type signature in form of DBus type description
 * @getter: a function called in order to get property value
 * @setter: a function called in order to set property value
 * @access: property access permissions specifier (R, W or RW)
 * Returns: Zero on success and -1 on failure
 *
 * Registers DBus property under given name and interface for the object.
 * Properties are set with giver setter function and get with getter.Getter
 * or setter are required to return DBusMessage which is response to Set/Get
 * method calls. Every property must be registered by this function before
 * being used.
 */
int wpa_dbus_property_register(struct wpa_dbus_object_desc *obj_dsc,
			       const char *dbus_interface,
			       const char *dbus_property,
			       const char *type,
			       WPADBusPropertyAccessor getter,
			       WPADBusPropertyAccessor setter,
			       enum dbus_prop_access _access)
{
	struct wpa_dbus_property_desc *property_dsc = obj_dsc->properties;
	struct wpa_dbus_property_desc *prev_desc;

	prev_desc = NULL;
	while (property_dsc) {
		prev_desc = property_dsc;
		property_dsc = property_dsc->next;
	}

	property_dsc = os_zalloc(sizeof(struct wpa_dbus_property_desc));
	if (!property_dsc)
		goto err;

	if (prev_desc == NULL)
		obj_dsc->properties = property_dsc;
	else
		prev_desc->next = property_dsc;

	/* copy interface name */
	property_dsc->dbus_interface = os_strdup(dbus_interface);
	if (!property_dsc->dbus_interface)
		goto err;

	/* copy property name */
	property_dsc->dbus_property = os_strdup(dbus_property);
	if (!property_dsc->dbus_property)
		goto err;

	/* copy property type */
	property_dsc->type = os_strdup(type);
	if (!property_dsc->type)
		goto err;

	property_dsc->getter = getter;
	property_dsc->setter = setter;
	property_dsc->access = _access;
	property_dsc->next = NULL;

	return 0;

err:
	wpa_printf(MSG_WARNING, "Failed to register dbus property %s in "
		   "interface %s", dbus_property, dbus_interface);
	if (property_dsc) {
		os_free(property_dsc->dbus_interface);
		os_free(property_dsc->dbus_property);
		os_free(property_dsc->type);

		if (prev_desc == NULL)
			obj_dsc->properties = NULL;
		else
			prev_desc->next = NULL;

		os_free(property_dsc);
	}

	return -1;
}


/**
 * wpas_dbus_signal_network_added - Send a property changed signal
 * @iface: dbus priv struct
 * @property_getter: propperty getter used to fetch new property value
 * @getter_arg: argument passed to property getter
 * @path: path to object which property has changed
 * @interface_name: signal and property interface
 * @property_name: name of property which has changed
 *
 * Notify listeners about changing value of some property. Signal
 * contains property name and its value fetched using given property
 * getter.
 */
void wpa_dbus_signal_property_changed(struct wpas_dbus_priv *iface,
				      WPADBusPropertyAccessor property_getter,
				      void *getter_arg,
				      const char *path,
				      const char *interface_name,
				      const char *property_name)
{

	DBusConnection *connection;
	DBusMessage *msg, *getter_reply;
	DBusMessageIter prop_iter, signal_iter, dict_iter, entry_iter;

	if (!iface)
		return;
	connection = iface->con;

	if (!property_getter || !path || !interface_name || !property_name) {
		wpa_printf(MSG_ERROR, "dbus: %s: A parameter not specified",
			   __func__);
		return;
	}

	getter_reply = property_getter(NULL, getter_arg);
	if (!getter_reply ||
	    dbus_message_get_type(getter_reply) == DBUS_MESSAGE_TYPE_ERROR) {
		wpa_printf(MSG_ERROR, "dbus: %s: Cannot get new value of "
			   "property %s", __func__, property_name);
		return;
	}

	msg = dbus_message_new_signal(path, interface_name,
				      "PropertiesChanged");
	if (msg == NULL) {
		dbus_message_unref(getter_reply);
		return;
	}

	dbus_message_iter_init(getter_reply, &prop_iter);
	dbus_message_iter_init_append(msg, &signal_iter);

	if (!dbus_message_iter_open_container(&signal_iter, DBUS_TYPE_ARRAY,
					      "{sv}", &dict_iter) ||
	    !dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_DICT_ENTRY,
					      NULL, &entry_iter) ||
	    !dbus_message_iter_append_basic(&entry_iter, DBUS_TYPE_STRING,
					    &property_name))
		goto err;

	recursive_iter_copy(&prop_iter, &entry_iter);

	if (!dbus_message_iter_close_container(&dict_iter, &entry_iter) ||
	    !dbus_message_iter_close_container(&signal_iter, &dict_iter))
		goto err;

	dbus_connection_send(connection, msg, NULL);

out:
	dbus_message_unref(getter_reply);
	dbus_message_unref(msg);
	return;

err:
	wpa_printf(MSG_DEBUG, "dbus: %s: Failed to construct signal",
		   __func__);
	goto out;
}


/**
 * wpa_dbus_get_object_properties - Put object's properties into dictionary
 * @iface: dbus priv struct
 * @path: path to DBus object which properties will be obtained
 * @interface: interface name which properties will be obtained
 * @dict_iter: correct, open DBus dictionary iterator.
 *
 * Iterates over all properties registered with object and execute getters
 * of those, which are readable and which interface matches interface
 * specified as argument. Obtained properties values are stored in
 * dict_iter dictionary.
 */
void wpa_dbus_get_object_properties(struct wpas_dbus_priv *iface,
				    const char *path, const char *interface,
				    DBusMessageIter *dict_iter)
{
	struct wpa_dbus_object_desc *obj_desc = NULL;

	dbus_connection_get_object_path_data(iface->con, path,
					     (void **) &obj_desc);
	if (!obj_desc) {
		wpa_printf(MSG_ERROR, "dbus: wpa_dbus_get_object_properties: "
			   "could not obtain object's private data: %s", path);
		return;
	}

	fill_dict_with_properties(dict_iter, obj_desc->properties,
				  interface, obj_desc->user_data);
}
