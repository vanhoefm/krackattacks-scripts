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
#include "eloop.h"
#include "dbus_common.h"
#include "dbus_common_i.h"
#include "dbus_new_helpers.h"

/**
 * struct wpa_dbus_method_desc - DBus method description
 */
struct wpa_dbus_method_desc {
	/* pointer to next description in list */
	struct wpa_dbus_method_desc *next;

	/* method interface */
	char *dbus_interface;
	/* method name */
	char *dbus_method;

	/* method handling function */
	WPADBusMethodHandler method_handler;
	/* handler function argument */
	void *handler_argument;
	/* function used to free handler argument */
	WPADBusArgumentFreeFunction argument_free_func;

	/* number of method arguments */
	int args_num;
	/* array of arguments */
	struct wpa_dbus_argument args[];
};


/**
 * struct wpa_dbus_signal_desc - DBus signal description
 */
struct wpa_dbus_signal_desc {
	/* pointer to next description in list */
	struct wpa_dbus_signal_desc *next;

	/* signal interface */
	char *dbus_interface;
	/* signal name */
	char *dbus_signal;

	/* number of signal arguments */
	int args_num;
	/* array of arguments */
	struct wpa_dbus_argument args[0];
};


/**
 * struct wpa_dbus_property_desc - DBus property description
 */
struct wpa_dbus_property_desc {
	/* pointer to next description in list */
	struct wpa_dbus_property_desc *next;

	/* property interface */
	char *dbus_interface;
	/* property name */
	char *dbus_property;
	/* property type signature in DBus type notation */
	char *type;

	/* property access permissions */
	enum dbus_prop_access access;

	/* property getter function */
	WPADBusPropertyAccessor getter;
	/* property setter function */
	WPADBusPropertyAccessor setter;
	/* argument for getter and setter functions */
	void *user_data;
	/* function used to free accessors argument */
	WPADBusArgumentFreeFunction user_data_free_func;
};


#ifdef CONFIG_CTRL_IFACE_DBUS_INTRO
#include <libxml/tree.h>

struct interfaces {
	struct interfaces *next;
	char *dbus_interface;
	xmlNodePtr interface_node;
};
#endif /* CONFIG_CTRL_IFACE_DBUS_INTRO */


#ifdef CONFIG_CTRL_IFACE_DBUS_INTRO

/**
 * extract_interfaces - Extract interfaces from methods, signals and props
 * @obj_dsc: Description of object from which interfaces will be extracted
 * @root_node: root node of XML introspection document
 * Returns: List of interfaces found in object description
 *
 * Iterates over all methods, signals and properties registered with
 * object and collects all declared DBus interfaces and create interface's
 * node in XML root node for each. Returned list elements contains interface
 * name and XML node of corresponding interface.
 */
static struct interfaces * extract_interfaces(
	struct wpa_dbus_object_desc *obj_dsc, xmlNodePtr root_node)
{
	struct wpa_dbus_method_desc *method_dsc = obj_dsc->methods;
	struct wpa_dbus_signal_desc *signal_dsc = obj_dsc->signals;
	struct wpa_dbus_property_desc *property_dsc = obj_dsc->properties;
	struct interfaces *head = NULL;
	struct interfaces *iface, *last;
	int len;

	/* extract interfaces from methods */
	while (method_dsc) {
		iface = head;
		last = NULL;

		/* go to next method if its interface is already extracted */
		while (iface) {
			if (!os_strcmp(iface->dbus_interface,
				       method_dsc->dbus_interface))
				break;
			last = iface;
			iface = iface->next;
		}
		if (iface) {
			method_dsc = method_dsc->next;
			continue;
		}

		iface = os_zalloc(sizeof(struct interfaces));
		if (!iface) {
			wpa_printf(MSG_ERROR, "Not enough memory to create "
				"interface introspection data");
			method_dsc = method_dsc->next;
			continue;
		}

		if (last)
			last->next = iface;
		else
			head = iface;

		len = os_strlen(method_dsc->dbus_interface) + 1;
		iface->dbus_interface = os_malloc(len);
		if (!iface->dbus_interface) {
			wpa_printf(MSG_ERROR, "Not enough memory to create "
				   "interface introspection data (interface "
				   "name)");
			method_dsc = method_dsc->next;
			continue;
		}
		os_strncpy(iface->dbus_interface, method_dsc->dbus_interface,
			   len);

		iface->interface_node = xmlNewChild(root_node, NULL,
						    BAD_CAST "interface",
						    NULL);
		xmlNewProp(iface->interface_node, BAD_CAST "name",
			   BAD_CAST method_dsc->dbus_interface);

		method_dsc = method_dsc->next;
	}

	/* extract interfaces from signals */
	while (signal_dsc) {
		iface = head;
		last = NULL;

		/* go to next signal if its interface is already extracted */
		while (iface) {
			if (!os_strcmp(iface->dbus_interface,
				       signal_dsc->dbus_interface))
				break;
			last = iface;
			iface = iface->next;
		}
		if (iface) {
			signal_dsc = signal_dsc->next;
			continue;
		}

		iface = os_zalloc(sizeof(struct interfaces));
		if (!iface) {
			wpa_printf(MSG_ERROR, "Not enough memory to create "
				   "interface introspection data");
			signal_dsc = signal_dsc->next;
			continue;
		}

		if (last)
			last->next = iface;
		else
			head = iface;

		len = os_strlen(signal_dsc->dbus_interface) + 1;
		iface->dbus_interface = os_malloc(len);
		if (!iface->dbus_interface) {
			wpa_printf(MSG_ERROR, "Not enough memory to create "
				   "interface introspection data (interface "
				   "name)");
			signal_dsc = signal_dsc->next;
			continue;
		}
		os_strncpy(iface->dbus_interface, signal_dsc->dbus_interface,
			   len);

		iface->interface_node = xmlNewChild(root_node, NULL,
						    BAD_CAST "interface",
						    NULL);
		xmlNewProp(iface->interface_node, BAD_CAST "name",
			   BAD_CAST signal_dsc->dbus_interface);

		signal_dsc = signal_dsc->next;
	}

	/* extract interfaces from properties */
	while (property_dsc) {
		iface = head;
		last = NULL;

		/* go to next property if its interface is already extracted */
		while (iface) {
			if (!os_strcmp(iface->dbus_interface,
				       property_dsc->dbus_interface))
				break;
			last = iface;
			iface = iface->next;
		}
		if (iface) {
			property_dsc = property_dsc->next;
			continue;
		}

		iface = os_zalloc(sizeof(struct interfaces));
		if (!iface) {
			wpa_printf(MSG_ERROR, "Not enough memory to create "
				   "interface introspection data");
			property_dsc = property_dsc->next;
			continue;
		}

		if (last)
			last->next = iface;
		else
			head = iface;

		len = os_strlen(property_dsc->dbus_interface) + 1;
		iface->dbus_interface = os_malloc(len);
		if (!iface->dbus_interface) {
			wpa_printf(MSG_ERROR, "Not enough memory to create "
				   "interface introspection data (interface "
				   "name)");
			property_dsc = property_dsc->next;
			continue;
		}
		os_strncpy(iface->dbus_interface, property_dsc->dbus_interface,
			   len);

		iface->interface_node = xmlNewChild(root_node, NULL,
						    BAD_CAST "interface",
						    NULL);
		xmlNewProp(iface->interface_node, BAD_CAST "name",
			   BAD_CAST property_dsc->dbus_interface);

		property_dsc = property_dsc->next;
	}

	return head;
}


/**
 * introspect - Responds for Introspect calls on object
 * @message: Message with Introspect call
 * @obj_dsc: Object description on which Introspect was called
 * Returns: Message with introspection result XML string as only argument
 *
 * Iterates over all methods, signals and properties registered with
 * object and generates introspection data for the object as XML string.
 */
static DBusMessage * introspect(DBusMessage *message,
				struct wpa_dbus_object_desc *obj_dsc)
{

	DBusMessage *reply;
	struct interfaces *ifaces, *tmp;
	struct wpa_dbus_signal_desc *signal_dsc;
	struct wpa_dbus_method_desc *method_dsc;
	struct wpa_dbus_property_desc *property_dsc;
	xmlChar *intro_str;
	char **children;
	int i, s;

	xmlDocPtr doc = NULL;
	xmlNodePtr root_node = NULL, node = NULL, iface_node = NULL;
	xmlNodePtr method_node = NULL, signal_node = NULL;
	xmlNodePtr property_node = NULL, arg_node = NULL;

	/* root node and dtd */
	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "node");
	xmlDocSetRootElement(doc, root_node);
	xmlCreateIntSubset(doc, BAD_CAST "node",
			   BAD_CAST DBUS_INTROSPECT_1_0_XML_PUBLIC_IDENTIFIER,
			   BAD_CAST DBUS_INTROSPECT_1_0_XML_SYSTEM_IDENTIFIER);

	/* Add Introspectable interface */
	iface_node = xmlNewChild(root_node, NULL, BAD_CAST "interface", NULL);
	xmlNewProp(iface_node, BAD_CAST "name",
		   BAD_CAST WPA_DBUS_INTROSPECTION_INTERFACE);

	/* Add Introspect method */
	method_node = xmlNewChild(iface_node, NULL, BAD_CAST "method", NULL);
	xmlNewProp(method_node, BAD_CAST "name",
		   BAD_CAST WPA_DBUS_INTROSPECTION_METHOD);
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "data");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "s");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "out");


	/* Add Properties interface */
	iface_node = xmlNewChild(root_node, NULL,
				 BAD_CAST "interface", NULL);
	xmlNewProp(iface_node, BAD_CAST "name",
		   BAD_CAST WPA_DBUS_PROPERTIES_INTERFACE);

	/* Add Get method */
	method_node = xmlNewChild(iface_node, NULL, BAD_CAST "method", NULL);
	xmlNewProp(method_node, BAD_CAST "name",
		   BAD_CAST WPA_DBUS_PROPERTIES_GET);
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "interface");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "s");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "in");
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "propname");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "s");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "in");
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "value");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "v");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "out");
	method_node = xmlNewChild(iface_node, NULL, BAD_CAST "method", NULL);

	/* Add GetAll method */
	xmlNewProp(method_node, BAD_CAST "name",
		   BAD_CAST WPA_DBUS_PROPERTIES_GETALL);
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "interface");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "s");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "in");
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "props");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "a{sv}");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "out");
	method_node = xmlNewChild(iface_node, NULL, BAD_CAST "method", NULL);

	/* Add Set method */
	xmlNewProp(method_node, BAD_CAST "name",
		   BAD_CAST WPA_DBUS_PROPERTIES_SET);
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "interface");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "s");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "in");
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "propname");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "s");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "in");
	arg_node = xmlNewChild(method_node, NULL, BAD_CAST "arg", NULL);
	xmlNewProp(arg_node, BAD_CAST "name", BAD_CAST "value");
	xmlNewProp(arg_node, BAD_CAST "type", BAD_CAST "v");
	xmlNewProp(arg_node, BAD_CAST "direction", BAD_CAST "in");

	/* get all interfaces registered with object */
	ifaces = extract_interfaces(obj_dsc, root_node);

	/* create methods' nodes */
	method_dsc = obj_dsc->methods;
	while (method_dsc) {

		struct interfaces *iface = ifaces;
		while (iface) {
			if (!os_strcmp(iface->dbus_interface,
				       method_dsc->dbus_interface))
				break;
			iface = iface->next;
		}
		if (!iface)
			continue;

		iface_node = iface->interface_node;
		method_node = xmlNewChild(iface_node, NULL, BAD_CAST "method",
					  NULL);
		xmlNewProp(method_node, BAD_CAST "name",
			   BAD_CAST method_dsc->dbus_method);

		/* create args' nodes */
		for (i = 0; i < method_dsc->args_num; i++) {
			struct wpa_dbus_argument arg = method_dsc->args[i];
			arg_node = xmlNewChild(method_node, NULL,
					       BAD_CAST "arg", NULL);
			if (arg.name && strlen(arg.name)) {
				xmlNewProp(arg_node, BAD_CAST "name",
					   BAD_CAST arg.name);
			}
			xmlNewProp(arg_node, BAD_CAST "type",
				   BAD_CAST arg.type);
			xmlNewProp(arg_node, BAD_CAST "direction",
				   BAD_CAST (arg.dir == ARG_IN ?
					     "in" : "out"));
		}
		method_dsc = method_dsc->next;
	}

	/* create signals' nodes */
	signal_dsc = obj_dsc->signals;
	while (signal_dsc) {

		struct interfaces *iface = ifaces;
		while (iface) {
			if (!os_strcmp(iface->dbus_interface,
				       signal_dsc->dbus_interface))
				break;
			iface = iface->next;
		}
		if (!iface)
			continue;

		iface_node = iface->interface_node;
		signal_node = xmlNewChild(iface_node, NULL, BAD_CAST "signal",
					  NULL);
		xmlNewProp(signal_node, BAD_CAST "name",
			   BAD_CAST signal_dsc->dbus_signal);

		/* create args' nodes */
		for (i = 0; i < signal_dsc->args_num; i++) {
			struct wpa_dbus_argument arg = signal_dsc->args[i];
			arg_node = xmlNewChild(signal_node, NULL,
					       BAD_CAST "arg", NULL);
			if (arg.name && strlen(arg.name)) {
				xmlNewProp(arg_node, BAD_CAST "name",
					   BAD_CAST arg.name);
			}
			xmlNewProp(arg_node, BAD_CAST "type",
				   BAD_CAST arg.type);
		}
		signal_dsc = signal_dsc->next;
	}

	/* create properties' nodes */
	property_dsc = obj_dsc->properties;
	while (property_dsc) {

		struct interfaces *iface = ifaces;
		while (iface) {
			if (!os_strcmp(iface->dbus_interface,
				       property_dsc->dbus_interface))
				break;
			iface = iface->next;
		}
		if (!iface)
			continue;

		iface_node = iface->interface_node;
		property_node = xmlNewChild(iface_node, NULL,
					    BAD_CAST "property", NULL);
		xmlNewProp(property_node, BAD_CAST "name",
			   BAD_CAST property_dsc->dbus_property);
		xmlNewProp(property_node, BAD_CAST "type",
			   BAD_CAST property_dsc->type);
		xmlNewProp(property_node, BAD_CAST "access", BAD_CAST
			   (property_dsc->access == R ? "read" :
			    (property_dsc->access == W ?
			     "write" : "readwrite")));

		property_dsc = property_dsc->next;
	}

	/* add child nodes to introspection tree; */
	dbus_connection_list_registered(obj_dsc->connection,
					dbus_message_get_path(message),
					&children);
	for (i = 0; children[i]; i++) {
		node = xmlNewChild(root_node, NULL, BAD_CAST "node", NULL);
		xmlNewProp(node, BAD_CAST "name", BAD_CAST children[i]);
	}
	dbus_free_string_array(children);


	xmlDocDumpFormatMemory(doc, &intro_str, &s, 1);

	xmlFreeDoc(doc);

	while (ifaces) {
		tmp = ifaces;
		ifaces = ifaces->next;
		os_free(tmp->dbus_interface);
		os_free(tmp);
	}

	reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		xmlFree(intro_str);
		return NULL;
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &intro_str,
				 DBUS_TYPE_INVALID);

	xmlFree(intro_str);

	return reply;
}

#else /* CONFIG_CTRL_IFACE_DBUS_INTRO */

/**
 * introspect - Responds for Introspect calls on object
 * @message: Message with Introspect call
 * @obj_dsc: Object description on which Introspect was called
 * Returns: Message with introspection result XML string as only argument
 *
 * Returns error informing that introspection support was not compiled.
 */
static DBusMessage * introspect(DBusMessage *message,
				struct wpa_dbus_object_desc *obj_dsc)
{
	return dbus_message_new_error(message, DBUS_ERROR_UNKNOWN_METHOD,
				      "wpa_supplicant was compiled without "
				      "introspection support.");
}

#endif /* CONFIG_CTRL_IFACE_DBUS_INTRO */


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
	while ((type = dbus_message_iter_get_arg_type (from)) !=
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
				dbus_message_iter_get_basic (from, &v);
				dbus_message_iter_append_basic (to, type, &v);
			} else {
				char *v;
				dbus_message_iter_get_basic (from, &v);
				dbus_message_iter_append_basic (to, type, &v);
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
	struct wpa_dbus_property_desc *property_dsc)
{
	/* Create and initialize the return message */
	DBusMessage *reply = dbus_message_new_method_return(message);
	DBusMessage *getterReply = NULL;
	DBusMessageIter iter, dict_iter, entry_iter, ret_iter;
	int counter = 0;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_VARIANT_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					 &dict_iter);

	while (property_dsc) {
		if (!os_strncmp(property_dsc->dbus_interface, interface,
				WPAS_DBUS_INTERFACE_MAX) &&
		    property_dsc->access != W && property_dsc->getter) {

			getterReply = property_dsc->getter(
				message, property_dsc->user_data);
			dbus_message_iter_init(getterReply, &ret_iter);

			dbus_message_iter_open_container(&dict_iter,
							 DBUS_TYPE_DICT_ENTRY,
							 NULL, &entry_iter);
			dbus_message_iter_append_basic(
				&entry_iter, DBUS_TYPE_STRING,
				&(property_dsc->dbus_property));

			recursive_iter_copy(&ret_iter, &entry_iter);

			dbus_message_iter_close_container(&dict_iter,
							  &entry_iter);
			dbus_message_unref(getterReply);
			counter++;
		}
		property_dsc = property_dsc->next;
	}
	dbus_message_iter_close_container(&iter, &dict_iter);

	if (counter == 0) {
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

	return get_all_properties(message, interface,
				  obj_dsc->properties);
}


static DBusMessage * properties_get(DBusMessage *message,
				    struct wpa_dbus_property_desc *dsc)
{
	if (os_strcmp(dbus_message_get_signature(message), "ss"))
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      NULL);

	if (dsc->access != W && dsc->getter)
		return dsc->getter(message, dsc->user_data);

	return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				      "Property is write-only");
}


static DBusMessage * properties_set(DBusMessage *message,
				    struct wpa_dbus_property_desc *dsc)
{
	if (os_strcmp(dbus_message_get_signature(message), "ssv"))
		return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					      NULL);

	if (dsc->access != R && dsc->setter)
		return dsc->setter(message, dsc->user_data);

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
		return properties_get(message, property_dsc);

	return properties_set(message, property_dsc);
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
					  method_dsc->handler_argument);
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
			WPAS_DBUS_INTERFACE_MAX))
		reply = introspect(message, obj_dsc);
	else if (!os_strncmp(WPA_DBUS_PROPERTIES_INTERFACE, msg_interface,
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

		if (tmp_met_dsc->argument_free_func)
			tmp_met_dsc->argument_free_func(
				tmp_met_dsc->handler_argument);

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

		if (tmp_prop_dsc->user_data_free_func)
			tmp_prop_dsc->user_data_free_func(
				tmp_prop_dsc->user_data);

		os_free(tmp_prop_dsc);
	}

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
		perror("dbus_connection_register_object_path[dbus]");
		wpa_printf(MSG_ERROR, "Could not set up DBus message "
			   "handler.");
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
		perror("dbus_bus_request_name[dbus]");
		wpa_printf(MSG_ERROR, "Could not request DBus service name: "
			   "already registered.");
		break;
	default:
		perror("dbus_bus_request_name[dbus]");
		wpa_printf(MSG_ERROR, "Could not request DBus service name: "
			   "%s %s.", error.name, error.message);
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
		perror("wpa_dbus_register_iface [dbus]");
		wpa_printf(MSG_ERROR, "Could not set up DBus message "
			   "handler for interface %s\n"
			   "and object %s.", ifname, path);
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
 * @handler_argument: an additional argument passed to handler function
 * @argument_free_func: function used to free handler argument
 * @args: method arguments list
 * Returns: Zero on success and -1 on failure
 *
 * Registers DBus method under given name and interface for the object.
 * Method calls will be handled with given handling function and optional
 * argument passed to this function. Handler function is required to return
 * a DBusMessage pointer which will be response to method call. Any method
 * call before being handled must have registered appropriate handler by
 * using this function.
 */
int wpa_dbus_method_register(struct wpa_dbus_object_desc *obj_dsc,
			     const char *dbus_interface,
			     const char *dbus_method,
			     WPADBusMethodHandler method_handler,
			     void *handler_argument,
			     WPADBusArgumentFreeFunction argument_free_func,
			     const struct wpa_dbus_argument args[])
{
	struct wpa_dbus_method_desc *method_dsc = obj_dsc->methods;
	struct wpa_dbus_method_desc *prev_desc;
	int args_num = 0;
	int interface_len, method_len, i, len, error;

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
	interface_len = os_strlen(dbus_interface) + 1;
	method_dsc->dbus_interface = os_malloc(interface_len);
	if (!method_dsc->dbus_interface)
		goto err;
	os_strncpy(method_dsc->dbus_interface, dbus_interface, interface_len);

	/* copy method name */
	method_len = os_strlen(dbus_method) + 1;
	method_dsc->dbus_method = os_malloc(method_len);
	if (!method_dsc->dbus_method)
		goto err;
	os_strncpy(method_dsc->dbus_method, dbus_method, method_len);

	/* copy arguments */
	error = 0;
	method_dsc->args_num = args_num;
	for (i = 0; i < args_num; i++) {
		len = os_strlen(args[i].name) + 1;
		method_dsc->args[i].name = os_malloc(len);
		if (!method_dsc->args[i].name) {
			error = 1;
			continue;
		}
		os_strncpy(method_dsc->args[i].name, args[i].name, len);

		len = os_strlen(args[i].type) + 1;
		method_dsc->args[i].type = os_malloc(len);
		if (!method_dsc->args[i].type) {
			error = 1;
			continue;
		}
		os_strncpy(method_dsc->args[i].type, args[i].type, len);

		method_dsc->args[i].dir = args[i].dir;
	}
	if (error)
		goto err;

	method_dsc->method_handler = method_handler;
	method_dsc->handler_argument = handler_argument;
	method_dsc->argument_free_func = argument_free_func;
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
	int interface_len, signal_len, i, len, error = 0;

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
	interface_len = strlen(dbus_interface) + 1;
	signal_dsc->dbus_interface = os_malloc(interface_len);
	if (!signal_dsc->dbus_interface)
		goto err;
	os_strncpy(signal_dsc->dbus_interface, dbus_interface, interface_len);

	/* copy signal name */
	signal_len = strlen(dbus_signal) + 1;
	signal_dsc->dbus_signal = os_malloc(signal_len);
	if (!signal_dsc->dbus_signal)
		goto err;
	os_strncpy(signal_dsc->dbus_signal, dbus_signal, signal_len);

	/* copy arguments */
	signal_dsc->args_num = args_num;
	for (i = 0; i < args_num; i++) {
		len = os_strlen(args[i].name) + 1;
		signal_dsc->args[i].name = os_malloc(len);
		if (!signal_dsc->args[i].name) {
			error = 1;
			continue;
		}
		os_strncpy(signal_dsc->args[i].name, args[i].name, len);

		len = strlen(args[i].type) + 1;
		signal_dsc->args[i].type = os_malloc(len);
		if (!signal_dsc->args[i].type) {
			error = 1;
			continue;
		}
		os_strncpy(signal_dsc->args[i].type, args[i].type, len);
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
 * @user_data: additional argument passed to setter or getter
 * @user_data_free_func: function used to free additional argument
 * @access: property access permissions specifier (R, W or RW)
 * Returns: Zero on success and -1 on failure
 *
 * Registers DBus property under given name and interface for the object.
 * Property are set with giver setter function and get with getter.
 * Additional argument is passed to getter or setter. Getter or setter
 * are required to return DBusMessage which is response to Set/Get method
 * calls. Every property must be registered by this function before being
 * used.
 */
int wpa_dbus_property_register(struct wpa_dbus_object_desc *obj_dsc,
			       const char *dbus_interface,
			       const char *dbus_property,
			       const char *type,
			       WPADBusPropertyAccessor getter,
			       WPADBusPropertyAccessor setter,
			       void *user_data,
			       WPADBusArgumentFreeFunction user_data_free_func,
			       enum dbus_prop_access _access)
{
	struct wpa_dbus_property_desc *property_dsc = obj_dsc->properties;
	struct wpa_dbus_property_desc *prev_desc;
	int interface_len, property_len, type_len;

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
	interface_len = os_strlen(dbus_interface) + 1;
	property_dsc->dbus_interface = os_malloc(interface_len);
	if (!property_dsc->dbus_interface)
		goto err;
	os_strncpy(property_dsc->dbus_interface, dbus_interface,
		   interface_len);

	/* copy property name */
	property_len = os_strlen(dbus_property) + 1;
	property_dsc->dbus_property = os_malloc(property_len);
	if (!property_dsc->dbus_property)
		goto err;
	os_strncpy(property_dsc->dbus_property, dbus_property, property_len);

	/* copy property type */
	type_len = os_strlen(type) + 1;
	property_dsc->type = os_malloc(type_len);
	if (!property_dsc->type)
		goto err;
	os_strncpy(property_dsc->type, type, type_len);

	property_dsc->getter = getter;
	property_dsc->setter = setter;
	property_dsc->user_data = user_data;
	property_dsc->user_data_free_func = user_data_free_func;
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
	DBusMessage *_signal, *getter_reply;
	DBusMessageIter prop_iter, signal_iter, dict_iter, entry_iter;

	if (!iface)
		return;
	connection = iface->con;

	if (!property_getter) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: property getter not specified");
		return;
	}

	if (!path || !interface_name || !property_name) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: path interface of property not specified");
		return;
	}

	getter_reply = property_getter(NULL, getter_arg);
	if (!getter_reply ||
	    dbus_message_get_type(getter_reply) == DBUS_MESSAGE_TYPE_ERROR) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: cannot get new value of property %s",
			   property_name);
		return;
	}

	_signal = dbus_message_new_signal(path, interface_name,
					  "PropertiesChanged");
	if (!_signal) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: cannot allocate signal");
		dbus_message_unref(getter_reply);
		return;
	}

	dbus_message_iter_init(getter_reply, &prop_iter);
	dbus_message_iter_init_append(_signal, &signal_iter);

	if (!dbus_message_iter_open_container(&signal_iter, DBUS_TYPE_ARRAY,
					      "{sv}", &dict_iter)) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: out of memory. cannot open dictionary");
		goto err;
	}

	if (!dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_DICT_ENTRY,
					      NULL, &entry_iter)) {
		wpa_printf(MSG_ERROR, "iwpa_dbus_signal_property_changed"
			   "[dbus]: out of memory. cannot open dictionary "
			   "element");
		goto err;
	}

	if (!dbus_message_iter_append_basic(&entry_iter, DBUS_TYPE_STRING,
					    &property_name)) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: out of memory. cannot open add property "
			   "name");
		goto err;
	}

	recursive_iter_copy(&prop_iter, &entry_iter);

	if (!dbus_message_iter_close_container(&dict_iter, &entry_iter)) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: out of memory. cannot close dictionary "
			   "element");
		goto err;
	}

	if (!dbus_message_iter_close_container(&signal_iter, &dict_iter)) {
		wpa_printf(MSG_ERROR, "wpa_dbus_signal_property_changed"
			   "[dbus]: out of memory. cannot close dictionary");
		goto err;
	}

	dbus_connection_send(connection, _signal, NULL);

err:
	dbus_message_unref(getter_reply);
	dbus_message_unref(_signal);

}
