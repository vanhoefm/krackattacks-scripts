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

#include "utils/includes.h"
#include <libxml/tree.h>

#include "utils/common.h"
#include "dbus_common_i.h"
#include "dbus_new_helpers.h"


struct interfaces {
	struct interfaces *next;
	char *dbus_interface;
	xmlNodePtr interface_node;
};

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
 * wpa_dbus_introspect - Responds for Introspect calls on object
 * @message: Message with Introspect call
 * @obj_dsc: Object description on which Introspect was called
 * Returns: Message with introspection result XML string as only argument
 *
 * Iterates over all methods, signals and properties registered with
 * object and generates introspection data for the object as XML string.
 */
DBusMessage * wpa_dbus_introspect(DBusMessage *message,
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

