/*
 * UFD routines for Wi-Fi Protected Setup
 * Copyright (c) 2009, Masashi Honma <honma@ictec.co.jp>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>

#include "wps/wps.h"

static int ufd_fd = -1;


static int dev_pwd_e_file_filter(const struct dirent *entry)
{
	unsigned int prefix;
	char ext[5];

	if (sscanf(entry->d_name, "%8x.%4s", &prefix, ext) != 2)
		return 0;
	if (prefix == 0)
		return 0;
	if (os_strcasecmp(ext, "WFA") != 0)
		return 0;

	return 1;
}


static int wps_get_dev_pwd_e_file_name(char *path, char *file_name)
{
	struct dirent **namelist;
	int i, file_num;

	file_num = scandir(path, &namelist, &dev_pwd_e_file_filter,
			   alphasort);
	if (file_num <= 0) {
		wpa_printf(MSG_ERROR, "WPS: OOB file not found");
		return -1;
	}
	os_strlcpy(file_name, namelist[0]->d_name, 13);
	for (i = 0; i < file_num; i++)
		os_free(namelist[i]);
	os_free(namelist);
	return 0;
}


static int get_file_name(struct wps_context *wps, int registrar,
			 char *file_name)
{
	switch (wps->oob_conf.oob_method) {
	case OOB_METHOD_CRED:
		os_snprintf(file_name, 13, "00000000.WSC");
		break;
	case OOB_METHOD_DEV_PWD_E:
		if (registrar) {
			char temp[128];

			os_snprintf(temp, sizeof(temp), "%s/SMRTNTKY/WFAWSC",
				wps->oob_dev->device_path);
			if (wps_get_dev_pwd_e_file_name(temp, file_name) < 0)
				return -1;
		} else {
			u8 *mac_addr = wps->dev.mac_addr;

			os_snprintf(file_name, 13, "%02X%02X%02X%02X.WFA",
				    mac_addr[2], mac_addr[3], mac_addr[4],
				    mac_addr[5]);
		}
		break;
	case OOB_METHOD_DEV_PWD_R:
		os_snprintf(file_name, 13, "00000000.WFA");
		break;
	default:
		wpa_printf(MSG_ERROR, "WPS: Invalid USBA OOB method");
		return -1;
	}
	return 0;
}


static int ufd_mkdir(const char *path)
{
	if (mkdir(path, S_IRWXU) < 0 && errno != EEXIST) {
		wpa_printf(MSG_ERROR, "WPS (UFD): Failed to create directory "
			   "'%s': %d (%s)", path, errno, strerror(errno));
		return -1;
	}
	return 0;
}


static int init_ufd(struct wps_context *wps, int registrar)
{
	int write_f;
	char temp[128];
	char *path = wps->oob_dev->device_path;
	char filename[13];

	write_f = wps->oob_conf.oob_method == OOB_METHOD_DEV_PWD_E ?
		!registrar : registrar;

	if (get_file_name(wps, registrar, filename) < 0) {
		wpa_printf(MSG_ERROR, "WPS (UFD): Failed to get file name");
		return -1;
	}

	if (write_f) {
		os_snprintf(temp, sizeof(temp), "%s/SMRTNTKY", path);
		if (ufd_mkdir(temp))
			return -1;
		os_snprintf(temp, sizeof(temp), "%s/SMRTNTKY/WFAWSC", path);
		if (ufd_mkdir(temp))
			return -1;
	}

	os_snprintf(temp, sizeof(temp), "%s/SMRTNTKY/WFAWSC/%s", path,
		    filename);
	if (write_f)
		ufd_fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC,
			      S_IRUSR | S_IWUSR);
	else
		ufd_fd = open(temp, O_RDONLY);
	if (ufd_fd < 0) {
		wpa_printf(MSG_ERROR, "WPS (UFD): Failed to open %s: %s",
			   temp, strerror(errno));
		return -1;
	}

	return 0;
}


static struct wpabuf * read_ufd(void)
{
	struct wpabuf *buf;
	struct stat s;
	size_t file_size;

	if (fstat(ufd_fd, &s) < 0) {
		wpa_printf(MSG_ERROR, "WPS (UFD): Failed to get file size");
		return NULL;
	}

	file_size = s.st_size;
	buf = wpabuf_alloc(file_size);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "WPS (UFD): Failed to alloc read "
			   "buffer");
		return NULL;
	}

	if (read(ufd_fd, wpabuf_mhead(buf), file_size) != (int) file_size) {
		wpabuf_free(buf);
		wpa_printf(MSG_ERROR, "WPS (UFD): Failed to read");
		return NULL;
	}
	wpabuf_put(buf, file_size);
	return buf;
}


static int write_ufd(struct wpabuf *buf)
{
	if (write(ufd_fd, wpabuf_mhead(buf), wpabuf_len(buf)) !=
	    (int) wpabuf_len(buf)) {
		wpa_printf(MSG_ERROR, "WPS (UFD): Failed to write");
		return -1;
	}
	return 0;
}


static int deinit_ufd(void)
{
	close(ufd_fd);
	ufd_fd = -1;
	return 0;
}


struct oob_device_data oob_ufd_device_data = {
	.device_path	= NULL,
	.init_func	= init_ufd,
	.read_func	= read_ufd,
	.write_func	= write_ufd,
	.deinit_func	= deinit_ufd,
};
