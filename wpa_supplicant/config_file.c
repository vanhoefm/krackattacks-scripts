/*
 * WPA Supplicant / Configuration backend: text file
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * This file implements a configuration backend for text files. All the
 * configuration information is stored in a text file that uses a format
 * described in the sample configuration file, wpa_supplicant.conf.
 */

#include "includes.h"

#include "common.h"
#include "config.h"
#include "base64.h"
#include "eap_peer/eap_methods.h"


/**
 * wpa_config_get_line - Read the next configuration file line
 * @s: Buffer for the line
 * @size: The buffer length
 * @stream: File stream to read from
 * @line: Pointer to a variable storing the file line number
 * @_pos: Buffer for the pointer to the beginning of data on the text line or
 * %NULL if not needed (returned value used instead)
 * Returns: Pointer to the beginning of data on the text line or %NULL if no
 * more text lines are available.
 *
 * This function reads the next non-empty line from the configuration file and
 * removes comments. The returned string is guaranteed to be null-terminated.
 */
static char * wpa_config_get_line(char *s, int size, FILE *stream, int *line,
				  char **_pos)
{
	char *pos, *end, *sstart;

	while (fgets(s, size, stream)) {
		(*line)++;
		s[size - 1] = '\0';
		pos = s;

		/* Skip white space from the beginning of line. */
		while (*pos == ' ' || *pos == '\t' || *pos == '\r')
			pos++;

		/* Skip comment lines and empty lines */
		if (*pos == '#' || *pos == '\n' || *pos == '\0')
			continue;

		/*
		 * Remove # comments unless they are within a double quoted
		 * string.
		 */
		sstart = os_strchr(pos, '"');
		if (sstart)
			sstart = os_strrchr(sstart + 1, '"');
		if (!sstart)
			sstart = pos;
		end = os_strchr(sstart, '#');
		if (end)
			*end-- = '\0';
		else
			end = pos + os_strlen(pos) - 1;

		/* Remove trailing white space. */
		while (end > pos &&
		       (*end == '\n' || *end == ' ' || *end == '\t' ||
			*end == '\r'))
			*end-- = '\0';

		if (*pos == '\0')
			continue;

		if (_pos)
			*_pos = pos;
		return pos;
	}

	if (_pos)
		*_pos = NULL;
	return NULL;
}


static int wpa_config_validate_network(struct wpa_ssid *ssid, int line)
{
	int errors = 0;

	if (ssid->passphrase) {
		if (ssid->psk_set) {
			wpa_printf(MSG_ERROR, "Line %d: both PSK and "
				   "passphrase configured.", line);
			errors++;
		}
		wpa_config_update_psk(ssid);
	}

	if ((ssid->key_mgmt & (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_FT_PSK)) &&
	    !ssid->psk_set) {
		wpa_printf(MSG_ERROR, "Line %d: WPA-PSK accepted for key "
			   "management, but no PSK configured.", line);
		errors++;
	}

	if ((ssid->group_cipher & WPA_CIPHER_CCMP) &&
	    !(ssid->pairwise_cipher & WPA_CIPHER_CCMP) &&
	    !(ssid->pairwise_cipher & WPA_CIPHER_NONE)) {
		/* Group cipher cannot be stronger than the pairwise cipher. */
		wpa_printf(MSG_DEBUG, "Line %d: removed CCMP from group cipher"
			   " list since it was not allowed for pairwise "
			   "cipher", line);
		ssid->group_cipher &= ~WPA_CIPHER_CCMP;
	}

	return errors;
}


static struct wpa_ssid * wpa_config_read_network(FILE *f, int *line, int id)
{
	struct wpa_ssid *ssid;
	int errors = 0, end = 0;
	char buf[256], *pos, *pos2;

	wpa_printf(MSG_MSGDUMP, "Line: %d - start of a new network block",
		   *line);
	ssid = os_zalloc(sizeof(*ssid));
	if (ssid == NULL)
		return NULL;
	ssid->id = id;

	wpa_config_set_network_defaults(ssid);

	while (wpa_config_get_line(buf, sizeof(buf), f, line, &pos)) {
		if (os_strcmp(pos, "}") == 0) {
			end = 1;
			break;
		}

		pos2 = os_strchr(pos, '=');
		if (pos2 == NULL) {
			wpa_printf(MSG_ERROR, "Line %d: Invalid SSID line "
				   "'%s'.", *line, pos);
			errors++;
			continue;
		}

		*pos2++ = '\0';
		if (*pos2 == '"') {
			if (os_strchr(pos2 + 1, '"') == NULL) {
				wpa_printf(MSG_ERROR, "Line %d: invalid "
					   "quotation '%s'.", *line, pos2);
				errors++;
				continue;
			}
		}

		if (wpa_config_set(ssid, pos, pos2, *line) < 0)
			errors++;
	}

	if (!end) {
		wpa_printf(MSG_ERROR, "Line %d: network block was not "
			   "terminated properly.", *line);
		errors++;
	}

	errors += wpa_config_validate_network(ssid, *line);

	if (errors) {
		wpa_config_free_ssid(ssid);
		ssid = NULL;
	}

	return ssid;
}


#ifndef CONFIG_NO_CONFIG_BLOBS
static struct wpa_config_blob * wpa_config_read_blob(FILE *f, int *line,
						     const char *name)
{
	struct wpa_config_blob *blob;
	char buf[256], *pos;
	unsigned char *encoded = NULL, *nencoded;
	int end = 0;
	size_t encoded_len = 0, len;

	wpa_printf(MSG_MSGDUMP, "Line: %d - start of a new named blob '%s'",
		   *line, name);

	while (wpa_config_get_line(buf, sizeof(buf), f, line, &pos)) {
		if (os_strcmp(pos, "}") == 0) {
			end = 1;
			break;
		}

		len = os_strlen(pos);
		nencoded = os_realloc(encoded, encoded_len + len);
		if (nencoded == NULL) {
			wpa_printf(MSG_ERROR, "Line %d: not enough memory for "
				   "blob", *line);
			os_free(encoded);
			return NULL;
		}
		encoded = nencoded;
		os_memcpy(encoded + encoded_len, pos, len);
		encoded_len += len;
	}

	if (!end) {
		wpa_printf(MSG_ERROR, "Line %d: blob was not terminated "
			   "properly", *line);
		os_free(encoded);
		return NULL;
	}

	blob = os_zalloc(sizeof(*blob));
	if (blob == NULL) {
		os_free(encoded);
		return NULL;
	}
	blob->name = os_strdup(name);
	blob->data = base64_decode(encoded, encoded_len, &blob->len);
	os_free(encoded);

	if (blob->name == NULL || blob->data == NULL) {
		wpa_config_free_blob(blob);
		return NULL;
	}

	return blob;
}


static int wpa_config_process_blob(struct wpa_config *config, FILE *f,
				   int *line, char *bname)
{
	char *name_end;
	struct wpa_config_blob *blob;

	name_end = os_strchr(bname, '=');
	if (name_end == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: no blob name terminator",
			   *line);
		return -1;
	}
	*name_end = '\0';

	blob = wpa_config_read_blob(f, line, bname);
	if (blob == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to read blob %s",
			   *line, bname);
		return -1;
	}
	wpa_config_set_blob(config, blob);
	return 0;
}
#endif /* CONFIG_NO_CONFIG_BLOBS */


#ifdef CONFIG_CTRL_IFACE
static int wpa_config_process_ctrl_interface(struct wpa_config *config,
					     char *pos)
{
	os_free(config->ctrl_interface);
	config->ctrl_interface = os_strdup(pos);
	wpa_printf(MSG_DEBUG, "ctrl_interface='%s'", config->ctrl_interface);
	return 0;
}


static int wpa_config_process_ctrl_interface_group(struct wpa_config *config,
						   char *pos)
{
	os_free(config->ctrl_interface_group);
	config->ctrl_interface_group = os_strdup(pos);
	wpa_printf(MSG_DEBUG, "ctrl_interface_group='%s' (DEPRECATED)",
		   config->ctrl_interface_group);
	return 0;
}
#endif /* CONFIG_CTRL_IFACE */


static int wpa_config_process_eapol_version(struct wpa_config *config,
					    int line, char *pos)
{
	config->eapol_version = atoi(pos);
	if (config->eapol_version < 1 || config->eapol_version > 2) {
		wpa_printf(MSG_ERROR, "Line %d: Invalid EAPOL version (%d): "
			   "'%s'.", line, config->eapol_version, pos);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "eapol_version=%d", config->eapol_version);
	return 0;
}


static int wpa_config_process_ap_scan(struct wpa_config *config, char *pos)
{
	config->ap_scan = atoi(pos);
	wpa_printf(MSG_DEBUG, "ap_scan=%d", config->ap_scan);
	return 0;
}


static int wpa_config_process_fast_reauth(struct wpa_config *config, char *pos)
{
	config->fast_reauth = atoi(pos);
	wpa_printf(MSG_DEBUG, "fast_reauth=%d", config->fast_reauth);
	return 0;
}


#ifdef EAP_TLS_OPENSSL

static int wpa_config_process_opensc_engine_path(struct wpa_config *config,
						 char *pos)
{
	os_free(config->opensc_engine_path);
	config->opensc_engine_path = os_strdup(pos);
	wpa_printf(MSG_DEBUG, "opensc_engine_path='%s'",
		   config->opensc_engine_path);
	return 0;
}


static int wpa_config_process_pkcs11_engine_path(struct wpa_config *config,
						 char *pos)
{
	os_free(config->pkcs11_engine_path);
	config->pkcs11_engine_path = os_strdup(pos);
	wpa_printf(MSG_DEBUG, "pkcs11_engine_path='%s'",
		   config->pkcs11_engine_path);
	return 0;
}


static int wpa_config_process_pkcs11_module_path(struct wpa_config *config,
						 char *pos)
{
	os_free(config->pkcs11_module_path);
	config->pkcs11_module_path = os_strdup(pos);
	wpa_printf(MSG_DEBUG, "pkcs11_module_path='%s'",
		   config->pkcs11_module_path);
	return 0;
}

#endif /* EAP_TLS_OPENSSL */


static int wpa_config_process_driver_param(struct wpa_config *config,
					   char *pos)
{
	os_free(config->driver_param);
	config->driver_param = os_strdup(pos);
	wpa_printf(MSG_DEBUG, "driver_param='%s'", config->driver_param);
	return 0;
}


static int wpa_config_process_pmk_lifetime(struct wpa_config *config,
					   char *pos)
{
	config->dot11RSNAConfigPMKLifetime = atoi(pos);
	wpa_printf(MSG_DEBUG, "dot11RSNAConfigPMKLifetime=%d",
		   config->dot11RSNAConfigPMKLifetime);
	return 0;
}


static int wpa_config_process_pmk_reauth_threshold(struct wpa_config *config,
						   char *pos)
{
	config->dot11RSNAConfigPMKReauthThreshold = atoi(pos);
	wpa_printf(MSG_DEBUG, "dot11RSNAConfigPMKReauthThreshold=%d",
		   config->dot11RSNAConfigPMKReauthThreshold);
	return 0;
}


static int wpa_config_process_sa_timeout(struct wpa_config *config, char *pos)
{
	config->dot11RSNAConfigSATimeout = atoi(pos);
	wpa_printf(MSG_DEBUG, "dot11RSNAConfigSATimeout=%d",
		   config->dot11RSNAConfigSATimeout);
	return 0;
}


#ifndef CONFIG_NO_CONFIG_WRITE
static int wpa_config_process_update_config(struct wpa_config *config,
					    char *pos)
{
	config->update_config = atoi(pos);
	wpa_printf(MSG_DEBUG, "update_config=%d", config->update_config);
	return 0;
}
#endif /* CONFIG_NO_CONFIG_WRITE */


static int wpa_config_process_load_dynamic_eap(int line, char *so)
{
	int ret;
	wpa_printf(MSG_DEBUG, "load_dynamic_eap=%s", so);
	ret = eap_peer_method_load(so);
	if (ret == -2) {
		wpa_printf(MSG_DEBUG, "This EAP type was already loaded - not "
			   "reloading.");
	} else if (ret) {
		wpa_printf(MSG_ERROR, "Line %d: Failed to load dynamic EAP "
			   "method '%s'.", line, so);
		return -1;
	}

	return 0;
}


static int wpa_config_process_global(struct wpa_config *config, char *pos,
				     int line)
{
#ifdef CONFIG_CTRL_IFACE
	if (os_strncmp(pos, "ctrl_interface=", 15) == 0)
		return wpa_config_process_ctrl_interface(config, pos + 15);

	if (os_strncmp(pos, "ctrl_interface_group=", 21) == 0)
		return wpa_config_process_ctrl_interface_group(config,
							       pos + 21);
#endif /* CONFIG_CTRL_IFACE */

	if (os_strncmp(pos, "eapol_version=", 14) == 0)
		return wpa_config_process_eapol_version(config, line,
							pos + 14);

	if (os_strncmp(pos, "ap_scan=", 8) == 0)
		return wpa_config_process_ap_scan(config, pos + 8);

	if (os_strncmp(pos, "fast_reauth=", 12) == 0)
		return wpa_config_process_fast_reauth(config, pos + 12);

#ifdef EAP_TLS_OPENSSL
	if (os_strncmp(pos, "opensc_engine_path=", 19) == 0)
		return wpa_config_process_opensc_engine_path(config, pos + 19);

	if (os_strncmp(pos, "pkcs11_engine_path=", 19) == 0)
		return wpa_config_process_pkcs11_engine_path(config, pos + 19);

	if (os_strncmp(pos, "pkcs11_module_path=", 19) == 0)
		return wpa_config_process_pkcs11_module_path(config, pos + 19);
#endif /* EAP_TLS_OPENSSL */

	if (os_strncmp(pos, "driver_param=", 13) == 0)
		return wpa_config_process_driver_param(config, pos + 13);

	if (os_strncmp(pos, "dot11RSNAConfigPMKLifetime=", 27) == 0)
		return wpa_config_process_pmk_lifetime(config, pos + 27);

	if (os_strncmp(pos, "dot11RSNAConfigPMKReauthThreshold=", 34) == 0)
		return wpa_config_process_pmk_reauth_threshold(config,
							       pos + 34);

	if (os_strncmp(pos, "dot11RSNAConfigSATimeout=", 25) == 0)
		return wpa_config_process_sa_timeout(config, pos + 25);

#ifndef CONFIG_NO_CONFIG_WRITE
	if (os_strncmp(pos, "update_config=", 14) == 0)
		return wpa_config_process_update_config(config, pos + 14);
#endif /* CONFIG_NO_CONFIG_WRITE */

	if (os_strncmp(pos, "load_dynamic_eap=", 17) == 0)
		return wpa_config_process_load_dynamic_eap(line, pos + 17);

	return -1;
}


struct wpa_config * wpa_config_read(const char *name)
{
	FILE *f;
	char buf[256], *pos;
	int errors = 0, line = 0;
	struct wpa_ssid *ssid, *tail = NULL, *head = NULL;
	struct wpa_config *config;
	int id = 0;

	config = wpa_config_alloc_empty(NULL, NULL);
	if (config == NULL)
		return NULL;
	wpa_printf(MSG_DEBUG, "Reading configuration file '%s'", name);
	f = fopen(name, "r");
	if (f == NULL) {
		os_free(config);
		return NULL;
	}

	while (wpa_config_get_line(buf, sizeof(buf), f, &line, &pos)) {
		if (os_strcmp(pos, "network={") == 0) {
			ssid = wpa_config_read_network(f, &line, id++);
			if (ssid == NULL) {
				wpa_printf(MSG_ERROR, "Line %d: failed to "
					   "parse network block.", line);
				errors++;
				continue;
			}
			if (head == NULL) {
				head = tail = ssid;
			} else {
				tail->next = ssid;
				tail = ssid;
			}
			if (wpa_config_add_prio_network(config, ssid)) {
				wpa_printf(MSG_ERROR, "Line %d: failed to add "
					   "network block to priority list.",
					   line);
				errors++;
				continue;
			}
#ifndef CONFIG_NO_CONFIG_BLOBS
		} else if (os_strncmp(pos, "blob-base64-", 12) == 0) {
			if (wpa_config_process_blob(config, f, &line, pos + 12)
			    < 0) {
				errors++;
				continue;
			}
#endif /* CONFIG_NO_CONFIG_BLOBS */
		} else if (wpa_config_process_global(config, pos, line) < 0) {
			wpa_printf(MSG_ERROR, "Line %d: Invalid configuration "
				   "line '%s'.", line, pos);
			errors++;
			continue;
		}
	}

	fclose(f);

	config->ssid = head;
	wpa_config_debug_dump_networks(config);

	if (errors) {
		wpa_config_free(config);
		config = NULL;
		head = NULL;
	}

	return config;
}


#ifndef CONFIG_NO_CONFIG_WRITE

static void write_str(FILE *f, const char *field, struct wpa_ssid *ssid)
{
	char *value = wpa_config_get(ssid, field);
	if (value == NULL)
		return;
	fprintf(f, "\t%s=%s\n", field, value);
	os_free(value);
}


static void write_int(FILE *f, const char *field, int value, int def)
{
	if (value == def)
		return;
	fprintf(f, "\t%s=%d\n", field, value);
}


static void write_bssid(FILE *f, struct wpa_ssid *ssid)
{
	char *value = wpa_config_get(ssid, "bssid");
	if (value == NULL)
		return;
	fprintf(f, "\tbssid=%s\n", value);
	os_free(value);
}


static void write_psk(FILE *f, struct wpa_ssid *ssid)
{
	char *value = wpa_config_get(ssid, "psk");
	if (value == NULL)
		return;
	fprintf(f, "\tpsk=%s\n", value);
	os_free(value);
}


static void write_proto(FILE *f, struct wpa_ssid *ssid)
{
	char *value;

	if (ssid->proto == DEFAULT_PROTO)
		return;

	value = wpa_config_get(ssid, "proto");
	if (value == NULL)
		return;
	if (value[0])
		fprintf(f, "\tproto=%s\n", value);
	os_free(value);
}


static void write_key_mgmt(FILE *f, struct wpa_ssid *ssid)
{
	char *value;

	if (ssid->key_mgmt == DEFAULT_KEY_MGMT)
		return;

	value = wpa_config_get(ssid, "key_mgmt");
	if (value == NULL)
		return;
	if (value[0])
		fprintf(f, "\tkey_mgmt=%s\n", value);
	os_free(value);
}


static void write_pairwise(FILE *f, struct wpa_ssid *ssid)
{
	char *value;

	if (ssid->pairwise_cipher == DEFAULT_PAIRWISE)
		return;

	value = wpa_config_get(ssid, "pairwise");
	if (value == NULL)
		return;
	if (value[0])
		fprintf(f, "\tpairwise=%s\n", value);
	os_free(value);
}


static void write_group(FILE *f, struct wpa_ssid *ssid)
{
	char *value;

	if (ssid->group_cipher == DEFAULT_GROUP)
		return;

	value = wpa_config_get(ssid, "group");
	if (value == NULL)
		return;
	if (value[0])
		fprintf(f, "\tgroup=%s\n", value);
	os_free(value);
}


static void write_auth_alg(FILE *f, struct wpa_ssid *ssid)
{
	char *value;

	if (ssid->auth_alg == 0)
		return;

	value = wpa_config_get(ssid, "auth_alg");
	if (value == NULL)
		return;
	if (value[0])
		fprintf(f, "\tauth_alg=%s\n", value);
	os_free(value);
}


#ifdef IEEE8021X_EAPOL
static void write_eap(FILE *f, struct wpa_ssid *ssid)
{
	char *value;

	value = wpa_config_get(ssid, "eap");
	if (value == NULL)
		return;

	if (value[0])
		fprintf(f, "\teap=%s\n", value);
	os_free(value);
}
#endif /* IEEE8021X_EAPOL */


static void write_wep_key(FILE *f, int idx, struct wpa_ssid *ssid)
{
	char field[20], *value;
	int res;

	res = os_snprintf(field, sizeof(field), "wep_key%d", idx);
	if (res < 0 || (size_t) res >= sizeof(field))
		return;
	value = wpa_config_get(ssid, field);
	if (value) {
		fprintf(f, "\t%s=%s\n", field, value);
		os_free(value);
	}
}


static void wpa_config_write_network(FILE *f, struct wpa_ssid *ssid)
{
	int i;

#define STR(t) write_str(f, #t, ssid)
#define INT(t) write_int(f, #t, ssid->t, 0)
#define INTe(t) write_int(f, #t, ssid->eap.t, 0)
#define INT_DEF(t, def) write_int(f, #t, ssid->t, def)
#define INT_DEFe(t, def) write_int(f, #t, ssid->eap.t, def)

	STR(ssid);
	INT(scan_ssid);
	write_bssid(f, ssid);
	write_psk(f, ssid);
	write_proto(f, ssid);
	write_key_mgmt(f, ssid);
	write_pairwise(f, ssid);
	write_group(f, ssid);
	write_auth_alg(f, ssid);
#ifdef IEEE8021X_EAPOL
	write_eap(f, ssid);
	STR(identity);
	STR(anonymous_identity);
	STR(password);
	STR(ca_cert);
	STR(ca_path);
	STR(client_cert);
	STR(private_key);
	STR(private_key_passwd);
	STR(dh_file);
	STR(subject_match);
	STR(altsubject_match);
	STR(ca_cert2);
	STR(ca_path2);
	STR(client_cert2);
	STR(private_key2);
	STR(private_key2_passwd);
	STR(dh_file2);
	STR(subject_match2);
	STR(altsubject_match2);
	STR(phase1);
	STR(phase2);
	STR(pcsc);
	STR(pin);
	STR(engine_id);
	STR(key_id);
	STR(cert_id);
	STR(ca_cert_id);
	STR(key2_id);
	STR(cert2_id);
	STR(ca_cert2_id);
	INTe(engine);
	INT_DEF(eapol_flags, DEFAULT_EAPOL_FLAGS);
#endif /* IEEE8021X_EAPOL */
	for (i = 0; i < 4; i++)
		write_wep_key(f, i, ssid);
	INT(wep_tx_keyidx);
	INT(priority);
#ifdef IEEE8021X_EAPOL
	INT_DEF(eap_workaround, DEFAULT_EAP_WORKAROUND);
	STR(pac_file);
	INT_DEFe(fragment_size, DEFAULT_FRAGMENT_SIZE);
#endif /* IEEE8021X_EAPOL */
	INT(mode);
	INT(proactive_key_caching);
	INT(disabled);
	INT(peerkey);
#ifdef CONFIG_IEEE80211W
	INT(ieee80211w);
#endif /* CONFIG_IEEE80211W */
	STR(id_str);

#undef STR
#undef INT
#undef INT_DEF
}


#ifndef CONFIG_NO_CONFIG_BLOBS
static int wpa_config_write_blob(FILE *f, struct wpa_config_blob *blob)
{
	unsigned char *encoded;

	encoded = base64_encode(blob->data, blob->len, NULL);
	if (encoded == NULL)
		return -1;

	fprintf(f, "\nblob-base64-%s={\n%s}\n", blob->name, encoded);
	os_free(encoded);
	return 0;
}
#endif /* CONFIG_NO_CONFIG_BLOBS */


static void wpa_config_write_global(FILE *f, struct wpa_config *config)
{
#ifdef CONFIG_CTRL_IFACE
	if (config->ctrl_interface)
		fprintf(f, "ctrl_interface=%s\n", config->ctrl_interface);
	if (config->ctrl_interface_group)
		fprintf(f, "ctrl_interface_group=%s\n",
			config->ctrl_interface_group);
#endif /* CONFIG_CTRL_IFACE */
	if (config->eapol_version != DEFAULT_EAPOL_VERSION)
		fprintf(f, "eapol_version=%d\n", config->eapol_version);
	if (config->ap_scan != DEFAULT_AP_SCAN)
		fprintf(f, "ap_scan=%d\n", config->ap_scan);
	if (config->fast_reauth != DEFAULT_FAST_REAUTH)
		fprintf(f, "fast_reauth=%d\n", config->fast_reauth);
#ifdef EAP_TLS_OPENSSL
	if (config->opensc_engine_path)
		fprintf(f, "opensc_engine_path=%s\n",
			config->opensc_engine_path);
	if (config->pkcs11_engine_path)
		fprintf(f, "pkcs11_engine_path=%s\n",
			config->pkcs11_engine_path);
	if (config->pkcs11_module_path)
		fprintf(f, "pkcs11_module_path=%s\n",
			config->pkcs11_module_path);
#endif /* EAP_TLS_OPENSSL */
	if (config->driver_param)
		fprintf(f, "driver_param=%s\n", config->driver_param);
	if (config->dot11RSNAConfigPMKLifetime)
		fprintf(f, "dot11RSNAConfigPMKLifetime=%d\n",
			config->dot11RSNAConfigPMKLifetime);
	if (config->dot11RSNAConfigPMKReauthThreshold)
		fprintf(f, "dot11RSNAConfigPMKReauthThreshold=%d\n",
			config->dot11RSNAConfigPMKReauthThreshold);
	if (config->dot11RSNAConfigSATimeout)
		fprintf(f, "dot11RSNAConfigSATimeout=%d\n",
			config->dot11RSNAConfigSATimeout);
	if (config->update_config)
		fprintf(f, "update_config=%d\n", config->update_config);
}

#endif /* CONFIG_NO_CONFIG_WRITE */


int wpa_config_write(const char *name, struct wpa_config *config)
{
#ifndef CONFIG_NO_CONFIG_WRITE
	FILE *f;
	struct wpa_ssid *ssid;
#ifndef CONFIG_NO_CONFIG_BLOBS
	struct wpa_config_blob *blob;
#endif /* CONFIG_NO_CONFIG_BLOBS */
	int ret = 0;

	wpa_printf(MSG_DEBUG, "Writing configuration file '%s'", name);

	f = fopen(name, "w");
	if (f == NULL) {
		wpa_printf(MSG_DEBUG, "Failed to open '%s' for writing", name);
		return -1;
	}

	wpa_config_write_global(f, config);

	for (ssid = config->ssid; ssid; ssid = ssid->next) {
		fprintf(f, "\nnetwork={\n");
		wpa_config_write_network(f, ssid);
		fprintf(f, "}\n");
	}

#ifndef CONFIG_NO_CONFIG_BLOBS
	for (blob = config->blobs; blob; blob = blob->next) {
		ret = wpa_config_write_blob(f, blob);
		if (ret)
			break;
	}
#endif /* CONFIG_NO_CONFIG_BLOBS */

	fclose(f);

	wpa_printf(MSG_DEBUG, "Configuration file '%s' written %ssuccessfully",
		   name, ret ? "un" : "");
	return ret;
#else /* CONFIG_NO_CONFIG_WRITE */
	return -1;
#endif /* CONFIG_NO_CONFIG_WRITE */
}
