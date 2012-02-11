/*
 * WPA Supplicant / Configuration backend: text file
 * Copyright (c) 2003-2008, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements a configuration backend for text files. All the
 * configuration information is stored in a text file that uses a format
 * described in the sample configuration file, wpa_supplicant.conf.
 */

#include "includes.h"

#include "common.h"
#include "config.h"
#include "base64.h"
#include "uuid.h"


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

	if (wpa_key_mgmt_wpa_psk(ssid->key_mgmt) && !ssid->psk_set) {
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

#ifndef WPA_IGNORE_CONFIG_ERRORS
	if (errors) {
		wpa_config_free(config);
		config = NULL;
		head = NULL;
	}
#endif /* WPA_IGNORE_CONFIG_ERRORS */

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


#ifdef CONFIG_P2P
static void write_p2p_client_list(FILE *f, struct wpa_ssid *ssid)
{
	char *value = wpa_config_get(ssid, "p2p_client_list");
	if (value == NULL)
		return;
	fprintf(f, "\tp2p_client_list=%s\n", value);
	os_free(value);
}
#endif /* CONFIG_P2P */


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
	STR(pin2);
	STR(engine2_id);
	STR(cert2_id);
	STR(ca_cert2_id);
	INTe(engine);
	INTe(engine2);
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
#ifdef CONFIG_P2P
	write_p2p_client_list(f, ssid);
#endif /* CONFIG_P2P */

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
	if (config->opensc_engine_path)
		fprintf(f, "opensc_engine_path=%s\n",
			config->opensc_engine_path);
	if (config->pkcs11_engine_path)
		fprintf(f, "pkcs11_engine_path=%s\n",
			config->pkcs11_engine_path);
	if (config->pkcs11_module_path)
		fprintf(f, "pkcs11_module_path=%s\n",
			config->pkcs11_module_path);
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
#ifdef CONFIG_WPS
	if (!is_nil_uuid(config->uuid)) {
		char buf[40];
		uuid_bin2str(config->uuid, buf, sizeof(buf));
		fprintf(f, "uuid=%s\n", buf);
	}
	if (config->device_name)
		fprintf(f, "device_name=%s\n", config->device_name);
	if (config->manufacturer)
		fprintf(f, "manufacturer=%s\n", config->manufacturer);
	if (config->model_name)
		fprintf(f, "model_name=%s\n", config->model_name);
	if (config->model_number)
		fprintf(f, "model_number=%s\n", config->model_number);
	if (config->serial_number)
		fprintf(f, "serial_number=%s\n", config->serial_number);
	{
		char _buf[WPS_DEV_TYPE_BUFSIZE], *buf;
		buf = wps_dev_type_bin2str(config->device_type,
					   _buf, sizeof(_buf));
		if (os_strcmp(buf, "0-00000000-0") != 0)
			fprintf(f, "device_type=%s\n", buf);
	}
	if (WPA_GET_BE32(config->os_version))
		fprintf(f, "os_version=%08x\n",
			WPA_GET_BE32(config->os_version));
	if (config->config_methods)
		fprintf(f, "config_methods=%s\n", config->config_methods);
	if (config->wps_cred_processing)
		fprintf(f, "wps_cred_processing=%d\n",
			config->wps_cred_processing);
#endif /* CONFIG_WPS */
#ifdef CONFIG_P2P
	if (config->p2p_listen_reg_class)
		fprintf(f, "p2p_listen_reg_class=%u\n",
			config->p2p_listen_reg_class);
	if (config->p2p_listen_channel)
		fprintf(f, "p2p_listen_channel=%u\n",
			config->p2p_listen_channel);
	if (config->p2p_oper_reg_class)
		fprintf(f, "p2p_oper_reg_class=%u\n",
			config->p2p_oper_reg_class);
	if (config->p2p_oper_channel)
		fprintf(f, "p2p_oper_channel=%u\n", config->p2p_oper_channel);
	if (config->p2p_go_intent != DEFAULT_P2P_GO_INTENT)
		fprintf(f, "p2p_go_intent=%u\n", config->p2p_go_intent);
	if (config->p2p_ssid_postfix)
		fprintf(f, "p2p_ssid_postfix=%s\n", config->p2p_ssid_postfix);
	if (config->persistent_reconnect)
		fprintf(f, "persistent_reconnect=%u\n",
			config->persistent_reconnect);
	if (config->p2p_intra_bss != DEFAULT_P2P_INTRA_BSS)
		fprintf(f, "p2p_intra_bss=%u\n", config->p2p_intra_bss);
	if (config->p2p_group_idle)
		fprintf(f, "p2p_group_idle=%u\n", config->p2p_group_idle);
#endif /* CONFIG_P2P */
	if (config->country[0] && config->country[1]) {
		fprintf(f, "country=%c%c\n",
			config->country[0], config->country[1]);
	}
	if (config->bss_max_count != DEFAULT_BSS_MAX_COUNT)
		fprintf(f, "bss_max_count=%u\n", config->bss_max_count);
	if (config->bss_expiration_age != DEFAULT_BSS_EXPIRATION_AGE)
		fprintf(f, "bss_expiration_age=%u\n",
			config->bss_expiration_age);
	if (config->bss_expiration_scan_count !=
	    DEFAULT_BSS_EXPIRATION_SCAN_COUNT)
		fprintf(f, "bss_expiration_scan_count=%u\n",
			config->bss_expiration_scan_count);
	if (config->filter_ssids)
		fprintf(f, "filter_ssids=%d\n", config->filter_ssids);
	if (config->max_num_sta != DEFAULT_MAX_NUM_STA)
		fprintf(f, "max_num_sta=%u\n", config->max_num_sta);
	if (config->disassoc_low_ack)
		fprintf(f, "disassoc_low_ack=%u\n", config->disassoc_low_ack);
#ifdef CONFIG_INTERWORKING
	if (config->home_realm)
		fprintf(f, "home_realm=%s\n", config->home_realm);
	if (config->home_username)
		fprintf(f, "home_username=%s\n", config->home_username);
	if (config->home_password)
		fprintf(f, "home_password=%s\n", config->home_password);
	if (config->home_ca_cert)
		fprintf(f, "home_ca_cert=%s\n", config->home_ca_cert);
	if (config->home_imsi)
		fprintf(f, "home_imsi=%s\n", config->home_imsi);
	if (config->home_milenage)
		fprintf(f, "home_milenage=%s\n", config->home_milenage);
	if (config->interworking)
		fprintf(f, "interworking=%u\n", config->interworking);
	if (!is_zero_ether_addr(config->hessid))
		fprintf(f, "hessid=" MACSTR "\n", MAC2STR(config->hessid));
	if (config->access_network_type != DEFAULT_ACCESS_NETWORK_TYPE)
		fprintf(f, "access_network_type=%d\n",
			config->access_network_type);
#endif /* CONFIG_INTERWORKING */
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
		if (ssid->key_mgmt == WPA_KEY_MGMT_WPS || ssid->temporary)
			continue; /* do not save temporary networks */
		if (wpa_key_mgmt_wpa_psk(ssid->key_mgmt) && !ssid->psk_set &&
		    !ssid->passphrase)
			continue; /* do not save invalid network */
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
