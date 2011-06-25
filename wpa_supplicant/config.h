/*
 * WPA Supplicant / Configuration file structures
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
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

#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_EAPOL_VERSION 1
#ifdef CONFIG_NO_SCAN_PROCESSING
#define DEFAULT_AP_SCAN 2
#else /* CONFIG_NO_SCAN_PROCESSING */
#define DEFAULT_AP_SCAN 1
#endif /* CONFIG_NO_SCAN_PROCESSING */
#define DEFAULT_FAST_REAUTH 1
#define DEFAULT_P2P_GO_INTENT 7
#define DEFAULT_P2P_INTRA_BSS 1
#define DEFAULT_BSS_MAX_COUNT 200
#define DEFAULT_BSS_EXPIRATION_AGE 180
#define DEFAULT_BSS_EXPIRATION_SCAN_COUNT 2
#define DEFAULT_MAX_NUM_STA 128

#include "config_ssid.h"
#include "wps/wps.h"


#define CFG_CHANGED_DEVICE_NAME BIT(0)
#define CFG_CHANGED_CONFIG_METHODS BIT(1)
#define CFG_CHANGED_DEVICE_TYPE BIT(2)
#define CFG_CHANGED_OS_VERSION BIT(3)
#define CFG_CHANGED_UUID BIT(4)
#define CFG_CHANGED_COUNTRY BIT(5)
#define CFG_CHANGED_SEC_DEVICE_TYPE BIT(6)
#define CFG_CHANGED_P2P_SSID_POSTFIX BIT(7)
#define CFG_CHANGED_WPS_STRING BIT(8)
#define CFG_CHANGED_P2P_INTRA_BSS BIT(9)
#define CFG_CHANGED_VENDOR_EXTENSION BIT(10)
#define CFG_CHANGED_P2P_LISTEN_CHANNEL BIT(11)
#define CFG_CHANGED_P2P_OPER_CHANNEL BIT(12)

/**
 * struct wpa_config - wpa_supplicant configuration data
 *
 * This data structure is presents the per-interface (radio) configuration
 * data. In many cases, there is only one struct wpa_config instance, but if
 * more than one network interface is being controlled, one instance is used
 * for each.
 */
struct wpa_config {
	/**
	 * ssid - Head of the global network list
	 *
	 * This is the head for the list of all the configured networks.
	 */
	struct wpa_ssid *ssid;

	/**
	 * pssid - Per-priority network lists (in priority order)
	 */
	struct wpa_ssid **pssid;

	/**
	 * num_prio - Number of different priorities used in the pssid lists
	 *
	 * This indicates how many per-priority network lists are included in
	 * pssid.
	 */
	int num_prio;

	/**
	 * eapol_version - IEEE 802.1X/EAPOL version number
	 *
	 * wpa_supplicant is implemented based on IEEE Std 802.1X-2004 which
	 * defines EAPOL version 2. However, there are many APs that do not
	 * handle the new version number correctly (they seem to drop the
	 * frames completely). In order to make wpa_supplicant interoperate
	 * with these APs, the version number is set to 1 by default. This
	 * configuration value can be used to set it to the new version (2).
	 */
	int eapol_version;

	/**
	 * ap_scan - AP scanning/selection
	 *
	 * By default, wpa_supplicant requests driver to perform AP
	 * scanning and then uses the scan results to select a
	 * suitable AP. Another alternative is to allow the driver to
	 * take care of AP scanning and selection and use
	 * wpa_supplicant just to process EAPOL frames based on IEEE
	 * 802.11 association information from the driver.
	 *
	 * 1: wpa_supplicant initiates scanning and AP selection (default).
	 *
	 * 0: Driver takes care of scanning, AP selection, and IEEE 802.11
	 * association parameters (e.g., WPA IE generation); this mode can
	 * also be used with non-WPA drivers when using IEEE 802.1X mode;
	 * do not try to associate with APs (i.e., external program needs
	 * to control association). This mode must also be used when using
	 * wired Ethernet drivers.
	 *
	 * 2: like 0, but associate with APs using security policy and SSID
	 * (but not BSSID); this can be used, e.g., with ndiswrapper and NDIS
	 * drivers to enable operation with hidden SSIDs and optimized roaming;
	 * in this mode, the network blocks in the configuration are tried
	 * one by one until the driver reports successful association; each
	 * network block should have explicit security policy (i.e., only one
	 * option in the lists) for key_mgmt, pairwise, group, proto variables.
	 */
	int ap_scan;

	/**
	 * ctrl_interface - Parameters for the control interface
	 *
	 * If this is specified, %wpa_supplicant will open a control interface
	 * that is available for external programs to manage %wpa_supplicant.
	 * The meaning of this string depends on which control interface
	 * mechanism is used. For all cases, the existance of this parameter
	 * in configuration is used to determine whether the control interface
	 * is enabled.
	 *
	 * For UNIX domain sockets (default on Linux and BSD): This is a
	 * directory that will be created for UNIX domain sockets for listening
	 * to requests from external programs (CLI/GUI, etc.) for status
	 * information and configuration. The socket file will be named based
	 * on the interface name, so multiple %wpa_supplicant processes can be
	 * run at the same time if more than one interface is used.
	 * /var/run/wpa_supplicant is the recommended directory for sockets and
	 * by default, wpa_cli will use it when trying to connect with
	 * %wpa_supplicant.
	 *
	 * Access control for the control interface can be configured
	 * by setting the directory to allow only members of a group
	 * to use sockets. This way, it is possible to run
	 * %wpa_supplicant as root (since it needs to change network
	 * configuration and open raw sockets) and still allow GUI/CLI
	 * components to be run as non-root users. However, since the
	 * control interface can be used to change the network
	 * configuration, this access needs to be protected in many
	 * cases. By default, %wpa_supplicant is configured to use gid
	 * 0 (root). If you want to allow non-root users to use the
	 * control interface, add a new group and change this value to
	 * match with that group. Add users that should have control
	 * interface access to this group.
	 *
	 * When configuring both the directory and group, use following format:
	 * DIR=/var/run/wpa_supplicant GROUP=wheel
	 * DIR=/var/run/wpa_supplicant GROUP=0
	 * (group can be either group name or gid)
	 *
	 * For UDP connections (default on Windows): The value will be ignored.
	 * This variable is just used to select that the control interface is
	 * to be created. The value can be set to, e.g., udp
	 * (ctrl_interface=udp).
	 *
	 * For Windows Named Pipe: This value can be used to set the security
	 * descriptor for controlling access to the control interface. Security
	 * descriptor can be set using Security Descriptor String Format (see
	 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthz/security/security_descriptor_string_format.asp).
	 * The descriptor string needs to be prefixed with SDDL=. For example,
	 * ctrl_interface=SDDL=D: would set an empty DACL (which will reject
	 * all connections).
	 */
	char *ctrl_interface;

	/**
	 * ctrl_interface_group - Control interface group (DEPRECATED)
	 *
	 * This variable is only used for backwards compatibility. Group for
	 * UNIX domain sockets should now be specified using GROUP=group in
	 * ctrl_interface variable.
	 */
	char *ctrl_interface_group;

	/**
	 * fast_reauth - EAP fast re-authentication (session resumption)
	 *
	 * By default, fast re-authentication is enabled for all EAP methods
	 * that support it. This variable can be used to disable fast
	 * re-authentication (by setting fast_reauth=0). Normally, there is no
	 * need to disable fast re-authentication.
	 */
	int fast_reauth;

	/**
	 * opensc_engine_path - Path to the OpenSSL engine for opensc
	 *
	 * This is an OpenSSL specific configuration option for loading OpenSC
	 * engine (engine_opensc.so); if %NULL, this engine is not loaded.
	 */
	char *opensc_engine_path;

	/**
	 * pkcs11_engine_path - Path to the OpenSSL engine for PKCS#11
	 *
	 * This is an OpenSSL specific configuration option for loading PKCS#11
	 * engine (engine_pkcs11.so); if %NULL, this engine is not loaded.
	 */
	char *pkcs11_engine_path;

	/**
	 * pkcs11_module_path - Path to the OpenSSL OpenSC/PKCS#11 module
	 *
	 * This is an OpenSSL specific configuration option for configuring
	 * path to OpenSC/PKCS#11 engine (opensc-pkcs11.so); if %NULL, this
	 * module is not loaded.
	 */
	char *pkcs11_module_path;

	/**
	 * driver_param - Driver interface parameters
	 *
	 * This text string is passed to the selected driver interface with the
	 * optional struct wpa_driver_ops::set_param() handler. This can be
	 * used to configure driver specific options without having to add new
	 * driver interface functionality.
	 */
	char *driver_param;

	/**
	 * dot11RSNAConfigPMKLifetime - Maximum lifetime of a PMK
	 *
	 * dot11 MIB variable for the maximum lifetime of a PMK in the PMK
	 * cache (unit: seconds).
	 */
	unsigned int dot11RSNAConfigPMKLifetime;

	/**
	 * dot11RSNAConfigPMKReauthThreshold - PMK re-authentication threshold
	 *
	 * dot11 MIB variable for the percentage of the PMK lifetime
	 * that should expire before an IEEE 802.1X reauthentication occurs.
	 */
	unsigned int dot11RSNAConfigPMKReauthThreshold;

	/**
	 * dot11RSNAConfigSATimeout - Security association timeout
	 *
	 * dot11 MIB variable for the maximum time a security association
	 * shall take to set up (unit: seconds).
	 */
	unsigned int dot11RSNAConfigSATimeout;

	/**
	 * update_config - Is wpa_supplicant allowed to update configuration
	 *
	 * This variable control whether wpa_supplicant is allow to re-write
	 * its configuration with wpa_config_write(). If this is zero,
	 * configuration data is only changed in memory and the external data
	 * is not overriden. If this is non-zero, wpa_supplicant will update
	 * the configuration data (e.g., a file) whenever configuration is
	 * changed. This update may replace the old configuration which can
	 * remove comments from it in case of a text file configuration.
	 */
	int update_config;

	/**
	 * blobs - Configuration blobs
	 */
	struct wpa_config_blob *blobs;

	/**
	 * uuid - Universally Unique IDentifier (UUID; see RFC 4122) for WPS
	 */
	u8 uuid[16];

	/**
	 * device_name - Device Name (WPS)
	 * User-friendly description of device; up to 32 octets encoded in
	 * UTF-8
	 */
	char *device_name;

	/**
	 * manufacturer - Manufacturer (WPS)
	 * The manufacturer of the device (up to 64 ASCII characters)
	 */
	char *manufacturer;

	/**
	 * model_name - Model Name (WPS)
	 * Model of the device (up to 32 ASCII characters)
	 */
	char *model_name;

	/**
	 * model_number - Model Number (WPS)
	 * Additional device description (up to 32 ASCII characters)
	 */
	char *model_number;

	/**
	 * serial_number - Serial Number (WPS)
	 * Serial number of the device (up to 32 characters)
	 */
	char *serial_number;

	/**
	 * device_type - Primary Device Type (WPS)
	 */
	u8 device_type[WPS_DEV_TYPE_LEN];

	/**
	 * config_methods - Config Methods
	 *
	 * This is a space-separated list of supported WPS configuration
	 * methods. For example, "label virtual_display virtual_push_button
	 * keypad".
	 * Available methods: usba ethernet label display ext_nfc_token
	 * int_nfc_token nfc_interface push_button keypad
	 * virtual_display physical_display
	 * virtual_push_button physical_push_button.
	 */
	char *config_methods;

	/**
	 * os_version - OS Version (WPS)
	 * 4-octet operating system version number
	 */
	u8 os_version[4];

	/**
	 * country - Country code
	 *
	 * This is the ISO/IEC alpha2 country code for which we are operating
	 * in
	 */
	char country[2];

	/**
	 * wps_cred_processing - Credential processing
	 *
	 *   0 = process received credentials internally
	 *   1 = do not process received credentials; just pass them over
	 *	ctrl_iface to external program(s)
	 *   2 = process received credentials internally and pass them over
	 *	ctrl_iface to external program(s)
	 */
	int wps_cred_processing;

#define MAX_SEC_DEVICE_TYPES 5
	/**
	 * sec_device_types - Secondary Device Types (P2P)
	 */
	u8 sec_device_type[MAX_SEC_DEVICE_TYPES][WPS_DEV_TYPE_LEN];
	int num_sec_device_types;

	int p2p_listen_reg_class;
	int p2p_listen_channel;
	int p2p_oper_reg_class;
	int p2p_oper_channel;
	int p2p_go_intent;
	char *p2p_ssid_postfix;
	int persistent_reconnect;
	int p2p_intra_bss;

#define MAX_WPS_VENDOR_EXT 10
	/**
	 * wps_vendor_ext - Vendor extension attributes in WPS
	 */
	struct wpabuf *wps_vendor_ext[MAX_WPS_VENDOR_EXT];

	/**
	 * p2p_group_idle - Maximum idle time in seconds for P2P group
	 *
	 * This value controls how long a P2P group is maintained after there
	 * is no other members in the group. As a GO, this means no associated
	 * stations in the group. As a P2P client, this means no GO seen in
	 * scan results. The maximum idle time is specified in seconds with 0
	 * indicating no time limit, i.e., the P2P group remains in active
	 * state indefinitely until explicitly removed.
	 */
	unsigned int p2p_group_idle;

	/**
	 * bss_max_count - Maximum number of BSS entries to keep in memory
	 */
	unsigned int bss_max_count;

	/**
	 * bss_expiration_age - BSS entry age after which it can be expired
	 *
	 * This value controls the time in seconds after which a BSS entry
	 * gets removed if it has not been updated or is not in use.
	 */
	unsigned int bss_expiration_age;

	/**
	 * bss_expiration_scan_count - Expire BSS after number of scans
	 *
	 * If the BSS entry has not been seen in this many scans, it will be
	 * removed. A value of 1 means that entry is removed after the first
	 * scan in which the BSSID is not seen. Larger values can be used
	 * to avoid BSS entries disappearing if they are not visible in
	 * every scan (e.g., low signal quality or interference).
	 */
	unsigned int bss_expiration_scan_count;

	/**
	 * filter_ssids - SSID-based scan result filtering
	 *
	 *   0 = do not filter scan results
	 *   1 = only include configured SSIDs in scan results/BSS table
	 */
	int filter_ssids;

	/**
	 * max_num_sta - Maximum number of STAs in an AP/P2P GO
	 */
	unsigned int max_num_sta;

	/**
	 * changed_parameters - Bitmap of changed parameters since last update
	 */
	unsigned int changed_parameters;

	/**
	 * disassoc_low_ack - Disassocicate stations with massive packet loss
	 */
	int disassoc_low_ack;
};


/* Prototypes for common functions from config.c */

void wpa_config_free(struct wpa_config *ssid);
void wpa_config_free_ssid(struct wpa_ssid *ssid);
void wpa_config_foreach_network(struct wpa_config *config,
				void (*func)(void *, struct wpa_ssid *),
				void *arg);
struct wpa_ssid * wpa_config_get_network(struct wpa_config *config, int id);
struct wpa_ssid * wpa_config_add_network(struct wpa_config *config);
int wpa_config_remove_network(struct wpa_config *config, int id);
void wpa_config_set_network_defaults(struct wpa_ssid *ssid);
int wpa_config_set(struct wpa_ssid *ssid, const char *var, const char *value,
		   int line);
char ** wpa_config_get_all(struct wpa_ssid *ssid, int get_keys);
char * wpa_config_get(struct wpa_ssid *ssid, const char *var);
char * wpa_config_get_no_key(struct wpa_ssid *ssid, const char *var);
void wpa_config_update_psk(struct wpa_ssid *ssid);
int wpa_config_add_prio_network(struct wpa_config *config,
				struct wpa_ssid *ssid);
int wpa_config_update_prio_list(struct wpa_config *config);
const struct wpa_config_blob * wpa_config_get_blob(struct wpa_config *config,
						   const char *name);
void wpa_config_set_blob(struct wpa_config *config,
			 struct wpa_config_blob *blob);
void wpa_config_free_blob(struct wpa_config_blob *blob);
int wpa_config_remove_blob(struct wpa_config *config, const char *name);

struct wpa_config * wpa_config_alloc_empty(const char *ctrl_interface,
					   const char *driver_param);
#ifndef CONFIG_NO_STDOUT_DEBUG
void wpa_config_debug_dump_networks(struct wpa_config *config);
#else /* CONFIG_NO_STDOUT_DEBUG */
#define wpa_config_debug_dump_networks(c) do { } while (0)
#endif /* CONFIG_NO_STDOUT_DEBUG */


/* Prototypes for common functions from config.c */
int wpa_config_process_global(struct wpa_config *config, char *pos, int line);


/* Prototypes for backend specific functions from the selected config_*.c */

/**
 * wpa_config_read - Read and parse configuration database
 * @name: Name of the configuration (e.g., path and file name for the
 * configuration file)
 * Returns: Pointer to allocated configuration data or %NULL on failure
 *
 * This function reads configuration data, parses its contents, and allocates
 * data structures needed for storing configuration information. The allocated
 * data can be freed with wpa_config_free().
 *
 * Each configuration backend needs to implement this function.
 */
struct wpa_config * wpa_config_read(const char *name);

/**
 * wpa_config_write - Write or update configuration data
 * @name: Name of the configuration (e.g., path and file name for the
 * configuration file)
 * @config: Configuration data from wpa_config_read()
 * Returns: 0 on success, -1 on failure
 *
 * This function write all configuration data into an external database (e.g.,
 * a text file) in a format that can be read with wpa_config_read(). This can
 * be used to allow wpa_supplicant to update its configuration, e.g., when a
 * new network is added or a password is changed.
 *
 * Each configuration backend needs to implement this function.
 */
int wpa_config_write(const char *name, struct wpa_config *config);

#endif /* CONFIG_H */
