/*
 * WPA Supplicant - command line interface for wpa_supplicant daemon
 * Copyright (c) 2004-2011, Jouni Malinen <j@w1.fi>
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

#ifdef CONFIG_CTRL_IFACE

#ifdef CONFIG_CTRL_IFACE_UNIX
#include <dirent.h>
#endif /* CONFIG_CTRL_IFACE_UNIX */

#include "common/wpa_ctrl.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/edit.h"
#include "common/version.h"
#ifdef ANDROID
#include <cutils/properties.h>
#endif /* ANDROID */


static const char *wpa_cli_version =
"wpa_cli v" VERSION_STR "\n"
"Copyright (c) 2004-2011, Jouni Malinen <j@w1.fi> and contributors";


static const char *wpa_cli_license =
"This program is free software. You can distribute it and/or modify it\n"
"under the terms of the GNU General Public License version 2.\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license. See README and COPYING for more details.\n";

static const char *wpa_cli_full_license =
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License version 2 as\n"
"published by the Free Software Foundation.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program; if not, write to the Free Software\n"
"Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license.\n"
"\n"
"Redistribution and use in source and binary forms, with or without\n"
"modification, are permitted provided that the following conditions are\n"
"met:\n"
"\n"
"1. Redistributions of source code must retain the above copyright\n"
"   notice, this list of conditions and the following disclaimer.\n"
"\n"
"2. Redistributions in binary form must reproduce the above copyright\n"
"   notice, this list of conditions and the following disclaimer in the\n"
"   documentation and/or other materials provided with the distribution.\n"
"\n"
"3. Neither the name(s) of the above-listed copyright holder(s) nor the\n"
"   names of its contributors may be used to endorse or promote products\n"
"   derived from this software without specific prior written permission.\n"
"\n"
"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
"\n";

static struct wpa_ctrl *ctrl_conn;
static struct wpa_ctrl *mon_conn;
static int wpa_cli_quit = 0;
static int wpa_cli_attached = 0;
static int wpa_cli_connected = 0;
static int wpa_cli_last_id = 0;
#ifndef CONFIG_CTRL_IFACE_DIR
#define CONFIG_CTRL_IFACE_DIR "/var/run/wpa_supplicant"
#endif /* CONFIG_CTRL_IFACE_DIR */
static const char *ctrl_iface_dir = CONFIG_CTRL_IFACE_DIR;
static char *ctrl_ifname = NULL;
static const char *pid_file = NULL;
static const char *action_file = NULL;
static int ping_interval = 5;
static int interactive = 0;


static void print_help(void);
static void wpa_cli_mon_receive(int sock, void *eloop_ctx, void *sock_ctx);


static void usage(void)
{
	printf("wpa_cli [-p<path to ctrl sockets>] [-i<ifname>] [-hvB] "
	       "[-a<action file>] \\\n"
	       "        [-P<pid file>] [-g<global ctrl>] [-G<ping interval>]  "
	       "[command..]\n"
	       "  -h = help (show this usage text)\n"
	       "  -v = shown version information\n"
	       "  -a = run in daemon mode executing the action file based on "
	       "events from\n"
	       "       wpa_supplicant\n"
	       "  -B = run a daemon in the background\n"
	       "  default path: " CONFIG_CTRL_IFACE_DIR "\n"
	       "  default interface: first interface found in socket path\n");
	print_help();
}


static int str_starts(const char *src, const char *match)
{
	return os_strncmp(src, match, os_strlen(match)) == 0;
}


static int wpa_cli_show_event(const char *event)
{
	const char *start;

	start = os_strchr(event, '>');
	if (start == NULL)
		return 1;

	start++;
	/*
	 * Skip BSS added/removed events since they can be relatively frequent
	 * and are likely of not much use for an interactive user.
	 */
	if (str_starts(start, WPA_EVENT_BSS_ADDED) ||
	    str_starts(start, WPA_EVENT_BSS_REMOVED))
		return 0;

	return 1;
}


static int wpa_cli_open_connection(const char *ifname, int attach)
{
#if defined(CONFIG_CTRL_IFACE_UDP) || defined(CONFIG_CTRL_IFACE_NAMED_PIPE)
	ctrl_conn = wpa_ctrl_open(ifname);
	if (ctrl_conn == NULL)
		return -1;

	if (attach && interactive)
		mon_conn = wpa_ctrl_open(ifname);
	else
		mon_conn = NULL;
#else /* CONFIG_CTRL_IFACE_UDP || CONFIG_CTRL_IFACE_NAMED_PIPE */
	char *cfile = NULL;
	int flen, res;

	if (ifname == NULL)
		return -1;

#ifdef ANDROID
	if (access(ctrl_iface_dir, F_OK) < 0) {
		cfile = os_strdup(ifname);
		if (cfile == NULL)
			return -1;
	}
#endif /* ANDROID */

	if (cfile == NULL) {
		flen = os_strlen(ctrl_iface_dir) + os_strlen(ifname) + 2;
		cfile = os_malloc(flen);
		if (cfile == NULL)
			return -1;
		res = os_snprintf(cfile, flen, "%s/%s", ctrl_iface_dir,
				  ifname);
		if (res < 0 || res >= flen) {
			os_free(cfile);
			return -1;
		}
	}

	ctrl_conn = wpa_ctrl_open(cfile);
	if (ctrl_conn == NULL) {
		os_free(cfile);
		return -1;
	}

	if (attach && interactive)
		mon_conn = wpa_ctrl_open(cfile);
	else
		mon_conn = NULL;
	os_free(cfile);
#endif /* CONFIG_CTRL_IFACE_UDP || CONFIG_CTRL_IFACE_NAMED_PIPE */

	if (mon_conn) {
		if (wpa_ctrl_attach(mon_conn) == 0) {
			wpa_cli_attached = 1;
			if (interactive)
				eloop_register_read_sock(
					wpa_ctrl_get_fd(mon_conn),
					wpa_cli_mon_receive, NULL, NULL);
		} else {
			printf("Warning: Failed to attach to "
			       "wpa_supplicant.\n");
			return -1;
		}
	}

	return 0;
}


static void wpa_cli_close_connection(void)
{
	if (ctrl_conn == NULL)
		return;

	if (wpa_cli_attached) {
		wpa_ctrl_detach(interactive ? mon_conn : ctrl_conn);
		wpa_cli_attached = 0;
	}
	wpa_ctrl_close(ctrl_conn);
	ctrl_conn = NULL;
	if (mon_conn) {
		eloop_unregister_read_sock(wpa_ctrl_get_fd(mon_conn));
		wpa_ctrl_close(mon_conn);
		mon_conn = NULL;
	}
}


static void wpa_cli_msg_cb(char *msg, size_t len)
{
	printf("%s\n", msg);
}


static int _wpa_ctrl_command(struct wpa_ctrl *ctrl, char *cmd, int print)
{
	char buf[2048];
	size_t len;
	int ret;

	if (ctrl_conn == NULL) {
		printf("Not connected to wpa_supplicant - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len,
			       wpa_cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}
	if (print) {
		buf[len] = '\0';
		printf("%s", buf);
		if (interactive && len > 0 && buf[len - 1] != '\n')
			printf("\n");
	}
	return 0;
}


static int wpa_ctrl_command(struct wpa_ctrl *ctrl, char *cmd)
{
	return _wpa_ctrl_command(ctrl, cmd, 1);
}


static int wpa_cli_cmd_status(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	int verbose = argc > 0 && os_strcmp(argv[0], "verbose") == 0;
	return wpa_ctrl_command(ctrl, verbose ? "STATUS-VERBOSE" : "STATUS");
}


static int wpa_cli_cmd_ping(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "PING");
}


static int wpa_cli_cmd_relog(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "RELOG");
}


static int wpa_cli_cmd_note(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int ret;
	if (argc == 0)
		return -1;
	ret = os_snprintf(cmd, sizeof(cmd), "NOTE %s", argv[0]);
	if (ret < 0 || (size_t) ret >= sizeof(cmd))
		return -1;
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_mib(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "MIB");
}


static int wpa_cli_cmd_pmksa(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "PMKSA");
}


static int wpa_cli_cmd_help(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	print_help();
	return 0;
}


static int wpa_cli_cmd_license(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	printf("%s\n\n%s\n", wpa_cli_version, wpa_cli_full_license);
	return 0;
}


static int wpa_cli_cmd_quit(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	wpa_cli_quit = 1;
	if (interactive)
		eloop_terminate();
	return 0;
}


static void wpa_cli_show_variables(void)
{
	printf("set variables:\n"
	       "  EAPOL::heldPeriod (EAPOL state machine held period, "
	       "in seconds)\n"
	       "  EAPOL::authPeriod (EAPOL state machine authentication "
	       "period, in seconds)\n"
	       "  EAPOL::startPeriod (EAPOL state machine start period, in "
	       "seconds)\n"
	       "  EAPOL::maxStart (EAPOL state machine maximum start "
	       "attempts)\n");
	printf("  dot11RSNAConfigPMKLifetime (WPA/WPA2 PMK lifetime in "
	       "seconds)\n"
	       "  dot11RSNAConfigPMKReauthThreshold (WPA/WPA2 reauthentication"
	       " threshold\n\tpercentage)\n"
	       "  dot11RSNAConfigSATimeout (WPA/WPA2 timeout for completing "
	       "security\n\tassociation in seconds)\n");
}


static int wpa_cli_cmd_set(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 0) {
		wpa_cli_show_variables();
		return 0;
	}

	if (argc != 2) {
		printf("Invalid SET command: needs two arguments (variable "
		       "name and value)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "SET %s %s", argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long SET command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_get(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid GET command: need one argument (variable "
		       "name)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "GET %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long GET command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_logoff(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "LOGOFF");
}


static int wpa_cli_cmd_logon(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "LOGON");
}


static int wpa_cli_cmd_reassociate(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return wpa_ctrl_command(ctrl, "REASSOCIATE");
}


static int wpa_cli_cmd_preauthenticate(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid PREAUTH command: needs one argument "
		       "(BSSID)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "PREAUTH %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long PREAUTH command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_ap_scan(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid AP_SCAN command: needs one argument (ap_scan "
		       "value)\n");
		return -1;
	}
	res = os_snprintf(cmd, sizeof(cmd), "AP_SCAN %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long AP_SCAN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_scan_interval(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid SCAN_INTERVAL command: needs one argument "
		       "scan_interval value)\n");
		return -1;
	}
	res = os_snprintf(cmd, sizeof(cmd), "SCAN_INTERVAL %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long SCAN_INTERVAL command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_bss_expire_age(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid BSS_EXPIRE_AGE command: needs one argument "
		       "(bss_expire_age value)\n");
		return -1;
	}
	res = os_snprintf(cmd, sizeof(cmd), "BSS_EXPIRE_AGE %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long BSS_EXPIRE_AGE command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_bss_expire_count(struct wpa_ctrl *ctrl, int argc,
				        char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid BSS_EXPIRE_COUNT command: needs one argument "
		       "(bss_expire_count value)\n");
		return -1;
	}
	res = os_snprintf(cmd, sizeof(cmd), "BSS_EXPIRE_COUNT %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long BSS_EXPIRE_COUNT command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_stkstart(struct wpa_ctrl *ctrl, int argc,
				char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid STKSTART command: needs one argument "
		       "(Peer STA MAC address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "STKSTART %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long STKSTART command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_ft_ds(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid FT_DS command: needs one argument "
		       "(Target AP MAC address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "FT_DS %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long FT_DS command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_pbc(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 0) {
		/* Any BSSID */
		return wpa_ctrl_command(ctrl, "WPS_PBC");
	}

	/* Specific BSSID */
	res = os_snprintf(cmd, sizeof(cmd), "WPS_PBC %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_PBC command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_pin(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 0) {
		printf("Invalid WPS_PIN command: need one or two arguments:\n"
		       "- BSSID: use 'any' to select any\n"
		       "- PIN: optional, used only with devices that have no "
		       "display\n");
		return -1;
	}

	if (argc == 1) {
		/* Use dynamically generated PIN (returned as reply) */
		res = os_snprintf(cmd, sizeof(cmd), "WPS_PIN %s", argv[0]);
		if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
			printf("Too long WPS_PIN command.\n");
			return -1;
		}
		return wpa_ctrl_command(ctrl, cmd);
	}

	/* Use hardcoded PIN from a label */
	res = os_snprintf(cmd, sizeof(cmd), "WPS_PIN %s %s", argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_PIN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_check_pin(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1 && argc != 2) {
		printf("Invalid WPS_CHECK_PIN command: needs one argument:\n"
		       "- PIN to be verified\n");
		return -1;
	}

	if (argc == 2)
		res = os_snprintf(cmd, sizeof(cmd), "WPS_CHECK_PIN %s %s",
				  argv[0], argv[1]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "WPS_CHECK_PIN %s",
				  argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_CHECK_PIN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_cancel(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	return wpa_ctrl_command(ctrl, "WPS_CANCEL");
}


#ifdef CONFIG_WPS_OOB
static int wpa_cli_cmd_wps_oob(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 3 && argc != 4) {
		printf("Invalid WPS_OOB command: need three or four "
		       "arguments:\n"
		       "- DEV_TYPE: use 'ufd' or 'nfc'\n"
		       "- PATH: path of OOB device like '/mnt'\n"
		       "- METHOD: OOB method 'pin-e' or 'pin-r', "
		       "'cred'\n"
		       "- DEV_NAME: (only for NFC) device name like "
		       "'pn531'\n");
		return -1;
	}

	if (argc == 3)
		res = os_snprintf(cmd, sizeof(cmd), "WPS_OOB %s %s %s",
				  argv[0], argv[1], argv[2]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "WPS_OOB %s %s %s %s",
				  argv[0], argv[1], argv[2], argv[3]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_OOB command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}
#endif /* CONFIG_WPS_OOB */


static int wpa_cli_cmd_wps_reg(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 2)
		res = os_snprintf(cmd, sizeof(cmd), "WPS_REG %s %s",
				  argv[0], argv[1]);
	else if (argc == 5 || argc == 6) {
		char ssid_hex[2 * 32 + 1];
		char key_hex[2 * 64 + 1];
		int i;

		ssid_hex[0] = '\0';
		for (i = 0; i < 32; i++) {
			if (argv[2][i] == '\0')
				break;
			os_snprintf(&ssid_hex[i * 2], 3, "%02x", argv[2][i]);
		}

		key_hex[0] = '\0';
		if (argc == 6) {
			for (i = 0; i < 64; i++) {
				if (argv[5][i] == '\0')
					break;
				os_snprintf(&key_hex[i * 2], 3, "%02x",
					    argv[5][i]);
			}
		}

		res = os_snprintf(cmd, sizeof(cmd),
				  "WPS_REG %s %s %s %s %s %s",
				  argv[0], argv[1], ssid_hex, argv[3], argv[4],
				  key_hex);
	} else {
		printf("Invalid WPS_REG command: need two arguments:\n"
		       "- BSSID of the target AP\n"
		       "- AP PIN\n");
		printf("Alternatively, six arguments can be used to "
		       "reconfigure the AP:\n"
		       "- BSSID of the target AP\n"
		       "- AP PIN\n"
		       "- new SSID\n"
		       "- new auth (OPEN, WPAPSK, WPA2PSK)\n"
		       "- new encr (NONE, WEP, TKIP, CCMP)\n"
		       "- new key\n");
		return -1;
	}

	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_REG command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_ap_pin(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	char cmd[256];
	int res;

	if (argc < 1) {
		printf("Invalid WPS_AP_PIN command: needs at least one "
		       "argument\n");
		return -1;
	}

	if (argc > 2)
		res = os_snprintf(cmd, sizeof(cmd), "WPS_AP_PIN %s %s %s",
				  argv[0], argv[1], argv[2]);
	else if (argc > 1)
		res = os_snprintf(cmd, sizeof(cmd), "WPS_AP_PIN %s %s",
				  argv[0], argv[1]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "WPS_AP_PIN %s",
				  argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_AP_PIN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_er_start(struct wpa_ctrl *ctrl, int argc,
				    char *argv[])
{
	char cmd[100];
	if (argc > 0) {
		os_snprintf(cmd, sizeof(cmd), "WPS_ER_START %s", argv[0]);
		return wpa_ctrl_command(ctrl, cmd);
	}
	return wpa_ctrl_command(ctrl, "WPS_ER_START");
}


static int wpa_cli_cmd_wps_er_stop(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return wpa_ctrl_command(ctrl, "WPS_ER_STOP");

}


static int wpa_cli_cmd_wps_er_pin(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	char cmd[256];
	int res;

	if (argc < 2) {
		printf("Invalid WPS_ER_PIN command: need at least two "
		       "arguments:\n"
		       "- UUID: use 'any' to select any\n"
		       "- PIN: Enrollee PIN\n"
		       "optional: - Enrollee MAC address\n");
		return -1;
	}

	if (argc > 2)
		res = os_snprintf(cmd, sizeof(cmd), "WPS_ER_PIN %s %s %s",
				  argv[0], argv[1], argv[2]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "WPS_ER_PIN %s %s",
				  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_ER_PIN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_er_pbc(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid WPS_ER_PBC command: need one argument:\n"
		       "- UUID: Specify the Enrollee\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "WPS_ER_PBC %s",
			  argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_ER_PBC command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_er_learn(struct wpa_ctrl *ctrl, int argc,
				    char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 2) {
		printf("Invalid WPS_ER_LEARN command: need two arguments:\n"
		       "- UUID: specify which AP to use\n"
		       "- PIN: AP PIN\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "WPS_ER_LEARN %s %s",
			  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_ER_LEARN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_er_set_config(struct wpa_ctrl *ctrl, int argc,
					 char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 2) {
		printf("Invalid WPS_ER_SET_CONFIG command: need two "
		       "arguments:\n"
		       "- UUID: specify which AP to use\n"
		       "- Network configuration id\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "WPS_ER_SET_CONFIG %s %s",
			  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_ER_SET_CONFIG command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_wps_er_config(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 5 || argc == 6) {
		char ssid_hex[2 * 32 + 1];
		char key_hex[2 * 64 + 1];
		int i;

		ssid_hex[0] = '\0';
		for (i = 0; i < 32; i++) {
			if (argv[2][i] == '\0')
				break;
			os_snprintf(&ssid_hex[i * 2], 3, "%02x", argv[2][i]);
		}

		key_hex[0] = '\0';
		if (argc == 6) {
			for (i = 0; i < 64; i++) {
				if (argv[5][i] == '\0')
					break;
				os_snprintf(&key_hex[i * 2], 3, "%02x",
					    argv[5][i]);
			}
		}

		res = os_snprintf(cmd, sizeof(cmd),
				  "WPS_ER_CONFIG %s %s %s %s %s %s",
				  argv[0], argv[1], ssid_hex, argv[3], argv[4],
				  key_hex);
	} else {
		printf("Invalid WPS_ER_CONFIG command: need six arguments:\n"
		       "- AP UUID\n"
		       "- AP PIN\n"
		       "- new SSID\n"
		       "- new auth (OPEN, WPAPSK, WPA2PSK)\n"
		       "- new encr (NONE, WEP, TKIP, CCMP)\n"
		       "- new key\n");
		return -1;
	}

	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long WPS_ER_CONFIG command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_ibss_rsn(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid IBSS_RSN command: needs one argument "
		       "(Peer STA MAC address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "IBSS_RSN %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long IBSS_RSN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_level(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid LEVEL command: needs one argument (debug "
		       "level)\n");
		return -1;
	}
	res = os_snprintf(cmd, sizeof(cmd), "LEVEL %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long LEVEL command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_identity(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256], *pos, *end;
	int i, ret;

	if (argc < 2) {
		printf("Invalid IDENTITY command: needs two arguments "
		       "(network id and identity)\n");
		return -1;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	ret = os_snprintf(pos, end - pos, WPA_CTRL_RSP "IDENTITY-%s:%s",
			  argv[0], argv[1]);
	if (ret < 0 || ret >= end - pos) {
		printf("Too long IDENTITY command.\n");
		return -1;
	}
	pos += ret;
	for (i = 2; i < argc; i++) {
		ret = os_snprintf(pos, end - pos, " %s", argv[i]);
		if (ret < 0 || ret >= end - pos) {
			printf("Too long IDENTITY command.\n");
			return -1;
		}
		pos += ret;
	}

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_password(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256], *pos, *end;
	int i, ret;

	if (argc < 2) {
		printf("Invalid PASSWORD command: needs two arguments "
		       "(network id and password)\n");
		return -1;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	ret = os_snprintf(pos, end - pos, WPA_CTRL_RSP "PASSWORD-%s:%s",
			  argv[0], argv[1]);
	if (ret < 0 || ret >= end - pos) {
		printf("Too long PASSWORD command.\n");
		return -1;
	}
	pos += ret;
	for (i = 2; i < argc; i++) {
		ret = os_snprintf(pos, end - pos, " %s", argv[i]);
		if (ret < 0 || ret >= end - pos) {
			printf("Too long PASSWORD command.\n");
			return -1;
		}
		pos += ret;
	}

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_new_password(struct wpa_ctrl *ctrl, int argc,
				    char *argv[])
{
	char cmd[256], *pos, *end;
	int i, ret;

	if (argc < 2) {
		printf("Invalid NEW_PASSWORD command: needs two arguments "
		       "(network id and password)\n");
		return -1;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	ret = os_snprintf(pos, end - pos, WPA_CTRL_RSP "NEW_PASSWORD-%s:%s",
			  argv[0], argv[1]);
	if (ret < 0 || ret >= end - pos) {
		printf("Too long NEW_PASSWORD command.\n");
		return -1;
	}
	pos += ret;
	for (i = 2; i < argc; i++) {
		ret = os_snprintf(pos, end - pos, " %s", argv[i]);
		if (ret < 0 || ret >= end - pos) {
			printf("Too long NEW_PASSWORD command.\n");
			return -1;
		}
		pos += ret;
	}

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_pin(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256], *pos, *end;
	int i, ret;

	if (argc < 2) {
		printf("Invalid PIN command: needs two arguments "
		       "(network id and pin)\n");
		return -1;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	ret = os_snprintf(pos, end - pos, WPA_CTRL_RSP "PIN-%s:%s",
			  argv[0], argv[1]);
	if (ret < 0 || ret >= end - pos) {
		printf("Too long PIN command.\n");
		return -1;
	}
	pos += ret;
	for (i = 2; i < argc; i++) {
		ret = os_snprintf(pos, end - pos, " %s", argv[i]);
		if (ret < 0 || ret >= end - pos) {
			printf("Too long PIN command.\n");
			return -1;
		}
		pos += ret;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_otp(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256], *pos, *end;
	int i, ret;

	if (argc < 2) {
		printf("Invalid OTP command: needs two arguments (network "
		       "id and password)\n");
		return -1;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	ret = os_snprintf(pos, end - pos, WPA_CTRL_RSP "OTP-%s:%s",
			  argv[0], argv[1]);
	if (ret < 0 || ret >= end - pos) {
		printf("Too long OTP command.\n");
		return -1;
	}
	pos += ret;
	for (i = 2; i < argc; i++) {
		ret = os_snprintf(pos, end - pos, " %s", argv[i]);
		if (ret < 0 || ret >= end - pos) {
			printf("Too long OTP command.\n");
			return -1;
		}
		pos += ret;
	}

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_passphrase(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	char cmd[256], *pos, *end;
	int i, ret;

	if (argc < 2) {
		printf("Invalid PASSPHRASE command: needs two arguments "
		       "(network id and passphrase)\n");
		return -1;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	ret = os_snprintf(pos, end - pos, WPA_CTRL_RSP "PASSPHRASE-%s:%s",
			  argv[0], argv[1]);
	if (ret < 0 || ret >= end - pos) {
		printf("Too long PASSPHRASE command.\n");
		return -1;
	}
	pos += ret;
	for (i = 2; i < argc; i++) {
		ret = os_snprintf(pos, end - pos, " %s", argv[i]);
		if (ret < 0 || ret >= end - pos) {
			printf("Too long PASSPHRASE command.\n");
			return -1;
		}
		pos += ret;
	}

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_bssid(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256], *pos, *end;
	int i, ret;

	if (argc < 2) {
		printf("Invalid BSSID command: needs two arguments (network "
		       "id and BSSID)\n");
		return -1;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	ret = os_snprintf(pos, end - pos, "BSSID");
	if (ret < 0 || ret >= end - pos) {
		printf("Too long BSSID command.\n");
		return -1;
	}
	pos += ret;
	for (i = 0; i < argc; i++) {
		ret = os_snprintf(pos, end - pos, " %s", argv[i]);
		if (ret < 0 || ret >= end - pos) {
			printf("Too long BSSID command.\n");
			return -1;
		}
		pos += ret;
	}

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_list_networks(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	return wpa_ctrl_command(ctrl, "LIST_NETWORKS");
}


static int wpa_cli_cmd_select_network(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char cmd[32];
	int res;

	if (argc < 1) {
		printf("Invalid SELECT_NETWORK command: needs one argument "
		       "(network id)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "SELECT_NETWORK %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_enable_network(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char cmd[32];
	int res;

	if (argc < 1) {
		printf("Invalid ENABLE_NETWORK command: needs one argument "
		       "(network id)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "ENABLE_NETWORK %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_disable_network(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	char cmd[32];
	int res;

	if (argc < 1) {
		printf("Invalid DISABLE_NETWORK command: needs one argument "
		       "(network id)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "DISABLE_NETWORK %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_add_network(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return wpa_ctrl_command(ctrl, "ADD_NETWORK");
}


static int wpa_cli_cmd_remove_network(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char cmd[32];
	int res;

	if (argc < 1) {
		printf("Invalid REMOVE_NETWORK command: needs one argument "
		       "(network id)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "REMOVE_NETWORK %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';

	return wpa_ctrl_command(ctrl, cmd);
}


static void wpa_cli_show_network_variables(void)
{
	printf("set_network variables:\n"
	       "  ssid (network name, SSID)\n"
	       "  psk (WPA passphrase or pre-shared key)\n"
	       "  key_mgmt (key management protocol)\n"
	       "  identity (EAP identity)\n"
	       "  password (EAP password)\n"
	       "  ...\n"
	       "\n"
	       "Note: Values are entered in the same format as the "
	       "configuration file is using,\n"
	       "i.e., strings values need to be inside double quotation "
	       "marks.\n"
	       "For example: set_network 1 ssid \"network name\"\n"
	       "\n"
	       "Please see wpa_supplicant.conf documentation for full list "
	       "of\navailable variables.\n");
}


static int wpa_cli_cmd_set_network(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 0) {
		wpa_cli_show_network_variables();
		return 0;
	}

	if (argc != 3) {
		printf("Invalid SET_NETWORK command: needs three arguments\n"
		       "(network id, variable name, and value)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "SET_NETWORK %s %s %s",
			  argv[0], argv[1], argv[2]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long SET_NETWORK command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_get_network(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 0) {
		wpa_cli_show_network_variables();
		return 0;
	}

	if (argc != 2) {
		printf("Invalid GET_NETWORK command: needs two arguments\n"
		       "(network id and variable name)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "GET_NETWORK %s %s",
			  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long GET_NETWORK command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_disconnect(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	return wpa_ctrl_command(ctrl, "DISCONNECT");
}


static int wpa_cli_cmd_reconnect(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	return wpa_ctrl_command(ctrl, "RECONNECT");
}


static int wpa_cli_cmd_save_config(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return wpa_ctrl_command(ctrl, "SAVE_CONFIG");
}


static int wpa_cli_cmd_scan(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "SCAN");
}


static int wpa_cli_cmd_scan_results(struct wpa_ctrl *ctrl, int argc,
				    char *argv[])
{
	return wpa_ctrl_command(ctrl, "SCAN_RESULTS");
}


static int wpa_cli_cmd_bss(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[64];
	int res;

	if (argc != 1) {
		printf("Invalid BSS command: need one argument (index or "
		       "BSSID)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "BSS %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_get_capability(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char cmd[64];
	int res;

	if (argc < 1 || argc > 2) {
		printf("Invalid GET_CAPABILITY command: need either one or "
		       "two arguments\n");
		return -1;
	}

	if ((argc == 2) && os_strcmp(argv[1], "strict") != 0) {
		printf("Invalid GET_CAPABILITY command: second argument, "
		       "if any, must be 'strict'\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "GET_CAPABILITY %s%s", argv[0],
			  (argc == 2) ? " strict" : "");
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_list_interfaces(struct wpa_ctrl *ctrl)
{
	printf("Available interfaces:\n");
	return wpa_ctrl_command(ctrl, "INTERFACES");
}


static int wpa_cli_cmd_interface(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	if (argc < 1) {
		wpa_cli_list_interfaces(ctrl);
		return 0;
	}

	wpa_cli_close_connection();
	os_free(ctrl_ifname);
	ctrl_ifname = os_strdup(argv[0]);

	if (wpa_cli_open_connection(ctrl_ifname, 1)) {
		printf("Connected to interface '%s.\n", ctrl_ifname);
	} else {
		printf("Could not connect to interface '%s' - re-trying\n",
		       ctrl_ifname);
	}
	return 0;
}


static int wpa_cli_cmd_reconfigure(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return wpa_ctrl_command(ctrl, "RECONFIGURE");
}


static int wpa_cli_cmd_terminate(struct wpa_ctrl *ctrl, int argc,
				 char *argv[])
{
	return wpa_ctrl_command(ctrl, "TERMINATE");
}


static int wpa_cli_cmd_interface_add(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[256];
	int res;

	if (argc < 1) {
		printf("Invalid INTERFACE_ADD command: needs at least one "
		       "argument (interface name)\n"
		       "All arguments: ifname confname driver ctrl_interface "
		       "driver_param bridge_name\n");
		return -1;
	}

	/*
	 * INTERFACE_ADD <ifname>TAB<confname>TAB<driver>TAB<ctrl_interface>TAB
	 * <driver_param>TAB<bridge_name>
	 */
	res = os_snprintf(cmd, sizeof(cmd),
			  "INTERFACE_ADD %s\t%s\t%s\t%s\t%s\t%s",
			  argv[0],
			  argc > 1 ? argv[1] : "", argc > 2 ? argv[2] : "",
			  argc > 3 ? argv[3] : "", argc > 4 ? argv[4] : "",
			  argc > 5 ? argv[5] : "");
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_interface_remove(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	char cmd[128];
	int res;

	if (argc != 1) {
		printf("Invalid INTERFACE_REMOVE command: needs one argument "
		       "(interface name)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "INTERFACE_REMOVE %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_interface_list(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	return wpa_ctrl_command(ctrl, "INTERFACE_LIST");
}


#ifdef CONFIG_AP
static int wpa_cli_cmd_sta(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char buf[64];
	if (argc != 1) {
		printf("Invalid 'sta' command - exactly one argument, STA "
		       "address, is required.\n");
		return -1;
	}
	os_snprintf(buf, sizeof(buf), "STA %s", argv[0]);
	return wpa_ctrl_command(ctrl, buf);
}


static int wpa_ctrl_command_sta(struct wpa_ctrl *ctrl, char *cmd,
				char *addr, size_t addr_len)
{
	char buf[4096], *pos;
	size_t len;
	int ret;

	if (ctrl_conn == NULL) {
		printf("Not connected to hostapd - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len,
			       wpa_cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}

	buf[len] = '\0';
	if (memcmp(buf, "FAIL", 4) == 0)
		return -1;
	printf("%s", buf);

	pos = buf;
	while (*pos != '\0' && *pos != '\n')
		pos++;
	*pos = '\0';
	os_strlcpy(addr, buf, addr_len);
	return 0;
}


static int wpa_cli_cmd_all_sta(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char addr[32], cmd[64];

	if (wpa_ctrl_command_sta(ctrl, "STA-FIRST", addr, sizeof(addr)))
		return 0;
	do {
		os_snprintf(cmd, sizeof(cmd), "STA-NEXT %s", addr);
	} while (wpa_ctrl_command_sta(ctrl, cmd, addr, sizeof(addr)) == 0);

	return -1;
}
#endif /* CONFIG_AP */


static int wpa_cli_cmd_suspend(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "SUSPEND");
}


static int wpa_cli_cmd_resume(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "RESUME");
}


static int wpa_cli_cmd_drop_sa(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "DROP_SA");
}


static int wpa_cli_cmd_roam(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[128];
	int res;

	if (argc != 1) {
		printf("Invalid ROAM command: needs one argument "
		       "(target AP's BSSID)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "ROAM %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long ROAM command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


#ifdef CONFIG_P2P

static int wpa_cli_cmd_p2p_find(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[128];
	int res;

	if (argc == 0)
		return wpa_ctrl_command(ctrl, "P2P_FIND");

	if (argc > 1)
		res = os_snprintf(cmd, sizeof(cmd), "P2P_FIND %s %s",
				  argv[0], argv[1]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "P2P_FIND %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_stop_find(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	return wpa_ctrl_command(ctrl, "P2P_STOP_FIND");
}


static int wpa_cli_cmd_p2p_connect(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	char cmd[128];
	int res;

	if (argc < 2) {
		printf("Invalid P2P_CONNECT command: needs at least two "
		       "arguments (address and pbc/PIN)\n");
		return -1;
	}

	if (argc > 4)
		res = os_snprintf(cmd, sizeof(cmd),
				  "P2P_CONNECT %s %s %s %s %s",
				  argv[0], argv[1], argv[2], argv[3],
				  argv[4]);
	else if (argc > 3)
		res = os_snprintf(cmd, sizeof(cmd), "P2P_CONNECT %s %s %s %s",
				  argv[0], argv[1], argv[2], argv[3]);
	else if (argc > 2)
		res = os_snprintf(cmd, sizeof(cmd), "P2P_CONNECT %s %s %s",
				  argv[0], argv[1], argv[2]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "P2P_CONNECT %s %s",
				  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_listen(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	char cmd[128];
	int res;

	if (argc == 0)
		return wpa_ctrl_command(ctrl, "P2P_LISTEN");

	res = os_snprintf(cmd, sizeof(cmd), "P2P_LISTEN %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_group_remove(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	char cmd[128];
	int res;

	if (argc != 1) {
		printf("Invalid P2P_GROUP_REMOVE command: needs one argument "
		       "(interface name)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_GROUP_REMOVE %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_group_add(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	char cmd[128];
	int res;

	if (argc == 0)
		return wpa_ctrl_command(ctrl, "P2P_GROUP_ADD");

	res = os_snprintf(cmd, sizeof(cmd), "P2P_GROUP_ADD %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_prov_disc(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[128];
	int res;

	if (argc != 2) {
		printf("Invalid P2P_PROV_DISC command: needs two arguments "
		       "(address and config method\n"
		       "(display, keypad, or pbc)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_PROV_DISC %s %s",
			  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_get_passphrase(struct wpa_ctrl *ctrl, int argc,
					  char *argv[])
{
	return wpa_ctrl_command(ctrl, "P2P_GET_PASSPHRASE");
}


static int wpa_cli_cmd_p2p_serv_disc_req(struct wpa_ctrl *ctrl, int argc,
					 char *argv[])
{
	char cmd[4096];
	int res;

	if (argc != 2 && argc != 4) {
		printf("Invalid P2P_SERV_DISC_REQ command: needs two "
		       "arguments (address and TLVs) or four arguments "
		       "(address, \"upnp\", version, search target "
		       "(SSDP ST:)\n");
		return -1;
	}

	if (argc == 4)
		res = os_snprintf(cmd, sizeof(cmd),
				  "P2P_SERV_DISC_REQ %s %s %s %s",
				  argv[0], argv[1], argv[2], argv[3]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "P2P_SERV_DISC_REQ %s %s",
				  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_serv_disc_cancel_req(struct wpa_ctrl *ctrl,
						int argc, char *argv[])
{
	char cmd[128];
	int res;

	if (argc != 1) {
		printf("Invalid P2P_SERV_DISC_CANCEL_REQ command: needs one "
		       "argument (pending request identifier)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_SERV_DISC_CANCEL_REQ %s",
			  argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_serv_disc_resp(struct wpa_ctrl *ctrl, int argc,
					  char *argv[])
{
	char cmd[4096];
	int res;

	if (argc != 4) {
		printf("Invalid P2P_SERV_DISC_RESP command: needs four "
		       "arguments (freq, address, dialog token, and TLVs)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_SERV_DISC_RESP %s %s %s %s",
			  argv[0], argv[1], argv[2], argv[3]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_service_update(struct wpa_ctrl *ctrl, int argc,
					  char *argv[])
{
	return wpa_ctrl_command(ctrl, "P2P_SERVICE_UPDATE");
}


static int wpa_cli_cmd_p2p_serv_disc_external(struct wpa_ctrl *ctrl,
					      int argc, char *argv[])
{
	char cmd[128];
	int res;

	if (argc != 1) {
		printf("Invalid P2P_SERV_DISC_EXTERNAL command: needs one "
		       "argument (external processing: 0/1)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_SERV_DISC_EXTERNAL %s",
			  argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_service_flush(struct wpa_ctrl *ctrl, int argc,
					 char *argv[])
{
	return wpa_ctrl_command(ctrl, "P2P_SERVICE_FLUSH");
}


static int wpa_cli_cmd_p2p_service_add(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	char cmd[4096];
	int res;

	if (argc != 3 && argc != 4) {
		printf("Invalid P2P_SERVICE_ADD command: needs three or four "
		       "arguments\n");
		return -1;
	}

	if (argc == 4)
		res = os_snprintf(cmd, sizeof(cmd),
				  "P2P_SERVICE_ADD %s %s %s %s",
				  argv[0], argv[1], argv[2], argv[3]);
	else
		res = os_snprintf(cmd, sizeof(cmd),
				  "P2P_SERVICE_ADD %s %s %s",
				  argv[0], argv[1], argv[2]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_service_del(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	char cmd[4096];
	int res;

	if (argc != 2 && argc != 3) {
		printf("Invalid P2P_SERVICE_DEL command: needs two or three "
		       "arguments\n");
		return -1;
	}

	if (argc == 3)
		res = os_snprintf(cmd, sizeof(cmd),
				  "P2P_SERVICE_DEL %s %s %s",
				  argv[0], argv[1], argv[2]);
	else
		res = os_snprintf(cmd, sizeof(cmd),
				  "P2P_SERVICE_DEL %s %s",
				  argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_reject(struct wpa_ctrl *ctrl,
				  int argc, char *argv[])
{
	char cmd[128];
	int res;

	if (argc != 1) {
		printf("Invalid P2P_REJECT command: needs one argument "
		       "(peer address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_REJECT %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_invite(struct wpa_ctrl *ctrl,
				  int argc, char *argv[])
{
	char cmd[128];
	int res;

	if (argc < 1) {
		printf("Invalid P2P_INVITE command: needs at least one "
		       "argument\n");
		return -1;
	}

	if (argc > 2)
		res = os_snprintf(cmd, sizeof(cmd), "P2P_INVITE %s %s %s",
				  argv[0], argv[1], argv[2]);
	else if (argc > 1)
		res = os_snprintf(cmd, sizeof(cmd), "P2P_INVITE %s %s",
				  argv[0], argv[1]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "P2P_INVITE %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_peer(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char buf[64];
	if (argc != 1) {
		printf("Invalid 'p2p_peer' command - exactly one argument, "
		       "P2P peer device address, is required.\n");
		return -1;
	}
	os_snprintf(buf, sizeof(buf), "P2P_PEER %s", argv[0]);
	return wpa_ctrl_command(ctrl, buf);
}


static int wpa_ctrl_command_p2p_peer(struct wpa_ctrl *ctrl, char *cmd,
				     char *addr, size_t addr_len,
				     int discovered)
{
	char buf[4096], *pos;
	size_t len;
	int ret;

	if (ctrl_conn == NULL)
		return -1;
	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len,
			       wpa_cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}

	buf[len] = '\0';
	if (memcmp(buf, "FAIL", 4) == 0)
		return -1;

	pos = buf;
	while (*pos != '\0' && *pos != '\n')
		pos++;
	*pos++ = '\0';
	os_strlcpy(addr, buf, addr_len);
	if (!discovered || os_strstr(pos, "[PROBE_REQ_ONLY]") == NULL)
		printf("%s\n", addr);
	return 0;
}


static int wpa_cli_cmd_p2p_peers(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char addr[32], cmd[64];
	int discovered;

	discovered = argc > 0 && os_strcmp(argv[0], "discovered") == 0;

	if (wpa_ctrl_command_p2p_peer(ctrl, "P2P_PEER FIRST",
				      addr, sizeof(addr), discovered))
		return 0;
	do {
		os_snprintf(cmd, sizeof(cmd), "P2P_PEER NEXT-%s", addr);
	} while (wpa_ctrl_command_p2p_peer(ctrl, cmd, addr, sizeof(addr),
			 discovered) == 0);

	return -1;
}


static int wpa_cli_cmd_p2p_set(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[100];
	int res;

	if (argc != 2) {
		printf("Invalid P2P_SET command: needs two arguments (field, "
		       "value)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_SET %s %s", argv[0], argv[1]);
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_flush(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "P2P_FLUSH");
}


static int wpa_cli_cmd_p2p_cancel(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	return wpa_ctrl_command(ctrl, "P2P_CANCEL");
}


static int wpa_cli_cmd_p2p_unauthorize(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	char cmd[100];
	int res;

	if (argc != 1) {
		printf("Invalid P2P_UNAUTHORIZE command: needs one argument "
		       "(peer address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "P2P_UNAUTHORIZE %s", argv[0]);

	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;

	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_presence_req(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	char cmd[100];
	int res;

	if (argc != 0 && argc != 2 && argc != 4) {
		printf("Invalid P2P_PRESENCE_REQ command: needs two arguments "
		       "(preferred duration, interval; in microsecods).\n"
		       "Optional second pair can be used to provide "
		       "acceptable values.\n");
		return -1;
	}

	if (argc == 4)
		res = os_snprintf(cmd, sizeof(cmd),
				  "P2P_PRESENCE_REQ %s %s %s %s",
				  argv[0], argv[1], argv[2], argv[3]);
	else if (argc == 2)
		res = os_snprintf(cmd, sizeof(cmd), "P2P_PRESENCE_REQ %s %s",
				  argv[0], argv[1]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "P2P_PRESENCE_REQ");
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_p2p_ext_listen(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char cmd[100];
	int res;

	if (argc != 0 && argc != 2) {
		printf("Invalid P2P_EXT_LISTEN command: needs two arguments "
		       "(availability period, availability interval; in "
		       "millisecods).\n"
		       "Extended Listen Timing can be cancelled with this "
		       "command when used without parameters.\n");
		return -1;
	}

	if (argc == 2)
		res = os_snprintf(cmd, sizeof(cmd), "P2P_EXT_LISTEN %s %s",
				  argv[0], argv[1]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "P2P_EXT_LISTEN");
	if (res < 0 || (size_t) res >= sizeof(cmd))
		return -1;
	cmd[sizeof(cmd) - 1] = '\0';
	return wpa_ctrl_command(ctrl, cmd);
}

#endif /* CONFIG_P2P */


static int wpa_cli_cmd_sta_autoconnect(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid STA_AUTOCONNECT command: needs one argument "
		       "(0/1 = disable/enable automatic reconnection)\n");
		return -1;
	}
	res = os_snprintf(cmd, sizeof(cmd), "STA_AUTOCONNECT %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long STA_AUTOCONNECT command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_tdls_discover(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid TDLS_DISCOVER command: needs one argument "
		       "(Peer STA MAC address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "TDLS_DISCOVER %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long TDLS_DISCOVER command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_tdls_setup(struct wpa_ctrl *ctrl, int argc,
				  char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid TDLS_SETUP command: needs one argument "
		       "(Peer STA MAC address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "TDLS_SETUP %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long TDLS_SETUP command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_tdls_teardown(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid TDLS_TEARDOWN command: needs one argument "
		       "(Peer STA MAC address)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "TDLS_TEARDOWN %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long TDLS_TEARDOWN command.\n");
		return -1;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_signal_poll(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return wpa_ctrl_command(ctrl, "SIGNAL_POLL");
}


enum wpa_cli_cmd_flags {
	cli_cmd_flag_none		= 0x00,
	cli_cmd_flag_sensitive		= 0x01
};

struct wpa_cli_cmd {
	const char *cmd;
	int (*handler)(struct wpa_ctrl *ctrl, int argc, char *argv[]);
	enum wpa_cli_cmd_flags flags;
	const char *usage;
};

static struct wpa_cli_cmd wpa_cli_commands[] = {
	{ "status", wpa_cli_cmd_status,
	  cli_cmd_flag_none,
	  "[verbose] = get current WPA/EAPOL/EAP status" },
	{ "ping", wpa_cli_cmd_ping,
	  cli_cmd_flag_none,
	  "= pings wpa_supplicant" },
	{ "relog", wpa_cli_cmd_relog,
	  cli_cmd_flag_none,
	  "= re-open log-file (allow rolling logs)" },
	{ "note", wpa_cli_cmd_note,
	  cli_cmd_flag_none,
	  "<text> = add a note to wpa_supplicant debug log" },
	{ "mib", wpa_cli_cmd_mib,
	  cli_cmd_flag_none,
	  "= get MIB variables (dot1x, dot11)" },
	{ "help", wpa_cli_cmd_help,
	  cli_cmd_flag_none,
	  "= show this usage help" },
	{ "interface", wpa_cli_cmd_interface,
	  cli_cmd_flag_none,
	  "[ifname] = show interfaces/select interface" },
	{ "level", wpa_cli_cmd_level,
	  cli_cmd_flag_none,
	  "<debug level> = change debug level" },
	{ "license", wpa_cli_cmd_license,
	  cli_cmd_flag_none,
	  "= show full wpa_cli license" },
	{ "quit", wpa_cli_cmd_quit,
	  cli_cmd_flag_none,
	  "= exit wpa_cli" },
	{ "set", wpa_cli_cmd_set,
	  cli_cmd_flag_none,
	  "= set variables (shows list of variables when run without "
	  "arguments)" },
	{ "get", wpa_cli_cmd_get,
	  cli_cmd_flag_none,
	  "<name> = get information" },
	{ "logon", wpa_cli_cmd_logon,
	  cli_cmd_flag_none,
	  "= IEEE 802.1X EAPOL state machine logon" },
	{ "logoff", wpa_cli_cmd_logoff,
	  cli_cmd_flag_none,
	  "= IEEE 802.1X EAPOL state machine logoff" },
	{ "pmksa", wpa_cli_cmd_pmksa,
	  cli_cmd_flag_none,
	  "= show PMKSA cache" },
	{ "reassociate", wpa_cli_cmd_reassociate,
	  cli_cmd_flag_none,
	  "= force reassociation" },
	{ "preauthenticate", wpa_cli_cmd_preauthenticate,
	  cli_cmd_flag_none,
	  "<BSSID> = force preauthentication" },
	{ "identity", wpa_cli_cmd_identity,
	  cli_cmd_flag_none,
	  "<network id> <identity> = configure identity for an SSID" },
	{ "password", wpa_cli_cmd_password,
	  cli_cmd_flag_sensitive,
	  "<network id> <password> = configure password for an SSID" },
	{ "new_password", wpa_cli_cmd_new_password,
	  cli_cmd_flag_sensitive,
	  "<network id> <password> = change password for an SSID" },
	{ "pin", wpa_cli_cmd_pin,
	  cli_cmd_flag_sensitive,
	  "<network id> <pin> = configure pin for an SSID" },
	{ "otp", wpa_cli_cmd_otp,
	  cli_cmd_flag_sensitive,
	  "<network id> <password> = configure one-time-password for an SSID"
	},
	{ "passphrase", wpa_cli_cmd_passphrase,
	  cli_cmd_flag_sensitive,
	  "<network id> <passphrase> = configure private key passphrase\n"
	  "  for an SSID" },
	{ "bssid", wpa_cli_cmd_bssid,
	  cli_cmd_flag_none,
	  "<network id> <BSSID> = set preferred BSSID for an SSID" },
	{ "list_networks", wpa_cli_cmd_list_networks,
	  cli_cmd_flag_none,
	  "= list configured networks" },
	{ "select_network", wpa_cli_cmd_select_network,
	  cli_cmd_flag_none,
	  "<network id> = select a network (disable others)" },
	{ "enable_network", wpa_cli_cmd_enable_network,
	  cli_cmd_flag_none,
	  "<network id> = enable a network" },
	{ "disable_network", wpa_cli_cmd_disable_network,
	  cli_cmd_flag_none,
	  "<network id> = disable a network" },
	{ "add_network", wpa_cli_cmd_add_network,
	  cli_cmd_flag_none,
	  "= add a network" },
	{ "remove_network", wpa_cli_cmd_remove_network,
	  cli_cmd_flag_none,
	  "<network id> = remove a network" },
	{ "set_network", wpa_cli_cmd_set_network,
	  cli_cmd_flag_sensitive,
	  "<network id> <variable> <value> = set network variables (shows\n"
	  "  list of variables when run without arguments)" },
	{ "get_network", wpa_cli_cmd_get_network,
	  cli_cmd_flag_none,
	  "<network id> <variable> = get network variables" },
	{ "save_config", wpa_cli_cmd_save_config,
	  cli_cmd_flag_none,
	  "= save the current configuration" },
	{ "disconnect", wpa_cli_cmd_disconnect,
	  cli_cmd_flag_none,
	  "= disconnect and wait for reassociate/reconnect command before\n"
	  "  connecting" },
	{ "reconnect", wpa_cli_cmd_reconnect,
	  cli_cmd_flag_none,
	  "= like reassociate, but only takes effect if already disconnected"
	},
	{ "scan", wpa_cli_cmd_scan,
	  cli_cmd_flag_none,
	  "= request new BSS scan" },
	{ "scan_results", wpa_cli_cmd_scan_results,
	  cli_cmd_flag_none,
	  "= get latest scan results" },
	{ "bss", wpa_cli_cmd_bss,
	  cli_cmd_flag_none,
	  "<<idx> | <bssid>> = get detailed scan result info" },
	{ "get_capability", wpa_cli_cmd_get_capability,
	  cli_cmd_flag_none,
	  "<eap/pairwise/group/key_mgmt/proto/auth_alg> = get capabilies" },
	{ "reconfigure", wpa_cli_cmd_reconfigure,
	  cli_cmd_flag_none,
	  "= force wpa_supplicant to re-read its configuration file" },
	{ "terminate", wpa_cli_cmd_terminate,
	  cli_cmd_flag_none,
	  "= terminate wpa_supplicant" },
	{ "interface_add", wpa_cli_cmd_interface_add,
	  cli_cmd_flag_none,
	  "<ifname> <confname> <driver> <ctrl_interface> <driver_param>\n"
	  "  <bridge_name> = adds new interface, all parameters but <ifname>\n"
	  "  are optional" },
	{ "interface_remove", wpa_cli_cmd_interface_remove,
	  cli_cmd_flag_none,
	  "<ifname> = removes the interface" },
	{ "interface_list", wpa_cli_cmd_interface_list,
	  cli_cmd_flag_none,
	  "= list available interfaces" },
	{ "ap_scan", wpa_cli_cmd_ap_scan,
	  cli_cmd_flag_none,
	  "<value> = set ap_scan parameter" },
	{ "scan_interval", wpa_cli_cmd_scan_interval,
	  cli_cmd_flag_none,
	  "<value> = set scan_interval parameter (in seconds)" },
	{ "bss_expire_age", wpa_cli_cmd_bss_expire_age,
	  cli_cmd_flag_none,
	  "<value> = set BSS expiration age parameter" },
	{ "bss_expire_count", wpa_cli_cmd_bss_expire_count,
	  cli_cmd_flag_none,
	  "<value> = set BSS expiration scan count parameter" },
	{ "stkstart", wpa_cli_cmd_stkstart,
	  cli_cmd_flag_none,
	  "<addr> = request STK negotiation with <addr>" },
	{ "ft_ds", wpa_cli_cmd_ft_ds,
	  cli_cmd_flag_none,
	  "<addr> = request over-the-DS FT with <addr>" },
	{ "wps_pbc", wpa_cli_cmd_wps_pbc,
	  cli_cmd_flag_none,
	  "[BSSID] = start Wi-Fi Protected Setup: Push Button Configuration" },
	{ "wps_pin", wpa_cli_cmd_wps_pin,
	  cli_cmd_flag_sensitive,
	  "<BSSID> [PIN] = start WPS PIN method (returns PIN, if not "
	  "hardcoded)" },
	{ "wps_check_pin", wpa_cli_cmd_wps_check_pin,
	  cli_cmd_flag_sensitive,
	  "<PIN> = verify PIN checksum" },
	{ "wps_cancel", wpa_cli_cmd_wps_cancel, cli_cmd_flag_none,
	  "Cancels the pending WPS operation" },
#ifdef CONFIG_WPS_OOB
	{ "wps_oob", wpa_cli_cmd_wps_oob,
	  cli_cmd_flag_sensitive,
	  "<DEV_TYPE> <PATH> <METHOD> [DEV_NAME] = start WPS OOB" },
#endif /* CONFIG_WPS_OOB */
	{ "wps_reg", wpa_cli_cmd_wps_reg,
	  cli_cmd_flag_sensitive,
	  "<BSSID> <AP PIN> = start WPS Registrar to configure an AP" },
	{ "wps_ap_pin", wpa_cli_cmd_wps_ap_pin,
	  cli_cmd_flag_sensitive,
	  "[params..] = enable/disable AP PIN" },
	{ "wps_er_start", wpa_cli_cmd_wps_er_start,
	  cli_cmd_flag_none,
	  "[IP address] = start Wi-Fi Protected Setup External Registrar" },
	{ "wps_er_stop", wpa_cli_cmd_wps_er_stop,
	  cli_cmd_flag_none,
	  "= stop Wi-Fi Protected Setup External Registrar" },
	{ "wps_er_pin", wpa_cli_cmd_wps_er_pin,
	  cli_cmd_flag_sensitive,
	  "<UUID> <PIN> = add an Enrollee PIN to External Registrar" },
	{ "wps_er_pbc", wpa_cli_cmd_wps_er_pbc,
	  cli_cmd_flag_none,
	  "<UUID> = accept an Enrollee PBC using External Registrar" },
	{ "wps_er_learn", wpa_cli_cmd_wps_er_learn,
	  cli_cmd_flag_sensitive,
	  "<UUID> <PIN> = learn AP configuration" },
	{ "wps_er_set_config", wpa_cli_cmd_wps_er_set_config,
	  cli_cmd_flag_none,
	  "<UUID> <network id> = set AP configuration for enrolling" },
	{ "wps_er_config", wpa_cli_cmd_wps_er_config,
	  cli_cmd_flag_sensitive,
	  "<UUID> <PIN> <SSID> <auth> <encr> <key> = configure AP" },
	{ "ibss_rsn", wpa_cli_cmd_ibss_rsn,
	  cli_cmd_flag_none,
	  "<addr> = request RSN authentication with <addr> in IBSS" },
#ifdef CONFIG_AP
	{ "sta", wpa_cli_cmd_sta,
	  cli_cmd_flag_none,
	  "<addr> = get information about an associated station (AP)" },
	{ "all_sta", wpa_cli_cmd_all_sta,
	  cli_cmd_flag_none,
	  "= get information about all associated stations (AP)" },
#endif /* CONFIG_AP */
	{ "suspend", wpa_cli_cmd_suspend, cli_cmd_flag_none,
	  "= notification of suspend/hibernate" },
	{ "resume", wpa_cli_cmd_resume, cli_cmd_flag_none,
	  "= notification of resume/thaw" },
	{ "drop_sa", wpa_cli_cmd_drop_sa, cli_cmd_flag_none,
	  "= drop SA without deauth/disassoc (test command)" },
	{ "roam", wpa_cli_cmd_roam,
	  cli_cmd_flag_none,
	  "<addr> = roam to the specified BSS" },
#ifdef CONFIG_P2P
	{ "p2p_find", wpa_cli_cmd_p2p_find, cli_cmd_flag_none,
	  "[timeout] [type=*] = find P2P Devices for up-to timeout seconds" },
	{ "p2p_stop_find", wpa_cli_cmd_p2p_stop_find, cli_cmd_flag_none,
	  "= stop P2P Devices search" },
	{ "p2p_connect", wpa_cli_cmd_p2p_connect, cli_cmd_flag_none,
	  "<addr> <\"pbc\"|PIN> = connect to a P2P Devices" },
	{ "p2p_listen", wpa_cli_cmd_p2p_listen, cli_cmd_flag_none,
	  "[timeout] = listen for P2P Devices for up-to timeout seconds" },
	{ "p2p_group_remove", wpa_cli_cmd_p2p_group_remove, cli_cmd_flag_none,
	  "<ifname> = remove P2P group interface (terminate group if GO)" },
	{ "p2p_group_add", wpa_cli_cmd_p2p_group_add, cli_cmd_flag_none,
	  "= add a new P2P group (local end as GO)" },
	{ "p2p_prov_disc", wpa_cli_cmd_p2p_prov_disc, cli_cmd_flag_none,
	  "<addr> <method> = request provisioning discovery" },
	{ "p2p_get_passphrase", wpa_cli_cmd_p2p_get_passphrase,
	  cli_cmd_flag_none,
	  "= get the passphrase for a group (GO only)" },
	{ "p2p_serv_disc_req", wpa_cli_cmd_p2p_serv_disc_req,
	  cli_cmd_flag_none,
	  "<addr> <TLVs> = schedule service discovery request" },
	{ "p2p_serv_disc_cancel_req", wpa_cli_cmd_p2p_serv_disc_cancel_req,
	  cli_cmd_flag_none,
	  "<id> = cancel pending service discovery request" },
	{ "p2p_serv_disc_resp", wpa_cli_cmd_p2p_serv_disc_resp,
	  cli_cmd_flag_none,
	  "<freq> <addr> <dialog token> <TLVs> = service discovery response" },
	{ "p2p_service_update", wpa_cli_cmd_p2p_service_update,
	  cli_cmd_flag_none,
	  "= indicate change in local services" },
	{ "p2p_serv_disc_external", wpa_cli_cmd_p2p_serv_disc_external,
	  cli_cmd_flag_none,
	  "<external> = set external processing of service discovery" },
	{ "p2p_service_flush", wpa_cli_cmd_p2p_service_flush,
	  cli_cmd_flag_none,
	  "= remove all stored service entries" },
	{ "p2p_service_add", wpa_cli_cmd_p2p_service_add,
	  cli_cmd_flag_none,
	  "<bonjour|upnp> <query|version> <response|service> = add a local "
	  "service" },
	{ "p2p_service_del", wpa_cli_cmd_p2p_service_del,
	  cli_cmd_flag_none,
	  "<bonjour|upnp> <query|version> [|service] = remove a local "
	  "service" },
	{ "p2p_reject", wpa_cli_cmd_p2p_reject,
	  cli_cmd_flag_none,
	  "<addr> = reject connection attempts from a specific peer" },
	{ "p2p_invite", wpa_cli_cmd_p2p_invite,
	  cli_cmd_flag_none,
	  "<cmd> [peer=addr] = invite peer" },
	{ "p2p_peers", wpa_cli_cmd_p2p_peers, cli_cmd_flag_none,
	  "[discovered] = list known (optionally, only fully discovered) P2P "
	  "peers" },
	{ "p2p_peer", wpa_cli_cmd_p2p_peer, cli_cmd_flag_none,
	  "<address> = show information about known P2P peer" },
	{ "p2p_set", wpa_cli_cmd_p2p_set, cli_cmd_flag_none,
	  "<field> <value> = set a P2P parameter" },
	{ "p2p_flush", wpa_cli_cmd_p2p_flush, cli_cmd_flag_none,
	  "= flush P2P state" },
	{ "p2p_cancel", wpa_cli_cmd_p2p_cancel, cli_cmd_flag_none,
	  "= cancel P2P group formation" },
	{ "p2p_unauthorize", wpa_cli_cmd_p2p_unauthorize, cli_cmd_flag_none,
	  "<address> = unauthorize a peer" },
	{ "p2p_presence_req", wpa_cli_cmd_p2p_presence_req, cli_cmd_flag_none,
	  "[<duration> <interval>] [<duration> <interval>] = request GO "
	  "presence" },
	{ "p2p_ext_listen", wpa_cli_cmd_p2p_ext_listen, cli_cmd_flag_none,
	  "[<period> <interval>] = set extended listen timing" },
#endif /* CONFIG_P2P */
	{ "sta_autoconnect", wpa_cli_cmd_sta_autoconnect, cli_cmd_flag_none,
	  "<0/1> = disable/enable automatic reconnection" },
	{ "tdls_discover", wpa_cli_cmd_tdls_discover,
	  cli_cmd_flag_none,
	  "<addr> = request TDLS discovery with <addr>" },
	{ "tdls_setup", wpa_cli_cmd_tdls_setup,
	  cli_cmd_flag_none,
	  "<addr> = request TDLS setup with <addr>" },
	{ "tdls_teardown", wpa_cli_cmd_tdls_teardown,
	  cli_cmd_flag_none,
	  "<addr> = tear down TDLS with <addr>" },
	{ "signal_poll", wpa_cli_cmd_signal_poll,
	  cli_cmd_flag_none,
	  "= get signal parameters" },
	{ NULL, NULL, cli_cmd_flag_none, NULL }
};


/*
 * Prints command usage, lines are padded with the specified string.
 */
static void print_cmd_help(struct wpa_cli_cmd *cmd, const char *pad)
{
	char c;
	size_t n;

	printf("%s%s ", pad, cmd->cmd);
	for (n = 0; (c = cmd->usage[n]); n++) {
		printf("%c", c);
		if (c == '\n')
			printf("%s", pad);
	}
	printf("\n");
}


static void print_help(void)
{
	int n;
	printf("commands:\n");
	for (n = 0; wpa_cli_commands[n].cmd; n++)
		print_cmd_help(&wpa_cli_commands[n], "  ");
}


static int wpa_cli_edit_filter_history_cb(void *ctx, const char *cmd)
{
	const char *c, *delim;
	int n;
	size_t len;

	delim = os_strchr(cmd, ' ');
	if (delim)
		len = delim - cmd;
	else
		len = os_strlen(cmd);

	for (n = 0; (c = wpa_cli_commands[n].cmd); n++) {
		if (os_strncasecmp(cmd, c, len) == 0 && len == os_strlen(c))
			return (wpa_cli_commands[n].flags &
				cli_cmd_flag_sensitive);
	}
	return 0;
}


static char ** wpa_list_cmd_list(void)
{
	char **res;
	int i, count;

	count = sizeof(wpa_cli_commands) / sizeof(wpa_cli_commands[0]);
	res = os_zalloc(count * sizeof(char *));
	if (res == NULL)
		return NULL;

	for (i = 0; wpa_cli_commands[i].cmd; i++) {
		res[i] = os_strdup(wpa_cli_commands[i].cmd);
		if (res[i] == NULL)
			break;
	}

	return res;
}


static char ** wpa_cli_cmd_completion(const char *cmd, const char *str,
				      int pos)
{
	int i;

	for (i = 0; wpa_cli_commands[i].cmd; i++) {
		if (os_strcasecmp(wpa_cli_commands[i].cmd, cmd) == 0) {
			edit_clear_line();
			printf("\r%s\n", wpa_cli_commands[i].usage);
			edit_redraw();
			break;
		}
	}

	return NULL;
}


static char ** wpa_cli_edit_completion_cb(void *ctx, const char *str, int pos)
{
	char **res;
	const char *end;
	char *cmd;

	end = os_strchr(str, ' ');
	if (end == NULL || str + pos < end)
		return wpa_list_cmd_list();

	cmd = os_malloc(pos + 1);
	if (cmd == NULL)
		return NULL;
	os_memcpy(cmd, str, pos);
	cmd[end - str] = '\0';
	res = wpa_cli_cmd_completion(cmd, str, pos);
	os_free(cmd);
	return res;
}


static int wpa_request(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	struct wpa_cli_cmd *cmd, *match = NULL;
	int count;
	int ret = 0;

	count = 0;
	cmd = wpa_cli_commands;
	while (cmd->cmd) {
		if (os_strncasecmp(cmd->cmd, argv[0], os_strlen(argv[0])) == 0)
		{
			match = cmd;
			if (os_strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* we have an exact match */
				count = 1;
				break;
			}
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = wpa_cli_commands;
		while (cmd->cmd) {
			if (os_strncasecmp(cmd->cmd, argv[0],
					   os_strlen(argv[0])) == 0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
		ret = 1;
	} else if (count == 0) {
		printf("Unknown command '%s'\n", argv[0]);
		ret = 1;
	} else {
		ret = match->handler(ctrl, argc - 1, &argv[1]);
	}

	return ret;
}


static int str_match(const char *a, const char *b)
{
	return os_strncmp(a, b, os_strlen(b)) == 0;
}


static int wpa_cli_exec(const char *program, const char *arg1,
			const char *arg2)
{
	char *cmd;
	size_t len;
	int res;
	int ret = 0;

	len = os_strlen(program) + os_strlen(arg1) + os_strlen(arg2) + 3;
	cmd = os_malloc(len);
	if (cmd == NULL)
		return -1;
	res = os_snprintf(cmd, len, "%s %s %s", program, arg1, arg2);
	if (res < 0 || (size_t) res >= len) {
		os_free(cmd);
		return -1;
	}
	cmd[len - 1] = '\0';
#ifndef _WIN32_WCE
	if (system(cmd) < 0)
		ret = -1;
#endif /* _WIN32_WCE */
	os_free(cmd);

	return ret;
}


static void wpa_cli_action_process(const char *msg)
{
	const char *pos;
	char *copy = NULL, *id, *pos2;

	pos = msg;
	if (*pos == '<') {
		/* skip priority */
		pos = os_strchr(pos, '>');
		if (pos)
			pos++;
		else
			pos = msg;
	}

	if (str_match(pos, WPA_EVENT_CONNECTED)) {
		int new_id = -1;
		os_unsetenv("WPA_ID");
		os_unsetenv("WPA_ID_STR");
		os_unsetenv("WPA_CTRL_DIR");

		pos = os_strstr(pos, "[id=");
		if (pos)
			copy = os_strdup(pos + 4);

		if (copy) {
			pos2 = id = copy;
			while (*pos2 && *pos2 != ' ')
				pos2++;
			*pos2++ = '\0';
			new_id = atoi(id);
			os_setenv("WPA_ID", id, 1);
			while (*pos2 && *pos2 != '=')
				pos2++;
			if (*pos2 == '=')
				pos2++;
			id = pos2;
			while (*pos2 && *pos2 != ']')
				pos2++;
			*pos2 = '\0';
			os_setenv("WPA_ID_STR", id, 1);
			os_free(copy);
		}

		os_setenv("WPA_CTRL_DIR", ctrl_iface_dir, 1);

		if (!wpa_cli_connected || new_id != wpa_cli_last_id) {
			wpa_cli_connected = 1;
			wpa_cli_last_id = new_id;
			wpa_cli_exec(action_file, ctrl_ifname, "CONNECTED");
		}
	} else if (str_match(pos, WPA_EVENT_DISCONNECTED)) {
		if (wpa_cli_connected) {
			wpa_cli_connected = 0;
			wpa_cli_exec(action_file, ctrl_ifname, "DISCONNECTED");
		}
	} else if (str_match(pos, P2P_EVENT_GROUP_STARTED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, P2P_EVENT_GROUP_REMOVED)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, P2P_EVENT_CROSS_CONNECT_ENABLE)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, P2P_EVENT_CROSS_CONNECT_DISABLE)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, WPS_EVENT_SUCCESS)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, WPS_EVENT_FAIL)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, WPA_EVENT_TERMINATING)) {
		printf("wpa_supplicant is terminating - stop monitoring\n");
		wpa_cli_quit = 1;
	}
}


#ifndef CONFIG_ANSI_C_EXTRA
static void wpa_cli_action_cb(char *msg, size_t len)
{
	wpa_cli_action_process(msg);
}
#endif /* CONFIG_ANSI_C_EXTRA */


static void wpa_cli_reconnect(void)
{
	wpa_cli_close_connection();
	wpa_cli_open_connection(ctrl_ifname, 1);
}


static void wpa_cli_recv_pending(struct wpa_ctrl *ctrl, int action_monitor)
{
	if (ctrl_conn == NULL) {
		wpa_cli_reconnect();
		return;
	}
	while (wpa_ctrl_pending(ctrl) > 0) {
		char buf[256];
		size_t len = sizeof(buf) - 1;
		if (wpa_ctrl_recv(ctrl, buf, &len) == 0) {
			buf[len] = '\0';
			if (action_monitor)
				wpa_cli_action_process(buf);
			else {
				if (wpa_cli_show_event(buf)) {
					edit_clear_line();
					printf("\r%s\n", buf);
					edit_redraw();
				}
			}
		} else {
			printf("Could not read pending message.\n");
			break;
		}
	}

	if (wpa_ctrl_pending(ctrl) < 0) {
		printf("Connection to wpa_supplicant lost - trying to "
		       "reconnect\n");
		wpa_cli_reconnect();
	}
}

#define max_args 10

static int tokenize_cmd(char *cmd, char *argv[])
{
	char *pos;
	int argc = 0;

	pos = cmd;
	for (;;) {
		while (*pos == ' ')
			pos++;
		if (*pos == '\0')
			break;
		argv[argc] = pos;
		argc++;
		if (argc == max_args)
			break;
		if (*pos == '"') {
			char *pos2 = os_strrchr(pos, '"');
			if (pos2)
				pos = pos2 + 1;
		}
		while (*pos != '\0' && *pos != ' ')
			pos++;
		if (*pos == ' ')
			*pos++ = '\0';
	}

	return argc;
}


static void wpa_cli_ping(void *eloop_ctx, void *timeout_ctx)
{
	if (ctrl_conn && _wpa_ctrl_command(ctrl_conn, "PING", 0)) {
		printf("Connection to wpa_supplicant lost - trying to "
		       "reconnect\n");
		wpa_cli_close_connection();
	}
	if (!ctrl_conn)
		wpa_cli_reconnect();
	eloop_register_timeout(ping_interval, 0, wpa_cli_ping, NULL, NULL);
}


static void wpa_cli_eloop_terminate(int sig, void *signal_ctx)
{
	eloop_terminate();
}


static void wpa_cli_mon_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	wpa_cli_recv_pending(mon_conn, 0);
}


static void wpa_cli_edit_cmd_cb(void *ctx, char *cmd)
{
	char *argv[max_args];
	int argc;
	argc = tokenize_cmd(cmd, argv);
	if (argc)
		wpa_request(ctrl_conn, argc, argv);
}


static void wpa_cli_edit_eof_cb(void *ctx)
{
	eloop_terminate();
}


static void wpa_cli_interactive(void)
{
	char *home, *hfile = NULL;

	printf("\nInteractive mode\n\n");

	home = getenv("HOME");
	if (home) {
		const char *fname = ".wpa_cli_history";
		int hfile_len = os_strlen(home) + 1 + os_strlen(fname) + 1;
		hfile = os_malloc(hfile_len);
		if (hfile)
			os_snprintf(hfile, hfile_len, "%s/%s", home, fname);
	}

	eloop_register_signal_terminate(wpa_cli_eloop_terminate, NULL);
	edit_init(wpa_cli_edit_cmd_cb, wpa_cli_edit_eof_cb,
		  wpa_cli_edit_completion_cb, NULL, hfile);
	eloop_register_timeout(ping_interval, 0, wpa_cli_ping, NULL, NULL);

	eloop_run();

	edit_deinit(hfile, wpa_cli_edit_filter_history_cb);
	os_free(hfile);
	eloop_cancel_timeout(wpa_cli_ping, NULL, NULL);
	wpa_cli_close_connection();
}


static void wpa_cli_action(struct wpa_ctrl *ctrl)
{
#ifdef CONFIG_ANSI_C_EXTRA
	/* TODO: ANSI C version(?) */
	printf("Action processing not supported in ANSI C build.\n");
#else /* CONFIG_ANSI_C_EXTRA */
	fd_set rfds;
	int fd, res;
	struct timeval tv;
	char buf[256]; /* note: large enough to fit in unsolicited messages */
	size_t len;

	fd = wpa_ctrl_get_fd(ctrl);

	while (!wpa_cli_quit) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = ping_interval;
		tv.tv_usec = 0;
		res = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (res < 0 && errno != EINTR) {
			perror("select");
			break;
		}

		if (FD_ISSET(fd, &rfds))
			wpa_cli_recv_pending(ctrl, 1);
		else {
			/* verify that connection is still working */
			len = sizeof(buf) - 1;
			if (wpa_ctrl_request(ctrl, "PING", 4, buf, &len,
					     wpa_cli_action_cb) < 0 ||
			    len < 4 || os_memcmp(buf, "PONG", 4) != 0) {
				printf("wpa_supplicant did not reply to PING "
				       "command - exiting\n");
				break;
			}
		}
	}
#endif /* CONFIG_ANSI_C_EXTRA */
}


static void wpa_cli_cleanup(void)
{
	wpa_cli_close_connection();
	if (pid_file)
		os_daemonize_terminate(pid_file);

	os_program_deinit();
}

static void wpa_cli_terminate(int sig)
{
	wpa_cli_cleanup();
	exit(0);
}


static char * wpa_cli_get_default_ifname(void)
{
	char *ifname = NULL;

#ifdef CONFIG_CTRL_IFACE_UNIX
	struct dirent *dent;
	DIR *dir = opendir(ctrl_iface_dir);
	if (!dir) {
#ifdef ANDROID
		char ifprop[PROPERTY_VALUE_MAX];
		if (property_get("wifi.interface", ifprop, NULL) != 0) {
			ifname = os_strdup(ifprop);
			printf("Using interface '%s'\n", ifname);
			return ifname;
		}
#endif /* ANDROID */
		return NULL;
	}
	while ((dent = readdir(dir))) {
#ifdef _DIRENT_HAVE_D_TYPE
		/*
		 * Skip the file if it is not a socket. Also accept
		 * DT_UNKNOWN (0) in case the C library or underlying
		 * file system does not support d_type.
		 */
		if (dent->d_type != DT_SOCK && dent->d_type != DT_UNKNOWN)
			continue;
#endif /* _DIRENT_HAVE_D_TYPE */
		if (os_strcmp(dent->d_name, ".") == 0 ||
		    os_strcmp(dent->d_name, "..") == 0)
			continue;
		printf("Selected interface '%s'\n", dent->d_name);
		ifname = os_strdup(dent->d_name);
		break;
	}
	closedir(dir);
#endif /* CONFIG_CTRL_IFACE_UNIX */

#ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
	char buf[2048], *pos;
	size_t len;
	struct wpa_ctrl *ctrl;
	int ret;

	ctrl = wpa_ctrl_open(NULL);
	if (ctrl == NULL)
		return NULL;

	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, "INTERFACES", 10, buf, &len, NULL);
	if (ret >= 0) {
		buf[len] = '\0';
		pos = os_strchr(buf, '\n');
		if (pos)
			*pos = '\0';
		ifname = os_strdup(buf);
	}
	wpa_ctrl_close(ctrl);
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */

	return ifname;
}


int main(int argc, char *argv[])
{
	int warning_displayed = 0;
	int c;
	int daemonize = 0;
	int ret = 0;
	const char *global = NULL;

	if (os_program_init())
		return -1;

	for (;;) {
		c = getopt(argc, argv, "a:Bg:G:hi:p:P:v");
		if (c < 0)
			break;
		switch (c) {
		case 'a':
			action_file = optarg;
			break;
		case 'B':
			daemonize = 1;
			break;
		case 'g':
			global = optarg;
			break;
		case 'G':
			ping_interval = atoi(optarg);
			break;
		case 'h':
			usage();
			return 0;
		case 'v':
			printf("%s\n", wpa_cli_version);
			return 0;
		case 'i':
			os_free(ctrl_ifname);
			ctrl_ifname = os_strdup(optarg);
			break;
		case 'p':
			ctrl_iface_dir = optarg;
			break;
		case 'P':
			pid_file = optarg;
			break;
		default:
			usage();
			return -1;
		}
	}

	interactive = (argc == optind) && (action_file == NULL);

	if (interactive)
		printf("%s\n\n%s\n\n", wpa_cli_version, wpa_cli_license);

	if (eloop_init())
		return -1;

	if (global) {
#ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
		ctrl_conn = wpa_ctrl_open(NULL);
#else /* CONFIG_CTRL_IFACE_NAMED_PIPE */
		ctrl_conn = wpa_ctrl_open(global);
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */
		if (ctrl_conn == NULL) {
			perror("Failed to connect to wpa_supplicant - "
			       "wpa_ctrl_open");
			return -1;
		}
	}

#ifndef _WIN32_WCE
	signal(SIGINT, wpa_cli_terminate);
	signal(SIGTERM, wpa_cli_terminate);
#endif /* _WIN32_WCE */

	if (ctrl_ifname == NULL)
		ctrl_ifname = wpa_cli_get_default_ifname();

	if (interactive) {
		for (; !global;) {
			if (wpa_cli_open_connection(ctrl_ifname, 1) == 0) {
				if (warning_displayed)
					printf("Connection established.\n");
				break;
			}

			if (!warning_displayed) {
				printf("Could not connect to wpa_supplicant - "
				       "re-trying\n");
				warning_displayed = 1;
			}
			os_sleep(1, 0);
			continue;
		}
	} else {
		if (!global &&
		    wpa_cli_open_connection(ctrl_ifname, 0) < 0) {
			perror("Failed to connect to wpa_supplicant - "
			       "wpa_ctrl_open");
			return -1;
		}

		if (action_file) {
			if (wpa_ctrl_attach(ctrl_conn) == 0) {
				wpa_cli_attached = 1;
			} else {
				printf("Warning: Failed to attach to "
				       "wpa_supplicant.\n");
				return -1;
			}
		}
	}

	if (daemonize && os_daemonize(pid_file))
		return -1;

	if (interactive)
		wpa_cli_interactive();
	else if (action_file)
		wpa_cli_action(ctrl_conn);
	else
		ret = wpa_request(ctrl_conn, argc - optind, &argv[optind]);

	os_free(ctrl_ifname);
	eloop_destroy();
	wpa_cli_cleanup();

	return ret;
}

#else /* CONFIG_CTRL_IFACE */
int main(int argc, char *argv[])
{
	printf("CONFIG_CTRL_IFACE not defined - wpa_cli disabled\n");
	return -1;
}
#endif /* CONFIG_CTRL_IFACE */
