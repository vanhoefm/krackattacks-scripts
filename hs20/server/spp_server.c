/*
 * Hotspot 2.0 SPP server
 * Copyright (c) 2012-2013, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sqlite3.h>

#include "common.h"
#include "base64.h"
#include "md5_i.h"
#include "xml-utils.h"
#include "spp_server.h"


#define SPP_NS_URI "http://www.wi-fi.org/specifications/hotspot2dot0/v1.0/spp"

#define URN_OMA_DM_DEVINFO "urn:oma:mo:oma-dm-devinfo:1.0"
#define URN_OMA_DM_DEVDETAIL "urn:oma:mo:oma-dm-devdetail:1.0"
#define URN_OMA_DM_DMACC "urn:oma:mo:oma-dm-dmacc:1.0"
#define URN_HS20_PPS "urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0"


/* TODO: timeout to expire sessions */

enum hs20_session_operation {
	NO_OPERATION,
	UPDATE_PASSWORD,
	CONTINUE_SUBSCRIPTION_REMEDIATION,
	CONTINUE_POLICY_UPDATE,
	USER_REMEDIATION,
	SUBSCRIPTION_REGISTRATION,
	POLICY_REMEDIATION,
	POLICY_UPDATE,
	FREE_REMEDIATION,
};


static char * db_get_session_val(struct hs20_svc *ctx, const char *user,
				 const char *realm, const char *session_id,
				 const char *field);
static char * db_get_osu_config_val(struct hs20_svc *ctx, const char *realm,
				    const char *field);
static xml_node_t * build_policy(struct hs20_svc *ctx, const char *user,
				 const char *realm, int use_dmacc);


static int db_add_session(struct hs20_svc *ctx,
			  const char *user, const char *realm,
			  const char *sessionid, const char *pw,
			  const char *redirect_uri,
			  enum hs20_session_operation operation)
{
	char *sql;
	int ret = 0;

	sql = sqlite3_mprintf("INSERT INTO sessions(timestamp,id,user,realm,"
			      "operation,password,redirect_uri) "
			      "VALUES "
			      "(strftime('%%Y-%%m-%%d %%H:%%M:%%f','now'),"
			      "%Q,%Q,%Q,%d,%Q,%Q)",
			      sessionid, user ? user : "", realm ? realm : "",
			      operation, pw ? pw : "",
			      redirect_uri ? redirect_uri : "");
	if (sql == NULL)
		return -1;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to add session entry into sqlite "
			    "database: %s", sqlite3_errmsg(ctx->db));
		ret = -1;
	}
	sqlite3_free(sql);
	return ret;
}


static void db_update_session_password(struct hs20_svc *ctx, const char *user,
				       const char *realm, const char *sessionid,
				       const char *pw)
{
	char *sql;

	sql = sqlite3_mprintf("UPDATE sessions SET password=%Q WHERE id=%Q AND "
			      "user=%Q AND realm=%Q",
			      pw, sessionid, user, realm);
	if (sql == NULL)
		return;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to update session password: %s",
			    sqlite3_errmsg(ctx->db));
	}
	sqlite3_free(sql);
}


static void db_add_session_pps(struct hs20_svc *ctx, const char *user,
			       const char *realm, const char *sessionid,
			       xml_node_t *node)
{
	char *str;
	char *sql;

	str = xml_node_to_str(ctx->xml, node);
	if (str == NULL)
		return;
	sql = sqlite3_mprintf("UPDATE sessions SET pps=%Q WHERE id=%Q AND "
			      "user=%Q AND realm=%Q",
			      str, sessionid, user, realm);
	free(str);
	if (sql == NULL)
		return;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to add session pps: %s",
			    sqlite3_errmsg(ctx->db));
	}
	sqlite3_free(sql);
}


static void db_add_session_devinfo(struct hs20_svc *ctx, const char *sessionid,
				   xml_node_t *node)
{
	char *str;
	char *sql;

	str = xml_node_to_str(ctx->xml, node);
	if (str == NULL)
		return;
	sql = sqlite3_mprintf("UPDATE sessions SET devinfo=%Q WHERE id=%Q",
			      str, sessionid);
	free(str);
	if (sql == NULL)
		return;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to add session devinfo: %s",
			    sqlite3_errmsg(ctx->db));
	}
	sqlite3_free(sql);
}


static void db_add_session_devdetail(struct hs20_svc *ctx,
				     const char *sessionid,
				     xml_node_t *node)
{
	char *str;
	char *sql;

	str = xml_node_to_str(ctx->xml, node);
	if (str == NULL)
		return;
	sql = sqlite3_mprintf("UPDATE sessions SET devdetail=%Q WHERE id=%Q",
			      str, sessionid);
	free(str);
	if (sql == NULL)
		return;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to add session devdetail: %s",
			    sqlite3_errmsg(ctx->db));
	}
	sqlite3_free(sql);
}


static void db_remove_session(struct hs20_svc *ctx,
			      const char *user, const char *realm,
			      const char *sessionid)
{
	char *sql;

	if (user == NULL || realm == NULL) {
		sql = sqlite3_mprintf("DELETE FROM sessions WHERE "
				      "id=%Q", sessionid);
	} else {
		sql = sqlite3_mprintf("DELETE FROM sessions WHERE "
				      "user=%Q AND realm=%Q AND id=%Q",
				      user, realm, sessionid);
	}
	if (sql == NULL)
		return;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to delete session entry from "
			    "sqlite database: %s", sqlite3_errmsg(ctx->db));
	}
	sqlite3_free(sql);
}


static void hs20_eventlog(struct hs20_svc *ctx,
			  const char *user, const char *realm,
			  const char *sessionid, const char *notes,
			  const char *dump)
{
	char *sql;
	char *user_buf = NULL, *realm_buf = NULL;

	debug_print(ctx, 1, "eventlog: %s", notes);

	if (user == NULL) {
		user_buf = db_get_session_val(ctx, NULL, NULL, sessionid,
					      "user");
		user = user_buf;
		realm_buf = db_get_session_val(ctx, NULL, NULL, sessionid,
					       "realm");
		realm = realm_buf;
	}

	sql = sqlite3_mprintf("INSERT INTO eventlog"
			      "(user,realm,sessionid,timestamp,notes,dump,addr)"
			      " VALUES (%Q,%Q,%Q,"
			      "strftime('%%Y-%%m-%%d %%H:%%M:%%f','now'),"
			      "%Q,%Q,%Q)",
			      user, realm, sessionid, notes,
			      dump ? dump : "", ctx->addr ? ctx->addr : "");
	free(user_buf);
	free(realm_buf);
	if (sql == NULL)
		return;
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to add eventlog entry into sqlite "
			    "database: %s", sqlite3_errmsg(ctx->db));
	}
	sqlite3_free(sql);
}


static void hs20_eventlog_node(struct hs20_svc *ctx,
			       const char *user, const char *realm,
			       const char *sessionid, const char *notes,
			       xml_node_t *node)
{
	char *str;

	if (node)
		str = xml_node_to_str(ctx->xml, node);
	else
		str = NULL;
	hs20_eventlog(ctx, user, realm, sessionid, notes, str);
	free(str);
}


static void db_update_mo_str(struct hs20_svc *ctx, const char *user,
			     const char *realm, const char *name,
			     const char *str)
{
	char *sql;
	if (user == NULL || realm == NULL || name == NULL)
		return;
	sql = sqlite3_mprintf("UPDATE users SET %s=%Q "
		 "WHERE identity=%Q AND realm=%Q AND phase2=1",
			      name, str, user, realm);
	if (sql == NULL)
		return;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to update user MO entry in sqlite "
			    "database: %s", sqlite3_errmsg(ctx->db));
	}
	sqlite3_free(sql);
}


static void db_update_mo(struct hs20_svc *ctx, const char *user,
			 const char *realm, const char *name, xml_node_t *mo)
{
	char *str;

	str = xml_node_to_str(ctx->xml, mo);
	if (str == NULL)
		return;

	db_update_mo_str(ctx, user, realm, name, str);
	free(str);
}


static void add_text_node(struct hs20_svc *ctx, xml_node_t *parent,
			  const char *name, const char *value)
{
	xml_node_create_text(ctx->xml, parent, NULL, name, value ? value : "");
}


static void add_text_node_conf(struct hs20_svc *ctx, const char *realm,
			       xml_node_t *parent, const char *name,
			       const char *field)
{
	char *val;
	val = db_get_osu_config_val(ctx, realm, field);
	xml_node_create_text(ctx->xml, parent, NULL, name, val ? val : "");
	os_free(val);
}


static int new_password(char *buf, int buflen)
{
	int i;

	if (buflen < 1)
		return -1;
	buf[buflen - 1] = '\0';
	if (os_get_random((unsigned char *) buf, buflen - 1) < 0)
		return -1;

	for (i = 0; i < buflen - 1; i++) {
		unsigned char val = buf[i];
		val %= 2 * 26 + 10;
		if (val < 26)
			buf[i] = 'a' + val;
		else if (val < 2 * 26)
			buf[i] = 'A' + val - 26;
		else
			buf[i] = '0' + val - 2 * 26;
	}

	return 0;
}


struct get_db_field_data {
	const char *field;
	char *value;
};


static int get_db_field(void *ctx, int argc, char *argv[], char *col[])
{
	struct get_db_field_data *data = ctx;
	int i;

	for (i = 0; i < argc; i++) {
		if (os_strcmp(col[i], data->field) == 0 && argv[i]) {
			os_free(data->value);
			data->value = os_strdup(argv[i]);
			break;
		}
	}

	return 0;
}


static char * db_get_val(struct hs20_svc *ctx, const char *user,
			 const char *realm, const char *field, int dmacc)
{
	char *cmd;
	struct get_db_field_data data;

	cmd = sqlite3_mprintf("SELECT %s FROM users WHERE "
			      "%s=%Q AND realm=%Q AND phase2=1",
			      field, dmacc ? "osu_user" : "identity",
			      user, realm);
	if (cmd == NULL)
		return NULL;
	memset(&data, 0, sizeof(data));
	data.field = field;
	if (sqlite3_exec(ctx->db, cmd, get_db_field, &data, NULL) != SQLITE_OK)
	{
		debug_print(ctx, 1, "Could not find user '%s'", user);
		sqlite3_free(cmd);
		return NULL;
	}
	sqlite3_free(cmd);

	debug_print(ctx, 1, "DB: user='%s' realm='%s' field='%s' dmacc=%d --> "
		    "value='%s'", user, realm, field, dmacc, data.value);

	return data.value;
}


static int db_update_val(struct hs20_svc *ctx, const char *user,
			 const char *realm, const char *field,
			 const char *val, int dmacc)
{
	char *cmd;
	int ret;

	cmd = sqlite3_mprintf("UPDATE users SET %s=%Q WHERE "
			      "%s=%Q AND realm=%Q AND phase2=1",
			      field, val, dmacc ? "osu_user" : "identity", user,
			      realm);
	if (cmd == NULL)
		return -1;
	debug_print(ctx, 1, "DB: %s", cmd);
	if (sqlite3_exec(ctx->db, cmd, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1,
			    "Failed to update user in sqlite database: %s",
			    sqlite3_errmsg(ctx->db));
		ret = -1;
	} else {
		debug_print(ctx, 1,
			    "DB: user='%s' realm='%s' field='%s' set to '%s'",
			    user, realm, field, val);
		ret = 0;
	}
	sqlite3_free(cmd);

	return ret;
}


static char * db_get_session_val(struct hs20_svc *ctx, const char *user,
				 const char *realm, const char *session_id,
				 const char *field)
{
	char *cmd;
	struct get_db_field_data data;

	if (user == NULL || realm == NULL) {
		cmd = sqlite3_mprintf("SELECT %s FROM sessions WHERE "
				      "id=%Q", field, session_id);
	} else {
		cmd = sqlite3_mprintf("SELECT %s FROM sessions WHERE "
				      "user=%Q AND realm=%Q AND id=%Q",
				      field, user, realm, session_id);
	}
	if (cmd == NULL)
		return NULL;
	debug_print(ctx, 1, "DB: %s", cmd);
	memset(&data, 0, sizeof(data));
	data.field = field;
	if (sqlite3_exec(ctx->db, cmd, get_db_field, &data, NULL) != SQLITE_OK)
	{
		debug_print(ctx, 1, "DB: Could not find session %s: %s",
			    session_id, sqlite3_errmsg(ctx->db));
		sqlite3_free(cmd);
		return NULL;
	}
	sqlite3_free(cmd);

	debug_print(ctx, 1, "DB: return '%s'", data.value);
	return data.value;
}


static int update_password(struct hs20_svc *ctx, const char *user,
			   const char *realm, const char *pw, int dmacc)
{
	char *cmd;

	cmd = sqlite3_mprintf("UPDATE users SET password=%Q, "
			      "remediation='' "
			      "WHERE %s=%Q AND phase2=1",
			      pw, dmacc ? "osu_user" : "identity",
			      user);
	if (cmd == NULL)
		return -1;
	debug_print(ctx, 1, "DB: %s", cmd);
	if (sqlite3_exec(ctx->db, cmd, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to update database for user '%s'",
			    user);
	}
	sqlite3_free(cmd);

	return 0;
}


static int add_eap_ttls(struct hs20_svc *ctx, xml_node_t *parent)
{
	xml_node_t *node;

	node = xml_node_create(ctx->xml, parent, NULL, "EAPMethod");
	if (node == NULL)
		return -1;

	add_text_node(ctx, node, "EAPType", "21");
	add_text_node(ctx, node, "InnerMethod", "MS-CHAP-V2");

	return 0;
}


static xml_node_t * build_username_password(struct hs20_svc *ctx,
					    xml_node_t *parent,
					    const char *user, const char *pw)
{
	xml_node_t *node;
	char *b64;

	node = xml_node_create(ctx->xml, parent, NULL, "UsernamePassword");
	if (node == NULL)
		return NULL;

	add_text_node(ctx, node, "Username", user);

	b64 = (char *) base64_encode((unsigned char *) pw, strlen(pw), NULL);
	if (b64 == NULL)
		return NULL;
	add_text_node(ctx, node, "Password", b64);
	free(b64);

	return node;
}


static int add_username_password(struct hs20_svc *ctx, xml_node_t *cred,
				 const char *user, const char *pw)
{
	xml_node_t *node;

	node = build_username_password(ctx, cred, user, pw);
	if (node == NULL)
		return -1;

	add_text_node(ctx, node, "MachineManaged", "TRUE");
	add_text_node(ctx, node, "SoftTokenApp", "");
	add_eap_ttls(ctx, node);

	return 0;
}


static void add_creation_date(struct hs20_svc *ctx, xml_node_t *cred)
{
	char str[30];
	time_t now;
	struct tm tm;

	time(&now);
	gmtime_r(&now, &tm);
	snprintf(str, sizeof(str), "%04u-%02u-%02uT%02u:%02u:%02uZ",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
	xml_node_create_text(ctx->xml, cred, NULL, "CreationDate", str);
}


static xml_node_t * build_credential_pw(struct hs20_svc *ctx,
					const char *user, const char *realm,
					const char *pw)
{
	xml_node_t *cred;

	cred = xml_node_create_root(ctx->xml, NULL, NULL, NULL, "Credential");
	if (cred == NULL) {
		debug_print(ctx, 1, "Failed to create Credential node");
		return NULL;
	}
	add_creation_date(ctx, cred);
	if (add_username_password(ctx, cred, user, pw) < 0) {
		xml_node_free(ctx->xml, cred);
		return NULL;
	}
	add_text_node(ctx, cred, "Realm", realm);

	return cred;
}


static xml_node_t * build_credential(struct hs20_svc *ctx,
				     const char *user, const char *realm,
				     char *new_pw, size_t new_pw_len)
{
	if (new_password(new_pw, new_pw_len) < 0)
		return NULL;
	debug_print(ctx, 1, "Update password to '%s'", new_pw);
	return build_credential_pw(ctx, user, realm, new_pw);
}


static xml_node_t * build_credential_cert(struct hs20_svc *ctx,
					  const char *user, const char *realm,
					  const char *cert_fingerprint)
{
	xml_node_t *cred, *cert;

	cred = xml_node_create_root(ctx->xml, NULL, NULL, NULL, "Credential");
	if (cred == NULL) {
		debug_print(ctx, 1, "Failed to create Credential node");
		return NULL;
	}
	add_creation_date(ctx, cred);
	cert = xml_node_create(ctx->xml, cred, NULL, "DigitalCertificate");
	add_text_node(ctx, cert, "CertificateType", "x509v3");
	add_text_node(ctx, cert, "CertSHA256Fingerprint", cert_fingerprint);
	add_text_node(ctx, cred, "Realm", realm);

	return cred;
}


static xml_node_t * build_post_dev_data_response(struct hs20_svc *ctx,
						 xml_namespace_t **ret_ns,
						 const char *session_id,
						 const char *status,
						 const char *error_code)
{
	xml_node_t *spp_node = NULL;
	xml_namespace_t *ns;

	spp_node = xml_node_create_root(ctx->xml, SPP_NS_URI, "spp", &ns,
					"sppPostDevDataResponse");
	if (spp_node == NULL)
		return NULL;
	if (ret_ns)
		*ret_ns = ns;

	xml_node_add_attr(ctx->xml, spp_node, ns, "sppVersion", "1.0");
	xml_node_add_attr(ctx->xml, spp_node, ns, "sessionID", session_id);
	xml_node_add_attr(ctx->xml, spp_node, ns, "sppStatus", status);

	if (error_code) {
		xml_node_t *node;
		node = xml_node_create(ctx->xml, spp_node, ns, "sppError");
		if (node)
			xml_node_add_attr(ctx->xml, node, NULL, "errorCode",
					  error_code);
	}

	return spp_node;
}


static int add_update_node(struct hs20_svc *ctx, xml_node_t *spp_node,
			   xml_namespace_t *ns, const char *uri,
			   xml_node_t *upd_node)
{
	xml_node_t *node, *tnds;
	char *str;

	tnds = mo_to_tnds(ctx->xml, upd_node, 0, NULL, NULL);
	if (!tnds)
		return -1;

	str = xml_node_to_str(ctx->xml, tnds);
	xml_node_free(ctx->xml, tnds);
	if (str == NULL)
		return -1;
	node = xml_node_create_text(ctx->xml, spp_node, ns, "updateNode", str);
	free(str);

	xml_node_add_attr(ctx->xml, node, ns, "managementTreeURI", uri);

	return 0;
}


static xml_node_t * build_sub_rem_resp(struct hs20_svc *ctx,
				       const char *user, const char *realm,
				       const char *session_id,
				       int machine_rem, int dmacc)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *cred;
	char buf[400];
	char new_pw[33];
	char *real_user = NULL;
	char *status;
	char *cert;

	if (dmacc) {
		real_user = db_get_val(ctx, user, realm, "identity", dmacc);
		if (real_user == NULL) {
			debug_print(ctx, 1, "Could not find user identity for "
				    "dmacc user '%s'", user);
			return NULL;
		}
	}

	cert = db_get_val(ctx, user, realm, "cert", dmacc);
	if (cert && cert[0] == '\0')
		cert = NULL;
	if (cert) {
		cred = build_credential_cert(ctx, real_user ? real_user : user,
					     realm, cert);
	} else {
		cred = build_credential(ctx, real_user ? real_user : user,
					realm, new_pw, sizeof(new_pw));
	}
	free(real_user);
	if (!cred) {
		debug_print(ctx, 1, "Could not build credential");
		return NULL;
	}

	status = "Remediation complete, request sppUpdateResponse";
	spp_node = build_post_dev_data_response(ctx, &ns, session_id, status,
						NULL);
	if (spp_node == NULL) {
		debug_print(ctx, 1, "Could not build sppPostDevDataResponse");
		return NULL;
	}

	snprintf(buf, sizeof(buf),
		 "./Wi-Fi/%s/PerProviderSubscription/Credential1/Credential",
		 realm);

	if (add_update_node(ctx, spp_node, ns, buf, cred) < 0) {
		debug_print(ctx, 1, "Could not add update node");
		xml_node_free(ctx->xml, spp_node);
		return NULL;
	}

	hs20_eventlog_node(ctx, user, realm, session_id,
			   machine_rem ? "machine remediation" :
			   "user remediation", cred);
	xml_node_free(ctx->xml, cred);

	if (cert) {
		debug_print(ctx, 1, "Certificate credential - no need for DB "
			    "password update on success notification");
	} else {
		debug_print(ctx, 1, "Request DB password update on success "
			    "notification");
		db_add_session(ctx, user, realm, session_id, new_pw, NULL,
			       UPDATE_PASSWORD);
	}

	return spp_node;
}


static xml_node_t * machine_remediation(struct hs20_svc *ctx,
					const char *user,
					const char *realm,
					const char *session_id, int dmacc)
{
	return build_sub_rem_resp(ctx, user, realm, session_id, 1, dmacc);
}


static xml_node_t * policy_remediation(struct hs20_svc *ctx,
				       const char *user, const char *realm,
				       const char *session_id, int dmacc)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *policy;
	char buf[400];
	const char *status;

	hs20_eventlog(ctx, user, realm, session_id,
		      "requires policy remediation", NULL);

	db_add_session(ctx, user, realm, session_id, NULL, NULL,
		       POLICY_REMEDIATION);

	policy = build_policy(ctx, user, realm, dmacc);
	if (!policy) {
		return build_post_dev_data_response(
			ctx, NULL, session_id,
			"No update available at this time", NULL);
	}

	status = "Remediation complete, request sppUpdateResponse";
	spp_node = build_post_dev_data_response(ctx, &ns, session_id, status,
						NULL);
	if (spp_node == NULL)
		return NULL;

	snprintf(buf, sizeof(buf),
		 "./Wi-Fi/%s/PerProviderSubscription/Credential1/Policy",
		 realm);

	if (add_update_node(ctx, spp_node, ns, buf, policy) < 0) {
		xml_node_free(ctx->xml, spp_node);
		xml_node_free(ctx->xml, policy);
		return NULL;
	}

	hs20_eventlog_node(ctx, user, realm, session_id,
			   "policy update (sub rem)", policy);
	xml_node_free(ctx->xml, policy);

	return spp_node;
}


static xml_node_t * browser_remediation(struct hs20_svc *ctx,
					const char *session_id,
					const char *redirect_uri,
					const char *uri)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *exec_node;

	if (redirect_uri == NULL) {
		debug_print(ctx, 1, "Missing redirectURI attribute for user "
			    "remediation");
		return NULL;
	}
	debug_print(ctx, 1, "redirectURI %s", redirect_uri);

	spp_node = build_post_dev_data_response(ctx, &ns, session_id, "OK",
		NULL);
	if (spp_node == NULL)
		return NULL;

	exec_node = xml_node_create(ctx->xml, spp_node, ns, "exec");
	xml_node_create_text(ctx->xml, exec_node, ns, "launchBrowserToURI",
			     uri);
	return spp_node;
}


static xml_node_t * user_remediation(struct hs20_svc *ctx, const char *user,
				     const char *realm, const char *session_id,
				     const char *redirect_uri)
{
	char uri[300], *val;

	hs20_eventlog(ctx, user, realm, session_id,
		      "requires user remediation", NULL);
	val = db_get_osu_config_val(ctx, realm, "remediation_url");
	if (val == NULL)
		return NULL;

	db_add_session(ctx, user, realm, session_id, NULL, redirect_uri,
		       USER_REMEDIATION);

	snprintf(uri, sizeof(uri), "%s%s", val, session_id);
	os_free(val);
	return browser_remediation(ctx, session_id, redirect_uri, uri);
}


static xml_node_t * free_remediation(struct hs20_svc *ctx,
				     const char *user, const char *realm,
				     const char *session_id,
				     const char *redirect_uri)
{
	char uri[300], *val;

	hs20_eventlog(ctx, user, realm, session_id,
		      "requires free/public account remediation", NULL);
	val = db_get_osu_config_val(ctx, realm, "free_remediation_url");
	if (val == NULL)
		return NULL;

	db_add_session(ctx, user, realm, session_id, NULL, redirect_uri,
		       FREE_REMEDIATION);

	snprintf(uri, sizeof(uri), "%s%s", val, session_id);
	os_free(val);
	return browser_remediation(ctx, session_id, redirect_uri, uri);
}


static xml_node_t * no_sub_rem(struct hs20_svc *ctx,
			       const char *user, const char *realm,
			       const char *session_id)
{
	const char *status;

	hs20_eventlog(ctx, user, realm, session_id,
		      "no subscription mediation available", NULL);

	status = "No update available at this time";
	return build_post_dev_data_response(ctx, NULL, session_id, status,
					    NULL);
}


static xml_node_t * hs20_subscription_remediation(struct hs20_svc *ctx,
						  const char *user,
						  const char *realm,
						  const char *session_id,
						  int dmacc,
						  const char *redirect_uri)
{
	char *type, *identity;
	xml_node_t *ret;
	char *free_account;

	identity = db_get_val(ctx, user, realm, "identity", dmacc);
	if (identity == NULL || strlen(identity) == 0) {
		hs20_eventlog(ctx, user, realm, session_id,
			      "user not found in database for remediation",
			      NULL);
		os_free(identity);
		return build_post_dev_data_response(ctx, NULL, session_id,
						    "Error occurred",
						    "Not found");
	}
	os_free(identity);

	free_account = db_get_osu_config_val(ctx, realm, "free_account");
	if (free_account && strcmp(free_account, user) == 0) {
		free(free_account);
		return no_sub_rem(ctx, user, realm, session_id);
	}
	free(free_account);

	type = db_get_val(ctx, user, realm, "remediation", dmacc);
	if (type && strcmp(type, "free") != 0) {
		char *val;
		int shared = 0;
		val = db_get_val(ctx, user, realm, "shared", dmacc);
		if (val)
			shared = atoi(val);
		free(val);
		if (shared) {
			free(type);
			return no_sub_rem(ctx, user, realm, session_id);
		}
	}
	if (type && strcmp(type, "user") == 0)
		ret = user_remediation(ctx, user, realm, session_id,
				       redirect_uri);
	else if (type && strcmp(type, "free") == 0)
		ret = free_remediation(ctx, user, realm, session_id,
				       redirect_uri);
	else if (type && strcmp(type, "policy") == 0)
		ret = policy_remediation(ctx, user, realm, session_id, dmacc);
	else
		ret = machine_remediation(ctx, user, realm, session_id, dmacc);
	free(type);

	return ret;
}


static xml_node_t * build_policy(struct hs20_svc *ctx, const char *user,
				 const char *realm, int use_dmacc)
{
	char *policy_id;
	char fname[200];
	xml_node_t *policy, *node;

	policy_id = db_get_val(ctx, user, realm, "policy", use_dmacc);
	if (policy_id == NULL || strlen(policy_id) == 0) {
		free(policy_id);
		policy_id = strdup("default");
		if (policy_id == NULL)
			return NULL;
	}

	snprintf(fname, sizeof(fname), "%s/spp/policy/%s.xml",
		 ctx->root_dir, policy_id);
	free(policy_id);
	debug_print(ctx, 1, "Use policy file %s", fname);

	policy = node_from_file(ctx->xml, fname);
	if (policy == NULL)
		return NULL;

	node = get_node_uri(ctx->xml, policy, "Policy/PolicyUpdate/URI");
	if (node) {
		char *url;
		url = db_get_osu_config_val(ctx, realm, "policy_url");
		if (url == NULL) {
			xml_node_free(ctx->xml, policy);
			return NULL;
		}
		xml_node_set_text(ctx->xml, node, url);
		free(url);
	}

	node = get_node_uri(ctx->xml, policy, "Policy/PolicyUpdate");
	if (node && use_dmacc) {
		char *pw;
		pw = db_get_val(ctx, user, realm, "osu_password", use_dmacc);
		if (pw == NULL ||
		    build_username_password(ctx, node, user, pw) == NULL) {
			debug_print(ctx, 1, "Failed to add Policy/PolicyUpdate/"
				    "UsernamePassword");
			free(pw);
			xml_node_free(ctx->xml, policy);
			return NULL;
		}
		free(pw);
	}

	return policy;
}


static xml_node_t * hs20_policy_update(struct hs20_svc *ctx,
				       const char *user, const char *realm,
				       const char *session_id, int dmacc)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node;
	xml_node_t *policy;
	char buf[400];
	const char *status;
	char *identity;

	identity = db_get_val(ctx, user, realm, "identity", dmacc);
	if (identity == NULL || strlen(identity) == 0) {
		hs20_eventlog(ctx, user, realm, session_id,
			      "user not found in database for policy update",
			      NULL);
		os_free(identity);
		return build_post_dev_data_response(ctx, NULL, session_id,
						    "Error occurred",
						    "Not found");
	}
	os_free(identity);

	policy = build_policy(ctx, user, realm, dmacc);
	if (!policy) {
		return build_post_dev_data_response(
			ctx, NULL, session_id,
			"No update available at this time", NULL);
	}

	db_add_session(ctx, user, realm, session_id, NULL, NULL, POLICY_UPDATE);

	status = "Update complete, request sppUpdateResponse";
	spp_node = build_post_dev_data_response(ctx, &ns, session_id, status,
						NULL);
	if (spp_node == NULL)
		return NULL;

	snprintf(buf, sizeof(buf),
		 "./Wi-Fi/%s/PerProviderSubscription/Credential1/Policy",
		 realm);

	if (add_update_node(ctx, spp_node, ns, buf, policy) < 0) {
		xml_node_free(ctx->xml, spp_node);
		xml_node_free(ctx->xml, policy);
		return NULL;
	}

	hs20_eventlog_node(ctx, user, realm, session_id, "policy update",
			   policy);
	xml_node_free(ctx->xml, policy);

	return spp_node;
}


static xml_node_t * spp_get_mo(struct hs20_svc *ctx, xml_node_t *node,
			       const char *urn, int *valid, char **ret_err)
{
	xml_node_t *child, *tnds, *mo;
	const char *name;
	char *mo_urn;
	char *str;
	char fname[200];

	*valid = -1;
	if (ret_err)
		*ret_err = NULL;

	xml_node_for_each_child(ctx->xml, child, node) {
		xml_node_for_each_check(ctx->xml, child);
		name = xml_node_get_localname(ctx->xml, child);
		if (strcmp(name, "moContainer") != 0)
			continue;
		mo_urn = xml_node_get_attr_value_ns(ctx->xml, child, SPP_NS_URI,
						    "moURN");
		if (strcasecmp(urn, mo_urn) == 0) {
			xml_node_get_attr_value_free(ctx->xml, mo_urn);
			break;
		}
		xml_node_get_attr_value_free(ctx->xml, mo_urn);
	}

	if (child == NULL)
		return NULL;

	debug_print(ctx, 1, "moContainer text for %s", urn);
	debug_dump_node(ctx, "moContainer", child);

	str = xml_node_get_text(ctx->xml, child);
	debug_print(ctx, 1, "moContainer payload: '%s'", str);
	tnds = xml_node_from_buf(ctx->xml, str);
	xml_node_get_text_free(ctx->xml, str);
	if (tnds == NULL) {
		debug_print(ctx, 1, "could not parse moContainer text");
		return NULL;
	}

	snprintf(fname, sizeof(fname), "%s/spp/dm_ddf-v1_2.dtd", ctx->root_dir);
	if (xml_validate_dtd(ctx->xml, tnds, fname, ret_err) == 0)
		*valid = 1;
	else if (ret_err && *ret_err &&
		 os_strcmp(*ret_err, "No declaration for attribute xmlns of element MgmtTree\n") == 0) {
		free(*ret_err);
		debug_print(ctx, 1, "Ignore OMA-DM DDF DTD validation error for MgmtTree namespace declaration with xmlns attribute");
		*ret_err = NULL;
		*valid = 1;
	} else
		*valid = 0;

	mo = tnds_to_mo(ctx->xml, tnds);
	xml_node_free(ctx->xml, tnds);
	if (mo == NULL) {
		debug_print(ctx, 1, "invalid moContainer for %s", urn);
	}

	return mo;
}


static xml_node_t * spp_exec_upload_mo(struct hs20_svc *ctx,
				       const char *session_id, const char *urn)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *node, *exec_node;

	spp_node = build_post_dev_data_response(ctx, &ns, session_id, "OK",
						NULL);
	if (spp_node == NULL)
		return NULL;

	exec_node = xml_node_create(ctx->xml, spp_node, ns, "exec");

	node = xml_node_create(ctx->xml, exec_node, ns, "uploadMO");
	xml_node_add_attr(ctx->xml, node, ns, "moURN", urn);

	return spp_node;
}


static xml_node_t * hs20_subscription_registration(struct hs20_svc *ctx,
						   const char *realm,
						   const char *session_id,
						   const char *redirect_uri)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *exec_node;
	char uri[300], *val;

	if (db_add_session(ctx, NULL, realm, session_id, NULL, redirect_uri,
			   SUBSCRIPTION_REGISTRATION) < 0)
		return NULL;
	val = db_get_osu_config_val(ctx, realm, "signup_url");
	if (val == NULL)
		return NULL;

	spp_node = build_post_dev_data_response(ctx, &ns, session_id, "OK",
						NULL);
	if (spp_node == NULL)
		return NULL;

	exec_node = xml_node_create(ctx->xml, spp_node, ns, "exec");

	snprintf(uri, sizeof(uri), "%s%s", val, session_id);
	os_free(val);
	xml_node_create_text(ctx->xml, exec_node, ns, "launchBrowserToURI",
			     uri);
	return spp_node;
}


static xml_node_t * hs20_user_input_remediation(struct hs20_svc *ctx,
						const char *user,
						const char *realm, int dmacc,
						const char *session_id)
{
	return build_sub_rem_resp(ctx, user, realm, session_id, 0, dmacc);
}


static char * db_get_osu_config_val(struct hs20_svc *ctx, const char *realm,
				    const char *field)
{
	char *cmd;
	struct get_db_field_data data;

	cmd = sqlite3_mprintf("SELECT value FROM osu_config WHERE realm=%Q AND "
			      "field=%Q", realm, field);
	if (cmd == NULL)
		return NULL;
	debug_print(ctx, 1, "DB: %s", cmd);
	memset(&data, 0, sizeof(data));
	data.field = "value";
	if (sqlite3_exec(ctx->db, cmd, get_db_field, &data, NULL) != SQLITE_OK)
	{
		debug_print(ctx, 1, "DB: Could not find osu_config %s: %s",
			    realm, sqlite3_errmsg(ctx->db));
		sqlite3_free(cmd);
		return NULL;
	}
	sqlite3_free(cmd);

	debug_print(ctx, 1, "DB: return '%s'", data.value);
	return data.value;
}


static xml_node_t * build_pps(struct hs20_svc *ctx,
			      const char *user, const char *realm,
			      const char *pw, const char *cert,
			      int machine_managed)
{
	xml_node_t *pps, *c, *trust, *aaa, *aaa1, *upd, *homesp;
	xml_node_t *cred, *eap, *userpw;

	pps = xml_node_create_root(ctx->xml, NULL, NULL, NULL,
				   "PerProviderSubscription");
	if (pps == NULL)
		return NULL;

	add_text_node(ctx, pps, "UpdateIdentifier", "1");

	c = xml_node_create(ctx->xml, pps, NULL, "Credential1");

	add_text_node(ctx, c, "CredentialPriority", "1");

	aaa = xml_node_create(ctx->xml, c, NULL, "AAAServerTrustRoot");
	aaa1 = xml_node_create(ctx->xml, aaa, NULL, "AAA1");
	add_text_node_conf(ctx, realm, aaa1, "CertURL",
			   "aaa_trust_root_cert_url");
	add_text_node_conf(ctx, realm, aaa1, "CertSHA256Fingerprint",
			   "aaa_trust_root_cert_fingerprint");

	upd = xml_node_create(ctx->xml, c, NULL, "SubscriptionUpdate");
	add_text_node(ctx, upd, "UpdateInterval", "4294967295");
	add_text_node(ctx, upd, "UpdateMethod", "ClientInitiated");
	add_text_node(ctx, upd, "Restriction", "HomeSP");
	add_text_node_conf(ctx, realm, upd, "URI", "spp_http_auth_url");
	trust = xml_node_create(ctx->xml, upd, NULL, "TrustRoot");
	add_text_node_conf(ctx, realm, trust, "CertURL", "trust_root_cert_url");
	add_text_node_conf(ctx, realm, trust, "CertSHA256Fingerprint",
			   "trust_root_cert_fingerprint");

	homesp = xml_node_create(ctx->xml, c, NULL, "HomeSP");
	add_text_node_conf(ctx, realm, homesp, "FriendlyName", "friendly_name");
	add_text_node_conf(ctx, realm, homesp, "FQDN", "fqdn");

	xml_node_create(ctx->xml, c, NULL, "SubscriptionParameters");

	cred = xml_node_create(ctx->xml, c, NULL, "Credential");
	add_creation_date(ctx, cred);
	if (cert) {
		xml_node_t *dc;
		dc = xml_node_create(ctx->xml, cred, NULL,
				     "DigitalCertificate");
		add_text_node(ctx, dc, "CertificateType", "x509v3");
		add_text_node(ctx, dc, "CertSHA256Fingerprint", cert);
	} else {
		userpw = build_username_password(ctx, cred, user, pw);
		add_text_node(ctx, userpw, "MachineManaged",
			      machine_managed ? "TRUE" : "FALSE");
		eap = xml_node_create(ctx->xml, userpw, NULL, "EAPMethod");
		add_text_node(ctx, eap, "EAPType", "21");
		add_text_node(ctx, eap, "InnerMethod", "MS-CHAP-V2");
	}
	add_text_node(ctx, cred, "Realm", realm);

	return pps;
}


static xml_node_t * spp_exec_get_certificate(struct hs20_svc *ctx,
					     const char *session_id,
					     const char *user,
					     const char *realm)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *enroll, *exec_node;
	char *val;
	char password[11];
	char *b64;

	if (new_password(password, sizeof(password)) < 0)
		return NULL;

	spp_node = build_post_dev_data_response(ctx, &ns, session_id, "OK",
						NULL);
	if (spp_node == NULL)
		return NULL;

	exec_node = xml_node_create(ctx->xml, spp_node, ns, "exec");

	enroll = xml_node_create(ctx->xml, exec_node, ns, "getCertificate");
	xml_node_add_attr(ctx->xml, enroll, NULL, "enrollmentProtocol", "EST");

	val = db_get_osu_config_val(ctx, realm, "est_url");
	xml_node_create_text(ctx->xml, enroll, ns, "enrollmentServerURI",
			     val ? val : "");
	os_free(val);
	xml_node_create_text(ctx->xml, enroll, ns, "estUserID", user);

	b64 = (char *) base64_encode((unsigned char *) password,
				     strlen(password), NULL);
	if (b64 == NULL) {
		xml_node_free(ctx->xml, spp_node);
		return NULL;
	}
	xml_node_create_text(ctx->xml, enroll, ns, "estPassword", b64);
	free(b64);

	db_update_session_password(ctx, user, realm, session_id, password);

	return spp_node;
}


static xml_node_t * hs20_user_input_registration(struct hs20_svc *ctx,
						 const char *session_id,
						 int enrollment_done)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *node = NULL;
	xml_node_t *pps, *tnds;
	char buf[400];
	char *str;
	char *user, *realm, *pw, *type, *mm;
	const char *status;
	int cert = 0;
	int machine_managed = 0;
	char *fingerprint;

	user = db_get_session_val(ctx, NULL, NULL, session_id, "user");
	realm = db_get_session_val(ctx, NULL, NULL, session_id, "realm");
	pw = db_get_session_val(ctx, NULL, NULL, session_id, "password");

	if (!user || !realm || !pw) {
		debug_print(ctx, 1, "Could not find session info from DB for "
			    "the new subscription");
		free(user);
		free(realm);
		free(pw);
		return NULL;
	}

	mm = db_get_session_val(ctx, NULL, NULL, session_id, "machine_managed");
	if (mm && atoi(mm))
		machine_managed = 1;
	free(mm);

	type = db_get_session_val(ctx, NULL, NULL, session_id, "type");
	if (type && strcmp(type, "cert") == 0)
		cert = 1;
	free(type);

	if (cert && !enrollment_done) {
		xml_node_t *ret;
		hs20_eventlog(ctx, user, realm, session_id,
			      "request client certificate enrollment", NULL);
		ret = spp_exec_get_certificate(ctx, session_id, user, realm);
		free(user);
		free(realm);
		free(pw);
		return ret;
	}

	if (!cert && strlen(pw) == 0) {
		machine_managed = 1;
		free(pw);
		pw = malloc(11);
		if (pw == NULL || new_password(pw, 11) < 0) {
			free(user);
			free(realm);
			free(pw);
			return NULL;
		}
	}

	status = "Provisioning complete, request sppUpdateResponse";
	spp_node = build_post_dev_data_response(ctx, &ns, session_id, status,
						NULL);
	if (spp_node == NULL)
		return NULL;

	fingerprint = db_get_session_val(ctx, NULL, NULL, session_id, "cert");
	pps = build_pps(ctx, user, realm, pw,
			fingerprint ? fingerprint : NULL, machine_managed);
	free(fingerprint);
	if (!pps) {
		xml_node_free(ctx->xml, spp_node);
		free(user);
		free(realm);
		free(pw);
		return NULL;
	}

	debug_print(ctx, 1, "Request DB subscription registration on success "
		    "notification");
	db_add_session_pps(ctx, user, realm, session_id, pps);

	hs20_eventlog_node(ctx, user, realm, session_id,
			   "new subscription", pps);
	free(user);
	free(pw);

	tnds = mo_to_tnds(ctx->xml, pps, 0, URN_HS20_PPS, NULL);
	xml_node_free(ctx->xml, pps);
	if (!tnds) {
		xml_node_free(ctx->xml, spp_node);
		free(realm);
		return NULL;
	}

	str = xml_node_to_str(ctx->xml, tnds);
	xml_node_free(ctx->xml, tnds);
	if (str == NULL) {
		xml_node_free(ctx->xml, spp_node);
		free(realm);
		return NULL;
	}

	node = xml_node_create_text(ctx->xml, spp_node, ns, "addMO", str);
	free(str);
	snprintf(buf, sizeof(buf), "./Wi-Fi/%s/PerProviderSubscription", realm);
	free(realm);
	xml_node_add_attr(ctx->xml, node, ns, "managementTreeURI", buf);
	xml_node_add_attr(ctx->xml, node, ns, "moURN", URN_HS20_PPS);

	return spp_node;
}


static xml_node_t * hs20_user_input_free_remediation(struct hs20_svc *ctx,
						     const char *user,
						     const char *realm,
						     const char *session_id)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node;
	xml_node_t *cred;
	char buf[400];
	char *status;
	char *free_account, *pw;

	free_account = db_get_osu_config_val(ctx, realm, "free_account");
	if (free_account == NULL)
		return NULL;
	pw = db_get_val(ctx, free_account, realm, "password", 0);
	if (pw == NULL) {
		free(free_account);
		return NULL;
	}

	cred = build_credential_pw(ctx, free_account, realm, pw);
	free(free_account);
	free(pw);
	if (!cred) {
		xml_node_free(ctx->xml, cred);
		return NULL;
	}

	status = "Remediation complete, request sppUpdateResponse";
	spp_node = build_post_dev_data_response(ctx, &ns, session_id, status,
						NULL);
	if (spp_node == NULL)
		return NULL;

	snprintf(buf, sizeof(buf),
		 "./Wi-Fi/%s/PerProviderSubscription/Credential1/Credential",
		 realm);

	if (add_update_node(ctx, spp_node, ns, buf, cred) < 0) {
		xml_node_free(ctx->xml, spp_node);
		return NULL;
	}

	hs20_eventlog_node(ctx, user, realm, session_id,
			   "free/public remediation", cred);
	xml_node_free(ctx->xml, cred);

	return spp_node;
}


static xml_node_t * hs20_user_input_complete(struct hs20_svc *ctx,
					     const char *user,
					     const char *realm, int dmacc,
					     const char *session_id)
{
	char *val;
	enum hs20_session_operation oper;

	val = db_get_session_val(ctx, user, realm, session_id, "operation");
	if (val == NULL) {
		debug_print(ctx, 1, "No session %s found to continue",
			    session_id);
		return NULL;
	}
	oper = atoi(val);
	free(val);

	if (oper == USER_REMEDIATION) {
		return hs20_user_input_remediation(ctx, user, realm, dmacc,
						   session_id);
	}

	if (oper == FREE_REMEDIATION) {
		return hs20_user_input_free_remediation(ctx, user, realm,
							session_id);
	}

	if (oper == SUBSCRIPTION_REGISTRATION) {
		return hs20_user_input_registration(ctx, session_id, 0);
	}

	debug_print(ctx, 1, "User session %s not in state for user input "
		    "completion", session_id);
	return NULL;
}


static xml_node_t * hs20_cert_enroll_completed(struct hs20_svc *ctx,
					       const char *user,
					       const char *realm, int dmacc,
					       const char *session_id)
{
	char *val;
	enum hs20_session_operation oper;

	val = db_get_session_val(ctx, user, realm, session_id, "operation");
	if (val == NULL) {
		debug_print(ctx, 1, "No session %s found to continue",
			    session_id);
		return NULL;
	}
	oper = atoi(val);
	free(val);

	if (oper == SUBSCRIPTION_REGISTRATION)
		return hs20_user_input_registration(ctx, session_id, 1);

	debug_print(ctx, 1, "User session %s not in state for certificate "
		    "enrollment completion", session_id);
	return NULL;
}


static xml_node_t * hs20_cert_enroll_failed(struct hs20_svc *ctx,
					    const char *user,
					    const char *realm, int dmacc,
					    const char *session_id)
{
	char *val;
	enum hs20_session_operation oper;
	xml_node_t *spp_node, *node;
	char *status;
	xml_namespace_t *ns;

	val = db_get_session_val(ctx, user, realm, session_id, "operation");
	if (val == NULL) {
		debug_print(ctx, 1, "No session %s found to continue",
			    session_id);
		return NULL;
	}
	oper = atoi(val);
	free(val);

	if (oper != SUBSCRIPTION_REGISTRATION) {
		debug_print(ctx, 1, "User session %s not in state for "
			    "enrollment failure", session_id);
		return NULL;
	}

	status = "Error occurred";
	spp_node = build_post_dev_data_response(ctx, &ns, session_id, status,
						NULL);
	if (spp_node == NULL)
		return NULL;
	node = xml_node_create(ctx->xml, spp_node, ns, "sppError");
	xml_node_add_attr(ctx->xml, node, NULL, "errorCode",
			  "Credentials cannot be provisioned at this time");
	db_remove_session(ctx, user, realm, session_id);

	return spp_node;
}


static xml_node_t * hs20_spp_post_dev_data(struct hs20_svc *ctx,
					   xml_node_t *node,
					   const char *user,
					   const char *realm,
					   const char *session_id,
					   int dmacc)
{
	const char *req_reason;
	char *redirect_uri = NULL;
	char *req_reason_buf = NULL;
	char str[200];
	xml_node_t *ret = NULL, *devinfo = NULL, *devdetail = NULL;
	xml_node_t *mo;
	char *version;
	int valid;
	char *supp, *pos;
	char *err;

	version = xml_node_get_attr_value_ns(ctx->xml, node, SPP_NS_URI,
					     "sppVersion");
	if (version == NULL || strstr(version, "1.0") == NULL) {
		ret = build_post_dev_data_response(
			ctx, NULL, session_id, "Error occurred",
			"SPP version not supported");
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "Unsupported sppVersion", ret);
		xml_node_get_attr_value_free(ctx->xml, version);
		return ret;
	}
	xml_node_get_attr_value_free(ctx->xml, version);

	mo = get_node(ctx->xml, node, "supportedMOList");
	if (mo == NULL) {
		ret = build_post_dev_data_response(
			ctx, NULL, session_id, "Error occurred",
			"Other");
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "No supportedMOList element", ret);
		return ret;
	}
	supp = xml_node_get_text(ctx->xml, mo);
	for (pos = supp; pos && *pos; pos++)
		*pos = tolower(*pos);
	if (supp == NULL ||
	    strstr(supp, URN_OMA_DM_DEVINFO) == NULL ||
	    strstr(supp, URN_OMA_DM_DEVDETAIL) == NULL ||
	    strstr(supp, URN_HS20_PPS) == NULL) {
		xml_node_get_text_free(ctx->xml, supp);
		ret = build_post_dev_data_response(
			ctx, NULL, session_id, "Error occurred",
			"One or more mandatory MOs not supported");
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "Unsupported MOs", ret);
		return ret;
	}
	xml_node_get_text_free(ctx->xml, supp);

	req_reason_buf = xml_node_get_attr_value(ctx->xml, node,
						 "requestReason");
	if (req_reason_buf == NULL) {
		debug_print(ctx, 1, "No requestReason attribute");
		return NULL;
	}
	req_reason = req_reason_buf;

	redirect_uri = xml_node_get_attr_value(ctx->xml, node, "redirectURI");

	debug_print(ctx, 1, "requestReason: %s  sessionID: %s  redirectURI: %s",
		    req_reason, session_id, redirect_uri);
	snprintf(str, sizeof(str), "sppPostDevData: requestReason=%s",
		 req_reason);
	hs20_eventlog(ctx, user, realm, session_id, str, NULL);

	devinfo = spp_get_mo(ctx, node, URN_OMA_DM_DEVINFO, &valid, &err);
	if (devinfo == NULL) {
		ret = build_post_dev_data_response(ctx, NULL, session_id,
						   "Error occurred", "Other");
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "No DevInfo moContainer in sppPostDevData",
				   ret);
		os_free(err);
		goto out;
	}

	hs20_eventlog_node(ctx, user, realm, session_id,
			   "Received DevInfo MO", devinfo);
	if (valid == 0) {
		hs20_eventlog(ctx, user, realm, session_id,
			      "OMA-DM DDF DTD validation errors in DevInfo MO",
			      err);
		ret = build_post_dev_data_response(ctx, NULL, session_id,
						   "Error occurred", "Other");
		os_free(err);
		goto out;
	}
	os_free(err);
	if (user)
		db_update_mo(ctx, user, realm, "devinfo", devinfo);

	devdetail = spp_get_mo(ctx, node, URN_OMA_DM_DEVDETAIL, &valid, &err);
	if (devdetail == NULL) {
		ret = build_post_dev_data_response(ctx, NULL, session_id,
						   "Error occurred", "Other");
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "No DevDetail moContainer in sppPostDevData",
				   ret);
		os_free(err);
		goto out;
	}

	hs20_eventlog_node(ctx, user, realm, session_id,
			   "Received DevDetail MO", devdetail);
	if (valid == 0) {
		hs20_eventlog(ctx, user, realm, session_id,
			      "OMA-DM DDF DTD validation errors "
			      "in DevDetail MO", err);
		ret = build_post_dev_data_response(ctx, NULL, session_id,
						   "Error occurred", "Other");
		os_free(err);
		goto out;
	}
	os_free(err);
	if (user)
		db_update_mo(ctx, user, realm, "devdetail", devdetail);

	if (user)
		mo = spp_get_mo(ctx, node, URN_HS20_PPS, &valid, &err);
	else {
		mo = NULL;
		err = NULL;
	}
	if (user && mo) {
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "Received PPS MO", mo);
		if (valid == 0) {
			hs20_eventlog(ctx, user, realm, session_id,
				      "OMA-DM DDF DTD validation errors "
				      "in PPS MO", err);
			xml_node_get_attr_value_free(ctx->xml, redirect_uri);
			os_free(err);
			return build_post_dev_data_response(
				ctx, NULL, session_id,
				"Error occurred", "Other");
		}
		db_update_mo(ctx, user, realm, "pps", mo);
		db_update_val(ctx, user, realm, "fetch_pps", "0", dmacc);
		xml_node_free(ctx->xml, mo);
	}
	os_free(err);

	if (user && !mo) {
		char *fetch;
		int fetch_pps;

		fetch = db_get_val(ctx, user, realm, "fetch_pps", dmacc);
		fetch_pps = fetch ? atoi(fetch) : 0;
		free(fetch);

		if (fetch_pps) {
			enum hs20_session_operation oper;
			if (strcasecmp(req_reason, "Subscription remediation")
			    == 0)
				oper = CONTINUE_SUBSCRIPTION_REMEDIATION;
			else if (strcasecmp(req_reason, "Policy update") == 0)
				oper = CONTINUE_POLICY_UPDATE;
			else
				oper = NO_OPERATION;
			if (db_add_session(ctx, user, realm, session_id, NULL,
					   NULL, oper) < 0)
				goto out;

			ret = spp_exec_upload_mo(ctx, session_id,
						 URN_HS20_PPS);
			hs20_eventlog_node(ctx, user, realm, session_id,
					   "request PPS MO upload",
					   ret);
			goto out;
		}
	}

	if (user && strcasecmp(req_reason, "MO upload") == 0) {
		char *val = db_get_session_val(ctx, user, realm, session_id,
					       "operation");
		enum hs20_session_operation oper;
		if (!val) {
			debug_print(ctx, 1, "No session %s found to continue",
				    session_id);
			goto out;
		}
		oper = atoi(val);
		free(val);
		if (oper == CONTINUE_SUBSCRIPTION_REMEDIATION)
			req_reason = "Subscription remediation";
		else if (oper == CONTINUE_POLICY_UPDATE)
			req_reason = "Policy update";
		else {
			debug_print(ctx, 1,
				    "No pending operation in session %s",
				    session_id);
			goto out;
		}
	}

	if (strcasecmp(req_reason, "Subscription registration") == 0) {
		ret = hs20_subscription_registration(ctx, realm, session_id,
						     redirect_uri);
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "subscription registration response",
				   ret);
		goto out;
	}
	if (user && strcasecmp(req_reason, "Subscription remediation") == 0) {
		ret = hs20_subscription_remediation(ctx, user, realm,
						    session_id, dmacc,
						    redirect_uri);
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "subscription remediation response",
				   ret);
		goto out;
	}
	if (user && strcasecmp(req_reason, "Policy update") == 0) {
		ret = hs20_policy_update(ctx, user, realm, session_id, dmacc);
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "policy update response",
				   ret);
		goto out;
	}

	if (strcasecmp(req_reason, "User input completed") == 0) {
		if (devinfo)
			db_add_session_devinfo(ctx, session_id, devinfo);
		if (devdetail)
			db_add_session_devdetail(ctx, session_id, devdetail);
		ret = hs20_user_input_complete(ctx, user, realm, dmacc,
					       session_id);
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "user input completed response", ret);
		goto out;
	}

	if (strcasecmp(req_reason, "Certificate enrollment completed") == 0) {
		ret = hs20_cert_enroll_completed(ctx, user, realm, dmacc,
						 session_id);
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "certificate enrollment response", ret);
		goto out;
	}

	if (strcasecmp(req_reason, "Certificate enrollment failed") == 0) {
		ret = hs20_cert_enroll_failed(ctx, user, realm, dmacc,
					      session_id);
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "certificate enrollment failed response",
				   ret);
		goto out;
	}

	debug_print(ctx, 1, "Unsupported requestReason '%s' user '%s'",
		    req_reason, user);
out:
	xml_node_get_attr_value_free(ctx->xml, req_reason_buf);
	xml_node_get_attr_value_free(ctx->xml, redirect_uri);
	if (devinfo)
		xml_node_free(ctx->xml, devinfo);
	if (devdetail)
		xml_node_free(ctx->xml, devdetail);
	return ret;
}


static xml_node_t * build_spp_exchange_complete(struct hs20_svc *ctx,
						const char *session_id,
						const char *status,
						const char *error_code)
{
	xml_namespace_t *ns;
	xml_node_t *spp_node, *node;

	spp_node = xml_node_create_root(ctx->xml, SPP_NS_URI, "spp", &ns,
					"sppExchangeComplete");


	xml_node_add_attr(ctx->xml, spp_node, ns, "sppVersion", "1.0");
	xml_node_add_attr(ctx->xml, spp_node, ns, "sessionID", session_id);
	xml_node_add_attr(ctx->xml, spp_node, ns, "sppStatus", status);

	if (error_code) {
		node = xml_node_create(ctx->xml, spp_node, ns, "sppError");
		xml_node_add_attr(ctx->xml, node, NULL, "errorCode",
				  error_code);
	}

	return spp_node;
}


static int add_subscription(struct hs20_svc *ctx, const char *session_id)
{
	char *user, *realm, *pw, *pw_mm, *pps, *str;
	char *sql;
	int ret = -1;
	char *free_account;
	int free_acc;
	char *type;
	int cert = 0;
	char *cert_pem, *fingerprint;

	user = db_get_session_val(ctx, NULL, NULL, session_id, "user");
	realm = db_get_session_val(ctx, NULL, NULL, session_id, "realm");
	pw = db_get_session_val(ctx, NULL, NULL, session_id, "password");
	pw_mm = db_get_session_val(ctx, NULL, NULL, session_id,
				   "machine_managed");
	pps = db_get_session_val(ctx, NULL, NULL, session_id, "pps");
	cert_pem = db_get_session_val(ctx, NULL, NULL, session_id, "cert_pem");
	fingerprint = db_get_session_val(ctx, NULL, NULL, session_id, "cert");
	type = db_get_session_val(ctx, NULL, NULL, session_id, "type");
	if (type && strcmp(type, "cert") == 0)
		cert = 1;
	free(type);

	if (!user || !realm || !pw) {
		debug_print(ctx, 1, "Could not find session info from DB for "
			    "the new subscription");
		goto out;
	}

	free_account = db_get_osu_config_val(ctx, realm, "free_account");
	free_acc = free_account && strcmp(free_account, user) == 0;
	free(free_account);

	debug_print(ctx, 1,
		    "New subscription: user='%s' realm='%s' free_acc=%d",
		    user, realm, free_acc);
	debug_print(ctx, 1, "New subscription: pps='%s'", pps);

	sql = sqlite3_mprintf("UPDATE eventlog SET user=%Q, realm=%Q WHERE "
			      "sessionid=%Q AND (user='' OR user IS NULL)",
			      user, realm, session_id);
	if (sql) {
		debug_print(ctx, 1, "DB: %s", sql);
		if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
			debug_print(ctx, 1, "Failed to update eventlog in "
				    "sqlite database: %s",
				    sqlite3_errmsg(ctx->db));
		}
		sqlite3_free(sql);
	}

	if (free_acc) {
		hs20_eventlog(ctx, user, realm, session_id,
			      "completed shared free account registration",
			      NULL);
		ret = 0;
		goto out;
	}

	sql = sqlite3_mprintf("INSERT INTO users(identity,realm,phase2,"
			      "methods,cert,cert_pem,machine_managed) VALUES "
			      "(%Q,%Q,1,%Q,%Q,%Q,%d)",
			      user, realm, cert ? "TLS" : "TTLS-MSCHAPV2",
			      fingerprint ? fingerprint : "",
			      cert_pem ? cert_pem : "",
			      pw_mm && atoi(pw_mm) ? 1 : 0);
	if (sql == NULL)
		goto out;
	debug_print(ctx, 1, "DB: %s", sql);
	if (sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		debug_print(ctx, 1, "Failed to add user in sqlite database: %s",
			    sqlite3_errmsg(ctx->db));
		sqlite3_free(sql);
		goto out;
	}
	sqlite3_free(sql);

	if (cert)
		ret = 0;
	else
		ret = update_password(ctx, user, realm, pw, 0);
	if (ret < 0) {
		sql = sqlite3_mprintf("DELETE FROM users WHERE identity=%Q AND "
				      "realm=%Q AND phase2=1",
				      user, realm);
		if (sql) {
			debug_print(ctx, 1, "DB: %s", sql);
			sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
			sqlite3_free(sql);
		}
	}

	if (pps)
		db_update_mo_str(ctx, user, realm, "pps", pps);

	str = db_get_session_val(ctx, NULL, NULL, session_id, "devinfo");
	if (str) {
		db_update_mo_str(ctx, user, realm, "devinfo", str);
		free(str);
	}

	str = db_get_session_val(ctx, NULL, NULL, session_id, "devdetail");
	if (str) {
		db_update_mo_str(ctx, user, realm, "devdetail", str);
		free(str);
	}

	if (ret == 0) {
		hs20_eventlog(ctx, user, realm, session_id,
			      "completed subscription registration", NULL);
	}

out:
	free(user);
	free(realm);
	free(pw);
	free(pw_mm);
	free(pps);
	free(cert_pem);
	free(fingerprint);
	return ret;
}


static xml_node_t * hs20_spp_update_response(struct hs20_svc *ctx,
					     xml_node_t *node,
					     const char *user,
					     const char *realm,
					     const char *session_id,
					     int dmacc)
{
	char *status;
	xml_node_t *ret;
	char *val;
	enum hs20_session_operation oper;

	status = xml_node_get_attr_value_ns(ctx->xml, node, SPP_NS_URI,
					    "sppStatus");
	if (status == NULL) {
		debug_print(ctx, 1, "No sppStatus attribute");
		return NULL;
	}

	debug_print(ctx, 1, "sppUpdateResponse: sppStatus: %s  sessionID: %s",
		    status, session_id);

	val = db_get_session_val(ctx, user, realm, session_id, "operation");
	if (!val) {
		debug_print(ctx, 1,
			    "No session active for user: %s  sessionID: %s",
			    user, session_id);
		oper = NO_OPERATION;
	} else
		oper = atoi(val);

	if (strcasecmp(status, "OK") == 0) {
		char *new_pw = NULL;

		xml_node_get_attr_value_free(ctx->xml, status);

		if (oper == USER_REMEDIATION) {
			new_pw = db_get_session_val(ctx, user, realm,
						    session_id, "password");
			if (new_pw == NULL || strlen(new_pw) == 0) {
				free(new_pw);
				ret = build_spp_exchange_complete(
					ctx, session_id, "Error occurred",
					"Other");
				hs20_eventlog_node(ctx, user, realm,
						   session_id, "No password "
						   "had been assigned for "
						   "session", ret);
				db_remove_session(ctx, user, realm, session_id);
				return ret;
			}
			oper = UPDATE_PASSWORD;
		}
		if (oper == UPDATE_PASSWORD) {
			if (!new_pw) {
				new_pw = db_get_session_val(ctx, user, realm,
							    session_id,
							    "password");
				if (!new_pw) {
					db_remove_session(ctx, user, realm,
							  session_id);
					return NULL;
				}
			}
			debug_print(ctx, 1, "Update user '%s' password in DB",
				    user);
			if (update_password(ctx, user, realm, new_pw, dmacc) <
			    0) {
				debug_print(ctx, 1, "Failed to update user "
					    "'%s' password in DB", user);
				ret = build_spp_exchange_complete(
					ctx, session_id, "Error occurred",
					"Other");
				hs20_eventlog_node(ctx, user, realm,
						   session_id, "Failed to "
						   "update database", ret);
				db_remove_session(ctx, user, realm, session_id);
				return ret;
			}
			hs20_eventlog(ctx, user, realm,
				      session_id, "Updated user password "
				      "in database", NULL);
		}
		if (oper == SUBSCRIPTION_REGISTRATION) {
			if (add_subscription(ctx, session_id) < 0) {
				debug_print(ctx, 1, "Failed to add "
					    "subscription into DB");
				ret = build_spp_exchange_complete(
					ctx, session_id, "Error occurred",
					"Other");
				hs20_eventlog_node(ctx, user, realm,
						   session_id, "Failed to "
						   "update database", ret);
				db_remove_session(ctx, user, realm, session_id);
				return ret;
			}
		}
		if (oper == POLICY_REMEDIATION || oper == POLICY_UPDATE) {
			char *val;
			val = db_get_val(ctx, user, realm, "remediation",
					 dmacc);
			if (val && strcmp(val, "policy") == 0)
				db_update_val(ctx, user, realm, "remediation",
					      "", dmacc);
			free(val);
		}
		ret = build_spp_exchange_complete(
			ctx, session_id,
			"Exchange complete, release TLS connection", NULL);
		hs20_eventlog_node(ctx, user, realm, session_id,
				   "Exchange completed", ret);
		db_remove_session(ctx, user, realm, session_id);
		return ret;
	}

	ret = build_spp_exchange_complete(ctx, session_id, "Error occurred",
					  "Other");
	hs20_eventlog_node(ctx, user, realm, session_id, "Error occurred", ret);
	db_remove_session(ctx, user, realm, session_id);
	xml_node_get_attr_value_free(ctx->xml, status);
	return ret;
}


#define SPP_SESSION_ID_LEN 16

static char * gen_spp_session_id(void)
{
	FILE *f;
	int i;
	char *session;

	session = os_malloc(SPP_SESSION_ID_LEN * 2 + 1);
	if (session == NULL)
		return NULL;

	f = fopen("/dev/urandom", "r");
	if (f == NULL) {
		os_free(session);
		return NULL;
	}
	for (i = 0; i < SPP_SESSION_ID_LEN; i++)
		os_snprintf(session + i * 2, 3, "%02x", fgetc(f));

	fclose(f);
	return session;
}

xml_node_t * hs20_spp_server_process(struct hs20_svc *ctx, xml_node_t *node,
				     const char *auth_user,
				     const char *auth_realm, int dmacc)
{
	xml_node_t *ret = NULL;
	char *session_id;
	const char *op_name;
	char *xml_err;
	char fname[200];

	debug_dump_node(ctx, "received request", node);

	if (!dmacc && auth_user && auth_realm) {
		char *real;
		real = db_get_val(ctx, auth_user, auth_realm, "identity", 0);
		if (!real) {
			real = db_get_val(ctx, auth_user, auth_realm,
					  "identity", 1);
			if (real)
				dmacc = 1;
		}
		os_free(real);
	}

	snprintf(fname, sizeof(fname), "%s/spp/spp.xsd", ctx->root_dir);
	if (xml_validate(ctx->xml, node, fname, &xml_err) < 0) {
		/*
		 * We may not be able to extract the sessionID from invalid
		 * input, but well, we can try.
		 */
		session_id = xml_node_get_attr_value_ns(ctx->xml, node,
							SPP_NS_URI,
							"sessionID");
		debug_print(ctx, 1, "SPP message failed validation");
		hs20_eventlog_node(ctx, auth_user, auth_realm, session_id,
				   "SPP message failed validation", node);
		hs20_eventlog(ctx, auth_user, auth_realm, session_id,
			      "Validation errors", xml_err);
		os_free(xml_err);
		xml_node_get_attr_value_free(ctx->xml, session_id);
		/* TODO: what to return here? */
		ret = xml_node_create_root(ctx->xml, NULL, NULL, NULL,
					   "SppValidationError");
		return ret;
	}

	session_id = xml_node_get_attr_value_ns(ctx->xml, node, SPP_NS_URI,
						"sessionID");
	if (session_id) {
		char *tmp;
		debug_print(ctx, 1, "Received sessionID %s", session_id);
		tmp = os_strdup(session_id);
		xml_node_get_attr_value_free(ctx->xml, session_id);
		if (tmp == NULL)
			return NULL;
		session_id = tmp;
	} else {
		session_id = gen_spp_session_id();
		if (session_id == NULL) {
			debug_print(ctx, 1, "Failed to generate sessionID");
			return NULL;
		}
		debug_print(ctx, 1, "Generated sessionID %s", session_id);
	}

	op_name = xml_node_get_localname(ctx->xml, node);
	if (op_name == NULL) {
		debug_print(ctx, 1, "Could not get op_name");
		return NULL;
	}

	if (strcmp(op_name, "sppPostDevData") == 0) {
		hs20_eventlog_node(ctx, auth_user, auth_realm, session_id,
				   "sppPostDevData received and validated",
				   node);
		ret = hs20_spp_post_dev_data(ctx, node, auth_user, auth_realm,
					     session_id, dmacc);
	} else if (strcmp(op_name, "sppUpdateResponse") == 0) {
		hs20_eventlog_node(ctx, auth_user, auth_realm, session_id,
				   "sppUpdateResponse received and validated",
				   node);
		ret = hs20_spp_update_response(ctx, node, auth_user,
					       auth_realm, session_id, dmacc);
	} else {
		hs20_eventlog_node(ctx, auth_user, auth_realm, session_id,
				   "Unsupported SPP message received and "
				   "validated", node);
		debug_print(ctx, 1, "Unsupported operation '%s'", op_name);
		/* TODO: what to return here? */
		ret = xml_node_create_root(ctx->xml, NULL, NULL, NULL,
					   "SppUnknownCommandError");
	}
	os_free(session_id);

	if (ret == NULL) {
		/* TODO: what to return here? */
		ret = xml_node_create_root(ctx->xml, NULL, NULL, NULL,
					   "SppInternalError");
	}

	return ret;
}


int hs20_spp_server_init(struct hs20_svc *ctx)
{
	char fname[200];
	ctx->db = NULL;
	snprintf(fname, sizeof(fname), "%s/AS/DB/eap_user.db", ctx->root_dir);
	if (sqlite3_open(fname, &ctx->db)) {
		printf("Failed to open sqlite database: %s\n",
		       sqlite3_errmsg(ctx->db));
		sqlite3_close(ctx->db);
		return -1;
	}

	return 0;
}


void hs20_spp_server_deinit(struct hs20_svc *ctx)
{
	sqlite3_close(ctx->db);
	ctx->db = NULL;
}
