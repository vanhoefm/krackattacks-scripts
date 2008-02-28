/*
 * EAP peer method: EAP-AKA (RFC 4187)
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
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
#include "eap_peer/eap_i.h"
#include "pcsc_funcs.h"
#include "eap_common/eap_sim_common.h"
#include "sha1.h"
#include "crypto.h"


struct eap_aka_data {
	u8 ik[EAP_AKA_IK_LEN], ck[EAP_AKA_CK_LEN], res[EAP_AKA_RES_MAX_LEN];
	size_t res_len;
	u8 nonce_s[EAP_SIM_NONCE_S_LEN];
	u8 mk[EAP_SIM_MK_LEN];
	u8 k_aut[EAP_SIM_K_AUT_LEN];
	u8 k_encr[EAP_SIM_K_ENCR_LEN];
	u8 msk[EAP_SIM_KEYING_DATA_LEN];
	u8 emsk[EAP_EMSK_LEN];
	u8 rand[EAP_AKA_RAND_LEN], autn[EAP_AKA_AUTN_LEN];
	u8 auts[EAP_AKA_AUTS_LEN];

	int num_id_req, num_notification;
	u8 *pseudonym;
	size_t pseudonym_len;
	u8 *reauth_id;
	size_t reauth_id_len;
	int reauth;
	unsigned int counter, counter_too_small;
	u8 *last_eap_identity;
	size_t last_eap_identity_len;
	enum {
		CONTINUE, RESULT_SUCCESS, RESULT_FAILURE, SUCCESS, FAILURE
	} state;

	struct wpabuf *id_msgs;
	int prev_id;
	int result_ind, use_result_ind;
};


#ifndef CONFIG_NO_STDOUT_DEBUG
static const char * eap_aka_state_txt(int state)
{
	switch (state) {
	case CONTINUE:
		return "CONTINUE";
	case RESULT_SUCCESS:
		return "RESULT_SUCCESS";
	case RESULT_FAILURE:
		return "RESULT_FAILURE";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}
#endif /* CONFIG_NO_STDOUT_DEBUG */


static void eap_aka_state(struct eap_aka_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-AKA: %s -> %s",
		   eap_aka_state_txt(data->state),
		   eap_aka_state_txt(state));
	data->state = state;
}


static void * eap_aka_init(struct eap_sm *sm)
{
	struct eap_aka_data *data;
	const char *phase1 = eap_get_config_phase1(sm);

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;

	eap_aka_state(data, CONTINUE);
	data->prev_id = -1;

	data->result_ind = phase1 && os_strstr(phase1, "result_ind=1") != NULL;

	return data;
}


static void eap_aka_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_aka_data *data = priv;
	if (data) {
		os_free(data->pseudonym);
		os_free(data->reauth_id);
		os_free(data->last_eap_identity);
		wpabuf_free(data->id_msgs);
		os_free(data);
	}
}


static int eap_aka_umts_auth(struct eap_sm *sm, struct eap_aka_data *data)
{
	wpa_printf(MSG_DEBUG, "EAP-AKA: UMTS authentication algorithm");
#ifdef PCSC_FUNCS
	return scard_umts_auth(sm->scard_ctx, data->rand,
			       data->autn, data->res, &data->res_len,
			       data->ik, data->ck, data->auts);
#else /* PCSC_FUNCS */
	/* These hardcoded Kc and SRES values are used for testing.
	 * Could consider making them configurable. */
	os_memset(data->res, '2', EAP_AKA_RES_MAX_LEN);
	data->res_len = EAP_AKA_RES_MAX_LEN;
	os_memset(data->ik, '3', EAP_AKA_IK_LEN);
	os_memset(data->ck, '4', EAP_AKA_CK_LEN);
	{
		u8 autn[EAP_AKA_AUTN_LEN];
		os_memset(autn, '1', EAP_AKA_AUTN_LEN);
		if (os_memcmp(autn, data->autn, EAP_AKA_AUTN_LEN) != 0) {
			wpa_printf(MSG_WARNING, "EAP-AKA: AUTN did not match "
				   "with expected value");
			return -1;
		}
	}
#if 0
	{
		static int test_resync = 1;
		if (test_resync) {
			/* Test Resynchronization */
			test_resync = 0;
			return -2;
		}
	}
#endif
	return 0;
#endif /* PCSC_FUNCS */
}


#define CLEAR_PSEUDONYM	0x01
#define CLEAR_REAUTH_ID	0x02
#define CLEAR_EAP_ID	0x04

static void eap_aka_clear_identities(struct eap_aka_data *data, int id)
{
	wpa_printf(MSG_DEBUG, "EAP-AKA: forgetting old%s%s%s",
		   id & CLEAR_PSEUDONYM ? " pseudonym" : "",
		   id & CLEAR_REAUTH_ID ? " reauth_id" : "",
		   id & CLEAR_EAP_ID ? " eap_id" : "");
	if (id & CLEAR_PSEUDONYM) {
		os_free(data->pseudonym);
		data->pseudonym = NULL;
		data->pseudonym_len = 0;
	}
	if (id & CLEAR_REAUTH_ID) {
		os_free(data->reauth_id);
		data->reauth_id = NULL;
		data->reauth_id_len = 0;
	}
	if (id & CLEAR_EAP_ID) {
		os_free(data->last_eap_identity);
		data->last_eap_identity = NULL;
		data->last_eap_identity_len = 0;
	}
}


static int eap_aka_learn_ids(struct eap_aka_data *data,
			     struct eap_sim_attrs *attr)
{
	if (attr->next_pseudonym) {
		os_free(data->pseudonym);
		data->pseudonym = os_malloc(attr->next_pseudonym_len);
		if (data->pseudonym == NULL) {
			wpa_printf(MSG_INFO, "EAP-AKA: (encr) No memory for "
				   "next pseudonym");
			return -1;
		}
		os_memcpy(data->pseudonym, attr->next_pseudonym,
			  attr->next_pseudonym_len);
		data->pseudonym_len = attr->next_pseudonym_len;
		wpa_hexdump_ascii(MSG_DEBUG,
				  "EAP-AKA: (encr) AT_NEXT_PSEUDONYM",
				  data->pseudonym,
				  data->pseudonym_len);
	}

	if (attr->next_reauth_id) {
		os_free(data->reauth_id);
		data->reauth_id = os_malloc(attr->next_reauth_id_len);
		if (data->reauth_id == NULL) {
			wpa_printf(MSG_INFO, "EAP-AKA: (encr) No memory for "
				   "next reauth_id");
			return -1;
		}
		os_memcpy(data->reauth_id, attr->next_reauth_id,
			  attr->next_reauth_id_len);
		data->reauth_id_len = attr->next_reauth_id_len;
		wpa_hexdump_ascii(MSG_DEBUG,
				  "EAP-AKA: (encr) AT_NEXT_REAUTH_ID",
				  data->reauth_id,
				  data->reauth_id_len);
	}

	return 0;
}


static int eap_aka_add_id_msg(struct eap_aka_data *data,
			      const struct wpabuf *msg)
{
	if (msg == NULL)
		return -1;

	if (data->id_msgs == NULL) {
		data->id_msgs = wpabuf_dup(msg);
		return data->id_msgs == NULL ? -1 : 0;
	}

	if (wpabuf_resize(&data->id_msgs, wpabuf_len(msg)) < 0)
		return -1;
	wpabuf_put_buf(data->id_msgs, msg);

	return 0;
}


static void eap_aka_add_checkcode(struct eap_aka_data *data,
				  struct eap_sim_msg *msg)
{
	const u8 *addr;
	size_t len;
	u8 hash[SHA1_MAC_LEN];

	wpa_printf(MSG_DEBUG, "   AT_CHECKCODE");

	if (data->id_msgs == NULL) {
		/*
		 * No EAP-AKA/Identity packets were exchanged - send empty
		 * checkcode.
		 */
		eap_sim_msg_add(msg, EAP_SIM_AT_CHECKCODE, 0, NULL, 0);
		return;
	}

	/* Checkcode is SHA1 hash over all EAP-AKA/Identity packets. */
	addr = wpabuf_head(data->id_msgs);
	len = wpabuf_len(data->id_msgs);
	wpa_hexdump(MSG_MSGDUMP, "EAP-AKA: AT_CHECKCODE data", addr, len);
	sha1_vector(1, &addr, &len, hash);

	eap_sim_msg_add(msg, EAP_SIM_AT_CHECKCODE, 0, hash,
			EAP_AKA_CHECKCODE_LEN);
}


static int eap_aka_verify_checkcode(struct eap_aka_data *data,
				    const u8 *checkcode, size_t checkcode_len)
{
	const u8 *addr;
	size_t len;
	u8 hash[SHA1_MAC_LEN];

	if (checkcode == NULL)
		return -1;

	if (data->id_msgs == NULL) {
		if (checkcode_len != 0) {
			wpa_printf(MSG_DEBUG, "EAP-AKA: Checkcode from server "
				   "indicates that AKA/Identity messages were "
				   "used, but they were not");
			return -1;
		}
		return 0;
	}

	if (checkcode_len != EAP_AKA_CHECKCODE_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-AKA: Checkcode from server "
			   "indicates that AKA/Identity message were not "
			   "used, but they were");
		return -1;
	}

	/* Checkcode is SHA1 hash over all EAP-AKA/Identity packets. */
	addr = wpabuf_head(data->id_msgs);
	len = wpabuf_len(data->id_msgs);
	sha1_vector(1, &addr, &len, hash);

	if (os_memcmp(hash, checkcode, EAP_AKA_CHECKCODE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "EAP-AKA: Mismatch in AT_CHECKCODE");
		return -1;
	}

	return 0;
}


static struct wpabuf * eap_aka_client_error(struct eap_aka_data *data, u8 id,
					    int err)
{
	struct eap_sim_msg *msg;

	eap_aka_state(data, FAILURE);
	data->num_id_req = 0;
	data->num_notification = 0;

	msg = eap_sim_msg_init(EAP_CODE_RESPONSE, id, EAP_TYPE_AKA,
			       EAP_AKA_SUBTYPE_CLIENT_ERROR);
	eap_sim_msg_add(msg, EAP_SIM_AT_CLIENT_ERROR_CODE, err, NULL, 0);
	return eap_sim_msg_finish(msg, NULL, NULL, 0);
}


static struct wpabuf * eap_aka_authentication_reject(struct eap_aka_data *data,
						     u8 id)
{
	struct eap_sim_msg *msg;

	eap_aka_state(data, FAILURE);
	data->num_id_req = 0;
	data->num_notification = 0;

	wpa_printf(MSG_DEBUG, "Generating EAP-AKA Authentication-Reject "
		   "(id=%d)", id);
	msg = eap_sim_msg_init(EAP_CODE_RESPONSE, id, EAP_TYPE_AKA,
			       EAP_AKA_SUBTYPE_AUTHENTICATION_REJECT);
	return eap_sim_msg_finish(msg, NULL, NULL, 0);
}


static struct wpabuf * eap_aka_synchronization_failure(
	struct eap_aka_data *data, u8 id)
{
	struct eap_sim_msg *msg;

	data->num_id_req = 0;
	data->num_notification = 0;

	wpa_printf(MSG_DEBUG, "Generating EAP-AKA Synchronization-Failure "
		   "(id=%d)", id);
	msg = eap_sim_msg_init(EAP_CODE_RESPONSE, id, EAP_TYPE_AKA,
			       EAP_AKA_SUBTYPE_SYNCHRONIZATION_FAILURE);
	wpa_printf(MSG_DEBUG, "   AT_AUTS");
	eap_sim_msg_add_full(msg, EAP_SIM_AT_AUTS, data->auts,
			     EAP_AKA_AUTS_LEN);
	return eap_sim_msg_finish(msg, NULL, NULL, 0);
}


static struct wpabuf * eap_aka_response_identity(struct eap_sm *sm,
						 struct eap_aka_data *data,
						 u8 id,
						 enum eap_sim_id_req id_req)
{
	const u8 *identity = NULL;
	size_t identity_len = 0;
	struct eap_sim_msg *msg;

	data->reauth = 0;
	if (id_req == ANY_ID && data->reauth_id) {
		identity = data->reauth_id;
		identity_len = data->reauth_id_len;
		data->reauth = 1;
	} else if ((id_req == ANY_ID || id_req == FULLAUTH_ID) &&
		   data->pseudonym) {
		identity = data->pseudonym;
		identity_len = data->pseudonym_len;
		eap_aka_clear_identities(data, CLEAR_REAUTH_ID);
	} else if (id_req != NO_ID_REQ) {
		identity = eap_get_config_identity(sm, &identity_len);
		if (identity) {
			eap_aka_clear_identities(data, CLEAR_PSEUDONYM |
						 CLEAR_REAUTH_ID);
		}
	}
	if (id_req != NO_ID_REQ)
		eap_aka_clear_identities(data, CLEAR_EAP_ID);

	wpa_printf(MSG_DEBUG, "Generating EAP-AKA Identity (id=%d)", id);
	msg = eap_sim_msg_init(EAP_CODE_RESPONSE, id, EAP_TYPE_AKA,
			       EAP_AKA_SUBTYPE_IDENTITY);

	if (identity) {
		wpa_hexdump_ascii(MSG_DEBUG, "   AT_IDENTITY",
				  identity, identity_len);
		eap_sim_msg_add(msg, EAP_SIM_AT_IDENTITY, identity_len,
				identity, identity_len);
	}

	return eap_sim_msg_finish(msg, NULL, NULL, 0);
}


static struct wpabuf * eap_aka_response_challenge(struct eap_aka_data *data,
						  u8 id)
{
	struct eap_sim_msg *msg;

	wpa_printf(MSG_DEBUG, "Generating EAP-AKA Challenge (id=%d)", id);
	msg = eap_sim_msg_init(EAP_CODE_RESPONSE, id, EAP_TYPE_AKA,
			       EAP_AKA_SUBTYPE_CHALLENGE);
	wpa_printf(MSG_DEBUG, "   AT_RES");
	eap_sim_msg_add(msg, EAP_SIM_AT_RES, data->res_len,
			data->res, data->res_len);
	eap_aka_add_checkcode(data, msg);
	if (data->use_result_ind) {
		wpa_printf(MSG_DEBUG, "   AT_RESULT_IND");
		eap_sim_msg_add(msg, EAP_SIM_AT_RESULT_IND, 0, NULL, 0);
	}
	wpa_printf(MSG_DEBUG, "   AT_MAC");
	eap_sim_msg_add_mac(msg, EAP_SIM_AT_MAC);
	return eap_sim_msg_finish(msg, data->k_aut, (u8 *) "", 0);
}


static struct wpabuf * eap_aka_response_reauth(struct eap_aka_data *data,
					       u8 id, int counter_too_small,
					       const u8 *nonce_s)
{
	struct eap_sim_msg *msg;
	unsigned int counter;

	wpa_printf(MSG_DEBUG, "Generating EAP-AKA Reauthentication (id=%d)",
		   id);
	msg = eap_sim_msg_init(EAP_CODE_RESPONSE, id, EAP_TYPE_AKA,
			       EAP_AKA_SUBTYPE_REAUTHENTICATION);
	wpa_printf(MSG_DEBUG, "   AT_IV");
	wpa_printf(MSG_DEBUG, "   AT_ENCR_DATA");
	eap_sim_msg_add_encr_start(msg, EAP_SIM_AT_IV, EAP_SIM_AT_ENCR_DATA);

	if (counter_too_small) {
		wpa_printf(MSG_DEBUG, "   *AT_COUNTER_TOO_SMALL");
		eap_sim_msg_add(msg, EAP_SIM_AT_COUNTER_TOO_SMALL, 0, NULL, 0);
		counter = data->counter_too_small;
	} else
		counter = data->counter;

	wpa_printf(MSG_DEBUG, "   *AT_COUNTER %d", counter);
	eap_sim_msg_add(msg, EAP_SIM_AT_COUNTER, counter, NULL, 0);

	if (eap_sim_msg_add_encr_end(msg, data->k_encr, EAP_SIM_AT_PADDING)) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Failed to encrypt "
			   "AT_ENCR_DATA");
		eap_sim_msg_free(msg);
		return NULL;
	}
	eap_aka_add_checkcode(data, msg);
	if (data->use_result_ind) {
		wpa_printf(MSG_DEBUG, "   AT_RESULT_IND");
		eap_sim_msg_add(msg, EAP_SIM_AT_RESULT_IND, 0, NULL, 0);
	}
	wpa_printf(MSG_DEBUG, "   AT_MAC");
	eap_sim_msg_add_mac(msg, EAP_SIM_AT_MAC);
	return eap_sim_msg_finish(msg, data->k_aut, nonce_s,
				  EAP_SIM_NONCE_S_LEN);
}


static struct wpabuf * eap_aka_response_notification(struct eap_aka_data *data,
						     u8 id, u16 notification)
{
	struct eap_sim_msg *msg;
	u8 *k_aut = (notification & 0x4000) == 0 ? data->k_aut : NULL;

	wpa_printf(MSG_DEBUG, "Generating EAP-AKA Notification (id=%d)", id);
	msg = eap_sim_msg_init(EAP_CODE_RESPONSE, id, EAP_TYPE_AKA,
			       EAP_AKA_SUBTYPE_NOTIFICATION);
	if (k_aut && data->reauth) {
		wpa_printf(MSG_DEBUG, "   AT_IV");
		wpa_printf(MSG_DEBUG, "   AT_ENCR_DATA");
		eap_sim_msg_add_encr_start(msg, EAP_SIM_AT_IV,
					   EAP_SIM_AT_ENCR_DATA);
		wpa_printf(MSG_DEBUG, "   *AT_COUNTER %d", data->counter);
		eap_sim_msg_add(msg, EAP_SIM_AT_COUNTER, data->counter,
				NULL, 0);
		if (eap_sim_msg_add_encr_end(msg, data->k_encr,
					     EAP_SIM_AT_PADDING)) {
			wpa_printf(MSG_WARNING, "EAP-AKA: Failed to encrypt "
				   "AT_ENCR_DATA");
			eap_sim_msg_free(msg);
			return NULL;
		}
	}
	if (k_aut) {
		wpa_printf(MSG_DEBUG, "   AT_MAC");
		eap_sim_msg_add_mac(msg, EAP_SIM_AT_MAC);
	}
	return eap_sim_msg_finish(msg, k_aut, (u8 *) "", 0);
}


static struct wpabuf * eap_aka_process_identity(struct eap_sm *sm,
						struct eap_aka_data *data,
						u8 id,
						const struct wpabuf *reqData,
						struct eap_sim_attrs *attr)
{
	int id_error;
	struct wpabuf *buf;

	wpa_printf(MSG_DEBUG, "EAP-AKA: subtype Identity");

	id_error = 0;
	switch (attr->id_req) {
	case NO_ID_REQ:
		break;
	case ANY_ID:
		if (data->num_id_req > 0)
			id_error++;
		data->num_id_req++;
		break;
	case FULLAUTH_ID:
		if (data->num_id_req > 1)
			id_error++;
		data->num_id_req++;
		break;
	case PERMANENT_ID:
		if (data->num_id_req > 2)
			id_error++;
		data->num_id_req++;
		break;
	}
	if (id_error) {
		wpa_printf(MSG_INFO, "EAP-AKA: Too many ID requests "
			   "used within one authentication");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	buf = eap_aka_response_identity(sm, data, id, attr->id_req);

	if (data->prev_id != id) {
		eap_aka_add_id_msg(data, reqData);
		eap_aka_add_id_msg(data, buf);
		data->prev_id = id;
	}

	return buf;
}


static struct wpabuf * eap_aka_process_challenge(struct eap_sm *sm,
						 struct eap_aka_data *data,
						 u8 id,
						 const struct wpabuf *reqData,
						 struct eap_sim_attrs *attr)
{
	const u8 *identity;
	size_t identity_len;
	int res;
	struct eap_sim_attrs eattr;

	wpa_printf(MSG_DEBUG, "EAP-AKA: subtype Challenge");

	if (attr->checkcode &&
	    eap_aka_verify_checkcode(data, attr->checkcode,
				     attr->checkcode_len)) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Invalid AT_CHECKCODE in the "
			   "message");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	data->reauth = 0;
	if (!attr->mac || !attr->rand || !attr->autn) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Challenge message "
			   "did not include%s%s%s",
			   !attr->mac ? " AT_MAC" : "",
			   !attr->rand ? " AT_RAND" : "",
			   !attr->autn ? " AT_AUTN" : "");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}
	os_memcpy(data->rand, attr->rand, EAP_AKA_RAND_LEN);
	os_memcpy(data->autn, attr->autn, EAP_AKA_AUTN_LEN);

	res = eap_aka_umts_auth(sm, data);
	if (res == -1) {
		wpa_printf(MSG_WARNING, "EAP-AKA: UMTS authentication "
			   "failed (AUTN)");
		return eap_aka_authentication_reject(data, id);
	} else if (res == -2) {
		wpa_printf(MSG_WARNING, "EAP-AKA: UMTS authentication "
			   "failed (AUTN seq# -> AUTS)");
		return eap_aka_synchronization_failure(data, id);
	} else if (res) {
		wpa_printf(MSG_WARNING, "EAP-AKA: UMTS authentication failed");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}
	if (data->last_eap_identity) {
		identity = data->last_eap_identity;
		identity_len = data->last_eap_identity_len;
	} else if (data->pseudonym) {
		identity = data->pseudonym;
		identity_len = data->pseudonym_len;
	} else
		identity = eap_get_config_identity(sm, &identity_len);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-AKA: Selected identity for MK "
			  "derivation", identity, identity_len);
	eap_aka_derive_mk(identity, identity_len, data->ik, data->ck,
			  data->mk);
	eap_sim_derive_keys(data->mk, data->k_encr, data->k_aut, data->msk,
			    data->emsk);
	if (eap_sim_verify_mac(data->k_aut, reqData, attr->mac, (u8 *) "", 0))
	{
		wpa_printf(MSG_WARNING, "EAP-AKA: Challenge message "
			   "used invalid AT_MAC");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	/* Old reauthentication and pseudonym identities must not be used
	 * anymore. In other words, if no new identities are received, full
	 * authentication will be used on next reauthentication. */
	eap_aka_clear_identities(data, CLEAR_PSEUDONYM | CLEAR_REAUTH_ID |
				 CLEAR_EAP_ID);

	if (attr->encr_data) {
		u8 *decrypted;
		decrypted = eap_sim_parse_encr(data->k_encr, attr->encr_data,
					       attr->encr_data_len, attr->iv,
					       &eattr, 0);
		if (decrypted == NULL) {
			return eap_aka_client_error(
				data, id, EAP_AKA_UNABLE_TO_PROCESS_PACKET);
		}
		eap_aka_learn_ids(data, &eattr);
		os_free(decrypted);
	}

	if (data->result_ind && attr->result_ind)
		data->use_result_ind = 1;

	if (data->state != FAILURE && data->state != RESULT_FAILURE) {
		eap_aka_state(data, data->use_result_ind ?
			      RESULT_SUCCESS : SUCCESS);
	}

	data->num_id_req = 0;
	data->num_notification = 0;
	/* RFC 4187 specifies that counter is initialized to one after
	 * fullauth, but initializing it to zero makes it easier to implement
	 * reauth verification. */
	data->counter = 0;
	return eap_aka_response_challenge(data, id);
}


static int eap_aka_process_notification_reauth(struct eap_aka_data *data,
					       struct eap_sim_attrs *attr)
{
	struct eap_sim_attrs eattr;
	u8 *decrypted;

	if (attr->encr_data == NULL || attr->iv == NULL) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Notification message after "
			   "reauth did not include encrypted data");
		return -1;
	}

	decrypted = eap_sim_parse_encr(data->k_encr, attr->encr_data,
				       attr->encr_data_len, attr->iv, &eattr,
				       0);
	if (decrypted == NULL) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Failed to parse encrypted "
			   "data from notification message");
		return -1;
	}

	if (eattr.counter < 0 || (size_t) eattr.counter != data->counter) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Counter in notification "
			   "message does not match with counter in reauth "
			   "message");
		os_free(decrypted);
		return -1;
	}

	os_free(decrypted);
	return 0;
}


static int eap_aka_process_notification_auth(struct eap_aka_data *data,
					     const struct wpabuf *reqData,
					     struct eap_sim_attrs *attr)
{
	if (attr->mac == NULL) {
		wpa_printf(MSG_INFO, "EAP-AKA: no AT_MAC in after_auth "
			   "Notification message");
		return -1;
	}

	if (eap_sim_verify_mac(data->k_aut, reqData, attr->mac, (u8 *) "", 0))
	{
		wpa_printf(MSG_WARNING, "EAP-AKA: Notification message "
			   "used invalid AT_MAC");
		return -1;
	}

	if (data->reauth &&
	    eap_aka_process_notification_reauth(data, attr)) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Invalid notification "
			   "message after reauth");
		return -1;
	}

	return 0;
}


static struct wpabuf * eap_aka_process_notification(
	struct eap_sm *sm, struct eap_aka_data *data, u8 id,
	const struct wpabuf *reqData, struct eap_sim_attrs *attr)
{
	wpa_printf(MSG_DEBUG, "EAP-AKA: subtype Notification");
	if (data->num_notification > 0) {
		wpa_printf(MSG_INFO, "EAP-AKA: too many notification "
			   "rounds (only one allowed)");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}
	data->num_notification++;
	if (attr->notification == -1) {
		wpa_printf(MSG_INFO, "EAP-AKA: no AT_NOTIFICATION in "
			   "Notification message");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	if ((attr->notification & 0x4000) == 0 &&
	    eap_aka_process_notification_auth(data, reqData, attr)) {
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	eap_sim_report_notification(sm->msg_ctx, attr->notification, 1);
	if (attr->notification >= 0 && attr->notification < 32768) {
		eap_aka_state(data, FAILURE);
	} else if (attr->notification == EAP_SIM_SUCCESS &&
		   data->state == RESULT_SUCCESS)
		eap_aka_state(data, SUCCESS);
	return eap_aka_response_notification(data, id, attr->notification);
}


static struct wpabuf * eap_aka_process_reauthentication(
	struct eap_sm *sm, struct eap_aka_data *data, u8 id,
	const struct wpabuf *reqData, struct eap_sim_attrs *attr)
{
	struct eap_sim_attrs eattr;
	u8 *decrypted;

	wpa_printf(MSG_DEBUG, "EAP-AKA: subtype Reauthentication");

	if (attr->checkcode &&
	    eap_aka_verify_checkcode(data, attr->checkcode,
				     attr->checkcode_len)) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Invalid AT_CHECKCODE in the "
			   "message");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	if (data->reauth_id == NULL) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Server is trying "
			   "reauthentication, but no reauth_id available");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	data->reauth = 1;
	if (eap_sim_verify_mac(data->k_aut, reqData, attr->mac, (u8 *) "", 0))
	{
		wpa_printf(MSG_WARNING, "EAP-AKA: Reauthentication "
			   "did not have valid AT_MAC");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	if (attr->encr_data == NULL || attr->iv == NULL) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Reauthentication "
			   "message did not include encrypted data");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	decrypted = eap_sim_parse_encr(data->k_encr, attr->encr_data,
				       attr->encr_data_len, attr->iv, &eattr,
				       0);
	if (decrypted == NULL) {
		wpa_printf(MSG_WARNING, "EAP-AKA: Failed to parse encrypted "
			   "data from reauthentication message");
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	if (eattr.nonce_s == NULL || eattr.counter < 0) {
		wpa_printf(MSG_INFO, "EAP-AKA: (encr) No%s%s in reauth packet",
			   !eattr.nonce_s ? " AT_NONCE_S" : "",
			   eattr.counter < 0 ? " AT_COUNTER" : "");
		os_free(decrypted);
		return eap_aka_client_error(data, id,
					    EAP_AKA_UNABLE_TO_PROCESS_PACKET);
	}

	if (eattr.counter < 0 || (size_t) eattr.counter <= data->counter) {
		struct wpabuf *res;
		wpa_printf(MSG_INFO, "EAP-AKA: (encr) Invalid counter "
			   "(%d <= %d)", eattr.counter, data->counter);
		data->counter_too_small = eattr.counter;

		eap_sim_derive_keys_reauth(eattr.counter, data->reauth_id,
					   data->reauth_id_len, eattr.nonce_s,
					   data->mk, NULL, NULL);

		/* Reply using Re-auth w/ AT_COUNTER_TOO_SMALL. The current
		 * reauth_id must not be used to start a new reauthentication.
		 * However, since it was used in the last EAP-Response-Identity
		 * packet, it has to saved for the following fullauth to be
		 * used in MK derivation. */
		os_free(data->last_eap_identity);
		data->last_eap_identity = data->reauth_id;
		data->last_eap_identity_len = data->reauth_id_len;
		data->reauth_id = NULL;
		data->reauth_id_len = 0;

		res = eap_aka_response_reauth(data, id, 1, eattr.nonce_s);
		os_free(decrypted);

		return res;
	}
	data->counter = eattr.counter;

	os_memcpy(data->nonce_s, eattr.nonce_s, EAP_SIM_NONCE_S_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-AKA: (encr) AT_NONCE_S",
		    data->nonce_s, EAP_SIM_NONCE_S_LEN);

	eap_sim_derive_keys_reauth(data->counter,
				   data->reauth_id, data->reauth_id_len,
				   data->nonce_s, data->mk, data->msk,
				   data->emsk);
	eap_aka_clear_identities(data, CLEAR_REAUTH_ID | CLEAR_EAP_ID);
	eap_aka_learn_ids(data, &eattr);

	if (data->result_ind && attr->result_ind)
		data->use_result_ind = 1;

	if (data->state != FAILURE && data->state != RESULT_FAILURE) {
		eap_aka_state(data, data->use_result_ind ?
			      RESULT_SUCCESS : SUCCESS);
	}

	data->num_id_req = 0;
	data->num_notification = 0;
	if (data->counter > EAP_AKA_MAX_FAST_REAUTHS) {
		wpa_printf(MSG_DEBUG, "EAP-AKA: Maximum number of "
			   "fast reauths performed - force fullauth");
		eap_aka_clear_identities(data, CLEAR_REAUTH_ID | CLEAR_EAP_ID);
	}
	os_free(decrypted);
	return eap_aka_response_reauth(data, id, 0, data->nonce_s);
}


static struct wpabuf * eap_aka_process(struct eap_sm *sm, void *priv,
				       struct eap_method_ret *ret,
				       const struct wpabuf *reqData)
{
	struct eap_aka_data *data = priv;
	const struct eap_hdr *req;
	u8 subtype, id;
	struct wpabuf *res;
	const u8 *pos;
	struct eap_sim_attrs attr;
	size_t len;

	wpa_hexdump_buf(MSG_DEBUG, "EAP-AKA: EAP data", reqData);
	if (eap_get_config_identity(sm, &len) == NULL) {
		wpa_printf(MSG_INFO, "EAP-AKA: Identity not configured");
		eap_sm_request_identity(sm);
		ret->ignore = TRUE;
		return NULL;
	}

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_AKA, reqData, &len);
	if (pos == NULL || len < 1) {
		ret->ignore = TRUE;
		return NULL;
	}
	req = wpabuf_head(reqData);
	id = req->identifier;
	len = be_to_host16(req->length);

	ret->ignore = FALSE;
	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_FAIL;
	ret->allowNotifications = TRUE;

	subtype = *pos++;
	wpa_printf(MSG_DEBUG, "EAP-AKA: Subtype=%d", subtype);
	pos += 2; /* Reserved */

	if (eap_sim_parse_attr(pos, wpabuf_head_u8(reqData) + len, &attr, 1,
			       0)) {
		res = eap_aka_client_error(data, id,
					   EAP_AKA_UNABLE_TO_PROCESS_PACKET);
		goto done;
	}

	switch (subtype) {
	case EAP_AKA_SUBTYPE_IDENTITY:
		res = eap_aka_process_identity(sm, data, id, reqData, &attr);
		break;
	case EAP_AKA_SUBTYPE_CHALLENGE:
		res = eap_aka_process_challenge(sm, data, id, reqData, &attr);
		break;
	case EAP_AKA_SUBTYPE_NOTIFICATION:
		res = eap_aka_process_notification(sm, data, id, reqData,
						   &attr);
		break;
	case EAP_AKA_SUBTYPE_REAUTHENTICATION:
		res = eap_aka_process_reauthentication(sm, data, id, reqData,
						       &attr);
		break;
	case EAP_AKA_SUBTYPE_CLIENT_ERROR:
		wpa_printf(MSG_DEBUG, "EAP-AKA: subtype Client-Error");
		res = eap_aka_client_error(data, id,
					   EAP_AKA_UNABLE_TO_PROCESS_PACKET);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-AKA: Unknown subtype=%d", subtype);
		res = eap_aka_client_error(data, id,
					   EAP_AKA_UNABLE_TO_PROCESS_PACKET);
		break;
	}

done:
	if (data->state == FAILURE) {
		ret->decision = DECISION_FAIL;
		ret->methodState = METHOD_DONE;
	} else if (data->state == SUCCESS) {
		ret->decision = data->use_result_ind ?
			DECISION_UNCOND_SUCC : DECISION_COND_SUCC;
		/*
		 * It is possible for the server to reply with AKA
		 * Notification, so we must allow the method to continue and
		 * not only accept EAP-Success at this point.
		 */
		ret->methodState = data->use_result_ind ?
			METHOD_DONE : METHOD_MAY_CONT;
	} else if (data->state == RESULT_FAILURE)
		ret->methodState = METHOD_CONT;
	else if (data->state == RESULT_SUCCESS)
		ret->methodState = METHOD_CONT;

	if (ret->methodState == METHOD_DONE) {
		ret->allowNotifications = FALSE;
	}

	return res;
}


static Boolean eap_aka_has_reauth_data(struct eap_sm *sm, void *priv)
{
	struct eap_aka_data *data = priv;
	return data->pseudonym || data->reauth_id;
}


static void eap_aka_deinit_for_reauth(struct eap_sm *sm, void *priv)
{
	struct eap_aka_data *data = priv;
	eap_aka_clear_identities(data, CLEAR_EAP_ID);
	data->prev_id = -1;
	wpabuf_free(data->id_msgs);
	data->id_msgs = NULL;
	data->use_result_ind = 0;
}


static void * eap_aka_init_for_reauth(struct eap_sm *sm, void *priv)
{
	struct eap_aka_data *data = priv;
	data->num_id_req = 0;
	data->num_notification = 0;
	eap_aka_state(data, CONTINUE);
	return priv;
}


static const u8 * eap_aka_get_identity(struct eap_sm *sm, void *priv,
				       size_t *len)
{
	struct eap_aka_data *data = priv;

	if (data->reauth_id) {
		*len = data->reauth_id_len;
		return data->reauth_id;
	}

	if (data->pseudonym) {
		*len = data->pseudonym_len;
		return data->pseudonym;
	}

	return NULL;
}


static Boolean eap_aka_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_aka_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_aka_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_aka_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS)
		return NULL;

	key = os_malloc(EAP_SIM_KEYING_DATA_LEN);
	if (key == NULL)
		return NULL;

	*len = EAP_SIM_KEYING_DATA_LEN;
	os_memcpy(key, data->msk, EAP_SIM_KEYING_DATA_LEN);

	return key;
}


static u8 * eap_aka_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_aka_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS)
		return NULL;

	key = os_malloc(EAP_EMSK_LEN);
	if (key == NULL)
		return NULL;

	*len = EAP_EMSK_LEN;
	os_memcpy(key, data->emsk, EAP_EMSK_LEN);

	return key;
}


int eap_peer_aka_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_AKA, "AKA");
	if (eap == NULL)
		return -1;

	eap->init = eap_aka_init;
	eap->deinit = eap_aka_deinit;
	eap->process = eap_aka_process;
	eap->isKeyAvailable = eap_aka_isKeyAvailable;
	eap->getKey = eap_aka_getKey;
	eap->has_reauth_data = eap_aka_has_reauth_data;
	eap->deinit_for_reauth = eap_aka_deinit_for_reauth;
	eap->init_for_reauth = eap_aka_init_for_reauth;
	eap->get_identity = eap_aka_get_identity;
	eap->get_emsk = eap_aka_get_emsk;

	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret;
}
