/*
 * IEEE 802.11 Frame type definitions
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
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

#ifndef IEEE802_11_DEFS_H
#define IEEE802_11_DEFS_H

/* IEEE 802.11 defines */

#define WLAN_FC_PVER		0x0003
#define WLAN_FC_TODS		0x0100
#define WLAN_FC_FROMDS		0x0200
#define WLAN_FC_MOREFRAG	0x0400
#define WLAN_FC_RETRY		0x0800
#define WLAN_FC_PWRMGT		0x1000
#define WLAN_FC_MOREDATA	0x2000
#define WLAN_FC_ISWEP		0x4000
#define WLAN_FC_ORDER		0x8000

#define WLAN_FC_GET_TYPE(fc)	(((fc) & 0x000c) >> 2)
#define WLAN_FC_GET_STYPE(fc)	(((fc) & 0x00f0) >> 4)

#define WLAN_GET_SEQ_FRAG(seq) ((seq) & (BIT(3) | BIT(2) | BIT(1) | BIT(0)))
#define WLAN_GET_SEQ_SEQ(seq) \
	(((seq) & (~(BIT(3) | BIT(2) | BIT(1) | BIT(0)))) >> 4)

#define WLAN_FC_TYPE_MGMT		0
#define WLAN_FC_TYPE_CTRL		1
#define WLAN_FC_TYPE_DATA		2

/* management */
#define WLAN_FC_STYPE_ASSOC_REQ		0
#define WLAN_FC_STYPE_ASSOC_RESP	1
#define WLAN_FC_STYPE_REASSOC_REQ	2
#define WLAN_FC_STYPE_REASSOC_RESP	3
#define WLAN_FC_STYPE_PROBE_REQ		4
#define WLAN_FC_STYPE_PROBE_RESP	5
#define WLAN_FC_STYPE_BEACON		8
#define WLAN_FC_STYPE_ATIM		9
#define WLAN_FC_STYPE_DISASSOC		10
#define WLAN_FC_STYPE_AUTH		11
#define WLAN_FC_STYPE_DEAUTH		12
#define WLAN_FC_STYPE_ACTION		13

/* control */
#define WLAN_FC_STYPE_PSPOLL		10
#define WLAN_FC_STYPE_RTS		11
#define WLAN_FC_STYPE_CTS		12
#define WLAN_FC_STYPE_ACK		13
#define WLAN_FC_STYPE_CFEND		14
#define WLAN_FC_STYPE_CFENDACK		15

/* data */
#define WLAN_FC_STYPE_DATA		0
#define WLAN_FC_STYPE_DATA_CFACK	1
#define WLAN_FC_STYPE_DATA_CFPOLL	2
#define WLAN_FC_STYPE_DATA_CFACKPOLL	3
#define WLAN_FC_STYPE_NULLFUNC		4
#define WLAN_FC_STYPE_CFACK		5
#define WLAN_FC_STYPE_CFPOLL		6
#define WLAN_FC_STYPE_CFACKPOLL		7
#define WLAN_FC_STYPE_QOS_DATA		8

/* Authentication algorithms */
#define WLAN_AUTH_OPEN			0
#define WLAN_AUTH_SHARED_KEY		1
#define WLAN_AUTH_FT			2
#define WLAN_AUTH_LEAP			128

#define WLAN_AUTH_CHALLENGE_LEN 128

#define WLAN_CAPABILITY_ESS BIT(0)
#define WLAN_CAPABILITY_IBSS BIT(1)
#define WLAN_CAPABILITY_CF_POLLABLE BIT(2)
#define WLAN_CAPABILITY_CF_POLL_REQUEST BIT(3)
#define WLAN_CAPABILITY_PRIVACY BIT(4)
#define WLAN_CAPABILITY_SHORT_PREAMBLE BIT(5)
#define WLAN_CAPABILITY_PBCC BIT(6)
#define WLAN_CAPABILITY_CHANNEL_AGILITY BIT(7)
#define WLAN_CAPABILITY_SPECTRUM_MGMT BIT(8)
#define WLAN_CAPABILITY_SHORT_SLOT_TIME BIT(10)
#define WLAN_CAPABILITY_DSSS_OFDM BIT(13)

/* Status codes */
#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_UNSPECIFIED_FAILURE 1
#define WLAN_STATUS_CAPS_UNSUPPORTED 10
#define WLAN_STATUS_REASSOC_NO_ASSOC 11
#define WLAN_STATUS_ASSOC_DENIED_UNSPEC 12
#define WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG 13
#define WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION 14
#define WLAN_STATUS_CHALLENGE_FAIL 15
#define WLAN_STATUS_AUTH_TIMEOUT 16
#define WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 17
#define WLAN_STATUS_ASSOC_DENIED_RATES 18
/* IEEE 802.11b */
#define WLAN_STATUS_ASSOC_DENIED_NOSHORT 19
#define WLAN_STATUS_ASSOC_DENIED_NOPBCC 20
#define WLAN_STATUS_ASSOC_DENIED_NOAGILITY 21
/* IEEE 802.11h */
#define WLAN_STATUS_SPEC_MGMT_REQUIRED 22
#define WLAN_STATUS_PWR_CAPABILITY_NOT_VALID 23
#define WLAN_STATUS_SUPPORTED_CHANNEL_NOT_VALID 24
/* 802.11g */
#define WLAN_STATUS_ASSOC_DENOED_NO_SHORT_SLOT_TIME 25
#define WLAN_STATUS_ASSOC_DENOED_NO_ER_PBCC 26
#define WLAN_STATUS_ASSOC_DENOED_NO_DSSS_OFDM 27
/* IEEE 802.11i */
#define WLAN_STATUS_INVALID_IE 40
#define WLAN_STATUS_GROUP_CIPHER_NOT_VALID 41
#define WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID 42
#define WLAN_STATUS_AKMP_NOT_VALID 43
#define WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION 44
#define WLAN_STATUS_INVALID_RSN_IE_CAPAB 45
#define WLAN_STATUS_CIPHER_REJECTED_PER_POLICY 46
/* IEEE 802.11r */
#define WLAN_STATUS_INVALID_FT_ACTION_FRAME_COUNT 52
#define WLAN_STATUS_EXPECTED_RESOURCE_REQ_FT 53
#define WLAN_STATUS_INVALID_PMKID 54
#define WLAN_STATUS_INVALID_MDIE 55
#define WLAN_STATUS_INVALID_FTIE 56

/* Reason codes */
#define WLAN_REASON_UNSPECIFIED 1
#define WLAN_REASON_PREV_AUTH_NOT_VALID 2
#define WLAN_REASON_DEAUTH_LEAVING 3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY 4
#define WLAN_REASON_DISASSOC_AP_BUSY 5
#define WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA 6
#define WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA 7
#define WLAN_REASON_DISASSOC_STA_HAS_LEFT 8
#define WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH 9
/* 802.11h */
#define WLAN_REASON_PWR_CAPABILITY_NOT_VALID 10
#define WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID 11
/* IEEE 802.11i */
#define WLAN_REASON_INVALID_IE 13
#define WLAN_REASON_MICHAEL_MIC_FAILURE 14
#define WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT 15
#define WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT 16
#define WLAN_REASON_IE_IN_4WAY_DIFFERS 17
#define WLAN_REASON_GROUP_CIPHER_NOT_VALID 18
#define WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID 19
#define WLAN_REASON_AKMP_NOT_VALID 20
#define WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION 21
#define WLAN_REASON_INVALID_RSN_IE_CAPAB 22
#define WLAN_REASON_IEEE_802_1X_AUTH_FAILED 23
#define WLAN_REASON_CIPHER_SUITE_REJECTED 24


/* Information Element IDs */
#define WLAN_EID_SSID 0
#define WLAN_EID_SUPP_RATES 1
#define WLAN_EID_FH_PARAMS 2
#define WLAN_EID_DS_PARAMS 3
#define WLAN_EID_CF_PARAMS 4
#define WLAN_EID_TIM 5
#define WLAN_EID_IBSS_PARAMS 6
#define WLAN_EID_COUNTRY 7
#define WLAN_EID_CHALLENGE 16
/* EIDs defined by IEEE 802.11h - START */
#define WLAN_EID_PWR_CONSTRAINT 32
#define WLAN_EID_PWR_CAPABILITY 33
#define WLAN_EID_TPC_REQUEST 34
#define WLAN_EID_TPC_REPORT 35
#define WLAN_EID_SUPPORTED_CHANNELS 36
#define WLAN_EID_CHANNEL_SWITCH 37
#define WLAN_EID_MEASURE_REQUEST 38
#define WLAN_EID_MEASURE_REPORT 39
#define WLAN_EID_QUITE 40
#define WLAN_EID_IBSS_DFS 41
/* EIDs defined by IEEE 802.11h - END */
#define WLAN_EID_ERP_INFO 42
#define WLAN_EID_RSN 48
#define WLAN_EID_EXT_SUPP_RATES 50
#define WLAN_EID_MOBILITY_DOMAIN 54
#define WLAN_EID_FAST_BSS_TRANSITION 55
#define WLAN_EID_TIMEOUT_INTERVAL 56
#define WLAN_EID_RIC_DATA 57
#define WLAN_EID_VENDOR_SPECIFIC 221


/* Action frame categories */
#define WLAN_ACTION_SPECTRUM_MGMT 0
#define WLAN_ACTION_QOS 1
#define WLAN_ACTION_DLS 2
#define WLAN_ACTION_BLOCK_ACK 3
#define WLAN_ACTION_RADIO_MEASUREMENT 5
#define WLAN_ACTION_FT 6


#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct ieee80211_mgmt {
	le16 frame_control;
	le16 duration;
	u8 da[6];
	u8 sa[6];
	u8 bssid[6];
	le16 seq_ctrl;
	union {
		struct {
			le16 auth_alg;
			le16 auth_transaction;
			le16 status_code;
			/* possibly followed by Challenge text */
			u8 variable[0];
		} STRUCT_PACKED auth;
		struct {
			le16 reason_code;
		} STRUCT_PACKED deauth;
		struct {
			le16 capab_info;
			le16 listen_interval;
			/* followed by SSID and Supported rates */
			u8 variable[0];
		} STRUCT_PACKED assoc_req;
		struct {
			le16 capab_info;
			le16 status_code;
			le16 aid;
			/* followed by Supported rates */
			u8 variable[0];
		} STRUCT_PACKED assoc_resp, reassoc_resp;
		struct {
			le16 capab_info;
			le16 listen_interval;
			u8 current_ap[6];
			/* followed by SSID and Supported rates */
			u8 variable[0];
		} STRUCT_PACKED reassoc_req;
		struct {
			le16 reason_code;
		} STRUCT_PACKED disassoc;
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			u8 variable[0];
		} STRUCT_PACKED beacon;
		struct {
			/* only variable items: SSID, Supported rates */
			u8 variable[0];
		} STRUCT_PACKED probe_req;
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params */
			u8 variable[0];
		} STRUCT_PACKED probe_resp;
		struct {
			u8 category;
			union {
				struct {
					u8 action_code;
					u8 dialog_token;
					u8 status_code;
					u8 variable[0];
				} STRUCT_PACKED wme_action;
				struct{
					u8 action_code;
					u8 element_id;
					u8 length;
					u8 switch_mode;
					u8 new_chan;
					u8 switch_count;
				} STRUCT_PACKED chan_switch;
				struct {
					u8 action;
					u8 sta_addr[ETH_ALEN];
					u8 target_ap_addr[ETH_ALEN];
					u8 variable[0]; /* FT Request */
				} STRUCT_PACKED ft_action_req;
				struct {
					u8 action;
					u8 sta_addr[ETH_ALEN];
					u8 target_ap_addr[ETH_ALEN];
					le16 status_code;
					u8 variable[0]; /* FT Request */
				} STRUCT_PACKED ft_action_resp;
			} u;
		} STRUCT_PACKED action;
	} u;
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

#define ERP_INFO_NON_ERP_PRESENT BIT(0)
#define ERP_INFO_USE_PROTECTION BIT(1)
#define ERP_INFO_BARKER_PREAMBLE_MODE BIT(2)

#endif /* IEEE802_11_DEFS_H */
