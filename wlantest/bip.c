/*
 * BIP
 * Copyright (c) 2010-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "crypto/aes_wrap.h"
#include "wlantest.h"


u8 * bip_protect(const u8 *igtk, u8 *frame, size_t len, u8 *ipn, int keyid,
		 size_t *prot_len)
{
	u8 *prot, *pos, *buf;
	u8 mic[16];
	u16 fc;
	struct ieee80211_hdr *hdr;
	size_t plen;

	plen = len + 18;
	prot = os_malloc(plen);
	if (prot == NULL)
		return NULL;
	os_memcpy(prot, frame, len);
	pos = prot + len;
	*pos++ = WLAN_EID_MMIE;
	*pos++ = 16;
	WPA_PUT_LE16(pos, keyid);
	pos += 2;
	os_memcpy(pos, ipn, 6);
	pos += 6;
	os_memset(pos, 0, 8); /* MIC */

	buf = os_malloc(plen + 20 - 24);
	if (buf == NULL) {
		os_free(prot);
		return NULL;
	}

	/* BIP AAD: FC(masked) A1 A2 A3 */
	hdr = (struct ieee80211_hdr *) frame;
	fc = le_to_host16(hdr->frame_control);
	fc &= ~(WLAN_FC_RETRY | WLAN_FC_PWRMGT | WLAN_FC_MOREDATA);
	WPA_PUT_LE16(buf, fc);
	os_memcpy(buf + 2, hdr->addr1, 3 * ETH_ALEN);
	os_memcpy(buf + 20, prot + 24, plen - 24);
	wpa_hexdump(MSG_MSGDUMP, "BIP: AAD|Body(masked)", buf, plen + 20 - 24);
	/* MIC = L(AES-128-CMAC(AAD || Frame Body(masked)), 0, 64) */
	if (omac1_aes_128(igtk, buf, plen + 20 - 24, mic) < 0) {
		os_free(prot);
		os_free(buf);
		return NULL;
	}
	os_free(buf);

	os_memcpy(pos, mic, 8);
	wpa_hexdump(MSG_DEBUG, "BIP MMIE MIC", pos, 8);

	*prot_len = plen;
	return prot;
}
