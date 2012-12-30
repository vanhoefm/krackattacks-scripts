/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SAE_H
#define SAE_H

#define SAE_COMMIT_MAX_LEN (2 + 3 * 32)

struct sae_data {
	enum { SAE_INIT, SAE_COMMIT, SAE_CONFIRM } state;
	u16 send_confirm;
	u8 own_commit_scalar[32];
	u8 own_commit_element[2 * 32];
	u8 pwe[2 * 32];
	u8 sae_rand[32];
};

int sae_prepare_commit(const u8 *addr1, const u8 *addr2,
		       const u8 *password, size_t password_len,
		       struct sae_data *sae);
void sae_write_commit(struct sae_data *sae, struct wpabuf *buf);

#endif /* SAE_H */
