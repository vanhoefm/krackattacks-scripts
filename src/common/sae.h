/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SAE_H
#define SAE_H

#define SAE_KCK_LEN 32
#define SAE_PMK_LEN 32
#define SAE_PMKID_LEN 16
#define SAE_KEYSEED_KEY_LEN 32
#define SAE_MAX_PRIME_LEN 32
#define SAE_COMMIT_MAX_LEN (2 + 3 * SAE_MAX_PRIME_LEN)
#define SAE_CONFIRM_MAX_LEN (2 + SAE_MAX_PRIME_LEN)

struct sae_data {
	enum { SAE_NOTHING, SAE_COMMITTED, SAE_CONFIRMED, SAE_ACCEPTED } state;
	u16 send_confirm;
	u8 kck[SAE_KCK_LEN];
	u8 pmk[SAE_PMK_LEN];
	u8 own_commit_scalar[SAE_MAX_PRIME_LEN];
	u8 own_commit_element[2 * SAE_MAX_PRIME_LEN];
	u8 peer_commit_scalar[SAE_MAX_PRIME_LEN];
	u8 peer_commit_element[2 * SAE_MAX_PRIME_LEN];
	u8 pwe[2 * SAE_MAX_PRIME_LEN];
	u8 sae_rand[SAE_MAX_PRIME_LEN];
	int group;
	struct crypto_ec *ec;
	int prime_len;
};

int sae_set_group(struct sae_data *sae, int group);
void sae_clear_data(struct sae_data *sae);

int sae_prepare_commit(const u8 *addr1, const u8 *addr2,
		       const u8 *password, size_t password_len,
		       struct sae_data *sae);
int sae_process_commit(struct sae_data *sae);
void sae_write_commit(struct sae_data *sae, struct wpabuf *buf,
		      const struct wpabuf *token);
u16 sae_parse_commit(struct sae_data *sae, const u8 *data, size_t len,
		     const u8 **token, size_t *token_len);
void sae_write_confirm(struct sae_data *sae, struct wpabuf *buf);
int sae_check_confirm(struct sae_data *sae, const u8 *data, size_t len);

#endif /* SAE_H */
