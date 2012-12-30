/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SAE_H
#define SAE_H

struct sae_data {
	enum { SAE_INIT, SAE_COMMIT, SAE_CONFIRM } state;
	u16 send_confirm;
};

#endif /* SAE_H */
