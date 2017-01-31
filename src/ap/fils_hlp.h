/*
 * FILS HLP request processing
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef FILS_HLP_H
#define FILS_HLP_H

void fils_process_hlp(struct hostapd_data *hapd, struct sta_info *sta,
		      const u8 *pos, int left);

#endif /* FILS_HLP_H */
