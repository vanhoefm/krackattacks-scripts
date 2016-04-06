/*
 * hostapd / Radio Measurement (RRM)
 * Copyright(c) 2013 - 2016 Intel Mobile Communications GmbH.
 * Copyright(c) 2011 - 2016 Intel Corporation. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef RRM_H
#define RRM_H

void hostapd_handle_radio_measurement(struct hostapd_data *hapd,
				      const u8 *buf, size_t len);

#endif /* RRM_H */
