/*
 * krackattacks
 * Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
 *
 * This code may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef ATTACKS_H_
#define ATTACKS_H_

// Make changes to hostapd to support 4-way and group handshake tests
// against the client.
#define KRACK_TEST_CLIENT

void poc_log(const u8 *clientmac, const char *format, ...);
void wpa_rekey_ptk(void *eloop_ctx, void *timeout_ctx);

#endif // ATTACKS_H_
