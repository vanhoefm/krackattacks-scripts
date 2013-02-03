/*
 * Event loop - empty template (basic structure, but no OS specific operations)
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "list.h"
#include "eloop.h"


struct eloop_sock {
	int sock;
	void *eloop_data;
	void *user_data;
	eloop_sock_handler handler;
};

struct eloop_timeout {
	struct dl_list list;
	struct os_time time;
	void *eloop_data;
	void *user_data;
	eloop_timeout_handler handler;
};

struct eloop_signal {
	int sig;
	void *user_data;
	eloop_signal_handler handler;
	int signaled;
};

struct eloop_data {
	int max_sock, reader_count;
	struct eloop_sock *readers;

	struct dl_list timeout;

	int signal_count;
	struct eloop_signal *signals;
	int signaled;
	int pending_terminate;

	int terminate;
	int reader_table_changed;
};

static struct eloop_data eloop;


int eloop_init(void)
{
	os_memset(&eloop, 0, sizeof(eloop));
	dl_list_init(&eloop.timeout);
	return 0;
}


int eloop_register_read_sock(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data)
{
	struct eloop_sock *tmp;

	tmp = os_realloc_array(eloop.readers, eloop.reader_count + 1,
			       sizeof(struct eloop_sock));
	if (tmp == NULL)
		return -1;

	tmp[eloop.reader_count].sock = sock;
	tmp[eloop.reader_count].eloop_data = eloop_data;
	tmp[eloop.reader_count].user_data = user_data;
	tmp[eloop.reader_count].handler = handler;
	eloop.reader_count++;
	eloop.readers = tmp;
	if (sock > eloop.max_sock)
		eloop.max_sock = sock;
	eloop.reader_table_changed = 1;

	return 0;
}


void eloop_unregister_read_sock(int sock)
{
	int i;

	if (eloop.readers == NULL || eloop.reader_count == 0)
		return;

	for (i = 0; i < eloop.reader_count; i++) {
		if (eloop.readers[i].sock == sock)
			break;
	}
	if (i == eloop.reader_count)
		return;
	if (i != eloop.reader_count - 1) {
		os_memmove(&eloop.readers[i], &eloop.readers[i + 1],
			   (eloop.reader_count - i - 1) *
			   sizeof(struct eloop_sock));
	}
	eloop.reader_count--;
	eloop.reader_table_changed = 1;
}


int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			   eloop_timeout_handler handler,
			   void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp;
	os_time_t now_sec;

	timeout = os_zalloc(sizeof(*timeout));
	if (timeout == NULL)
		return -1;
	if (os_get_time(&timeout->time) < 0) {
		os_free(timeout);
		return -1;
	}
	now_sec = timeout->time.sec;
	timeout->time.sec += secs;
	if (timeout->time.sec < now_sec) {
		/*
		 * Integer overflow - assume long enough timeout to be assumed
		 * to be infinite, i.e., the timeout would never happen.
		 */
		wpa_printf(MSG_DEBUG, "ELOOP: Too long timeout (secs=%u) to "
			   "ever happen - ignore it", secs);
		os_free(timeout);
		return 0;
	}
	timeout->time.usec += usecs;
	while (timeout->time.usec >= 1000000) {
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;

	/* Maintain timeouts in order of increasing time */
	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (os_time_before(&timeout->time, &tmp->time)) {
			dl_list_add(tmp->list.prev, &timeout->list);
			return 0;
		}
	}
	dl_list_add_tail(&eloop.timeout, &timeout->list);

	return 0;
}


static void eloop_remove_timeout(struct eloop_timeout *timeout)
{
	dl_list_del(&timeout->list);
	os_free(timeout);
}


int eloop_cancel_timeout(eloop_timeout_handler handler,
			 void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev;
	int removed = 0;

	dl_list_for_each_safe(timeout, prev, &eloop.timeout,
			      struct eloop_timeout, list) {
		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||
		     eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == ELOOP_ALL_CTX)) {
			eloop_remove_timeout(timeout);
			removed++;
		}
	}

	return removed;
}


int eloop_cancel_timeout_one(eloop_timeout_handler handler,
			     void *eloop_data, void *user_data,
			     struct os_time *remaining)
{
	struct eloop_timeout *timeout, *prev;
	int removed = 0;
	struct os_time now;

	os_get_time(&now);
	remaining->sec = remaining->usec = 0;

	dl_list_for_each_safe(timeout, prev, &eloop.timeout,
			      struct eloop_timeout, list) {
		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data) &&
		    (timeout->user_data == user_data)) {
			removed = 1;
			if (os_time_before(&now, &timeout->time))
				os_time_sub(&timeout->time, &now, remaining);
			eloop_remove_timeout(timeout);
			break;
		}
	}
	return removed;
}


int eloop_is_timeout_registered(eloop_timeout_handler handler,
				void *eloop_data, void *user_data)
{
	struct eloop_timeout *tmp;

	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (tmp->handler == handler &&
		    tmp->eloop_data == eloop_data &&
		    tmp->user_data == user_data)
			return 1;
	}

	return 0;
}


/* TODO: replace with suitable signal handler */
#if 0
static void eloop_handle_signal(int sig)
{
	int i;

	eloop.signaled++;
	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].sig == sig) {
			eloop.signals[i].signaled++;
			break;
		}
	}
}
#endif


static void eloop_process_pending_signals(void)
{
	int i;

	if (eloop.signaled == 0)
		return;
	eloop.signaled = 0;

	if (eloop.pending_terminate) {
		eloop.pending_terminate = 0;
	}

	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].signaled) {
			eloop.signals[i].signaled = 0;
			eloop.signals[i].handler(eloop.signals[i].sig,
						 eloop.signals[i].user_data);
		}
	}
}


int eloop_register_signal(int sig, eloop_signal_handler handler,
			  void *user_data)
{
	struct eloop_signal *tmp;

	tmp = os_realloc_array(eloop.signals, eloop.signal_count + 1,
			       sizeof(struct eloop_signal));
	if (tmp == NULL)
		return -1;

	tmp[eloop.signal_count].sig = sig;
	tmp[eloop.signal_count].user_data = user_data;
	tmp[eloop.signal_count].handler = handler;
	tmp[eloop.signal_count].signaled = 0;
	eloop.signal_count++;
	eloop.signals = tmp;

	/* TODO: register signal handler */

	return 0;
}


int eloop_register_signal_terminate(eloop_signal_handler handler,
				    void *user_data)
{
#if 0
	/* TODO: for example */
	int ret = eloop_register_signal(SIGINT, handler, user_data);
	if (ret == 0)
		ret = eloop_register_signal(SIGTERM, handler, user_data);
	return ret;
#endif
	return 0;
}


int eloop_register_signal_reconfig(eloop_signal_handler handler,
				   void *user_data)
{
#if 0
	/* TODO: for example */
	return eloop_register_signal(SIGHUP, handler, user_data);
#endif
	return 0;
}


void eloop_run(void)
{
	int i;
	struct os_time tv, now;

	while (!eloop.terminate &&
		(!dl_list_empty(&eloop.timeout) || eloop.reader_count > 0)) {
		struct eloop_timeout *timeout;
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
					list);
		if (timeout) {
			os_get_time(&now);
			if (os_time_before(&now, &timeout->time))
				os_time_sub(&timeout->time, &now, &tv);
			else
				tv.sec = tv.usec = 0;
		}

		/*
		 * TODO: wait for any event (read socket ready, timeout (tv),
		 * signal
		 */
		os_sleep(1, 0); /* just a dummy wait for testing */

		eloop_process_pending_signals();

		/* check if some registered timeouts have occurred */
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
					list);
		if (timeout) {
			os_get_time(&now);
			if (!os_time_before(&now, &timeout->time)) {
				void *eloop_data = timeout->eloop_data;
				void *user_data = timeout->user_data;
				eloop_timeout_handler handler =
					timeout->handler;
				eloop_remove_timeout(timeout);
				handler(eloop_data, user_data);
			}

		}

		eloop.reader_table_changed = 0;
		for (i = 0; i < eloop.reader_count; i++) {
			/*
			 * TODO: call each handler that has pending data to
			 * read
			 */
			if (0 /* TODO: eloop.readers[i].sock ready */) {
				eloop.readers[i].handler(
					eloop.readers[i].sock,
					eloop.readers[i].eloop_data,
					eloop.readers[i].user_data);
				if (eloop.reader_table_changed)
					break;
			}
		}
	}
}


void eloop_terminate(void)
{
	eloop.terminate = 1;
}


void eloop_destroy(void)
{
	struct eloop_timeout *timeout, *prev;

	dl_list_for_each_safe(timeout, prev, &eloop.timeout,
			      struct eloop_timeout, list) {
		eloop_remove_timeout(timeout);
	}
	os_free(eloop.readers);
	os_free(eloop.signals);
}


int eloop_terminated(void)
{
	return eloop.terminate;
}


void eloop_wait_for_read_sock(int sock)
{
	/*
	 * TODO: wait for the file descriptor to have something available for
	 * reading
	 */
}
