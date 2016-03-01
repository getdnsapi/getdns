/**
 *
 * \file ub_loop.c
 * @brief Interface to the unbound pluggable event API
 *
 * These routines are not intended to be used by applications calling into
 * the library.
 *
 */

/*
 * Copyright (c) 2013, NLnet Labs, Verisign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ub_loop.h"
#ifdef HAVE_UNBOUND_EVENT_API

#ifndef HAVE_UNBOUND_EVENT_H
/** event timeout */
#define UB_EV_TIMEOUT      0x01
/** event fd readable */
#define UB_EV_READ         0x02
/** event fd writable */
#define UB_EV_WRITE        0x04
/** event signal */
#define UB_EV_SIGNAL       0x08
/** event must persist */
#define UB_EV_PERSIST      0x10

struct ub_event_base_vmt {
	void (*event_base_free)(struct ub_event_base*);
	int (*event_base_dispatch)(struct ub_event_base*);
	int (*event_base_loopexit)(struct ub_event_base*, struct timeval*);
	struct ub_event* (*event_new)(struct ub_event_base*,
	    int fd, short bits, void (*cb)(int, short, void*), void* arg);
	struct ub_event* (*signal_new)(struct ub_event_base*, int fd,
	    void (*cb)(int, short, void*), void* arg);
	struct ub_event* (*winsock_register_wsaevent)(struct ub_event_base*,
	    void* wsaevent, void (*cb)(int, short, void*), void* arg);
};

struct ub_event_vmt {
	void (*event_add_bits)(struct ub_event*, short);
	void (*event_del_bits)(struct ub_event*, short);
	void (*event_set_fd)(struct ub_event*, int);
	void (*event_free)(struct ub_event*);
	int (*event_add)(struct ub_event*, struct timeval*);
	int (*event_del)(struct ub_event*);
	int (*timer_add)(struct ub_event*, struct ub_event_base*,
	    void (*cb)(int, short, void*), void* arg, struct timeval*);
	int (*timer_del)(struct ub_event*);
	int (*signal_add)(struct ub_event*, struct timeval*);
	int (*signal_del)(struct ub_event*);
	void (*winsock_unregister_wsaevent)(struct ub_event* ev);
	void (*winsock_tcp_wouldblock)(struct ub_event*, int eventbit);
};

struct ub_event {
	struct ub_event_vmt* vmt;
};
#endif

typedef struct my_event {
	struct ub_event        super;
	/** event in the getdns event loop */
	getdns_eventloop_event gev;
	/** is event already added */
	int added;

	/** event loop it belongs to */
	_getdns_ub_loop *loop;
	/** fd to poll or -1 for timeouts. signal number for sigs. */
	int fd;
	/** what events this event is interested in, see EV_.. above. */
	short bits;
	/** timeout value */
	uint64_t timeout;
	/** callback to call: fd, eventbits, userarg */
	void (*cb)(int, short, void *arg);
	/** callback user arg */
	void *arg;
} my_event;

#define AS_UB_LOOP(x) \
	(((union {struct ub_event_base* a; _getdns_ub_loop* b;})x).b)
#define AS_MY_EVENT(x) \
	(((union {struct ub_event* a; my_event* b;})x).b)

static void my_event_base_free(struct ub_event_base* base)
{
	(void)base;
	return;
}

static int my_event_base_dispatch(struct ub_event_base* base)
{
	(void)base;
	/* We don't run the pluggable event base ourselfs */
	return -1;
}

static int my_event_base_loopexit(struct ub_event_base* base, struct timeval* tv)
{
	(void)tv;
	AS_UB_LOOP(base)->running = 0;
	return 0;
}

#define CLEAR_MY_EVENT(ev) \
	do { (ev)->loop->extension->vmt->clear((ev)->loop->extension, \
	    &(ev)->gev); (ev)->added = 0; } while(0)

#define SCHEDULE_MY_EVENT(ev) \
	do { if ((ev)->gev.read_cb||(ev)->gev.write_cb||(ev)->gev.timeout_cb){\
		(ev)->loop->extension->vmt->schedule((ev)->loop->extension, \
		(ev)->fd, (uint64_t)-1, &(ev)->gev); (ev)->added=1; }}while(0)

static void read_cb(void *userarg)
{
        struct my_event *ev = (struct my_event *)userarg;
        (*ev->cb)(ev->fd, UB_EV_READ, ev->arg);
	if ((ev->bits & UB_EV_PERSIST) == 0)
		CLEAR_MY_EVENT(ev);
}

static void write_cb(void *userarg)
{
        struct my_event *ev = (struct my_event *)userarg;
        (*ev->cb)(ev->fd, UB_EV_WRITE, ev->arg);
	if ((ev->bits & UB_EV_PERSIST) == 0)
		CLEAR_MY_EVENT(ev);
}

static void timeout_cb(void *userarg)
{
        struct my_event *ev = (struct my_event *)userarg;
        (*ev->cb)(ev->fd, UB_EV_TIMEOUT, ev->arg);
	if ((ev->bits & UB_EV_PERSIST) == 0)
		CLEAR_MY_EVENT(ev);
}

static void set_gev_callbacks(my_event* ev, short bits)
{
	int added = ev->added;

	if (ev->bits != bits) {
		if (added)
			CLEAR_MY_EVENT(ev);

		ev->gev.read_cb    = bits & UB_EV_READ    ? read_cb    : NULL;
		ev->gev.write_cb   = bits & UB_EV_WRITE   ? write_cb   : NULL;
		ev->gev.timeout_cb = bits & UB_EV_TIMEOUT ? timeout_cb : NULL;
		ev->bits = bits;

		if (added)
			SCHEDULE_MY_EVENT(ev);
	}
}

static void my_event_add_bits(struct ub_event* ev, short bits)
{
	set_gev_callbacks(AS_MY_EVENT(ev), AS_MY_EVENT(ev)->bits | bits);
}

static void my_event_del_bits(struct ub_event* ev, short bits)
{
	set_gev_callbacks(AS_MY_EVENT(ev), AS_MY_EVENT(ev)->bits & ~bits);
}

static void my_event_set_fd(struct ub_event* ub_ev, int fd)
{
	my_event *ev = AS_MY_EVENT(ub_ev);

	if (ev->fd != fd) {
		if (ev->added) {
			CLEAR_MY_EVENT(ev);
			ev->fd = fd;
			SCHEDULE_MY_EVENT(ev);
		} else
			ev->fd = fd;
	}
}

static void my_event_free(struct ub_event* ev)
{
	GETDNS_FREE(AS_MY_EVENT(ev)->loop->mf, ev);
}

static int my_event_del(struct ub_event* ev)
{
	if (AS_MY_EVENT(ev)->added)
		CLEAR_MY_EVENT(AS_MY_EVENT(ev));
	return 0;
}

static int my_event_add(struct ub_event* ev, struct timeval* tv)
{
	if (AS_MY_EVENT(ev)->added)
		my_event_del(ev);
	if (tv && (AS_MY_EVENT(ev)->bits & UB_EV_TIMEOUT) != 0)
		AS_MY_EVENT(ev)->timeout = (tv->tv_sec * 1000) + (tv->tv_usec / 1000);
	SCHEDULE_MY_EVENT(AS_MY_EVENT(ev));
	return 0;
}

static int my_timer_add(struct ub_event* ub_ev, struct ub_event_base* base,
    void (*cb)(int, short, void*), void* arg, struct timeval* tv)
{
	my_event *ev = AS_MY_EVENT(ub_ev);

	if (!base || !cb || !tv || AS_UB_LOOP(base) != ev->loop)
		return -1;

	if (ev->added)
		CLEAR_MY_EVENT(ev);

	ev->cb = cb;
	ev->arg = arg;
	return my_event_add(ub_ev, tv);
}

static int my_timer_del(struct ub_event* ev)
{
	return my_event_del(ev);
}


static int my_signal_add(struct ub_event* ub_ev, struct timeval* tv)
{
	return -1;
}

static int my_signal_del(struct ub_event* ub_ev)
{
	return -1;
}

static void my_winsock_unregister_wsaevent(struct ub_event* ev)
{
	(void)ev;
}

static void my_winsock_tcp_wouldblock(struct ub_event* ev, int bits)
{
	(void)ev; (void)bits;
}

static struct ub_event* my_event_new(struct ub_event_base* base, int fd,
    short bits, void (*cb)(int, short, void*), void* arg)
{
	static struct ub_event_vmt vmt = {
		my_event_add_bits,
		my_event_del_bits,
		my_event_set_fd,
		my_event_free,
		my_event_add,
		my_event_del,
		my_timer_add,
		my_timer_del,
		my_signal_add,
		my_signal_del,
		my_winsock_unregister_wsaevent,
		my_winsock_tcp_wouldblock
	};
	my_event *ev;

	if (!base || !cb)
		return NULL;
       
	ev = GETDNS_MALLOC(AS_UB_LOOP(base)->mf, my_event);
	ev->super.vmt = &vmt;
	ev->loop = AS_UB_LOOP(base);
	ev->added = 0;
	ev->fd = fd;
	ev->bits = bits;
	ev->timeout = (uint64_t)-1;
	ev->cb = cb;
	ev->arg = arg;
	ev->gev.userarg = ev;
	ev->gev.read_cb    = bits & UB_EV_READ    ? read_cb    : NULL;
	ev->gev.write_cb   = bits & UB_EV_WRITE   ? write_cb   : NULL;
	ev->gev.timeout_cb = bits & UB_EV_TIMEOUT ? timeout_cb : NULL;
	return &ev->super;
}

static struct ub_event* my_signal_new(struct ub_event_base* base, int fd,
    void (*cb)(int, short, void*), void* arg)
{
	return my_event_new(base, fd, UB_EV_SIGNAL | UB_EV_PERSIST, cb, arg);
}

static struct ub_event* my_winsock_register_wsaevent(struct ub_event_base *b,
    void* wsaevent, void (*cb)(int, short, void*), void* arg)
{
	/* Not applicable, because in unbound used for tubes only */
	(void)b; (void)wsaevent; (void)cb; (void)arg;
	return NULL;
}

void _getdns_ub_loop_init(_getdns_ub_loop *loop, struct mem_funcs *mf, getdns_eventloop *extension)
{
	static struct ub_event_base_vmt vmt = {
		my_event_base_free,
		my_event_base_dispatch,
		my_event_base_loopexit,
		my_event_new,
		my_signal_new,
		my_winsock_register_wsaevent
	};

	loop->super.vmt = &vmt;
	loop->mf = *mf;
	loop->extension = extension;
	loop->running = 1;
}

#endif
/* ub_loop.c */
