/**
 *
 * \file libmini_event.c
 * @brief Build in default eventloop extension that uses select.
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

#include "extension/libmini_event.h"
#include "context.h"

static void
getdns_mini_event_cleanup(getdns_eventloop *loop)
{
	getdns_mini_event *ext = (getdns_mini_event *)loop;
	getdns_event_base_free(ext->base);
}

void
getdns_mini_event_destroy(getdns_mini_event *ext)
{
	assert(ext);
	ext->loop.vmt->cleanup(&ext->loop);
	GETDNS_FREE(ext->mf, ext);
}

void getdns_handle_timeouts(struct getdns_event_base* base,
    struct timeval* now, struct timeval* wait);
int getdns_handle_select(struct getdns_event_base* base, struct timeval* wait);

static int
getdns_mini_event_settime(getdns_mini_event *ext)
{
	if (gettimeofday(&ext->time_tv, NULL) < 0)
		return -1;
	ext->time_secs = (time_t)ext->time_tv.tv_sec;
	return 0;
}

static void
getdns_mini_event_run(getdns_eventloop *loop)
{
	getdns_mini_event *ext = (getdns_mini_event *)loop;
	struct timeval wait;

	if (ext->n_events == 0 || getdns_mini_event_settime(ext) < 0)
		return;

	do {
		(void) getdns_handle_timeouts(ext->base, &ext->time_tv, &wait);

		if (!ext->n_events)
			break;

		if (getdns_handle_select(ext->base, &wait))
			break;

	} while (ext->n_events);
}

static void
getdns_mini_event_run_once(getdns_eventloop *loop, int blocking)
{
	static struct timeval immediately = { 0, 0 };
	getdns_mini_event *ext = (getdns_mini_event *)loop;
	struct timeval wait;

	if (blocking) {
		if (getdns_mini_event_settime(ext) < 0)
			return;
		getdns_handle_timeouts(ext->base, &ext->time_tv, &wait);
		if (getdns_handle_select(ext->base, &wait) < 0)
			return;

	} else if (getdns_handle_select(ext->base, &immediately) < 0)
		return;

	getdns_handle_timeouts(ext->base, &ext->time_tv, &wait);
}

static getdns_return_t
getdns_mini_event_clear(getdns_eventloop *loop, getdns_eventloop_event *el_ev)
{
	getdns_mini_event *ext = (getdns_mini_event *)loop;
	
	assert(el_ev->ev);

	if (getdns_event_del(el_ev->ev) != 0)
		return GETDNS_RETURN_GENERIC_ERROR;

	GETDNS_FREE(ext->mf, el_ev->ev);
	el_ev->ev = NULL;

	ext->n_events--;

	return GETDNS_RETURN_GOOD;
}

static void
getdns_mini_event_callback(int fd, short bits, void *arg)
{
	getdns_eventloop_event *el_ev = (getdns_eventloop_event *)arg;
	if (bits & EV_READ) {
		assert(el_ev->read_cb);
		el_ev->read_cb(el_ev->userarg);
	} else if (bits & EV_WRITE) {
		assert(el_ev->write_cb);
		el_ev->write_cb(el_ev->userarg);
	} else if (bits & EV_TIMEOUT) {
		assert(el_ev->timeout_cb);
		el_ev->timeout_cb(el_ev->userarg);
	} else
		assert(ASSERT_UNREACHABLE);
}

static getdns_return_t
getdns_mini_event_schedule(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *el_ev)
{
	getdns_mini_event *ext = (getdns_mini_event *)loop;
	struct getdns_event *my_ev;
	struct timeval tv = { timeout / 1000, (timeout % 1000) * 1000 };

	assert(el_ev);
	assert(!(el_ev->read_cb || el_ev->write_cb) || fd >= 0);
	assert(  el_ev->read_cb || el_ev->write_cb  || el_ev->timeout_cb);

	if (!(my_ev = GETDNS_MALLOC(ext->mf, struct getdns_event)))
		return GETDNS_RETURN_MEMORY_ERROR;

	el_ev->ev = my_ev;
	getdns_event_set(my_ev, fd, (
	    (el_ev->read_cb ? EV_READ|EV_PERSIST : 0) |
	    (el_ev->write_cb ? EV_WRITE|EV_PERSIST : 0) |
	    (el_ev->timeout_cb ? EV_TIMEOUT : 0)),
	    getdns_mini_event_callback, el_ev);
	
	if (getdns_mini_event_settime(ext))
		goto error;

	(void) getdns_event_base_set(ext->base, my_ev);
	if (getdns_event_add(my_ev, el_ev->timeout_cb ? &tv : NULL))
		goto error;

	ext->n_events++;

	return GETDNS_RETURN_GOOD;
error:
	GETDNS_FREE(ext->mf, my_ev);
	el_ev->ev = NULL;
	return GETDNS_RETURN_GENERIC_ERROR;
}

getdns_return_t
getdns_mini_event_init(getdns_context *context, getdns_mini_event *ext)
{
	static getdns_eventloop_vmt getdns_mini_event_vmt = {
		getdns_mini_event_cleanup,
		getdns_mini_event_schedule,
		getdns_mini_event_clear,
		getdns_mini_event_run,
		getdns_mini_event_run_once
	};

	if (!context)
		return GETDNS_RETURN_BAD_CONTEXT;
	if (!ext)
		return GETDNS_RETURN_INVALID_PARAMETER;

	ext->n_events = 0;
	ext->loop.vmt = &getdns_mini_event_vmt;
	ext->base = getdns_event_init(&ext->time_secs, &ext->time_tv);
	if (!ext->base)
		return GETDNS_RETURN_MEMORY_ERROR;

	ext->mf = context->mf;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_mini_event_create(getdns_context *context, getdns_mini_event **ext)
{
	if (!context) return GETDNS_RETURN_BAD_CONTEXT;
	if (!ext)     return GETDNS_RETURN_INVALID_PARAMETER;

	*ext = GETDNS_MALLOC(context->mf, getdns_mini_event);
	return getdns_mini_event_init(context, *ext);
}
