/**
 * \file
 * \brief Public interfaces to getdns, include in your application to use getdns API.
 *
 * This source was taken from the original pseudo-implementation by
 * Paul Hoffman.
 */

/*
 * Copyright (c) 2013, NLNet Labs, Verisign, Inc.
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

#include <sys/time.h>
#include <stdio.h>
#include <uv.h>
#include "getdns/getdns_ext_libuv.h"
#include "types-internal.h"

#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

typedef struct getdns_libuv {
	getdns_eventloop_vmt *vmt;
	uv_loop_t            *loop;
	struct mem_funcs      mf;
} getdns_libuv;

static getdns_return_t getdns_libuv_cleanup(getdns_eventloop *loop);
static getdns_return_t getdns_libuv_schedule_read(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *ev);
static getdns_return_t getdns_libuv_schedule_timeout
    (getdns_eventloop *loop, uint64_t timeout, getdns_eventloop_event *ev);
static getdns_return_t getdns_libuv_clear_event
    (getdns_eventloop *loop, getdns_eventloop_event *ev);

static getdns_eventloop_vmt getdns_libuv_vmt = {
	getdns_libuv_cleanup,
	getdns_libuv_schedule_read,
	getdns_libuv_clear_event,
	getdns_libuv_schedule_timeout,
	getdns_libuv_clear_event,
};

getdns_return_t
getdns_extension_set_libuv_loop(getdns_context *context, uv_loop_t *loop)
{
	getdns_libuv *ext;
	getdns_return_t r;

	RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	RETURN_IF_NULL(loop, GETDNS_RETURN_INVALID_PARAMETER);

	if ((r = getdns_context_detach_eventloop(context)))
		return r;

	ext = GETDNS_MALLOC(*priv_getdns_context_mf(context), getdns_libuv);
	ext->vmt  = &getdns_libuv_vmt;
	ext->loop = loop;
	ext->mf   = *priv_getdns_context_mf(context);

	return getdns_context_set_eventloop(context, (getdns_eventloop *)&ext);
}

static getdns_return_t
getdns_libuv_cleanup(getdns_eventloop *loop)
{
	getdns_libuv *ext = (getdns_libuv *)loop;

	GETDNS_FREE(ext->mf, ext);
	return GETDNS_RETURN_GOOD;
}

typedef struct poll_timer {
	uv_poll_t  poll;
	uv_timer_t timer;
} poll_timer;


static void
getdns_libuv_read_cb(uv_poll_t *poll, int status, int events)
{
        getdns_eventloop_event *el_ev = (getdns_eventloop_event *)poll->data;
        assert(el_ev->read_cb);
        el_ev->read_cb(el_ev->userarg);
}

static void
getdns_libuv_timeout_cb(uv_timer_t *timer, int status)
{
        getdns_eventloop_event *el_ev = (getdns_eventloop_event *)timer->data;
        assert(el_ev->timeout_cb);
        el_ev->timeout_cb(el_ev->userarg);
}

static getdns_return_t
getdns_libuv_schedule_read(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *el_ev)
{
	getdns_libuv *ext = (getdns_libuv *)loop;
	poll_timer   *my_ev;
	uv_poll_t    *my_poll;
	uv_timer_t   *my_timer;

	if (fd < 0) el_ev->read_cb = NULL;
	if (timeout == TIMEOUT_FOREVER) el_ev->timeout_cb = NULL;

	if (!el_ev->read_cb && !el_ev->timeout_cb)
		return GETDNS_RETURN_GOOD; /* Nothing to schedule */

	if (!(my_ev = GETDNS_MALLOC(ext->mf, poll_timer)))
		return GETDNS_RETURN_MEMORY_ERROR;

	el_ev->ev = my_ev;
	
	if (el_ev->read_cb) {
		my_poll = &my_ev->poll;
		uv_poll_init(ext->loop, my_poll, fd);
		my_poll->data = el_ev;
		uv_poll_start(my_poll, UV_READABLE, getdns_libuv_read_cb);
	}
	if (el_ev->timeout_cb) {
		my_timer = &my_ev->timer;
		uv_timer_init(ext->loop, my_timer);
		my_timer->data = el_ev;
		uv_timer_start(my_timer, getdns_libuv_timeout_cb, timeout, 0);
	}
	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libuv_schedule_timeout(getdns_eventloop *loop,
    uint64_t timeout, getdns_eventloop_event *el_ev)
{
	return getdns_libuv_schedule_read(loop, -1, timeout, el_ev);
}

static getdns_return_t
getdns_libuv_clear_event(getdns_eventloop *loop,
    getdns_eventloop_event *el_ev)
{
	getdns_libuv *ext = (getdns_libuv *)loop;
	poll_timer *my_ev = (poll_timer *)el_ev->ev;
	
	assert(my_ev);

	if (el_ev->read_cb) {
		uv_poll_stop(&my_ev->poll);
		uv_close((uv_handle_t *)&my_ev->poll, NULL);
	}
	if (el_ev->timeout_cb)
		uv_timer_stop(&my_ev->timer);
		uv_close((uv_handle_t *)&my_ev->timer, NULL);

	GETDNS_FREE(ext->mf, el_ev->ev);
	el_ev->ev = NULL;
	return GETDNS_RETURN_GOOD;
}

