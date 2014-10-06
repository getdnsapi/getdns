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
#include "getdns/getdns_ext_libev.h"
#include "config.h"

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

/* extension info */
struct getdns_libev_data {
    struct ev_loop* loop;
    struct ev_io* poll_handle;
};

static void
request_count_changed(uint32_t request_count, struct getdns_libev_data *ev_data) {
    if (request_count > 0) {
        ev_io_start(ev_data->loop, ev_data->poll_handle);
    } else {
        ev_io_stop(ev_data->loop, ev_data->poll_handle);
    }
}

/* lib ev callbacks */
static void
getdns_libev_cb(struct ev_loop *loop, struct ev_io *handle, int revents) {
    struct getdns_context* context = (struct getdns_context*) handle->data;
    if (getdns_context_process_async(context) == GETDNS_RETURN_BAD_CONTEXT) {
        // context destroyed
        return;
    }
    uint32_t rc = getdns_context_get_num_pending_requests(context, NULL);
    struct getdns_libev_data* ev_data =
        (struct getdns_libev_data*) getdns_context_get_extension_data(context);
    request_count_changed(rc, ev_data);
}

static void
getdns_libev_timeout_cb(struct ev_loop *loop, struct ev_timer* handle, int status) {
    getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) handle->data;
    timeout_data->callback(timeout_data->userarg);
}

/* getdns extension functions */
static getdns_return_t
getdns_libev_request_count_changed(struct getdns_context* context,
    uint32_t request_count, void* eventloop_data) {
    struct getdns_libev_data *ev_data = (struct getdns_libev_data*) eventloop_data;
    request_count_changed(request_count, ev_data);
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libev_cleanup(struct getdns_context* context, void* data) {
    struct getdns_libev_data *ev_data = (struct getdns_libev_data*) data;
    ev_io_stop(ev_data->loop, ev_data->poll_handle);
    free(ev_data->poll_handle);
    free(ev_data);
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libev_schedule_timeout(struct getdns_context* context,
    void* eventloop_data, uint64_t timeout,
    getdns_timeout_data_t* timeout_data)
{
    struct ev_timer *timer;
    struct getdns_libev_data* ev_data = (struct getdns_libev_data*) eventloop_data;
    ev_tstamp to = timeout;
    to /= 1000;
    timer = (struct ev_timer*) malloc(sizeof(struct ev_timer));
    ev_timer_init(timer, getdns_libev_timeout_cb, to, 0);
    timer->data = timeout_data;
    timeout_data->extension_timer = timer;
    ev_timer_start(ev_data->loop, timer);

    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libev_clear_timeout(struct getdns_context* context,
    void* eventloop_data, void* eventloop_timer) {
    struct ev_timer* timer = (struct ev_timer*) eventloop_timer;
    struct getdns_libev_data* ev_data = (struct getdns_libev_data*) eventloop_data;
    ev_timer_stop(ev_data->loop, timer);
    free(timer);
    return GETDNS_RETURN_GOOD;
}


static getdns_eventloop_extension LIBEV_EXT = {
    getdns_libev_cleanup,
    getdns_libev_schedule_timeout,
    getdns_libev_clear_timeout,
    getdns_libev_request_count_changed
};

/*
 * getdns_extension_set_libev_loop
 *
 */
getdns_return_t
getdns_extension_set_libev_loop(struct getdns_context *context,
    struct ev_loop *loop)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(loop, GETDNS_RETURN_INVALID_PARAMETER);
    /* TODO: cleanup current extension base */
    getdns_return_t r = getdns_extension_detach_eventloop(context);
    if (r != GETDNS_RETURN_GOOD) {
        return r;
    }
    struct getdns_libev_data* ev_data = (struct getdns_libev_data*) malloc(sizeof(struct getdns_libev_data));
    if (!ev_data) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    int fd = getdns_context_fd(context);
    ev_data->poll_handle = (struct ev_io*) malloc(sizeof(struct ev_io));
    ev_io_init(ev_data->poll_handle, getdns_libev_cb, fd, EV_READ);
    ev_data->loop = loop;

    ev_data->poll_handle->data = context;
    return getdns_extension_set_eventloop(context, &LIBEV_EXT, ev_data);
}               /* getdns_extension_set_libev_loop */
