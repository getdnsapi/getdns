/**
 * \file
 * \brief Public interfaces to getdns, include in your application to use getdns API.
 *
 * This source was taken from the original pseudo-implementation by
 * Paul Hoffman.
 */

/*
 * Copyright (c) 2013, NLNet Labs, Versign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
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

#include <getdns/getdns_ext_libev.h>
#include "config.h"
#include "context.h"
#include <sys/time.h>
#include <stdio.h>
#include <ev.h>

#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

/* extension info */
struct getdns_libev_data {
    struct ev_loop* loop;
    struct ev_io* poll_handle;
};

/* lib event callbacks */
static void
getdns_libev_cb(struct ev_loop *loop, struct ev_io *handle, int revents) {
    printf("CB on loop %p\n", loop);
    struct getdns_context* context = (struct getdns_context*) handle->data;
    struct getdns_libev_data* data = (struct getdns_libev_data*) context->extension_data;
    printf("context data %p %p %p\n", context, data, data->loop);
    getdns_context_process_async(context);
    printf("(2) context data %p %p\n", data, data->loop);
}

static void
getdns_libev_timeout_cb(struct ev_loop *loop, struct ev_timer* handle, int status) {
    printf("Timeout on loop %p\n", loop);
    getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) handle->data;
    timeout_data->callback(timeout_data->userarg);
}

/* getdns extension functions */
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
    void* eventloop_data, uint16_t timeout,
    getdns_timeout_data_t* timeout_data,
    void** eventloop_timer) {

    struct ev_timer *timer;
    struct getdns_libev_data* ev_data = (struct getdns_libev_data*) eventloop_data;
    ev_tstamp to = timeout;
    to /= 1000;
    timer = (struct ev_timer*) malloc(sizeof(struct ev_timer));
    ev_timer_init(timer, getdns_libev_timeout_cb, to, 0);
    timer->data = timeout_data;
    ev_timer_start(ev_data->loop, timer);

    *eventloop_timer = timer;
    printf("Scheduled timer %p on loop %p (%p)\n", timer, ev_data->loop, ev_data);
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libev_clear_timeout(struct getdns_context* context,
    void* eventloop_data, void* eventloop_timer) {
    struct ev_timer* timer = (struct ev_timer*) eventloop_timer;
    struct getdns_libev_data* ev_data = (struct getdns_libev_data*) eventloop_data;
    printf("Clearing timer %p on loop %p (%p, %p)\n", timer, ev_data->loop, ev_data, context);
    ev_timer_stop(ev_data->loop, timer);
    free(timer);
    return GETDNS_RETURN_GOOD;
}


static getdns_eventloop_extension LIBEV_EXT = {
    getdns_libev_cleanup,
    getdns_libev_schedule_timeout,
    getdns_libev_clear_timeout
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

    printf("Attaching to loop %p (%p)\n", ev_data->loop, ev_data);
    ev_io_start(ev_data->loop, ev_data->poll_handle);
    ev_data->poll_handle->data = context;
    return getdns_extension_set_eventloop(context, &LIBEV_EXT, ev_data);
}               /* getdns_extension_set_libev_loop */
