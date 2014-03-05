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

#include <getdns/getdns_ext_libuv.h>
#include <sys/time.h>
#include <stdio.h>
#include <uv.h>

#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

/* extension info */
struct getdns_libuv_data {
    uv_loop_t* loop;
    uv_poll_t* poll_handle;
};

static void request_count_changed(uint32_t request_count, struct getdns_libuv_data *uv_data);

/* lib event callbacks */
static void
getdns_libuv_cb(uv_poll_t* handle, int status, int events) {
    struct getdns_context* context = (struct getdns_context*) handle->data;
    if (getdns_context_process_async(context) == GETDNS_RETURN_BAD_CONTEXT) {
        // context destroyed
        return;
    }
    uint32_t rc = getdns_context_get_num_pending_requests(context, NULL);
    struct getdns_libuv_data* uv_data =
        (struct getdns_libuv_data*) getdns_context_get_extension_data(context);
    request_count_changed(rc, uv_data);
}

static void
request_count_changed(uint32_t request_count, struct getdns_libuv_data *uv_data) {
    if (request_count > 0 && !uv_is_active((uv_handle_t*) uv_data->poll_handle)) {
        uv_poll_start(uv_data->poll_handle, UV_READABLE, getdns_libuv_cb);
    } else if (request_count == 0 && uv_is_active((uv_handle_t*) uv_data->poll_handle)) {
        uv_poll_stop(uv_data->poll_handle);
    }
}

static void
getdns_libuv_timeout_cb(uv_timer_t* handle, int status) {
    getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) handle->data;
    timeout_data->callback(timeout_data->userarg);
    uint32_t rc = getdns_context_get_num_pending_requests(timeout_data->context, NULL);
    struct getdns_libuv_data* uv_data =
        (struct getdns_libuv_data*) getdns_context_get_extension_data(timeout_data->context);
    request_count_changed(rc, uv_data);
}

static void
getdns_libuv_close_cb(uv_handle_t* handle) {
    free(handle);
}

/* getdns extension functions */
static getdns_return_t
getdns_libuv_request_count_changed(struct getdns_context* context,
    uint32_t request_count, void* eventloop_data) {
    struct getdns_libuv_data *edata = (struct getdns_libuv_data*) eventloop_data;
    request_count_changed(request_count, edata);
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libuv_cleanup(struct getdns_context* context, void* data) {
    struct getdns_libuv_data *uv_data = (struct getdns_libuv_data*) data;
    uv_poll_stop(uv_data->poll_handle);
    uv_close((uv_handle_t*) uv_data->poll_handle, getdns_libuv_close_cb);
    /* handle itself gets cleaned up in close_cb */
    free(uv_data);
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libuv_schedule_timeout(struct getdns_context* context,
    void* eventloop_data, uint16_t timeout,
    getdns_timeout_data_t* timeout_data,
    void** eventloop_timer) {

    uv_timer_t *timer;
    struct getdns_libuv_data* uv_data = (struct getdns_libuv_data*) eventloop_data;

    timer = (uv_timer_t*) malloc(sizeof(uv_timer_t));
    timer->data = timeout_data;
    uv_timer_init(uv_data->loop, timer);
    uv_timer_start(timer, getdns_libuv_timeout_cb, timeout, 0);

    *eventloop_timer = timer;
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libuv_clear_timeout(struct getdns_context* context,
    void* eventloop_data, void* eventloop_timer) {
    uv_timer_t* timer = (uv_timer_t*) eventloop_timer;
    uv_timer_stop(timer);
    uv_close((uv_handle_t*) timer, getdns_libuv_close_cb);
    return GETDNS_RETURN_GOOD;
}


static getdns_eventloop_extension LIBUV_EXT = {
    getdns_libuv_cleanup,
    getdns_libuv_schedule_timeout,
    getdns_libuv_clear_timeout,
    getdns_libuv_request_count_changed
};

/*
 * getdns_extension_set_libuv_loop
 *
 */
getdns_return_t
getdns_extension_set_libuv_loop(struct getdns_context *context,
    struct uv_loop_s *uv_loop)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(uv_loop, GETDNS_RETURN_INVALID_PARAMETER);
    /* TODO: cleanup current extension base */
    getdns_return_t r = getdns_extension_detach_eventloop(context);
    if (r != GETDNS_RETURN_GOOD) {
        return r;
    }
    struct getdns_libuv_data* uv_data = (struct getdns_libuv_data*) malloc(sizeof(struct getdns_libuv_data));
    if (!uv_data) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    int fd = getdns_context_fd(context);
    uv_data->poll_handle = (uv_poll_t*) malloc(sizeof(uv_poll_t));
    if (!uv_data->poll_handle) {
        free(uv_data);
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    uv_poll_init(uv_loop, uv_data->poll_handle, fd);
    uv_data->poll_handle->data = context;
    uv_data->loop = uv_loop;
    return getdns_extension_set_eventloop(context, &LIBUV_EXT, uv_data);
}               /* getdns_extension_set_libuv_loop */
