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

#include <getdns/getdns_ext_libevent.h>
#include "config.h"
#include <sys/time.h>

#ifdef HAVE_EVENT2_EVENT_H
#  include <event2/event.h>
#else
#  include <event.h>
#  define evutil_socket_t int
#  define event_free free
#  define evtimer_new(b, cb, arg) event_new((b), -1, 0, (cb), (arg))
#endif
#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

#ifndef HAVE_EVENT_BASE_FREE
#define event_base_free(x) /* nop */
#endif
#ifndef HAVE_EVENT_BASE_NEW
#define event_base_new event_init
#endif

#ifndef HAVE_EVENT2_EVENT_H
static struct event *
event_new(struct event_base *b, evutil_socket_t fd, short ev, void* cb, void *arg)
{
    struct event* e = (struct event*)calloc(1, sizeof(struct event));
    if(!e) return NULL;
    event_set(e, fd, ev, cb, arg);
    event_base_set(b, e);
    return e;
}
#endif /* no event2 */

/* extension info */
struct event_data {
    struct event* event;
    struct event_base* event_base;
};

static void
request_count_changed(uint32_t request_count, struct event_data *ev_data) {
    if (request_count > 0) {
        event_add(ev_data->event, NULL);
    } else {
        event_del(ev_data->event);
    }
}

/* lib event callbacks */
static void
getdns_libevent_cb(evutil_socket_t fd, short what, void *userarg) {
    struct getdns_context* context = (struct getdns_context*) userarg;
    getdns_context_process_async(context);
    uint32_t rc = getdns_context_get_num_pending_requests(context, NULL);
    struct event_data* ev_data =
        (struct event_data*) getdns_context_get_extension_data(context);
    request_count_changed(rc, ev_data);
}

static void
getdns_libevent_timeout_cb(evutil_socket_t fd, short what, void* userarg) {
    getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) userarg;
    timeout_data->callback(timeout_data->userarg);
    uint32_t rc = getdns_context_get_num_pending_requests(timeout_data->context, NULL);
    struct event_data* ev_data =
        (struct event_data*) getdns_context_get_extension_data(timeout_data->context);
    request_count_changed(rc, ev_data);
}

/* getdns extension functions */
static getdns_return_t
getdns_libevent_request_count_changed(struct getdns_context* context,
    uint32_t request_count, void* eventloop_data) {
    struct event_data *edata = (struct event_data*) eventloop_data;
    request_count_changed(request_count, edata);
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libevent_cleanup(struct getdns_context* context, void* data) {
    struct event_data *edata = (struct event_data*) data;
    event_del(edata->event);
    event_free(edata->event);
    free(edata);
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libevent_schedule_timeout(struct getdns_context* context,
    void* eventloop_data, uint16_t timeout,
    getdns_timeout_data_t* timeout_data,
    void** eventloop_timer) {

    struct timeval tv;
    struct event* ev = NULL;
    struct event_data* ev_data = (struct event_data*) eventloop_data;

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    ev = evtimer_new(ev_data->event_base, getdns_libevent_timeout_cb, timeout_data);
    evtimer_add(ev, &tv);

    *eventloop_timer = ev;
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
getdns_libevent_clear_timeout(struct getdns_context* context,
    void* eventloop_data, void* eventloop_timer) {
    struct event* ev = (struct event*) eventloop_timer;
    event_del(ev);
    event_free(ev);
    return GETDNS_RETURN_GOOD;
}


static getdns_eventloop_extension LIBEVENT_EXT = {
    getdns_libevent_cleanup,
    getdns_libevent_schedule_timeout,
    getdns_libevent_clear_timeout,
    getdns_libevent_request_count_changed
};

/*
 * getdns_extension_set_libevent_base
 *
 */
getdns_return_t
getdns_extension_set_libevent_base(struct getdns_context *context,
    struct event_base * this_event_base)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
    RETURN_IF_NULL(this_event_base, GETDNS_RETURN_INVALID_PARAMETER);
    /* TODO: cleanup current extension base */
    getdns_return_t r = getdns_extension_detach_eventloop(context);
    if (r != GETDNS_RETURN_GOOD) {
        return r;
    }
    int fd = getdns_context_fd(context);
    struct event* getdns_event = event_new(this_event_base, fd, EV_READ | EV_PERSIST, getdns_libevent_cb, context);
    if (!getdns_event) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    /* TODO: use context functs? */
    struct event_data* ev_data = (struct event_data*) malloc(sizeof(struct event_data));
    if (!ev_data) {
        /* cleanup */
        event_del(getdns_event);
        event_free(getdns_event);
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    ev_data->event = getdns_event;
    ev_data->event_base = this_event_base;
    return getdns_extension_set_eventloop(context, &LIBEVENT_EXT, ev_data);
}               /* getdns_extension_set_libevent_base */
