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

#ifndef _GETDNS_EXTRA_H_
#define _GETDNS_EXTRA_H_

#include <getdns/getdns.h>
#include <sys/time.h>

/* Enable the return_dnssec_status extension on every request.
   value is either GETDNS_EXTENSION_TRUE or GETDNS_EXTENSION_FALSE
   returns GETDNS_RETURN_GOOD on success or GETDNS_RETURN_INVALID_PARAMETER
   if context or value is invalid */
getdns_return_t getdns_context_set_return_dnssec_status(getdns_context* context, int enabled);

/* dict util */
/* set a string as bindata */
getdns_return_t getdns_dict_util_set_string(struct getdns_dict * dict, char *name,
    const char *value);

/* get a string from a dict.  the result must be freed if valid */
getdns_return_t getdns_dict_util_get_string(struct getdns_dict * dict, char *name,
    char **result);

/* Async support */
uint32_t getdns_context_get_num_pending_requests(getdns_context* context, struct timeval* next_timeout);

/* get the fd */
int getdns_context_fd(getdns_context* context);

/* process async reqs */
getdns_return_t getdns_context_process_async(getdns_context* context);


/* extensions */
typedef void (*getdns_timeout_callback) (void* userarg);

/* context timeout data */
typedef struct getdns_timeout_data {
    /* a timeout id */
    getdns_transaction_t transaction_id;
    /* the absolute time of the timeout */
    struct timeval timeout_time;
    /* the timeout callback to fire */
    getdns_timeout_callback callback;
    /* timeout callback user arg */
    void* userarg;
    /* pointer to the underlying extension pointer that the extension
       will create and free */
    void* extension_timer;
    /* context */
    struct getdns_context* context;
} getdns_timeout_data_t;

/* call the extension when the data needs to be cleaned up */
typedef getdns_return_t (*getdns_eventloop_cleanup_t)(struct getdns_context* context, void* eventloop_data);

/* call the extension to schedule a timer.  Any timer data that needs to be tracked should be
   stored in eventloop_timer */
typedef getdns_return_t (*getdns_eventloop_schedule_timeout_t)(struct getdns_context* context,
    void* eventloop_data, uint16_t timeout,
    getdns_timeout_data_t* timeout_data,
    void** eventloop_timer);

/* call the extension to free a timer.  The timer passed in is the same as that returned in
   the schedule timeout */
typedef getdns_return_t (*getdns_eventloop_clear_timeout_t)(struct getdns_context* context,
    void* eventloop_data, void* eventloop_timer);

/* call the extension to tell it that the number of outbound requests changed.  This is called
   when an async request is submitted or canceled by the user */
typedef getdns_return_t (*getdns_eventloop_request_count_changed_t)(struct getdns_context* context,
    uint32_t request_count, void* eventloop_data);

typedef struct getdns_eventloop_extension {
    getdns_eventloop_cleanup_t cleanup_data;
    getdns_eventloop_schedule_timeout_t schedule_timeout;
    getdns_eventloop_clear_timeout_t clear_timeout;
    getdns_eventloop_request_count_changed_t request_count_changed;
} getdns_eventloop_extension;

/* set an event loop extension on the context */
getdns_return_t
getdns_extension_set_eventloop(struct getdns_context* context,
    getdns_eventloop_extension* extension, void* extension_data);

void*
getdns_context_get_extension_data(struct getdns_context* context);

/* detach the eventloop from the context */
getdns_return_t
getdns_extension_detach_eventloop(struct getdns_context* context);


#endif
