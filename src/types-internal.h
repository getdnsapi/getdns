/**
 *
 * /brief getdns contect management functions
 *
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
 *
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TYPES_INTERNAL_H_
#define TYPES_INTERNAL_H_

#include "context.h"
#include <ldns/ldns.h>

/* declarations */
struct getdns_dns_req;
struct getdns_network_req;
struct ub_ctx;
struct event;
struct event_base;

typedef enum network_req_state_enum {
    NET_REQ_NOT_SENT,
    NET_REQ_IN_FLIGHT,
    NET_REQ_FINISHED,
    NET_REQ_CANCELED
} network_req_state;

/**
 * Request data for unbound
 **/
typedef struct getdns_network_req {
	/* the async_id from unbound */
    int unbound_id;
    /* state var */
    network_req_state state;
    /* owner request (contains name) */
    struct getdns_dns_req* owner;

    /* request type */
    uint16_t request_type;

    /* request class */
    uint16_t request_class;

    /* result */
    ldns_pkt* result;

    /* next request to issue after this one */
    struct getdns_network_req* next;
} getdns_network_req;

/* dns request - manages a number of network requests and
 * the initial data passed to getdns_general
 */
typedef struct getdns_dns_req {

    /* name */
    char *name;

    /* canceled flag */
    int canceled;

    /* current network request */
	struct getdns_network_req *current_req;

    /* first request in list */
    struct getdns_network_req *first_req;

    /* request timeout event */
    struct event* timeout;

    /* local callback timer */
    struct event* local_cb_timer;

    /* event base this req is scheduled on */
    struct event_base* ev_base;

    /* context that owns the request */
    getdns_context_t context;

    /* ub_ctx issuing the request */
    struct ub_ctx* unbound;

    /* request extensions */
    getdns_dict *extensions;

    /* callback data */
    getdns_callback_t user_callback;
    void *user_pointer;

    /* the transaction id */
    getdns_transaction_t trans_id;

} getdns_dns_req;

/* utility methods */

/* network request utilities */
void network_req_free(getdns_network_req* net_req);

getdns_network_req* network_req_new(getdns_dns_req* owner,
                                    uint16_t request_type,
                                    uint16_t request_class,
                                    struct getdns_dict* extensions);


/* dns request utils */
getdns_dns_req* dns_req_new(getdns_context_t context,
                            struct ub_ctx* unbound,
                            const char* name,
                            uint16_t request_type,
                            struct getdns_dict *extensions);


void dns_req_free(getdns_dns_req* req);

#endif
