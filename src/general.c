/**
 *
 * /brief getdns core functions
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

#include <string.h>
#include <unbound.h>
#include <unbound-event.h>
#include <event2/event.h>
#include <ldns/ldns.h>
#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include <stdio.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/* declarations */
static void ub_resolve_callback(void* arg, int err, ldns_buffer* result, int sec, char* bogus);
static void ub_resolve_timeout(evutil_socket_t fd, short what, void *arg);
static void ub_local_resolve_timeout(evutil_socket_t fd, short what, void *arg);

static void handle_network_request_error(getdns_network_req* netreq, int err);
static void handle_dns_request_complete(getdns_dns_req* dns_req);
static int submit_network_request(getdns_network_req* netreq);

typedef struct netreq_cb_data {
     getdns_network_req *netreq;
     int err;
     ldns_buffer* result;
     int sec;
     char* bogus;
} netreq_cb_data;

/* cancel, cleanup and send timeout to callback */
static void ub_resolve_timeout(evutil_socket_t fd, short what, void *arg) {
    getdns_dns_req *dns_req = (getdns_dns_req*) arg;
    getdns_context_t context = dns_req->context;
    getdns_transaction_t trans_id = dns_req->trans_id;
    getdns_callback_t cb = dns_req->user_callback;
    void* user_arg = dns_req->user_pointer;

    /* cancel the req - also clears it from outbound */
    getdns_context_cancel_request(context, trans_id, 0);

    /* cleanup */
    dns_req_free(dns_req);

    cb(context,
       GETDNS_CALLBACK_TIMEOUT,
       NULL,
       user_arg,
       trans_id);
}

static void ub_local_resolve_timeout(evutil_socket_t fd, short what, void *arg) {    
    netreq_cb_data* cb_data = (netreq_cb_data*) arg;
    
    /* cleanup the local timer here since the memory may be
     * invalid after calling ub_resolve_callback
     */
    getdns_dns_req* dnsreq = cb_data->netreq->owner;
    event_free(dnsreq->local_cb_timer);
    dnsreq->local_cb_timer = NULL;

    /* just call ub_resolve_callback */
    ub_resolve_callback(cb_data->netreq, cb_data->err, cb_data->result, cb_data->sec, cb_data->bogus);

    /* cleanup the state */
    ldns_buffer_free(cb_data->result);
    if (cb_data->bogus) {
        free(cb_data->bogus);
    }     
    free(cb_data);
}

/* cleanup and send an error to the user callback */
static void handle_network_request_error(getdns_network_req* netreq, int err) {
    getdns_dns_req *dns_req = netreq->owner;
    getdns_context_t context = dns_req->context;
    getdns_transaction_t trans_id = dns_req->trans_id;
    getdns_callback_t cb = dns_req->user_callback;
    void* user_arg = dns_req->user_pointer;

    /* clean up */
    getdns_context_clear_outbound_request(dns_req);
    dns_req_free(dns_req);

    cb(context,
       GETDNS_CALLBACK_ERROR,
       NULL,
       user_arg,
       trans_id);
}

/* cleanup and send the response to the user callback */
static void handle_dns_request_complete(getdns_dns_req* dns_req) {
    getdns_dict* response = create_getdns_response(dns_req);

    getdns_context_t context = dns_req->context;
    getdns_transaction_t trans_id = dns_req->trans_id;
    getdns_callback_t cb = dns_req->user_callback;
    void* user_arg = dns_req->user_pointer;

    /* clean up the request */
    getdns_context_clear_outbound_request(dns_req);
    dns_req_free(dns_req);
    if (response) {
        cb(context,
           GETDNS_CALLBACK_COMPLETE,
           response,
           user_arg,
           trans_id);
    } else {
        cb(context,
           GETDNS_CALLBACK_ERROR,
           NULL,
           user_arg,
           trans_id);
    }

}

static int submit_network_request(getdns_network_req* netreq) {
    getdns_dns_req *dns_req = netreq->owner;
    int r = ub_resolve_event(dns_req->unbound,
                            dns_req->name,
                            netreq->request_type,
                            netreq->request_class,
                            netreq,
                            ub_resolve_callback,
                            &(netreq->unbound_id));
    netreq->state = NET_REQ_IN_FLIGHT;
    return r;
}



static void ub_resolve_callback(void* arg, int err, ldns_buffer* result, int sec, char* bogus) {
    getdns_network_req* netreq = (getdns_network_req*) arg;
    /* if netreq->state == NET_REQ_NOT_SENT here, that implies
     * that ub called us back immediately - probably from a local file.
     * This most likely means that getdns_general has not returned
     */
    if (netreq->state == NET_REQ_NOT_SENT) {
        /* just do a very short timer since this was called immediately.
         * we can make this less hacky, but it gets interesting when multiple 
         * netreqs need to be issued and some resolve immediately vs. not.
         */        
        struct timeval tv;
        getdns_dns_req* dnsreq = netreq->owner;
        netreq_cb_data* cb_data = (netreq_cb_data*) malloc(sizeof(netreq_cb_data));

        cb_data->netreq = netreq;
        cb_data->err = err;
        cb_data->sec = sec;
        cb_data->result = NULL;
        cb_data->bogus = NULL; /* unused but here in case we need it */
        if (result) {
            cb_data->result = ldns_buffer_new(ldns_buffer_limit(result));
            if (!cb_data->result) {
                cb_data->err = GETDNS_RETURN_GENERIC_ERROR;
            } else {
                /* copy */
                ldns_buffer_copy(cb_data->result, result);
            }
        }
        /* schedule the timeout */
        dnsreq->local_cb_timer = evtimer_new(dnsreq->ev_base, ub_local_resolve_timeout, cb_data);
        tv.tv_sec = 0;
        /* half ms */
        tv.tv_usec = 500;
        evtimer_add(dnsreq->local_cb_timer, &tv);
        return;
    }
    netreq->state = NET_REQ_FINISHED;
    if (err) {
        handle_network_request_error(netreq, err);
    } else {
        /* parse */
        ldns_status r = ldns_buffer2pkt_wire(&(netreq->result), result);
        if (r != LDNS_STATUS_OK) {
            handle_network_request_error(netreq, r);
        } else {
            /* is this the last request */
            if (!netreq->next) {
                /* finished */
                handle_dns_request_complete(netreq->owner);
            } else {
                /* not finished - update to next request and ship it */
                getdns_dns_req* dns_req = netreq->owner;
                dns_req->current_req = netreq->next;
                submit_network_request(netreq->next);
            }
        }
    }
}

getdns_return_t
getdns_general_ub(struct ub_ctx* unbound,
                  struct event_base* ev_base,
                  getdns_context_t context,
                  const char *name,
                  uint16_t request_type,
                  struct getdns_dict *extensions,
                  void *userarg,
                  getdns_transaction_t *transaction_id,
                  getdns_callback_t callbackfn) {
    /* timeout */
    struct timeval tv;
    getdns_return_t gr;
    int r;

    if (!name) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    gr = getdns_context_prepare_for_resolution(context);
    if (gr != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_BAD_CONTEXT;
    }

    /* request state */
    getdns_dns_req* req = dns_req_new(context,
                                      unbound,
                                      name,
                                      request_type,
                                      extensions);
    if (!req) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    req->user_pointer = userarg;
    req->user_callback = callbackfn;

    if (transaction_id) {
        *transaction_id = req->trans_id;
    }

    getdns_context_track_outbound_request(req);

    /* assign a timeout */
    req->ev_base = ev_base;
    req->timeout = evtimer_new(ev_base, ub_resolve_timeout, req);
    tv.tv_sec = context->timeout / 1000;
    tv.tv_usec = (context->timeout % 1000) * 1000;
    evtimer_add(req->timeout, &tv);

    /* issue the first network req */

    r = submit_network_request(req->first_req);

    if (r != 0) {
        /* clean up the request */
        getdns_context_clear_outbound_request(req);
        dns_req_free(req);
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    return GETDNS_RETURN_GOOD;
}

/*
 * getdns_general
 */
 getdns_return_t
 getdns_general(getdns_context_t context,
                const char *name,
                uint16_t request_type,
                struct getdns_dict *extensions,
                void *userarg,
                getdns_transaction_t *transaction_id,
                getdns_callback_t callback) {

    if (!context || !context->event_base_async ||
        callback == NULL) {
        /* Can't do async without an event loop
         * or callback
         */
        return GETDNS_RETURN_BAD_CONTEXT;
    }

    return getdns_general_ub(context->unbound_async,
                             context->event_base_async,
                             context,
                             name,
                             request_type,
                             extensions,
                             userarg,
                             transaction_id,
                             callback);

} /* getdns_general */


/*
 * getdns_address
 *
 */
 getdns_return_t
 getdns_address(getdns_context_t context,
                const char *name,
                struct getdns_dict *extensions,
                void *userarg,
                getdns_transaction_t *transaction_id,
                getdns_callback_t callback) {
    int cleanup_extensions = 0;
    if (!extensions) {
        extensions = getdns_dict_create();
        cleanup_extensions = 1;
    }
    getdns_dict_set_int(extensions,
                        GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6,
                        GETDNS_EXTENSION_TRUE);

    getdns_return_t result =
        getdns_general(context, name, GETDNS_RRTYPE_A,
                       extensions, userarg, transaction_id,
                       callback);
    if (cleanup_extensions) {
        getdns_dict_destroy(extensions);
    }
    return result;
}

/* getdns_general.c */
