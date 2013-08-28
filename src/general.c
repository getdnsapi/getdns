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

/**
 * Much of this is based on / duplicated code from libevent evdns.  Credits to
 * Nick Mathewson and Niels Provos
 *
 * https://github.com/libevent/libevent/
 *
 * libevent dns is based on software by Adam Langly. Adam's original message:
 *
 * Async DNS Library
 * Adam Langley <agl@imperialviolet.org>
 * http://www.imperialviolet.org/eventdns.html
 * Public Domain code
 *
 * This software is Public Domain. To view a copy of the public domain dedication,
 * visit http://creativecommons.org/licenses/publicdomain/ or send a letter to
 * Creative Commons, 559 Nathan Abbott Way, Stanford, California 94305, USA.
 *
 * I ask and expect, but do not require, that all derivative works contain an
 * attribution similar to:
 *	Parts developed by Adam Langley <agl@imperialviolet.org>
 *
 * You may wish to replace the word "Parts" with something else depending on
 * the amount of original code.
 *
 * (Derivative works does not include programs which link against, run or include
 * the source verbatim in their source distributions)
 *
 * Version: 0.1b
 */

#include "types-internal.h"
#include "util-internal.h"

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/* libevent callback for a network request */
static void dns_req_callback(int fd, short events, void *arg) {
    getdns_dns_req *request = (getdns_dns_req*) arg;
    uint8_t data[1500];
    if (events & EV_READ) {
        while (1) {
            ssize_t r = recv(fd, data, sizeof(data), MSG_DONTWAIT);
            if (r < 0) {
                if (errno == EAGAIN) return;
                /* otherwise failed */
                request->user_callback(request->context,
                                       GETDNS_CALLBACK_ERROR,
                                       NULL, request->user_pointer,
                                       request->trans_id);
            }
            /* parse a packet */
            ldns_pkt* pkt = NULL;
            ldns_wire2pkt(&pkt, data, r);
            if (pkt == NULL) {
                /* otherwise failed */
                request->user_callback(request->context,
                                       GETDNS_CALLBACK_ERROR,
                                       NULL, request->user_pointer,
                                       request->trans_id);
            } else {
                /* success */
                getdns_dict* response = create_getdns_response(pkt);
                ldns_pkt_free(pkt);
                request->user_callback(request->context, GETDNS_CALLBACK_COMPLETE,
                                       response, request->user_pointer,
                                       request->trans_id);
            }
        }
    } else if (events & EV_TIMEOUT) {
        request->user_callback(request->context, GETDNS_CALLBACK_TIMEOUT,
                               NULL, request->user_pointer, request->trans_id);
    }
    /* clean up ns since right now it's 1:1 with the request */
    nameserver_free(request->current_req->ns);
    /* cleanup the request */
    dns_req_free(request);
}

/* submit a new request to the event loop */
static getdns_return_t submit_new_dns_req(getdns_dns_req *request) {
    getdns_dict *ip_dict = NULL;
    getdns_context_t context = request->context;
    uint8_t* data = NULL;
    size_t data_len = 0;
    struct timeval timeout = { 5, 0 };
    
    /* get first upstream server */
    getdns_list_get_dict(context->upstream_list, 0, &ip_dict);
    if (!ip_dict) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    
    /* get the nameserver */
    getdns_nameserver *ns = nameserver_new_from_ip_dict(context, ip_dict);
    if (!ns) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    
    request->current_req->ns = ns;

    /* schedule on the loop */
    ns->event = event_new(context->event_base, request->current_req->ns->socket,
                          EV_READ | EV_TIMEOUT,
                          dns_req_callback, request);
    
    event_add(ns->event, &timeout);
    
    /* send data */
    ldns_pkt *pkt = request->current_req->pkt;
    ldns_pkt2wire(&data, pkt, &data_len);
    send(ns->socket, data, data_len, MSG_DONTWAIT);
    free(data);
    
    return GETDNS_RETURN_GOOD;
}


/*
 * getdns_general
 */
getdns_return_t
getdns_general(
  getdns_context_t           context,
  const char                 *name,
  uint16_t                   request_type,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{
    /* Default to zero */
    if (transaction_id != NULL) {
        *transaction_id = 0;
    }
    if (!context || context->event_base == NULL ||
        callback == NULL ||
        context->resolution_type != GETDNS_CONTEXT_STUB) {
        /* Can't do async without an event loop
         * or callback
         *
         * Only supports stub right now.
         */
        return GETDNS_RETURN_BAD_CONTEXT;
    }
    

    /* create a req */
    getdns_dns_req *dns_req = dns_req_new(context, name, request_type,
                                          extensions, transaction_id);
    if (dns_req == NULL) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    
    dns_req->user_callback = callback;
    dns_req->user_pointer = userarg;
    
    /* submit it */
    submit_new_dns_req(dns_req);

    return GETDNS_RETURN_GOOD;
} /* getdns_general */


/*
 * getdns_address
 *
 */
getdns_return_t
getdns_address(
  getdns_context_t           context,
  const char                 *name,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{
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
