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

#include "types-internal.h"
#include "util-internal.h"

/* useful macros */
#define gd_malloc(sz) context->memory_allocator(sz)
#define gd_free(ptr) context->memory_deallocator(ptr)

void network_req_free(getdns_network_req* net_req) {
    if (!net_req) {
        return;
    }
    getdns_context_t context = net_req->owner->context;
    if (net_req->result) {
        ldns_pkt_free(net_req->result);
    }
    gd_free(net_req);
}

getdns_network_req* network_req_new(getdns_dns_req* owner,
                                    uint16_t request_type,
                                    uint16_t request_class,
                                    struct getdns_dict* extensions) {

    getdns_context_t context = owner->context;
    getdns_network_req* net_req = gd_malloc(sizeof(getdns_network_req));
    if (!net_req) {
        return NULL;
    }
    net_req->result = NULL;
    net_req->next = NULL;

    net_req->request_type = request_type;
    net_req->request_class = request_class;
    net_req->unbound_id = -1;
    net_req->state = NET_REQ_NOT_SENT;
    net_req->owner = owner;

    /* TODO: records and other extensions */

    return net_req;
}

void dns_req_free(getdns_dns_req* req) {
    if (!req) {
        return;
    }
    getdns_network_req *net_req = NULL;
    getdns_context_t context = req->context;

    /* free network requests */
    net_req = req->first_req;
    while (net_req) {
        getdns_network_req *next = net_req->next;
        network_req_free(net_req);
        net_req = next;
    }

    /* free strduped name */
    free(req->name);

    gd_free(req);
}

/* create a new dns req to be submitted */
getdns_dns_req* dns_req_new(getdns_context_t context,
                            struct ub_ctx* unbound,
                            const char* name,
                            uint16_t request_type,
                            struct getdns_dict *extensions) {

    getdns_dns_req *result = NULL;
    getdns_network_req *req = NULL;
    getdns_return_t r;
    uint32_t both = GETDNS_EXTENSION_FALSE;

    result = gd_malloc(sizeof(getdns_dns_req));
    if (result == NULL) {
        return NULL;
    }

    result->name = strdup(name);
    result->context = context;
    result->unbound = unbound;
    result->current_req = NULL;
    result->first_req = NULL;
    result->trans_id = ldns_get_random();

    getdns_dict_copy(extensions, &result->extensions);

    /* will be set by caller */
    result->user_pointer = NULL;
    result->user_callback = NULL;

    /* create the requests */
    req = network_req_new(result,
                          request_type,
                          LDNS_RR_CLASS_IN,
                          extensions);
    if (!req) {
        dns_req_free(result);
        return NULL;
    }

    result->current_req = req;
    result->first_req = req;

    /* tack on A or AAAA if needed */
    r = getdns_dict_get_int(extensions,
                            GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6,
                            &both);
    if (r == GETDNS_RETURN_GOOD &&
        both == GETDNS_EXTENSION_TRUE &&
        (request_type == GETDNS_RRTYPE_A || request_type == GETDNS_RRTYPE_AAAA)) {

        uint16_t next_req_type = (request_type == GETDNS_RRTYPE_A) ? GETDNS_RRTYPE_AAAA : GETDNS_RRTYPE_A;
        getdns_network_req* next_req =
            network_req_new(result,
                            next_req_type,
                            LDNS_RR_CLASS_IN,
                            extensions);
        if (!next_req) {
            dns_req_free(result);
            return NULL;
        }
        req->next = next_req;
    }

    return result;
}
