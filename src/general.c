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

#include "getdns_context.h"
#include <ldns/ldns.h>

/* useful macros */
#define gd_malloc(sz) context->memory_allocator(sz)
#define gd_free(ptr) context->memory_deallocator(ptr)

struct getdns_dns_req;

typedef struct getdns_nameserver {
	evutil_socket_t socket;	 /* a connected UDP socket */
	struct sockaddr_storage address;
	ev_socklen_t addrlen;

	int failed_times;  /* number of times which we have given this server a chance */
	int timedout;  /* number of times in a row a request has timed out */
	struct event event;

	struct event timeout_event;  /* used to keep the timeout for */
    /* when we next probe this server. */
    /* Valid if state == 0 */
	/* Outstanding probe request for this nameserver, if any */
	struct getdns_dns_req *probe_request;
	char state;  /* zero if we think that this server is down */
	char choked;  /* true if we have an EAGAIN from this server's socket */
	char write_waiting;  /* true if we are waiting for EV_WRITE events */
	
    /* getdns context */
    getdns_context_t context;
    
	/* Number of currently inflight requests: used
	 * to track when we should add/del the event. */
	int requests_inflight;
} getdns_nameserver;

/* network request - state for a network request and referenced
 * by the the outbound_req
 */
typedef struct getdns_network_req {
	ldns_pkt *pkt;  /* the dns packet data */
	uint16_t request_type; /* query type */

	int reissue_count;
	int tx_count;  /* the number of times that this packet has been sent */
	
    /* not owned */
    struct nameserver *ns;	/* the server which we last sent it (unused) */
    getdns_dict *upstream_server;
    
	struct event timeout_event;
    
	getdns_transaction_t trans_id;  /* the transaction id */
	
	unsigned transmit_me :1;  /* needs to be transmitted */
    
	getdns_context_t context;
    
	struct getdns_dns_req *owner;

} getdns_network_req;

/* outbound request - manages recursion and stub reqs */
typedef struct getdns_dns_req {
    
	struct getdns_network_req *current_req;
    getdns_context_t context;
    
    uint16_t resolver_type;
    
    /* callback data */
    getdns_callback_t user_callback;
    void *user_pointer;
	
    
	int pending_cb; /* Waiting for its callback to be invoked; not
                     * owned by event base any more. */
    
	/* search not supported.. yet */

} getdns_dns_req;

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/* TODO: flags */
static ldns_pkt *create_new_pkt(getdns_context_t context,
                                const char* name,
                                uint16_t request_type,
                                struct getdns_dict* extensions) {
    ldns_pkt *pkt = NULL;
    ldns_rr_type type = (ldns_rr_type) request_type;
    ldns_pkt_query_new_frm_str(&pkt, name,
                                type,
                                LDNS_RR_CLASS_IN, 0);
    if (pkt) {
        /* id */
        ldns_pkt_set_id(pkt, ldns_get_random());
    }
    return pkt;
}

static void network_req_free(getdns_context_t context,
                             getdns_network_req* net_req) {
    if (!net_req) {
        return;
    }
    if (net_req->pkt) {
        ldns_pkt_free(net_req->pkt);
    }
    gd_free(net_req);
}

static getdns_network_req* network_req_new(getdns_context_t context,
                                           const char* name,
                                           uint16_t request_type,
                                           struct getdns_dict* extensions,
                                           getdns_transaction_t *transaction_id) {
    getdns_network_req *net_req = NULL;
    ldns_pkt *pkt = NULL;
    net_req = gd_malloc(sizeof(getdns_network_req));
    if (!net_req) {
        return NULL;
    }
    net_req->ns = NULL;
    net_req->pkt = NULL;
    net_req->context = context;
    net_req->request_type = request_type;
    
    /* create ldns packet */
    pkt = create_new_pkt(context, name, request_type, extensions);
    if (!pkt) {
        /* free up the req */
        network_req_free(context, net_req);
        return NULL;
    }
    net_req->pkt = pkt;
    net_req->trans_id = ldns_pkt_id(pkt);
    if (transaction_id) {
        *transaction_id = net_req->trans_id;
    }
    
    return net_req;
}

static void dns_req_free(getdns_context_t context,
                         getdns_dns_req* req) {
    if (!req) {
        return;
    }
    network_req_free(context, req->current_req);
    gd_free(req);
}

/* create a new dns req to be submitted */
static getdns_dns_req* dns_req_new(getdns_context_t context,
                                   const char* name,
                                   uint16_t request_type,
                                   struct getdns_dict *extensions,
                                   getdns_transaction_t *transaction_id) {
    getdns_dns_req *result = NULL;
    getdns_network_req *net_req = NULL;
    result = gd_malloc(sizeof(getdns_dns_req));
    if (result == NULL) {
        return NULL;
    }
    result->context = context;
    result->current_req = NULL;
    result->pending_cb = 0;
    result->resolver_type = context->resolution_type;
    
    /* create the initial network request */
    net_req = network_req_new(context, name, request_type,
                              extensions, transaction_id);
    if (!net_req) {
        dns_req_free(context, result);
        result = NULL;
    }
    
    result->current_req = net_req;
    net_req->owner = result;
    
    return result;
}

static getdns_return_t dict_to_sockaddr(getdns_dict* ns, struct sockaddr_storage* output) {
    struct getdns_bindata *address_type = NULL;
    struct getdns_bindata *address_data = NULL;
    uint16_t port = htons(53);
    memset(output, 0, sizeof(struct sockaddr_storage));
    output->ss_family = AF_UNSPEC;
    
    getdns_dict_get_bindata(ns, GETDNS_STR_ADDRESS_TYPE, &address_type);
    getdns_dict_get_bindata(ns, GETDNS_STR_ADDRESS_DATA, &address_data);
    if (!address_type || !address_data) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    if (strcmp((char*) address_type->data, GETDNS_STR_IPV4)) {
        /* data is an in_addr_t */
        struct sockaddr_in* addr = (struct sockaddr_in*) output;
        addr->sin_family = AF_INET;
        addr->sin_port = port;
        memcpy(&(addr->sin_addr), address_data->data, address_data->size);
    } else {
        /* data is a v6 addr in host order */
        struct sockaddr_in6* addr = (struct sockaddr_in6*) output;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = port;
        memcpy(&(addr->sin6_addr), address_data->data, address_data->size);
    }
    return GETDNS_RETURN_GOOD;
}

/* submit a new request to the event loop */
static getdns_return_t submit_new_dns_req(getdns_dns_req *request) {
    getdns_dict *nameserver = NULL;
    getdns_context_t context = request->context;
    struct sockaddr_storage sockdata;
    
    /* get first upstream server */
    getdns_list_get_dict(context->upstream_list, 0, &nameserver);
    if (!nameserver) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    
    /* setup socket */
    if (dict_to_sockaddr(nameserver, &sockdata) != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    evutil_socket_t sock = socket(sockdata.ss_family, SOCK_DGRAM, 0);
    evutil_make_socket_closeonexec(sock);
    evutil_make_socket_nonblocking(sock);
    
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

    UNUSED_PARAM(userarg);
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
