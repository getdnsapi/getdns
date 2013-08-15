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
struct getdns_nameserver;
struct getdns_network_req;

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

/* network request - state for a single network request and referenced
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

/* utility methods */

/* network request utilities */
void network_req_free(getdns_network_req* net_req);

getdns_network_req* network_req_new(getdns_context_t context,
                                    const char* name,
                                    uint16_t request_type,
                                    struct getdns_dict* extensions,
                                    getdns_transaction_t *transaction_id);


/* dns request utils */
getdns_dns_req* dns_req_new(getdns_context_t context,
                            const char* name,
                            uint16_t request_type,
                            struct getdns_dict *extensions,
                            getdns_transaction_t *transaction_id);


void dns_req_free(getdns_dns_req* req);

/* nameserver utils */
getdns_nameserver* nameserver_new_from_ip_dict(getdns_dict* ip_dict);

void nameserver_free(getdns_nameserver* nameserver);


#endif
