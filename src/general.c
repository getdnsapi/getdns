/**
 *
 * \file general.c
 * @brief getdns_general and related support functions
 *
 * The getdns_general function is called by most of the other public entry
 * points to the library.  Private support functions are also included in this
 * file where they are directly logically related to the getdns_general implementation.
 */

/*
 * Copyright (c) 2013, NLnet Labs, Verisign, Inc.
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

#include <stdio.h>
#include <string.h>
#include <unbound.h>
#include <ldns/ldns.h>
#include "config.h"
#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"
#include "stub.h"
#include "gldns/str2wire.h"
#include "gldns/pkthdr.h"


/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/* declarations */
static void ub_resolve_callback(void* mydata, int err, struct ub_result* result);
static void ub_resolve_timeout(void *arg);

static void handle_network_request_error(getdns_network_req * netreq, int err);
static void handle_dns_request_complete(getdns_dns_req * dns_req);

/* cancel, cleanup and send timeout to callback */
static void
ub_resolve_timeout(void *arg)
{
	getdns_dns_req *dns_req = (getdns_dns_req *) arg;
	(void) getdns_context_request_timed_out(dns_req);
}

void priv_getdns_call_user_callback(getdns_dns_req *dns_req,
    struct getdns_dict *response)
{
	struct getdns_context *context = dns_req->context;
	getdns_transaction_t trans_id = dns_req->trans_id;
	getdns_callback_t cb = dns_req->user_callback;
	void *user_arg = dns_req->user_pointer;

	/* clean up */
	getdns_context_clear_outbound_request(dns_req);
	dns_req_free(dns_req);

	cb(context,
	    (response ? GETDNS_CALLBACK_COMPLETE : GETDNS_CALLBACK_ERROR),
	    response, user_arg, trans_id);
}

/* cleanup and send an error to the user callback */
static void
handle_network_request_error(getdns_network_req * netreq, int err)
{
	priv_getdns_call_user_callback(netreq->owner, NULL);
}

/* cleanup and send the response to the user callback */
static void
handle_dns_request_complete(getdns_dns_req * dns_req)
{
	if (is_extension_set(dns_req->extensions, "dnssec_return_validation_chain"))
		priv_getdns_get_validation_chain(dns_req);
	else
		priv_getdns_call_user_callback(
		    dns_req, create_getdns_response(dns_req));
}

static void
stub_resolve_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dns_req = netreq->owner;

	(void) getdns_context_request_timed_out(dns_req);
}

static void
stub_resolve_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dns_req = netreq->owner;

	static size_t pkt_buf_len = 4096;
	size_t        pkt_len = pkt_buf_len;
	uint8_t       pkt_buf[pkt_buf_len];
	uint8_t      *pkt = pkt_buf;

	size_t read;

	dns_req->loop->vmt->clear(dns_req->loop, &netreq->event);

	read = recvfrom(netreq->udp_fd, pkt, pkt_len, 0, NULL, NULL);
	if (read < GLDNS_HEADER_SIZE)
		return; /* Not DNS */
	
	if (GLDNS_ID_WIRE(pkt) != netreq->query_id)
		return; /* Cache poisoning attempt ;) */

	close(netreq->udp_fd);
	netreq->state = NET_REQ_FINISHED;
	ldns_wire2pkt(&(netreq->result), pkt, read);

	/* Do the dnssec here */
	netreq->secure = 0;
	netreq->bogus  = 0;

	netreq = dns_req->first_req;
	while (netreq) {
		if (netreq->state != NET_REQ_FINISHED &&
		    netreq->state != NET_REQ_CANCELED)
			return;
		netreq = netreq->next;
	}
	handle_dns_request_complete(dns_req);
}

static getdns_return_t
submit_stub_request(getdns_network_req *netreq)
{
	getdns_dns_req *dns_req = netreq->owner;
	static size_t pkt_buf_len = 4096;
	size_t        pkt_len = pkt_buf_len;
	uint8_t       pkt_buf[pkt_buf_len];
	uint8_t      *pkt = pkt_buf;
	int s;
	struct getdns_upstream *upstream;
	ssize_t sent;

	s = getdns_make_query_pkt_buf(dns_req->context, dns_req->name,
	    netreq->request_type, dns_req->extensions, pkt_buf, &pkt_len);
	if (s == GLDNS_WIREPARSE_ERR_BUFFER_TOO_SMALL) {
		/* TODO: Allocate 64K and retry */
		return GETDNS_RETURN_GENERIC_ERROR;
	} else if (s)
		return GETDNS_RETURN_GENERIC_ERROR;
	
	netreq->query_id = ldns_get_random();
	GLDNS_ID_SET(pkt, netreq->query_id);

	upstream = &dns_req->upstreams->upstreams[dns_req->ns_index];

	/* TODO: TCP */
	if (dns_req->context->dns_transport != GETDNS_TRANSPORT_UDP_ONLY &&
	    dns_req->context->dns_transport !=
	    GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP)
		return GETDNS_RETURN_GENERIC_ERROR;

	if ((netreq->udp_fd = socket(
	    upstream->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return GETDNS_RETURN_GENERIC_ERROR;

	sent = sendto(netreq->udp_fd, pkt, pkt_len, 0,
	    (struct sockaddr *)&upstream->addr, upstream->addr_len);
	if (sent != pkt_len) {
		close(netreq->udp_fd);
		return GETDNS_RETURN_GENERIC_ERROR;
	}

	netreq->event.userarg    = netreq;
	netreq->event.read_cb    = stub_resolve_read_cb;
	netreq->event.write_cb   = NULL;
	netreq->event.timeout_cb = stub_resolve_timeout_cb;
	netreq->event.ev         = NULL;
	dns_req->loop->vmt->schedule(dns_req->loop,
	    netreq->udp_fd, dns_req->context->timeout, &netreq->event);

	if (s == GLDNS_WIREPARSE_ERR_BUFFER_TOO_SMALL) {
		/* TODO: Free the 64K allocated buffer */
	}
	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
submit_network_request(getdns_network_req *netreq)
{
	getdns_return_t r;
	getdns_dns_req *dns_req = netreq->owner;

	if (dns_req->context->resolution_type == GETDNS_RESOLUTION_RECURSING ||
	    dns_req->context->dns_transport == GETDNS_TRANSPORT_TCP_ONLY ||
	    dns_req->context->dns_transport == GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN) {

		/* schedule the timeout */
		if (! dns_req->timeout.timeout_cb) {
			dns_req->timeout.userarg    = dns_req;
			dns_req->timeout.read_cb    = NULL;
			dns_req->timeout.write_cb   = NULL;
			dns_req->timeout.timeout_cb = ub_resolve_timeout;
			dns_req->timeout.ev         = NULL;
			if ((r = dns_req->loop->vmt->schedule(dns_req->loop, -1,
			    dns_req->context->timeout, &dns_req->timeout)))
				return r;
		}

		return ub_resolve_async(dns_req->context->unbound_ctx,
		    dns_req->name, netreq->request_type, netreq->request_class,
		    netreq, ub_resolve_callback, &(netreq->unbound_id)) ?
		    GETDNS_RETURN_GENERIC_ERROR : GETDNS_RETURN_GOOD;
	}
	/* Submit with stub resolver */
	return submit_stub_request(netreq);
}

static void
ub_resolve_callback(void* arg, int err, struct ub_result* ub_res)
// ub_resolve_callback(void *arg, int err, ldns_buffer * result, int sec,
//    char *bogus)
{
	getdns_network_req *netreq = (getdns_network_req *) arg;
	getdns_dns_req *dns_req = netreq->owner;

	netreq->state = NET_REQ_FINISHED;
	if (err != 0) {
		handle_network_request_error(netreq, err);
		return;
	}
	/* parse */
	if (getdns_apply_network_result(netreq, ub_res)) {
		ub_resolve_free(ub_res);
		handle_network_request_error(netreq, err);
		return;
	}
	ub_resolve_free(ub_res);

	netreq = dns_req->first_req;
	while (netreq) {
		if (netreq->state != NET_REQ_FINISHED &&
		    netreq->state != NET_REQ_CANCELED)
			return;
		netreq = netreq->next;
	}
	handle_dns_request_complete(dns_req);
} /* ub_resolve_callback */

getdns_return_t
getdns_general_ns(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_transaction_t *transaction_id,
    getdns_callback_t callbackfn, int usenamespaces)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_network_req *netreq;
	getdns_dns_req *req;
	getdns_dict *localnames_response;
	size_t i;

	if (!context || !name || !callbackfn)
		return GETDNS_RETURN_INVALID_PARAMETER;
	
	if ((r = validate_dname(name)))
		return r;

	if (extensions && (r = validate_extensions(extensions)))
		return r;

	/* Set up the context assuming we won't use the specified namespaces.
	   This is (currently) identical to setting up a pure DNS namespace */
	if ((r = getdns_context_prepare_for_resolution(context, 0)))
		return r;

	/* create the request */
	if (!(req = dns_req_new(context, loop, name, request_type, extensions)))
		return GETDNS_RETURN_MEMORY_ERROR;

	req->user_pointer = userarg;
	req->user_callback = callbackfn;

	if (transaction_id)
		*transaction_id = req->trans_id;

	getdns_context_track_outbound_request(req);

	if (!usenamespaces)
		/* issue all network requests */
		for (netreq = req->first_req; !r && netreq; netreq = netreq->next)
			r = submit_network_request(netreq);

	else for (i = 0; i < context->namespace_count; i++) {
		if (context->namespaces[i] == GETDNS_NAMESPACE_LOCALNAMES) {

			if (!(r = getdns_context_local_namespace_resolve(
			    req, &localnames_response, context))) {

				priv_getdns_call_user_callback
				    ( req, localnames_response);
				break;
			}
		} else if (context->namespaces[i] == GETDNS_NAMESPACE_DNS) {

			/* TODO: We will get a good return code here even if
			   the name is not found (NXDOMAIN). We should consider
			   if this means we go onto the next namespace instead
			   of returning */
			r = GETDNS_RETURN_GOOD;
			netreq = req->first_req;
			while (!r && netreq) {
				r = submit_network_request(netreq);
				netreq = netreq->next;
			}
			break;
		} else
			r = GETDNS_RETURN_BAD_CONTEXT;
	}

	if (r != 0) {
		/* clean up the request */
		getdns_context_clear_outbound_request(req);
		dns_req_free(req);
		return r;
	}
	return GETDNS_RETURN_GOOD;
}				/* getdns_general_ns */

getdns_return_t
getdns_general_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_transaction_t *transaction_id,
    getdns_callback_t callback)
{
	return getdns_general_ns(context, loop,
	    name, request_type, extensions,
	    userarg, transaction_id, callback, 0);

}				/* getdns_general_loop */

getdns_return_t
getdns_address_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	int cleanup_extensions = 0;
	getdns_return_t r;

	if (!extensions) {
		if (!(extensions = getdns_dict_create_with_context(context)))
			return GETDNS_RETURN_MEMORY_ERROR;
		cleanup_extensions = 1;
	}
	if ((r = getdns_dict_set_int(extensions, "return_both_v4_and_v6",
	    GETDNS_EXTENSION_TRUE)))
		return r;
	
	r = getdns_general_ns(context, loop,
	    name, GETDNS_RRTYPE_A, extensions,
	    userarg, transaction_id, callback, 1);

	if (cleanup_extensions)
		getdns_dict_destroy(extensions);

	return r;
} /* getdns_address_loop */

/**
 * getdns_general
 */
getdns_return_t
getdns_general(getdns_context *context,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_transaction_t * transaction_id,
    getdns_callback_t callback)
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	return getdns_general_loop(context, context->extension,
	    name, request_type, extensions,
	    userarg, transaction_id, callback);

}				/* getdns_general */

/*
 * getdns_address
 *
 */
getdns_return_t
getdns_address(getdns_context *context,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	return getdns_address_loop(context, context->extension,
	    name, extensions, userarg,
	    transaction_id, callback);
} /* getdns_address */


/* getdns_general.c */
