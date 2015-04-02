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

void
priv_getdns_check_dns_req_complete(getdns_dns_req *dns_req)
{
	getdns_network_req **netreq_p, *netreq;
	int results_found = 0;
	
	for (netreq_p = dns_req->netreqs; (netreq = *netreq_p); netreq_p++)
		if (netreq->state != NET_REQ_FINISHED &&
		    netreq->state != NET_REQ_CANCELED)
			return;
		else if (netreq->response_len > 0)
			results_found = 1;

	if (dns_req->internal_cb)
		dns_req->internal_cb(dns_req);
	else if (! results_found)
		priv_getdns_call_user_callback(dns_req, NULL);
	else if (dns_req->dnssec_return_validation_chain
#ifdef STUB_NATIVE_DNSSEC
	    || (dns_req->context->resolution_type == GETDNS_RESOLUTION_STUB
	        && (dns_req->dnssec_return_status ||
	            dns_req->dnssec_return_only_secure))
#endif
	    )
		priv_getdns_get_validation_chain(dns_req);
	else
		priv_getdns_call_user_callback(
		    dns_req, create_getdns_response(dns_req));
}

static void
ub_resolve_callback(void* arg, int err, struct ub_result* ub_res)
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

	priv_getdns_check_dns_req_complete(dns_req);

} /* ub_resolve_callback */


static getdns_return_t
submit_network_request(getdns_network_req *netreq)
{
	getdns_return_t r;
	getdns_dns_req *dns_req = netreq->owner;

	if (dns_req->context->resolution_type == GETDNS_RESOLUTION_RECURSING
	    /* TODO: Until DNSSEC with the new async stub resolver is finished,
	     *       use unbound when we need DNSSEC.
	     */
#ifndef STUB_NATIVE_DNSSEC
	    || dns_req->dnssec_return_status
	    || dns_req->dnssec_return_only_secure
	    || dns_req->dnssec_return_validation_chain
#endif
	    ) {

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
	return priv_getdns_submit_stub_request(netreq);
}

static getdns_return_t
getdns_general_ns(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_transaction_t *transaction_id,
    getdns_callback_t callbackfn, internal_cb_t internal_cb, int usenamespaces)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_network_req *netreq, **netreq_p;
	getdns_dns_req *req;
	getdns_dict *localnames_response;
	size_t i;

	if (!context || !name || (!callbackfn && !internal_cb))
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
	req->internal_cb = internal_cb;

	if (transaction_id)
		*transaction_id = req->trans_id;

	getdns_context_track_outbound_request(req);

	if (!usenamespaces)
		/* issue all network requests */
		for ( netreq_p = req->netreqs
		    ; !r && (netreq = *netreq_p)
		    ; netreq_p++)
			r = submit_network_request(netreq);

	else for (i = 0; i < context->namespace_count; i++) {
		if (context->namespaces[i] == GETDNS_NAMESPACE_LOCALNAMES) {

			if (!(r = getdns_context_local_namespace_resolve(
			    req, &localnames_response))) {

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
			for ( netreq_p = req->netreqs
			    ; !r && (netreq = *netreq_p)
			    ; netreq_p++)
				r = submit_network_request(netreq);
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
priv_getdns_general_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_transaction_t *transaction_id,
    getdns_callback_t callback, internal_cb_t internal_cb)
{
	return getdns_general_ns(context, loop,
	    name, request_type, extensions,
	    userarg, transaction_id, callback, internal_cb, 0);

}				/* getdns_general_loop */

getdns_return_t
priv_getdns_address_loop(getdns_context *context, getdns_eventloop *loop,
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
	    name, GETDNS_RRTYPE_AAAA, extensions,
	    userarg, transaction_id, callback, NULL, 1);

	if (cleanup_extensions)
		getdns_dict_destroy(extensions);

	return r;
} /* getdns_address_loop */

getdns_return_t
priv_getdns_hostname_loop(getdns_context *context, getdns_eventloop *loop,
    getdns_dict *address, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	struct getdns_bindata *address_data;
	struct getdns_bindata *address_type;
	uint16_t req_type;
	char name[1024];
	getdns_return_t retval;

	if ((retval =
		getdns_dict_get_bindata(address, "address_data",
		    &address_data)) != GETDNS_RETURN_GOOD)
		return retval;
	if ((retval =
		getdns_dict_get_bindata(address, "address_type",
		    &address_type)) != GETDNS_RETURN_GOOD)
		return retval;
	if ((strncmp(GETDNS_STR_IPV4, (char *) address_type->data,
		    ( strlen(GETDNS_STR_IPV4) < address_type->size
		    ? strlen(GETDNS_STR_IPV4) : address_type->size )) == 0
	        && address_data->size == 4)
	    || (strncmp(GETDNS_STR_IPV6, (char *) address_type->data,
		    ( strlen(GETDNS_STR_IPV6) < address_type->size
		    ? strlen(GETDNS_STR_IPV6) : address_type->size )) == 0
		&& address_data->size == 16))
		req_type = GETDNS_RRTYPE_PTR;
	else
		return GETDNS_RETURN_INVALID_PARAMETER;

	switch (address_data->size) {
	case 4:
		(void)snprintf(name, sizeof(name),
		    "%hhu.%hhu.%hhu.%hhu.in-addr.arpa.",
		    ((uint8_t *)address_data->data)[3],
		    ((uint8_t *)address_data->data)[2],
		    ((uint8_t *)address_data->data)[1],
		    ((uint8_t *)address_data->data)[0]);
		break;
	case 16:
		(void)snprintf(name, sizeof(name),
		    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx."
		    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx."
		    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx."
		    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.ip6.arpa.",
		    ((uint8_t *)address_data->data)[15] & 0x0F,
		    ((uint8_t *)address_data->data)[15] >> 4,
		    ((uint8_t *)address_data->data)[14] & 0x0F,
		    ((uint8_t *)address_data->data)[14] >> 4,
		    ((uint8_t *)address_data->data)[13] & 0x0F,
		    ((uint8_t *)address_data->data)[13] >> 4,
		    ((uint8_t *)address_data->data)[12] & 0x0F,
		    ((uint8_t *)address_data->data)[12] >> 4,
		    ((uint8_t *)address_data->data)[11] & 0x0F,
		    ((uint8_t *)address_data->data)[11] >> 4,
		    ((uint8_t *)address_data->data)[10] & 0x0F,
		    ((uint8_t *)address_data->data)[10] >> 4,
		    ((uint8_t *)address_data->data)[9] & 0x0F,
		    ((uint8_t *)address_data->data)[9] >> 4,
		    ((uint8_t *)address_data->data)[8] & 0x0F,
		    ((uint8_t *)address_data->data)[8] >> 4,
		    ((uint8_t *)address_data->data)[7] & 0x0F,
		    ((uint8_t *)address_data->data)[7] >> 4,
		    ((uint8_t *)address_data->data)[6] & 0x0F,
		    ((uint8_t *)address_data->data)[6] >> 4,
		    ((uint8_t *)address_data->data)[5] & 0x0F,
		    ((uint8_t *)address_data->data)[5] >> 4,
		    ((uint8_t *)address_data->data)[4] & 0x0F,
		    ((uint8_t *)address_data->data)[4] >> 4,
		    ((uint8_t *)address_data->data)[3] & 0x0F,
		    ((uint8_t *)address_data->data)[3] >> 4,
		    ((uint8_t *)address_data->data)[2] & 0x0F,
		    ((uint8_t *)address_data->data)[2] >> 4,
		    ((uint8_t *)address_data->data)[1] & 0x0F,
		    ((uint8_t *)address_data->data)[1] >> 4,
		    ((uint8_t *)address_data->data)[0] & 0x0F,
		    ((uint8_t *)address_data->data)[0] >> 4);
		break;
	default:
		return GETDNS_RETURN_INVALID_PARAMETER;
	}
	retval = priv_getdns_general_loop(context, loop, name, req_type,
	    extensions, userarg, transaction_id, callback, NULL);
	return retval;
}				/* getdns_hostname_loop */

getdns_return_t
priv_getdns_service_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callback)
{
	return getdns_general_ns(context, loop, name, GETDNS_RRTYPE_SRV,
	    extensions, userarg, transaction_id, callback, NULL, 1);
}				/* getdns_service_loop */

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
	return priv_getdns_general_loop(context, context->extension,
	    name, request_type, extensions,
	    userarg, transaction_id, callback, NULL);

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
	return priv_getdns_address_loop(context, context->extension,
	    name, extensions, userarg,
	    transaction_id, callback);
} /* getdns_address */

/*
 * getdns_hostname
 *
 */
getdns_return_t
getdns_hostname(getdns_context *context,
    getdns_dict *address, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	return priv_getdns_hostname_loop(context, context->extension,
	    address, extensions, userarg, transaction_id, callback);
}				/* getdns_hostname */

/*
 * getdns_service
 *
 */
getdns_return_t
getdns_service(getdns_context *context,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	return priv_getdns_service_loop(context, context->extension,
	    name, extensions, userarg, transaction_id, callback);
}				/* getdns_service */

/* getdns_general.c */
