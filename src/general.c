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
 * Copyright (c) 2013, NLNet Labs, Versign, Inc.
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

#include "config.h"
#include <string.h>
#include <unbound.h>
#include <ldns/ldns.h>
#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"
#include <stdio.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/* declarations */
static void ub_resolve_callback(void* mydata, int err, struct ub_result* result);
static void ub_resolve_timeout(void *arg);
static void ub_local_resolve_timeout(void *arg);

static void handle_network_request_error(getdns_network_req * netreq, int err);
static void handle_dns_request_complete(getdns_dns_req * dns_req);
static int submit_network_request(getdns_network_req * netreq);

typedef struct netreq_cb_data
{
	getdns_network_req *netreq;
	int err;
	struct ub_result* ub_res;
} netreq_cb_data;

/* cancel, cleanup and send timeout to callback */
static void
ub_resolve_timeout(void *arg)
{
	getdns_dns_req *dns_req = (getdns_dns_req *) arg;
	struct getdns_context *context = dns_req->context;
	getdns_transaction_t trans_id = dns_req->trans_id;
	getdns_callback_t cb = dns_req->user_callback;
	void *user_arg = dns_req->user_pointer;

	/* cancel the req - also clears it from outbound and cleans up*/
	getdns_context_cancel_request(context, trans_id, 0);

	cb(context, GETDNS_CALLBACK_TIMEOUT, NULL, user_arg, trans_id);
}

static void
ub_local_resolve_timeout(void *arg)
{
	netreq_cb_data *cb_data = (netreq_cb_data *) arg;

	/* cleanup the local timer here since the memory may be
	 * invalid after calling ub_resolve_callback
	 */
	getdns_dns_req *dnsreq = cb_data->netreq->owner;
    /* clear the timeout */

	getdns_context_clear_timeout(dnsreq->context, dnsreq->local_timeout_id);
	dnsreq->local_timeout_id = 0;

	/* just call ub_resolve_callback */
	ub_resolve_callback(cb_data->netreq, cb_data->err, cb_data->ub_res);

	/* cleanup the state */
	GETDNS_FREE(dnsreq->my_mf, cb_data);
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

static int
submit_network_request(getdns_network_req * netreq)
{
	getdns_dns_req *dns_req = netreq->owner;
	int r = ub_resolve_async(dns_req->context->unbound_ctx,
	    dns_req->name,
	    netreq->request_type,
	    netreq->request_class,
	    netreq,
	    ub_resolve_callback,
	    &(netreq->unbound_id));
	netreq->state = NET_REQ_IN_FLIGHT;
	return r;
}

static void
ub_resolve_callback(void* arg, int err, struct ub_result* ub_res)
// ub_resolve_callback(void *arg, int err, ldns_buffer * result, int sec,
//    char *bogus)
{
    getdns_network_req *netreq = (getdns_network_req *) arg;
    if (err != 0) {
        handle_network_request_error(netreq, err);
        return;
    }
	/* if netreq->state == NET_REQ_NOT_SENT here, that implies
	 * that ub called us back immediately - probably from a local file.
	 * This most likely means that getdns_general has not returned
	 */
	if (netreq->state == NET_REQ_NOT_SENT) {
		/* just do a very short timer since this was called immediately.
		 * we can make this less hacky, but it gets interesting when multiple
		 * netreqs need to be issued and some resolve immediately vs. not.
		 */
        getdns_dns_req *dnsreq = netreq->owner;
        netreq_cb_data *cb_data = GETDNS_MALLOC(dnsreq->my_mf, netreq_cb_data);
        cb_data->netreq = netreq;
        cb_data->err = err;
        cb_data->ub_res = ub_res;

        dnsreq->local_timeout_id = ldns_get_random();

        getdns_context_schedule_timeout(dnsreq->context,
            dnsreq->local_timeout_id, 1, ub_local_resolve_timeout, cb_data);
		return;
	}
	netreq->state = NET_REQ_FINISHED;
	/* parse */
    /* TODO: optimize */
    getdns_return_t r = getdns_apply_network_result(netreq, ub_res);
    ub_resolve_free(ub_res);
    if (r != GETDNS_RETURN_GOOD) {
        handle_network_request_error(netreq, err);
    } else {
		/* is this the last request */
		if (!netreq->next) {
			/* finished */
			handle_dns_request_complete(netreq->owner);
		} else {
			/* not finished - update to next request and ship it */
			getdns_dns_req *dns_req = netreq->owner;
			dns_req->current_req = netreq->next;
			submit_network_request(netreq->next);
		}
	}
} /* ub_resolve_callback */

getdns_return_t
getdns_general_ub(struct getdns_context *context,
    const char *name,
    uint16_t request_type,
    struct getdns_dict *extensions,
    void *userarg,
    getdns_transaction_t * transaction_id,
    getdns_callback_t callbackfn,
	int usenamespaces)
{
	getdns_return_t gr;
	int r;

	if (!name) {
		return GETDNS_RETURN_INVALID_PARAMETER;
	}

	gr = getdns_context_prepare_for_resolution(context, usenamespaces);
	if (gr != GETDNS_RETURN_GOOD) {
		return gr;
	}

	/* request state */
	getdns_dns_req *req = dns_req_new(context,
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
	// req->ev_base = ev_base;
	// req->timeout = evtimer_new(ev_base, ub_resolve_timeout, req);
    /* schedule the timeout */
    getdns_context_schedule_timeout(context, req->trans_id,
        context->timeout, ub_resolve_timeout, req);

	/* issue the first network req */

	r = submit_network_request(req->first_req);

	if (r != 0) {
		/* clean up the request */
		getdns_context_clear_outbound_request(req);
		dns_req_free(req);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	return GETDNS_RETURN_GOOD;
}				/* getdns_general_ub */

/**
 * getdns_general
 */
getdns_return_t
getdns_general(struct getdns_context *context,
    const char *name,
    uint16_t request_type,
    struct getdns_dict * extensions,
    void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callback)
{
	int extcheck = GETDNS_RETURN_GOOD;

	if (!context) {
		/* Can't do async without an event loop
		 * or callback
		 */
		return GETDNS_RETURN_INVALID_PARAMETER;
	}

    /* ensure callback is not NULL */
    if (!callback || !name) {
         return GETDNS_RETURN_INVALID_PARAMETER;
    }

    extcheck = validate_dname(name);
    if (extcheck != GETDNS_RETURN_GOOD) {
        return extcheck;
    }

	extcheck = validate_extensions(extensions);
	if (extcheck != GETDNS_RETURN_GOOD)
		return extcheck;

	return getdns_general_ub(context,
	    name, request_type, extensions, userarg, transaction_id, callback, 0);

}				/* getdns_general */

/*
 * getdns_address
 *
 */
getdns_return_t
getdns_address(struct getdns_context *context,
    const char *name,
    struct getdns_dict * extensions,
    void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callback)
{
	int cleanup_extensions = 0;
	int extcheck;
	getdns_return_t result;

	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;
    if (!callback || !name)
         return GETDNS_RETURN_INVALID_PARAMETER;

    extcheck = validate_dname(name);
    if (extcheck != GETDNS_RETURN_GOOD)
        return extcheck;

	/* we set the extensions that make general behave like getdns_address */
	if (!extensions)
	{
		extensions = getdns_dict_create_with_context(context);
		cleanup_extensions = 1;
	}
	getdns_dict_set_int(extensions,
	    GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6, GETDNS_EXTENSION_TRUE);
	extcheck = validate_extensions(extensions);
	if (extcheck != GETDNS_RETURN_GOOD)
		return extcheck;

	result = getdns_general_ub(context,
	    name, GETDNS_RRTYPE_A, extensions, userarg, transaction_id, callback, 1);

	if (cleanup_extensions)
		getdns_dict_destroy(extensions);

	return result;
} /* getdns_address */

/* getdns_general.c */
