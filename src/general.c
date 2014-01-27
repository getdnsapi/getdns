/**
 *
 * /brief getdns_general and related support functions
 *
 * The getdns_general function is called by most of the other public entry
 * points to the library.  Private support functions are also included in this
 * file where they are directly logically related to the getdns_general implementation.
 */

/*
 * Copyright (c) 2013, Versign, Inc.
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
#ifdef HAVE_EVENT2_EVENT_H
#  include <event2/event.h>
#else
#  include <event.h>
#  define evutil_socket_t int
#  define event_free free
#  define evtimer_new(b, cb, arg) event_new((b), -1, 0, (cb), (arg))
#endif
#include <string.h>
#include <unbound.h>
#include <unbound-event.h>
#include <ldns/ldns.h>
#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include <stdio.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/* declarations */
static void ub_resolve_callback(void *arg, int err, ldns_buffer * result,
    int sec, char *bogus);
static void ub_resolve_timeout(evutil_socket_t fd, short what, void *arg);
static void ub_local_resolve_timeout(evutil_socket_t fd, short what,
    void *arg);

static void handle_network_request_error(getdns_network_req * netreq, int err);
static void handle_dns_request_complete(getdns_dns_req * dns_req);
static int submit_network_request(getdns_network_req * netreq);

typedef struct netreq_cb_data
{
	getdns_network_req *netreq;
	int err;
	ldns_buffer *result;
	int sec;
	char *bogus;
} netreq_cb_data;

#ifndef HAVE_EVENT2_EVENT_H
static struct event *
event_new(struct event_base *b, evutil_socket_t fd, short ev, void* cb, void *arg)
{
	struct event* e = (struct event*)calloc(1, sizeof(struct event));
	if(!e) return NULL;
	event_set(e, fd, ev, cb, arg);
	event_base_set(b, e);
	return e;
}
#endif /* no event2 */

/* cancel, cleanup and send timeout to callback */
static void
ub_resolve_timeout(evutil_socket_t fd, short what, void *arg)
{
	getdns_dns_req *dns_req = (getdns_dns_req *) arg;
	struct getdns_context *context = dns_req->context;
	getdns_transaction_t trans_id = dns_req->trans_id;
	getdns_callback_t cb = dns_req->user_callback;
	void *user_arg = dns_req->user_pointer;

	/* cancel the req - also clears it from outbound */
	getdns_context_cancel_request(context, trans_id, 0);

	/* cleanup */
	dns_req_free(dns_req);

	cb(context, GETDNS_CALLBACK_TIMEOUT, NULL, user_arg, trans_id);
}

static void
ub_local_resolve_timeout(evutil_socket_t fd, short what, void *arg)
{
	netreq_cb_data *cb_data = (netreq_cb_data *) arg;

	/* cleanup the local timer here since the memory may be
	 * invalid after calling ub_resolve_callback
	 */
	getdns_dns_req *dnsreq = cb_data->netreq->owner;
	event_free(dnsreq->local_cb_timer);
	dnsreq->local_cb_timer = NULL;

	/* just call ub_resolve_callback */
	ub_resolve_callback(cb_data->netreq, cb_data->err, cb_data->result,
	    cb_data->sec, cb_data->bogus);

	/* cleanup the state */
	ldns_buffer_free(cb_data->result);
	if (cb_data->bogus) {
		free(cb_data->bogus);
	}
	free(cb_data);
}

static void call_user_callback(getdns_dns_req *dns_req,
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
	call_user_callback(netreq->owner, NULL);
}

struct validation_chain {
	ldns_rbtree_t root;
	struct mem_funcs mf;
	getdns_dns_req *dns_req;
	size_t todo;
};
struct chain_response {
	int err;
	ldns_rr_list *result;
	int sec;
	char *bogus;
	struct validation_chain *chain;
	int unbound_id;
};
struct chain_link {
	ldns_rbnode_t node;
	struct chain_response DNSKEY;
	struct chain_response DS;
};

static void submit_link(struct validation_chain *chain, char *name);
static void callback_on_complete_chain(struct validation_chain *chain);
static void
ub_supporting_callback(void *arg, int err, ldns_buffer *result, int sec,
    char *bogus)
{
	struct chain_response *response = (struct chain_response *) arg;
	ldns_status r;
	ldns_pkt *p;
	ldns_rr_list *answer;
	ldns_rr_list *keys;
	size_t i;

	response->err    = err;
	response->sec    = sec;
	response->bogus  = bogus;

	if (result == NULL)
		goto done;

	r = ldns_buffer2pkt_wire(&p, result);
	if (r != LDNS_STATUS_OK) {
		if (err == 0)
			response->err = r;
		goto done;
	}

	keys = ldns_rr_list_new();
	answer = ldns_pkt_answer(p);
	for (i = 0; i < ldns_rr_list_rr_count(answer); i++) {
		ldns_rr *rr = ldns_rr_list_rr(answer, i);

		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY ||
		    ldns_rr_get_type(rr) == LDNS_RR_TYPE_DS) {

			(void) ldns_rr_list_push_rr(keys, ldns_rr_clone(rr));
			continue;
		}
		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG)
			continue;

		if (ldns_read_uint16(ldns_rdf_data(ldns_rr_rdf(rr, 0))) ==
		    LDNS_RR_TYPE_DS)
			submit_link(response->chain,
			    ldns_rdf2str(ldns_rr_rdf(rr, 7)));

		else if (ldns_read_uint16(ldns_rdf_data(ldns_rr_rdf(rr, 0))) !=
		    LDNS_RR_TYPE_DNSKEY)
			continue;

		(void) ldns_rr_list_push_rr(keys, ldns_rr_clone(rr));
	}
	if (ldns_rr_list_rr_count(keys))
		response->result = keys;
	else
		ldns_rr_list_free(keys);

	ldns_pkt_free(p);

done:	if (response->err == 0 && response->result == NULL)
		response->err = -1;

	callback_on_complete_chain(response->chain);
}

static void submit_link(struct validation_chain *chain, char *name)
{
	int r;
	struct chain_link *link = (struct chain_link *)
	    ldns_rbtree_search((ldns_rbtree_t *)&(chain->root), name);

	if (link) {
		free(name);
		return;
	}
	link = GETDNS_MALLOC(chain->mf, struct chain_link);
	link->node.key = name;

	link->DNSKEY.err        = 0;
	link->DNSKEY.result     = NULL;
	link->DNSKEY.sec        = 0;
	link->DNSKEY.bogus      = NULL;
	link->DNSKEY.chain      = chain;
	link->DNSKEY.unbound_id = -1;

	link->DS.err        = 0;
	link->DS.result     = NULL;
	link->DS.sec        = 0;
	link->DS.bogus      = NULL;
	link->DS.chain      = chain;
	link->DS.unbound_id = -1;

	ldns_rbtree_insert(&(chain->root), (ldns_rbnode_t *)link);
	/* fprintf(stderr, "submitting for: %s\n", name); */

	r = ub_resolve_event(chain->dns_req->unbound,
	    name, LDNS_RR_TYPE_DNSKEY, LDNS_RR_CLASS_IN, &link->DNSKEY,
	    ub_supporting_callback, &link->DNSKEY.unbound_id);
	if (r != 0)
		link->DNSKEY.err = r;

	r = ub_resolve_event(chain->dns_req->unbound,
	    name, LDNS_RR_TYPE_DS, LDNS_RR_CLASS_IN, &link->DS,
	    ub_supporting_callback, &link->DS.unbound_id);
	if (r != 0)
		link->DS.err = r;
}

void destroy_chain_link(ldns_rbnode_t * node, void *arg)
{
	struct chain_link *link = (struct chain_link*) node;
	struct validation_chain *chain   = (struct validation_chain*) arg;

	free((void *)link->node.key);
	ldns_rr_list_deep_free(link->DNSKEY.result);
	ldns_rr_list_deep_free(link->DS.result);
	GETDNS_FREE(chain->mf, link);
}

static void destroy_chain(struct getdns_context *context,
    struct validation_chain *chain)
{
	ldns_traverse_postorder(&(chain->root),
	    destroy_chain_link, chain);
	GETDNS_FREE(chain->mf, chain);
}

static void callback_on_complete_chain(struct validation_chain *chain)
{
	struct getdns_context *context = chain->dns_req->context;
	struct getdns_dict *response;
	struct chain_link *link;
	size_t todo = chain->todo;
	ldns_rr_list *keys;
	struct getdns_list *getdns_keys;

	LDNS_RBTREE_FOR(link, struct chain_link *,
	    (ldns_rbtree_t *)&(chain->root)) {
		if (link->DNSKEY.result == NULL && link->DNSKEY.err == 0)
			todo++;
		if (link->DS.result     == NULL && link->DS.err     == 0 &&
		   (((const char *)link->node.key)[0] != '.'  ||
		    ((const char *)link->node.key)[1] != '\0' ))
		       	todo++;
	}
	/* fprintf(stderr, "todo until validation: %d\n", (int)todo); */
	if (todo == 0) {
		response = create_getdns_response(chain->dns_req);

		keys = ldns_rr_list_new();
		LDNS_RBTREE_FOR(link, struct chain_link *,
		    (ldns_rbtree_t *)&(chain->root)) {
			(void) ldns_rr_list_cat(keys, link->DNSKEY.result);
			(void) ldns_rr_list_cat(keys, link->DS.result);
		}
		getdns_keys = create_list_from_rr_list(context, keys);
		(void) getdns_dict_set_list(response, "validation_chain",
		    getdns_keys);
		getdns_list_destroy(getdns_keys);
		ldns_rr_list_free(keys);
		destroy_chain(context, chain);
		call_user_callback(chain->dns_req, response);
	}
}

/* Do some additional requests to fetch the complete validation chain */
static void get_validation_chain(getdns_dns_req *dns_req)
{
	getdns_network_req *netreq = dns_req->first_req;
	struct validation_chain *chain = GETDNS_MALLOC(dns_req->context->mf,
	    struct validation_chain);

	ldns_rbtree_init(&(chain->root),
	    (int (*)(const void *, const void *)) strcmp);
	chain->mf.mf_arg         = dns_req->context->mf.mf_arg;
	chain->mf.mf.ext.malloc  = dns_req->context->mf.mf.ext.malloc;
	chain->mf.mf.ext.realloc = dns_req->context->mf.mf.ext.realloc;
	chain->mf.mf.ext.free    = dns_req->context->mf.mf.ext.free;
	chain->dns_req = dns_req;
	chain->todo = 1;

	while (netreq) {
		size_t i;
		ldns_rr_list *answer = ldns_pkt_answer(netreq->result);
		for (i = 0; i < ldns_rr_list_rr_count(answer); i++) {
			ldns_rr *rr = ldns_rr_list_rr(answer, i);
			if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
				submit_link(chain,
				    ldns_rdf2str(ldns_rr_rdf(rr, 7)));
		}
		netreq = netreq->next;
	}
	chain->todo--;
	callback_on_complete_chain(chain);
}

/* cleanup and send the response to the user callback */
static void
handle_dns_request_complete(getdns_dns_req * dns_req)
{
	uint32_t ret_chain_ext = GETDNS_EXTENSION_FALSE;
	getdns_return_t r = getdns_dict_get_int(dns_req->extensions,
	    "dnssec_return_validation_chain", &ret_chain_ext);

	if (r == GETDNS_RETURN_GOOD && ret_chain_ext == GETDNS_EXTENSION_TRUE)

		get_validation_chain(dns_req);
	else
		call_user_callback(dns_req, create_getdns_response(dns_req));
}

static int
submit_network_request(getdns_network_req * netreq)
{
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

static void
ub_resolve_callback(void *arg, int err, ldns_buffer * result, int sec,
    char *bogus)
{
	getdns_network_req *netreq = (getdns_network_req *) arg;
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
		getdns_dns_req *dnsreq = netreq->owner;
		netreq_cb_data *cb_data =
		    (netreq_cb_data *) malloc(sizeof(netreq_cb_data));

		cb_data->netreq = netreq;
		cb_data->err = err;
		cb_data->sec = sec;
		cb_data->result = NULL;
		cb_data->bogus = NULL;	/* unused but here in case we need it */
		if (result) {
			cb_data->result =
			    ldns_buffer_new(ldns_buffer_limit(result));
			if (!cb_data->result) {
				cb_data->err = GETDNS_RETURN_GENERIC_ERROR;
			} else {
				/* copy */
				ldns_buffer_copy(cb_data->result, result);
			}
		}
		/* schedule the timeout */
		dnsreq->local_cb_timer =
		    evtimer_new(dnsreq->ev_base, ub_local_resolve_timeout,
		    cb_data);
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
		ldns_status r =
		    ldns_buffer2pkt_wire(&(netreq->result), result);
		if (r != LDNS_STATUS_OK) {
			handle_network_request_error(netreq, r);
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
	}
}

getdns_return_t
getdns_general_ub(struct ub_ctx *unbound,
    struct event_base *ev_base,
    struct getdns_context *context,
    const char *name,
    uint16_t request_type,
    struct getdns_dict *extensions,
    void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callbackfn)
{
	/* timeout */
	struct timeval tv;
	getdns_return_t gr;
	int r;

	if (!name) {
		return GETDNS_RETURN_INVALID_PARAMETER;
	}

	gr = getdns_context_prepare_for_resolution(context);
	if (gr != GETDNS_RETURN_GOOD) {
		return GETDNS_RETURN_BAD_CONTEXT;
	}

	/* request state */
	getdns_dns_req *req = dns_req_new(context,
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

	if (!context || !context->event_base_async) {
		/* Can't do async without an event loop
		 * or callback
		 */
		return GETDNS_RETURN_BAD_CONTEXT;
	}

    /* ensure callback is not NULL */
    if (!callback || !name) {
         return GETDNS_RETURN_INVALID_PARAMETER;
    }

	extcheck = validate_extensions(extensions);
	if (extcheck != GETDNS_RETURN_GOOD)
		return extcheck;

	return getdns_general_ub(context->unbound_async,
	    context->event_base_async,
	    context,
	    name, request_type, extensions, userarg, transaction_id, callback);

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
	if (!extensions) {
		extensions = getdns_dict_create_with_context(context);
		cleanup_extensions = 1;
	}
	getdns_dict_set_int(extensions,
	    GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6, GETDNS_EXTENSION_TRUE);

	getdns_return_t result = getdns_general(context, name, GETDNS_RRTYPE_A,
	    extensions, userarg, transaction_id,
	    callback);
	if (cleanup_extensions) {
		getdns_dict_destroy(extensions);
	}
	return result;
}

/* getdns_general.c */
