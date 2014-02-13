/**
 *
 * /brief priv_getdns_get_validation_chain function
 *
 * The priv_getdns_get_validation_chain function is called after an answer
 * has been fetched when the dnssec_return_validation_chain extension is set.
 * It fetches DNSKEYs, DSes and their signatures for all RRSIGs found in the
 * answer.
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

#include <unbound.h>
#include <ldns/ldns.h>
#include <getdns/getdns.h>
#include "context.h"
#include "util-internal.h"
#include "types-internal.h"

void priv_getdns_call_user_callback(getdns_dns_req *, struct getdns_dict *);

struct validation_chain {
	ldns_rbtree_t root;
	struct mem_funcs mf;
	getdns_dns_req *dns_req;
	size_t lock;
	struct getdns_dict **sync_response;
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

static void launch_chain_link_lookup(struct validation_chain *chain, char *name);
static void destroy_chain(struct validation_chain *chain);

static void callback_on_complete_chain(struct validation_chain *chain)
{
	struct getdns_context *context = chain->dns_req->context;
	struct getdns_dict *response;
	struct chain_link *link;
	size_t ongoing = chain->lock;
	ldns_rr_list *keys;
	struct getdns_list *getdns_keys;

	LDNS_RBTREE_FOR(link, struct chain_link *,
	    (ldns_rbtree_t *)&(chain->root)) {
		if (link->DNSKEY.result == NULL && link->DNSKEY.err == 0)
			ongoing++;
		if (link->DS.result     == NULL && link->DS.err     == 0 &&
		   (((const char *)link->node.key)[0] != '.'  ||
		    ((const char *)link->node.key)[1] != '\0' ))
		       	ongoing++;
	}
	if (ongoing == 0) {
		getdns_dns_req *dns_req = chain->dns_req;
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
		if (chain->sync_response) {
			*chain->sync_response = response;
		} else
			priv_getdns_call_user_callback(dns_req, response);
		destroy_chain(chain);
	}
}


static void
ub_chain_response_callback(void *arg, int err, struct ub_result* ub_res)
{
	struct chain_response *response = (struct chain_response *) arg;
    ldns_status r;
    ldns_pkt *p;
    ldns_rr_list *answer;
    ldns_rr_list *keys;
    size_t i;

    response->err    = err;
    response->sec    = ub_res ? ub_res->secure : 0;
    response->bogus  = ub_res ? ub_res->why_bogus : NULL;

    if (ub_res == NULL)
        goto done;

    r = ldns_wire2pkt(&p, ub_res->answer_packet, ub_res->answer_len);
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
			launch_chain_link_lookup(response->chain,
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
    ub_resolve_free(ub_res);

done:	if (response->err == 0 && response->result == NULL)
		response->err = -1;

	callback_on_complete_chain(response->chain);
}

static void chain_response_init(
    struct validation_chain *chain, struct chain_response *response)
{
	response->err        = 0;
	response->result     = NULL;
	response->sec        = 0;
	response->bogus      = NULL;
	response->chain      = chain;
	response->unbound_id = -1;
}

static int
resolve(char* name, int rrtype, struct chain_response *response)
{
	int r;
	struct ub_result *ub_res;

	if (response->chain->sync_response) {
		ub_res = NULL;
		r = ub_resolve(response->chain->dns_req->context->unbound_ctx,
		    name, rrtype, LDNS_RR_CLASS_IN, &ub_res);
		ub_chain_response_callback(response, r, ub_res);
		return r;
	} else
		return ub_resolve_async(
		    response->chain->dns_req->context->unbound_ctx,
		    name, rrtype, LDNS_RR_CLASS_IN, response,
		    ub_chain_response_callback, &response->unbound_id);
}

static void
launch_chain_link_lookup(struct validation_chain *chain, char *name)
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

	chain_response_init(chain, &link->DNSKEY);
	chain_response_init(chain, &link->DS);

	ldns_rbtree_insert(&(chain->root), (ldns_rbnode_t *)link);

	chain->lock++;
	r = resolve(name, LDNS_RR_TYPE_DNSKEY, &link->DNSKEY);
	if (r != 0)
		link->DNSKEY.err = r;

	if (name[0] != '.' || name[1] != '\0') {
		r = resolve(name, LDNS_RR_TYPE_DS, &link->DS);
		if (r != 0)
			link->DS.err = r;
	}
	chain->lock--;
}

static struct validation_chain *create_chain(
    getdns_dns_req *dns_req, struct getdns_dict **sync_response)
{
	struct validation_chain *chain = GETDNS_MALLOC(
	    dns_req->context->mf, struct validation_chain);

	if (! chain)
		return NULL;

	ldns_rbtree_init(&(chain->root),
	    (int (*)(const void *, const void *)) strcmp);
	chain->mf.mf_arg         = dns_req->context->mf.mf_arg;
	chain->mf.mf.ext.malloc  = dns_req->context->mf.mf.ext.malloc;
	chain->mf.mf.ext.realloc = dns_req->context->mf.mf.ext.realloc;
	chain->mf.mf.ext.free    = dns_req->context->mf.mf.ext.free;
	chain->dns_req = dns_req;
	chain->lock = 0;
	chain->sync_response = sync_response;
	return chain;
}

static void destroy_chain_link(ldns_rbnode_t * node, void *arg)
{
	struct chain_link *link = (struct chain_link*) node;
	struct validation_chain *chain   = (struct validation_chain*) arg;

	free((void *)link->node.key);
	ldns_rr_list_deep_free(link->DNSKEY.result);
	ldns_rr_list_deep_free(link->DS.result);
	GETDNS_FREE(chain->mf, link);
}

static void destroy_chain(struct validation_chain *chain)
{
	ldns_traverse_postorder(&(chain->root),
	    destroy_chain_link, chain);
	GETDNS_FREE(chain->mf, chain);
}

/* Do some additional requests to fetch the complete validation chain */
static void
getdns_get_validation_chain(
    getdns_dns_req *dns_req, struct getdns_dict **sync_response)
{
	getdns_network_req *netreq = dns_req->first_req;
	struct validation_chain *chain = create_chain(dns_req, sync_response);

	if (! chain) {
		if (sync_response)
			*sync_response = create_getdns_response(dns_req);
		else
			priv_getdns_call_user_callback(
			    dns_req, create_getdns_response(dns_req));
		return;
	}
	while (netreq) {
		size_t i;
		ldns_rr_list *answer = ldns_pkt_answer(netreq->result);
		for (i = 0; i < ldns_rr_list_rr_count(answer); i++) {
			ldns_rr *rr = ldns_rr_list_rr(answer, i);
			if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
				launch_chain_link_lookup(chain,
				    ldns_rdf2str(ldns_rr_rdf(rr, 7)));
		}
		netreq = netreq->next;
	}
	callback_on_complete_chain(chain);
}


void priv_getdns_get_validation_chain(getdns_dns_req *dns_req)
{
	getdns_get_validation_chain(dns_req, NULL);
}

struct getdns_dict *
priv_getdns_get_validation_chain_sync(getdns_dns_req *dns_req)
{
	struct getdns_dict *sync_response = NULL;
	getdns_get_validation_chain(dns_req, &sync_response);
	return sync_response;
}

/* validation-chain.c */
