/**
 *
 * /brief function for DNSSEC
 *
 * The priv_getdns_get_validation_chain function is called after an answer
 * has been fetched when the dnssec_return_validation_chain extension is set.
 * It fetches DNSKEYs, DSes and their signatures for all RRSIGs found in the
 * answer.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unbound.h>
#include <ldns/ldns.h>
#include "getdns/getdns.h"
#include "config.h"
#include "context.h"
#include "util-internal.h"
#include "types-internal.h"
#include "dnssec.h"
#include "rr-dict.h"

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

/********************** functions for validate_dnssec *************************/

static getdns_return_t
priv_getdns_rr_list_from_list(struct getdns_list *list, ldns_rr_list **rr_list)
{
	getdns_return_t r;
	size_t i, l;
	struct getdns_dict *rr_dict;
	ldns_rr *rr;

	if ((r = getdns_list_get_length(list, &l)))
		return r;

	if (! (*rr_list = ldns_rr_list_new()))
		return GETDNS_RETURN_MEMORY_ERROR;

	for (i = 0; i < l; i++) {
		if ((r = getdns_list_get_dict(list, i, &rr_dict)))
			break;

		if ((r = priv_getdns_create_rr_from_dict(rr_dict, &rr)))
			break;

		if (! ldns_rr_list_push_rr(*rr_list, rr)) {
			ldns_rr_free(rr);
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
	}
	if (r)
		ldns_rr_list_deep_free(*rr_list);
	return r;
}

static getdns_return_t
priv_getdns_dnssec_zone_from_list(struct getdns_list *list,
    ldns_dnssec_zone **zone)
{
	getdns_return_t r;
	size_t i, l;
	struct getdns_dict *rr_dict;
	ldns_rr *rr;
	ldns_status s;

	if ((r = getdns_list_get_length(list, &l)))
		return r;

	if (! (*zone = ldns_dnssec_zone_new()))
		return GETDNS_RETURN_MEMORY_ERROR;

	for (i = 0; i < l; i++) {
		if ((r = getdns_list_get_dict(list, i, &rr_dict)))
			break;

		if ((r = priv_getdns_create_rr_from_dict(rr_dict, &rr)))
			break;

		if ((s = ldns_dnssec_zone_add_rr(*zone, rr))) {
			ldns_rr_free(rr);
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
	}
	if (r)
		ldns_dnssec_zone_free(*zone);
	return r;
}

typedef struct zone_iter {
	ldns_dnssec_zone   *zone;
	ldns_rbnode_t      *cur_node;
	ldns_dnssec_rrsets *cur_rrset;
} zone_iter;

static void
rrset_iter_init_zone(zone_iter *i, ldns_dnssec_zone *zone)
{	
	assert(i);

	i->zone = zone;
	i->cur_node = zone->names ? ldns_rbtree_first(zone->names)
	                          : LDNS_RBTREE_NULL;
	i->cur_rrset = i->cur_node != LDNS_RBTREE_NULL
	    ? ((ldns_dnssec_name *)i->cur_node->data)->rrsets
	    : NULL;
}

static ldns_dnssec_rrsets *
rrset_iter_value(zone_iter *i)
{
	assert(i);

	return i->cur_rrset;
}

static void
rrset_iter_next(zone_iter *i)
{
	assert(i);

	if (! i->cur_rrset)
		return;

	if (!  (i->cur_rrset = i->cur_rrset->next)) {
		i->cur_node  = ldns_rbtree_next(i->cur_node);
		i->cur_rrset = i->cur_node != LDNS_RBTREE_NULL
		    ? ((ldns_dnssec_name *)i->cur_node->data)->rrsets
		    : NULL;
	}
}

static ldns_rr_list *
rrs2rr_list(ldns_dnssec_rrs *rrs)
{
	ldns_rr_list *r = ldns_rr_list_new();
	if (r)
		while (rrs) {
			(void) ldns_rr_list_push_rr(r, rrs->rr);
			rrs = rrs->next;
		}
	return r;
}

static ldns_status
verify_rrset(ldns_dnssec_rrsets *rrset_and_sigs,
    const ldns_rr_list *keys, ldns_rr_list *good_keys)
{
	ldns_status s;
	ldns_rr_list *rrset = rrs2rr_list(rrset_and_sigs->rrs);
	ldns_rr_list *sigs  = rrs2rr_list(rrset_and_sigs->signatures);
	s = ldns_verify(rrset, sigs, keys, good_keys);
	ldns_rr_list_free(sigs);
	ldns_rr_list_free(rrset);
	return s;
}

static ldns_status
chase(ldns_dnssec_rrsets *rrset, ldns_dnssec_zone *support,
    ldns_rr_list *support_keys, ldns_rr_list *trusted)
{
	ldns_status s;
	ldns_rr_list *verifying_keys;
	size_t i, j;
	ldns_rr *rr;
	ldns_dnssec_rrsets *key_rrset;
	ldns_dnssec_rrs *rrs;

	/* Secure by trusted keys? */
	s = verify_rrset(rrset, trusted, NULL);
	if (s == 0)
		return s;

	/* No, chase with support records..
	 * Is there a verifying key in the support records?
	 */
	verifying_keys = ldns_rr_list_new();
	s = verify_rrset(rrset, support_keys, verifying_keys);
	if (s != 0)
		goto done_free_verifying_keys;

	/* Ok, we have verifying keys from the support records.
	 * Compare them with the *trusted* keys or DSes,
	 * or chase them further down the validation chain.
	 */
	for (i = 0; i < ldns_rr_list_rr_count(verifying_keys); i++) {
		/* Lookup the rrset for key rr from the support records */
		rr = ldns_rr_list_rr(verifying_keys, i);
		key_rrset = ldns_dnssec_zone_find_rrset(
		    support, ldns_rr_owner(rr), ldns_rr_get_type(rr));
		if (! key_rrset) {
			s = LDNS_STATUS_CRYPTO_NO_DNSKEY;
			break;
		}
		/* When we signed ourselves, we have to cross domain border
		 * and look for a matching DS signed by a parents key
		 */
		if (rrset == key_rrset) {
			/* Is the verifying key trusted?
			 * (i.e. DS in trusted)
			 */
			for (j = 0; j < ldns_rr_list_rr_count(trusted); j++)
				if (ldns_rr_compare_ds(ldns_rr_list_rr(
				    trusted, j), rr))
					break;
			/* If so, check for the next verifying key
			 * (or exit SECURE)
			 */
			if (j < ldns_rr_list_rr_count(trusted))
				continue;

			/* Search for a matching DS in the support records */
			key_rrset = ldns_dnssec_zone_find_rrset(
			    support, ldns_rr_owner(rr), LDNS_RR_TYPE_DS);
			if (! key_rrset) {
				s = LDNS_STATUS_CRYPTO_NO_DNSKEY;
				break;
			}
			/* Now check if DS matches the DNSKEY! */
			for (rrs = key_rrset->rrs; rrs; rrs = rrs->next)
				if (ldns_rr_compare_ds(rr, rrs->rr))
					break;
			if (! rrs) {
				s = LDNS_STATUS_CRYPTO_NO_DNSKEY;
				break;
			}
		}
		/* Pursue the chase with the verifying key (or its DS) */
		s = chase(key_rrset, support, support_keys, trusted);
		if (s != 0)
			break;
	}
done_free_verifying_keys:
	ldns_rr_list_free(verifying_keys);
	return s;
}

/*
 * getdns_validate_dnssec
 *
 */
getdns_return_t
getdns_validate_dnssec(struct getdns_list *records_to_validate,
    struct getdns_list *support_records,
    struct getdns_list *trust_anchors)
{
	getdns_return_t r;
	ldns_rr_list     *trusted;
	ldns_dnssec_zone *support;
	ldns_rr_list     *support_keys;
	ldns_dnssec_zone *to_validate;
	zone_iter i;
	ldns_dnssec_rrsets *rrset;
	ldns_dnssec_rrs *rrs;
	ldns_status s = LDNS_STATUS_OK;

	if ((r = priv_getdns_rr_list_from_list(trust_anchors, &trusted)))
		return r;

	if ((r = priv_getdns_dnssec_zone_from_list(
	    support_records, &support)))
		goto done_free_trusted;

	if ((r = priv_getdns_dnssec_zone_from_list(
	    records_to_validate, &to_validate)))
		goto done_free_support;

	if (! (support_keys = ldns_rr_list_new())) {
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto done_free_to_validate;
	}
	/* Create a rr_list of all the keys in the support records */
	for (rrset_iter_init_zone(&i, support);
	    (rrset = rrset_iter_value(&i)); rrset_iter_next(&i))

		if (ldns_dnssec_rrsets_type(rrset) == LDNS_RR_TYPE_DS ||
		    ldns_dnssec_rrsets_type(rrset) == LDNS_RR_TYPE_DNSKEY)

			for (rrs = rrset->rrs; rrs; rrs = rrs->next)
				(void) ldns_rr_list_push_rr(
				    support_keys, rrs->rr);

	/* Now walk through the rrsets to validate */
	for (rrset_iter_init_zone(&i, to_validate);
	    (rrset = rrset_iter_value(&i)); rrset_iter_next(&i)) {

		s |= chase(rrset, support, support_keys, trusted);
		if (s != 0)
			break;
	}
	if (s == LDNS_STATUS_CRYPTO_BOGUS)
		r = GETDNS_DNSSEC_BOGUS;
	else if (s != LDNS_STATUS_OK)
		r = GETDNS_DNSSEC_INSECURE;
	else
		r = GETDNS_DNSSEC_SECURE;

	ldns_rr_list_free(support_keys);
done_free_to_validate:
	ldns_dnssec_zone_deep_free(to_validate);
done_free_support:
	ldns_dnssec_zone_deep_free(support);
done_free_trusted:
	ldns_rr_list_deep_free(trusted);
	return r;
}				/* getdns_validate_dnssec */

int
priv_getdns_parse_ta_file(time_t *ta_mtime, ldns_rr_list *ta_rrs)
{
	uint32_t ttl = 3600;
	ldns_rdf* orig = NULL, *prev = NULL;
	int line = 1;
	ldns_status s;
	ldns_rr *rr;
	int nkeys;
	struct stat st;
	FILE *in;

	if (stat(TRUST_ANCHOR_FILE, &st) != 0)
		return 0;

	if (ta_mtime)
		*ta_mtime = st.st_mtime;

	in = fopen(TRUST_ANCHOR_FILE, "r");
	if (!in)
		return 0;

	nkeys = 0;
	while (! feof(in)) {
		rr = NULL;
		s = ldns_rr_new_frm_fp_l(&rr, in, &ttl, &orig, &prev, &line);
		if (s == LDNS_STATUS_SYNTAX_EMPTY /* empty line */
		    || s == LDNS_STATUS_SYNTAX_TTL /* $TTL */
		    || s == LDNS_STATUS_SYNTAX_ORIGIN /* $ORIGIN */)
			continue;

		if (s != LDNS_STATUS_OK) {
			ldns_rr_free(rr);
			nkeys = 0;
			break;
		}
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DS ||
		    ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY) {

			nkeys++;
			if (ta_rrs) {
				ldns_rr_list_push_rr(ta_rrs, rr);
				continue;
			}
		}
		ldns_rr_free(rr);
	}
	ldns_rdf_deep_free(orig);
	ldns_rdf_deep_free(prev);
	fclose(in);
	return nkeys;
}

getdns_list *
getdns_root_trust_anchor(time_t *utc_date_of_anchor)
{
	getdns_list  *tas_gd_list = NULL;
	ldns_rr_list *tas_rr_list = ldns_rr_list_new();

	if (! tas_rr_list)
		return NULL;

	if (! priv_getdns_parse_ta_file(utc_date_of_anchor, tas_rr_list)) {
		goto done_free_tas_rr_list;
		return NULL;
	}
	tas_gd_list = create_list_from_rr_list(NULL, tas_rr_list);

done_free_tas_rr_list:
	ldns_rr_list_deep_free(tas_rr_list);
	return tas_gd_list;
}

/* dnssec.c */
