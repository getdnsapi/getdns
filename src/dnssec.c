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
#include "gldns/str2wire.h"
#include "gldns/wire2str.h"
#include "general.h"
#include "dict.h"

#if defined(SEC_DEBUG) && SEC_DEBUG
static void debug_sec_print_rr(const char *msg, priv_getdns_rr_iter *rr)
{
	char str_spc[8192], *str = str_spc;
	size_t str_len = sizeof(str_spc);
	uint8_t *data = rr->pos;
	size_t data_len = rr->nxt - rr->pos;

	if (!rr || !rr->pos) {
		DEBUG_SEC("<nil>\n");
		return;
	}
	(void) gldns_wire2str_rr_scan(&data, &data_len, &str, &str_len, rr->pkt, rr->pkt_end - rr->pkt);
	DEBUG_SEC("%s%s", msg, str_spc);
}
#else
#define debug_sec_print_rr(...) DEBUG_OFF(__VA_ARGS__)
#endif


static inline uint16_t rr_iter_type(priv_getdns_rr_iter *rr)
{ return rr->rr_type + 2 <= rr->nxt ? gldns_read_uint16(rr->rr_type) : 0; }
static inline uint16_t rr_iter_class(priv_getdns_rr_iter *rr)
{ return rr->rr_type + 4 <= rr->nxt ? gldns_read_uint16(rr->rr_type + 2) : 0; }

static priv_getdns_rr_iter *rr_iter_ansauth(priv_getdns_rr_iter *rr)
{
	while (rr && rr->pos && !(
	    priv_getdns_rr_iter_section(rr) == GLDNS_SECTION_ANSWER ||
	    priv_getdns_rr_iter_section(rr) == GLDNS_SECTION_AUTHORITY))

		rr = priv_getdns_rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

static int rr_owner_equal(priv_getdns_rr_iter *rr, uint8_t *name)
{
	uint8_t owner_spc[256], *owner;
	size_t  owner_len = sizeof(owner_spc);

	return (owner = priv_getdns_owner_if_or_as_decompressed(rr,  owner_spc
	                                                          , &owner_len))
	    && priv_getdns_dname_equal(owner, name);
}

static priv_getdns_rr_iter *rr_iter_name_class_type(priv_getdns_rr_iter *rr,
    uint8_t *name, uint16_t rr_class, uint16_t rr_type)
{
	while (rr_iter_ansauth(rr) && !(
	    rr_iter_type(rr)  == rr_type  &&
	    rr_iter_class(rr) == rr_class &&
	    rr_owner_equal(rr, name)))

		rr = priv_getdns_rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

static priv_getdns_rr_iter *rr_iter_not_name_class_type(priv_getdns_rr_iter *rr,
    uint8_t *name, uint16_t rr_class, uint16_t rr_type)
{
	while (rr_iter_ansauth(rr) && (
	    rr_iter_type(rr)  == GETDNS_RRTYPE_RRSIG || (
	    rr_iter_type(rr)  == rr_type  &&
	    rr_iter_class(rr) == rr_class &&
	    rr_owner_equal(rr, name))))

		rr = priv_getdns_rr_iter_next(rr);
	
	return rr && rr->pos ? rr : NULL;
}

static priv_getdns_rr_iter *rr_iter_rrsig_covering(priv_getdns_rr_iter *rr,
    uint8_t *name, uint16_t rr_class, uint16_t rr_type)
{
	while (rr_iter_ansauth(rr) && !(
	    rr_iter_type(rr)  == GETDNS_RRTYPE_RRSIG &&
	    rr_iter_class(rr) == rr_class &&
	    rr->rr_type + 12 <= rr->nxt &&
	    gldns_read_uint16(rr->rr_type + 10) == rr_type && 
	    rr_owner_equal(rr, name)))

		rr = priv_getdns_rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

typedef struct getdns_rrset {
	uint8_t            *name;
	uint16_t            rr_class;
	uint16_t            rr_type;
	getdns_network_req *netreq;
	uint8_t             name_spc[];
} getdns_rrset;

typedef struct rrtype_iter {
	priv_getdns_rr_iter  rr_i;
	getdns_rrset        *rrset;
} rrtype_iter;

typedef struct rrsig_iter {
	priv_getdns_rr_iter  rr_i;
	getdns_rrset        *rrset;
} rrsig_iter;

static rrtype_iter *rrtype_iter_next(rrtype_iter *i)
{
	return (rrtype_iter *) rr_iter_name_class_type(
	    priv_getdns_rr_iter_next(&i->rr_i),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

static rrtype_iter *rrtype_iter_init(rrtype_iter *i, getdns_rrset *rrset)
{
	i->rrset = rrset;
	return (rrtype_iter *) rr_iter_name_class_type(
	    priv_getdns_rr_iter_init(&i->rr_i, rrset->netreq->response
	                                     , rrset->netreq->response_len),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

static rrsig_iter *rrsig_iter_next(rrsig_iter *i)
{
	return (rrsig_iter *) rr_iter_rrsig_covering(
	    priv_getdns_rr_iter_next(&i->rr_i),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

static rrsig_iter *rrsig_iter_init(rrsig_iter *i, getdns_rrset *rrset)
{
	i->rrset = rrset;
	return (rrsig_iter *) rr_iter_rrsig_covering(
	    priv_getdns_rr_iter_init(&i->rr_i, rrset->netreq->response
	                                     , rrset->netreq->response_len),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

static int rrset_has_rrsigs(getdns_rrset *rrset)
{
	rrsig_iter rrsig;
	return rrsig_iter_init(&rrsig, rrset) != NULL;
}

#if defined(SEC_DEBUG) && SEC_DEBUG
static void debug_sec_print_rrset(const char *msg, getdns_rrset *rrset)
{
	char owner[1024];
	char buf_space[2048];
	gldns_buffer buf;
	rrtype_iter *rr, rr_space;
	rrsig_iter  *rrsig, rrsig_space;
	size_t i;

	if (!rrset) {
		DEBUG_SEC("<nil>");
		return;
	}
	gldns_buffer_init_frm_data(&buf, buf_space, sizeof(buf_space));
	if (gldns_wire2str_dname_buf(rrset->name, 256, owner, sizeof(owner)))
		gldns_buffer_printf(&buf, "%s ", owner);
	else	gldns_buffer_printf(&buf, "<nil> ");

	switch (rrset->rr_class) {
	case GETDNS_RRCLASS_IN	: gldns_buffer_printf(&buf, "IN ")  ; break;
	case GETDNS_RRCLASS_CH	: gldns_buffer_printf(&buf, "CH ")  ; break;
	case GETDNS_RRCLASS_HS	: gldns_buffer_printf(&buf, "HS ")  ; break;
	case GETDNS_RRCLASS_NONE: gldns_buffer_printf(&buf, "NONE "); break;
	case GETDNS_RRCLASS_ANY	: gldns_buffer_printf(&buf, "ANY ") ; break;
	default			: gldns_buffer_printf(&buf, "CLASS%d "
						          , rrset->rr_class);
				  break;
	}
	gldns_buffer_printf(&buf, "%s", priv_getdns_rr_type_name(rrset->rr_type));

	gldns_buffer_printf(&buf, ", rrs:");
	for ( rr = rrtype_iter_init(&rr_space, rrset), i = 1
	    ; rr
	    ; rr = rrtype_iter_next(rr), i++)
		gldns_buffer_printf(&buf, " %d", (int)i);

	gldns_buffer_printf(&buf, ", rrsigs:");
	for ( rrsig = rrsig_iter_init(&rrsig_space, rrset), i = 1
	    ; rrsig
	    ; rrsig = rrsig_iter_next(rrsig), i++)
		gldns_buffer_printf(&buf, " %d", (int)i);

	DEBUG_SEC("%s%s\n", msg, buf_space);
}
#else
#define debug_sec_print_rrset(...) DEBUG_OFF(__VA_ARGS__)
#endif



typedef struct rrset_iter rrset_iter;
struct rrset_iter {
	getdns_rrset        rrset;
	uint8_t             name_spc[256];
	size_t              name_len;
	priv_getdns_rr_iter rr_i;
};

static rrset_iter *rrset_iter_init(rrset_iter *i, getdns_network_req *netreq)
{
	priv_getdns_rr_iter *rr;

	i->rrset.name = i->name_spc;
	i->rrset.netreq = netreq;
	i->name_len = 0;

	for ( rr = priv_getdns_rr_iter_init(&i->rr_i
	                                   , netreq->response
	                                   , netreq->response_len)
	    ;(rr = rr_iter_ansauth(rr))
	    ; rr = priv_getdns_rr_iter_next(rr)) {

		if ((i->rrset.rr_type = rr_iter_type(rr))
		    == GETDNS_RRTYPE_RRSIG)
			continue;

		i->rrset.rr_class = rr_iter_class(rr);

		if (!(i->rrset.name = priv_getdns_owner_if_or_as_decompressed(
		    rr, i->name_spc, &i->name_len)))
			continue;

		return i;
	}
	return NULL;
}


static rrset_iter *rrset_iter_next(rrset_iter *i)
{
	priv_getdns_rr_iter *rr;

	if (!(rr = i && i->rr_i.pos ? &i->rr_i : NULL))
		return NULL;

	if (!(rr = rr_iter_not_name_class_type(rr,
	    i->rrset.name, i->rrset.rr_class, i->rrset.rr_type)))
		return NULL;

	i->rrset.rr_type  = rr_iter_type(rr);
	i->rrset.rr_class = rr_iter_class(rr);
	if (!(i->rrset.name = priv_getdns_owner_if_or_as_decompressed(
		    rr, i->name_spc, &i->name_len)))
		return rrset_iter_next(i);

	return i;
}

static getdns_rrset *rrset_iter_value(rrset_iter *i)
{
	if (!i)
		return NULL;
	if (!i->rr_i.pos)
		return NULL;
	return &i->rrset;
}

typedef struct chain_head chain_head;
typedef struct chain_node chain_node;

struct chain_head {
	chain_head  *next;
	chain_node  *parent;
	getdns_rrset rrset;
};

struct chain_node {
	chain_node  *parent;
	
	unsigned int skip: 1; /* This label plays no role */
	unsigned int cut : 1; /* At a zone cut */

	getdns_rrset dnskey;
	getdns_rrset ds    ;
};

static void check_chain_complete(chain_head *chain)
{
}

static void add2val_chain(
    chain_head **chain_p, getdns_network_req *netreq)
{
	rrset_iter *i, i_spc;

	assert(netreq->response);
	assert(netreq->response_len >= GLDNS_HEADER_SIZE);

	/* For all things with signatures, create a chain */

	/* For all things without signature, find SOA (zonecut) and query DS */

	/* On empty packet, find SOA (zonecut) for the qname and query DS */

	for (i = rrset_iter_init(&i_spc, netreq); i; i = rrset_iter_next(i)) {
		debug_sec_print_rrset("rrset: ", rrset_iter_value(i));
	}
}

static void get_val_chain(getdns_dns_req *dnsreq)
{
	getdns_network_req *netreq, **netreq_p;
	chain_head *chain = NULL;

	for (netreq_p = dnsreq->netreqs; (netreq = *netreq_p) ; netreq_p++)
		add2val_chain(&chain, netreq);

	if (chain)
		check_chain_complete(chain);
	else
		priv_getdns_call_user_callback(dnsreq,
		    create_getdns_response(dnsreq));
}

/******************************************************************************/
/*****************************                  *******************************/
/*****************************  NEW CHAIN CODE  *******************************/
/*****************************     (above)      *******************************/
/*****************************                  *******************************/
/******************************************************************************/

struct validation_chain {
	getdns_rbtree_t root;
	struct mem_funcs mf;
	getdns_dns_req *dns_req;
	size_t lock;
	uint64_t *timeout;
};

struct chain_response {
	int err;
	getdns_list *result;
	struct validation_chain *chain;
	getdns_dns_req *dns_req;
};

struct chain_link {
	getdns_rbnode_t node;
	struct chain_response DNSKEY;
	struct chain_response DS;
};

static void launch_chain_link_lookup(struct validation_chain *chain,
    uint8_t *dname);
static void destroy_chain(struct validation_chain *chain);

#ifdef STUB_NATIVE_DNSSEC
static void
native_stub_validate_dnssec(getdns_dns_req *dns_req, getdns_list *support)
{
	getdns_network_req *netreq, **netreq_p;
	getdns_list *trust_anchors;
	getdns_dict *reply = NULL;
	getdns_list *to_validate;
	getdns_list *list;
	getdns_dict *rr_dict;
	size_t i;

	if (!(trust_anchors = getdns_root_trust_anchor(NULL)))
		return;

	for (netreq_p = dns_req->netreqs; (netreq = *netreq_p) ; netreq_p++) {
		if (!(reply = priv_getdns_create_reply_dict(dns_req->context,
		    netreq, NULL, NULL)))
			continue;
		if (!(to_validate =
		    getdns_list_create_with_context(dns_req->context)))
			break;
		if (getdns_dict_get_list(reply, "answer", &list)) {
			getdns_list_destroy(to_validate);
			break;
		}
		for (i = 0; !getdns_list_get_dict(list, i, &rr_dict); i++)
			(void) getdns_list_append_dict(to_validate, rr_dict);

		if (getdns_dict_get_list(reply, "authority", &list)) {
			getdns_list_destroy(to_validate);
			break;
		}
		for (i = 0; !getdns_list_get_dict(list, i, &rr_dict); i++)
			(void) getdns_list_append_dict(to_validate, rr_dict);

		switch ((int)getdns_validate_dnssec(
		    to_validate, support, trust_anchors)) {
		case GETDNS_DNSSEC_SECURE:
			netreq->secure = 1;
			netreq->bogus  = 0;
			break;
		case GETDNS_DNSSEC_BOGUS:
			netreq->secure = 0;
			netreq->bogus  = 1;
			break;
		default:
			/* GETDNS_DNSSEC_INSECURE */
			netreq->secure = 0;
			netreq->bogus  = 0;
			break;
		}
		getdns_list_destroy(to_validate);
		getdns_dict_destroy(reply);
		reply = NULL;
	}
	getdns_list_destroy(trust_anchors);
	getdns_dict_destroy(reply);
}
#endif

static void callback_on_complete_chain(struct validation_chain *chain)
{
	getdns_context *context = chain->dns_req->context;
	getdns_dict *response;
	struct chain_link *link;
	size_t ongoing = chain->lock;
	getdns_list *keys;
	size_t i;
	getdns_dict *rr_dict;

	RBTREE_FOR(link, struct chain_link *,
	    (getdns_rbtree_t *)&(chain->root)) {
		if (link->DNSKEY.result == NULL && link->DNSKEY.err == 0)
			ongoing++;
		if (link->DS.result     == NULL && link->DS.err     == 0 &&
		   (((const char *)link->node.key)[0] != '.'  ||
		    ((const char *)link->node.key)[1] != '\0' ))
		       	ongoing++;
	}
	if (ongoing > 0)
		return;

	if (!(keys = getdns_list_create_with_context(context))) {
		priv_getdns_call_user_callback(chain->dns_req,
		    create_getdns_response(chain->dns_req));
		destroy_chain(chain);
		return;
	}
	RBTREE_FOR(link, struct chain_link *,
	    (getdns_rbtree_t *)&(chain->root)) {
		for (i = 0; !getdns_list_get_dict( link->DS.result
						 , i, &rr_dict); i++)
			(void) getdns_list_append_dict(keys, rr_dict);

		for (i = 0; !getdns_list_get_dict( link->DNSKEY.result
						 , i, &rr_dict); i++)
			(void) getdns_list_append_dict(keys, rr_dict);
	}
#ifdef STUB_NATIVE_DNSSEC
	native_stub_validate_dnssec(chain->dns_req, keys);
#endif
	if ((response = create_getdns_response(chain->dns_req)) &&
	    chain->dns_req->dnssec_return_validation_chain) {
	    (void)getdns_dict_set_list(response, "validation_chain", keys);
	}
	getdns_list_destroy(keys);
	priv_getdns_call_user_callback(chain->dns_req, response);
	destroy_chain(chain);
}


static void
chain_response_callback(struct getdns_dns_req *dns_req)
{
	struct chain_response *response =
	    (struct chain_response *) dns_req->user_pointer;
	getdns_context *context = dns_req->context;
	getdns_network_req **netreq_p, *netreq;
	priv_getdns_rr_iter rr_iter_storage, *rr_iter;
	priv_getdns_rdf_iter rdf_storage, *rdf;
	gldns_pkt_section section;
	uint16_t rr_type, type_covered;
	getdns_dict *rr_dict;
	getdns_list *keys;
	size_t nkeys;
	getdns_return_t r;
	uint8_t sign_name_space[256], *sign_name;
	size_t sign_name_len = sizeof(sign_name_space);

	response->dns_req = dns_req;
	if (!(keys = getdns_list_create_with_context(context)))
	    goto done;

	for (netreq_p = dns_req->netreqs; (netreq = *netreq_p); netreq_p++) {
		for ( rr_iter = priv_getdns_rr_iter_init(&rr_iter_storage
							, netreq->response
							, netreq->response_len)
		    ; rr_iter
		    ; rr_iter = priv_getdns_rr_iter_next(rr_iter)
		    ) {
			section = priv_getdns_rr_iter_section(rr_iter);
			if (section != GLDNS_SECTION_ANSWER &&
			    section != GLDNS_SECTION_AUTHORITY)
				continue;

			rr_type = gldns_read_uint16(rr_iter->rr_type);

			if (rr_type == GETDNS_RRTYPE_DS ||
			    rr_type == GETDNS_RRTYPE_DNSKEY ||
			    rr_type == GETDNS_RRTYPE_NSEC ||
			    rr_type == GETDNS_RRTYPE_NSEC3) {
				if (!(rr_dict = priv_getdns_rr_iter2rr_dict(
				    context, rr_iter)))
					continue;
				r = getdns_list_append_dict(keys, rr_dict);
				getdns_dict_destroy(rr_dict);
				if (r) break;
			}
			if (rr_type != GETDNS_RRTYPE_RRSIG)
				continue;

			if (!(rdf = priv_getdns_rdf_iter_init(
			    &rdf_storage, rr_iter)))
				continue;

			type_covered = gldns_read_uint16(rdf->pos);
			if (type_covered == GETDNS_RRTYPE_DS ||
			    type_covered == GETDNS_RRTYPE_NSEC ||
			    type_covered == GETDNS_RRTYPE_NSEC3) {

				if ((rdf = priv_getdns_rdf_iter_init_at(
				    &rdf_storage, rr_iter, 7)) &&
				    (sign_name = priv_getdns_rdf_if_or_as_decompressed(
				    rdf, sign_name_space, &sign_name_len)))

					launch_chain_link_lookup(
					    response->chain, sign_name);

			} else if (type_covered != GETDNS_RRTYPE_DNSKEY)
				continue;

			if (!(rr_dict = priv_getdns_rr_iter2rr_dict(
			    context, rr_iter)))
				continue;
			r = getdns_list_append_dict(keys, rr_dict);
			getdns_dict_destroy(rr_dict);
			if (r) break;
		}
	}
	if (getdns_list_get_length(keys, &nkeys))
		getdns_list_destroy(keys);

	else if (!nkeys)
		getdns_list_destroy(keys);
	else
		response->result = keys;


done:	if (response->err == 0 && response->result == NULL)
		response->err = -1;

	callback_on_complete_chain(response->chain);
}

static void chain_response_init(
    struct validation_chain *chain, struct chain_response *response)
{
	response->err     = 0;
	response->result  = NULL;
	response->chain   = chain;
	response->dns_req = NULL;
}

static int
resolve(char* name, int rrtype, struct chain_response *response)
{
	getdns_return_t r;
	getdns_dict *extensions;

	if (!(extensions = getdns_dict_create_with_context(
	    response->chain->dns_req->context)))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!(r = getdns_dict_set_int(extensions,
	    "dnssec_ok_checking_disabled", GETDNS_EXTENSION_TRUE)))

		r = priv_getdns_general_loop(response->chain->dns_req->context,
		    response->chain->dns_req->loop, name, rrtype, extensions,
		    response, NULL, NULL, chain_response_callback);

	getdns_dict_destroy(extensions);
	return r;
}

static void
find_delegation_point_callback(struct getdns_dns_req *dns_req)
{
	struct validation_chain *chain =
	    (struct validation_chain *) dns_req->user_pointer;
	getdns_network_req **netreq_p, *netreq;
	priv_getdns_rr_iter rr_iter_storage, *rr_iter;
	gldns_pkt_section section;
	uint16_t rr_type;
	uint8_t rr_name_space[256], *rr_name;
	size_t rr_name_len = sizeof(rr_name_space);

	for (netreq_p = dns_req->netreqs; (netreq = *netreq_p); netreq_p++) {
		for ( rr_iter = priv_getdns_rr_iter_init(&rr_iter_storage
							, netreq->response
							, netreq->response_len)
		    ; rr_iter
		    ; rr_iter = priv_getdns_rr_iter_next(rr_iter)
		    ) {
			section = priv_getdns_rr_iter_section(rr_iter);
			if (section != GLDNS_SECTION_ANSWER &&
			    section != GLDNS_SECTION_AUTHORITY)
				continue;

			rr_type = gldns_read_uint16(rr_iter->rr_type);
			if (rr_type != GETDNS_RRTYPE_SOA)
				continue;

			if (!(rr_name = priv_getdns_owner_if_or_as_decompressed(
			    rr_iter, rr_name_space, &rr_name_len)))
				continue;

			launch_chain_link_lookup(chain, rr_name);
		}
	}
	chain->lock--;
	getdns_context_clear_outbound_request(dns_req);
	dns_req_free(dns_req);
	callback_on_complete_chain(chain);
}

static int
find_delegation_point(struct validation_chain *chain, uint8_t *dname)
{
	getdns_return_t r;
	getdns_dict *extensions;
	char name[1024];

	if (!gldns_wire2str_dname_buf(dname, 256, name, sizeof(name)))
		return GETDNS_RETURN_GENERIC_ERROR;

	if (!(extensions = getdns_dict_create_with_context(
	    chain->dns_req->context)))
		return GETDNS_RETURN_MEMORY_ERROR;

	chain->lock++;
	if (!(r = getdns_dict_set_int(extensions,
	    "dnssec_ok_checking_disabled", GETDNS_EXTENSION_TRUE)))

		r = priv_getdns_general_loop(chain->dns_req->context,
		    chain->dns_req->loop, name, GETDNS_RRTYPE_SOA, extensions,
		    chain, NULL, NULL, find_delegation_point_callback);

	getdns_dict_destroy(extensions);
	if (r)
		chain->lock--;
	return r;
}

static void
launch_chain_link_lookup(
    struct validation_chain *chain, uint8_t *dname)
{
	int r;
	struct chain_link *link;
	char name[1024];
	
	if (!gldns_wire2str_dname_buf(dname, 256, name, sizeof(name)))
		return;

	if ((link = (struct chain_link *)
	    getdns_rbtree_search((getdns_rbtree_t *)&(chain->root), name)))
		return;

	link = GETDNS_MALLOC(chain->mf, struct chain_link);
	link->node.key = getdns_strdup(&chain->mf, name);

	chain_response_init(chain, &link->DNSKEY);
	chain_response_init(chain, &link->DS);

	getdns_rbtree_insert(&(chain->root), (getdns_rbnode_t *)link);

	chain->lock++;
	r = resolve(name, GETDNS_RRTYPE_DNSKEY, &link->DNSKEY);
	if (r != 0)
		link->DNSKEY.err = r;

	if (name[0] != '.' || name[1] != '\0') {
		r = resolve(name, GETDNS_RRTYPE_DS, &link->DS);
		if (r != 0)
			link->DS.err = r;
	}
	chain->lock--;
}

static struct validation_chain *create_chain(getdns_dns_req *dns_req,
    uint64_t *timeout)
{
	struct validation_chain *chain = GETDNS_MALLOC(
	    dns_req->context->mf, struct validation_chain);

	if (! chain)
		return NULL;

	getdns_rbtree_init(&(chain->root),
	    (int (*)(const void *, const void *)) strcmp);
	chain->mf.mf_arg         = dns_req->context->mf.mf_arg;
	chain->mf.mf.ext.malloc  = dns_req->context->mf.mf.ext.malloc;
	chain->mf.mf.ext.realloc = dns_req->context->mf.mf.ext.realloc;
	chain->mf.mf.ext.free    = dns_req->context->mf.mf.ext.free;
	chain->dns_req = dns_req;
	chain->lock = 0;
	chain->timeout = timeout;
	return chain;
}

static void destroy_chain_link(getdns_rbnode_t * node, void *arg)
{
	struct chain_link *link = (struct chain_link*) node;
	struct validation_chain *chain   = (struct validation_chain*) arg;

	free((void *)link->node.key);

	getdns_list_destroy(link->DNSKEY.result);
	if (link->DNSKEY.dns_req) {
		getdns_context_clear_outbound_request(link->DNSKEY.dns_req);
		dns_req_free(link->DNSKEY.dns_req);
	}
	getdns_list_destroy(link->DS.result);
	if (link->DS.dns_req) {
		getdns_context_clear_outbound_request(link->DS.dns_req);
		dns_req_free(link->DS.dns_req);
	}
	GETDNS_FREE(chain->mf, link);
}

static void destroy_chain(struct validation_chain *chain)
{
	getdns_traverse_postorder(&(chain->root), destroy_chain_link, chain);
	GETDNS_FREE(chain->mf, chain);
}


static int priv_getdns_dname_is_subdomain(
    const uint8_t *subdomain, const uint8_t *domain)
{
	while (*domain) {
		if (priv_getdns_dname_equal(subdomain, domain))
			return 1;

		domain += *domain + 1;
	}
	return *subdomain == 0;
}
/* Do some additional requests to fetch the complete validation chain */
static void
getdns_get_validation_chain(getdns_dns_req *dns_req, uint64_t *timeout)
{
	getdns_network_req **netreq_p, *netreq;
	struct validation_chain *chain = create_chain(dns_req, timeout);
	priv_getdns_rr_iter rr_iter_storage, *rr_iter;
	priv_getdns_rdf_iter rdf_storage, *rdf;
	gldns_pkt_section section;
	uint16_t rr_type;
	priv_getdns_rr_iter rrsig_iter_storage, *rrsig_iter;
	uint8_t rr_name_space[256], *rr_name;
	uint8_t rrsig_name_space[256], *rrsig_name;
	uint8_t sign_name_space[256], *sign_name;
	size_t rr_name_len = sizeof(rr_name_space);
	size_t rrsig_name_len = sizeof(rrsig_name_space);
	size_t sign_name_len = sizeof(sign_name_space);
	int rrsigs_found;

	if (! chain) {
		priv_getdns_call_user_callback(
		    dns_req, create_getdns_response(dns_req));
		return;
	}
	chain->lock++;
	for (netreq_p = dns_req->netreqs; (netreq = *netreq_p); netreq_p++) {

		for ( rr_iter = priv_getdns_rr_iter_init(&rr_iter_storage
		                                        , netreq->response
							, netreq->response_len)
		    ; rr_iter
		    ; rr_iter = priv_getdns_rr_iter_next(rr_iter)
		    ) {
			section = priv_getdns_rr_iter_section(rr_iter);
			if (section != GLDNS_SECTION_ANSWER &&
			    section != GLDNS_SECTION_AUTHORITY)
				continue;

			/* Skip RRSIGs because we do only lookups for RRSIGS
			 * that have an rrset in the record too.
			 */
			rr_type = gldns_read_uint16(rr_iter->rr_type);
			if (rr_type == GETDNS_RRTYPE_RRSIG)
				continue;

			if (!(rr_name = priv_getdns_owner_if_or_as_decompressed(
			    rr_iter, rr_name_space, &rr_name_len)))
				continue;

			rrsigs_found = 0;
			for ( rrsig_iter = priv_getdns_rr_iter_init(&rrsig_iter_storage
								   , netreq->response
								   , netreq->response_len )
			    ; rrsig_iter
			    ; rrsig_iter = priv_getdns_rr_iter_next(rrsig_iter)
			    ) {
				section = priv_getdns_rr_iter_section(rrsig_iter);
				if (section != GLDNS_SECTION_ANSWER &&
				    section != GLDNS_SECTION_AUTHORITY)
					continue;

				if (GETDNS_RRTYPE_RRSIG != 
				    gldns_read_uint16(rrsig_iter->rr_type))
					continue;

				rdf =  priv_getdns_rdf_iter_init(&rdf_storage
				                                , rrsig_iter);
				if (!rdf || gldns_read_uint16(rdf->pos) != rr_type)
					continue;

				if (!(rrsig_name = priv_getdns_owner_if_or_as_decompressed(
				    rrsig_iter, rrsig_name_space, &rrsig_name_len)))
					continue;

				if (!priv_getdns_dname_equal(rr_name, rrsig_name))
					continue;

				if (!(rdf =  priv_getdns_rdf_iter_init_at(
				    &rdf_storage , rrsig_iter, 7)))
					continue;

				if (!(sign_name = priv_getdns_rdf_if_or_as_decompressed(
				    rdf, sign_name_space, &sign_name_len)))
					continue;

				if (!priv_getdns_dname_is_subdomain(sign_name, rr_name))
					continue;

				rrsigs_found++;
				launch_chain_link_lookup(chain, sign_name);
			}
			if (rrsigs_found)
				continue;

			find_delegation_point(chain, rr_name);
		}
	}
	chain->lock--;
	callback_on_complete_chain(chain);
}


void priv_getdns_get_validation_chain(getdns_dns_req *dns_req)
{
	get_val_chain(dns_req);
	//getdns_get_validation_chain(dns_req, NULL);
}

/********************** functions for validate_dnssec *************************/

static getdns_return_t
priv_getdns_create_rr_from_dict(getdns_dict *rr_dict, ldns_rr **rr)
{
	gldns_buffer buf;
	uint8_t space[8192], *xspace = NULL;
	size_t xsize, pos = 0;
	ldns_status s;
	getdns_return_t r;

	gldns_buffer_init_frm_data(&buf, space, sizeof(space));
	if ((r = priv_getdns_rr_dict2wire(rr_dict, &buf)))
		return r;

	if ((xsize = gldns_buffer_position(&buf)) > sizeof(space)) {
		if (!(xspace = GETDNS_XMALLOC(rr_dict->mf, uint8_t, xsize)))
			return GETDNS_RETURN_MEMORY_ERROR;

		gldns_buffer_init_frm_data(&buf, xspace, xsize);
		if ((r = priv_getdns_rr_dict2wire(rr_dict, &buf))) {
			GETDNS_FREE(rr_dict->mf, xspace);
			return r;
		}
	}
	s = ldns_wire2rr(rr, gldns_buffer_begin(&buf),
	    gldns_buffer_position(&buf), &pos, GLDNS_SECTION_ANSWER);
	if (xspace)
		GETDNS_FREE(rr_dict->mf, xspace);
	return s ? GETDNS_RETURN_GENERIC_ERROR : GETDNS_RETURN_GOOD;
}
	
static getdns_return_t
priv_getdns_rr_list_from_list(getdns_list *list, ldns_rr_list **rr_list)
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

static int
ldns_dname_compare_v(const void *a, const void *b) {
	return ldns_dname_compare((ldns_rdf *)a, (ldns_rdf *)b);
}

ldns_status
priv_getdns_ldns_dnssec_zone_add_rr(ldns_dnssec_zone *zone, ldns_rr *rr)
{
	ldns_dnssec_name *new_name;
	ldns_rbnode_t *new_node;

	if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_NSEC3)
		return ldns_dnssec_zone_add_rr(zone, rr);
	
	if (!(new_name = ldns_dnssec_name_new()))
		return LDNS_STATUS_MEM_ERR;

	new_name->name = ldns_rdf_clone(ldns_rr_owner(rr));
	new_name->hashed_name = ldns_dname_label(ldns_rr_owner(rr), 0);
	new_name->name_alloced = true;

	if (!(new_node = LDNS_MALLOC(ldns_rbnode_t))) {
		ldns_dnssec_name_free(new_name);
		return LDNS_STATUS_MEM_ERR;
	}
	new_node->key = new_name->name;
	new_node->data = new_name;
	if (!zone->names)
		zone->names = ldns_rbtree_create(ldns_dname_compare_v);
	(void)ldns_rbtree_insert(zone->names, new_node);

#ifdef LDNS_DNSSEC_ZONE_HASHED_NAMES
	if (!(new_node = LDNS_MALLOC(ldns_rbnode_t))) {
		ldns_dnssec_name_free(new_name);
		return LDNS_STATUS_MEM_ERR;
	}
	new_node->key = new_name->hashed_name;
	new_node->data = new_name;
	if (!zone->hashed_names) {
		zone->_nsec3params = rr;
		zone->hashed_names = ldns_rbtree_create(ldns_dname_compare_v);
	}
	(void)ldns_rbtree_insert(zone->hashed_names, new_node);
#endif

	return ldns_dnssec_zone_add_rr(zone, rr);
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

		if ((s = priv_getdns_ldns_dnssec_zone_add_rr(*zone, rr))) {
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

	ldns_dnssec_rrsets nsec_rrset;
	ldns_dnssec_rrs    nsec_rrs;
} zone_iter;

static void
rrset_iter_init_zone(zone_iter *i, ldns_dnssec_zone *zone)
{	
	ldns_dnssec_name *name;
	assert(i);

	i->zone = zone;
	if ((i->cur_node = zone->names
	                 ? ldns_rbtree_first(zone->names)
	                 : LDNS_RBTREE_NULL) == LDNS_RBTREE_NULL) {

		i->cur_rrset = NULL;
		return;
	}

	i->cur_rrset = ((ldns_dnssec_name *)i->cur_node->data)->rrsets;
	if (!i->cur_rrset) {
		name = ((ldns_dnssec_name *)i->cur_node->data);
		if (name->nsec && name->nsec_signatures) {
			i->cur_rrset = &i->nsec_rrset;
			i->nsec_rrset.rrs = &i->nsec_rrs;
			i->nsec_rrs.rr = name->nsec;
			i->nsec_rrs.next = NULL;
			i->nsec_rrset.type = ldns_rr_get_type(name->nsec);
			i->nsec_rrset.signatures =
				name->nsec_signatures;
			i->nsec_rrset.next = NULL;
			return;
		}
	}
}

static ldns_dnssec_rrsets *
_rrset_iter_value(zone_iter *i)
{
	assert(i);

	return i->cur_rrset;
}

static void
_rrset_iter_next(zone_iter *i)
{
	int was_nsec_rrset;
	ldns_dnssec_name *name;
	assert(i);

	if (! i->cur_rrset)
		return;

	was_nsec_rrset = (i->cur_rrset == &i->nsec_rrset);
	if (!  (i->cur_rrset = i->cur_rrset->next)) {

		if (!was_nsec_rrset) {
			name = ((ldns_dnssec_name *)i->cur_node->data);
			if (name->nsec && name->nsec_signatures) {
				i->cur_rrset = &i->nsec_rrset;
				i->nsec_rrset.rrs = &i->nsec_rrs;
				i->nsec_rrs.rr = name->nsec;
				i->nsec_rrs.next = NULL;
				i->nsec_rrset.type = ldns_rr_get_type(name->nsec);
				i->nsec_rrset.signatures =
					name->nsec_signatures;
				i->nsec_rrset.next = NULL;
				return;
			}
		}
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
#if 0
	if (s != 0) {
		fprintf(stderr, "verify status %d\nrrset: ", s);
		ldns_rr_list_print(stderr, rrset);
		fprintf(stderr, "\nsigs: ");
		ldns_rr_list_print(stderr, sigs);
		fprintf(stderr, "\nkeys: ");
		ldns_rr_list_print(stderr, keys);
		fprintf(stderr, "\n\n");
	}
#endif
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
			/* No DS found, try one of the other keys */
			if (! rrs)
				continue;
		}
		/* Pursue the chase with the verifying key (or its DS)
		 * and we're done.
		 */
		s = chase(key_rrset, support, support_keys, trusted);
		break;
	}
	if (i == ldns_rr_list_rr_count(verifying_keys))
		s = LDNS_STATUS_CRYPTO_NO_DNSKEY;
done_free_verifying_keys:
	ldns_rr_list_free(verifying_keys);
	return s;
}

/*
 * getdns_validate_dnssec
 *
 */
getdns_return_t
getdns_validate_dnssec(getdns_list *records_to_validate,
    getdns_list *support_records,
    getdns_list *trust_anchors)
{
	getdns_return_t r;
	ldns_rr_list     *trusted;
	ldns_dnssec_zone *support;
	ldns_rr_list     *support_keys;
	ldns_dnssec_zone *to_validate;
	zone_iter i;
	ldns_dnssec_rrsets *rrset;
	ldns_dnssec_rrs *rrs;
	ldns_status s = LDNS_STATUS_ERR;

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
	    (rrset = _rrset_iter_value(&i)); _rrset_iter_next(&i))

		if (ldns_dnssec_rrsets_type(rrset) == LDNS_RR_TYPE_DS ||
		    ldns_dnssec_rrsets_type(rrset) == LDNS_RR_TYPE_DNSKEY)

			for (rrs = rrset->rrs; rrs; rrs = rrs->next)
				(void) ldns_rr_list_push_rr(
				    support_keys, rrs->rr);

	/* Now walk through the rrsets to validate */
	for (rrset_iter_init_zone(&i, to_validate);
	    (rrset = _rrset_iter_value(&i)); _rrset_iter_next(&i)) {

		if ((s = chase(rrset, support, support_keys, trusted)))
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
priv_getdns_parse_ta_file(time_t *ta_mtime, getdns_list *ta_rrs)
{

	struct gldns_file_parse_state pst;
	struct stat st;
	struct {
		uint16_t id;
		uint16_t flags;
		uint16_t qdcount;
		uint16_t ancount;
		uint16_t nscount;
		uint16_t arcount;
		uint8_t rr[8192]; /* Reasonable max size for a single RR */
	} pkt;
	size_t len, dname_len;
	FILE *in;
	priv_getdns_rr_iter rr_iter;
	getdns_dict *rr_dict = NULL;
	int ta_count = 0;

	if (stat(TRUST_ANCHOR_FILE, &st) != 0)
		return 0;

	if (ta_mtime)
		*ta_mtime = st.st_mtime;

	if (!(in = fopen(TRUST_ANCHOR_FILE, "r")))
		return 0;

	pkt.id = pkt.flags = pkt.qdcount = pkt.nscount = pkt.arcount = 0;
	pkt.ancount = htons(1);

	memset(&pst, 0, sizeof(pst));
	pst.default_ttl = 3600;
	pst.lineno = 1;

	while (!feof(in)) {
		len = sizeof(pkt.rr);
		dname_len = 0;
		if (gldns_fp2wire_rr_buf(in, pkt.rr, &len, &dname_len, &pst))
			break;
		if (len == 0)  /* empty, $TTL, $ORIGIN */
			continue;
		if (gldns_wirerr_get_type(pkt.rr, len, dname_len) 
		    != LDNS_RR_TYPE_DS &&
		    gldns_wirerr_get_type(pkt.rr, len, dname_len)
		    != LDNS_RR_TYPE_DNSKEY)
			continue;
		if (!priv_getdns_rr_iter_init(&rr_iter, (void *)&pkt, sizeof(pkt)))
			break;
		if (!(rr_dict = priv_getdns_rr_iter2rr_dict(NULL, &rr_iter)))
			break;
		if (ta_rrs && getdns_list_append_dict(ta_rrs, rr_dict))
			break;
		getdns_dict_destroy(rr_dict);
		rr_dict = NULL;
		ta_count++;
	}
	if (rr_dict)
		getdns_dict_destroy(rr_dict);
	fclose(in);

	return ta_count;
}

getdns_list *
getdns_root_trust_anchor(time_t *utc_date_of_anchor)
{
	getdns_list *ta_rrs = getdns_list_create();
	(void) priv_getdns_parse_ta_file(utc_date_of_anchor, ta_rrs);
	return ta_rrs;
}

/* dnssec.c */
