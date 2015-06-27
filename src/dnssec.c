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
#include "gldns/keyraw.h"
#include "gldns/parseutil.h"
#include "general.h"
#include "dict.h"

/* subdomain is same or parent of domain */
static int is_subdomain(
    const uint8_t * const subdomain, const uint8_t *domain)
{
	while (*domain) {
		if (priv_getdns_dname_equal(subdomain, domain))
			return 1;

		domain += *domain + 1;
	}
	return *subdomain == 0;
}

static void _getdns_list2wire(gldns_buffer *buf, getdns_list *l)
{
	getdns_dict *rr_dict;
	getdns_return_t r;
	size_t i, pkt_start, ancount;
	uint32_t qtype, qclass;
	getdns_bindata *qname;

	pkt_start = gldns_buffer_position(buf);
	/* Empty header */
	gldns_buffer_write_u32(buf, 0);
	gldns_buffer_write_u32(buf, 0);
	gldns_buffer_write_u32(buf, 0);

	for ( i = 0
	    ; (r = getdns_list_get_dict(l, i, &rr_dict))
	          != GETDNS_RETURN_NO_SUCH_LIST_ITEM
	    ; i++ ) {

		if (r) {
			if (r == GETDNS_RETURN_WRONG_TYPE_REQUESTED)
				continue;
			else
				break;
		}
		if (getdns_dict_get_int(rr_dict, "qtype", &qtype) ||
		    getdns_dict_get_bindata(rr_dict, "qname", &qname))
			continue;
		(void) getdns_dict_get_int(rr_dict, "qclass", &qclass);
		gldns_buffer_write(buf, qname->data, qname->size);
		gldns_buffer_write_u16(buf, (uint16_t)qtype);
		gldns_buffer_write_u16(buf, (uint16_t)qclass);
		gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_QDCOUNT_OFF, 1);
		break;
	}
	for ( i = 0, ancount = 0
	    ; (r = getdns_list_get_dict(l, i, &rr_dict))
	          != GETDNS_RETURN_NO_SUCH_LIST_ITEM
	    ; i++ ) {

		if (r) {
			if (r == GETDNS_RETURN_WRONG_TYPE_REQUESTED)
				continue;
			else
				break;
		}
		if (priv_getdns_rr_dict2wire(rr_dict, buf) == GETDNS_RETURN_GOOD)
			ancount++;
	}
	gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_ANCOUNT_OFF, ancount);
}

#if defined(SEC_DEBUG) && SEC_DEBUG
inline static void debug_sec_print_rr(const char *msg, priv_getdns_rr_iter *rr)
{
	char str_spc[8192], *str = str_spc;
	size_t str_len = sizeof(str_spc);
	uint8_t *data = rr->pos;
	size_t data_len = rr->nxt - rr->pos;

	if (!rr || !rr->pos) {
		DEBUG_SEC("%s<nil>\n", msg);
		return;
	}
	(void) gldns_wire2str_rr_scan(
	    &data, &data_len, &str, &str_len, rr->pkt, rr->pkt_end - rr->pkt);
	DEBUG_SEC("%s%s", msg, str_spc);
}
inline static void debug_sec_print_dname(const char *msg, uint8_t *label)
{
	char str[1024];

	if (label && gldns_wire2str_dname_buf(label, 256, str, sizeof(str)))
		DEBUG_SEC("%s%s\n", msg, str);
	else
		DEBUG_SEC("%s<nil>\n", msg);
}
inline static void debug_sec_print_pkt(const char *msg, uint8_t *pkt, size_t pkt_len)
{
	char *str;
	DEBUG_SEC("%s%s\n", msg, (str = gldns_wire2str_pkt(pkt, pkt_len)));
	if (str) free(str);
}
#else
#define debug_sec_print_rr(...) DEBUG_OFF(__VA_ARGS__)
#define debug_sec_print_dname(...) DEBUG_OFF(__VA_ARGS__)
#define debug_sec_print_pkt(...) DEBUG_OFF(__VA_ARGS__)
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
	uint8_t  *name;
	uint16_t  rr_class;
	uint16_t  rr_type;
	uint8_t  *pkt;
	size_t    pkt_len;
	uint8_t   name_spc[];
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
	    priv_getdns_rr_iter_init(&i->rr_i, rrset->pkt, rrset->pkt_len ),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

inline static int rrset_has_rrs(getdns_rrset *rrset)
{
	rrtype_iter rr_spc;
	return rrtype_iter_init(&rr_spc, rrset) != NULL;
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
	    priv_getdns_rr_iter_init(&i->rr_i, rrset->pkt, rrset->pkt_len),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

inline static int rrset_has_rrsigs(getdns_rrset *rrset)
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

static rrset_iter *rrset_iter_init(rrset_iter *i, uint8_t *pkt, size_t pkt_len)
{
	priv_getdns_rr_iter *rr;

	i->rrset.name = i->name_spc;
	i->rrset.pkt = pkt;
	i->rrset.pkt_len = pkt_len;
	i->name_len = 0;

	for ( rr = priv_getdns_rr_iter_init(&i->rr_i, pkt, pkt_len)
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

static rrset_iter *rrset_iter_rewind(rrset_iter *i)
{
	return rrset_iter_init(i, i->rrset.pkt, i->rrset.pkt_len);
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

/* ------------------------------------------------------------------------- */

typedef struct chain_head chain_head;
typedef struct chain_node chain_node;

struct chain_head {
	struct mem_funcs  my_mf;

	chain_head         *next;
	chain_node         *parent;
	size_t              node_count; /* Number of nodes attached directly
	                                 * to this head.  For cleaning.  */
	getdns_network_req *netreq;
	getdns_rrset        rrset;
	uint8_t             name_spc[];
};

struct chain_node {
	chain_node  *parent;
	
	getdns_network_req *dnskey_req;
	getdns_rrset        dnskey;
	getdns_network_req *ds_req;
	getdns_rrset        ds;
	getdns_network_req *soa_req;

	chain_head  *chains;
};

inline static size_t _dname_len(uint8_t *name)
{
	uint8_t *p;
	for (p = name; *p; p += *p + 1);
	return p - name + 1;
}

inline static size_t _dname_label_count(uint8_t *name)
{
	size_t c;
	for (c = 0; *name; name += *name + 1, c++);
	return c;
}

#ifdef STUB_NATIVE_DNSSEC
static int key_matches_signer(getdns_rrset *dnskey, getdns_rrset *rrset)
{
	rrtype_iter rr_spc, *rr;
	rrsig_iter rrsig_spc, *rrsig;
	uint16_t keytag;
	priv_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len = sizeof(signer_spc);

	assert(dnskey->rr_type == GETDNS_RRTYPE_DNSKEY);


	for ( rr = rrtype_iter_init(&rr_spc, dnskey)
	    ; rr ; rr = rrtype_iter_next(rr) ) {

		keytag = gldns_calc_keytag_raw(rr->rr_i.rr_type + 10,
				rr->rr_i.nxt - rr->rr_i.rr_type - 10);

		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
		    ; rrsig ; rrsig = rrsig_iter_next(rrsig) ) {

			if (/* Space for keytag & signer in rrsig rdata? */
			       rrsig->rr_i.nxt >= rrsig->rr_i.rr_type + 28

			    /* Does the keytag match? */
			    && gldns_read_uint16(rrsig->rr_i.rr_type + 26)
					    == keytag

			    /* Does the signer name match? */
			    && (rdf = priv_getdns_rdf_iter_init_at(
					    &rdf_spc, &rrsig->rr_i, 7))

			    && (signer = priv_getdns_rdf_if_or_as_decompressed(
					    rdf, signer_spc, &signer_len))

			    && priv_getdns_dname_equal(dnskey->name, signer))

				return 1;
		}
	}
	return 0;
}

static ldns_rr *rr2ldns_rr(priv_getdns_rr_iter *rr)
{
	ldns_rr *rr_l;
	size_t pos = rr->pos - rr->pkt;

	if (ldns_wire2rr(&rr_l, rr->pkt, rr->pkt_end - rr->pkt, &pos,
			priv_getdns_rr_iter_section(rr)) == LDNS_STATUS_OK)
		return rr_l;
	else
		return NULL;
}

static ldns_rr_list *rrset2ldns_rr_list(getdns_rrset *rrset)
{
	rrtype_iter rr_spc, *rr;
	ldns_rr_list *rr_list = ldns_rr_list_new();
	ldns_rr *rr_l;

	if (rr_list) {
		for ( rr = rrtype_iter_init(&rr_spc, rrset)
		    ; rr ; rr = rrtype_iter_next(rr) )
			if ((rr_l = rr2ldns_rr(&rr->rr_i)))
				ldns_rr_list_push_rr(rr_list, rr_l);
	}
	return rr_list;
}


/* Verifies the signature rrsig for rrset rrset with key key.
 * When the rrset was a wildcard expansion (rrsig labels < labels owner name),
 * nc_name will be set to the next closer (within rrset->name).
 */
static int _getdns_verify_rrsig(
    getdns_rrset *rrset, rrsig_iter *rrsig, rrtype_iter *key, uint8_t **nc_name)
{
	ldns_rr_list *rrset_l = rrset2ldns_rr_list(rrset);
	ldns_rr *rrsig_l = rr2ldns_rr(&rrsig->rr_i);
	ldns_rr *key_l = rr2ldns_rr(&key->rr_i);
	int r;
	size_t to_skip;

	/* nc_name should already have been initialized by the parent! */
	assert(nc_name);
	assert(!*nc_name);

	r = rrset_l && rrsig_l && key_l &&
	    ldns_verify_rrsig(rrset_l, rrsig_l, key_l) == LDNS_STATUS_OK;

	ldns_rr_list_deep_free(rrset_l);
	ldns_rr_free(rrsig_l);
	ldns_rr_free(key_l);

	if (!r)
		return 0;

	/* Verification has already been done, so the labels rdata field is
	 * definitely readable
	 */
	assert(rrsig->rr_i.rr_type + 14 <= rrsig->rr_i.nxt);

	/* If the number of labels in the owner name mathes the "labels" rdata
	 * field, then this was not a wildcard expansion, and everything is
	 * good.
	 */
	if ((size_t)rrsig->rr_i.rr_type[13] == _dname_label_count(rrset->name))
		return 1;

	/* This is a valid wildcard expansion.  Calculate and return the 
	 * "Next closer" name, because we need another NSEC to cover it
	 * for wildcards to hold...xi
	 * (except for rrsigs for NSECs, but those are dealt with later)
	 */
	to_skip = _dname_label_count(rrset->name)
		- (size_t)rrsig->rr_i.rr_type[13] - 1;

	for ( *nc_name = rrset->name
	    ; to_skip
	    ; *nc_name += **nc_name + 1, to_skip--);

	return 1;
}

static uint8_t *_getdns_nsec3_hash_label(uint8_t *label, size_t label_len,
    uint8_t *name, uint8_t algorithm, uint16_t iterations, uint8_t *salt)
{
	ldns_rdf name_l = { _dname_len(name), LDNS_RDF_TYPE_DNAME, name };
	ldns_rdf *hname_l;
	
	if (!(hname_l = ldns_nsec3_hash_name(
	    &name_l, algorithm, iterations, *salt, salt + 1)))
		return NULL;

	if (   label_len < hname_l->_size-1 
	    || label_len < *((uint8_t *)hname_l->_data) + 1
	    || hname_l->_size-1 < *((uint8_t *)hname_l->_data) + 1) {
		ldns_rdf_deep_free(hname_l);
		return NULL;
	}
	memcpy(label, hname_l->_data,  *((uint8_t *)hname_l->_data) + 1);
	ldns_rdf_deep_free(hname_l);
	return label;
}

static int dnskey_signed_rrset(
    rrtype_iter *dnskey, getdns_rrset *rrset, uint8_t **nc_name)
{
	rrsig_iter rrsig_spc, *rrsig;
	priv_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len = sizeof(signer_spc);
	uint16_t keytag;

	assert(dnskey->rrset->rr_type == GETDNS_RRTYPE_DNSKEY);
	assert(nc_name);

	*nc_name = NULL;

	keytag = gldns_calc_keytag_raw(dnskey->rr_i.rr_type + 10,
			dnskey->rr_i.nxt - dnskey->rr_i.rr_type - 10);

	for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
	    ; rrsig ; rrsig = rrsig_iter_next(rrsig) ) {

		if (/* Space for keytag & signer in rrsig rdata? */
		        rrsig->rr_i.nxt >= rrsig->rr_i.rr_type + 28

		    /* Does the keytag match? */
		    && gldns_read_uint16(rrsig->rr_i.rr_type + 26) == keytag

		    /* Does the signer name match? */
		    && (rdf = priv_getdns_rdf_iter_init_at(
				    &rdf_spc, &rrsig->rr_i, 7))

		    && (signer = priv_getdns_rdf_if_or_as_decompressed(
				    rdf, signer_spc, &signer_len))

		    && priv_getdns_dname_equal(dnskey->rrset->name, signer)
		    
		    /* Does the signature verify? */
		    && _getdns_verify_rrsig(rrset, rrsig, dnskey, nc_name)) {

			debug_sec_print_rr("key ", &dnskey->rr_i);
			debug_sec_print_rrset("signed ", rrset);

			return 1;
		}
	}
	return 0;
}

static int find_nsec_covering_name(
    getdns_rrset *dnskey, getdns_rrset *rrset, uint8_t *name);

static int a_key_signed_rrset(getdns_rrset *keyset, getdns_rrset *rrset)
{
	rrtype_iter dnskey_spc, *dnskey;
	uint8_t *nc_name;

	assert(keyset->rr_type == GETDNS_RRTYPE_DNSKEY);

	for ( dnskey = rrtype_iter_init(&dnskey_spc, keyset)
	    ; dnskey ; dnskey = rrtype_iter_next(dnskey) ) {

		if (!dnskey_signed_rrset(dnskey, rrset, &nc_name))
			continue;

		if (!nc_name) /* Not a wildcard, then success! */
			return 1;

		/* Wildcard RRSIG for a NSEC on the wildcard.
		 * There is no more specific!
		 */
		if (rrset->rr_type == GETDNS_RRTYPE_NSEC &&
		    rrset->name[0] == 1 && rrset->name[1] == '*')
			return 1;

		debug_sec_print_rrset("wildcard expanded to: ", rrset);
		debug_sec_print_dname("Find NSEC covering the more sepecific: "
				, nc_name);

		if (find_nsec_covering_name(keyset, rrset, nc_name))
			return 1;
	}
	return 0;
}

static int ds_authenticates_keys(getdns_rrset *ds_set, getdns_rrset *dnskey_set)
{
	rrtype_iter dnskey_spc, *dnskey;
	rrtype_iter ds_spc, *ds;
	uint16_t keytag;
	uint8_t *nc_name;
	ldns_rr *dnskey_l;
	ldns_rr *ds_l = NULL;

	assert(ds_set->rr_type == GETDNS_RRTYPE_DS);
	assert(dnskey_set->rr_type == GETDNS_RRTYPE_DNSKEY);

	if (!priv_getdns_dname_equal(ds_set->name, dnskey_set->name))
		return 0;

	for ( dnskey = rrtype_iter_init(&dnskey_spc, dnskey_set)
	    ; dnskey ; dnskey = rrtype_iter_next(dnskey)) {

		keytag = gldns_calc_keytag_raw(dnskey->rr_i.rr_type + 10,
				dnskey->rr_i.nxt - dnskey->rr_i.rr_type - 10);

		dnskey_l = NULL;

		for ( ds = rrtype_iter_init(&ds_spc, ds_set)
		    ; ds ; ds = rrtype_iter_next(ds)) {

			if (/* Space for keytag & signer in rrsig rdata? */
			       ds->rr_i.nxt < ds->rr_i.rr_type + 12

			    /* Does the keytag match? */
			    || gldns_read_uint16(ds->rr_i.rr_type+10)!=keytag)
				continue;

			if (!dnskey_l)
				if (!(dnskey_l = rr2ldns_rr(&dnskey->rr_i)))
					continue;

			if (!(ds_l = rr2ldns_rr(&ds->rr_i)))
				continue;

			if (!ldns_rr_compare_ds(ds_l, dnskey_l)) {
				ldns_rr_free(ds_l);
				ds_l = NULL;
				continue;
			}
			ldns_rr_free(dnskey_l);

			if (dnskey_signed_rrset(dnskey, dnskey_set, &nc_name)
			    && !nc_name /* No DNSKEY's on wildcards! */) {

				debug_sec_print_rrset(
				    "keyset authenticated: ", dnskey_set);
				return 1;
			}
			debug_sec_print_rrset(
			    "keyset failed authentication: ", dnskey_set);

			return 0;
		}
		ldns_rr_free(dnskey_l);
	}
	return 0;
}

static int bitmap_contains_rrtype(priv_getdns_rdf_iter *bitmap, uint16_t rr_type)
{
	uint8_t *dptr, *dend;
	uint8_t window  = rr_type >> 8;
	uint8_t subtype = rr_type & 0xFF;

	DEBUG_SEC("bitmap: %p, type: %d\n", bitmap, (int)rr_type);
	if (!bitmap)
		return 0;
	dptr = bitmap->pos;
	dend = bitmap->nxt;

	/* Type Bitmap = ( Window Block # | Bitmap Length | Bitmap ) +
	 *                 dptr[0]          dptr[1]         dptr[2:]
	 */
	while (dptr < dend && dptr[0] <= window) {
		if (dptr[0] == window && subtype / 8 < dptr[1] &&
		    dptr + dptr[1] + 2 <= dend)
			return  dptr[2 + subtype / 8] & (0x80 >> (subtype % 8));
		dptr += dptr[1] + 2; /* next window */
	}
	return 0;
}

static int nsec_bitmap_excludes_rrtype(getdns_rrset *nsec_rrset, uint16_t rr_type)
{
	rrtype_iter nsec_space, *nsec_rr;
	priv_getdns_rdf_iter bitmap_spc, *bitmap;

	return (nsec_rrset->rr_type == GETDNS_RRTYPE_NSEC ||
	        nsec_rrset->rr_type == GETDNS_RRTYPE_NSEC3 )
	    && (nsec_rr = rrtype_iter_init(&nsec_space, nsec_rrset))
	    && (bitmap = priv_getdns_rdf_iter_init_at(&bitmap_spc, &nsec_rr->rr_i,
			nsec_rrset->rr_type == GETDNS_RRTYPE_NSEC ? 1: 5))
	    && !bitmap_contains_rrtype(bitmap, rr_type);

	return 0;
}

static uint8_t **reverse_labels(uint8_t *dname, uint8_t **labels)
{
	if (*dname)
		labels = reverse_labels(dname + *dname + 1, labels);
	*labels = dname;
	return labels + 1;
}

static uint8_t *dname_shared_parent(uint8_t *left, uint8_t *right)
{
	uint8_t *llabels[128], *rlabels[128], **last_llabel, **last_rlabel,
		**llabel, **rlabel, *l, *r, sz;

	last_llabel = reverse_labels(left, llabels);
	last_rlabel = reverse_labels(right, rlabels);

	for ( llabel = llabels, rlabel = rlabels
	    ; llabel < last_llabel
	    ; llabel++, rlabel++ ) {

		if (   rlabel == last_rlabel 
		    || (sz = **llabel) != **rlabel)
			return llabel[-1];

		for (l = *llabel+1, r = *rlabel+1; sz; l++, r++, sz-- ) 
			if (*l != *r && tolower((unsigned char)*l) !=
					tolower((unsigned char)*r))
				return llabel[-1];
	}
	return llabel[-1];
}

static int dname_compare(uint8_t *left, uint8_t *right)
{
	uint8_t *llabels[128], *rlabels[128], **last_llabel, **last_rlabel,
		**llabel, **rlabel, *l, *r, lsz, rsz;

	last_llabel = reverse_labels(left, llabels);
	last_rlabel = reverse_labels(right, rlabels);

	for ( llabel = llabels, rlabel = rlabels
	    ; llabel < last_llabel
	    ; llabel++, rlabel++ ) {

		if (rlabel == last_rlabel)
			return 1;

		for ( l = *llabel, lsz = *l++, r = *rlabel, rsz = *r++
		    ; lsz; l++, r++, lsz--, rsz-- ) {

			if (!rsz)
				return 1;
			if (*l != *r && tolower((unsigned char)*l) !=
					tolower((unsigned char)*r)) {
				if (tolower((unsigned char)*l) <
				    tolower((unsigned char)*r))
					return -1;
				return 1;
			}
		}
	}
	return rlabel == last_rlabel ? 0 : -1;
}

static int nsec_covers_name(
    getdns_rrset *nsec, uint8_t *name, uint8_t **ce_name)
{
	uint8_t owner_spc[256], *owner;
	size_t owner_len = sizeof(owner_spc);
	uint8_t next_spc[256], *next;
	size_t next_len = sizeof(next_spc);
	rrtype_iter rr_spc, *rr;
	priv_getdns_rdf_iter rdf_spc, *rdf;
	int nsec_cmp;
	uint8_t *common1, *common2;

	if (   !(rr = rrtype_iter_init(&rr_spc, nsec))
	    || !(rdf = priv_getdns_rdf_iter_init(&rdf_spc, &rr->rr_i))
	    || !(owner = priv_getdns_owner_if_or_as_decompressed(
			    &rr->rr_i, owner_spc, &owner_len))
	    || !(next = priv_getdns_rdf_if_or_as_decompressed(
			    rdf, next_spc, &next_len)))
		return 0;

	debug_sec_print_dname("nsec owner: ", owner);
	debug_sec_print_dname("name      : ", name);
	debug_sec_print_dname("nsec next : ", next);

	if (ce_name) {
		common1 = dname_shared_parent(name, owner);
		common2 = dname_shared_parent(name, next);
		*ce_name = _dname_label_count(common1)
		         > _dname_label_count(common2) ? common1 : common2;
		debug_sec_print_dname("nsec closest encloser: ", *ce_name);
	}

	nsec_cmp = dname_compare(owner, next);
	if (nsec_cmp < 0) {
		DEBUG_SEC("nsec owner < next\n");
		return dname_compare(name, owner) >= 0
		    && dname_compare(name, next)  <  0;
	} else if (nsec_cmp > 0) {
		/* The wrap around nsec */
		DEBUG_SEC("nsec owner > next\n");
		return dname_compare(name, owner) >= 0;
	} else {
		DEBUG_SEC("nsec owner == next\n");
		return 1;
	}
}

static uint8_t *name2nsec3_label(
    getdns_rrset *nsec3, uint8_t *name, uint8_t *label, size_t label_len)
{
	rrsig_iter rrsig_spc, *rrsig;
	priv_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len = sizeof(signer_spc);
	rrtype_iter rr_spc, *rr;

	if (/* With the "first" signature */
	       (rrsig = rrsig_iter_init(&rrsig_spc, nsec3))

	    /* Access the signer name rdata field (7th) */
	    && (rdf = priv_getdns_rdf_iter_init_at(
			    &rdf_spc, &rrsig->rr_i, 7))

	    /* Verify & decompress */
	    && (signer = priv_getdns_rdf_if_or_as_decompressed(
			    rdf, signer_spc, &signer_len))

	    /* signer of the NSEC3 is direct parent for this NSEC3? */
	    && priv_getdns_dname_equal(
		    signer, nsec3->name + *nsec3->name + 1)

	    /* signer of the NSEC3 is parent of name? */
	    && is_subdomain(signer, name)

	    /* Initialize rr for getting NSEC3 rdata fields */
	    && (rr = rrtype_iter_init(&rr_spc, nsec3))
	    
	    /* Check for available space to get rdata fields */
	    && rr->rr_i.rr_type + 15 <= rr->rr_i.nxt
	    && rr->rr_i.rr_type + 14 + rr->rr_i.rr_type[14] <= rr->rr_i.nxt)

		/* Get the hashed label */
		return _getdns_nsec3_hash_label(label, label_len, name,
			    rr->rr_i.rr_type[10],
			    gldns_read_uint16(rr->rr_i.rr_type + 12),
			    rr->rr_i.rr_type + 14);
	return NULL;
}

static int nsec3_matches_name(getdns_rrset *nsec3, uint8_t *name)
{
	uint8_t label[64];

	if (name2nsec3_label(nsec3, name, label, sizeof(label)))

		return *nsec3->name == label[0] /* Labels same size? */
		    && memcmp(nsec3->name + 1, label + 1, label[0]) == 0;

	return 0;
}

static int nsec3_covers_name(getdns_rrset *nsec3, uint8_t *name)
{
	uint8_t label[65], next[65], owner[65];
	rrtype_iter rr_spc, *rr;
	priv_getdns_rdf_iter rdf_spc, *rdf;
	int nsz = 0, nsec_cmp;

	if (!name2nsec3_label(nsec3, name, label, sizeof(label)-1))
		return 0;
	label[label[0]+1] = 0;

	if (   !(rr = rrtype_iter_init(&rr_spc, nsec3))
	    || !(rdf = priv_getdns_rdf_iter_init_at(&rdf_spc, &rr->rr_i, 4))
	    || rdf->pos + *rdf->pos + 1 > rdf->nxt
	    || (nsz = gldns_b32_ntop_extended_hex(rdf->pos + 1, *rdf->pos,
		    (char *)next + 1, sizeof(next)-2)) < 0
	    || *nsec3->name > sizeof(owner) - 2
	    || !memcpy(owner, nsec3->name, *nsec3->name + 1)) {

		DEBUG_SEC("Error getting NSEC3 owner & next labels\n");
		return 0;
	}
	owner[owner[0]+1] = 0;
	next[(next[0] = (uint8_t)nsz)+1] = 0;

	debug_sec_print_dname("NSEC3 for: ", name);
	debug_sec_print_dname("       is: ", label);
	debug_sec_print_dname("inbetween: ", owner);
	debug_sec_print_dname("      and: ", next);

	nsec_cmp = dname_compare(owner, next);
	if (nsec_cmp < 0) {
		DEBUG_SEC("nsec owner < next\n");
		return dname_compare(label, owner) >= 0
		    && dname_compare(label, next)  <  0;
	} else if (nsec_cmp > 0) {
		/* The wrap around nsec */
		DEBUG_SEC("nsec owner > next\n");
		return dname_compare(label, owner) >= 0;
	} else {
		DEBUG_SEC("nsec owner == next\n");
		return 1;
	}
}

static int find_nsec_covering_name(
    getdns_rrset *dnskey, getdns_rrset *rrset, uint8_t *name)
{
	rrset_iter i_spc, *i;
	getdns_rrset *n;

	for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
	    ; i ; i = rrset_iter_next(i)) {

		if ((n = rrset_iter_value(i))->rr_type == GETDNS_RRTYPE_NSEC3
		    && nsec3_covers_name(n, name)
		    && a_key_signed_rrset(dnskey, n)) {

			debug_sec_print_rrset("NSEC3:   ", n);
			debug_sec_print_dname("covered: ", name);

			return 1;
		}
		if ((n = rrset_iter_value(i))->rr_type == GETDNS_RRTYPE_NSEC
		    && nsec_covers_name(n, name, NULL)
		    && a_key_signed_rrset(dnskey, n)) {

			debug_sec_print_rrset("NSEC:   ", n);
			debug_sec_print_dname("covered: ", name);

			return 1;
		}
	}
	return 0;
}

static int nsec3_find_next_closer(
    getdns_rrset *dnskey, getdns_rrset *rrset, uint8_t *nc_name)
{
	uint8_t wc_name[256] = { 1, (uint8_t)'*' };

	if (!find_nsec_covering_name(dnskey, rrset, nc_name))
		return 0;

	/* Wild card not needed on a "covering" * NODATA response,
	 * because of opt-out?
	 */
	if (GLDNS_RCODE_WIRE(rrset->pkt) == GETDNS_RCODE_NOERROR)
		return 1;

	nc_name += *nc_name + 1;
	(void) memcpy(wc_name + 2, nc_name, _dname_len(nc_name));

	return find_nsec_covering_name(dnskey, rrset, wc_name);
}

static int key_proves_nonexistance(getdns_rrset *dnskey, getdns_rrset *rrset)
{
	getdns_rrset nsec_rrset, *cover, *ce;
	rrset_iter i_spc, *i;
	uint8_t *ce_name, *nc_name;
	uint8_t wc_name[256] = { 1, (uint8_t)'*' };

	assert(dnskey->rr_type == GETDNS_RRTYPE_DNSKEY);

	/* The NSEC NODATA case
	 * ====================
	 * NSEC has same ownername as the rrset to deny.
	 * Only the rr_type is missing from the bitmap.
	 */
	nsec_rrset = *rrset;
	nsec_rrset.rr_type = GETDNS_RRTYPE_NSEC;
	if (nsec_bitmap_excludes_rrtype(&nsec_rrset, rrset->rr_type) &&
	    a_key_signed_rrset(dnskey, &nsec_rrset)) {

		debug_sec_print_rrset("NSEC NODATA proof for: ", rrset);
		return 1;
	}

	/* The NSEC Name error case
	 * ========================
	 * - First find the NSEC that covers the owner name.
	 */
	for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
	    ; i ; i = rrset_iter_next(i)) {

		if ((cover=rrset_iter_value(i))->rr_type != GETDNS_RRTYPE_NSEC
		    || !nsec_covers_name(cover, rrset->name, &ce_name)
		    || !a_key_signed_rrset(dnskey, cover))
			continue;

		debug_sec_print_dname("Closest Encloser: ", ce_name);
		memcpy(wc_name + 2, ce_name, _dname_len(ce_name));
		debug_sec_print_dname("        Wildcard: ", wc_name);

		return find_nsec_covering_name(dnskey, rrset, wc_name);
	}

	/* The NSEC3 NODATA case
	 * =====================
	 * NSEC3 has same (hashed) ownername as the rrset to deny.
	 * Only the rr_type (and CNAME) is missing from the bitmap.
	 */
	for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
	    ; i ; i = rrset_iter_next(i)) {

		if ((ce = rrset_iter_value(i))->rr_type == GETDNS_RRTYPE_NSEC3
		    && nsec_bitmap_excludes_rrtype(ce, rrset->rr_type)
		    && nsec_bitmap_excludes_rrtype(ce, GETDNS_RRTYPE_CNAME)
		    && nsec3_matches_name(ce, rrset->name)
		    && a_key_signed_rrset(dnskey, ce)) {

			debug_sec_print_rrset("NSEC3 No Data for: ", rrset);
			return 1;
		}
	}
	/* The NSEC3 Name error case
	 * ========================+
	 * First find the closest encloser.
	 */
	for ( nc_name = rrset->name, ce_name = rrset->name + *rrset->name + 1
	    ; *ce_name ; nc_name = ce_name, ce_name += *ce_name + 1) {

		for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
		    ; i ; i = rrset_iter_next(i)) {

			if (   (ce = rrset_iter_value(i))->rr_type
					!= GETDNS_RRTYPE_NSEC3
			    || !nsec3_matches_name(ce, ce_name)
			    || !a_key_signed_rrset(dnskey, ce))
				continue;

			debug_sec_print_rrset("Closest Encloser: ", ce);
			debug_sec_print_dname("Closest Encloser: ", ce_name);
			debug_sec_print_dname("     Next closer: ", nc_name);

			if (nsec3_find_next_closer(dnskey, rrset, nc_name))
				return 1;
		}
	}
	return 0;
}

static int chain_node_get_trusted_keys(
    chain_node *node, getdns_rrset *ta, getdns_rrset **keys)
{
	int s;

	/* Descend down to the root */
	if (! node)
		return GETDNS_DNSSEC_BOGUS;
	
	else if (ta->rr_type == GETDNS_RRTYPE_DS) {
		
		if (ds_authenticates_keys(&node->ds, &node->dnskey)) {
			*keys = &node->dnskey;
			return GETDNS_DNSSEC_SECURE;
		}

	} else if (ta->rr_type == GETDNS_RRTYPE_DNSKEY) {

		/* ta is KSK */
		if (a_key_signed_rrset(ta, &node->dnskey)) {
			*keys = &node->dnskey;
			return GETDNS_DNSSEC_SECURE;
		}
		/* ta is ZSK */
		if (key_proves_nonexistance(ta, &node->ds))
			return GETDNS_DNSSEC_INSECURE;

		if (a_key_signed_rrset(ta, &node->ds)) {
			if (ds_authenticates_keys(&node->ds, &node->dnskey)) {
				*keys = &node->dnskey;
				return GETDNS_DNSSEC_SECURE;
			}
			return GETDNS_DNSSEC_BOGUS;
		}
	} else
		return GETDNS_DNSSEC_BOGUS;

	if (GETDNS_DNSSEC_SECURE != 
	    (s = chain_node_get_trusted_keys(node->parent, ta, keys)))
		return s;

	/* keys is an authenticated dnskey rrset always now (i.e. ZSK) */
	ta = *keys;
	/* Back up to the head */
	if (key_proves_nonexistance(ta, &node->ds))
		return GETDNS_DNSSEC_INSECURE;

	if (key_matches_signer(ta, &node->ds)) {
		if (a_key_signed_rrset(ta, &node->ds) &&
		    ds_authenticates_keys(&node->ds, &node->dnskey)) {

			*keys = &node->dnskey;
			return GETDNS_DNSSEC_SECURE;
		}
		return GETDNS_DNSSEC_BOGUS;
	}
	return GETDNS_DNSSEC_SECURE;
}

static int chain_head_validate_with_ta(chain_head *head, getdns_rrset *ta)
{
	getdns_rrset *keys;
	int s;

	if ((s = chain_node_get_trusted_keys(head->parent, ta, &keys))
	    != GETDNS_DNSSEC_SECURE)
			return s;

	if (rrset_has_rrs(&head->rrset)) {
		if (a_key_signed_rrset(keys, &head->rrset))
			return GETDNS_DNSSEC_SECURE;

	} else if (key_proves_nonexistance(keys, &head->rrset))
		return GETDNS_DNSSEC_SECURE;

	return GETDNS_DNSSEC_BOGUS;
}

static int chain_head_validate(chain_head *head, rrset_iter *tas)
{
	rrset_iter *i;
	getdns_rrset *ta;
	int s = GETDNS_DNSSEC_INDETERMINATE;

	for (i = rrset_iter_rewind(tas); i ;i = rrset_iter_next(i)) {
		ta = rrset_iter_value(i);

		if ((ta->rr_type != GETDNS_RRTYPE_DNSKEY &&
		     ta->rr_type != GETDNS_RRTYPE_DS
		    ) || !is_subdomain(ta->name, head->rrset.name))
			continue;

		/* The best status for any ta counts */
		switch (chain_head_validate_with_ta(head, ta)) {
		case GETDNS_DNSSEC_SECURE  : s = GETDNS_DNSSEC_SECURE;
		case GETDNS_DNSSEC_INSECURE: if (s != GETDNS_DNSSEC_SECURE)
						     s = GETDNS_DNSSEC_INSECURE;
		                             break;
		case GETDNS_DNSSEC_BOGUS   : if (s != GETDNS_DNSSEC_SECURE &&
		                                 s != GETDNS_DNSSEC_INSECURE)
		                                     s = GETDNS_DNSSEC_BOGUS;
		                             break;
		default                    : break;
		}
	}
	return s;
}

static void chain_validate_dnssec(chain_head *chain, rrset_iter *tas)
{
	chain_head *head;

	for (head = chain; head; head = head->next) {
		switch (chain_head_validate(head, tas)) {
		case GETDNS_DNSSEC_SECURE: if (!head->netreq->bogus)
						   head->netreq->secure = 1;
		                           break;
		case GETDNS_DNSSEC_BOGUS : head->netreq->bogus  = 1;
					   head->netreq->secure = 0;
		                           break;
		default                  : break;
		}
	}
}
#endif

static size_t count_outstanding_requests(chain_head *head)
{
	size_t count;
	chain_node *node;

	if (!head)
		return 0;

	for ( node = head->parent, count = 0
	    ; node
	    ; node = node->parent) {

		if (node->dnskey_req &&
		    node->dnskey_req->state != NET_REQ_FINISHED &&
		    node->dnskey_req->state != NET_REQ_CANCELED)
			count++;

		if (node->ds_req &&
		    node->ds_req->state != NET_REQ_FINISHED &&
		    node->ds_req->state != NET_REQ_CANCELED)
			count++;

		if (node->soa_req &&
		    node->soa_req->state != NET_REQ_FINISHED &&
		    node->soa_req->state != NET_REQ_CANCELED)
			count++;
	}
	return count + count_outstanding_requests(head->next);
}

static void append_rrs2val_chain_list(getdns_context *ctxt,
    getdns_list *val_chain_list, getdns_network_req *netreq)
{
	rrset_iter *i, i_spc;
	getdns_rrset *rrset;
	rrtype_iter *rr, rr_spc;
	rrsig_iter  *rrsig, rrsig_spc;
	getdns_dict *rr_dict;

	for ( i = rrset_iter_init(&i_spc,netreq->response,netreq->response_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);

		if (rrset->rr_type != GETDNS_RRTYPE_DNSKEY &&
		    rrset->rr_type != GETDNS_RRTYPE_DS     &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC   &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC3)
			continue;

		for ( rr = rrtype_iter_init(&rr_spc, rrset)
		    ; rr; rr = rrtype_iter_next(rr)) {

			rr_dict = priv_getdns_rr_iter2rr_dict(ctxt, &rr->rr_i);
			if (!rr_dict) continue;

			(void)getdns_list_append_dict(val_chain_list, rr_dict);
			getdns_dict_destroy(rr_dict);
		}
		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
		    ; rrsig; rrsig = rrsig_iter_next(rrsig)) {

			rr_dict=priv_getdns_rr_iter2rr_dict(ctxt,&rrsig->rr_i);
			if (!rr_dict) continue;

			(void)getdns_list_append_dict(val_chain_list, rr_dict);
			getdns_dict_destroy(rr_dict);
		}
	}
}

static void check_chain_complete(chain_head *chain)
{
	getdns_dns_req *dnsreq;
	getdns_context *context;
	size_t o, node_count;
	chain_head *head, *next;
	chain_node *node;
	getdns_list *val_chain_list;
	getdns_dict *response_dict;
#ifdef STUB_NATIVE_DNSSEC
	uint8_t tas_spc[4096], *tas;
	size_t tas_sz;
	gldns_buffer tas_buf;
	rrset_iter tas_iter;
#endif

	if ((o = count_outstanding_requests(chain)) > 0) {
		DEBUG_SEC("%zu outstanding requests\n", o);
		return;
	}
	DEBUG_SEC("Chain done!\n");
	dnsreq = chain->netreq->owner;
	context = dnsreq->context;

#ifdef STUB_NATIVE_DNSSEC
	gldns_buffer_init_frm_data(&tas_buf, (tas = tas_spc), sizeof(tas_spc));
	_getdns_list2wire(&tas_buf, context->dnssec_trust_anchors);
	if ((tas_sz = gldns_buffer_position(&tas_buf)) > sizeof(tas_spc)) {
		if ((tas = GETDNS_XMALLOC(dnsreq->my_mf, uint8_t, tas_sz))) {
			gldns_buffer_init_frm_data(&tas_buf, tas, tas_sz);
			_getdns_list2wire(&tas_buf, context->dnssec_trust_anchors);
		}
	} else if (! GLDNS_ANCOUNT(tas))
		tas = NULL;

	if (tas)
		chain_validate_dnssec(chain,
		    rrset_iter_init(&tas_iter, tas, tas_sz));
#endif

	val_chain_list = dnsreq->dnssec_return_validation_chain
		? getdns_list_create_with_context(context) : NULL;

	/* Walk chain to add values to val_chain_list and to cleanup */
	for ( head = chain; head ; head = next ) {
		next = head->next;
		for ( node_count = head->node_count, node = head->parent
		    ; node_count
		    ; node_count--, node = node->parent ) {

			if (node->dnskey_req) {
				append_rrs2val_chain_list(context,
				    val_chain_list, node->dnskey_req);
				dns_req_free(node->dnskey_req->owner);
			}
			if (node->ds_req) {
				append_rrs2val_chain_list(context,
				    val_chain_list, node->ds_req);
				dns_req_free(node->ds_req->owner);
			}
		}
		GETDNS_FREE(head->my_mf, head);
	}

	response_dict = create_getdns_response(dnsreq);
	if (val_chain_list) {
		(void) getdns_dict_set_list(
		    response_dict, "validation_chain", val_chain_list);
		getdns_list_destroy(val_chain_list);
	}


#ifdef STUB_NATIVE_DNSSEC
	if (tas && tas != tas_spc)
		GETDNS_FREE(dnsreq->my_mf, tas);
#endif
	/* Final user callback */

	priv_getdns_call_user_callback(dnsreq, response_dict);
}

static void val_chain_node_soa_cb(getdns_dns_req *dnsreq);
static void val_chain_sched_soa_node(chain_node *node)
{
	getdns_context *context;
	getdns_eventloop *loop;
	getdns_dns_req *dnsreq;
	char  name[1024];

	context = node->chains->netreq->owner->context;
	loop    = node->chains->netreq->owner->loop;

	if (!gldns_wire2str_dname_buf(node->ds.name, 256, name, sizeof(name)))
		return;

	if (! node->soa_req &&
	    ! priv_getdns_general_loop(context, loop, name, GETDNS_RRTYPE_SOA,
	    dnssec_ok_checking_disabled, node, &dnsreq, NULL,
	    val_chain_node_soa_cb))

		node->soa_req     = dnsreq->netreqs[0];
}

static void val_chain_sched_soa(chain_head *head, uint8_t *dname)
{
	chain_node *node;

	if (!*dname)
		return;

	for ( node = head->parent
	    ; node && !priv_getdns_dname_equal(dname, node->ds.name)
	    ; node = node->parent);

	if (node)
		val_chain_sched_soa_node(node);
}

static void val_chain_node_cb(getdns_dns_req *dnsreq);
static void val_chain_sched_node(chain_node *node)
{
	getdns_context *context;
	getdns_eventloop *loop;
	getdns_dns_req *dnsreq;
	char  name[1024];

	context = node->chains->netreq->owner->context;
	loop    = node->chains->netreq->owner->loop;

	if (!gldns_wire2str_dname_buf(node->ds.name, 256, name, sizeof(name)))
		return;

	DEBUG_SEC("schedule DS & DNSKEY lookup for %s\n", name);

	if (! node->dnskey_req /* not scheduled */ &&
	    ! priv_getdns_general_loop(context, loop, name, GETDNS_RRTYPE_DNSKEY,
	    dnssec_ok_checking_disabled, node, &dnsreq, NULL, val_chain_node_cb))

		node->dnskey_req     = dnsreq->netreqs[0];

	if (! node->ds_req && node->parent /* not root */ &&
	    ! priv_getdns_general_loop(context, loop, name, GETDNS_RRTYPE_DS,
	    dnssec_ok_checking_disabled, node, &dnsreq, NULL, val_chain_node_cb))

		node->ds_req = dnsreq->netreqs[0];
}

static void val_chain_sched(chain_head *head, uint8_t *dname)
{
	chain_node *node;

	for ( node = head->parent
	    ; node && !priv_getdns_dname_equal(dname, node->ds.name)
	    ; node = node->parent);
	if (node)
		val_chain_sched_node(node);
}

static void val_chain_sched_signer_node(chain_node *node, rrsig_iter *rrsig)
{
	priv_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len;
	
	if (!(rdf = priv_getdns_rdf_iter_init_at(&rdf_spc, &rrsig->rr_i, 7)))
		return;

	if (!(signer = priv_getdns_rdf_if_or_as_decompressed(
	    rdf, signer_spc, &signer_len)))
		return;

	while (node && !priv_getdns_dname_equal(signer, node->ds.name))
		node = node->parent;
	if (node)
		val_chain_sched_node(node);
}

static void val_chain_sched_signer(chain_head *head, rrsig_iter *rrsig)
{
	val_chain_sched_signer_node(head->parent, rrsig);
}

static void val_chain_node_cb(getdns_dns_req *dnsreq)
{
	chain_node *node = (chain_node *)dnsreq->user_pointer;
	getdns_network_req *netreq = dnsreq->netreqs[0];
	rrset_iter *i, i_spc;
	getdns_rrset *rrset;
	rrsig_iter  *rrsig, rrsig_spc;

	getdns_context_clear_outbound_request(dnsreq);
	switch (netreq->request_type) {
	case GETDNS_RRTYPE_DS    : node->ds.pkt     = netreq->response;
	                           node->ds.pkt_len = netreq->response_len;
	                           break;
	case GETDNS_RRTYPE_DNSKEY: node->dnskey.pkt     = netreq->response;
	                           node->dnskey.pkt_len = netreq->response_len;
	default                  : check_chain_complete(node->chains);
				   return;
	}
	for ( i = rrset_iter_init(&i_spc,netreq->response,netreq->response_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);

		if (rrset->rr_type != GETDNS_RRTYPE_DS     &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC   &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC3)
			continue;

		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
		    ; rrsig; rrsig = rrsig_iter_next(rrsig))

			val_chain_sched_signer_node(node, rrsig);
	}
	check_chain_complete(node->chains);
}


static getdns_rrset *rrset_by_type(
    rrset_iter *i_spc, getdns_network_req *netreq, uint16_t rr_type)
{
	rrset_iter   *i;
	getdns_rrset *rrset;

	for ( i = rrset_iter_init(i_spc,netreq->response,netreq->response_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);
		if (rrset->rr_type == rr_type) /* Check class too? */
			return rrset;
	}
	return NULL;
}

static void val_chain_node_soa_cb(getdns_dns_req *dnsreq)
{
	chain_node *node = (chain_node *)dnsreq->user_pointer;
	getdns_network_req *netreq = dnsreq->netreqs[0];
	rrset_iter i_spc;
	getdns_rrset *rrset;

	getdns_context_clear_outbound_request(dnsreq);

	if ((rrset = rrset_by_type(&i_spc, netreq, GETDNS_RRTYPE_SOA))) {

		while (node &&
		    ! priv_getdns_dname_equal(node->ds.name, rrset->name))
			node = node->parent;

		val_chain_sched_node(node);
	} else
		val_chain_sched_soa_node(node->parent);

	check_chain_complete(node->chains);
}

static chain_head *add_rrset2val_chain(struct mem_funcs *mf,
    chain_head **chain_p, getdns_rrset *rrset, getdns_network_req *netreq)
{
	chain_head *head;
	uint8_t    *labels[128], **last_label, **label;

	size_t      max_labels; /* max labels in common */
	chain_head *max_head;
	chain_node *max_node;

	size_t      dname_len, head_sz, node_count, n;
	uint8_t    *dname, *region;
	chain_node *node;

	last_label = reverse_labels(rrset->name, labels);

	/* Try to find a chain with the most overlapping labels.
	 * max_labels will be the number of labels in common from the root
	 *            (so at least one; the root)
	 * max_head   will be the head of the chain with max # labebs in common
	 */
	max_head = NULL;
	max_labels = 0;
	for (head = *chain_p; head; head = head->next) {
		for (label = labels; label < last_label; label++) {
			if (! is_subdomain(*label, head->rrset.name))
				break;
		}
		if (label - labels > max_labels) {
			max_labels = label - labels;
			max_head = head;
		}
	}
	/* Chain found.  Now set max_node to the point in the chain where nodes
	 *               will be common.
	 */
	if (max_head) {
		for ( node = max_head->parent, n = 0
		    ; node
		    ; node = node->parent, n++);

		for ( n -= max_labels, node = max_head->parent
		    ; n
		    ; n--, node = node->parent);

		max_node = node;
	} else
		max_node = NULL;

	/* node_count is the amount of nodes to still allocate.
	 * the last one's parent has to hook into the max_node.
	 */
	dname_len = *labels - last_label[-1] + 1;
	head_sz = (sizeof(chain_head) + dname_len + 7) / 8 * 8;
	node_count = last_label - labels - max_labels;
	DEBUG_SEC( "%zu labels in common. %zu labels to allocate\n"
	         , max_labels, node_count);

	if (! (region = GETDNS_XMALLOC(*mf, uint8_t, head_sz + 
	    node_count * sizeof(chain_node))))
		return NULL;
	
	/* Append the head on the linked list of heads */
	for (head = *chain_p; head && head->next; head = head->next);
	if  (head)
		head = head->next = (chain_head *)region;
	else
		head = *chain_p   = (chain_head *)region;

	head->my_mf = *mf;
	head->next = NULL;
	head->rrset.name = head->name_spc;
	memcpy(head->name_spc, rrset->name, dname_len);
	head->rrset.rr_class = rrset->rr_class;
	head->rrset.rr_type = rrset->rr_type;
	head->rrset.pkt = rrset->pkt;
	head->rrset.pkt_len = rrset->pkt_len;
	head->netreq = netreq;
	head->node_count = node_count;

	if (!node_count) {
		head->parent = max_head->parent;
		return head;
	}

	/* Initialize the nodes */
	node = (chain_node *)(region + head_sz);
	head->parent = node;

	for ( node = (chain_node *)(region + head_sz), head->parent = node
	                                             , dname = head->rrset.name
	    ; node_count
	    ; node_count--, node = node->parent =&node[1], dname += *dname + 1) {

		node->ds.name         = dname;
		node->dnskey.name     = dname;
		node->ds.rr_class     = head->rrset.rr_class;
		node->dnskey.rr_class = head->rrset.rr_class;
		node->ds.rr_type      = GETDNS_RRTYPE_DS;
		node->dnskey.rr_type  = GETDNS_RRTYPE_DNSKEY;
		node->ds.pkt          = NULL;
		node->ds.pkt_len      = 0;
		node->dnskey.pkt      = NULL;
		node->dnskey.pkt_len  = 0;
		node->ds_req          = NULL;
		node->dnskey_req      = NULL;
		node->soa_req         = NULL;

		node->chains          = *chain_p;
	}
	/* On the first chain, max_node == NULL.
	 * Schedule a root DNSKEY query, we always need that.
	 */
	if (!(node[-1].parent = max_node))
		val_chain_sched(head, (uint8_t *)"\0");

	return head;
}

static void add_netreq2val_chain(
    chain_head **chain_p, getdns_network_req *netreq)
{
	rrset_iter *i, i_spc;
	getdns_rrset *rrset;
	rrsig_iter *rrsig, rrsig_spc;
	size_t n_rrsigs;
	chain_head *head;
	struct mem_funcs *mf;
	getdns_rrset empty_rrset;

	getdns_rrset q_rrset;
	uint8_t cname_spc[256];
	size_t cname_len = sizeof(cname_spc);
	size_t anti_loop;
	priv_getdns_rdf_iter rdf_spc, *rdf;
	rrtype_iter *rr, rr_spc;

	assert(netreq->response);
	assert(netreq->response_len >= GLDNS_HEADER_SIZE);

	mf = priv_getdns_context_mf(netreq->owner->context);

	/* On empty packet, find SOA (zonecut) for the qname and query DS */

	/* For all things with signatures, create a chain */

	/* For all things without signature, find SOA (zonecut) and query DS */

	if (GLDNS_ANCOUNT(netreq->response) == 0 &&
	    GLDNS_NSCOUNT(netreq->response) == 0) {

		empty_rrset.name = netreq->query + GLDNS_HEADER_SIZE;
		empty_rrset.rr_class = GETDNS_RRCLASS_IN;
		empty_rrset.rr_type  = 0;
		empty_rrset.pkt = netreq->response;
		empty_rrset.pkt_len = netreq->response_len;

		head = add_rrset2val_chain(mf, chain_p, &empty_rrset, netreq);
		val_chain_sched_soa(head, empty_rrset.name);
		return;
	}
	for ( i = rrset_iter_init(&i_spc,netreq->response,netreq->response_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);
		debug_sec_print_rrset("rrset: ", rrset);

		head = add_rrset2val_chain(mf, chain_p, rrset, netreq);
		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset), n_rrsigs = 0
		    ; rrsig
		    ; rrsig = rrsig_iter_next(rrsig), n_rrsigs++) {
			
			val_chain_sched_signer(head, rrsig);
		}
		if (n_rrsigs)
			continue;

		if (rrset->rr_type == GETDNS_RRTYPE_SOA)
			val_chain_sched(head, rrset->name);
		else
			val_chain_sched_soa(head, rrset->name);
	}
	/* For NOERROR/NODATA or NXDOMAIN responses add extra rrset to 
	 * the validation chain so the denial of existence will be
	 * checked eventually.
	 */

	/* First find the canonical name for the question */
	q_rrset.name     = netreq->query + GLDNS_HEADER_SIZE;
	q_rrset.rr_type  = GETDNS_RRTYPE_CNAME;
	q_rrset.rr_class = netreq->request_class;
	q_rrset.pkt      = netreq->response;
	q_rrset.pkt_len  = netreq->response_len;

	for (anti_loop = 1000; anti_loop; anti_loop--) {
		if (!(rr = rrtype_iter_init(&rr_spc, &q_rrset)))
			break;
		if (!(rdf = priv_getdns_rdf_iter_init(&rdf_spc, &rr->rr_i)))
			break;
		q_rrset.name = priv_getdns_rdf_if_or_as_decompressed(
				rdf, cname_spc, &cname_len);
	}

	q_rrset.rr_type  = netreq->request_type;
	if (!(rr = rrtype_iter_init(&rr_spc, &q_rrset))) {

		debug_sec_print_rrset("Adding NX rrset: ", &q_rrset);
		add_rrset2val_chain(mf, chain_p, &q_rrset, netreq);
	}
}

static void get_val_chain(getdns_dns_req *dnsreq)
{
	getdns_network_req *netreq, **netreq_p;
	chain_head *chain = NULL;

	for (netreq_p = dnsreq->netreqs; (netreq = *netreq_p) ; netreq_p++)
		add_netreq2val_chain(&chain, netreq);

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

void priv_getdns_get_validation_chain(getdns_dns_req *dns_req)
{
	get_val_chain(dns_req);
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
