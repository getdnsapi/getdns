/**
 *
 * \file validate_dnssec.c
 * @brief dnssec validation functions
 * 
 * Originally taken from the getdns API description pseudo implementation.
 *
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

#include <getdns/getdns.h>
#include <ldns/ldns.h>
#include "rr-dict.h"

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

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
	i->cur_node = ldns_rbtree_first(zone->names);
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
	size_t i;
	ldns_rr *rr;
	ldns_dnssec_rrsets *key_rrset;

	printf(";; RRSET to validate:\n");
	ldns_dnssec_rrsets_print(stdout, rrset, 0);

	printf(";;\n;; Validating with trust anchors:\n");
	verifying_keys = ldns_rr_list_new();
	s = verify_rrset(rrset, trusted, verifying_keys);
	printf(";; status: %s\n", ldns_get_errorstr_by_id(s));
	if (ldns_rr_list_rr_count(verifying_keys)) { ldns_rr_list_print(stdout, verifying_keys); printf(";;\n"); }
	ldns_rr_list_free(verifying_keys);
	if (s == 0)
		return s;

	printf(";; Validating with support keys:\n");
	verifying_keys = ldns_rr_list_new();
	s = verify_rrset(rrset, support_keys, verifying_keys);
	printf(";; status: %s\n", ldns_get_errorstr_by_id(s));
	if (ldns_rr_list_rr_count(verifying_keys)) { ldns_rr_list_print(stdout, verifying_keys); printf(";;\n"); }
	if (s != 0)
		goto done_free_verifying_keys;

	printf(";; Looking up the verifying keys:\n");
	for (i = 0; i < ldns_rr_list_rr_count(verifying_keys); i++) {
		rr = ldns_rr_list_rr(verifying_keys, i);
		key_rrset = ldns_dnssec_zone_find_rrset(
		    support, ldns_rr_owner(rr), ldns_rr_get_type(rr));
		if (! key_rrset) {
			printf(";; Key not found:\n;;\n");
			s = LDNS_STATUS_CRYPTO_NO_DNSKEY;
			break;
		}
		if (rrset == key_rrset) {
			printf(";; Key verifies itself, lookup DS:\n");
			key_rrset = ldns_dnssec_zone_find_rrset(
			    support, ldns_rr_owner(rr), LDNS_RR_TYPE_DS);
			if (! key_rrset) {
				printf(";; DS not found:\n;;\n");
				s = LDNS_STATUS_CRYPTO_NO_DNSKEY;
				break;
			}
			/* Now check if DS matches the DNSKEY! */
		}
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
	ldns_status s;

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

	/*
	for(zone_iter_init(&i, to_validate);
	    (rrset = zone_iter_rrset(&i)); zone_iter_next(&i)) {

		ldns_dnssec_rrsets_print(stdout, rrset, 0);
	}
	*/

	ldns_rr_list_free(support_keys);
done_free_to_validate:
	ldns_dnssec_zone_free(to_validate);
done_free_support:
	ldns_dnssec_zone_free(support);
done_free_trusted:
	ldns_rr_list_deep_free(trusted);
	return r;
}				/* getdns_validate_dnssec */

/* validate_dnssec.c */
