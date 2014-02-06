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

/*
 * getdns_validate_dnssec
 *
 */
getdns_return_t
getdns_validate_dnssec(struct getdns_bindata *to_validate,
    struct getdns_list *support_records,
    struct getdns_list *trust_anchors)
{
	getdns_return_t r;
	ldns_rr_list *tas;
	ldns_rr_list *chain;

	if ((r = priv_getdns_rr_list_from_list(trust_anchors, &tas)))
		return r;

	printf(";; trust anchors:\n");
	ldns_rr_list_print(stdout, tas);

	if ((r = priv_getdns_rr_list_from_list(support_records, &chain)))
		return r;

	printf(";; support records:\n");
	ldns_rr_list_print(stdout, chain);


	return r;
}				/* getdns_validate_dnssec */

/* validate_dnssec.c */
