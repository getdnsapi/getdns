/**
 *
 * /brief RR iterator over wireformat DNS packet
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

#ifndef RR_ITER_H_
#define RR_ITER_H_

#include "getdns/getdns.h"
#include "rr-dict.h"
#include "gldns/pkthdr.h"
#include "gldns/gbuffer.h"

typedef struct priv_getdns_rr_iter {
	uint8_t *pkt;
	uint8_t *pkt_end;

	/* Which RR are we currently at */
	size_t   n;

	/* pos points to start of the owner name the RR.
	 * Or is NULL when there are no RR's left.
	 */
	uint8_t *pos;

	/* rr_type will point to the rr_type right after the RR's owner name.
	 * rr_type is guaranteed to have a value when pos has a value
	 */
	uint8_t *rr_type;

	/* nxt point to the owner name of the next RR or to pkt_end */
	uint8_t *nxt;

} priv_getdns_rr_iter;

priv_getdns_rr_iter *priv_getdns_rr_iter_init(priv_getdns_rr_iter *i,
    uint8_t *pkt, size_t pkt_len);

priv_getdns_rr_iter *priv_getdns_rr_iter_next(priv_getdns_rr_iter *i);

static inline gldns_pkt_section
priv_getdns_rr_iter_section(priv_getdns_rr_iter *i)
{
	return i->n < GLDNS_QDCOUNT(i->pkt) ? LDNS_SECTION_QUESTION
	     : i->n < GLDNS_QDCOUNT(i->pkt)
	            + GLDNS_ANCOUNT(i->pkt) ? GLDNS_SECTION_ANSWER
	     : i->n < GLDNS_QDCOUNT(i->pkt)
	            + GLDNS_ANCOUNT(i->pkt)
	            + GLDNS_NSCOUNT(i->pkt) ? GLDNS_SECTION_AUTHORITY
	     : i->n < GLDNS_QDCOUNT(i->pkt)
	            + GLDNS_ANCOUNT(i->pkt)
	            + GLDNS_NSCOUNT(i->pkt)
	            + GLDNS_ARCOUNT(i->pkt) ? GLDNS_SECTION_ADDITIONAL
	                                    : GLDNS_SECTION_ANY;
}

typedef struct piv_getdns_rdf_iter {
	uint8_t                     *pkt;
	uint8_t                     *pkt_end;
	const priv_getdns_rdata_def *rdd_pos;
	const priv_getdns_rdata_def *rdd_end;
	const priv_getdns_rdata_def *rdd_repeat;
	uint8_t                     *pos;
	uint8_t                     *end;
	uint8_t                     *nxt;
} priv_getdns_rdf_iter;

priv_getdns_rdf_iter *priv_getdns_rdf_iter_init(priv_getdns_rdf_iter *i,
    priv_getdns_rr_iter *rr);

priv_getdns_rdf_iter *priv_getdns_rdf_iter_next(priv_getdns_rdf_iter *i);


#endif
