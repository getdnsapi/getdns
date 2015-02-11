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

#include "rr-iter.h"
#include "config.h"
#include <gldns/pkthdr.h>
#include <gldns/gbuffer.h>

static getdns_rr_iter *
find_rrtype(getdns_rr_iter *i)
{
	size_t dlen;
	uint8_t *pos;

	/* Past the last RR in the pkt */
	if (GLDNS_QDCOUNT(i->pkt) + GLDNS_ANCOUNT(i->pkt) +
	    GLDNS_NSCOUNT(i->pkt) + GLDNS_ARCOUNT(i->pkt) <= i->n) {

		i->pos = NULL;
		return NULL;
	}

	/* This iterator was already done */
	if (!i->pos)
		return NULL;

	pos  = i->pos;
	dlen = i->pkt_len - (pos - i->pkt);

	while (dlen >= 5) { /* At least space for type and class  */

		if (*pos == 0) {
			i->rr_type = pos + 1;
			return i;
		}
		if ((*pos & 0xC0) == 0xC0) {
			i->rr_type = pos + 2;
			return i;
		}
		if ((*pos & 0xC0) != 0)
			break; /* Unknown label type */

		if (*pos > dlen)
			break; /* Label size overflows packet size! */

		dlen -= *pos + 1;
		pos  += *pos + 1;
	}
	i->pos = NULL;
	return NULL;
}

getdns_rr_iter *
priv_getdns_rr_iter_init(getdns_rr_iter *i, uint8_t *pkt, size_t pkt_len)
{
	if (pkt_len < GLDNS_HEADER_SIZE + 5)
		return NULL;

	i->pkt     = pkt;
	i->pkt_len = pkt_len;
	i->n       = 0;
	i->pos     = pkt + GLDNS_HEADER_SIZE;

	return find_rrtype(i);
}


getdns_rr_iter *
priv_getdns_rr_iter_next(getdns_rr_iter *i)
{
	size_t dlen;

	/* Already done */
	if (!i->pos)
		return NULL;

	assert(i->rr_type);

	i->n += 1;

	if (i->n <= GLDNS_QDCOUNT(i->pkt)) {
		i->pos = i->rr_type + 4;
		return find_rrtype(i);
	}

	dlen = i->pkt_len - (i->rr_type - i->pkt);
	if (dlen < 10)
		goto garbage; /* No space for type, class, ttl & rdlength */

	if (gldns_read_uint16(i->rr_type + 8) > dlen - 10)
		goto garbage; /* RData size overflos packet size */

	i->pos = i->rr_type + 10 + gldns_read_uint16(i->rr_type + 8);
	return find_rrtype(i);
garbage:
	i->pos = NULL;
	return NULL;
}

