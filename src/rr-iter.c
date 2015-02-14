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

static void
rr_iter_find_nxt(priv_getdns_rr_iter *i)
{
	assert(i);
	assert(i->rr_type);

	i->nxt = i->n < GLDNS_QDCOUNT(i->pkt)
	       ? i->rr_type + 4
	       : i->rr_type + 10 > i->pkt_end
	       ? i->pkt_end
	       : i->rr_type + 10 + gldns_read_uint16(i->rr_type + 8) > i->pkt_end
	       ? i->pkt_end
	       : i->rr_type + 10 + gldns_read_uint16(i->rr_type + 8);
}

static priv_getdns_rr_iter *
find_rrtype(priv_getdns_rr_iter *i)
{
	uint8_t *pos;

	assert(i);
	assert(i->pos);

	/* Past the last RR in the pkt */
	if (GLDNS_QDCOUNT(i->pkt) + GLDNS_ANCOUNT(i->pkt) +
	    GLDNS_NSCOUNT(i->pkt) + GLDNS_ARCOUNT(i->pkt) <= i->n)
		goto done;

	for (pos = i->pos; pos + 4 < i->pkt_end; pos += *pos + 1)
		if (!*pos) {
			i->rr_type = pos + 1;
			rr_iter_find_nxt(i);
			return i;

		} else if ((*pos & 0xC0) == 0xC0) {
			if ( pos + 6 > i->pkt_end)
				break; /* No space for class */

			i->rr_type = pos + 2;
			rr_iter_find_nxt(i);
			return i;

		} else if (*pos & 0xC0)
			break; /* Unknown label type */
done:
	i->pos = NULL;
	return NULL;
}

priv_getdns_rr_iter *
priv_getdns_rr_iter_init(priv_getdns_rr_iter *i, uint8_t *pkt, size_t pkt_len)
{
	assert(i);

	if (pkt_len < GLDNS_HEADER_SIZE + 5) {
		i->pos = NULL;
		return NULL;
	}
	i->pkt     = pkt;
	i->pkt_end = pkt + pkt_len;
	i->n       = 0;
	i->pos     = pkt + GLDNS_HEADER_SIZE;

	return find_rrtype(i);
}


priv_getdns_rr_iter *
priv_getdns_rr_iter_next(priv_getdns_rr_iter *i)
{
	assert(i);

	/* Already done */
	if (!i->pos)
		return NULL;

	i->n  += 1;
	i->pos = i->nxt;
	return find_rrtype(i);
}

static priv_getdns_rdf_iter *
rdf_iter_find_nxt(priv_getdns_rdf_iter *i)
{
	uint8_t *pos;

	assert(i);
	assert(i->pos);
	assert(i->rdd_pos);

	if (!i->rdd_repeat && (i->rdd_pos->type & GETDNS_RDF_REPEAT)) {
		if (i->rdd_pos->type == GETDNS_RDF_REPEAT &&
		    ++i->rdd_pos == i->rdd_end)
			goto done;
		i->rdd_repeat = i->rdd_pos;
	}
	if (i->rdd_pos->type & GETDNS_RDF_FIXEDSZ)
		i->nxt = i->pos + (i->rdd_pos->type & GETDNS_RDF_FIXEDSZ);

	else if ((i->rdd_pos->type & GETDNS_RDF_LEN_VAL) == 0x100)
		i->nxt = i->pos < i->end ? i->pos + *i->pos + 1 : i->end;

	else if ((i->rdd_pos->type & GETDNS_RDF_LEN_VAL) == 0x200)
		i->nxt = i->pos + 1 < i->end
		       ? i->pos + gldns_read_uint16(i->pos) + 2 : i->end;

	else if ((i->rdd_pos->type & GETDNS_RDF_DNAME) == GETDNS_RDF_DNAME)

		for (pos = i->pos; pos < i->end; pos += *pos + 1) {
			if (!*pos) {
				i->nxt = pos + 1;
				break;
			} else if ((*pos & 0xC0) == 0xC0) {
				i->nxt = pos + 2;
				break;
			} else if (*pos & 0xC0) /* Uknown label type */
				goto done;
		}
	else
		i->nxt = i->end;

	if (i->nxt <= i->end)
		return i;
done:
	i->pos = NULL;
	return NULL;
}

priv_getdns_rdf_iter *
priv_getdns_rdf_iter_init(priv_getdns_rdf_iter *i, priv_getdns_rr_iter *rr)
{
	const priv_getdns_rr_def *rr_def;

	assert(i);
	assert(rr);

	/* rr_iter already done or in question section */
	if (!rr->pos || rr->n < GLDNS_QDCOUNT(rr->pkt))
		goto done;

	i->pkt     = rr->pkt;
	i->pkt_end = rr->pkt_end;
	rr_def     = priv_getdns_rr_def_lookup(gldns_read_uint16(rr->rr_type));
	i->rdd_pos = rr_def->rdata;
	i->rdd_end = rr_def->rdata + rr_def->n_rdata_fields;

	/* No rdata */
	if (i->rdd_pos == i->rdd_end)
		goto done;

	/* No space to read rdata len */
	if (rr->rr_type + 10 >= rr->nxt)
		goto done;

	i->rdd_repeat = NULL;
	i->pos        = rr->rr_type + 10;
	i->end        = rr->nxt;

	return rdf_iter_find_nxt(i);
done:
	i->pos = NULL;
	return NULL;
}

priv_getdns_rdf_iter *
priv_getdns_rdf_iter_next(priv_getdns_rdf_iter *i)
{
	if (!i->pos)
		return NULL;

	i->rdd_pos += 1;
	if ((i->pos = i->nxt) >= i->end)
		goto done; /* Out of rdata */
	if (i->rdd_pos >= i->rdd_end && !(i->rdd_pos = i->rdd_repeat))
		goto done; /* Remaining rdata, but out of definitions! */

	return rdf_iter_find_nxt(i);
done:
	i->pos = NULL;
	return NULL;
}

