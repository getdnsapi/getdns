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
#include "gldns/rrdef.h"

static void
rr_iter_find_nxt(_getdns_rr_iter *i)
{
	assert(i);
	assert(i->rr_type);

	i->nxt = i->pkt && i->n < GLDNS_QDCOUNT(i->pkt)
	       ? i->rr_type + 4
	       : i->rr_type + 10 > i->pkt_end
	       ? i->pkt_end
	       : i->rr_type + 10 + gldns_read_uint16(i->rr_type + 8) > i->pkt_end
	       ? i->pkt_end
	       : i->rr_type + 10 + gldns_read_uint16(i->rr_type + 8);
}

static _getdns_rr_iter *
find_rrtype(_getdns_rr_iter *i)
{
	const uint8_t *pos;

	assert(i);
	assert(i->pos);

	/* Past the last RR in the pkt */
	if (i->pkt &&
	    GLDNS_QDCOUNT(i->pkt) + GLDNS_ANCOUNT(i->pkt) +
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

_getdns_rr_iter *
_getdns_rr_iter_init(_getdns_rr_iter *i, const uint8_t *pkt, size_t pkt_len)
{
	assert(i);

	if (!pkt || pkt_len < GLDNS_HEADER_SIZE + 5) {
		i->pos = NULL;
		return NULL;
	}
	i->pkt     = pkt;
	i->pkt_end = pkt + pkt_len;
	i->n       = 0;
	i->pos     = pkt + GLDNS_HEADER_SIZE;

	return find_rrtype(i);
}

_getdns_rr_iter *
_getdns_single_rr_iter_init(
    _getdns_rr_iter *i, const uint8_t *wire, size_t wire_len)
{
	assert(i);

	if (!wire || wire_len < 5 /* name + type + class */) {
		i->pos = NULL;
		return NULL;
	}
	i->pkt     = NULL;
	i->pos     = wire;
	i->pkt_end = wire + wire_len;
	i->n       = 0;

	return find_rrtype(i);
}


_getdns_rr_iter *
_getdns_rr_iter_rewind(_getdns_rr_iter *i)
{
	assert(i);

	return _getdns_rr_iter_init(i, i->pkt, i->pkt_end - i->pkt);
}

_getdns_rr_iter *
_getdns_rr_iter_next(_getdns_rr_iter *i)
{
	assert(i);

	/* Already done */
	if (!i->pos)
		return NULL;

	i->n  += 1;
	i->pos = i->nxt;
	return find_rrtype(i);
}

static const uint8_t *
dname_if_or_as_decompressed(const uint8_t *pkt, const uint8_t *pkt_end,
    const uint8_t *pos, uint8_t *buf, size_t *len, size_t refs)
{
	uint16_t offset;
	const uint8_t *start;
	uint8_t *dst;

	assert(pkt_end);
	assert(pos);
	assert(buf);
	assert(len);

	if (refs > GLDNS_MAX_POINTERS)
		goto error;

	if ((*pos & 0xC0) == 0xC0) {
		if (!pkt || pos + 1 >= pkt_end)
			goto error;
		offset = gldns_read_uint16(pos) & 0x3FFF;
		if (pkt + offset >= pkt_end)
			goto error;
		return dname_if_or_as_decompressed(pkt, pkt_end, pkt + offset,
		    buf, len, refs + 1);
	}
	if (*pos & 0xC0)
		goto error;

	start = pos;
	*len  = 0;
	while (*pos) {
		if ((*pos & 0xC0) == 0xC0)
			break;

		else if (*pos & 0xC0)
			goto error;

		*len += *pos + 1;
		pos += *pos + 1;
	}
	if (!*pos) {
		*len += 1;
		return start;
	}
	dst = buf;
	for (;;) {
		if (pos > start) {
			if (dst + (pos - start) > buf + 255)
				goto error;
			(void) memcpy(dst, start, pos - start);
			dst += (pos - start);
			start = pos;
		}
		if ((*pos & 0xC0) == 0xC0) {
			if (!pkt || pos + 1 >= pkt_end)
				goto error;
			offset = gldns_read_uint16(pos) & 0x3FFF;
			if (pkt + offset >= pkt_end)
				goto error;

			start = pos = pkt + offset;
			if (++refs > 256)
				goto error;
		}
		if ((*pos & 0xC0) == 0xC0)
			continue;

		else if (*pos & 0xC0)
			goto error;

		else if (!*pos) {
			*len += 1;
			*dst = 0;
			return buf;
		}
		*len += *pos + 1;
		pos += *pos + 1;
	}
error:
	*len = 0;
	return NULL;
}

const uint8_t *
_getdns_owner_if_or_as_decompressed(_getdns_rr_iter *i,
    uint8_t *ff_bytes, size_t *len)
{
	return dname_if_or_as_decompressed(i->pkt, i->pkt_end, i->pos,
	    ff_bytes, len, 0);
}

static _getdns_rdf_iter *
rdf_iter_find_nxt(_getdns_rdf_iter *i)
{
	const uint8_t *pos;

	assert(i);
	assert(i->pos);
	assert(i->rdd_pos);

	if (!i->rdd_repeat && (i->rdd_pos->type & GETDNS_RDF_REPEAT)) {
		i->rdd_repeat = i->rdd_pos;
		if (i->rdd_pos->type == GETDNS_RDF_REPEAT &&
		    ++i->rdd_pos == i->rdd_end)
			goto done;
	}
	if (i->rdd_pos->type & GETDNS_RDF_FIXEDSZ)
		i->nxt = i->pos + (i->rdd_pos->type & GETDNS_RDF_FIXEDSZ);

	else if ((i->rdd_pos->type & GETDNS_RDF_LEN_VAL) == 0x100)
		i->nxt = i->pos < i->end ? i->pos + *i->pos + 1 : i->end;

	else if ((i->rdd_pos->type & GETDNS_RDF_LEN_VAL) == 0x200)
		i->nxt = i->pos + 1 < i->end
		       ? i->pos + gldns_read_uint16(i->pos) + 2 : i->end;

	else if (i->rdd_pos->type & GETDNS_RDF_DNAME)

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
	else if ((i->rdd_pos->type & GETDNS_RDF_SPECIAL) && i->rdd_pos->special) {
		if (!(i->nxt = i->rdd_pos->special->rdf_end(
		    i->pkt, i->pkt_end, i->pos)))
			i->nxt = i->end;

	} else /* RDF is for remaining data */
		i->nxt = i->end;

	if ( i->nxt <= i->end &&

	    /* Empty rdata fields are only allowed in case of non-repeating
	     * remaining data. So only the GETDNS_RDF_BINDATA bit is set.
	     */
	    (i->nxt >  i->pos || (i->rdd_pos->type == GETDNS_RDF_BINDATA)))
		return i;
done:
	i->pos = NULL;
	return NULL;
}

_getdns_rdf_iter *
_getdns_rdf_iter_init(_getdns_rdf_iter *i, _getdns_rr_iter *rr)
{
	const _getdns_rr_def *rr_def;

	assert(i);
	assert(rr);

	i->end     = NULL;
	/* rr_iter already done or in question section */
	if (!rr->pos || _getdns_rr_iter_section(rr) == GLDNS_SECTION_QUESTION)
		goto done;

	i->pkt     = rr->pkt;
	i->pkt_end = rr->pkt_end;
	rr_def     = _getdns_rr_def_lookup(gldns_read_uint16(rr->rr_type));
	i->rdd_pos = rr_def->rdata;
	i->rdd_end = rr_def->rdata + rr_def->n_rdata_fields;

	/* No space to read rdata len */
	if (rr->rr_type + 10 >= rr->nxt)
		goto done;

	i->rdd_repeat = NULL;
	i->pos        = rr->rr_type + 10;
	i->end        = rr->nxt;

	/* rdata */
	if (i->rdd_pos != i->rdd_end)
		return rdf_iter_find_nxt(i);
done:
	i->pos = NULL;
	return NULL;
}

_getdns_rdf_iter *
_getdns_rdf_iter_next(_getdns_rdf_iter *i)
{
	if (!i->pos)
		return NULL;

	i->rdd_pos += 1;
	if ((i->pos = i->nxt) > i->end)
		goto done; /* Overflow */
	if (i->rdd_pos >= i->rdd_end && !(i->rdd_pos = i->rdd_repeat))
		goto done; /* Remaining rdata, but out of definitions! */
	if (i->rdd_pos->type == GETDNS_RDF_REPEAT)
		i->rdd_pos += 1;

	return rdf_iter_find_nxt(i);
done:
	i->pos = NULL;
	return NULL;
}

_getdns_rdf_iter *
_getdns_rdf_iter_init_at(
    _getdns_rdf_iter *i, _getdns_rr_iter *rr, size_t pos)
{
	for ( i = _getdns_rdf_iter_init(i, rr)
	    ; i && pos
	    ; i = _getdns_rdf_iter_next(i), pos--);
	return i;
}       

const uint8_t *
_getdns_rdf_if_or_as_decompressed(
    _getdns_rdf_iter *i, uint8_t *ff_bytes, size_t *len)
{
	return dname_if_or_as_decompressed(i->pkt, i->pkt_end, i->pos,
	    ff_bytes, len, 0);
}

