/**
 *
 * /brief function for stub resolving
 *
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

#include "getdns/getdns.h"
#include "config.h"
#include "gldns/gbuffer.h"
#include "gldns/rrdef.h"
#include "gldns/str2wire.h"
#include <ldns/util.h>

gldns_buffer *
make_query_pkt(const char *name, uint16_t request_type, struct getdns_dict *extensions)
{
	uint16_t flags = 0; /* QUERY, NOERROR */
	uint32_t klass;
	size_t pos;
	gldns_buffer *pkt = gldns_buffer_new(512); /* max query */

	if (! pkt)
		return NULL;

        gldns_buffer_clear(pkt);
        gldns_buffer_write_u16(pkt, ldns_get_random());
        gldns_buffer_write_u16(pkt, flags);
        gldns_buffer_write_u16(pkt, 1); /* query count */
        gldns_buffer_write(pkt, "\000\000\000\000\000\000", 6); /* counts */
	pos = gldns_buffer_remaining(pkt);
	if (gldns_str2wire_dname_buf(name, gldns_buffer_current(pkt), &pos)) {
		gldns_buffer_free(pkt);
		return NULL;
	}
	gldns_buffer_skip(pkt, gldns_buffer_remaining(pkt) - pos);
        gldns_buffer_write_u16(pkt, request_type);
	if (getdns_dict_get_int(extensions, "specify_class", &klass)
	    != GETDNS_RETURN_GOOD)
		klass = GLDNS_RR_CLASS_IN;
        gldns_buffer_write_u16(pkt, (uint16_t) klass);
	return pkt;
}

/* stub.c */

