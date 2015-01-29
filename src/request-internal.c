/**
 *
 * /brief getdns contect management functions
 *
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
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

#include "config.h"
#include "types-internal.h"
#include "util-internal.h"
#include "gldns/rrdef.h"

static void
network_req_cleanup(getdns_network_req *net_req)
{
	assert(net_req);

	if (net_req->result)
		ldns_pkt_free(net_req->result);

	if (net_req->response && net_req->response != net_req->wire_data)
		GETDNS_FREE(net_req->owner->my_mf, net_req->response);
}

static void
network_req_init(getdns_network_req *net_req,
    getdns_dns_req *owner, uint16_t request_type,
    uint16_t request_class, size_t wire_data_sz)
{
	net_req->result = NULL;

	net_req->request_type = request_type;
	net_req->request_class = request_class;
	net_req->unbound_id = -1;
	net_req->state = NET_REQ_NOT_SENT;
	net_req->owner = owner;

	net_req->upstream = NULL;
	net_req->fd = -1;
	memset(&net_req->event, 0, sizeof(net_req->event));
	memset(&net_req->tcp, 0, sizeof(net_req->tcp));
	net_req->query_id = 0;
	net_req->max_udp_payload_size = 0;
	net_req->write_queue_tail = NULL;

	net_req->wire_data_sz = wire_data_sz;
	net_req->response = NULL;
}

void
dns_req_free(getdns_dns_req * req)
{
	getdns_network_req **net_req;
	if (!req) {
		return;
	}

	/* free extensions */
	getdns_dict_destroy(req->extensions);

	if (req->upstreams && --req->upstreams->referenced == 0)
		GETDNS_FREE(req->upstreams->mf, req->upstreams);

	/* cleanup network requests */
	for (net_req = req->netreqs; *net_req; net_req++)
		network_req_cleanup(*net_req);

	/* clear timeout event */
	if (req->timeout.timeout_cb) {
		req->loop->vmt->clear(req->loop, &req->timeout);
		req->timeout.timeout_cb = NULL;
	}

	/* free strduped name */
	GETDNS_FREE(req->my_mf, req->name);
	GETDNS_FREE(req->my_mf, req);
}

/* create a new dns req to be submitted */
getdns_dns_req *
dns_req_new(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions)
{

	getdns_dns_req *result = NULL;
        uint32_t klass = GLDNS_RR_CLASS_IN;
	size_t edns_maximum_udp_payload_size =
	    getdns_get_maximum_udp_payload_size(context, extensions, NULL);
	int a_aaaa_query =
	    is_extension_set(extensions, "return_both_v4_and_v6") &&
	    ( request_type == GETDNS_RRTYPE_A ||
	      request_type == GETDNS_RRTYPE_AAAA );
	/* Reserve for the buffer at least one more byte
	 * (to test for udp overflow) (hence the + 1),
	 * And align on the 8 byte boundry  (hence the (x + 7) / 8 * 8)
	 */
	size_t netreq_sz = ( sizeof(getdns_network_req)
	                   + edns_maximum_udp_payload_size + 1 + 7) / 8 * 8;
	size_t dnsreq_base_sz = ( sizeof(getdns_dns_req) 
	                        + (a_aaaa_query ? 3 : 2) 
	                        * sizeof(getdns_network_req *));
	uint8_t *region;

	if (! (region = GETDNS_XMALLOC(context->mf, uint8_t, 
	    dnsreq_base_sz + (a_aaaa_query ? 2 : 1) * netreq_sz)))
		return NULL;

	result = (getdns_dns_req *)region;
	result->netreqs[0] = (getdns_network_req *)(region + dnsreq_base_sz);
	if (a_aaaa_query) {
		result->netreqs[1] = (getdns_network_req *)
		    (region + dnsreq_base_sz + netreq_sz);
		result->netreqs[2] = NULL;
	} else
		result->netreqs[1] = NULL;

	result->my_mf = context->mf;
	result->name = getdns_strdup(&(result->my_mf), name);
	result->context = context;
	result->loop = loop;
	result->canceled = 0;
	result->trans_id = (uint64_t)(((intptr_t) result) ^ ldns_get_random());

	getdns_dict_copy(extensions, &result->extensions);
	result->return_dnssec_status = context->return_dnssec_status;

	/* will be set by caller */
	result->user_pointer = NULL;
	result->user_callback = NULL;
	memset(&result->timeout, 0, sizeof(result->timeout));

        /* check the specify_class extension */
        (void) getdns_dict_get_int(extensions, "specify_class", &klass);
        
	result->upstreams = context->upstreams;
	if (result->upstreams)
		result->upstreams->referenced++;

	network_req_init(result->netreqs[0], result, request_type,
	    klass, netreq_sz - sizeof(getdns_network_req));

	if (a_aaaa_query)
		network_req_init(result->netreqs[1], result,
		    ( request_type == GETDNS_RRTYPE_A
		    ? GETDNS_RRTYPE_AAAA : GETDNS_RRTYPE_A ),
		    klass, netreq_sz - sizeof(getdns_network_req));

	return result;
}
