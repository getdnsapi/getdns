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
#include "gldns/str2wire.h"
#include "gldns/gbuffer.h"
#include "gldns/pkthdr.h"

static int
is_extension_set(getdns_dict *extensions, const char *extension)
{
	getdns_return_t r;
	uint32_t value;

	if (! extensions)
		return 0;

	r = getdns_dict_get_int(extensions, extension, &value);
	return r == GETDNS_RETURN_GOOD && value == GETDNS_EXTENSION_TRUE;
}

static void
network_req_cleanup(getdns_network_req *net_req)
{
	assert(net_req);

	if (net_req->response && (net_req->response < net_req->wire_data ||
	    net_req->response > net_req->wire_data+ net_req->wire_data_sz))
		GETDNS_FREE(net_req->owner->my_mf, net_req->response);
}

static int
network_req_init(getdns_network_req *net_req, getdns_dns_req *owner,
    const char *name, uint16_t request_type, uint16_t request_class,
    int dnssec_extension_set, int with_opt,
    uint16_t edns_maximum_udp_payload_size,
    uint8_t edns_extended_rcode, uint8_t edns_version, int edns_do_bit,
    uint16_t opt_options_size, size_t noptions, getdns_list *options,
    size_t wire_data_sz, size_t max_query_sz)
{
	uint8_t *buf;
	size_t dname_len;
	getdns_dict    *option;
	uint32_t        option_code;
	getdns_bindata *option_data;
	size_t i;
	int r = 0;

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
	net_req->edns_maximum_udp_payload_size = edns_maximum_udp_payload_size;
	net_req->max_udp_payload_size = edns_maximum_udp_payload_size != -1
	                              ? edns_maximum_udp_payload_size : 1432;
	net_req->write_queue_tail = NULL;
	net_req->query_len = 0;
	net_req->response_len = 0;

	net_req->wire_data_sz = wire_data_sz;
	if (max_query_sz) {
		/* first two bytes will contain query length (for tcp) */
		buf = net_req->query = net_req->wire_data + 2;

		gldns_write_uint16(buf + 2, 0); /* reset all flags */
		GLDNS_RD_SET(buf);
		if (dnssec_extension_set) /* We will do validation ourselves */
			GLDNS_CD_SET(buf);
		GLDNS_OPCODE_SET(buf, GLDNS_PACKET_QUERY);
		gldns_write_uint16(buf + GLDNS_QDCOUNT_OFF, 1); /* 1 query */
		gldns_write_uint16(buf + GLDNS_ANCOUNT_OFF, 0); /* 0 answers */
		gldns_write_uint16(buf + GLDNS_NSCOUNT_OFF, 0); /* 0 authorities */
		gldns_write_uint16(buf + GLDNS_ARCOUNT_OFF, with_opt ? 1 : 0);

		buf += GLDNS_HEADER_SIZE;
		dname_len = max_query_sz - GLDNS_HEADER_SIZE;
		if ((r = gldns_str2wire_dname_buf(name, buf, &dname_len))) {
			net_req->opt = NULL;
			return r;
		}

		buf += dname_len;

		gldns_write_uint16(buf, request_type);
		gldns_write_uint16(buf + 2, request_class);
		buf += 4;

		if (with_opt) {
			net_req->opt = buf;
			buf[0] = 0; /* dname for . */
			gldns_write_uint16(buf + 1, GLDNS_RR_TYPE_OPT);
			gldns_write_uint16(net_req->opt + 3,
			    net_req->max_udp_payload_size);
			buf[5] = edns_extended_rcode;
			buf[6] = edns_version;
			buf[7] = edns_do_bit ? 0x80 : 0;
			buf[8] = 0;
			gldns_write_uint16(buf + 9, opt_options_size);
			buf += 11;
			for (i = 0; i < noptions; i++) {
				if (getdns_list_get_dict(options, i, &option))
					continue;
				if (getdns_dict_get_int(
				    option, "option_code", &option_code))
					continue;
				if (getdns_dict_get_bindata(
				    option, "option_data", &option_data))
					continue;

				gldns_write_uint16(buf, (uint16_t) option_code);
				gldns_write_uint16(buf + 2,
				    (uint16_t) option_data->size);
				(void) memcpy(buf + 4, option_data->data,
				    option_data->size);

				buf += option_data->size + 4;
			}
		} else
			net_req->opt = NULL;
		net_req->response = buf;
		gldns_write_uint16(net_req->wire_data, net_req->response - net_req->query);
	} else {
		net_req->query    = NULL;
		net_req->opt      = NULL;
		net_req->response = net_req->wire_data;
	}
	return r;
}

void
dns_req_free(getdns_dns_req * req)
{
	getdns_network_req **net_req;
	if (!req) {
		return;
	}

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
	int dnssec_return_status
	    =  context->return_dnssec_status == GETDNS_EXTENSION_TRUE
	    || is_extension_set(extensions, "dnssec_return_status");
	int dnssec_return_only_secure
	    =  is_extension_set(extensions, "dnssec_return_only_secure");
	int dnssec_return_validation_chain
	    =  is_extension_set(extensions, "dnssec_return_validation_chain");
	int dnssec_extension_set = dnssec_return_status
	    || dnssec_return_only_secure || dnssec_return_validation_chain;

	uint32_t edns_do_bit;
	int      edns_maximum_udp_payload_size;
	uint32_t get_edns_maximum_udp_payload_size;
	uint32_t edns_extended_rcode;
	uint32_t edns_version;

	getdns_dict *add_opt_parameters;
	int     have_add_opt_parameters;

	getdns_list *options;
	size_t      noptions = 0;
	size_t       i;

	getdns_dict    *option;
	uint32_t        option_code;
	getdns_bindata *option_data;
	size_t opt_options_size = 0;

	int with_opt;

	getdns_dns_req *result = NULL;
        uint32_t klass = GLDNS_RR_CLASS_IN;
	int a_aaaa_query =
	    is_extension_set(extensions, "return_both_v4_and_v6") &&
	    ( request_type == GETDNS_RRTYPE_A ||
	      request_type == GETDNS_RRTYPE_AAAA );
	/* Reserve for the buffer at least one more byte
	 * (to test for udp overflow) (hence the + 1),
	 * And align on the 8 byte boundry  (hence the (x + 7) / 8 * 8)
	 */
	size_t max_query_sz, max_response_sz, netreq_sz, dnsreq_base_sz;
	uint8_t *region;
	
	have_add_opt_parameters = getdns_dict_get_dict(extensions,
	    "add_opt_parameters", &add_opt_parameters) == GETDNS_RETURN_GOOD;

	if (dnssec_extension_set) {
		edns_maximum_udp_payload_size = -1;
		edns_extended_rcode = 0;
		edns_version = 0;
		edns_do_bit = 1;
	} else {
		edns_maximum_udp_payload_size =
		    context->edns_maximum_udp_payload_size;
		edns_extended_rcode = context->edns_extended_rcode;
		edns_version = context->edns_version;
		edns_do_bit = context->edns_do_bit;

		if (have_add_opt_parameters) {
			if (!getdns_dict_get_int(add_opt_parameters,
			    "maximum_udp_payload_size",
			    &get_edns_maximum_udp_payload_size))
				edns_maximum_udp_payload_size =
				    get_edns_maximum_udp_payload_size;
			(void) getdns_dict_get_int(add_opt_parameters,
			    "extended_rcode", &edns_extended_rcode);
			(void) getdns_dict_get_int(add_opt_parameters,
			    "version", &edns_version);
			(void) getdns_dict_get_int(add_opt_parameters,
			    "do_bit", &edns_do_bit);
		}
	}
	if (have_add_opt_parameters && getdns_dict_get_list(
	    add_opt_parameters, "options", &options) == GETDNS_RETURN_GOOD)
		(void) getdns_list_get_length(options, &noptions);

	with_opt = edns_do_bit != 0 || edns_maximum_udp_payload_size != 512 ||
	    edns_extended_rcode != 0 || edns_version != 0 || noptions;

	edns_maximum_udp_payload_size = with_opt &&
	    ( edns_maximum_udp_payload_size == -1 ||
	      edns_maximum_udp_payload_size > 512 )
	    ? edns_maximum_udp_payload_size : 512;

	/* (x + 7) / 8 * 8 to align on 8 byte boundries */
	if (context->resolution_type == GETDNS_RESOLUTION_RECURSING)
		max_query_sz = 0;
	else {
		for (i = 0; i < noptions; i++) {
			if (getdns_list_get_dict(options, i, &option)) continue;
			if (getdns_dict_get_int(
			    option, "option_code", &option_code)) continue;
			if (getdns_dict_get_bindata(
			    option, "option_data", &option_data)) continue;

			opt_options_size += option_data->size
			    + 2 /* option-code   */
			    + 2 /* option-length */
			    ;
		}
		max_query_sz = ( GLDNS_HEADER_SIZE
		    + strlen(name) + 1 + 4 /* dname always smaller then strlen(name) + 1 */
		    + 12 + opt_options_size /* space needed for OPT (if needed) */
		    /* TODO: TSIG */
		    + 7) / 8 * 8;
	}
	max_response_sz = (( edns_maximum_udp_payload_size != -1
	                   ? edns_maximum_udp_payload_size : 1432
	                   ) + 1 /* +1 for udp overflow detection */
	                     + 7 ) / 8 * 8;

	netreq_sz = ( sizeof(getdns_network_req)
	            + max_query_sz + max_response_sz  + 7 ) / 8 * 8;
	dnsreq_base_sz = (( sizeof(getdns_dns_req) 
	                  + (a_aaaa_query ? 3 : 2) * sizeof(getdns_network_req*)
			  ) + 7) / 8 * 8;

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
	result->dnssec_return_status           = dnssec_return_status;
	result->dnssec_return_only_secure      = dnssec_return_only_secure;
	result->dnssec_return_validation_chain = dnssec_return_validation_chain;

	/* will be set by caller */
	result->user_pointer = NULL;
	result->user_callback = NULL;
	memset(&result->timeout, 0, sizeof(result->timeout));

        /* check the specify_class extension */
        (void) getdns_dict_get_int(extensions, "specify_class", &klass);
        
	result->upstreams = context->upstreams;
	if (result->upstreams)
		result->upstreams->referenced++;

	network_req_init(result->netreqs[0], result,
	    name, request_type, klass,
	    dnssec_extension_set, with_opt,
	    edns_maximum_udp_payload_size,
	    edns_extended_rcode, edns_version, edns_do_bit,
	    opt_options_size, noptions, options,
	    netreq_sz - sizeof(getdns_network_req), max_query_sz);

	if (a_aaaa_query)
		network_req_init(result->netreqs[1], result, name,
		    ( request_type == GETDNS_RRTYPE_A
		    ? GETDNS_RRTYPE_AAAA : GETDNS_RRTYPE_A ), klass,
		    dnssec_extension_set, with_opt,
		    edns_maximum_udp_payload_size,
		    edns_extended_rcode, edns_version, edns_do_bit,
		    opt_options_size, noptions, options,
		    netreq_sz - sizeof(getdns_network_req), max_query_sz);

	return result;
}
