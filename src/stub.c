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

#include "config.h"
#include "stub.h"
#include "gldns/rrdef.h"
#include "gldns/str2wire.h"
#include "gldns/pkthdr.h"
#include "context.h"
#include <ldns/util.h>
#include "util-internal.h"
#include "gldns/gbuffer.h"
#include "gldns/wire2str.h"
#include "extension/libmini_event.h"

#define STUBDEBUG 1

typedef struct stub_resolver {
	getdns_eventloop *ext;
	getdns_context   *context;
	getdns_upstreams *upstreams;
	const char       *name;
	uint16_t          request_type;
	getdns_dict      *extensions;
	gldns_buffer     *response;

	
	size_t   request_pkt_len;
	uint8_t *request_pkt;

	size_t   ns_index;
	size_t   to_retry;
	int      udp_fd;

	getdns_eventloop_event event;
} stub_resolver;

static void
udp_request_timeout_cb(void *arg)
{
	stub_resolver *resolver = (stub_resolver *)arg;
	resolver->ext->vmt->clear(resolver->ext, &resolver->event);
	fprintf(stderr, "TIMEOUT!\n");
}

static void
udp_request_read_cb(void *arg)
{
	stub_resolver *resolver = (stub_resolver *)arg;
	ssize_t read;

	resolver->ext->vmt->clear(resolver->ext, &resolver->event);

	read = recvfrom(resolver->udp_fd,
	    gldns_buffer_current(resolver->response),
	    gldns_buffer_remaining(resolver->response),
	    0, NULL, NULL);

	if (read == -1 || read == 0)
		return;

	gldns_buffer_skip(resolver->response, read);
	gldns_buffer_flip(resolver->response);
#if STUBDEBUG
	do {
		char *str = gldns_wire2str_pkt(
		    gldns_buffer_current(resolver->response),
		    gldns_buffer_limit(resolver->response));
		fprintf(stderr, "%s\n", str);
		free(str);
	} while(0);
#endif
}

static getdns_return_t
query_ns(stub_resolver *resolver)
{
	struct getdns_upstream *upstream;
	ssize_t sent;

	assert(resolver);

	if (resolver->ns_index >= resolver->upstreams->count)
		return GETDNS_RETURN_GENERIC_ERROR;

	upstream = &resolver->upstreams->upstreams[resolver->ns_index];
	/* TODO: Try next upstream if something is not right with this one
	 */

	/* TODO: Check how to connect first (udp or tcp) */

	resolver->udp_fd = socket(upstream->addr.ss_family, SOCK_DGRAM,
	    IPPROTO_UDP);
	if (resolver->udp_fd == -1) {
		/* Retry with tcp? */
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	
	sent = sendto(resolver->udp_fd,
	    resolver->request_pkt, resolver->request_pkt_len, 0,
	    (struct sockaddr *)&upstream->addr, upstream->addr_len);
	if (sent == -1 || sent != resolver->request_pkt_len)
		return GETDNS_RETURN_GENERIC_ERROR;
	
	resolver->event.userarg    = resolver;
	resolver->event.read_cb    = udp_request_read_cb;
	resolver->event.write_cb   = NULL;
	resolver->event.timeout_cb = udp_request_timeout_cb;
	resolver->ext->vmt->schedule(resolver->ext, resolver->udp_fd,
	    resolver->context->timeout, &resolver->event);

	return GETDNS_RETURN_GOOD;
}

getdns_return_t 
getdns_stub_dns_query_async(struct getdns_eventloop *ext,
    getdns_context *context, const char *name, uint16_t request_type,
    getdns_dict *extensions, gldns_buffer *response)
{
	getdns_return_t r;
	stub_resolver *resolver;
	
	resolver = GETDNS_MALLOC(context->mf, stub_resolver);
	if (! resolver)
		return GETDNS_RETURN_MEMORY_ERROR;

	resolver->ext          = ext;
	resolver->context      = context;
	resolver->upstreams    = context->upstreams;
	resolver->upstreams->referenced++;
	resolver->name         = name;
	resolver->request_type = request_type;
	resolver->extensions   = extensions;
	resolver->response     = response;
	resolver->request_pkt  = getdns_make_query_pkt(context,
	    name, request_type, extensions, &resolver->request_pkt_len);
	if (! resolver->request_pkt) {
		GETDNS_FREE(context->mf, resolver);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
#if STUBDEBUG
	do {
		char *str = gldns_wire2str_pkt(
		    resolver->request_pkt, resolver->request_pkt_len);
		fprintf(stderr, "%s\n", str);
		free(str);
	} while(0);
#endif
	resolver->ns_index     = 0;
	resolver->to_retry     = 2;
	r = query_ns(resolver);
	if (r) {
		if (--resolver->upstreams->referenced == 0)
			GETDNS_FREE(resolver->upstreams->mf, resolver->upstreams);
		GETDNS_FREE(context->mf, resolver);
	}
	return r;
}

getdns_return_t
getdns_stub_dns_query_sync(
    getdns_context *context, const char *name, uint16_t request_type,
    getdns_dict *extensions, gldns_buffer *response)
{
	getdns_return_t r;
	getdns_mini_event mini_event;
	getdns_eventloop *ext = &mini_event.loop;
	
	r = getdns_mini_event_init(context, &mini_event);
	if (r)
		return r;

	r = getdns_stub_dns_query_async(ext, context, name, request_type,
	    extensions, response);
	if (r)
		return r;

	ext->vmt->run(ext);
	return GETDNS_RETURN_GOOD;
}

int
getdns_make_query_pkt_buf(getdns_context *context, const char *name,
    uint16_t request_type, getdns_dict *extensions, uint8_t* buf, size_t* olen)
{
	uint32_t klass = GLDNS_RR_CLASS_IN;
	size_t len;

	int dnssec_return_status
	    = is_extension_set(extensions, "dnssec_return_status");
	int dnssec_return_only_secure
	    = is_extension_set(extensions, "dnssec_return_only_secure");
	int dnssec_return_validation_chain
	    = is_extension_set(extensions, "dnssec_return_validation_chain");
	int dnssec_extension_set = dnssec_return_status
	    || dnssec_return_only_secure || dnssec_return_validation_chain;

	uint32_t edns_do_bit;
	uint32_t edns_maximum_udp_payload_size;
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
	int r;
	size_t dname_len;
	
	have_add_opt_parameters = getdns_dict_get_dict(extensions,
	    "add_opt_parameters", &add_opt_parameters) == GETDNS_RETURN_GOOD;

	if (dnssec_extension_set) {
		edns_maximum_udp_payload_size = 1232;
		edns_extended_rcode = 0;
		edns_version = 0;
		edns_do_bit = 1;
	} else {
		edns_maximum_udp_payload_size
		    = context->edns_maximum_udp_payload_size;
		edns_extended_rcode = context->edns_extended_rcode;
		edns_version = context->edns_version;
		edns_do_bit = context->edns_do_bit;

		if (have_add_opt_parameters) {
			(void) getdns_dict_get_int(add_opt_parameters,
			    "maximum_udp_payload_size",
			    &edns_maximum_udp_payload_size);
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

	with_opt = edns_do_bit || edns_maximum_udp_payload_size > 512
	    || edns_extended_rcode != 0 || edns_version != 0
	    || opt_options_size > 0;

	assert(buf);
	assert(olen);

	len = *olen;
	*olen = 0;

	(void) getdns_dict_get_int(extensions, "specify_class", &klass);

	if (len < GLDNS_HEADER_SIZE)
		return GLDNS_WIREPARSE_ERR_BUFFER_TOO_SMALL;

	gldns_write_uint16(buf + 2, 0); /* reset all flags */
	GLDNS_RD_SET(buf);
	if (dnssec_extension_set) /* We will do validation outselves */
		GLDNS_CD_SET(buf);
	GLDNS_OPCODE_SET(buf, GLDNS_PACKET_QUERY);
	gldns_write_uint16(buf + GLDNS_QDCOUNT_OFF, 1); /* 1 query */
	gldns_write_uint16(buf + GLDNS_ANCOUNT_OFF, 0); /* 0 answers */
	gldns_write_uint16(buf + GLDNS_NSCOUNT_OFF, 0); /* 0 authorities */
	gldns_write_uint16(buf + GLDNS_ARCOUNT_OFF, with_opt ? 1 : 0);

	len   -= GLDNS_HEADER_SIZE;
	*olen += GLDNS_HEADER_SIZE;
	buf   += GLDNS_HEADER_SIZE;

	dname_len = len;
	if ((r = gldns_str2wire_dname_buf(name, buf, &dname_len))) return r;
	len   -= dname_len;
	*olen += dname_len;
	buf   += dname_len;

	if (len < 4)
		return GLDNS_WIREPARSE_ERR_BUFFER_TOO_SMALL;
	gldns_write_uint16(buf, request_type);
	gldns_write_uint16(buf + 2, klass);
	len   -= 4;
	*olen += 4;
	buf   += 4;

	if (with_opt) {
		if (len < 11)
			return GLDNS_WIREPARSE_ERR_BUFFER_TOO_SMALL;

		buf[0] = 0; /* dname for . */
		gldns_write_uint16(buf + 1, GLDNS_RR_TYPE_OPT);
		gldns_write_uint16(buf + 3, (uint16_t) edns_maximum_udp_payload_size);
		buf[5] = (uint8_t) edns_extended_rcode;
		buf[6] = (uint8_t) edns_version;
		buf[7] = edns_do_bit ? 0x80 : 0;
		buf[8] = 0;
		gldns_write_uint16(buf + 9, (uint16_t) opt_options_size);
		len   -= 11;
		*olen += 11;
		buf   += 11;
		for (i = 0; i < noptions; i++) {
			if (getdns_list_get_dict(options, i, &option))
			    continue;
			if (getdns_dict_get_int(
			    option, "option_code", &option_code)) continue;
			if (getdns_dict_get_bindata(
			    option, "option_data", &option_data)) continue;

			if (len < option_data->size + 4) {
				gldns_write_uint16(buf - opt_options_size - 2,
				    (uint16_t) opt_options_size);
				return GLDNS_WIREPARSE_ERR_BUFFER_TOO_SMALL;
			}
			gldns_write_uint16(buf, (uint16_t) option_code);
			gldns_write_uint16(buf + 2,
			    (uint16_t) option_data->size);
			(void) memcpy(buf + 4, option_data->data,
			    option_data->size);

			opt_options_size += option_data->size + 4;
			len              -= option_data->size + 4;
			*olen            += option_data->size + 4;
			buf              += option_data->size + 4;
		}
		gldns_write_uint16(buf - opt_options_size - 2,
		    (uint16_t) opt_options_size);
	}
	return 0;
}


/* Return a rough estimate for mallocs */
size_t
getdns_get_query_pkt_size(getdns_context *context,
    const char *name, uint16_t request_type, getdns_dict *extensions)
{
	getdns_dict *add_opt_parameters;

	getdns_list *options;
	size_t      noptions = 0;
	size_t       i;

	getdns_dict    *option;
	uint32_t        option_code;
	getdns_bindata *option_data;
	size_t opt_options_size = 0;

	do {
		if (getdns_dict_get_dict(extensions,
		    "add_opt_parameters", &add_opt_parameters)) break;
		if (getdns_dict_get_list(
		    add_opt_parameters, "options", &options)) break;
		if (getdns_list_get_length(options, &noptions)) break;

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
	} while (0);
	
	return GLDNS_HEADER_SIZE
	    + strlen(name) + 1 + 4 /* dname always smaller then strlen(name) + 1 */
	    + 12 + opt_options_size /* space needed for OPT (if needed) */
	    /* TODO: TSIG */
	    ;
}


uint8_t *
getdns_make_query_pkt(getdns_context *context, const char *name,
    uint16_t request_type, getdns_dict *extensions, size_t *pkt_len)
{
	size_t query_pkt_sz = getdns_get_query_pkt_size(
	    context, name, request_type, extensions);
	uint8_t *query_pkt = GETDNS_XMALLOC(context->mf, uint8_t, query_pkt_sz);

	if (query_pkt) {
		if (getdns_make_query_pkt_buf(context, name, request_type,
		    extensions, query_pkt, &query_pkt_sz)) {
			GETDNS_FREE(context->mf, query_pkt);
			return NULL;
		}
	}
	*pkt_len = query_pkt_sz;
	return query_pkt;
}

/* stub.c */
