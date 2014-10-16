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
#include <fcntl.h>
#include "stub.h"
#include "gldns/rrdef.h"
#include "gldns/str2wire.h"
#include "gldns/gbuffer.h"
#include "gldns/pkthdr.h"
#include "context.h"
#include <ldns/util.h>
#include "util-internal.h"
#include "general.h"

static int
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
static size_t
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

/** best effort to set nonblocking */
static void
getdns_sock_nonblock(int sockfd)
{
#ifdef HAVE_FCNTL
	int flag;
	if((flag = fcntl(sockfd, F_GETFL)) != -1) {
		flag |= O_NONBLOCK;
		if(fcntl(sockfd, F_SETFL, flag) == -1) {
			/* ignore error, continue blockingly */
		}
	}
#elif defined(HAVE_IOCTLSOCKET)
	unsigned long on = 1;
	if(ioctlsocket(sockfd, FIONBIO, &on) != 0) {
		/* ignore error, continue blockingly */
	}
#endif
}

static void
stub_resolve_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dns_req = netreq->owner;

	if (! --netreq->upstream->to_retry) 
		netreq->upstream->to_retry = -(netreq->upstream->back_off *= 2);

	if (++dns_req->upstreams->current > dns_req->upstreams->count)
		dns_req->upstreams->current = 0;

	(void) getdns_context_request_timed_out(dns_req);
}

static void
stub_resolve_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dns_req = netreq->owner;

	static size_t pkt_buf_len = 4096;
	size_t        pkt_len = pkt_buf_len;
	uint8_t       pkt_buf[pkt_buf_len];
	uint8_t      *pkt = pkt_buf;

	size_t read;

	dns_req->loop->vmt->clear(dns_req->loop, &netreq->event);

	read = recvfrom(netreq->udp_fd, pkt, pkt_len, 0, NULL, NULL);
	if (read == -1 && (errno = EAGAIN || errno == EWOULDBLOCK))
		return;

	if (read < GLDNS_HEADER_SIZE)
		return; /* Not DNS */
	
	if (GLDNS_ID_WIRE(pkt) != netreq->query_id)
		return; /* Cache poisoning attempt ;) */

	close(netreq->udp_fd);
	netreq->state = NET_REQ_FINISHED;
	ldns_wire2pkt(&(netreq->result), pkt, read);
	dns_req->upstreams->current = 0;

	/* Do the dnssec here */
	netreq->secure = 0;
	netreq->bogus  = 0;

	priv_getdns_check_dns_req_complete(dns_req);
}

static void
stub_resolve_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dns_req = netreq->owner;

	static size_t   pkt_buf_len = 4096;
	uint8_t         pkt_buf[pkt_buf_len];
	uint8_t        *pkt = pkt_buf;
	size_t          pkt_len;
	size_t          pkt_size_needed;

	dns_req->loop->vmt->clear(dns_req->loop, &netreq->event);

	pkt_size_needed = getdns_get_query_pkt_size(dns_req->context,
	    dns_req->name, netreq->request_type, dns_req->extensions);

	if (pkt_size_needed > pkt_buf_len) {
		pkt = GETDNS_XMALLOC(
		    dns_req->context->mf, uint8_t, pkt_size_needed);
		pkt_len = pkt_size_needed;
	} else
		pkt_len = pkt_buf_len;

	if (getdns_make_query_pkt_buf(dns_req->context, dns_req->name,
	    netreq->request_type, dns_req->extensions, pkt_buf, &pkt_len))
		goto done;

	netreq->query_id = ldns_get_random();
	GLDNS_ID_SET(pkt, netreq->query_id);

	if (pkt_len != sendto(netreq->udp_fd, pkt, pkt_len, 0,
	    (struct sockaddr *)&netreq->upstream->addr,
	                        netreq->upstream->addr_len)) {
		close(netreq->udp_fd);
		goto done;
	}

	netreq->event.userarg    = netreq;
	netreq->event.read_cb    = stub_resolve_read_cb;
	netreq->event.write_cb   = NULL;
	netreq->event.timeout_cb = stub_resolve_timeout_cb;
	netreq->event.ev         = NULL;
	dns_req->loop->vmt->schedule(dns_req->loop,
	    netreq->udp_fd, dns_req->context->timeout, &netreq->event);

done:
	if (pkt_size_needed > pkt_buf_len)
		GETDNS_FREE(dns_req->context->mf, pkt);

	return;
}

static getdns_upstream *
pick_upstream(getdns_dns_req *dns_req)
{
	getdns_upstream *upstream;
	size_t i;
	
	if (!dns_req->upstreams->count)
		return NULL;

	for (i = 0; i < dns_req->upstreams->count; i++)
		if (dns_req->upstreams->upstreams[i].to_retry <= 0)
			dns_req->upstreams->upstreams[i].to_retry++;

	i = dns_req->upstreams->current;
	do {
		if (dns_req->upstreams->upstreams[i].to_retry > 0) {
			dns_req->upstreams->current = i;
			return &dns_req->upstreams->upstreams[i];
		}
		if (++i > dns_req->upstreams->count)
			i = 0;
	} while (i != dns_req->upstreams->current);

	upstream = dns_req->upstreams->upstreams;
	for (i = 1; i < dns_req->upstreams->count; i++)
		if (dns_req->upstreams->upstreams[i].back_off <
		    upstream->back_off)
			upstream = &dns_req->upstreams->upstreams[i];

	upstream->back_off++;
	upstream->to_retry = 1;
	dns_req->upstreams->current = upstream - dns_req->upstreams->upstreams;
	return upstream;
}

getdns_return_t
priv_getdns_submit_stub_request(getdns_network_req *netreq)
{
	getdns_dns_req *dns_req = netreq->owner;

	getdns_upstream *upstream;

	/* TODO: TCP */
	if (dns_req->context->dns_transport != GETDNS_TRANSPORT_UDP_ONLY &&
	    dns_req->context->dns_transport !=
	    GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP)
	    	return GETDNS_RETURN_GENERIC_ERROR;

	if (!(upstream = pick_upstream(dns_req)))
		return GETDNS_RETURN_GENERIC_ERROR;

	if ((netreq->udp_fd = socket(
	    upstream->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return GETDNS_RETURN_GENERIC_ERROR;
	netreq->upstream = upstream;

	getdns_sock_nonblock(netreq->udp_fd);

	netreq->event.userarg    = netreq;
	netreq->event.read_cb    = NULL;
	netreq->event.write_cb   = stub_resolve_write_cb;
	netreq->event.timeout_cb = stub_resolve_timeout_cb;
	netreq->event.ev         = NULL;
	dns_req->loop->vmt->schedule(dns_req->loop,
	    netreq->udp_fd, dns_req->context->timeout, &netreq->event);

	return GETDNS_RETURN_GOOD;
}

/* stub.c */
