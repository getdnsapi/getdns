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
		gldns_write_uint16(buf + 3,
		    (uint16_t) edns_maximum_udp_payload_size);
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
stub_next_upstream(getdns_network_req *netreq)
{
	getdns_dns_req *dnsreq = netreq->owner;

	if (! --netreq->upstream->to_retry) 
		netreq->upstream->to_retry = -(netreq->upstream->back_off *= 2);

	if (++dnsreq->upstreams->current > dnsreq->upstreams->count)
		dnsreq->upstreams->current = 0;
}

static void
stub_cleanup(getdns_network_req *netreq)
{
	getdns_dns_req *dnsreq = netreq->owner;
	getdns_network_req *r, *prev_r;
	getdns_upstream *upstream;
	intptr_t query_id_intptr;
	int reschedule;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	GETDNS_NULL_FREE(dnsreq->context->mf, netreq->tcp.write_buf);
	GETDNS_NULL_FREE(dnsreq->context->mf, netreq->tcp.read_buf);

	/* Nothing globally scheduled? Then nothing queued */
	if (!(upstream = netreq->upstream)->event.ev)
		return;

	/* Delete from upstream->netreq_by_query_id (if present) */
	query_id_intptr = (intptr_t)netreq->query_id;
	(void) getdns_rbtree_delete(
	    &upstream->netreq_by_query_id, (void *)query_id_intptr);

	/* Delete from upstream->write_queue (if present) */
	for (prev_r = NULL, r = upstream->write_queue; r;
	     prev_r = r, r = r->write_queue_tail)

		if (r == netreq) {
			if (prev_r)
				prev_r->write_queue_tail = r->write_queue_tail;
			else
				upstream->write_queue = r->write_queue_tail;

			if (r == upstream->write_queue_last)
				upstream->write_queue_last =
				    prev_r ? prev_r : NULL;
			break;
		}
	reschedule = 0;
	if (!upstream->write_queue && upstream->event.write_cb) {
		upstream->event.write_cb = NULL;
		reschedule = 1;
	}
	if (!upstream->netreq_by_query_id.count && upstream->event.read_cb) {
		upstream->event.read_cb = NULL;
		reschedule = 1;
	}
	if (reschedule) {
		GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
		if (upstream->event.read_cb || upstream->event.write_cb) 
			GETDNS_SCHEDULE_EVENT(upstream->loop,
			    upstream->fd, TIMEOUT_FOREVER, &upstream->event);
	}
}

static void
upstream_erred(getdns_upstream *upstream)
{
	getdns_network_req *netreq;

	while ((netreq = upstream->write_queue)) {
		stub_cleanup(netreq);
		netreq->state = NET_REQ_FINISHED;
		priv_getdns_check_dns_req_complete(netreq->owner);
	}
	while (upstream->netreq_by_query_id.count) {
		netreq = (getdns_network_req *)
		    getdns_rbtree_first(&upstream->netreq_by_query_id);
		stub_cleanup(netreq);
		netreq->state = NET_REQ_FINISHED;
		priv_getdns_check_dns_req_complete(netreq->owner);
	}
	close(upstream->fd);
	upstream->fd = -1;
}

void
priv_getdns_cancel_stub_request(getdns_network_req *netreq)
{
	stub_cleanup(netreq);
	if (netreq->fd >= 0) close(netreq->fd);
}

static void
stub_erred(getdns_network_req *netreq)
{
	stub_next_upstream(netreq);
	stub_cleanup(netreq);
	if (netreq->fd >= 0) close(netreq->fd);
	netreq->state = NET_REQ_FINISHED;
	priv_getdns_check_dns_req_complete(netreq->owner);
}

static void
stub_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;

	stub_next_upstream(netreq);
	stub_cleanup(netreq);
	if (netreq->fd >= 0) close(netreq->fd);
	(void) getdns_context_request_timed_out(netreq->owner);
}

static void
stub_udp_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;

	static size_t pkt_buf_len = 4096;
	size_t        pkt_len = pkt_buf_len;
	uint8_t       pkt_buf[pkt_buf_len];
	uint8_t      *pkt = pkt_buf;

	size_t read;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	read = recvfrom(netreq->fd, pkt, pkt_len, 0, NULL, NULL);
	if (read == -1 && (errno = EAGAIN || errno == EWOULDBLOCK))
		return;

	if (read < GLDNS_HEADER_SIZE)
		return; /* Not DNS */
	
	if (GLDNS_ID_WIRE(pkt) != netreq->query_id)
		return; /* Cache poisoning attempt ;) */

	close(netreq->fd);
	netreq->state = NET_REQ_FINISHED;
	ldns_wire2pkt(&(netreq->result), pkt, read);
	dnsreq->upstreams->current = 0;

	/* TODO: DNSSEC */
	netreq->secure = 0;
	netreq->bogus  = 0;

	priv_getdns_check_dns_req_complete(dnsreq);
}

static void
stub_udp_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;

	static size_t   pkt_buf_len = 4096;
	uint8_t         pkt_buf[pkt_buf_len];
	uint8_t        *pkt = pkt_buf;
	size_t          pkt_len;
	size_t          pkt_size_needed;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	pkt_size_needed = getdns_get_query_pkt_size(dnsreq->context,
	    dnsreq->name, netreq->request_type, dnsreq->extensions);

	if (pkt_size_needed > pkt_buf_len) {
		pkt = GETDNS_XMALLOC(
		    dnsreq->context->mf, uint8_t, pkt_size_needed);
		pkt_len = pkt_size_needed;
	} else
		pkt_len = pkt_buf_len;

	if (getdns_make_query_pkt_buf(dnsreq->context, dnsreq->name,
	    netreq->request_type, dnsreq->extensions, pkt_buf, &pkt_len))
		goto done;

	netreq->query_id = ldns_get_random();
	GLDNS_ID_SET(pkt, netreq->query_id);

	if (pkt_len != sendto(netreq->fd, pkt, pkt_len, 0,
	    (struct sockaddr *)&netreq->upstream->addr,
	                        netreq->upstream->addr_len)) {
		close(netreq->fd);
		goto done;
	}
	GETDNS_SCHEDULE_EVENT(
	    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
	    getdns_eventloop_event_init(&netreq->event, netreq,
	    stub_udp_read_cb, NULL, stub_timeout_cb));

done:
	if (pkt_size_needed > pkt_buf_len)
		GETDNS_FREE(dnsreq->context->mf, pkt);

	return;
}

static getdns_upstream *
pick_upstream(getdns_dns_req *dnsreq)
{
	getdns_upstream *upstream;
	size_t i;
	
	if (!dnsreq->upstreams->count)
		return NULL;

	for (i = 0; i < dnsreq->upstreams->count; i++)
		if (dnsreq->upstreams->upstreams[i].to_retry <= 0)
			dnsreq->upstreams->upstreams[i].to_retry++;

	i = dnsreq->upstreams->current;
	do {
		if (dnsreq->upstreams->upstreams[i].to_retry > 0) {
			dnsreq->upstreams->current = i;
			return &dnsreq->upstreams->upstreams[i];
		}
		if (++i > dnsreq->upstreams->count)
			i = 0;
	} while (i != dnsreq->upstreams->current);

	upstream = dnsreq->upstreams->upstreams;
	for (i = 1; i < dnsreq->upstreams->count; i++)
		if (dnsreq->upstreams->upstreams[i].back_off <
		    upstream->back_off)
			upstream = &dnsreq->upstreams->upstreams[i];

	upstream->back_off++;
	upstream->to_retry = 1;
	dnsreq->upstreams->current = upstream - dnsreq->upstreams->upstreams;
	return upstream;
}

#define STUB_TCP_AGAIN -2
#define STUB_TCP_ERROR -1

static int
stub_tcp_read(int fd, getdns_tcp_state *tcp, struct mem_funcs *mf)
{
	size_t   read;
	uint8_t *buf;
	size_t   buf_size;

	if (!tcp->read_buf) {
		/* First time tcp read, create a buffer for reading */
		if (!(tcp->read_buf = GETDNS_XMALLOC(*mf, uint8_t, 4096)))
			return STUB_TCP_ERROR;

		tcp->read_buf_len = 4096;
		tcp->read_pos = tcp->read_buf;
		tcp->to_read = 2; /* Packet size */
	}
	read = recv(fd, tcp->read_pos, tcp->to_read, 0);
	if (read == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return STUB_TCP_AGAIN;
		else
			return STUB_TCP_ERROR;
	} else if (read == 0) {
		/* Remote end closed the socket */
		/* TODO: Try to reconnect */
		return STUB_TCP_ERROR;
	}
	tcp->to_read  -= read;
	tcp->read_pos += read;
	
	if (tcp->to_read > 0)
		return STUB_TCP_AGAIN;

	read = tcp->read_pos - tcp->read_buf;
	if (read == 2) {
		/* Read the packet size short */
		tcp->to_read = gldns_read_uint16(tcp->read_buf);

		if (tcp->to_read < GLDNS_HEADER_SIZE)
			return STUB_TCP_ERROR;

		/* Resize our buffer if needed */
		if (tcp->to_read > tcp->read_buf_len) {
			buf_size = tcp->read_buf_len;
			while (tcp->to_read > buf_size)
				buf_size *= 2;

			if (!(buf = GETDNS_XREALLOC(*mf,
			    tcp->read_buf, uint8_t, tcp->read_buf_len)))
				return STUB_TCP_ERROR;

			tcp->read_buf = buf;
			tcp->read_buf_len = buf_size;
		}
		/* Ready to start reading the packet */
		tcp->read_pos = tcp->read_buf;
		return STUB_TCP_AGAIN;
	}
	return GLDNS_ID_WIRE(tcp->read_buf);
}

static void
stub_tcp_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;
	int q;

	switch ((q = stub_tcp_read(netreq->fd, &netreq->tcp,
	                          &dnsreq->context->mf))) {

	case STUB_TCP_AGAIN:
		return;

	case STUB_TCP_ERROR:
		stub_erred(netreq);
		return;

	default:
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
		if (q != netreq->query_id)
			return;
		/* TODO: fallback to TCP when TC bit set */
		netreq->state = NET_REQ_FINISHED;
		ldns_wire2pkt(&(netreq->result), netreq->tcp.read_buf,
		    netreq->tcp.read_pos - netreq->tcp.read_buf);
		dnsreq->upstreams->current = 0;

		/* TODO: DNSSEC */
		netreq->secure = 0;
		netreq->bogus  = 0;

		stub_cleanup(netreq);
		close(netreq->fd);
		priv_getdns_check_dns_req_complete(dnsreq);
	}
}

static void netreq_upstream_read_cb(void *userarg);
static void netreq_upstream_write_cb(void *userarg);
static void
upstream_read_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_network_req *netreq;
	getdns_dns_req *dnsreq;
	int q;
	uint16_t query_id;
	intptr_t query_id_intptr;

	switch ((q = stub_tcp_read(upstream->fd, &upstream->tcp,
	                          &upstream->upstreams->mf))) {
	case STUB_TCP_AGAIN:
		return;

	case STUB_TCP_ERROR:
		upstream_erred(upstream);
		return;

	default:
		/* Lookup netreq */
		query_id = (uint16_t) q;
		query_id_intptr = (intptr_t) query_id;
		netreq = (getdns_network_req *)getdns_rbtree_delete(
		    &upstream->netreq_by_query_id, (void *)query_id_intptr);
		if (! netreq) /* maybe canceled */
			break;

		netreq->state = NET_REQ_FINISHED;
		ldns_wire2pkt(&(netreq->result), upstream->tcp.read_buf,
		    upstream->tcp.read_pos - upstream->tcp.read_buf);
		upstream->upstreams->current = 0;

		/* TODO: DNSSEC */
		netreq->secure = 0;
		netreq->bogus  = 0;

		stub_cleanup(netreq);

		/* reset read buffer */
		upstream->tcp.read_pos = upstream->tcp.read_buf;
		upstream->tcp.to_read = 2;

		/* More the read/write for syncronous lookups? */
		if (netreq->event.read_cb) {
			dnsreq = netreq->owner;
			GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
			if (upstream->netreq_by_query_id.count ||
			    upstream->write_queue)
				GETDNS_SCHEDULE_EVENT(
				    dnsreq->loop, upstream->fd,
				    dnsreq->context->timeout,
				    getdns_eventloop_event_init(
				    &netreq->event, netreq,
				    ( upstream->netreq_by_query_id.count ?
				      netreq_upstream_read_cb : NULL ),
				    ( upstream->write_queue ?
				      netreq_upstream_write_cb : NULL),
				    stub_timeout_cb));
		}
		priv_getdns_check_dns_req_complete(netreq->owner);

		/* Nothing more to read? Then, deschedule the reads.*/
		if (! upstream->netreq_by_query_id.count) {
			upstream->event.read_cb = NULL;
			GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
			if (upstream->event.write_cb)
				GETDNS_SCHEDULE_EVENT(upstream->loop,
				    upstream->fd, TIMEOUT_FOREVER,
				    &upstream->event);
		}
	}
}

static void
netreq_upstream_read_cb(void *userarg)
{
	upstream_read_cb(((getdns_network_req *)userarg)->upstream);
}

/* stub_tcp_write(fd, tcp, netreq)
 * will return STUB_TCP_AGAIN when we need to come back again,
 * STUB_TCP_ERROR on error and a query_id on successfull sent.
 */
static int
stub_tcp_write(int fd, getdns_tcp_state *tcp, getdns_network_req *netreq)
{
	getdns_dns_req *dnsreq = netreq->owner;

	static size_t   pkt_buf_len = 4096;
	uint8_t         pkt_buf[pkt_buf_len];
	uint8_t        *pkt = pkt_buf;
	size_t          pkt_len;
	size_t          query_pkt_size;

	size_t          written;
	uint16_t        query_id;
	intptr_t        query_id_intptr;

	/* Do we have remaining data that we could write before?  */
	if (! tcp->write_buf) {
		/* Initial write. Create packet and try to send */
		query_pkt_size = getdns_get_query_pkt_size(dnsreq->context,
		    dnsreq->name, netreq->request_type, dnsreq->extensions);

		if (query_pkt_size + 2 > pkt_buf_len) {
			/* Not enough space in out stack buffer.
			 * Allocate a buffer on the heap.
			 */
			if (!(pkt = GETDNS_XMALLOC(dnsreq->context->mf,
			    uint8_t, query_pkt_size + 2)))
				return STUB_TCP_ERROR;

			tcp->write_buf = pkt;
			tcp->write_buf_len = query_pkt_size + 2;
			tcp->written = 0;

			pkt_len = query_pkt_size;
		} else
			pkt_len = pkt_buf_len - 2;

		/* Construct query packet */
		if (getdns_make_query_pkt_buf(dnsreq->context, dnsreq->name,
		    netreq->request_type,dnsreq->extensions,pkt + 2,&pkt_len))
			return STUB_TCP_ERROR;

		/* Prepend length short */
		gldns_write_uint16(pkt, pkt_len);

		/* Not keeping connections open? Then the first random number
		 * will do as the query id.
		 *
		 * Otherwise find a unique query_id not already written (or in
		 * the write_queue) for that upstream.  Register this netreq 
		 * by query_id in the process.
		 */
		if (dnsreq->context->dns_transport !=
		    GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN)

			query_id = ldns_get_random();
		else do {
			query_id = ldns_get_random();
			query_id_intptr = (intptr_t)query_id;
			netreq->node.key = (void *)query_id_intptr;

		} while (!getdns_rbtree_insert(
		    &netreq->upstream->netreq_by_query_id, &netreq->node));

		GLDNS_ID_SET(pkt + 2, query_id);

		/* We have an initialized packet buffer.
		 * Lets see how much of it we can write
		 */
		written = write(fd, pkt, pkt_len + 2);
		if ((written == -1 && (errno == EAGAIN ||
		                       errno == EWOULDBLOCK)) ||
		     written  < pkt_len + 2) {

			/* We couldn't write the whole packet.
			 * We have to return with STUB_TCP_AGAIN, but if
			 * the packet was on the stack only, we have to copy
			 * it to heap space fist, because the stack will be
			 * gone after return.
			 */
			if (!tcp->write_buf) {
				/* Copy stack packet buffer to heap  */
				if (!(tcp->write_buf = GETDNS_XMALLOC(
				    dnsreq->context->mf,uint8_t,pkt_len + 2)))
				 	return STUB_TCP_ERROR;
				(void) memcpy(pkt, pkt_buf, pkt_len + 2);
				tcp->write_buf_len = pkt_len + 2;
			}
			/* Because written could be -1 (and errno EAGAIN) */
			tcp->written = written >= 0 ? written : 0;

			return STUB_TCP_AGAIN;

		} else if (written == -1)
			return STUB_TCP_ERROR;

		/* We were able to write everything!  Start reading. */
		GETDNS_NULL_FREE(dnsreq->context->mf, tcp->write_buf);

	} else {/* if (! tcp->write_buf) */

		/* Coming back from an earlier unfinished write.
		 * Try to send remaining data */
		written = write(fd, tcp->write_buf     + tcp->written,
		                    tcp->write_buf_len - tcp->written);
		if (written == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return STUB_TCP_AGAIN;
			else
				return STUB_TCP_ERROR;
		}
		tcp->written += written;
		if (tcp->written < tcp->write_buf_len)
			/* Still more to send */
			return STUB_TCP_AGAIN;

		/* Done. Start reading */
		query_id = GLDNS_ID_WIRE(tcp->write_buf + 2);

	} /* if (! tcp->write_buf) */

	GETDNS_NULL_FREE(dnsreq->context->mf, tcp->write_buf);
	return (int) query_id;
}

static void
stub_tcp_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;
	int q;

	switch ((q = stub_tcp_write(netreq->fd, &netreq->tcp, netreq))) {
	case STUB_TCP_AGAIN:
		return;

	case STUB_TCP_ERROR:
		stub_erred(netreq);
		return;

	default:
		netreq->query_id = (uint16_t) q;
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		    stub_tcp_read_cb, NULL, stub_timeout_cb));
		return;
	}
}

static void
upstream_write_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_network_req *netreq = upstream->write_queue;
	getdns_dns_req *dnsreq = netreq->owner;
	int q;

	switch ((q = stub_tcp_write(upstream->fd, &upstream->tcp, netreq))) {
	case STUB_TCP_AGAIN:
		return;

	case STUB_TCP_ERROR:
		stub_erred(netreq);
		return;

	default:
		netreq->query_id = (uint16_t) q;

		/* Unqueue the netreq from the write_queue */
		if (!(upstream->write_queue = netreq->write_queue_tail)) {
			upstream->write_queue_last = NULL;
			upstream->event.write_cb = NULL;

			/* Reschedule (if already reading) to clear writable */
			if (upstream->event.read_cb) {
				GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
				GETDNS_SCHEDULE_EVENT(upstream->loop,
				    upstream->fd, TIMEOUT_FOREVER,
				    &upstream->event);
			}
		}
		/* Schedule reading (if not already scheduled) */
		if (!upstream->event.read_cb) {
			upstream->event.read_cb = upstream_read_cb;
			GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
			GETDNS_SCHEDULE_EVENT(upstream->loop,
			    upstream->fd, TIMEOUT_FOREVER, &upstream->event);
		}
		/* With synchonous lookups, schedule the read locally too */
		if (netreq->event.write_cb) {
			GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
			GETDNS_SCHEDULE_EVENT(
			    dnsreq->loop, upstream->fd, dnsreq->context->timeout,
			    getdns_eventloop_event_init(&netreq->event, netreq,
			    netreq_upstream_read_cb,
			    ( upstream->write_queue ?
			      netreq_upstream_write_cb : NULL),
			    stub_timeout_cb));
		}
		return;
	}
}

static void
netreq_upstream_write_cb(void *userarg)
{
	upstream_write_cb(((getdns_network_req *)userarg)->upstream);
}

static void
upstream_schedule_netreq(getdns_upstream *upstream, getdns_network_req *netreq)
{
	/* We have a connected socket and a global event loop */
	assert(upstream->fd >= 0);
	assert(upstream->loop);

	/* Append netreq to write_queue */
	if (!upstream->write_queue) {
		upstream->write_queue = upstream->write_queue_last = netreq;
		upstream->event.write_cb = upstream_write_cb;
		GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
		GETDNS_SCHEDULE_EVENT(upstream->loop,
		    upstream->fd, TIMEOUT_FOREVER, &upstream->event);
	} else {
		upstream->write_queue_last->write_queue_tail = netreq;
		upstream->write_queue_last = netreq;
	}
}

getdns_return_t
priv_getdns_submit_stub_request(getdns_network_req *netreq)
{
	getdns_dns_req  *dnsreq   = netreq->owner;
	getdns_upstream *upstream = pick_upstream(dnsreq);

	if (!upstream)
	    	return GETDNS_RETURN_GENERIC_ERROR;

	switch(dnsreq->context->dns_transport) {
	case GETDNS_TRANSPORT_UDP_ONLY:
	case GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP:

		if ((netreq->fd = socket(
		    upstream->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
			return GETDNS_RETURN_GENERIC_ERROR;

		getdns_sock_nonblock(netreq->fd);
		netreq->upstream = upstream;

		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		    NULL, stub_udp_write_cb, stub_timeout_cb));

		return GETDNS_RETURN_GOOD;

	case GETDNS_TRANSPORT_TCP_ONLY:

		if ((netreq->fd = socket(
		    upstream->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
			return GETDNS_RETURN_GENERIC_ERROR;
		
		getdns_sock_nonblock(netreq->fd);
		if (connect(netreq->fd, (struct sockaddr *)&upstream->addr,
		    upstream->addr_len) == -1 && errno != EINPROGRESS) {

			close(netreq->fd);
			return GETDNS_RETURN_GENERIC_ERROR;
		}
		netreq->upstream = upstream;

		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		    NULL, stub_tcp_write_cb, stub_timeout_cb));

		return GETDNS_RETURN_GOOD;
	
	case GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN:
		
		/* In coming comments, "global" means "context wide" */

		/* Are we the first? (Is global socket initialized?) */
		if (upstream->fd == -1) {
			/* We are the first. Make global socket and connect. */
			if ((upstream->fd = socket(upstream->addr.ss_family,
			    SOCK_STREAM, IPPROTO_TCP)) == -1)
				return GETDNS_RETURN_GENERIC_ERROR;
			
			getdns_sock_nonblock(upstream->fd);
			if (connect(upstream->fd,
			    (struct sockaddr *)&upstream->addr,
			    upstream->addr_len) == -1 && errno != EINPROGRESS){

				close(upstream->fd);
				upstream->fd = -1;
				return GETDNS_RETURN_GENERIC_ERROR;
			}
			/* Attach to the global event loop
			 * so it can do it's own scheduling
			 */
			upstream->loop = dnsreq->context->extension;
		}
		netreq->upstream = upstream;

		/* We have a context wide socket.
		 * Now schedule the write request.
		 */
		upstream_schedule_netreq(upstream, netreq);

		/* Schedule at least the timeout locally.
		 * And also the write if we perform a synchronous lookup
		 */
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, upstream->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq, NULL,
		    ( dnsreq->loop != upstream->loop /* Synchronous lookup? */
		    ? netreq_upstream_write_cb : NULL), stub_timeout_cb));

		return GETDNS_RETURN_GOOD;
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}

/* stub.c */
