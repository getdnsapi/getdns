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
#include "gldns/gbuffer.h"
#include "gldns/pkthdr.h"
#include "context.h"
#include <ldns/util.h>
#include "util-internal.h"
#include "general.h"


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

static void stub_tcp_write_cb(void *userarg);
static void
stub_udp_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;
	getdns_upstream *upstream = netreq->upstream;

	ssize_t       read;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	read = recvfrom(netreq->fd, netreq->response,
	    netreq->max_udp_payload_size + 1, /* If read == max_udp_payload_size
	                                       * then all is good.  If read ==
	                                       * max_udp_payload_size + 1, then
	                                       * we receive more then requested!
	                                       * i.e. overflow
	                                       */
	    0, NULL, NULL);
	if (read == -1 && (errno = EAGAIN || errno == EWOULDBLOCK))
		return;

	if (read < GLDNS_HEADER_SIZE)
		return; /* Not DNS */
	
	if (GLDNS_ID_WIRE(netreq->response) != netreq->query_id)
		return; /* Cache poisoning attempt ;) */

	close(netreq->fd);
	if (GLDNS_TC_WIRE(netreq->response) &&
	    dnsreq->context->dns_transport ==
	    GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP) {

		if ((netreq->fd = socket(
		    upstream->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
			goto done;
		
		getdns_sock_nonblock(netreq->fd);
		if (connect(netreq->fd, (struct sockaddr *)&upstream->addr,
		    upstream->addr_len) == -1 && errno != EINPROGRESS) {

			close(netreq->fd);
			goto done;
		}
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		    NULL, stub_tcp_write_cb, stub_timeout_cb));

		return;
	}
	ldns_wire2pkt(&(netreq->result), netreq->response, (size_t)read);
	dnsreq->upstreams->current = 0;

	/* TODO: DNSSEC */
	netreq->secure = 0;
	netreq->bogus  = 0;
done:
	netreq->state = NET_REQ_FINISHED;
	priv_getdns_check_dns_req_complete(dnsreq);
}

static void
stub_udp_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req     *dnsreq = netreq->owner;
	size_t             pkt_len = netreq->response - netreq->query;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	netreq->query_id = ldns_get_random();
	GLDNS_ID_SET(netreq->query, netreq->query_id);
	if (netreq->edns_maximum_udp_payload_size == -1)
		gldns_write_uint16(netreq->opt + 3,
		    ( netreq->max_udp_payload_size =
		      netreq->upstream->addr.ss_family == AF_INET6
		    ? 1232 : 1432));

	if ((ssize_t)pkt_len != sendto(netreq->fd, netreq->query, pkt_len, 0,
	    (struct sockaddr *)&netreq->upstream->addr,
	                        netreq->upstream->addr_len)) {
		close(netreq->fd);
		return;
	}
	GETDNS_SCHEDULE_EVENT(
	    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
	    getdns_eventloop_event_init(&netreq->event, netreq,
	    stub_udp_read_cb, NULL, stub_timeout_cb));
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
	ssize_t  read;
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
		netreq->state = NET_REQ_FINISHED;
		netreq->response = netreq->tcp.read_buf;
		netreq->max_udp_payload_size =
		    netreq->tcp.read_pos - netreq->tcp.read_buf;
		netreq->tcp.read_buf = NULL;
		ldns_wire2pkt(&(netreq->result), netreq->response,
		    netreq->max_udp_payload_size);
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
		if (! netreq) /* maybe canceled */ {
			/* reset read buffer */
			upstream->tcp.read_pos = upstream->tcp.read_buf;
			upstream->tcp.to_read = 2;
			return;
		}

		netreq->state = NET_REQ_FINISHED;
		netreq->response = upstream->tcp.read_buf;
		netreq->max_udp_payload_size =
		    upstream->tcp.read_pos - upstream->tcp.read_buf;
		upstream->tcp.read_buf = NULL;
		ldns_wire2pkt(&(netreq->result), netreq->response,
		    netreq->max_udp_payload_size);
		upstream->upstreams->current = 0;

		/* TODO: DNSSEC */
		netreq->secure = 0;
		netreq->bogus  = 0;

		stub_cleanup(netreq);

		/* More to read/write for syncronous lookups? */
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

		/* Nothing more to read? Then deschedule the reads.*/
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

	size_t          pkt_len = netreq->response - netreq->query;
	ssize_t         written;
	uint16_t        query_id;
	intptr_t        query_id_intptr;

	/* Do we have remaining data that we could not write before?  */
	if (! tcp->write_buf) {
		/* No, this is an initial write. Try to send
		 */

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

		GLDNS_ID_SET(netreq->query, query_id);
		gldns_write_uint16(netreq->opt + 3, 65535); /* no limits on the
							       max udp payload
							       size with tcp */

		/* We have an initialized packet buffer.
		 * Lets see how much of it we can write
		 */
#ifdef USE_TCP_FASTOPEN
		/* We use sendto() here which will do both a connect and send */
		written = sendto(fd, netreq->query - 2, pkt_len + 2,
		    MSG_FASTOPEN, (struct sockaddr *)&(netreq->upstream->addr),
		    netreq->upstream->addr_len);
		/* If pipelining we will find that the connection is already up so 
		   just fall back to a 'normal' write. */
		if (written == -1 && errno == EISCONN) 
			written = write(fd, netreq->query - 2, pkt_len + 2);

		if ((written == -1 && (errno == EAGAIN ||
		                       errno == EWOULDBLOCK ||
		/* Add the error case where the connection is in progress which is when
		   a cookie is not available (e.g. when doing the first request to an
		   upstream). We must let the handshake complete since non-blocking. */
		                       errno == EINPROGRESS)) ||
		     written  < pkt_len + 2) {
#else
		written = write(fd, netreq->query - 2, pkt_len + 2);
		if ((written == -1 && (errno == EAGAIN ||
		                       errno == EWOULDBLOCK)) ||
		     written  < pkt_len + 2) {
#endif
			/* We couldn't write the whole packet.
			 * We have to return with STUB_TCP_AGAIN.
			 * Setup tcp to track the state.
			 */
			tcp->write_buf = netreq->query - 2;
			tcp->write_buf_len = pkt_len + 2;
			tcp->written = written >= 0 ? written : 0;

			return STUB_TCP_AGAIN;

		} else if (written == -1)
			return STUB_TCP_ERROR;

		/* We were able to write everything!  Start reading. */
		return (int) query_id;

	} else {/* if (! tcp->write_buf) */

		/* Coming back from an earlier unfinished write or handshake.
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
		tcp->write_buf = NULL;
		return (int)GLDNS_ID_WIRE(tcp->write_buf + 2);

	} /* if (! tcp->write_buf) */
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
#ifdef USE_TCP_FASTOPEN
		/* Leave the connect to the later call to sendto() */
#else
		if (connect(netreq->fd, (struct sockaddr *)&upstream->addr,
		    upstream->addr_len) == -1 && errno != EINPROGRESS) {

			close(netreq->fd);
			return GETDNS_RETURN_GENERIC_ERROR;
		}
#endif
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
#ifdef USE_TCP_FASTOPEN
		/* Leave the connect to the later call to sendto() */
#else
			if (connect(upstream->fd,
			    (struct sockaddr *)&upstream->addr,
			    upstream->addr_len) == -1 && errno != EINPROGRESS){

				close(upstream->fd);
				upstream->fd = -1;
				return GETDNS_RETURN_GENERIC_ERROR;
			}
#endif
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
