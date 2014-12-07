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

#define TLS_PORT 1021

static time_t secret_rollover_time = 0;
static uint32_t secret = 0;
static uint32_t prev_secret = 0;

static void
rollover_secret()
{
	time_t now = 0;

	/* Create and roll server secrets */
	if (time(&now) <= secret_rollover_time)
		return;

	/* Remember previous secret, in to keep answering on rollover
	 * boundry with old cookie.
	 */
	prev_secret = secret;
	secret = arc4random();

	/* Next rollover over EDNS_COOKIE_ROLLOVER_TIME with 30% jitter,
	 * I.e. some offset + or - 15% of the future point in time.
	 */
	secret_rollover_time = now + (EDNS_COOKIE_ROLLOVER_TIME / 20 * 17)
		 + arc4random_uniform(EDNS_COOKIE_ROLLOVER_TIME / 10 * 3);
}

static void
calc_new_cookie(getdns_upstream *upstream, uint8_t *cookie)
{
        const EVP_MD *md;
        EVP_MD_CTX *mdctx;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        size_t i;
        sa_family_t af = upstream->addr.ss_family;
        void *sa_addr = ((struct sockaddr*)&upstream->addr)->sa_data;
	size_t addr_len = ( af == AF_INET6 ? sizeof(struct sockaddr_in6)
	                  : af == AF_INET  ? sizeof(struct sockaddr_in)
	                  : 0 ) - sizeof(sa_family_t);

        md = EVP_sha256();
        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, &secret, sizeof(secret));
        EVP_DigestUpdate(mdctx, sa_addr, addr_len);
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_destroy(mdctx);

        (void) memset(cookie, 0, 8);
        for (i = 0; i < md_len; i++)
                cookie[i % 8] ^= md_value[i];
}

static uint8_t *
attach_edns_cookie(getdns_upstream *upstream, uint8_t *opt)
{
	rollover_secret();

	if (!upstream->has_client_cookie) {
		calc_new_cookie(upstream, upstream->client_cookie);
		upstream->secret = secret;
		upstream->has_client_cookie = 1;

		gldns_write_uint16(opt +  9, 12); /* rdata len */
		gldns_write_uint16(opt + 11, EDNS_COOKIE_OPCODE);
		gldns_write_uint16(opt + 13,  8); /* opt len */
		memcpy(opt + 15, upstream->client_cookie, 8);
		return opt + 23;

	} else if (upstream->secret != secret) {
		memcpy( upstream->prev_client_cookie
		      , upstream->client_cookie, 8);
		upstream->has_prev_client_cookie = 1;
		calc_new_cookie(upstream, upstream->client_cookie);
		upstream->secret = secret;

		gldns_write_uint16(opt +  9, 12); /* rdata len */
		gldns_write_uint16(opt + 11, EDNS_COOKIE_OPCODE);
		gldns_write_uint16(opt + 13,  8); /* opt len */
		memcpy(opt + 15, upstream->client_cookie, 8);
		return opt + 23;

	} else if (!upstream->has_server_cookie) {
		gldns_write_uint16(opt +  9, 12); /* rdata len */
		gldns_write_uint16(opt + 11, EDNS_COOKIE_OPCODE);
		gldns_write_uint16(opt + 13,  8); /* opt len */
		memcpy(opt + 15, upstream->client_cookie, 8);
		return opt + 23;
	} else {
		gldns_write_uint16( opt +  9, 12  /* rdata len */
		                  + upstream->server_cookie_len);
		gldns_write_uint16(opt + 11, EDNS_COOKIE_OPCODE);
		gldns_write_uint16(opt + 13,  8   /* opt len */
		                  + upstream->server_cookie_len);
		memcpy(opt + 15, upstream->client_cookie, 8);
		memcpy(opt + 23, upstream->server_cookie
		               , upstream->server_cookie_len);
		return opt + 23+ upstream->server_cookie_len;
	}
}

static int
match_and_process_server_cookie(
    getdns_upstream *upstream, uint8_t *response, size_t response_len)
{
	priv_getdns_rr_iter rr_iter_storage, *rr_iter;
	uint8_t *pos;
	uint16_t rdata_len, opt_code, opt_len;

	/* Search for the OPT RR (if any) */
	for ( rr_iter = priv_getdns_rr_iter_init(&rr_iter_storage
	                                        , response, response_len)
	    ; rr_iter
	    ; rr_iter = priv_getdns_rr_iter_next(rr_iter)) {

		if (priv_getdns_rr_iter_section(rr_iter) !=
		    GLDNS_SECTION_ADDITIONAL)
			continue;

		if (gldns_read_uint16(rr_iter->rr_type) != GETDNS_RRTYPE_OPT)
			continue;

		break;
	}
	if (! rr_iter)
		return 0; /* No OPT, no cookie */

	pos = rr_iter->rr_type + 8;

	/* OPT found, now search for the cookie option */
	if (pos + 2 > rr_iter->nxt)
		return 1; /* FORMERR */

	rdata_len = gldns_read_uint16(pos); pos += 2;
	if (pos + rdata_len > rr_iter->nxt)
		return 1; /* FORMERR */

	while (pos < rr_iter->nxt) {
		opt_code = gldns_read_uint16(pos); pos += 2;
		opt_len  = gldns_read_uint16(pos); pos += 2;
		if (pos + opt_len > rr_iter->nxt)
			return 1; /* FORMERR */
		if (opt_code == EDNS_COOKIE_OPCODE)
			break;
		pos += opt_len; /* Skip unknown options */
	}
	if (pos >= rr_iter->nxt || opt_code != EDNS_COOKIE_OPCODE)
		return 0; /* Everything OK, just no cookie found. */

	if (opt_len < 16 || opt_len > 40)
		return 1; /* FORMERR */

	if (!upstream->has_client_cookie)
		return 1; /* Cookie reply, but we didn't sent one */

	if (memcmp(upstream->client_cookie, pos, 8) != 0) {
		if (!upstream->has_prev_client_cookie)
			return 1; /* Cookie didn't match */
		if (memcmp(upstream->prev_client_cookie, pos, 8) != 0)
			return 1; /* Previous cookie didn't match either */

		upstream->has_server_cookie = 0;
		return 0; /* Don't store server cookie, because it
		           * is for our previous client cookie
			   */
	}
	pos += 8;
	opt_len -= 8;
	upstream->has_server_cookie = 1;
	upstream->server_cookie_len = opt_len;
	(void) memcpy(upstream->server_cookie, pos, opt_len);
	return 0;
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
	// TODO[TLS]: When we get an error (which is probably a timeout) and are 
	// using to keep connections open should we leave the connection up here?
	if (upstream->tls_obj) {
		SSL_shutdown(upstream->tls_obj);
		SSL_free(upstream->tls_obj);
		upstream->tls_obj = NULL;
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

	if (netreq->owner->edns_cookies && match_and_process_server_cookie(
	    upstream, netreq->response, read))
		return; /* Client cookie didn't match? */

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
	netreq->response_len = read;
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

	netreq->query_id = arc4random();
	GLDNS_ID_SET(netreq->query, netreq->query_id);
	if (netreq->opt) {
		if (netreq->edns_maximum_udp_payload_size == -1)
			gldns_write_uint16(netreq->opt + 3,
			    ( netreq->max_udp_payload_size =
			      netreq->upstream->addr.ss_family == AF_INET6
			    ? 1232 : 1432));
		if (netreq->owner->edns_cookies) {
			netreq->response = attach_edns_cookie(
			    netreq->upstream, netreq->opt);
			pkt_len = netreq->response - netreq->query;
		}
	}

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

	fprintf(stderr, "[TLS] method: stub_tcp_read\n");

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
	fprintf(stderr, "[TLS] method: read %d TCP bytes \n", (int)read);
	tcp->to_read  -= read;
	tcp->read_pos += read;
	
	if ((int)tcp->to_read > 0)
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
			    tcp->read_buf, uint8_t, buf_size)))
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
		fprintf(stderr, "[TLS] method: stub_tcp_read_cb -> tcp again\n");
		return;

	case STUB_TCP_ERROR:
		fprintf(stderr, "[TLS] method: stub_tcp_read_cb -> tcp error\n");
		stub_erred(netreq);
		return;

	default:
		fprintf(stderr, "[TLS] method: stub_tcp_read_cb -> All done. close fd %d\n", netreq->fd);
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
		if (q != netreq->query_id)
			return;
		if (netreq->owner->edns_cookies &&
		    match_and_process_server_cookie(
		    netreq->upstream, netreq->tcp.read_buf,
		    netreq->tcp.read_pos - netreq->tcp.read_buf))
			return; /* Client cookie didn't match? */
		netreq->state = NET_REQ_FINISHED;
		netreq->response = netreq->tcp.read_buf;
		netreq->response_len =
		    netreq->tcp.read_pos - netreq->tcp.read_buf;
		netreq->tcp.read_buf = NULL;
		dnsreq->upstreams->current = 0;

		/* TODO: DNSSEC */
		netreq->secure = 0;
		netreq->bogus  = 0;

		stub_cleanup(netreq);
		close(netreq->fd);
		priv_getdns_check_dns_req_complete(dnsreq);
	}
}

/** wait for a socket to become ready */
static int
sock_wait(int sockfd)
{
	int ret;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(FD_SET_T sockfd, &fds);
	struct timeval timeout = {2, 0 };
	ret = select(sockfd+1, NULL, &fds, NULL, &timeout);
	if(ret == 0)
		/* timeout expired */
		return 0;
	else if(ret == -1)
		/* error */
		return 0;
	return 1;
}

static int
sock_connected(int sockfd) 
{
	fprintf(stderr, "[TLS] connect in progress \n");
	/* wait(write) until connected or error */
	while(1) {
		int error = 0;
		socklen_t len = (socklen_t)sizeof(error);

		if(!sock_wait(sockfd)) {
			close(sockfd);
			return -1;
		}

		/* check if there is a pending error for nonblocking connect */
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void*)&error, &len) < 0) {
			error = errno; /* on solaris errno is error */
		}
		if (error == EINPROGRESS || error == EWOULDBLOCK)
			continue; /* try again */
		else if (error != 0) {
			close(sockfd);
			return -1;
		}
		/* connected */
		break;
	}
	return sockfd;
}

/* The connection testing and handshake should be handled by integrating this 
 * with the event loop framework, but for now just implement a standalone
 * handshake method.*/
SSL*
do_tls_handshake(getdns_dns_req *dnsreq, getdns_upstream *upstream) 
{
	/*Lets make sure the connection is up before we try a handshake*/
	if (errno == EINPROGRESS && sock_connected(upstream->fd) == -1) {
		fprintf(stderr, "[TLS] connect failed \n");
		return NULL;
	}
	fprintf(stderr, "[TLS] connect done \n");

	/* Create SSL instance */
	SSL* ssl = SSL_new(dnsreq->context->tls_ctx);
	if(!ssl) {
		return NULL;
	}
	/* Connect the SSL object with a file descriptor */
	if(!SSL_set_fd(ssl, upstream->fd)) {
		SSL_free(ssl);
		return NULL;
	}
	SSL_set_connect_state(ssl);
	(void) SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	int r;
	int want;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(upstream->fd, &fds);
	struct timeval timeout = {dnsreq->context->timeout/1000, 0 };
	while ((r = SSL_do_handshake(ssl)) != 1)
	{
		want = SSL_get_error(ssl, r);
		fprintf(stderr, "[TLS] in handshake loop  %d, want is %d \n", r, want);
		switch (want) {
			case SSL_ERROR_WANT_READ:
				if (select(upstream->fd + 1, &fds, NULL, NULL, &timeout) == 0) {
					fprintf(stderr, "[TLS] ssl handshake timeout %d\n", want);
					SSL_free(ssl);
					return NULL;
				}
				break;
			case SSL_ERROR_WANT_WRITE:
				if (select(upstream->fd + 1, NULL, &fds, NULL, &timeout) == 0) {
					fprintf(stderr, "[TLS] ssl handshake timeout %d\n", want);
					SSL_free(ssl);
					return NULL;
				}
				break;
			default: 
				fprintf(stderr, "[TLS] got ssl error code %d\n", want);
				SSL_free(ssl);
				return NULL;
	   }
	}
	fprintf(stderr, "[TLS] got TLS connection\n");
	return ssl;
}

static int
stub_tls_read(SSL* tls_obj, getdns_tcp_state *tcp, struct mem_funcs *mf)
{
	ssize_t  read;
	uint8_t *buf;
	size_t   buf_size;

	fprintf(stderr, "[TLS] method: stub_tls_read\n");

	if (!tcp->read_buf) {
		/* First time tls read, create a buffer for reading */
		if (!(tcp->read_buf = GETDNS_XMALLOC(*mf, uint8_t, 4096)))
			return STUB_TCP_ERROR;

		tcp->read_buf_len = 4096;
		tcp->read_pos = tcp->read_buf;
		tcp->to_read = 2; /* Packet size */
	}

	ERR_clear_error();
	read = SSL_read(tls_obj, tcp->read_pos, tcp->to_read);
	if (read <= 0) {
		/* TODO[TLS]: Handle SSL_ERROR_WANT_WRITE which means handshake
		   renegotiation. Need to keep handshake state to do that.*/
		int want = SSL_get_error(tls_obj, read);
		if (want == SSL_ERROR_WANT_READ) {
			return STUB_TCP_AGAIN; /* read more later */
		} else 
			return STUB_TCP_ERROR;
	}
	fprintf(stderr, "[TLS] method: read %d TLS bytes \n", (int)read);
	tcp->to_read  -= read;
	tcp->read_pos += read;

	if ((int)tcp->to_read > 0)
		return STUB_TCP_AGAIN;

	read = tcp->read_pos - tcp->read_buf;
	if (read == 2) {
		/* Read the packet size short */
		tcp->to_read = gldns_read_uint16(tcp->read_buf);
		fprintf(stderr, "[TLS] method: %d TLS bytes to read \n", (int)tcp->to_read);

		if (tcp->to_read < GLDNS_HEADER_SIZE)
			return STUB_TCP_ERROR;

		/* Resize our buffer if needed */
		if (tcp->to_read > tcp->read_buf_len) {
			buf_size = tcp->read_buf_len;
			while (tcp->to_read > buf_size)
				buf_size *= 2;
		
			if (!(buf = GETDNS_XREALLOC(*mf,
			    tcp->read_buf, uint8_t, buf_size)))
				return STUB_TCP_ERROR;
		
			tcp->read_buf = buf;
			tcp->read_buf_len = buf_size;
		}

		/* Ready to start reading the packet */
		fprintf(stderr, "[TLS] method: resetting read_pos \n");
		tcp->read_pos = tcp->read_buf;
		read = SSL_read(tls_obj, tcp->read_pos, tcp->to_read);
		if (read <= 0) {
			/* TODO[TLS]: Handle SSL_ERROR_WANT_WRITE which means handshake
			   renegotiation. Need to keep handshake state to do that.*/
			int want = SSL_get_error(tls_obj, read);
			if (want == SSL_ERROR_WANT_READ) {
				return STUB_TCP_AGAIN; /* read more later */
			} else 
				return STUB_TCP_ERROR;
		}
		tcp->to_read  -= read;
		tcp->read_pos += read;
		if ((int)tcp->to_read > 0)
			return STUB_TCP_AGAIN;
	}
	return GLDNS_ID_WIRE(tcp->read_buf);
}

static void netreq_upstream_read_cb(void *userarg);
static void netreq_upstream_write_cb(void *userarg);
static void upstream_write_cb(void *userarg);
static void
upstream_read_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_network_req *netreq;
	getdns_dns_req *dnsreq;
	int q;
	uint16_t query_id;
	intptr_t query_id_intptr;

	fprintf(stderr, "[TLS] method: upstream_read_cb\n");

	if (upstream->tls_obj)
		q = stub_tls_read(upstream->tls_obj, &upstream->tcp,
		              &upstream->upstreams->mf);
	else
		q = stub_tcp_read(upstream->fd, &upstream->tcp,
		             &upstream->upstreams->mf);

	switch (q) {
	case STUB_TCP_AGAIN:
		fprintf(stderr, "[TLS] method: upstream_read_cb -> STUB_TCP_AGAIN\n");
		return;

	case STUB_TCP_ERROR:
		upstream_erred(upstream);
		return;

	default:
		fprintf(stderr, "[TLS] method: upstream_read_cb -> processing reponse\n");

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
		netreq->response_len =
		    upstream->tcp.read_pos - upstream->tcp.read_buf;
		netreq->tls_obj = upstream->tls_obj;
		upstream->tcp.read_buf = NULL;
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
	fprintf(stderr, "[TLS] method: stub_tcp_write\n");

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
		if ((dnsreq->context->dns_transport == GETDNS_TRANSPORT_TCP_ONLY) ||
			(dnsreq->context->dns_transport == GETDNS_TRANSPORT_UDP_ONLY) ||
			(dnsreq->context->dns_transport == GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP))
			query_id = arc4random();
		else do {
			query_id = arc4random();
			query_id_intptr = (intptr_t)query_id;
			netreq->node.key = (void *)query_id_intptr;

		} while (!getdns_rbtree_insert(
		    &netreq->upstream->netreq_by_query_id, &netreq->node));

		GLDNS_ID_SET(netreq->query, query_id);
		if (netreq->opt) {
			/* no limits on the max udp payload size with tcp */
			gldns_write_uint16(netreq->opt + 3, 65535);

			if (netreq->owner->edns_cookies) {
				netreq->response = attach_edns_cookie(
				    netreq->upstream, netreq->opt);
				pkt_len = netreq->response - netreq->query;
				gldns_write_uint16(netreq->query - 2, pkt_len);
			}
		}
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

		query_id = (int)GLDNS_ID_WIRE(tcp->write_buf + 2);
		/* Done. Start reading */
		tcp->write_buf = NULL;
		return query_id;

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

static int
stub_tls_write(SSL* tls_obj, getdns_tcp_state *tcp, getdns_network_req *netreq)
{
	fprintf(stderr, "[TLS] method: stub_tls_write\n");

	size_t          pkt_len = netreq->response - netreq->query;
	ssize_t         written;
	uint16_t        query_id;
	intptr_t        query_id_intptr;

	/* Do we have remaining data that we could not write before?  */
	if (! tcp->write_buf) {
		/* No, this is an initial write. Try to send
		 */

		 /* Find a unique query_id not already written (or in
		 * the write_queue) for that upstream.  Register this netreq 
		 * by query_id in the process.
		 */
		do {
			query_id = ldns_get_random();
			query_id_intptr = (intptr_t)query_id;
			netreq->node.key = (void *)query_id_intptr;

		} while (!getdns_rbtree_insert(
		    &netreq->upstream->netreq_by_query_id, &netreq->node));

		GLDNS_ID_SET(netreq->query, query_id);
		if (netreq->opt)
			/* no limits on the max udp payload size with tcp */
			gldns_write_uint16(netreq->opt + 3, 65535);

		/* We have an initialized packet buffer.
		 * Lets see how much of it we can write */
		
		// TODO[TLS]: Handle error cases, partial writes, renegotiation etc.
		ERR_clear_error();
		written = SSL_write(tls_obj, netreq->query - 2, pkt_len + 2);
		if (written <= 0)
			return STUB_TCP_ERROR;

		/* We were able to write everything!  Start reading. */
		return (int) query_id;

	} 

	return STUB_TCP_ERROR;
}


static void
upstream_write_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_network_req *netreq = upstream->write_queue;
	getdns_dns_req *dnsreq = netreq->owner;
	int q;

	fprintf(stderr, "[TLS] method: upstream_write_cb for %s with class %d\n", dnsreq->name, (int)netreq->request_class);
	
	if (upstream->tls_obj)
		q = stub_tls_write(upstream->tls_obj, &upstream->tcp, netreq);
	else
		q = stub_tcp_write(upstream->fd, &upstream->tcp, netreq);

	switch (q) {
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

static in_port_t
get_port(struct sockaddr_storage* addr)
{
	return ntohs(addr->ss_family == AF_INET
	    ? ((struct sockaddr_in *)addr)->sin_port
	    : ((struct sockaddr_in6*)addr)->sin6_port);
}

void
set_port(struct sockaddr_storage* addr, in_port_t port)
{
	addr->ss_family == AF_INET
	    ? (((struct sockaddr_in *)addr)->sin_port = htons(port))
	    : (((struct sockaddr_in6*)addr)->sin6_port = htons(port));
}

typedef enum getdns_base_transport {
	NONE,
	UDP,
	TCP_SINGLE,
	TCP,
	TLS
} getdns_base_transport_t;

getdns_transport_t
get_transport(getdns_transport_t transport, int level) {
	if (!(level == 0 || level == 1)) return NONE;
	switch (transport) {
 		case GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP:
			if (level == 0) return UDP;
			if (level == 1) return TCP;
		case GETDNS_TRANSPORT_UDP_ONLY:
			if (level == 0) return UDP;
			if (level == 1) return NONE;
		case GETDNS_TRANSPORT_TCP_ONLY:
			if (level == 0) return TCP_SINGLE;
			if (level == 1) return NONE;
		case GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN:
			if (level == 0) return TCP;
			if (level == 1) return NONE;
		case GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN:
			if (level == 0) return TLS;
			if (level == 1) return NONE;
		case GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN:
			if (level == 0) return TLS;
			if (level == 1) return TCP;
		default:
			return NONE;
		}
}

int
tcp_connect (getdns_upstream *upstream, getdns_base_transport_t transport) {

	int fd =-1;
	struct sockaddr_storage  connect_addr;
	struct sockaddr_storage* addr = &upstream->addr;
	socklen_t addr_len = upstream->addr_len;

	/* TODO[TLS]: For now, override the port to a hardcoded value*/
	if (transport == TLS && (int)get_port(addr) != TLS_PORT) {
		connect_addr = upstream->addr;
		addr = &connect_addr;
		set_port(addr, TLS_PORT);
		fprintf(stderr, "[TLS] Forcing switch to port %d for TLS\n", TLS_PORT);
	}

	if ((fd = socket(addr->ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;

	getdns_sock_nonblock(fd);
#ifdef USE_TCP_FASTOPEN
	/* Leave the connect to the later call to sendto() if using TCP*/
	if (transport == TCP || transport == TCP_SINGLE)
		return fd;
#endif
	if (connect(fd, (struct sockaddr *)addr,
	    addr_len) == -1) {
		if (errno != EINPROGRESS) {
			close(fd);
			return -1;
		}
	}
	return fd;
}

getdns_return_t
priv_getdns_submit_stub_request(getdns_network_req *netreq)
{
	getdns_dns_req  *dnsreq   = netreq->owner;
	getdns_upstream *upstream = pick_upstream(dnsreq);

	fprintf(stderr, "[TLS] method: priv_getdns_submit_stub_request\n");

	if (!upstream)
	    	return GETDNS_RETURN_GENERIC_ERROR;

	// Work out the primary and fallback transport options
	getdns_base_transport_t transport    = get_transport(
	                                       dnsreq->context->dns_transport,0);
	getdns_base_transport_t fb_transport = get_transport(
	                                       dnsreq->context->dns_transport,1);
	switch(transport) {
	case UDP:

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

	case TCP_SINGLE:

		if ((netreq->fd = tcp_connect(upstream, transport)) == -1)
			return GETDNS_RETURN_GENERIC_ERROR;
		netreq->upstream = upstream;

		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		    NULL, stub_tcp_write_cb, stub_timeout_cb));

		return GETDNS_RETURN_GOOD;
	
	case TCP:
	case TLS:
		
		/* In coming comments, "global" means "context wide" */

		/* Are we the first? (Is global socket initialized?) */
		if (upstream->fd == -1) {
			/* TODO[TLS]: We should remember on the context if we had to fallback
			 * for this upstream so when re-connecting from a dropped TCP 
			 * connection we don't retry TLS. */
			int fallback = 0;

			/* We are the first. Make global socket and connect. */
			if ((upstream->fd = tcp_connect(upstream, transport)) == -1) {
				//TODO: Hum, a reset doesn't make the connect fail...
				if (fb_transport == NONE)
					return GETDNS_RETURN_GENERIC_ERROR;
				fprintf(stderr, "[TLS] Connect failed on fd... %d\n", upstream->fd);
				if ((upstream->fd = tcp_connect(upstream, fb_transport)) == -1)
					return GETDNS_RETURN_GENERIC_ERROR;
				fallback = 1; 
			}
			
			/* Now do a handshake for TLS. Note waiting for this to succeed or 
			   timeout blocks the scheduling of any messages for this upstream*/
			if (transport == TLS && (fallback == 0)) {
				fprintf(stderr, "[TLS] Doing SSL handshake... %d\n", upstream->fd);
				upstream->tls_obj = do_tls_handshake(dnsreq, upstream);
				if (!upstream->tls_obj) {
					if (fb_transport == NONE)
						return GETDNS_RETURN_GENERIC_ERROR;
					close(upstream->fd);
					if ((upstream->fd = tcp_connect(upstream, fb_transport)) == -1)
						return GETDNS_RETURN_GENERIC_ERROR;
				}
			}
		} else {
			/* Cater for the case of the user downgrading and existing TLS
			   connection to TCP for some reason...*/
			if (transport == TCP && upstream->tls_obj) {
				SSL_shutdown(upstream->tls_obj);
				SSL_free(upstream->tls_obj);
				upstream->tls_obj = NULL;
			}
		}
		netreq->upstream = upstream;

		/* Attach to the global event loop
		 * so it can do it's own scheduling
		 */
		upstream->loop = dnsreq->context->extension;

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
