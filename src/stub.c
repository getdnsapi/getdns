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
#include "debug.h"
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include "stub.h"
#include "gldns/gbuffer.h"
#include "gldns/pkthdr.h"
#include "gldns/rrdef.h"
#include "gldns/str2wire.h"
#include "gldns/wire2str.h"
#include "rr-iter.h"
#include "context.h"
#include "util-internal.h"
#include "general.h"
#include "pubkey-pinning.h"

#ifdef USE_WINSOCK
typedef u_short sa_family_t;
#define _getdns_EWOULDBLOCK (WSAGetLastError() == WSATRY_AGAIN ||\
                             WSAGetLastError() == WSAEWOULDBLOCK)
#define _getdns_EINPROGRESS (WSAGetLastError() == WSAEINPROGRESS)
#else
#define _getdns_EWOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
#define _getdns_EINPROGRESS (errno == EINPROGRESS)
#endif

/* WSA TODO: 
 * STUB_TCP_WOULDBLOCK added to deal with edge triggered event loops (versus
 * level triggered).  See also lines containing WSA TODO below...
 */
#define STUB_TCP_WOULDBLOCK -6
#define STUB_OUT_OF_OPTIONS -5 /* upstream options exceeded MAXIMUM_UPSTREAM_OPTION_SPACE */
#define STUB_TLS_SETUP_ERROR -4
#define STUB_TCP_AGAIN -3
#define STUB_TCP_ERROR -2

/* Don't currently have access to the context whilst doing handshake */
#define TIMEOUT_TLS 2500
/* Arbritray number of message for EDNS keepalive resend*/
#define EDNS_KEEPALIVE_RESEND 5

static time_t secret_rollover_time = 0;
static uint32_t secret = 0;
static uint32_t prev_secret = 0;

static void upstream_read_cb(void *userarg);
static void upstream_write_cb(void *userarg);
static void upstream_idle_timeout_cb(void *userarg);
static void upstream_schedule_netreq(getdns_upstream *upstream, 
                                     getdns_network_req *netreq);
static void upstream_reschedule_events(getdns_upstream *upstream, 
                                     size_t idle_timeout);
static int  upstream_connect(getdns_upstream *upstream, 
                             getdns_transport_list_t transport,
                             getdns_dns_req *dnsreq);
static int  fallback_on_write(getdns_network_req *netreq);

static void stub_timeout_cb(void *userarg);
static uint64_t _getdns_get_time_as_uintt64();
/*****************************/
/* General utility functions */
/*****************************/

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

static getdns_return_t
attach_edns_client_subnet_private(getdns_network_req *req)
{
	/* see
	 * https://tools.ietf.org/html/draft-ietf-dnsop-edns-client-subnet-04#section-6 */
	/* all-zeros is a request to not leak the data further: */
	/* "\x00\x00"  FAMILY: 0 (because no address) */
	/* "\x00"  SOURCE PREFIX-LENGTH: 0 */ 
	/* "\x00";  SCOPE PREFIX-LENGTH: 0 */
	return _getdns_network_req_add_upstream_option(req,
						       GLDNS_EDNS_CLIENT_SUBNET,
						       4, NULL);
}

static getdns_return_t
attach_edns_keepalive(getdns_network_req *req)
{
    /* Client always sends length 0, omits the timeout */
	return _getdns_network_req_add_upstream_option(req,
						       GLDNS_EDNS_KEEPALIVE,
						       0, NULL);
}

static getdns_return_t
attach_edns_cookie(getdns_network_req *req)
{
	getdns_upstream *upstream = req->upstream;
	uint16_t sz;
	void* val;
	uint8_t buf[8 + 32]; /* server cookies can be no larger than 32 bytes */
	rollover_secret();

	if (!upstream->has_client_cookie) {
		calc_new_cookie(upstream, upstream->client_cookie);
		upstream->secret = secret;
		upstream->has_client_cookie = 1;

		sz = 8;
		val = upstream->client_cookie;
	} else if (upstream->secret != secret) {
		memcpy( upstream->prev_client_cookie
		      , upstream->client_cookie, 8);
		upstream->has_prev_client_cookie = 1;
		calc_new_cookie(upstream, upstream->client_cookie);
		upstream->secret = secret;

		sz = 8;
		val = upstream->client_cookie;
	} else if (!upstream->has_server_cookie) {
		sz = 8;
		val = upstream->client_cookie;
	} else {
		sz = 8 + upstream->server_cookie_len;
		memcpy(buf, upstream->client_cookie, 8);
		memcpy(buf+8, upstream->server_cookie, upstream->server_cookie_len);
		val = buf;
	}
	return _getdns_network_req_add_upstream_option(req, EDNS_COOKIE_OPCODE, sz, val);

}

/* Will find a matching OPT RR, but leaves the caller to validate it
 *
 * Returns 2 when found
 *         0 when not found
 *     and 1 on FORMERR
 */
static int
match_edns_opt_rr(uint16_t code, uint8_t *response, size_t response_len,
                  const uint8_t **position, uint16_t *option_len)
{
	_getdns_rr_iter rr_iter_storage, *rr_iter;
	const uint8_t *pos;
	uint16_t rdata_len, opt_code = 0, opt_len = 0;

	/* Search for the OPT RR (if any) */
	for ( rr_iter = _getdns_rr_iter_init(&rr_iter_storage
	                                        , response, response_len)
	    ; rr_iter
	    ; rr_iter = _getdns_rr_iter_next(rr_iter)) {

		if (_getdns_rr_iter_section(rr_iter) != SECTION_ADDITIONAL)
			continue;

		if (gldns_read_uint16(rr_iter->rr_type) != GETDNS_RRTYPE_OPT)
			continue;

		break;
	}
	if (! rr_iter)
		return 0; /* No OPT, no cookie */

	pos = rr_iter->rr_type + 8;

#if defined(STUB_DEBUG) && STUB_DEBUG
	char str_spc[8192], *str = str_spc;
	size_t str_len = sizeof(str_spc);
	uint8_t *data = (uint8_t *)rr_iter->pos;
	size_t data_len = rr_iter->nxt - rr_iter->pos;
	(void) gldns_wire2str_rr_scan(
	    &data, &data_len, &str, &str_len, (uint8_t *)rr_iter->pkt, rr_iter->pkt_end - rr_iter->pkt);
	DEBUG_STUB("%s %-35s: OPT RR: %s\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, str_spc);
#endif

	/* OPT found, now search for the specified option */
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
		if (opt_code == code)
			break;
		pos += opt_len; /* Skip unknown options */
	}
	if (pos >= rr_iter->nxt || opt_code != code)
		return 0; /* Everything OK, just no cookie found. */
	*position = pos;
	*option_len = opt_len;
	return 2;
}

/* TODO: Test combinations of EDNS0 options*/
static int
match_and_process_server_cookie(
    getdns_upstream *upstream, uint8_t *response, size_t response_len) 
{
	const uint8_t *position = NULL;
	uint16_t option_len = 0;
	int found = match_edns_opt_rr(EDNS_COOKIE_OPCODE, response, 
	                              response_len, &position, &option_len);
	if (found != 2)
		return found;

	if (option_len < 16 || option_len > 40)
		return 1; /* FORMERR */

	if (!upstream->has_client_cookie)
		return 1; /* Cookie reply, but we didn't sent one */

	if (memcmp(upstream->client_cookie, position, 8) != 0) {
		if (!upstream->has_prev_client_cookie)
			return 1; /* Cookie didn't match */
		if (memcmp(upstream->prev_client_cookie, position, 8) != 0)
			return 1; /* Previous cookie didn't match either */

		upstream->has_server_cookie = 0;
		return 0; /* Don't store server cookie, because it
		           * is for our previous client cookie
			   */
	}
	position += 8;
	option_len -= 8;
	upstream->has_server_cookie = 1;
	upstream->server_cookie_len = option_len;
	(void) memcpy(upstream->server_cookie, position, option_len);
	return 0;
}

static void
process_keepalive(
    getdns_upstream *upstream, getdns_network_req *netreq, 
    uint8_t *response, size_t response_len) 
{
	const uint8_t *position = NULL;
	uint16_t option_len = 0;
	int found = match_edns_opt_rr(GLDNS_EDNS_KEEPALIVE, response, 
	                              response_len, &position, &option_len);
	if (found != 2 || option_len != 2) {
		if (netreq->keepalive_sent == 1)
			/* If no keepalive sent back, then we must use 0 idle timeout
			   as server does not support it.*/
#if defined(KEEP_CONNECTIONS_OPEN_DEBUG) && KEEP_CONNECTIONS_OPEN_DEBUG
			upstream->keepalive_timeout = netreq->owner->context->idle_timeout;
#else
			upstream->keepalive_timeout = 0;
#endif
		return;
	}
	/* Use server sent value unless the client specified a shorter one.
	   Convert to ms first (wire value has units of 100ms) */
	uint64_t server_keepalive = ((uint64_t)gldns_read_uint16(position))*100;
	if (netreq->owner->context->idle_timeout < server_keepalive)
		upstream->keepalive_timeout = netreq->owner->context->idle_timeout;
	else {
		upstream->keepalive_timeout = server_keepalive;
		DEBUG_STUB("%s %-35s: FD:  %d Server Keepalive used: %d ms\n",
		           STUB_DEBUG_CLEANUP, __FUNCTION__, upstream->fd, 
		           (int)server_keepalive);
	}
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

static int
tcp_connect(getdns_upstream *upstream, getdns_transport_list_t transport) 
{
	int fd = -1;
	DEBUG_STUB("%s %-35s: Creating TCP connection:       %p\n", STUB_DEBUG_SETUP, 
	           __FUNCTION__, upstream);
	if ((fd = socket(upstream->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;

	getdns_sock_nonblock(fd);
#ifdef USE_TCP_FASTOPEN
	/* Leave the connect to the later call to sendto() if using TCP*/
	if (transport == GETDNS_TRANSPORT_TCP)
		return fd;
#elif USE_OSX_TCP_FASTOPEN
	sa_endpoints_t endpoints;
	endpoints.sae_srcif = 0;
	endpoints.sae_srcaddr = NULL;
	endpoints.sae_srcaddrlen = 0;
	endpoints.sae_dstaddr = (struct sockaddr *)&upstream->addr;
	endpoints.sae_dstaddrlen = upstream->addr_len;
	if (connectx(fd, &endpoints, SAE_ASSOCID_ANY,  
	             CONNECT_DATA_IDEMPOTENT | CONNECT_RESUME_ON_READ_WRITE,
	             NULL, 0, NULL, NULL) == -1) {
		if (errno != EINPROGRESS) {
			close(fd);
			return -1;
		}
	}
	return fd;
#endif
	if (connect(fd, (struct sockaddr *)&upstream->addr,
	    upstream->addr_len) == -1) {
		if (_getdns_EINPROGRESS || _getdns_EWOULDBLOCK)
			return fd;
		close(fd);
		return -1;
	}
	return fd;
}

static int
tcp_connected(getdns_upstream *upstream) {
	/* Already tried and failed, so let the fallback code take care of things */
	/* TODO: We _should_ use a timeout on the TCP handshake*/
	if (upstream->fd == -1 || upstream->tcp.write_error != 0)
		return STUB_TCP_ERROR;

	int error = 0;
	socklen_t len = (socklen_t)sizeof(error);
	getsockopt(upstream->fd, SOL_SOCKET, SO_ERROR, (void*)&error, &len);
#ifdef USE_WINSOCK
	if (error == WSAEINPROGRESS)
		return STUB_TCP_WOULDBLOCK;
	else if (error == WSAEWOULDBLOCK) 
		return STUB_TCP_WOULDBLOCK;
	else if (error != 0)
		return STUB_TCP_ERROR;
#else
	if (error == EINPROGRESS)
		return STUB_TCP_WOULDBLOCK;
	else if (error == EWOULDBLOCK || error == EAGAIN) 
		return STUB_TCP_WOULDBLOCK;
	else if (error != 0)
		return STUB_TCP_ERROR;
#endif
	return 0;
}

/**************************/
/* Error/cleanup functions*/
/**************************/

static void
stub_next_upstream(getdns_network_req *netreq)
{
	getdns_dns_req *dnsreq = netreq->owner;

	if (! --netreq->upstream->to_retry) 
		netreq->upstream->to_retry = -(netreq->upstream->back_off *= 2);

	/*[TLS]:TODO - This works because the next message won't try the exact
	 * same upstream (and the next message may not use the same transport),
	 * but the next message will find the next matching one thanks to logic in
	 * upstream_select, but this could be better */
	if (++dnsreq->upstreams->current >= dnsreq->upstreams->count)
		dnsreq->upstreams->current = 0;
}

static void
stub_cleanup(getdns_network_req *netreq)
{
	DEBUG_STUB("%s %-35s: MSG: %p\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, netreq);
	getdns_dns_req *dnsreq = netreq->owner;
	getdns_network_req *r, *prev_r;
	getdns_upstream *upstream;
	intptr_t query_id_intptr;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	GETDNS_NULL_FREE(dnsreq->context->mf, netreq->tcp.read_buf);

	/* Nothing globally scheduled? Then nothing queued */
	if (!(upstream = netreq->upstream)->event.ev)
		return;

	/* Delete from upstream->netreq_by_query_id (if present) */
	query_id_intptr = (intptr_t)netreq->query_id;
	(void) _getdns_rbtree_delete(
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
			netreq->write_queue_tail = NULL;
			break;
		}
	upstream_reschedule_events(upstream, upstream->keepalive_timeout);
}

static int
tls_cleanup(getdns_upstream *upstream, int handshake_fail)
{
	DEBUG_STUB("%s %-35s: FD:  %d\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, upstream->fd);
	if (upstream->tls_obj != NULL)
		SSL_free(upstream->tls_obj);
	upstream->tls_obj = NULL;
	/* This will prevent the connection from being tried again for the cases
	   where we know it didn't work. Otherwise leave it to try again.*/
	if (handshake_fail)
		upstream->tls_hs_state = GETDNS_HS_FAILED;
	/* Reset timeout on failure*/
	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
	GETDNS_SCHEDULE_EVENT(upstream->loop, upstream->fd, TIMEOUT_FOREVER,
	    getdns_eventloop_event_init(&upstream->event, upstream,
	     NULL, upstream_write_cb, NULL));
	return STUB_TLS_SETUP_ERROR;
}

static void
upstream_erred(getdns_upstream *upstream)
{
	DEBUG_STUB("%s %-35s: FD:  %d\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, upstream->fd);
	getdns_network_req *netreq;

	while ((netreq = upstream->write_queue)) {
		stub_cleanup(netreq);
		netreq->state = NET_REQ_FINISHED;
		_getdns_check_dns_req_complete(netreq->owner);
	}
	while (upstream->netreq_by_query_id.count) {
		netreq = (getdns_network_req *)
		    _getdns_rbtree_first(&upstream->netreq_by_query_id);
		stub_cleanup(netreq);
		netreq->state = NET_REQ_FINISHED;
		_getdns_check_dns_req_complete(netreq->owner);
	}
	_getdns_upstream_shutdown(upstream);
}

void
_getdns_cancel_stub_request(getdns_network_req *netreq)
{
	stub_cleanup(netreq);
	if (netreq->fd >= 0) close(netreq->fd);
}

/* May be needed in future for better UDP error handling?*/
/*static void
stub_erred(getdns_network_req *netreq)
{
	DEBUG_STUB("*** %s\n", __FUNCTION__);
	stub_next_upstream(netreq);
	stub_cleanup(netreq);
	if (netreq->fd >= 0) close(netreq->fd);
	netreq->state = NET_REQ_FINISHED;
	_getdns_check_dns_req_complete(netreq->owner);
}*/

static void
stub_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	DEBUG_STUB("%s %-35s: MSG:  %p\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, netreq);
	stub_next_upstream(netreq);
	stub_cleanup(netreq);
	if (netreq->fd >= 0) close(netreq->fd);
	netreq->state = NET_REQ_TIMED_OUT;
	if (netreq->owner->user_callback) {		
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		(void) _getdns_context_request_timed_out(netreq->owner);
	} else
		_getdns_check_dns_req_complete(netreq->owner);
}


static void
upstream_idle_timeout_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	DEBUG_STUB("%s %-35s: FD:  %d Closing connection\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, upstream->fd);
	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
	upstream->event.timeout_cb = NULL;
	upstream->event.read_cb = NULL;
	upstream->event.write_cb = NULL;
	_getdns_upstream_shutdown(upstream);
}

static void
upstream_tls_timeout_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	DEBUG_STUB("%s %-35s: FD:  %d\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, upstream->fd);
	/* Clean up and trigger a write to let the fallback code to its job */
	tls_cleanup(upstream, 1);

	/* Need to handle the case where the far end doesn't respond to a
	 * TCP SYN and doesn't do a reset (as is the case with e.g. 8.8.8.8@853).
	 * For that case the socket never becomes writable so doesn't trigger any
	 * callbacks. If so then clear out the queue in one go.*/
	int ret;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(FD_SET_T upstream->fd, &fds);
	struct timeval tval;
	tval.tv_sec = 0;
	tval.tv_usec = 0;
	ret = select(upstream->fd+1, NULL, &fds, NULL, &tval);
	if (ret == 0) {
		while (upstream->write_queue)
			upstream_write_cb(upstream);
	}
}

static void
stub_tls_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_upstream *upstream = netreq->upstream;
	DEBUG_STUB("%s %-35s: MSG: %p\n",
	           STUB_DEBUG_CLEANUP, __FUNCTION__, netreq);
	/* Clean up and trigger a write to let the fallback code to its job */
	tls_cleanup(upstream, 0);

	/* Need to handle the case where the far end doesn't respond to a
	 * TCP SYN and doesn't do a reset (as is the case with e.g. 8.8.8.8@853).
	 * For that case the socket never becomes writable so doesn't trigger any
	 * callbacks. If so then clear out the queue in one go.*/
	int ret;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(FD_SET_T upstream->fd, &fds);
	struct timeval tval;
	tval.tv_sec = 0;
	tval.tv_usec = 0;
	ret = select(upstream->fd+1, NULL, &fds, NULL, &tval);
	if (ret == 0) {
		while (upstream->write_queue)
			upstream_write_cb(upstream);
	}
}

/****************************/
/* TCP read/write functions */
/****************************/

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
	read = recv(fd, (void *)tcp->read_pos, tcp->to_read, 0);
	if (read == -1) {
		if (_getdns_EWOULDBLOCK)
			return STUB_TCP_WOULDBLOCK;
		else
			return STUB_TCP_ERROR;
	} else if (read == 0) {
		/* Remote end closed the socket */
		/* TODO: Try to reconnect */
		return STUB_TCP_ERROR;
	} else if (read> tcp->to_read) {
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

/* stub_tcp_write(fd, tcp, netreq)
 * will return STUB_TCP_AGAIN when we need to come back again,
 * STUB_TCP_ERROR on error and a query_id on successfull sent.
 */
static int
stub_tcp_write(int fd, getdns_tcp_state *tcp, getdns_network_req *netreq)
{

	size_t          pkt_len;
	ssize_t         written;
	uint16_t        query_id;
	intptr_t        query_id_intptr;

	int q = tcp_connected(netreq->upstream);
	if (q != 0)
		return q;

	netreq->debug_udp = 0;
	/* Do we have remaining data that we could not write before?  */
	if (! tcp->write_buf) {
		/* No, this is an initial write. Try to send
		 */
		do {
			query_id = arc4random();
			query_id_intptr = (intptr_t)query_id;
			netreq->node.key = (void *)query_id_intptr;

		} while (!_getdns_rbtree_insert(
		    &netreq->upstream->netreq_by_query_id, &netreq->node));

		GLDNS_ID_SET(netreq->query, query_id);
		if (netreq->opt) {
			_getdns_network_req_clear_upstream_options(netreq);
			/* no limits on the max udp payload size with tcp */
			gldns_write_uint16(netreq->opt + 3, 65535);

			if (netreq->owner->edns_cookies)
				if (attach_edns_cookie(netreq))
					return STUB_OUT_OF_OPTIONS;
			if (netreq->owner->edns_client_subnet_private)
				if (attach_edns_client_subnet_private(netreq))
					return STUB_OUT_OF_OPTIONS;
			if (netreq->upstream->writes_done == 0 && 
				netreq->owner->context->idle_timeout != 0) {
				/* Add the keepalive option to the first query on this connection*/
				DEBUG_STUB("%s %-35s: FD:  %d Requesting keepalive \n",
				           STUB_DEBUG_WRITE, __FUNCTION__, fd);
				if (attach_edns_keepalive(netreq))
					return STUB_OUT_OF_OPTIONS;
				netreq->keepalive_sent = 1;
			}
		}
		pkt_len = _getdns_network_req_add_tsig(netreq);
		/* We have an initialized packet buffer.
		 * Lets see how much of it we can write
		 */
		/* We use sendto() here which will do both a connect and send */
#ifdef USE_TCP_FASTOPEN
		written = sendto(fd, netreq->query - 2, pkt_len + 2,
		    MSG_FASTOPEN, (struct sockaddr *)&(netreq->upstream->addr),
		    netreq->upstream->addr_len);
		/* If pipelining we will find that the connection is already up so 
		   just fall back to a 'normal' write. */
		if (written == -1 && errno == EISCONN) 
			written = write(fd, netreq->query - 2, pkt_len + 2);
#else
		written = sendto(fd, (const char *)(netreq->query - 2),
		    pkt_len + 2, 0,
		    (struct sockaddr *)&(netreq->upstream->addr),
		    netreq->upstream->addr_len);
#endif
		if ((written == -1 && (_getdns_EWOULDBLOCK ||
		/* Add the error case where the connection is in progress which is when
		   a cookie is not available (e.g. when doing the first request to an
		   upstream). We must let the handshake complete since non-blocking. */
		                       _getdns_EINPROGRESS)) ||
		     written  < pkt_len + 2) {

			/* We couldn't write the whole packet.
			 * We have to return with STUB_TCP_AGAIN.
			 * Setup tcp to track the state.
			 */
			tcp->write_buf = netreq->query - 2;
			tcp->write_buf_len = pkt_len + 2;
			tcp->written = written >= 0 ? written : 0;

			return STUB_TCP_WOULDBLOCK;

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
			if (_getdns_EWOULDBLOCK)
				return STUB_TCP_WOULDBLOCK;
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

/*************************/
/* TLS Utility functions */
/*************************/

static int
tls_requested(getdns_network_req *netreq)
{
	return (netreq->transports[netreq->transport_current] ==
	        GETDNS_TRANSPORT_TLS) ?
	        1 : 0;
}

static int
tls_should_write(getdns_upstream *upstream)
{
	/* Should messages be written on TLS upstream. */
	return ((upstream->transport == GETDNS_TRANSPORT_TLS) &&
	         upstream->tls_hs_state != GETDNS_HS_NONE) ? 1 : 0;
}

static int
tls_should_read(getdns_upstream *upstream)
{
	return ((upstream->transport == GETDNS_TRANSPORT_TLS) &&
	       !(upstream->tls_hs_state == GETDNS_HS_FAILED ||
	         upstream->tls_hs_state == GETDNS_HS_NONE)) ? 1 : 0;
}

static int 
tls_failed(getdns_upstream *upstream)
{
	/* No messages should be scheduled onto an upstream in this state */
	return ((upstream->transport == GETDNS_TRANSPORT_TLS) &&
	         upstream->tls_hs_state == GETDNS_HS_FAILED) ? 1 : 0;
}

static int
tls_auth_status_ok(getdns_upstream *upstream, getdns_network_req *netreq) {
	return (netreq->tls_auth_min == GETDNS_AUTHENTICATION_REQUIRED &&
		    upstream->tls_auth_failed) ? 0 : 1;
}

int
tls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	getdns_upstream *upstream;
	getdns_return_t pinset_ret = GETDNS_RETURN_GOOD;
	upstream = _getdns_upstream_from_x509_store(ctx);

#if defined(STUB_DEBUG) && STUB_DEBUG || defined(X509_V_ERR_HOSTNAME_MISMATCH)
	int     err = X509_STORE_CTX_get_error(ctx);

	DEBUG_STUB("%s %-35s: FD:  %d Verify result: (%d) \"%s\"\n",
	            STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->fd, err,
	            X509_verify_cert_error_string(err));
#endif

#ifdef X509_V_ERR_HOSTNAME_MISMATCH
	/*Report if error is hostname mismatch*/
	if (upstream && upstream->tls_fallback_ok && err == X509_V_ERR_HOSTNAME_MISMATCH)
		DEBUG_STUB("%s %-35s: FD:  %d WARNING: Proceeding even though hostname validation failed!\n",
		           STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->fd);
#endif
	if (upstream && upstream->tls_pubkey_pinset)
		pinset_ret = _getdns_verify_pinset_match(upstream->tls_pubkey_pinset, ctx);

	if (pinset_ret != GETDNS_RETURN_GOOD) {
		DEBUG_STUB("%s %-35s: FD:  %d, WARNING: Pinset validation failure!\n",
	           STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->fd);
		preverify_ok = 0;
		upstream->tls_auth_failed = 1;
		if (upstream->tls_fallback_ok)
			DEBUG_STUB("%s %-35s: FD:  %d, WARNING: Proceeding even though pinset validation failed!\n",
			            STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->fd);
	}
	/* If fallback is allowed, proceed regardless of what the auth error is
	   (might not be hostname or pinset related) */
	return (upstream && upstream->tls_fallback_ok) ? 1 : preverify_ok;
}

static SSL*
tls_create_object(getdns_dns_req *dnsreq, int fd, getdns_upstream *upstream)
{
	/* Create SSL instance */
	getdns_context *context = dnsreq->context;
	if (context->tls_ctx == NULL)
		return NULL;
	SSL* ssl = SSL_new(context->tls_ctx);
	if(!ssl) 
		return NULL;
	/* Connect the SSL object with a file descriptor */
	if(!SSL_set_fd(ssl,fd)) {
		SSL_free(ssl);
		return NULL;
	}
	/* make sure we'll be able to find the context again when we need it */
	if (_getdns_associate_upstream_with_SSL(ssl, upstream) != GETDNS_RETURN_GOOD) {
		SSL_free(ssl);
		return NULL;
	}

	/* NOTE: this code will fallback on a given upstream, without trying
	   authentication on other upstreams first. This is non-optimal and but avoids
	   multiple TLS handshakes before getting a usable connection. */

	upstream->tls_fallback_ok = 0;
	/* If we have a hostname, always use it */
	if (upstream->tls_auth_name[0] != '\0') {
		/*Request certificate for the auth_name*/
		DEBUG_STUB("%s %-35s: Hostname verification requested for: %s\n",
		           STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->tls_auth_name);
		SSL_set_tlsext_host_name(ssl, upstream->tls_auth_name);
#ifdef HAVE_SSL_HN_AUTH
		/* Set up native OpenSSL hostname verification*/
		X509_VERIFY_PARAM *param;
		param = SSL_get0_param(ssl);
		X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, upstream->tls_auth_name, 0);
#else
		if (dnsreq->netreqs[0]->tls_auth_min == GETDNS_AUTHENTICATION_REQUIRED) {
			/* TODO: Trigger post-handshake custom validation*/
			DEBUG_STUB("%s %-35s: ERROR: TLS Authentication functionality not available\n",
		           STUB_DEBUG_SETUP_TLS, __FUNCTION__);
			upstream->tls_hs_state = GETDNS_HS_FAILED;
			upstream->tls_auth_failed = 1;
			return NULL;
		}
#endif
		/* Allow fallback to opportunistic if settings permit it*/
		if (dnsreq->netreqs[0]->tls_auth_min != GETDNS_AUTHENTICATION_REQUIRED)
			upstream->tls_fallback_ok = 1;
	} else {
		/* Lack of host name is OK unless only authenticated
		 * TLS is specified and we have no pubkey_pinset */
		if (dnsreq->netreqs[0]->tls_auth_min == GETDNS_AUTHENTICATION_REQUIRED) {
			if (upstream->tls_pubkey_pinset) {
				DEBUG_STUB("%s %-35s: Proceeding with only pubkey pinning authentication\n",
			           STUB_DEBUG_SETUP_TLS, __FUNCTION__);
			} else {
				DEBUG_STUB("%s %-35s: ERROR: No host name or pubkey pinset provided for TLS authentication\n",
			           STUB_DEBUG_SETUP_TLS, __FUNCTION__);
				upstream->tls_hs_state = GETDNS_HS_FAILED;
				upstream->tls_auth_failed = 1;
				return NULL;
			}
		} else {
			/* no hostname verification, so we will make opportunistic connections */
			DEBUG_STUB("%s %-35s: Proceeding even though no hostname provided!\n",
			           STUB_DEBUG_SETUP_TLS, __FUNCTION__);
			upstream->tls_auth_failed = 1;
			upstream->tls_fallback_ok = 1;
		}
	}
	if (upstream->tls_fallback_ok) {
		SSL_set_cipher_list(ssl, "DEFAULT");
		DEBUG_STUB("%s %-35s: WARNING: Using Oppotunistic TLS (fallback allowed)!\n",
		           STUB_DEBUG_SETUP_TLS, __FUNCTION__);
	} else
		DEBUG_STUB("%s %-35s: Using Strict TLS \n", STUB_DEBUG_SETUP_TLS, 
		             __FUNCTION__);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, tls_verify_callback);

	SSL_set_connect_state(ssl);
	(void) SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	return ssl;
}

static int
tls_do_handshake(getdns_upstream *upstream)
{
	DEBUG_STUB("%s %-35s: FD:  %d \n", STUB_DEBUG_SETUP_TLS, 
	             __FUNCTION__, upstream->fd);
	int r;
	int want;
	ERR_clear_error();
	while ((r = SSL_do_handshake(upstream->tls_obj)) != 1)
	{
		want = SSL_get_error(upstream->tls_obj, r);
		switch (want) {
			case SSL_ERROR_WANT_READ:
				GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
				upstream->event.read_cb = upstream_read_cb;
				upstream->event.write_cb = NULL;
				GETDNS_SCHEDULE_EVENT(upstream->loop,
				    upstream->fd, TIMEOUT_TLS, &upstream->event);
				upstream->tls_hs_state = GETDNS_HS_READ;
				return STUB_TCP_AGAIN;
			case SSL_ERROR_WANT_WRITE:
				GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
				upstream->event.read_cb = NULL;
				upstream->event.write_cb = upstream_write_cb;
				GETDNS_SCHEDULE_EVENT(upstream->loop,
				    upstream->fd, TIMEOUT_TLS, &upstream->event);
				upstream->tls_hs_state = GETDNS_HS_WRITE;
				return STUB_TCP_AGAIN;
			default:
				DEBUG_STUB("%s %-35s: FD:  %d Handshake failed %d\n", 
				            STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->fd,
				            want);
				return tls_cleanup(upstream, 1);
	   }
	}
	upstream->tls_hs_state = GETDNS_HS_DONE;
	DEBUG_STUB("%s %-35s: FD:  %d Handshake succeeded\n", 
	            STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->fd);
	r = SSL_get_verify_result(upstream->tls_obj);
	if (upstream->tls_auth_name[0])
#ifdef X509_V_ERR_HOSTNAME_MISMATCH
		if (r == X509_V_ERR_HOSTNAME_MISMATCH)
#else
 /* if we weren't built against OpenSSL with hostname matching we
  * could not have matched the hostname, so this would be an automatic
  * tls_auth_fail. */
#endif
			upstream->tls_auth_failed = 1;
	DEBUG_STUB("%s %-35s: FD:  %d Session is %s\n", 
		         STUB_DEBUG_SETUP_TLS, __FUNCTION__, upstream->fd,
		         SSL_session_reused(upstream->tls_obj) ?"re-used":"new");
	if (upstream->tls_session != NULL)
	    SSL_SESSION_free(upstream->tls_session);
	upstream->tls_session = SSL_get1_session(upstream->tls_obj);
	/* Reset timeout on success*/
	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
	upstream->event.read_cb = NULL;
	upstream->event.write_cb = upstream_write_cb;
	GETDNS_SCHEDULE_EVENT(upstream->loop, upstream->fd, TIMEOUT_FOREVER,
	    getdns_eventloop_event_init(&upstream->event, upstream,
	     NULL, upstream_write_cb, NULL));
	return 0;
}

static int
tls_connected(getdns_upstream* upstream)
{
	/* Already have a TLS connection*/
	if (upstream->tls_hs_state == GETDNS_HS_DONE && 
	    (upstream->tls_obj != NULL))
		return 0;

	/* Already tried and failed, so let the fallback code take care of things */
	if (upstream->tls_hs_state == GETDNS_HS_FAILED)
		return STUB_TLS_SETUP_ERROR;

	/* Lets make sure the connection is up before we try a handshake*/
	int q = tcp_connected(upstream);
	if (q != 0) {
		if (q == STUB_TCP_ERROR)
			tls_cleanup(upstream, 0);
		return q;
	}

	return tls_do_handshake(upstream);
}

/***************************/
/* TLS read/write functions*/
/***************************/

static int
stub_tls_read(getdns_upstream *upstream, getdns_tcp_state *tcp,
              struct mem_funcs *mf)
{
	ssize_t  read;
	uint8_t *buf;
	size_t   buf_size;
	SSL* tls_obj = upstream->tls_obj;

	int q = tls_connected(upstream);
	if (q != 0)
		return q;

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

static int
stub_tls_write(getdns_upstream *upstream, getdns_tcp_state *tcp,
               getdns_network_req *netreq)
{
	size_t          pkt_len;
	ssize_t         written;
	uint16_t        query_id;
	intptr_t        query_id_intptr;
	SSL* tls_obj = upstream->tls_obj;
	uint16_t        padding_sz;

	int q = tls_connected(upstream);
	if (q != 0)
		return q;
	if (!tls_auth_status_ok(upstream, netreq))
		return STUB_TLS_SETUP_ERROR;

	/* Do we have remaining data that we could not write before?  */
	if (! tcp->write_buf) {
		/* No, this is an initial write. Try to send
		 */

		 /* Find a unique query_id not already written (or in
		 * the write_queue) for that upstream.  Register this netreq 
		 * by query_id in the process.
		 */
		do {
			query_id = arc4random();
			query_id_intptr = (intptr_t)query_id;
			netreq->node.key = (void *)query_id_intptr;

		} while (!_getdns_rbtree_insert(
		    &netreq->upstream->netreq_by_query_id, &netreq->node));

		GLDNS_ID_SET(netreq->query, query_id);
		/* TODO: Review if more EDNS0 handling can be centralised.*/
		if (netreq->opt) {
			_getdns_network_req_clear_upstream_options(netreq);
			/* no limits on the max udp payload size with tcp */
			gldns_write_uint16(netreq->opt + 3, 65535);
			/* we do not edns_cookie over TLS, since TLS
			 * provides stronger guarantees than cookies
			 * already */
			if (netreq->owner->edns_client_subnet_private)
				if (attach_edns_client_subnet_private(netreq))
					return STUB_OUT_OF_OPTIONS;
			if (netreq->upstream->writes_done % EDNS_KEEPALIVE_RESEND == 0 && 
				netreq->owner->context->idle_timeout != 0) {
				/* Add the keepalive option to every nth query on this 
				   connection */
				DEBUG_STUB("%s %-35s: FD:  %d Requesting keepalive \n",  
			             STUB_DEBUG_SETUP, __FUNCTION__, upstream->fd);
				if (attach_edns_keepalive(netreq))
					return STUB_OUT_OF_OPTIONS;
				netreq->keepalive_sent = 1;
			}
			if (netreq->owner->tls_query_padding_blocksize > 1) {
				pkt_len = netreq->response - netreq->query;
				pkt_len += 4; /* this accounts for the OPTION-CODE and OPTION-LENGTH of the padding */
				padding_sz = pkt_len % netreq->owner->tls_query_padding_blocksize;
				if (padding_sz)
					padding_sz = netreq->owner->tls_query_padding_blocksize - padding_sz;
				if (_getdns_network_req_add_upstream_option(netreq,
									    EDNS_PADDING_OPCODE,
									    padding_sz, NULL))
					return STUB_OUT_OF_OPTIONS;
			}
		}

		pkt_len = _getdns_network_req_add_tsig(netreq);
		/* We have an initialized packet buffer.
		 * Lets see how much of it we can write */
		
		/* TODO[TLS]: Handle error cases, partial writes, renegotiation etc. */
		ERR_clear_error();
		written = SSL_write(tls_obj, netreq->query - 2, pkt_len + 2);
		if (written <= 0)
			return STUB_TCP_ERROR;

		/* We were able to write everything!  Start reading. */
		return (int) query_id;

	} 

	return STUB_TCP_ERROR;
}

static uint64_t
_getdns_get_time_as_uintt64() {
	
	struct timeval tv;
	uint64_t       now;
	
	if (gettimeofday(&tv, NULL)) {
		return 0;
	}
	now = tv.tv_sec * 1000000 + tv.tv_usec;
	return now;
}

/**************************/
/* UDP callback functions */
/**************************/

static void
stub_udp_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;
	getdns_upstream *upstream = netreq->upstream;
	ssize_t       read;
	DEBUG_STUB("%s %-35s: MSG: %p \n", STUB_DEBUG_READ, 
	             __FUNCTION__, netreq);

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	read = recvfrom(netreq->fd, (void *)netreq->response,
	    netreq->max_udp_payload_size + 1, /* If read == max_udp_payload_size
	                                       * then all is good.  If read ==
	                                       * max_udp_payload_size + 1, then
	                                       * we receive more then requested!
	                                       * i.e. overflow
	                                       */
	    0, NULL, NULL);
	if (read == -1 && _getdns_EWOULDBLOCK)
		return;

	if (read < GLDNS_HEADER_SIZE)
		return; /* Not DNS */
	
	if (GLDNS_ID_WIRE(netreq->response) != netreq->query_id)
		return; /* Cache poisoning attempt ;) */

	if (netreq->owner->edns_cookies && match_and_process_server_cookie(
	    upstream, netreq->response, read))
		return; /* Client cookie didn't match? */

	close(netreq->fd);
	while (GLDNS_TC_WIRE(netreq->response)) {
		DEBUG_STUB("%s %-35s: MSG: %p TC bit set in response \n", STUB_DEBUG_READ, 
		             __FUNCTION__, netreq);
		if (!(netreq->transport_current < netreq->transport_count))
			break;
		getdns_transport_list_t next_transport = 
		                      netreq->transports[++netreq->transport_current];
		if (next_transport != GETDNS_TRANSPORT_TCP &&
		    next_transport != GETDNS_TRANSPORT_TLS)
			break;
		/* For now, special case where fallback should be on the same upstream*/
		if ((netreq->fd = upstream_connect(upstream, next_transport,
		                                   dnsreq)) == -1)
			break;
		upstream_schedule_netreq(netreq->upstream, netreq);
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, -1, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event,
		    netreq, NULL, NULL, stub_timeout_cb));

		return;
	}
	netreq->response_len = read;
	dnsreq->upstreams->current = 0;
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	netreq->state = NET_REQ_FINISHED;
	_getdns_check_dns_req_complete(dnsreq);
}

static void
stub_udp_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req     *dnsreq = netreq->owner;
	size_t             pkt_len;
	DEBUG_STUB("%s %-35s: MSG: %p \n", STUB_DEBUG_WRITE, 
	             __FUNCTION__, netreq);

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	netreq->debug_start_time = _getdns_get_time_as_uintt64();
	netreq->debug_udp = 1;
	netreq->query_id = arc4random();
	GLDNS_ID_SET(netreq->query, netreq->query_id);
	if (netreq->opt) {
		_getdns_network_req_clear_upstream_options(netreq);
		if (netreq->edns_maximum_udp_payload_size == -1)
			gldns_write_uint16(netreq->opt + 3,
			    ( netreq->max_udp_payload_size =
			      netreq->upstream->addr.ss_family == AF_INET6
			    ? 1232 : 1432));
		if (netreq->owner->edns_cookies)
			if (attach_edns_cookie(netreq))
				return; /* too many upstream options */
		if (netreq->owner->edns_client_subnet_private)
			if (attach_edns_client_subnet_private(netreq))
				return; /* too many upstream options */
	}
	pkt_len = _getdns_network_req_add_tsig(netreq);
	if ((ssize_t)pkt_len != sendto(
	    netreq->fd, (const void *)netreq->query, pkt_len, 0,
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

/**************************/
/* Upstream callback functions*/
/**************************/

static void
process_finished_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_dns_req *dnsreq;

	/* Upstream->loop is always the async one, because finished_events
	 * are only scheduled against (and thus fired from) the async loop
	 */
	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->finished_event);
	upstream->finished_event.timeout_cb = NULL;
	while (upstream->finished_dnsreqs) {
		dnsreq = upstream->finished_dnsreqs;
		upstream->finished_dnsreqs = dnsreq->finished_next;
		_getdns_check_dns_req_complete(dnsreq);
	}
}

static void
upstream_read_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	DEBUG_STUB("%s %-35s: FD:  %d \n", STUB_DEBUG_READ, __FUNCTION__,
	            upstream->fd);
	getdns_network_req *netreq;
	int q;
	uint16_t query_id;
	intptr_t query_id_intptr;
	getdns_dns_req *dnsreq;

	if (tls_should_read(upstream))
		q = stub_tls_read(upstream, &upstream->tcp,
		                 &upstream->upstreams->mf);
	else
		q = stub_tcp_read(upstream->fd, &upstream->tcp,
		                 &upstream->upstreams->mf);

	switch (q) {
	case STUB_TCP_AGAIN:
		/* WSA TODO: if callback is still upstream_read_cb, do it again
		 */
	case STUB_TCP_WOULDBLOCK:
		return;

	case STUB_TCP_ERROR:
		upstream_erred(upstream);
		return;

	default:

		/* Lookup netreq */
		query_id = (uint16_t) q;
		query_id_intptr = (intptr_t) query_id;
		netreq = (getdns_network_req *)_getdns_rbtree_delete(
		    &upstream->netreq_by_query_id, (void *)query_id_intptr);
		if (! netreq) /* maybe canceled */ {
			/* reset read buffer */
			upstream->tcp.read_pos = upstream->tcp.read_buf;
			upstream->tcp.to_read = 2;
			return;
		}

		DEBUG_STUB("%s %-35s: MSG: %p (read)\n",
		    STUB_DEBUG_READ, __FUNCTION__, netreq);
		netreq->state = NET_REQ_FINISHED;
		netreq->response = upstream->tcp.read_buf;
		netreq->response_len =
		    upstream->tcp.read_pos - upstream->tcp.read_buf;
		upstream->tcp.read_buf = NULL;
		upstream->responses_received++;
		/* TODO[TLS]: I don't think we should do this for TCP. We should stay
		 * on a working connection until we hit a problem.*/
		upstream->upstreams->current = 0;
		
		/* !THIS CODE NEEDS TESTING! */
		if (netreq->owner->edns_cookies &&
		    match_and_process_server_cookie(
		    netreq->upstream, netreq->tcp.read_buf,
		    netreq->tcp.read_pos - netreq->tcp.read_buf))
			return; /* Client cookie didn't match (or FORMERR) */

		if (netreq->owner->context->idle_timeout != 0)
		     process_keepalive(netreq->upstream, netreq, netreq->response,
		                       netreq->response_len);

		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		/* This also reschedules events for the upstream*/
		stub_cleanup(netreq);

		if (!upstream->is_sync_loop || netreq->owner->is_sync_request)
			_getdns_check_dns_req_complete(netreq->owner);

		else {
			assert(upstream->is_sync_loop &&
			    !netreq->owner->is_sync_request);

			/* We have a result for an asynchronously scheduled
			 * netreq, while processing the synchronous loop.
			 * Queue dns_req_complete checks.
			 */

			/* First check if one for the dns_req already exists */
			for ( dnsreq = upstream->finished_dnsreqs
			    ; dnsreq && dnsreq != netreq->owner
			    ; dnsreq = dnsreq->finished_next)
				; /* pass */

			if (!dnsreq) {
				/* Schedule dns_req_complete check for this
				 * netreq's owner
				 */
				dnsreq = netreq->owner;
				dnsreq->finished_next =
				    upstream->finished_dnsreqs;
				upstream->finished_dnsreqs = dnsreq;
			
				if (!upstream->finished_event.timeout_cb) {
					upstream->finished_event.timeout_cb
					    = process_finished_cb;
					GETDNS_SCHEDULE_EVENT(
					    dnsreq->context->extension,
					    -1, 1, &upstream->finished_event);
				}
			}
		}

		/* WSA TODO: if callback is still upstream_read_cb, do it again
		 */
		return;
	}
}

static void
upstream_write_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_network_req *netreq = upstream->write_queue;
	int q;
	
	if (!netreq) {
		GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
		upstream->event.write_cb = NULL;
		return;
	}
	/* TODO: think about TCP AGAIN */
	netreq->debug_start_time = _getdns_get_time_as_uintt64();
	DEBUG_STUB("%s %-35s: MSG: %p (writing)\n", STUB_DEBUG_WRITE,
	            __FUNCTION__, netreq);

	if (tls_requested(netreq) && tls_should_write(upstream))
		q = stub_tls_write(upstream, &upstream->tcp, netreq);
	else
		q = stub_tcp_write(upstream->fd, &upstream->tcp, netreq);

	switch (q) {
	case STUB_TCP_AGAIN:
		/* WSA TODO: if callback is still upstream_write_cb, do it again
		 */

	case STUB_TCP_WOULDBLOCK:
		return;

	case STUB_TCP_ERROR:
		/* Problem with the TCP connection itself. Need to fallback.*/
		DEBUG_STUB("%s %-35s: MSG: %p ERROR!\n", STUB_DEBUG_WRITE,
		             __FUNCTION__, ((getdns_network_req *)userarg));
		upstream->tcp.write_error = 1;
		/* Use policy of trying next upstream in this case. Need more work on
		 * TCP connection re-use.*/
		stub_next_upstream(netreq);
		/* Fall through */
	case STUB_TLS_SETUP_ERROR:
		/* Could not complete the TLS set up. Need to fallback.*/
		stub_cleanup(netreq);
		if (fallback_on_write(netreq) == STUB_TCP_ERROR) {
			netreq->state = NET_REQ_FINISHED;
			_getdns_check_dns_req_complete(netreq->owner);
		}
		return;

	default:
		/* Need this because auth status is reset on connection clode */
		netreq->debug_tls_auth_status = netreq->upstream->tls_auth_failed;
		upstream->writes_done++;
		netreq->query_id = (uint16_t) q;
		/* Unqueue the netreq from the write_queue */
		if (!(upstream->write_queue = netreq->write_queue_tail)) {
			upstream->write_queue_last = NULL;
			GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
			upstream->event.write_cb = NULL;
			/* Reschedule (if already reading) to clear writable */
			if (upstream->event.read_cb) {
				GETDNS_SCHEDULE_EVENT(upstream->loop,
				    upstream->fd, TIMEOUT_FOREVER,
				    &upstream->event);
			}
		}
		/* Schedule reading (if not already scheduled) */
		if (!upstream->event.read_cb) {
			GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
			upstream->event.read_cb = upstream_read_cb;
			GETDNS_SCHEDULE_EVENT(upstream->loop,
			    upstream->fd, TIMEOUT_FOREVER, &upstream->event);
		}
		/* WSA TODO: if callback is still upstream_write_cb, do it again
		 */
		return;
	}
}


/*****************************/
/* Upstream utility functions*/
/*****************************/

static int
upstream_transport_valid(getdns_upstream *upstream,
                        getdns_transport_list_t transport,
                        getdns_network_req *netreq)
{
	/* Single shot UDP, uses same upstream as plain TCP. */
	if (transport == GETDNS_TRANSPORT_UDP)
		return (upstream->transport == GETDNS_TRANSPORT_TCP ? 1:0);
	/* If we got an error and have never managed to write to this TCP then
	   treat it as a hard failure */
	if (transport == GETDNS_TRANSPORT_TCP &&
	    upstream->transport == GETDNS_TRANSPORT_TCP &&
	    upstream->tcp.write_error != 0) {
		return 0;
	}
	/* Otherwise, transport must match, and not have failed */
	if (upstream->transport != transport)
		return 0;
	if (tls_failed(upstream) || !tls_auth_status_ok(upstream, netreq))
		return 0;
	return 1;
}

static getdns_upstream *
upstream_select(getdns_network_req *netreq, getdns_transport_list_t transport)
{
	getdns_upstream *upstream;
	getdns_upstreams *upstreams = netreq->owner->upstreams;
	size_t i;
	
	if (!upstreams->count)
		return NULL;
	
	
	/* Only do this when a new message is scheduled?*/
	for (i = 0; i < upstreams->count; i++)
		if (upstreams->upstreams[i].to_retry <= 0)
			upstreams->upstreams[i].to_retry++;

	/* TODO[TLS]: Should we create a tmp array of upstreams with correct*/
	/*  transport type and/or maintain separate current for transports?*/
	i = upstreams->current;
	DEBUG_STUB("%s %-35s: Starting from upstream: %d of %d available \n", STUB_DEBUG_SETUP,
	            __FUNCTION__, (int)i, (int)upstreams->count);
	do {
		if (upstreams->upstreams[i].to_retry > 0 &&
		    upstream_transport_valid(&upstreams->upstreams[i], transport, netreq)) {
			upstreams->current = i;
			DEBUG_STUB("%s %-35s: Selected upstream:      %d      %p transport: %d\n",
			           STUB_DEBUG_SETUP, __FUNCTION__, (int)i, 
			           &upstreams->upstreams[i], transport);
			return &upstreams->upstreams[i];
		}
		if (++i >= upstreams->count)
			i = 0;
	} while (i != upstreams->current);

	upstream = upstreams->upstreams;
	for (i = 0; i < upstreams->count; i++)
		if (upstreams->upstreams[i].back_off < upstream->back_off &&
			upstream_transport_valid(&upstreams->upstreams[i], transport, netreq))
			upstream = &upstreams->upstreams[i];

	/* Need to check again that the transport is valid */
	if (!upstream_transport_valid(upstream, transport, netreq)) {
		DEBUG_STUB("%s %-35s: No valid upstream available for transport %d!\n",
		           STUB_DEBUG_SETUP, __FUNCTION__, transport);
		return NULL;
	}
	upstream->back_off++;
	upstream->to_retry = 1;
	upstreams->current = upstream - upstreams->upstreams;
	return upstream;
}


int
upstream_connect(getdns_upstream *upstream, getdns_transport_list_t transport,
                    getdns_dns_req *dnsreq) 
{
	DEBUG_STUB("%s %-35s: Checking upstream connection:  %p\n", STUB_DEBUG_SETUP, 
	           __FUNCTION__, upstream);
	int fd = -1;
	switch(transport) {
	case GETDNS_TRANSPORT_UDP:
		if ((fd = socket(
		    upstream->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
			return -1;
		getdns_sock_nonblock(fd);
		return fd;

	case GETDNS_TRANSPORT_TCP:
		/* Use existing if available*/
		if (upstream->fd != -1)
			return upstream->fd;
		fd = tcp_connect(upstream, transport);
		upstream->loop = dnsreq->loop;
		upstream->is_sync_loop = dnsreq->is_sync_request;
		upstream->fd = fd;
		break;
	
	case GETDNS_TRANSPORT_TLS:
		/* Use existing if available*/
		if (upstream->fd != -1 && !tls_failed(upstream))
			return upstream->fd;
		fd = tcp_connect(upstream, transport);
		if (fd == -1) return -1;
		upstream->tls_obj = tls_create_object(dnsreq, fd, upstream);
		if (upstream->tls_obj == NULL) {
			close(fd);
			return -1;
		}

		if (upstream->tls_session != NULL) 
		    SSL_set_session(upstream->tls_obj, upstream->tls_session);
		upstream->tls_hs_state = GETDNS_HS_WRITE;
		upstream->loop = dnsreq->loop;
		upstream->is_sync_loop = dnsreq->is_sync_request;
		upstream->fd = fd;
		break;
	default:
		return -1;
		/* Nothing to do*/
	}
	return fd;
}

static getdns_upstream*
upstream_find_for_transport(getdns_network_req *netreq,
                             getdns_transport_list_t transport,
                             int *fd)
{
	// TODO[TLS]: Need to loop over upstreams here!! 
	getdns_upstream *upstream = upstream_select(netreq, transport);
	if (!upstream)
		return NULL;
	*fd = upstream_connect(upstream, transport, netreq->owner);
	DEBUG_STUB("%s %-35s: FD:  %d Connected for upstream: %p\n", 
	           STUB_DEBUG_SETUP, __FUNCTION__, *fd, upstream);
	return upstream;
}

static int
upstream_find_for_netreq(getdns_network_req *netreq)
{
	int fd = -1;
	getdns_upstream *upstream;
	for (size_t i = netreq->transport_current; 
	            i < netreq->transport_count; i++) {
		upstream = upstream_find_for_transport(netreq,
		                                  netreq->transports[i],
		                                  &fd);
		if (fd == -1 || !upstream)
			continue;
		netreq->transport_current = i;
		netreq->upstream = upstream;
		netreq->keepalive_sent = 0;
		return fd;
	}
	return -1;
}

/************************/
/* Scheduling functions */
/***********************/

static int
fallback_on_write(getdns_network_req *netreq) 
{

	/* Deal with UDP and change error code*/

	DEBUG_STUB("%s %-35s: MSG: %p FALLING BACK \n", STUB_DEBUG_SCHEDULE, __FUNCTION__, netreq);

	/* Try to find a fallback transport*/
	getdns_return_t result = _getdns_submit_stub_request(netreq);

	if (result != GETDNS_RETURN_GOOD)
		return STUB_TCP_ERROR;

	return (netreq->transports[netreq->transport_current] 
	         == GETDNS_TRANSPORT_UDP) ?
	      netreq->fd : netreq->upstream->fd;
}

static void
upstream_reschedule_events(getdns_upstream *upstream, size_t idle_timeout) {

	DEBUG_STUB("%s %-35s: FD:  %d \n", STUB_DEBUG_SCHEDULE, 
	             __FUNCTION__, upstream->fd);
	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
	if (!upstream->write_queue && upstream->event.write_cb) {
		upstream->event.write_cb = NULL;
	}
	if (upstream->write_queue && !upstream->event.write_cb) {
		upstream->event.write_cb = upstream_write_cb;
	}
	if (!upstream->netreq_by_query_id.count && upstream->event.read_cb) {
		upstream->event.read_cb = NULL;
	}
	if (upstream->netreq_by_query_id.count && !upstream->event.read_cb) {
		upstream->event.read_cb = upstream_read_cb;
	}
	if (upstream->event.read_cb || upstream->event.write_cb)
		GETDNS_SCHEDULE_EVENT(upstream->loop,
		    upstream->fd, TIMEOUT_FOREVER, &upstream->event);
	else {
		DEBUG_STUB("%s %-35s: FD:  %d Connection idle - timeout is %d\n", 
			    STUB_DEBUG_SCHEDULE, __FUNCTION__, upstream->fd, (int)idle_timeout);
		upstream->event.timeout_cb = upstream_idle_timeout_cb;
		if (upstream->tcp.write_error != 0)
			idle_timeout = 0;
		GETDNS_SCHEDULE_EVENT(upstream->loop, -1, 
		    idle_timeout, &upstream->event);
	}
}

static void
upstream_schedule_netreq(getdns_upstream *upstream, getdns_network_req *netreq)
{
	DEBUG_STUB("%s %-35s: MSG: %p (schedule event)\n", STUB_DEBUG_SCHEDULE, __FUNCTION__, netreq);
	/* We have a connected socket and a global event loop */
	assert(upstream->fd >= 0);
	assert(upstream->loop);

	/* Append netreq to write_queue */
	if (!upstream->write_queue) {
		upstream->write_queue = upstream->write_queue_last = netreq;
		GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
		if (netreq->owner->is_sync_request && !upstream->is_sync_loop){
			/* An initial synchronous call, change loop */
			upstream->loop = netreq->owner->loop;
			upstream->is_sync_loop = 1;
		}
		upstream->event.timeout_cb = NULL;
		upstream->event.write_cb = upstream_write_cb;
		if (upstream->tls_hs_state == GETDNS_HS_WRITE) {
			/* Set a timeout on the upstream so we can catch failed setup*/
			/* TODO[TLS]: When generic fallback supported, we should decide how
			 * to split the timeout between transports. */
			upstream->event.timeout_cb = upstream_tls_timeout_cb;
			GETDNS_SCHEDULE_EVENT(upstream->loop,
			    upstream->fd, netreq->owner->context->timeout / 2, 
			    &upstream->event);
		} else {
			GETDNS_SCHEDULE_EVENT(upstream->loop,
			    upstream->fd, TIMEOUT_FOREVER, &upstream->event);
		}
	} else if (netreq->owner->is_sync_request && !upstream->is_sync_loop) {
		/* Initial synchronous call on an upstream in use,
		 * prioritize this request (insert at 0)
		 * and reschedule against synchronous loop.
		 */
		netreq->write_queue_tail = upstream->write_queue;
		upstream->write_queue = netreq;
		GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
		upstream->loop = netreq->owner->loop;
		upstream->is_sync_loop = 1;
		GETDNS_SCHEDULE_EVENT(upstream->loop, upstream->fd,
		    TIMEOUT_FOREVER, &upstream->event);

	} else {
		/* "Follow-up synchronous" or Asynchronous call,
		 * this request comes last (append)
		 */
		upstream->write_queue_last->write_queue_tail = netreq;
		upstream->write_queue_last = netreq;
	}
}

getdns_return_t
_getdns_submit_stub_request(getdns_network_req *netreq)
{
	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNCTION__,
	           netreq, netreq->request_type);
	int fd = -1;
	getdns_dns_req *dnsreq = netreq->owner;

	/* This does a best effort to get a initial fd.
	 * All other set up is done async*/
	fd = upstream_find_for_netreq(netreq);
	if (fd == -1)
		return GETDNS_RETURN_GENERIC_ERROR;

	getdns_transport_list_t transport =
	                             netreq->transports[netreq->transport_current];
	switch(transport) {
	case GETDNS_TRANSPORT_UDP:
		netreq->fd = fd;
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		    NULL, stub_udp_write_cb, stub_timeout_cb));
		return GETDNS_RETURN_GOOD;

	case GETDNS_TRANSPORT_TLS:
	case GETDNS_TRANSPORT_TCP:
		upstream_schedule_netreq(netreq->upstream, netreq);
		/* For TLS, set a short timeout to catch setup problems. This is reset
		   when the connection is successful.*/
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
		/*************************************************************
		 ******                                                  *****
		 ******            Scheduling differences of             *****
		 ******      synchronous and asynchronous requests       *****
		 ******                                                  *****
		 *************************************************************
		 *
		 * Besides the asynchronous event loop, which is typically
		 * shared with the application, every getdns context also
		 * has another event loop (not registered by the user) which
		 * is used specifically and only for synchronous requests:
		 * context->sync_eventloop.
		 *
		 * We do not use the asynchronous loop for the duration of the
		 * synchronous query, because:
		 * - Callbacks for outstanding (and thus asynchronous) queries
		 *   might fire as a side effect.
		 * - But worse, since the asynchronous loop is created and 
		 *   managed by the user, which may well have her own non-dns
		 *   related events scheduled against it, they will fire as
		 *   well as a side effect of doing the synchronous request!
		 *
		 *
		 * Transports that keep connections open, have their own event
		 * structure to keep their connection state.  The event is 
		 * associated with the upstream struct.  Note that there is a
		 * separate upstream struct for each state full transport, so
		 * each upstream has multiple transport structs!
		 *
		 *     side note: The upstream structs have their own reference
		 *                to the "context's" event loop so they can,
		 *                in theory, be detached (to finish running 
		 *                queries for example).
		 *
		 * If a synchronous request is scheduled for such a transport,
		 * then the sync-loop temporarily has to "run" that 
		 * upstream/transport's event!  Outstanding requests for that
		 * upstream/transport might come in while processing the 
		 * synchronous call.  When this happens, they are queued up
		 * (at upstream->finished_queue) and an timeout event of 1
		 * will be scheduled against the asynchronous loop to start
		 * processing those received request as soon as the 
		 * asynchronous loop will be run.
		 *
		 *
		 * When getdns is linked with libunbound 1.5.8 or older, then
		 * when a RECURSING synchronous request is made then 
		 * outstanding asynchronously scheduled RECURSING requests
		 * may fire as a side effect, as we reuse the same code path 
		 * For both synchronous and asynchronous calls,
		 * ub_resolve_async() is used under the hood.
		 *
		 * With libunbound versions newer than 1.5.8, libunbound will
		 * share the event loops used with getdns which will prevent
		 * these side effects from happening.
		 *
		 *
		 * The event loop used for a specific request is in 
		 * dnsreq->loop.  The asynchronous is always also available
		 * at the upstream as upstream->loop. 
		 */
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, -1,

		    dnsreq->context->timeout,

		    getdns_eventloop_event_init(
		    &netreq->event, netreq, NULL, NULL,

		    ( transport == GETDNS_TRANSPORT_TLS
		    ?  stub_tls_timeout_cb : stub_timeout_cb)));

		return GETDNS_RETURN_GOOD;
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}

/* stub.c */
