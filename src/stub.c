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

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "config.h"
#include <fcntl.h>
#include "stub.h"
#include "gldns/gbuffer.h"
#include "gldns/pkthdr.h"
#include "gldns/rrdef.h"
#include "gldns/str2wire.h"
#include "rr-iter.h"
#include "context.h"
#include "util-internal.h"
#include "general.h"

#define STUB_OUT_OF_OPTIONS -5 /* upstream options exceeded MAXIMUM_UPSTREAM_OPTION_SPACE */
#define STUB_TLS_SETUP_ERROR -4
#define STUB_TCP_AGAIN -3
#define STUB_TCP_ERROR -2

/* Don't currently have access to the context whilst doing handshake */
#define TIMEOUT_TLS 2500

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
static void upstream_reschedule_netreq_events(getdns_upstream *upstream, 
                                     getdns_network_req *netreq);
static int  upstream_connect(getdns_upstream *upstream, 
                             getdns_transport_list_t transport,
                             getdns_dns_req *dnsreq);
static void netreq_upstream_read_cb(void *userarg);
static void netreq_upstream_write_cb(void *userarg);
static int  fallback_on_write(getdns_network_req *netreq);

static void stub_tcp_write_cb(void *userarg);
static void stub_timeout_cb(void *userarg);
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

static int
match_and_process_server_cookie(
    getdns_upstream *upstream, uint8_t *response, size_t response_len)
{
	_getdns_rr_iter rr_iter_storage, *rr_iter;
	const uint8_t *pos;
	uint16_t rdata_len, opt_code = 0, opt_len = 0;

	/* Search for the OPT RR (if any) */
	for ( rr_iter = _getdns_rr_iter_init(&rr_iter_storage
	                                        , response, response_len)
	    ; rr_iter
	    ; rr_iter = _getdns_rr_iter_next(rr_iter)) {

		if (_getdns_rr_iter_section(rr_iter) !=
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

static int
create_starttls_request(getdns_dns_req *dnsreq, getdns_upstream *upstream,
                        getdns_eventloop *loop)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_dict* extensions = getdns_dict_create_with_context(dnsreq->context);
	if (!extensions) {
	    return 0;
	}
	r = getdns_dict_set_int(extensions, "specify_class", GLDNS_RR_CLASS_CH);
	if (r != GETDNS_RETURN_GOOD) {
	    getdns_dict_destroy(extensions);
		return 0;
	}
	upstream->starttls_req = _getdns_dns_req_new(dnsreq->context, loop,
	    "STARTTLS", GETDNS_RRTYPE_TXT, extensions);
	/*TODO[TLS]: TO BIT*/
	if (upstream->starttls_req == NULL)
		return 0;
	getdns_dict_destroy(extensions);

	upstream->starttls_req->netreqs[0]->upstream = upstream;
	return 1;
}

static int
is_starttls_response(getdns_network_req *netreq) 
{
	_getdns_rr_iter rr_iter_storage, *rr_iter;
	_getdns_rdf_iter rdf_iter_storage, *rdf_iter;
	uint16_t rr_type;
	gldns_pkt_section section;
	uint8_t starttls_name_space[256], owner_name_space[256];
	const uint8_t *owner_name, *starttls_name;
	size_t starttls_name_len = sizeof(starttls_name_space);
	size_t owner_name_len = sizeof(owner_name_space);;

	/* Servers that are not STARTTLS aware will refuse the CH query*/
	if (GLDNS_RCODE_NOERROR != GLDNS_RCODE_WIRE(netreq->response))
		return 0;

	if (GLDNS_ANCOUNT(netreq->response) != 1)
		return 0;

	for ( rr_iter = _getdns_rr_iter_init(&rr_iter_storage
	                                        , netreq->response
	                                        , netreq->response_len)
	    ; rr_iter
	    ; rr_iter = _getdns_rr_iter_next(rr_iter)) {

		section = _getdns_rr_iter_section(rr_iter);
		rr_type = gldns_read_uint16(rr_iter->rr_type);
		if (section != GLDNS_SECTION_ANSWER
		    || rr_type != GETDNS_RRTYPE_TXT)
			continue;

		owner_name = _getdns_owner_if_or_as_decompressed(
		    rr_iter, owner_name_space, &owner_name_len);
		if (!_getdns_dname_equal(netreq->owner->name, owner_name))
			continue;

		if (!(rdf_iter = _getdns_rdf_iter_init(
		     &rdf_iter_storage, rr_iter)))
			continue;

		if ((starttls_name = _getdns_rdf_if_or_as_decompressed(
		    rdf_iter, starttls_name_space, &starttls_name_len)) &&
		    _getdns_dname_equal(starttls_name, owner_name)) 
			return 1;

		return 0;
	}
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

static int
tcp_connect(getdns_upstream *upstream, getdns_transport_list_t transport) 
{
	int fd = -1;
	if ((fd = socket(upstream->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;

	getdns_sock_nonblock(fd);
#ifdef USE_TCP_FASTOPEN
	/* Leave the connect to the later call to sendto() if using TCP*/
	if (transport == GETDNS_TRANSPORT_TCP || 
	    transport == GETDNS_TRANSPORT_STARTTLS)
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
		if (errno != EINPROGRESS) {
			close(fd);
			return -1;
		}
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
	if (error == EINPROGRESS || error == EWOULDBLOCK) 
		return STUB_TCP_AGAIN; /* try again */
	else if (error != 0)
		return STUB_TCP_ERROR;
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
	DEBUG_STUB("*** %s(%p)\n", __FUNCTION__, netreq);
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
	upstream_reschedule_events(upstream, netreq->owner->context->idle_timeout);
}

static int
tls_cleanup(getdns_upstream *upstream)
{
	DEBUG_STUB("*** %s\n", __FUNCTION__);
	if (upstream->tls_obj != NULL)
		SSL_free(upstream->tls_obj);
	upstream->tls_obj = NULL;
	upstream->tls_hs_state = GETDNS_HS_FAILED;
	/* Reset timeout on failure*/
	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
	GETDNS_SCHEDULE_EVENT(upstream->loop, upstream->fd, TIMEOUT_FOREVER,
	    getdns_eventloop_event_init(&upstream->event, upstream,
	     NULL, upstream_write_cb, NULL));
	/* Reset sync event, with full timeout (which isn't correct)*/
	getdns_network_req *netreq = upstream->write_queue;
	if (netreq) {
		GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);
		GETDNS_SCHEDULE_EVENT(
		    netreq->owner->loop, upstream->fd, netreq->owner->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq, NULL,
		    ( netreq->owner->loop != netreq->upstream->loop /* Synchronous lookup? */
		    ? netreq_upstream_write_cb : NULL), stub_timeout_cb));
	}
	return STUB_TLS_SETUP_ERROR;
}

static void
upstream_erred(getdns_upstream *upstream)
{
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

static void
stub_erred(getdns_network_req *netreq)
{
	DEBUG_STUB("*** %s\n", __FUNCTION__);
	stub_next_upstream(netreq);
	stub_cleanup(netreq);
	/* TODO[TLS]: When we get an error (which is probably a timeout) and are 
	 * using to keep connections open should we leave the connection up here? */
	if (netreq->fd >= 0) close(netreq->fd);
	netreq->state = NET_REQ_FINISHED;
	_getdns_check_dns_req_complete(netreq->owner);
}

static void
stub_timeout_cb(void *userarg)
{
	DEBUG_STUB("*** %s(%p)\n", __FUNCTION__, userarg);
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	
	/* For now, mark a STARTTLS timeout as a failured negotiation and allow 
	 * fallback but don't close the connection. */
	if (netreq->owner == netreq->upstream->starttls_req) {
		netreq->upstream->tls_hs_state = GETDNS_HS_FAILED;
		stub_next_upstream(netreq);
		stub_cleanup(netreq);
		return;
	}

	stub_next_upstream(netreq);
	stub_cleanup(netreq);
	if (netreq->fd >= 0) close(netreq->fd);
	if (netreq->owner->user_callback)
		(void) _getdns_context_request_timed_out(netreq->owner);
	else {
		netreq->state = NET_REQ_FINISHED;
		_getdns_check_dns_req_complete(netreq->owner);
	}
}


static void
upstream_idle_timeout_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	DEBUG_STUB("*** %s: **Closing connection %d**\n", 
	           __FUNCTION__, upstream->fd);

	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
	upstream->event.timeout_cb = NULL;
	upstream->event.read_cb = NULL;
	upstream->event.write_cb = NULL;
	_getdns_upstream_shutdown(upstream);
}

static void
upstream_tls_timeout_cb(void *userarg)
{
	DEBUG_STUB("*** %s\n", __FUNCTION__);
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	/* Clean up and trigger a write to let the fallback code to its job */
	tls_cleanup(upstream);

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
	DEBUG_STUB("*** %s\n", __FUNCTION__);
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_upstream *upstream = netreq->upstream;
	/* Clean up and trigger a write to let the fallback code to its job */
	tls_cleanup(upstream);

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
		}
		pkt_len = netreq->response - netreq->query;
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

/*************************/
/* TLS Utility functions */
/*************************/

static int
tls_requested(getdns_network_req *netreq)
{
	return (netreq->transports[netreq->transport_current] ==
	        GETDNS_TRANSPORT_TLS ||
	        netreq->transports[netreq->transport_current] ==
	        GETDNS_TRANSPORT_STARTTLS) ?
	        1 : 0;
}

static int
tls_should_write(getdns_upstream *upstream)
{
	/* Should messages be written on TLS upstream. Remember that for STARTTLS
	 * the first message should got over TCP as the handshake isn't started yet.*/
	return ((upstream->transport == GETDNS_TRANSPORT_TLS ||
	         upstream->transport == GETDNS_TRANSPORT_STARTTLS) &&
	         upstream->tls_hs_state != GETDNS_HS_NONE) ? 1 : 0;
}

static int
tls_should_read(getdns_upstream *upstream)
{
	return ((upstream->transport == GETDNS_TRANSPORT_TLS ||
	         upstream->transport == GETDNS_TRANSPORT_STARTTLS) &&
	       !(upstream->tls_hs_state == GETDNS_HS_FAILED ||
	         upstream->tls_hs_state == GETDNS_HS_NONE)) ? 1 : 0;
}

static int 
tls_failed(getdns_upstream *upstream)
{
	/* No messages should be scheduled onto an upstream in this state */
	return ((upstream->transport == GETDNS_TRANSPORT_TLS ||
	         upstream->transport == GETDNS_TRANSPORT_STARTTLS) &&
	         upstream->tls_hs_state == GETDNS_HS_FAILED) ? 1 : 0;
}

static int
tls_auth_status_ok(getdns_upstream *upstream, getdns_network_req *netreq) {
	return (netreq->tls_auth_min == GETDNS_AUTHENTICATION_HOSTNAME &&
		    upstream->tls_auth_failed) ? 0 : 1;
}

int
tls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
#if defined(STUB_DEBUG) && STUB_DEBUG
	int     err;
	const char * err_str;

	err = X509_STORE_CTX_get_error(ctx);
	err_str = X509_verify_cert_error_string(err);
	DEBUG_STUB("--- %s, VERIFY RESULT: %s\n", __FUNCTION__, err_str);
#endif
	/*Always proceed without changing result*/
	return preverify_ok;
}

int
tls_verify_callback_with_fallback(int preverify_ok, X509_STORE_CTX *ctx)
{
#ifdef X509_V_ERR_HOSTNAME_MISMATCH
	int     err;
# if defined(STUB_DEBUG) && STUB_DEBUG
	const char * err_str;
# endif
	
	err = X509_STORE_CTX_get_error(ctx);
# if defined(STUB_DEBUG) && STUB_DEBUG
	err_str = X509_verify_cert_error_string(err);
	DEBUG_STUB("--- %s, VERIFY RESULT: (%d) \"%s\"\n", __FUNCTION__, err, err_str);
# endif
	/*Proceed if error is hostname mismatch*/
	if (err == X509_V_ERR_HOSTNAME_MISMATCH) {
		DEBUG_STUB("--- %s, PROCEEDING WITHOUT HOSTNAME VALIDATION!!\n", __FUNCTION__);
		return 1;
	}
	else
#endif
		return preverify_ok;
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

	/* NOTE: this code will fallback on a given upstream, without trying
	   authentication on other upstreams first. This is non-optimal and but avoids
	   multiple TLS handshakes before getting a usable connection. */

	/* If we have a hostname, always use it */
	if (upstream->tls_auth_name[0] != '\0') {
		/*Request certificate for the auth_name*/
		DEBUG_STUB("--- %s, HOSTNAME VERIFICATION REQUESTED for: %s\n"
		          , __FUNCTION__, upstream->tls_auth_name);
		SSL_set_tlsext_host_name(ssl, upstream->tls_auth_name);
#ifdef HAVE_SSL_HN_AUTH
		/* Set up native OpenSSL hostname verification*/
		X509_VERIFY_PARAM *param;
		param = SSL_get0_param(ssl);
		X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, upstream->tls_auth_name, 0);
		DEBUG_STUB("--- %s, HOSTNAME VERIFICATION REQUESTED \n", __FUNCTION__);
#else
		if (dnsreq->netreqs[0]->tls_auth_min == GETDNS_AUTHENTICATION_HOSTNAME) {
			/* TODO: Trigger post-handshake custom validation*/
			DEBUG_STUB("--- %s, ERROR: Authentication functionality not available\n", __FUNCTION__);
			upstream->tls_hs_state = GETDNS_HS_FAILED;
			upstream->tls_auth_failed = 1;
			return NULL;
		}
#endif
		/* Allow fallback to opportunistic if settings permit it*/
		if (dnsreq->netreqs[0]->tls_auth_min == GETDNS_AUTHENTICATION_HOSTNAME)
			SSL_set_verify(ssl, SSL_VERIFY_PEER, tls_verify_callback);
		else {
			SSL_set_verify(ssl, SSL_VERIFY_NONE, tls_verify_callback_with_fallback);
			SSL_set_cipher_list(ssl, "DEFAULT");
		}
	} else {
		/* Lack of host name is OK unless only authenticated TLS is specified*/
		if (dnsreq->netreqs[0]->tls_auth_min == GETDNS_AUTHENTICATION_HOSTNAME) {
			DEBUG_STUB("--- %s, ERROR: No host name provided for authentication\n", __FUNCTION__);
			upstream->tls_hs_state = GETDNS_HS_FAILED;
			upstream->tls_auth_failed = 1;
			return NULL;
		} else {
                  /* no hostname verification, so we will make opportunistic connections */
			DEBUG_STUB("--- %s, PROCEEDING WITHOUT HOSTNAME VALIDATION!!\n", __FUNCTION__);
			upstream->tls_auth_failed = 1;
			SSL_set_verify(ssl, SSL_VERIFY_NONE, tls_verify_callback_with_fallback);
			SSL_set_cipher_list(ssl, "DEFAULT");
		}
	}
	
	SSL_set_connect_state(ssl);
	(void) SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	return ssl;
}

static int
tls_do_handshake(getdns_upstream *upstream)
{
	DEBUG_STUB("--- %s\n", __FUNCTION__);
	int r;
	int want;
	ERR_clear_error();
	getdns_network_req *netreq = upstream->write_queue;
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
				/* Reschedule for synchronous */
				if (netreq && netreq->event.write_cb) {
					GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);
					GETDNS_SCHEDULE_EVENT(
					    netreq->owner->loop, upstream->fd, TIMEOUT_TLS,
					    getdns_eventloop_event_init(
					    &netreq->event, netreq,
					    netreq_upstream_read_cb, NULL,
					    stub_tls_timeout_cb));
				}
				upstream->tls_hs_state = GETDNS_HS_READ;
				return STUB_TCP_AGAIN;
			case SSL_ERROR_WANT_WRITE:
				GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
				upstream->event.read_cb = NULL;
				upstream->event.write_cb = upstream_write_cb;
				GETDNS_SCHEDULE_EVENT(upstream->loop,
				    upstream->fd, TIMEOUT_TLS, &upstream->event);
				/* Reschedule for synchronous */
				if (netreq && netreq->event.read_cb) {
					GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);
					GETDNS_SCHEDULE_EVENT(
					    netreq->owner->loop, upstream->fd, TIMEOUT_TLS,
					    getdns_eventloop_event_init(
					    &netreq->event, netreq,
					    NULL, netreq_upstream_write_cb,
					    stub_tls_timeout_cb));
				}
				upstream->tls_hs_state = GETDNS_HS_WRITE;
				return STUB_TCP_AGAIN;
			default:
				DEBUG_STUB("--- %s %s %d\n", __FUNCTION__, "Handshake failed: ", want);
				return tls_cleanup(upstream);
	   }
	}
	upstream->tls_hs_state = GETDNS_HS_DONE;
	r = SSL_get_verify_result(upstream->tls_obj);
#ifdef X509_V_ERR_HOSTNAME_MISMATCH
	if (r == X509_V_ERR_HOSTNAME_MISMATCH)
#endif
		upstream->tls_auth_failed = 1;
	/* Reset timeout on success*/
	GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
	upstream->event.read_cb = NULL;
	upstream->event.write_cb = upstream_write_cb;
	GETDNS_SCHEDULE_EVENT(upstream->loop, upstream->fd, TIMEOUT_FOREVER,
	    getdns_eventloop_event_init(&upstream->event, upstream,
	     NULL, upstream_write_cb, NULL));
	GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);
	GETDNS_SCHEDULE_EVENT(
	    netreq->owner->loop, upstream->fd, netreq->owner->context->timeout,
	    getdns_eventloop_event_init(&netreq->event, netreq, NULL,
	    ( netreq->owner->loop != netreq->upstream->loop /* Synchronous lookup? */
	    ? netreq_upstream_write_cb : NULL), stub_timeout_cb));
	/* Reschedule for synchronous */
	/* TODO[TLS]: Re-instating full context->timeout here is wrong, as time has 
	   passes since the netreq was originally scheduled, but we only hove one
	   timeout in sync mode.... Need a timer on requests really.... Worst case
	   is we add TIMEOUT_TLS to the total timeout, since TLS is likely to be
	   the first choice if it is used at all.*/
	if (netreq && (netreq->event.read_cb || netreq->event.write_cb))
		upstream_reschedule_netreq_events(upstream, netreq);
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
			tls_cleanup(upstream);
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

		pkt_len = netreq->response - netreq->query;
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
	DEBUG_STUB("%s\n", __FUNCTION__);
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
	if (GLDNS_TC_WIRE(netreq->response)) {
		if (!(netreq->transport_current < netreq->transport_count))
			goto done;
		getdns_transport_list_t next_transport = 
		                      netreq->transports[++netreq->transport_current];
		if (next_transport != GETDNS_TRANSPORT_TCP)
			goto done;
		/* For now, special case where fallback should be on the same upstream*/
		if ((netreq->fd = upstream_connect(upstream, next_transport,
		                                   dnsreq)) == -1)
			goto done;
		upstream_schedule_netreq(netreq->upstream, netreq);
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->upstream->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq, NULL,
		    ( dnsreq->loop != netreq->upstream->loop /* Synchronous lookup? */
		    ? netreq_upstream_write_cb : NULL), stub_timeout_cb));

		return;
	}
	netreq->response_len = read;
	dnsreq->upstreams->current = 0;
done:
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	netreq->state = NET_REQ_FINISHED;
	_getdns_check_dns_req_complete(dnsreq);
}

static void
stub_udp_write_cb(void *userarg)
{
	DEBUG_STUB("%s\n", __FUNCTION__);
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req     *dnsreq = netreq->owner;
	size_t             pkt_len;

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
	pkt_len = netreq->response - netreq->query;
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

/**************************/
/* TCP callback functions*/
/**************************/

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
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		stub_cleanup(netreq);
		close(netreq->fd);
		_getdns_check_dns_req_complete(dnsreq);
	}
}

static void
stub_tcp_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;
	int q;
	netreq->debug_start_time = _getdns_get_time_as_uintt64();
	switch ((q = stub_tcp_write(netreq->fd, &netreq->tcp, netreq))) {
	case STUB_TCP_AGAIN:
		return;

	case STUB_TCP_ERROR:
		stub_erred(netreq);
		return;

	default:
		netreq->debug_udp = 0;
		netreq->query_id = (uint16_t) q;
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		    stub_tcp_read_cb, NULL, stub_timeout_cb));
		return;
	}
}

/**************************/
/* Upstream callback functions*/
/**************************/

static void
upstream_read_cb(void *userarg)
{
	DEBUG_STUB("--- READ: %s\n", __FUNCTION__);
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_network_req *netreq;
	getdns_dns_req *dnsreq;
	int q;
	uint16_t query_id;
	intptr_t query_id_intptr;

	if (tls_should_read(upstream))
		q = stub_tls_read(upstream, &upstream->tcp,
		              &upstream->upstreams->mf);
	else
		q = stub_tcp_read(upstream->fd, &upstream->tcp,
		             &upstream->upstreams->mf);

	switch (q) {
	case STUB_TCP_AGAIN:
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

		netreq->state = NET_REQ_FINISHED;
		netreq->response = upstream->tcp.read_buf;
		netreq->response_len =
		    upstream->tcp.read_pos - upstream->tcp.read_buf;
		upstream->tcp.read_buf = NULL;
		upstream->responses_received++;
		/* TODO[TLS]: I don't think we should do this for TCP. We should stay
		 * on a working connection until we hit a problem.*/
		upstream->upstreams->current = 0;

		if (netreq->owner == upstream->starttls_req) {
			dnsreq = netreq->owner;
			if (is_starttls_response(netreq)) {
				upstream->tls_obj = tls_create_object(dnsreq,
				                                      upstream->fd,
				                                      upstream);
				if (upstream->tls_obj == NULL) 
					upstream->tls_hs_state = GETDNS_HS_FAILED;
				upstream->tls_hs_state = GETDNS_HS_WRITE;
			} else 
				upstream->tls_hs_state = GETDNS_HS_FAILED;

			/* Now reschedule the writes on this connection */
			GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
			GETDNS_SCHEDULE_EVENT(upstream->loop, upstream->fd,
			    netreq->owner->context->timeout,
			    getdns_eventloop_event_init(&upstream->event, upstream,
			     NULL, upstream_write_cb, NULL));
		}
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		/* This also reschedules events for the upstream*/
		stub_cleanup(netreq);

		/* More to read/write for syncronous lookups? */
		if (netreq->event.read_cb)
			upstream_reschedule_netreq_events(upstream, netreq);

		if (netreq->owner != upstream->starttls_req)
			_getdns_check_dns_req_complete(netreq->owner);
	}
}

static void
netreq_upstream_read_cb(void *userarg)
{
	DEBUG_STUB("--- READ: %s\n", __FUNCTION__);
	upstream_read_cb(((getdns_network_req *)userarg)->upstream);
}

static void
upstream_write_cb(void *userarg)
{
	getdns_upstream *upstream = (getdns_upstream *)userarg;
	getdns_network_req *netreq = upstream->write_queue;
	getdns_dns_req *dnsreq;
	int q;
	
	if (!netreq) {
		GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
		upstream->event.write_cb = NULL;
		return;
	}
	dnsreq = netreq->owner;
	/* TODO: think about TCP AGAIN */
	netreq->debug_start_time = _getdns_get_time_as_uintt64();
	
	DEBUG_STUB("--- WRITE: %s: %p TYPE: %d\n", __FUNCTION__, netreq,
	           netreq->request_type);
	if (tls_requested(netreq) && tls_should_write(upstream))
		q = stub_tls_write(upstream, &upstream->tcp, netreq);
	else
		q = stub_tcp_write(upstream->fd, &upstream->tcp, netreq);

	switch (q) {
	case STUB_TCP_AGAIN:
		return;

	case STUB_TCP_ERROR:
		/* Problem with the TCP connection itself. Need to fallback.*/
		DEBUG_STUB("--- WRITE: Setting write error\n");
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
		if (upstream->starttls_req && netreq->owner == upstream->starttls_req) {
			/* Now deschedule any further writes on this connection until we get
			 * the STARTTLS answer*/
			GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
			upstream->event.write_cb = NULL;
			GETDNS_SCHEDULE_EVENT(upstream->loop,
			    upstream->fd, TIMEOUT_FOREVER, &upstream->event);
		} else if (upstream->starttls_req) {
			/* Delay the cleanup of the STARTTLS req until the write of the next
			 * req in the queue since for sync req, the event on a request is
			 * used for the callback that writes the next req. */
			_getdns_dns_req_free(upstream->starttls_req);
			upstream->starttls_req = NULL;
		}
		/* With synchonous lookups, schedule the read locally too */
		if (netreq->event.write_cb) {
			GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
			GETDNS_SCHEDULE_EVENT(
			    dnsreq->loop, upstream->fd, dnsreq->context->timeout,
			    getdns_eventloop_event_init(&netreq->event, netreq,
			    netreq_upstream_read_cb,
			    (upstream->write_queue && !upstream->starttls_req ?
			      netreq_upstream_write_cb : NULL),
			    stub_timeout_cb));
		}
		return;
	}
}

static void
netreq_upstream_write_cb(void *userarg)
{
	DEBUG_STUB("--- WRITE: %s: %p TYPE: %d\n", __FUNCTION__,
	           ((getdns_network_req *)userarg),
	           ((getdns_network_req *)userarg)->request_type);
	upstream_write_cb(((getdns_network_req *)userarg)->upstream);
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
	/* Allow TCP messages to be sent on a STARTTLS upstream that hasn't
	 * upgraded to avoid opening a new connection if one is aleady open. */
	if (transport == GETDNS_TRANSPORT_TCP &&
	    upstream->transport == GETDNS_TRANSPORT_STARTTLS &&
	    upstream->tls_hs_state == GETDNS_HS_FAILED)
		return 1;
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
	DEBUG_STUB(" %s\n", __FUNCTION__);
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
	DEBUG_STUB(" current upstream: %d of %d \n",(int)i, (int)upstreams->count);
	do {
		if (upstreams->upstreams[i].to_retry > 0 &&
		    upstream_transport_valid(&upstreams->upstreams[i], transport, netreq)) {
			upstreams->current = i;
			DEBUG_STUB(" selected upstream: %d\n",(int)i);
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
		DEBUG_STUB(" ! No valid upstream available\n");
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
		upstream->loop = dnsreq->context->extension;
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
		upstream->tls_hs_state = GETDNS_HS_WRITE;
		upstream->loop = dnsreq->context->extension;
		upstream->fd = fd;
		break;
	case GETDNS_TRANSPORT_STARTTLS:
		/* Use existing if available. Let the fallback code handle it if
		 * STARTTLS isn't availble. */
		if (upstream->fd != -1)
			return upstream->fd;
		fd = tcp_connect(upstream, transport);
		if (fd == -1) return -1;
		if (!create_starttls_request(dnsreq, upstream, dnsreq->loop))
			return GETDNS_RETURN_GENERIC_ERROR;
		getdns_network_req *starttls_netreq = upstream->starttls_req->netreqs[0];
		upstream->loop = dnsreq->context->extension;
		upstream->fd = fd;
		upstream_schedule_netreq(upstream, starttls_netreq);
		/* Schedule at least the timeout locally, but use less than half the 
		 * context value so by default this timeouts before the TIMEOUT_TLS.
		 * And also the write if we perform a synchronous lookup */
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, upstream->fd, dnsreq->context->timeout / 3,
		    getdns_eventloop_event_init(&starttls_netreq->event,
		    starttls_netreq, NULL, (dnsreq->loop != upstream->loop
		    ? netreq_upstream_write_cb : NULL), stub_timeout_cb));
		break;
	default:
		return -1;
		/* Nothing to do*/
	}
	return fd;
}

static getdns_upstream*
find_upstream_for_specific_transport(getdns_network_req *netreq,
                             getdns_transport_list_t transport,
                             int *fd)
{
	// TODO[TLS]: Need to loop over upstreams here!! 
	getdns_upstream *upstream = upstream_select(netreq, transport);
	if (!upstream)
		return NULL;
	*fd = upstream_connect(upstream, transport, netreq->owner);
	DEBUG_STUB(" %s: Found: %d %p fd:%d\n", __FUNCTION__,
	            transport, upstream, upstream->fd);
	return upstream;
}

static int
find_upstream_for_netreq(getdns_network_req *netreq)
{
	int fd = -1;
	getdns_upstream *upstream;
	for (size_t i = netreq->transport_current; 
	            i < netreq->transport_count; i++) {
		upstream = find_upstream_for_specific_transport(netreq,
		                                  netreq->transports[i],
		                                  &fd);
		if (fd == -1 || !upstream)
			continue;
		netreq->transport_current = i;
		netreq->upstream = upstream;
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

	DEBUG_STUB("#-----> %s: %p TYPE: %d\n", __FUNCTION__, netreq, netreq->request_type);
	getdns_upstream *upstream = netreq->upstream;

	/* Try to find a fallback transport*/
	getdns_return_t result = _getdns_submit_stub_request(netreq);

	/* For sync messages we must re-schedule the events on the old upstream
	 * here too. Must schedule this last to make sure it is called back first! */
	if (netreq->owner->loop != upstream->loop)
		upstream_reschedule_netreq_events(upstream, upstream->write_queue);

	if (result != GETDNS_RETURN_GOOD)
		return STUB_TCP_ERROR;

	return (netreq->transports[netreq->transport_current] 
	         == GETDNS_TRANSPORT_UDP) ?
	      netreq->fd : netreq->upstream->fd;
}

static void
upstream_reschedule_events(getdns_upstream *upstream, size_t idle_timeout) {

	DEBUG_STUB("# %s: %p %d\n", __FUNCTION__, upstream, upstream->fd);
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
		DEBUG_STUB("# %s: *Idle connection %d* \n", 
			    __FUNCTION__, upstream->fd);
		upstream->event.timeout_cb = upstream_idle_timeout_cb;
		if (upstream->tcp.write_error != 0)
			idle_timeout = 0;
		GETDNS_SCHEDULE_EVENT(upstream->loop, upstream->fd, 
		    idle_timeout, &upstream->event);
	}
}

static void
upstream_reschedule_netreq_events(getdns_upstream *upstream,
                                  getdns_network_req *netreq) {
	if (netreq) {
	DEBUG_STUB("# %s: %p: TYPE: %d\n", __FUNCTION__,
	             netreq, netreq->request_type);
	getdns_dns_req *dnsreq = netreq->owner;
	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
	if (upstream->netreq_by_query_id.count || upstream->write_queue)
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, upstream->fd, dnsreq->context->timeout,
		    getdns_eventloop_event_init(&netreq->event, netreq,
		        (upstream->netreq_by_query_id.count ?
		         netreq_upstream_read_cb : NULL ),
		        (upstream->write_queue ?
		         netreq_upstream_write_cb : NULL),
		        stub_timeout_cb));
	}
	if (!upstream->netreq_by_query_id.count && !upstream->write_queue) {
		/* This is a sync call, and the connection is idle. But we can't set a
		 * timeout since we won't have an event loop if there are no netreqs.
		 * Could set a timer and check it when the next req comes in but...
		 * chances are it will be on the same transport and if we have a new
		 * req the conneciton is no longer idle so probably better to re-use
		 * than shut and immediately open a new one!
		 * So we will have to be aggressive and shut the connection....*/
		DEBUG_STUB("# %s: **Closing connection %d**\n",
		            __FUNCTION__, upstream->fd);
		_getdns_upstream_shutdown(upstream);
	}
}

static void
upstream_schedule_netreq(getdns_upstream *upstream, getdns_network_req *netreq)
{
	DEBUG_STUB("# %s: %p TYPE: %d\n", __FUNCTION__, netreq, netreq->request_type);
	/* We have a connected socket and a global event loop */
	assert(upstream->fd >= 0);
	assert(upstream->loop);

	/* Append netreq to write_queue */
	if (!upstream->write_queue) {
		upstream->write_queue = upstream->write_queue_last = netreq;
		GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
		upstream->event.timeout_cb = NULL;
		upstream->event.write_cb = upstream_write_cb;
		if (upstream->tls_hs_state == GETDNS_HS_WRITE ||
		    (upstream->starttls_req &&
		     upstream->starttls_req->netreqs[0] == netreq)) {
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
	} else {
		upstream->write_queue_last->write_queue_tail = netreq;
		upstream->write_queue_last = netreq;
	}
}

getdns_return_t
_getdns_submit_stub_request(getdns_network_req *netreq)
{
	DEBUG_STUB("--> %s\n", __FUNCTION__);
	int fd = -1;
	getdns_dns_req *dnsreq = netreq->owner;

	/* This does a best effort to get a initial fd.
	 * All other set up is done async*/
	fd = find_upstream_for_netreq(netreq);
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
		    NULL, (transport == GETDNS_TRANSPORT_UDP ?
		    stub_udp_write_cb: stub_tcp_write_cb), stub_timeout_cb));
		return GETDNS_RETURN_GOOD;
	
	case GETDNS_TRANSPORT_STARTTLS:
	case GETDNS_TRANSPORT_TLS:
	case GETDNS_TRANSPORT_TCP:
		upstream_schedule_netreq(netreq->upstream, netreq);
		/* TODO[TLS]: Change scheduling for sync calls. */
		/* For TLS, set a short timeout to catch setup problems. This is reset
		   when the connection is successful.*/
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
		/*************************************************************
		 ******                                                  *****
		 ******              Confusing code alert!               *****
		 ******                                                  *****
		 *************************************************************
		 *
		 * Synchronous requests have their own event loop for the
		 * occasion of that single request.  That event loop is in
		 * the dnsreq structure: dnsreq->loop;
		 *
		 * We do not use the context's loop for the duration of the
		 * synchronous query, because:
		 * - Callbacks for outstanding (and thus asynchronous) queries
		 *   might fire as a side effect.
		 * - But worse, since the context's loop is created and managed
		 *   by the user, which may well have her own non-dns related
		 *   events scheduled against it, they will fire as well as a
		 *   side effect of doing the synchronous request!
		 *
		 * Transports that keep connections open, have their own event
		 * structure to keep their connection state.  The event is 
		 * associated with the upstream struct.  Note that there is a
		 * separate upstream struct for each statefull transport, so
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
		 * upstream/transport might the fire then as well as a side
		 * effect.
		 *
		 *
		 * Discussion
		 * ==========
		 * Furthermore, when a RECURSING sync request is made (opposed
		 * to a STUB sync request) then outstanding RECURSING requests
		 * may fire as a side effect, as we reuse the same code path 
		 * as with async RECURSING requests.  In both cases 
		 * ub_resolve_async() is used under the hood instead of
		 * ub_resolve().  The fix (by calling ub_resolver()) we have
		 * to create more divergent code paths.
		 *
		 * If we would simply accept the fact that side effects can
		 * happen while doing sync requests, we could greatly simplify
		 * this code and have the same code path (for scheduling the
		 * request and the timeout) for both synchronous and
		 * asynchronous requests.
		 *
		 * We should ask ourself: How likely is it that an user that
		 * uses asynchronous queries would do a synchronous query, that
		 * should block all async activity, in between?  Is
		 * anticipating this behaviour (in which we only partly succeed
		 * to begin with) worth the complexity of divergent code paths?
		 */
		GETDNS_SCHEDULE_EVENT(
		    dnsreq->loop, netreq->upstream->fd, /*dnsreq->context->timeout,*/
		    (transport == GETDNS_TRANSPORT_TLS ?
		    dnsreq->context->timeout /2 : dnsreq->context->timeout),
		    getdns_eventloop_event_init(&netreq->event, netreq, NULL,
		    ( dnsreq->loop != netreq->upstream->loop /* Synchronous lookup? */
		    ? netreq_upstream_write_cb : NULL), 
		    ( transport == GETDNS_TRANSPORT_TLS ? 
		      stub_tls_timeout_cb : stub_timeout_cb)));

		return GETDNS_RETURN_GOOD;
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}

/* stub.c */
