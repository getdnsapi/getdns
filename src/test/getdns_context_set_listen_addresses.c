/*
 * Copyright (c) 2013, NLNet Labs, Verisign, Inc.
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
#include "getdns_context_set_listen_addresses.h"
#include "getdns/getdns_extra.h"
#include "types-internal.h"
#include <netdb.h>

#define DNS_REQUEST_SZ          4096
#define DOWNSTREAM_IDLE_TIMEOUT 5000
#define TCP_LISTEN_BACKLOG      16

typedef struct listen_data {
	getdns_eventloop_event   event;
	socklen_t                addr_len;
	struct sockaddr_storage  addr;
	int                      fd;
	getdns_transport_list_t  transport;

	getdns_context          *context;
	/* Should be per context eventually */
	getdns_request_handler_t handler;
} listen_data;


typedef struct dns_msg {
	listen_data            *ld;
} dns_msg;

typedef struct udp_msg {
	listen_data            *ld;
	struct sockaddr_storage remote_in;
	socklen_t               addrlen;
} udp_msg;

typedef struct tcp_to_write tcp_to_write;
struct tcp_to_write {
	size_t        write_buf_len;
	size_t        written;
	tcp_to_write *next;
	uint8_t       write_buf[];
};

typedef struct downstream {
	listen_data            *ld;
	struct sockaddr_storage remote_in;
	socklen_t               addrlen;
	int                     fd;
	getdns_eventloop_event  event;

	uint8_t                *read_buf;
	size_t                  read_buf_len;
	uint8_t                *read_pos;
	size_t                  to_read;

	tcp_to_write           *to_write;
	size_t                  to_answer;
} downstream;

typedef struct tcp_msg {
	listen_data *ld;
	downstream  *conn;
} tcp_msg;

static void downstream_destroy(downstream *conn)
{
	struct mem_funcs *mf;
	getdns_eventloop *loop;

	tcp_to_write *cur, *next;

	if (!(mf = priv_getdns_context_mf(conn->ld->context)))
		return;

	if (getdns_context_get_eventloop(conn->ld->context, &loop))
		return;

	if (conn->event.read_cb||conn->event.write_cb||conn->event.timeout_cb)
		loop->vmt->clear(loop, &conn->event);
	if (conn->fd >= 0) {
		if (close(conn->fd) == -1)
			; /* Whatever */
	}
	GETDNS_FREE(*mf, conn->read_buf);
	for (cur = conn->to_write; cur; cur = next) {
		next = cur->next;
		GETDNS_FREE(*mf, cur);
	}
	GETDNS_FREE(*mf, conn);
}

static void tcp_write_cb(void *userarg)
{
	downstream *conn = (downstream *)userarg;
	struct mem_funcs *mf;
	getdns_eventloop *loop;

	tcp_to_write *to_write;
	ssize_t written;

	assert(userarg);

	if (!(mf = priv_getdns_context_mf(conn->ld->context)))
		return;

	if (getdns_context_get_eventloop(conn->ld->context, &loop))
		return;

	/* Reset downstream idle timeout */
	loop->vmt->clear(loop, &conn->event);
	
	if (!conn->to_write) {
		conn->event.write_cb = NULL;
		(void) loop->vmt->schedule(loop, conn->fd,
		    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);
		return;
	}
	to_write = conn->to_write;
	if ((written = write(conn->fd, &to_write->write_buf[to_write->written],
	    to_write->write_buf_len - to_write->written)) == -1) {

		/* IO error, close connection */
		conn->event.read_cb = conn->event.write_cb =
		    conn->event.timeout_cb = NULL;
		downstream_destroy(conn);
		return;
	}
	to_write->written += written;
	if (to_write->written == to_write->write_buf_len) {
		conn->to_write = to_write->next;
		GETDNS_FREE(*mf, to_write);
	}
	if (!conn->to_write)
		conn->event.write_cb = NULL;

	(void) loop->vmt->schedule(loop, conn->fd,
	    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);
}

void
_getdns_cancel_reply(getdns_context *context, getdns_transaction_t request_id)
{
	/* TODO: Check request_id at context->outbound_requests */
	dns_msg *msg = (dns_msg *)(intptr_t)request_id;
	struct mem_funcs *mf;

	if (context && msg &&
	    (mf = priv_getdns_context_mf(msg->ld->context)))
		GETDNS_FREE(*mf, msg);
}

getdns_return_t
getdns_reply(
    getdns_context *context, getdns_transaction_t request_id, getdns_dict *reply)
{
	/* TODO: Check request_id at context->outbound_requests */
	dns_msg *msg = (dns_msg *)(intptr_t)request_id;
	struct mem_funcs *mf;
	getdns_eventloop *loop;
	uint8_t buf[65536];
	size_t len;
	getdns_return_t r;

	if (!context || !reply || !msg)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(mf = priv_getdns_context_mf(msg->ld->context)))
		return GETDNS_RETURN_GENERIC_ERROR;;

	if ((r = getdns_context_get_eventloop(msg->ld->context, &loop)))
		return r;

	len = sizeof(buf);
	if ((r = getdns_msg_dict2wire_buf(reply, buf, &len)))
		return r;

	else if (msg->ld->transport == GETDNS_TRANSPORT_UDP) {
		udp_msg *msg = (udp_msg *)(intptr_t)request_id;

		if (sendto(msg->ld->fd, buf, len, 0,
		    (struct sockaddr *)&msg->remote_in, msg->addrlen) == -1)
			; /* IO error, TODO: cleanup this listener */

	} else if (msg->ld->transport == GETDNS_TRANSPORT_TCP) {
		tcp_msg *msg = (tcp_msg *)(intptr_t)request_id;
		tcp_to_write **to_write_p;
		tcp_to_write *to_write = (tcp_to_write *)GETDNS_XMALLOC(
		    *mf, uint8_t, sizeof(tcp_to_write) + len + 2);

		if (!to_write)
			return GETDNS_RETURN_MEMORY_ERROR;

		to_write->write_buf_len = len + 2;
		to_write->write_buf[0] = (len >> 8) & 0xFF;
		to_write->write_buf[1] = len & 0xFF;
		to_write->written = 0;
		to_write->next = NULL;
		(void) memcpy(to_write->write_buf + 2, buf, len);

		/* Appen to_write to conn->to_write list */
		for ( to_write_p = &msg->conn->to_write
		    ; *to_write_p
		    ; to_write_p = &(*to_write_p)->next)
			; /* pass */
		*to_write_p = to_write;

		loop->vmt->clear(loop, &msg->conn->event);
		msg->conn->event.write_cb = tcp_write_cb;
		(void) loop->vmt->schedule(loop,
		    msg->conn->fd, DOWNSTREAM_IDLE_TIMEOUT,
		    &msg->conn->event);
	}
	/* TODO: other transport types */
	if (msg)
		GETDNS_FREE(*mf, msg);

	return r;
}

static void tcp_read_cb(void *userarg)
{
	downstream *conn = (downstream *)userarg;
	ssize_t bytes_read;
	tcp_msg *msg;
	getdns_return_t r;
	struct mem_funcs *mf;
	getdns_eventloop *loop;
	getdns_dict *request_dict;

	assert(userarg);

	if (!(mf = priv_getdns_context_mf(conn->ld->context)))
		return;

	if ((r = getdns_context_get_eventloop(conn->ld->context, &loop)))
		return;

	/* Reset downstream idle timeout */
	loop->vmt->clear(loop, &conn->event);
	(void) loop->vmt->schedule(loop, conn->fd,
	    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);

	if ((bytes_read = read(conn->fd, conn->read_pos, conn->to_read)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return; /* Come back to do the read later */

		/* IO error, close connection */
		downstream_destroy(conn);
		return;
	}
	if (bytes_read == 0) {
		/* remote end closed connection, cleanup */
		downstream_destroy(conn);
		return;
	}
	assert(bytes_read <= conn->to_read);

	conn->to_read  -= bytes_read;
	conn->read_pos += bytes_read;
	if (conn->to_read)
		return; /* More to read */

	if (conn->read_pos - conn->read_buf == 2) {
		/* read length of dns msg to read */
		conn->to_read = (conn->read_buf[0] << 8) | conn->read_buf[1];
		if (conn->to_read > conn->read_buf_len) {
			GETDNS_FREE(*mf, conn->read_buf);
			while (conn->to_read > conn->read_buf_len)
				conn->read_buf_len *= 2;
			if (!(conn->read_buf = GETDNS_XMALLOC(
			    *mf, uint8_t, conn->read_buf_len))) {
				/* Memory error */
				downstream_destroy(conn);
				return;
			}
		}
		if (conn->to_read < 12) {
			/* Request smaller than DNS header, FORMERR */
			downstream_destroy(conn);
			return;
		}
		conn->read_pos = conn->read_buf;
		return;  /* Read DNS message */
	}
	if (!(msg = GETDNS_MALLOC(*mf, tcp_msg))) {
		/* Memory error */
		downstream_destroy(conn);
		return;
	}
	msg->ld = conn->ld;
	msg->conn = conn;
	if ((r = getdns_wire2msg_dict(conn->read_buf,
	    (conn->read_pos - conn->read_buf), &request_dict)))
		; /* FROMERR on input, ignore */

	else {
		conn->to_answer += 1;

		/* Call request handler */
		conn->ld->handler(
		    conn->ld->context, request_dict, (intptr_t)msg);

		conn->read_pos = conn->read_buf;
		conn->to_read = 2;
		return; /* Read more requests */
	}
	GETDNS_FREE(*mf, msg);
	conn->read_pos = conn->read_buf;
	conn->to_read = 2;
	 /* Read more requests */
}

static void tcp_timeout_cb(void *userarg)
{
	downstream *conn = (downstream *)userarg;

	assert(userarg);

	downstream_destroy(conn);
}

static void tcp_accept_cb(void *userarg)
{
	listen_data *ld = (listen_data *)userarg;
	downstream *conn;
	struct mem_funcs *mf;
	getdns_eventloop *loop;
	getdns_return_t r;

	assert(userarg);

	if (!(mf = priv_getdns_context_mf(ld->context)))
		return;

	if ((r = getdns_context_get_eventloop(ld->context, &loop)))
		return;

	if (!(conn = GETDNS_MALLOC(*mf, downstream)))
		return;

	(void) memset(conn, 0, sizeof(downstream));

	conn->ld = ld;
	conn->addrlen = sizeof(conn->remote_in);
	if ((conn->fd = accept(ld->fd,
	    (struct sockaddr *)&conn->remote_in, &conn->addrlen)) == -1) {
		/* IO error, TODO: cleanup this listener */
		GETDNS_FREE(*mf, conn);
	}
	if (!(conn->read_buf = malloc(DNS_REQUEST_SZ))) {
		/* Memory error */
		GETDNS_FREE(*mf, conn);
		return;
	}
	conn->read_buf_len = DNS_REQUEST_SZ;
	conn->read_pos = conn->read_buf;
	conn->to_read = 2;
	conn->event.userarg = conn;
	conn->event.read_cb = tcp_read_cb;
	conn->event.timeout_cb = tcp_timeout_cb;
	(void) loop->vmt->schedule(loop, conn->fd,
	    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);
}

static void udp_read_cb(void *userarg)
{
	listen_data *ld = (listen_data *)userarg;
	udp_msg *msg;
	struct mem_funcs *mf;
	getdns_dict *request_dict;

	/* Maximum reasonable size for requests */
	uint8_t buf[4096];
	ssize_t len;
	getdns_return_t r;
	
	assert(userarg);

	if (!(mf = priv_getdns_context_mf(ld->context)))
		return;

	if (!(msg = GETDNS_MALLOC(*mf, udp_msg)))
		return;

	msg->ld = ld;
	msg->addrlen = sizeof(msg->remote_in);
	if ((len = recvfrom(ld->fd, buf, sizeof(buf), 0,
	    (struct sockaddr *)&msg->remote_in, &msg->addrlen)) == -1)
		; /* IO error, TODO: cleanup this listener */

	else if ((r = getdns_wire2msg_dict(buf, len, &request_dict)))
		; /* FROMERR on input, ignore */

	else {
		/* Call request handler */
		ld->handler(ld->context, request_dict, (intptr_t)msg);
		return;
	}
	GETDNS_FREE(*mf, msg);
}

getdns_return_t getdns_context_set_listen_addresses(getdns_context *context,
    getdns_request_handler_t request_handler, getdns_list *listen_addresses)
{
	static const getdns_transport_list_t listen_transports[]
		= { GETDNS_TRANSPORT_UDP, GETDNS_TRANSPORT_TCP };
	static const uint32_t transport_ports[] = { 53, 53 };
	static const size_t n_transports = sizeof( listen_transports)
	                                 / sizeof(*listen_transports);

	/* Things that should (eventually) be stored in the getdns_context */
	size_t            listen_count;
	listen_data      *listening;
	struct mem_funcs *mf;
	getdns_eventloop *loop;

	/* auxiliary variables */
	getdns_return_t r;
	size_t i;
	size_t t;
	struct addrinfo hints;
	char addrstr[1024], portstr[1024], *eos;
	const int enable = 1; /* For SO_REUSEADDR */

	if (!(mf = priv_getdns_context_mf(context)))
		return GETDNS_RETURN_GENERIC_ERROR;

	if ((r = getdns_context_get_eventloop(context, &loop)))
		return r;

	if ((r = getdns_list_get_length(listen_addresses, &listen_count)))
		return r;

	if (!listen_count)
		return GETDNS_RETURN_GOOD;

	if (!(listening = GETDNS_XMALLOC(
	    *mf, listen_data, listen_count * n_transports)))
		return GETDNS_RETURN_MEMORY_ERROR;

	(void) memset(listening, 0,
	    sizeof(listen_data) * n_transports * listen_count);
	(void) memset(&hints, 0, sizeof(struct addrinfo));

	(void) memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;
	hints.ai_flags     = AI_NUMERICHOST;

	for (i = 0; !r && i < listen_count; i++) {
		getdns_dict             *dict = NULL;
		getdns_bindata          *address_data;
		struct sockaddr_storage  addr;
		getdns_bindata          *scope_id;

		if ((r = getdns_list_get_dict(listen_addresses, i, &dict))) {
			if ((r = getdns_list_get_bindata(
			    listen_addresses, i, &address_data)))
				break;

		} else if ((r = getdns_dict_get_bindata(
		    dict, "address_data", &address_data)))
			break;

		if (address_data->size == 4)
			addr.ss_family = AF_INET;
		else if (address_data->size == 16)
			addr.ss_family = AF_INET6;
		else {
			r = GETDNS_RETURN_INVALID_PARAMETER;
			break;
		}
		if (inet_ntop(addr.ss_family,
		    address_data->data, addrstr, 1024) == NULL) {
			r = GETDNS_RETURN_INVALID_PARAMETER;
			break;
		}
		if (dict && getdns_dict_get_bindata(dict,"scope_id",&scope_id)
		    == GETDNS_RETURN_GOOD) {
			if (strlen(addrstr) + scope_id->size > 1022) {
				r = GETDNS_RETURN_INVALID_PARAMETER;
				break;
			}
			eos = &addrstr[strlen(addrstr)];
			*eos++ = '%';
			(void) memcpy(eos, scope_id->data, scope_id->size);
			eos[scope_id->size] = 0;
		}
		for (t = 0; !r && t < n_transports; t++) {
			getdns_transport_list_t transport
			    = listen_transports[t];
			uint32_t port = transport_ports[t];
			struct addrinfo *ai;
			listen_data *ld = &listening[i * n_transports + t];

			ld->fd = -1;
			if (dict)
				(void) getdns_dict_get_int(dict,
				    ( transport == GETDNS_TRANSPORT_TLS
				    ? "tls_port" : "port" ), &port);

			(void) snprintf(portstr, 1024, "%d", (int)port);

			if (getaddrinfo(addrstr, portstr, &hints, &ai)) {
				r = GETDNS_RETURN_INVALID_PARAMETER;
				break;
			}
			if (!ai)
				continue;

			ld->addr.ss_family = addr.ss_family;
			ld->addr_len = ai->ai_addrlen;
			(void) memcpy(&ld->addr, ai->ai_addr, ai->ai_addrlen);
			ld->transport = transport;
			ld->handler = request_handler;
			ld->context = context;
			freeaddrinfo(ai);
		}
	}
	if (r) {
		GETDNS_FREE(*mf, listening);
		listening = NULL;

	} else for (i = 0; !r && i < listen_count * n_transports; i++) {
		listen_data *ld = &listening[i];

		if (ld->transport != GETDNS_TRANSPORT_UDP &&
		    ld->transport != GETDNS_TRANSPORT_TCP)
			continue;

		if ((ld->fd = socket(ld->addr.ss_family,
		    ( ld->transport == GETDNS_TRANSPORT_UDP
		    ? SOCK_DGRAM : SOCK_STREAM), 0)) == -1)
			/* IO error, TODO: report? */
			continue;

		if (setsockopt(ld->fd, SOL_SOCKET, SO_REUSEADDR,
		    &enable, sizeof(int)) < 0)
			; /* Ignore */

		if (bind(ld->fd, (struct sockaddr *)&ld->addr,
		    ld->addr_len) == -1) {
			/* IO error, TODO: report? */
			(void) close(ld->fd);
			ld->fd = -1;
		}
		if (ld->transport == GETDNS_TRANSPORT_UDP) {
			ld->event.userarg = ld;
			ld->event.read_cb = udp_read_cb;
			(void) loop->vmt->schedule(
			    loop, ld->fd, -1, &ld->event);

		} else if (listen(ld->fd, TCP_LISTEN_BACKLOG) == -1) {
			/* IO error, TODO: report? */
			(void) close(ld->fd);
			ld->fd = -1;
		} else {
			ld->event.userarg = ld;
			ld->event.read_cb = tcp_accept_cb;
			(void) loop->vmt->schedule(
			    loop, ld->fd, -1, &ld->event);
		}
	}
	return r;
}

