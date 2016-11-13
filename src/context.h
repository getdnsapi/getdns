/**
 *
 * \file context.h
 * @brief getdns context management functions
 *
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

#ifndef _GETDNS_CONTEXT_H_
#define _GETDNS_CONTEXT_H_

#include "getdns/getdns.h"
#include "getdns/getdns_extra.h"
#include "config.h"
#include "types-internal.h"
#include "extension/default_eventloop.h"
#include "util/rbtree.h"
#include "ub_loop.h"
#include "server.h"

struct getdns_dns_req;
struct ub_ctx;

#define GETDNS_FN_RESOLVCONF "/etc/resolv.conf"
#define GETDNS_FN_HOSTS      "/etc/hosts"

enum filechgs { GETDNS_FCHG_ERRORS = -1
 , GETDNS_FCHG_NOERROR   = 0
 , GETDNS_FCHG_NOCHANGES = 0
 , GETDNS_FCHG_MTIME     = 1
 , GETDNS_FCHG_CTIME     = 2};

/** function pointer typedefs */
typedef void (*getdns_update_callback) (struct getdns_context *,
    getdns_context_code_t);

typedef void (*getdns_update_callback2) (struct getdns_context *,
    getdns_context_code_t, void *userarg);

/* internal use only for detecting changes to system files */
struct filechg {
	char *fn;
	int  changes;
	int  errors;
	struct stat *prevstat;
};

typedef enum getdns_tls_hs_state {
	GETDNS_HS_NONE,
	GETDNS_HS_WRITE,
	GETDNS_HS_READ,
	GETDNS_HS_DONE,
	GETDNS_HS_FAILED
} getdns_tls_hs_state_t;

typedef enum getdns_conn_state {
	GETDNS_CONN_CLOSED,
	GETDNS_CONN_SETUP,
	GETDNS_CONN_OPEN,
	GETDNS_CONN_TEARDOWN,
	GETDNS_CONN_BACKOFF
} getdns_conn_state_t;

typedef enum getdns_tsig_algo {
	GETDNS_NO_TSIG     = 0, /* Do not use tsig */
	GETDNS_HMAC_MD5    = 1, /* 128 bits */
	GETDNS_GSS_TSIG    = 2, /* Not supported */
	GETDNS_HMAC_SHA1   = 3, /* 160 bits */
	GETDNS_HMAC_SHA224 = 4,
	GETDNS_HMAC_SHA256 = 5,
	GETDNS_HMAC_SHA384 = 6,
	GETDNS_HMAC_SHA512 = 7
} getdns_tsig_algo;

typedef struct getdns_tsig_info {
	getdns_tsig_algo  alg;
	const char       *name;
	size_t            strlen_name;
	const uint8_t    *dname;
	size_t            dname_len;
	size_t            min_size; /* in # octets */
	size_t            max_size; /* Actual size in # octets */
} getdns_tsig_info;

const getdns_tsig_info *_getdns_get_tsig_info(getdns_tsig_algo tsig_alg);

/* for doing public key pinning of TLS-capable upstreams: */
typedef struct sha256_pin {
	char pin[SHA256_DIGEST_LENGTH];
	struct sha256_pin *next;
} sha256_pin_t;

typedef struct getdns_upstream {
	/* backpointer to containing upstreams structure */
	struct getdns_upstreams *upstreams;

	socklen_t                addr_len;
	struct sockaddr_storage  addr;
#if defined(DAEMON_DEBUG) && DAEMON_DEBUG
	char                     addr_str[INET6_ADDRSTRLEN];
#endif

	/* How is this upstream doing over UDP? */
	int                      to_retry;
	int                      back_off;

	/* For stateful upstreams, need to share the connection and track the
	   activity on the connection */
	int                      fd;
	getdns_transport_list_t  transport;
	getdns_eventloop_event   event;
	getdns_eventloop        *loop;
	getdns_tcp_state         tcp;
	/* These are running totals or historical info */
	size_t                   conn_completed;
	size_t                   conn_shutdowns;
	size_t                   conn_setup_failed;
	time_t                   conn_retry_time;
	size_t                   conn_backoffs;
	size_t                   total_responses;
	size_t                   total_timeouts;
	getdns_auth_state_t      best_tls_auth_state;
	getdns_auth_state_t      last_tls_auth_state;
	/* These are per connection. */
	getdns_conn_state_t      conn_state;
	size_t                   queries_sent;
	size_t                   responses_received;
	size_t                   responses_timeouts;
	size_t                   keepalive_shutdown;
	uint64_t                 keepalive_timeout;

	/* Management of outstanding requests on stateful transports */
	getdns_network_req      *write_queue;
	getdns_network_req      *write_queue_last;
	_getdns_rbtree_t         netreq_by_query_id;

    /* TLS specific connection handling*/
	SSL*                     tls_obj;
	SSL_SESSION*             tls_session;
	getdns_tls_hs_state_t    tls_hs_state;
	getdns_auth_state_t      tls_auth_state;
	unsigned                 tls_fallback_ok : 1;
	/* Auth credentials*/
	char                     tls_auth_name[256];
	sha256_pin_t            *tls_pubkey_pinset;

	/* When requests have been scheduled asynchronously on an upstream
	 * that is kept open, and a synchronous call is then done with the
	 * upstream before all scheduled requests have been answered, answers
	 * for the asynchronous requests may be received on the open upstream.
	 * Those cannot be processed immediately, because then asynchronous
	 * callbacks will be fired as a side-effect.
	 *
	 * finished_dnsreqs is a list of dnsreqs for which answers have been
	 * received during a synchronous request.  They will be processed
	 * when the asynchronous eventloop is run.  For this the finished_event
	 * will be scheduled to the registered asynchronous event loop with a
	 * timeout of 1, so it will fire immediately (but not while scheduling)
	 * when the asynchronous eventloop is run.
	 */
	getdns_dns_req          *finished_dnsreqs;
	getdns_eventloop_event   finished_event;
	unsigned is_sync_loop : 1;

	/* EDNS cookies */
	uint32_t secret;
	uint8_t  client_cookie[8];
	uint8_t  prev_client_cookie[8];
	uint8_t  server_cookie[32];

	unsigned has_client_cookie : 1;
	unsigned has_prev_client_cookie : 1;
	unsigned has_server_cookie : 1;
	unsigned server_cookie_len : 5;

	/* TSIG */
	uint8_t          tsig_dname[256];
	size_t           tsig_dname_len;
	size_t           tsig_size;
	uint8_t          tsig_key[256];
	getdns_tsig_algo tsig_alg;

} getdns_upstream;

typedef struct getdns_upstreams {
	struct mem_funcs mf;
	size_t referenced;
	size_t count;
	size_t current_udp;
	getdns_upstream upstreams[];
} getdns_upstreams;

struct getdns_context {
	/* Context values */
	getdns_resolution_t  resolution_type;
	getdns_namespace_t   *namespaces;
	int                  namespace_count;
	uint64_t             timeout;
	uint64_t             idle_timeout;
	getdns_redirects_t   follow_redirects;
	getdns_list          *dns_root_servers;

#if defined(HAVE_LIBUNBOUND) && !defined(HAVE_UB_CTX_SET_STUB)
	char                 root_servers_fn[FILENAME_MAX];
#endif
	getdns_append_name_t append_name;
	/* Suffix buffer containing a list of (length byte | dname) where 
	 * length bytes contains the length of the following dname.
	 * The last dname should be the zero byte.
	 */
	const uint8_t        *suffixes;
	/* Length of all suffixes in the suffix buffer */
	size_t               suffixes_len; 
	uint8_t              *trust_anchors;
	size_t                trust_anchors_len;
	getdns_upstreams     *upstreams;
	uint16_t             limit_outstanding_queries;
	uint32_t             dnssec_allowed_skew;
	getdns_tls_authentication_t  tls_auth;  /* What user requested for TLS*/
	getdns_tls_authentication_t  tls_auth_min; /* Derived minimum auth allowed*/

	getdns_transport_list_t   *dns_transports;
	size_t                     dns_transport_count;

	uint8_t edns_extended_rcode;
	uint8_t edns_version;
	uint8_t edns_do_bit;
	int edns_maximum_udp_payload_size; /* -1 is unset */
	uint8_t edns_client_subnet_private;
	uint16_t tls_query_padding_blocksize;
	SSL_CTX* tls_ctx;

	getdns_update_callback  update_callback;
	getdns_update_callback2 update_callback2;
	void                   *update_userarg;

	int processing;
	int destroying;

	struct mem_funcs mf;
	struct mem_funcs my_mf;

#ifdef HAVE_LIBUNBOUND
	/* The underlying contexts that do the real work */
	struct ub_ctx *unbound_ctx;
	int            unbound_ta_set;
#ifdef HAVE_UNBOUND_EVENT_API
	_getdns_ub_loop ub_loop;
#endif
#endif
	/* A tree to hold local host information*/
	_getdns_rbtree_t local_hosts;

	/* which resolution type the contexts are configured for
	 * 0 means nothing set
	 */
	getdns_resolution_t resolution_type_set;

	/*
	 * outbound requests -> transaction to getdns_dns_req
	 */
	_getdns_rbtree_t outbound_requests;

	struct listen_set *server;

	/* Event loop extension.  */
	getdns_eventloop       *extension;

#ifdef HAVE_LIBUNBOUND
	getdns_eventloop_event  ub_event;
	/* lock to prevent nested ub_event scheduling */
	int                     ub_event_scheduling;
#endif

	/* The default extension */
	_getdns_default_eventloop default_eventloop;
	_getdns_default_eventloop sync_eventloop;

	/* request extension defaults */
	getdns_dict *header;
	getdns_dict *add_opt_parameters;
	int add_warning_for_bad_dns             : 1;
	int dnssec_return_all_statuses          : 1;
	int dnssec_return_full_validation_chain : 1;
	int dnssec_return_only_secure           : 1;
	int dnssec_return_status                : 1;
	int dnssec_return_validation_chain      : 1;
#ifdef DNSSEC_ROADBLOCK_AVOIDANCE
	int dnssec_roadblock_avoidance          : 1;
#endif
	int edns_cookies                        : 1;
	int return_api_information              : 1; /* Not used */
	int return_both_v4_and_v6               : 1;
	int return_call_reporting               : 1;
	uint16_t specify_class;

	/*
	 * state data used to detect changes to the system config files
	 */
	struct filechg *fchg_resolvconf;
	struct filechg *fchg_hosts;

	uint8_t trust_anchors_spc[1024];

#ifdef USE_WINSOCK
	/* We need to run WSAStartup() to be able to use getaddrinfo() */
	WSADATA wsaData;
#endif
}; /* getdns_context */

/** internal functions **/
/**
 * Sets up the unbound contexts with stub or recursive behavior
 * if needed.
 * @param context previously initialized getdns_context
 * @param usenamespaces if 0 then only use the DNS, else use context namespace list
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t _getdns_context_prepare_for_resolution(struct getdns_context *context,
 int usenamespaces);

/* track an outbound request */
getdns_return_t _getdns_context_track_outbound_request(struct getdns_dns_req
    *req);
/* clear the outbound request from being tracked - does not cancel it */
getdns_return_t _getdns_context_clear_outbound_request(struct getdns_dns_req
    *req);

getdns_return_t _getdns_context_request_timed_out(struct getdns_dns_req
    *req);

/* cancel callback internal - flag to indicate if req should be freed and callback fired */
getdns_return_t _getdns_context_cancel_request(struct getdns_context *context,
    getdns_transaction_t transaction_id, int fire_callback);

char *_getdns_strdup(const struct mem_funcs *mfs, const char *str);

struct getdns_bindata *_getdns_bindata_copy(
    struct mem_funcs *mfs, size_t size, const uint8_t *data);

void _getdns_bindata_destroy(
    struct mem_funcs *mfs,
    struct getdns_bindata *bindata);

/* perform name resolution in /etc/hosts */
getdns_return_t _getdns_context_local_namespace_resolve(
    getdns_dns_req* req, struct getdns_dict **response);

int _getdns_filechg_check(struct getdns_context *context, struct filechg *fchg);

void _getdns_context_ub_read_cb(void *userarg);

void _getdns_upstreams_dereference(getdns_upstreams *upstreams);

void _getdns_upstream_shutdown(getdns_upstream *upstream);

#endif /* _GETDNS_CONTEXT_H_ */
