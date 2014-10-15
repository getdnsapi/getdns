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
#include "extension/libmini_event.h"

struct getdns_dns_req;
struct ldns_rbtree_t;
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

/* internal use only for detecting changes to system files */
struct filechg {
	char *fn;
	int  changes;
	int  errors;
	struct stat *prevstat;
};

struct getdns_upstream {
	socklen_t               addr_len;
	struct sockaddr_storage addr;
	int tcp_fd;
	int rtt;
};

typedef struct getdns_upstreams {
	struct mem_funcs mf;
	size_t referenced;
	size_t count;
	struct getdns_upstream upstreams[];
} getdns_upstreams;

struct getdns_context {
	/* Context values */
	getdns_resolution_t  resolution_type;
	getdns_namespace_t   *namespaces;
	int                  namespace_count;
	uint64_t             timeout;
	getdns_redirects_t   follow_redirects;
	struct getdns_list   *dns_root_servers;
	getdns_append_name_t append_name;
	struct getdns_list   *suffix;
	struct getdns_list   *dnssec_trust_anchors;
	getdns_upstreams *upstreams;
	getdns_transport_t   dns_transport;
	uint16_t             limit_outstanding_queries;
	uint32_t             dnssec_allowed_skew;

	uint8_t edns_extended_rcode;
	uint8_t edns_version;
	uint8_t edns_do_bit;
	uint16_t edns_maximum_udp_payload_size;

	getdns_update_callback update_callback;

	int processing;
	int destroying;

	struct mem_funcs mf;
	struct mem_funcs my_mf;

	/* The underlying contexts that do the real work */
	struct ub_ctx *unbound_ctx;
	ldns_resolver *ldns_res;
	/* A tree to hold local host information*/
	struct ldns_rbtree_t *local_hosts;
	int has_ta; /* No DNSSEC without trust anchor */
	int return_dnssec_status;

	/* which resolution type the contexts are configured for
	 * 0 means nothing set
	 */
	getdns_resolution_t resolution_type_set;

	/*
	 * outbound requests -> transaction to getdns_dns_req
	 */
	struct ldns_rbtree_t *outbound_requests;

	/* Event loop extension.  */
	getdns_eventloop       *extension;
	getdns_eventloop_event  ub_event;

	/* The default extension */
	getdns_mini_event mini_event;

	/*
	 * state data used to detect changes to the system config files
	 */
	struct filechg *fchg_resolvconf;
	struct filechg *fchg_hosts;

}; /* getdns_context */

/** internal functions **/
/**
 * Sets up the unbound contexts with stub or recursive behavior
 * if needed.
 * @param context previously initialized getdns_context
 * @param usenamespaces if 0 then only use the DNS, else use context namespace list
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t getdns_context_prepare_for_resolution(struct getdns_context *context,
 int usenamespaces);

/* track an outbound request */
getdns_return_t getdns_context_track_outbound_request(struct getdns_dns_req
    *req);
/* clear the outbound request from being tracked - does not cancel it */
getdns_return_t getdns_context_clear_outbound_request(struct getdns_dns_req
    *req);

getdns_return_t getdns_context_request_timed_out(struct getdns_dns_req
    *req);

/* cancel callback internal - flag to indicate if req should be freed and callback fired */
getdns_return_t getdns_context_cancel_request(struct getdns_context *context,
    getdns_transaction_t transaction_id, int fire_callback);

char *getdns_strdup(const struct mem_funcs *mfs, const char *str);

struct getdns_bindata *getdns_bindata_copy(
    struct mem_funcs *mfs,
    const struct getdns_bindata *src);

void getdns_bindata_destroy(
    struct mem_funcs *mfs,
    struct getdns_bindata *bindata);

/* perform name resolution in /etc/hosts */
getdns_return_t getdns_context_local_namespace_resolve(getdns_dns_req* req,
                                               struct getdns_dict **response,
                                               struct getdns_context *context);

int filechg_check(struct getdns_context *context, struct filechg *fchg);

void priv_getdns_context_ub_read_cb(void *userarg);

#endif /* _GETDNS_CONTEXT_H_ */
