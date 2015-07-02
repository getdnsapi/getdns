/**
 *
 * /brief type declarations private to the getdns library
 *
 * These type declarations are not meant to be used by applications calling
 * the public library functions.
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

#ifndef TYPES_INTERNAL_H_
#define TYPES_INTERNAL_H_

#include "getdns/getdns.h"
#include "getdns/getdns_extra.h"
#include "util/rbtree.h"


struct getdns_context;
struct getdns_upstreams;
struct getdns_upstream;

/**
 * \defgroup strings String Constants
 * @{
 */
#define GETDNS_STR_IPV4 "IPv4"
#define GETDNS_STR_IPV6 "IPv6"
#define GETDNS_STR_ADDRESS_TYPE "address_type"
#define GETDNS_STR_ADDRESS_DATA "address_data"
#define GETDNS_STR_PORT "port"
#define GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6 "return_both_v4_and_v6"

#define GETDNS_STR_KEY_STATUS "status"
#define GETDNS_STR_KEY_REPLIES_TREE "replies_tree"
#define GETDNS_STR_KEY_REPLIES_FULL "replies_full"
#define GETDNS_STR_KEY_JUST_ADDRS "just_address_answers"
#define GETDNS_STR_KEY_CANONICAL_NM "canonical_name"
#define GETDNS_STR_KEY_ANSWER_TYPE "answer_type"
#define GETDNS_STR_KEY_INTERM_ALIASES "intermediate_aliases"
#define GETDNS_STR_KEY_NAME "name"
#define GETDNS_STR_KEY_HEADER "header"
#define GETDNS_STR_KEY_QUESTION "question"
#define GETDNS_STR_KEY_ANSWER "answer"
#define GETDNS_STR_KEY_TYPE "type"
#define GETDNS_STR_KEY_CLASS "class"
#define GETDNS_STR_KEY_TTL "ttl"
#define GETDNS_STR_KEY_RDATA "rdata"
#define GETDNS_STR_KEY_V4_ADDR "ipv4_address"
#define GETDNS_STR_KEY_V6_ADDR "ipv6_address"
#define GETDNS_STR_KEY_RDATA_RAW "rdata_raw"
#define GETDNS_STR_KEY_AUTHORITY "authority"
#define GETDNS_STR_KEY_ADDITIONAL "additional"
#define GETDNS_STR_KEY_QTYPE "qtype"
#define GETDNS_STR_KEY_QCLASS "qclass"
#define GETDNS_STR_KEY_QNAME "qname"
#define GETDNS_STR_KEY_QR "qr"
/* header flags */
#define GETDNS_STR_KEY_ID "id"
#define GETDNS_STR_KEY_OPCODE "opcode"
#define GETDNS_STR_KEY_RCODE "rcode"
#define GETDNS_STR_KEY_AA "aa"
#define GETDNS_STR_KEY_TC "tc"
#define GETDNS_STR_KEY_RD "rd"
#define GETDNS_STR_KEY_RA "ra"
#define GETDNS_STR_KEY_AD "ad"
#define GETDNS_STR_KEY_CD "cd"
#define GETDNS_STR_KEY_Z "z"
#define GETDNS_STR_KEY_QDCOUNT "qdcount"
#define GETDNS_STR_KEY_ANCOUNT "ancount"
#define GETDNS_STR_KEY_NSCOUNT "nscount"
#define GETDNS_STR_KEY_ARCOUNT "arcount"

#define TIMEOUT_FOREVER ((int64_t)-1)
#define ASSERT_UNREACHABLE 0

#define GETDNS_TRANSPORTS_MAX 4
#define GETDNS_UPSTREAM_TRANSPORTS 3

/** @}
 */

/* declarations */
struct getdns_dns_req;
struct getdns_network_req;

typedef void (*internal_cb_t)(struct getdns_dns_req *dns_req);

#define MF_PLAIN ((void *)&plain_mem_funcs_user_arg)
extern void *plain_mem_funcs_user_arg;

typedef union {
        struct {
            void *(*malloc)(size_t);
            void *(*realloc)(void *, size_t);
            void (*free)(void *);
        } pln;
        struct {
            void *(*malloc)(void *userarg, size_t);
            void *(*realloc)(void *userarg, void *, size_t);
            void (*free)(void *userarg, void *);
        } ext;
    } mf_union;

struct mem_funcs {
    void *mf_arg;
    mf_union mf;
};

struct mem_funcs *
priv_getdns_context_mf(getdns_context *context);

typedef enum network_req_state_enum
{
	NET_REQ_NOT_SENT,
	NET_REQ_IN_FLIGHT,
	NET_REQ_FINISHED,
	NET_REQ_CANCELED
} network_req_state;

/**
 * structure used by validate_extensions() to check extension formats
 */
typedef struct getdns_extension_format
{
	char *extstring;
	getdns_data_type exttype;
} getdns_extension_format;


/* State for async tcp stub resolving */
typedef struct getdns_tcp_state {

	uint8_t *write_buf;
	size_t   write_buf_len;
	size_t   written;
	int      write_error;

	uint8_t *read_buf;
	size_t   read_buf_len;
	uint8_t *read_pos;
	size_t   to_read;

} getdns_tcp_state;


/**
 * Request data
 **/
typedef struct getdns_network_req
{
	/* For storage in upstream->netreq_by_query_id */
	getdns_rbnode_t node;
	/* the async_id from unbound */
	int unbound_id;
	/* state var */
	network_req_state state;
	/* owner request (contains name) */
	struct getdns_dns_req *owner;

	/* request type */
	uint16_t request_type;

	/* request class */
	uint16_t request_class;

	/* dnssec status */
	int dnssec_status;

	/* For stub resolving */
	struct getdns_upstream *upstream;
	int                     fd;
	getdns_transport_list_t transports[GETDNS_TRANSPORTS_MAX];
	size_t                   transport_count;
	size_t                   transport_current;
	getdns_eventloop_event  event;
	getdns_tcp_state        tcp;
	uint16_t                query_id;

	int                     edns_maximum_udp_payload_size;
	uint16_t                max_udp_payload_size;

	/* Network requests scheduled to write after me */
	struct getdns_network_req *write_queue_tail;

	/* When more space is needed for the wire_data response than is
	 * available in wire_data[], it will be allocated seperately.
	 * response will then not point to wire_data anymore.
	 */
	size_t   query_len;
	uint8_t *query;
	uint8_t *opt; /* offset of OPT RR in query */
	size_t   response_len;
	uint8_t *response;
	size_t   wire_data_sz;
	uint8_t  wire_data[];

} getdns_network_req;

/**
 * dns request - manages a number of network requests and
 * the initial data passed to getdns_general
 */
typedef struct getdns_dns_req {
	/* For storage in context->outbound_requests */
	getdns_rbnode_t node;

	/* name */
	uint8_t name[256];
	size_t  name_len;

	/* canceled flag */
	int canceled;

	/* context that owns the request */
	struct getdns_context *context;

	/* request extensions */
	int dnssec_return_status;
	int dnssec_return_only_secure;
	int dnssec_return_validation_chain;
	int edns_cookies;

	/* Internally used by return_validation_chain */
	int dnssec_ok_checking_disabled;

	/* internally scheduled request */
	internal_cb_t internal_cb;

	/* event loop */
	getdns_eventloop *loop;

	/* callback data */
	getdns_callback_t user_callback;
	void *user_pointer;

	/* the transaction id */
	getdns_transaction_t trans_id;

	/* for scheduling timeouts when using libunbound */
	getdns_eventloop_event timeout;

	/* mem funcs */
	struct mem_funcs my_mf;

	/* Stuff for stub resolving */
	struct getdns_upstreams *upstreams;

	/* network requests for this dns request.
	 * The array is terminated with NULL.
	 *
	 * Memory for these netreqs has been allocated by the same malloc
	 * operation that reserved space for this getdns_dns_req.
	 * They will thus be freed as part of the desctruction of this struct,
	 * and do not need to be freed seperately.
	 */
	getdns_network_req *netreqs[];

} getdns_dns_req;

#define GETDNS_XMALLOC(obj, type, count)	\
    ((obj).mf_arg == MF_PLAIN \
    ? ((type *)(*(obj).mf.pln.malloc)(              (count)*sizeof(type))) \
    : ((type *)(*(obj).mf.ext.malloc)((obj).mf_arg, (count)*sizeof(type))) \
    )

#define GETDNS_XREALLOC(obj, ptr, type, count)	\
    ((obj).mf_arg == MF_PLAIN \
    ? ((type *)(*(obj).mf.pln.realloc)( (ptr), (count)*sizeof(type))) \
    : ((type *)(*(obj).mf.ext.realloc)( (obj).mf_arg                  \
                                      , (ptr), (count)*sizeof(type))) \
    )

#define GETDNS_FREE(obj, ptr)	\
    ((obj).mf_arg == MF_PLAIN \
    ? ((*(obj).mf.pln.free)(              (ptr))) \
    : ((*(obj).mf.ext.free)((obj).mf_arg, (ptr))) \
    )

#define GETDNS_NULL_FREE(obj, ptr)	\
	do { \
		if (!(ptr)) \
			break; \
		if ((obj).mf_arg == MF_PLAIN) \
			(*(obj).mf.pln.free)(              (ptr)); \
		else \
			(*(obj).mf.ext.free)((obj).mf_arg, (ptr)); \
		(ptr) = NULL; \
	} while (0);

#define GETDNS_MALLOC(obj, type)	GETDNS_XMALLOC(obj, type, 1)
#define GETDNS_REALLOC(obj, ptr, type)	GETDNS_XREALLOC(obj, ptr, type, 1);


/* utility methods */

extern getdns_dict *dnssec_ok_checking_disabled;

/* dns request utils */
getdns_dns_req *dns_req_new(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions);

void dns_req_free(getdns_dns_req * req);

#endif
/* types-internal.h */
