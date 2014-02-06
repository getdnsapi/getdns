/**
 *
 * /brief type declarations private to the getdns library
 *
 * These type declarations are not meant to be used by applications calling
 * the public library functions.
 */

/*
 * Copyright (c) 2013, Versign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
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

#include <getdns/getdns.h>
#include <netinet/in.h>
#include <ldns/ldns.h>
struct getdns_context;

/**
 * \defgroup strings String Constants
 * @{
 */
#define GETDNS_STR_IPV4 "IPv4"
#define GETDNS_STR_IPV6 "IPv6"
#define GETDNS_STR_ADDRESS_TYPE "address_type"
#define GETDNS_STR_ADDRESS_DATA "address_data"
#define GETDNS_STR_ADDRESS_STRING "address_string"
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


/** @}
 */

/* declarations */
struct getdns_dns_req;
struct getdns_network_req;

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

/**
 * Request data for unbound
 **/
typedef struct getdns_network_req
{
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

	/* result */
	ldns_pkt *result;

	/* next request to issue after this one */
	struct getdns_network_req *next;
} getdns_network_req;

/**
 * dns request - manages a number of network requests and
 * the initial data passed to getdns_general
 */
typedef struct getdns_dns_req
{

	/* name */
	char *name;

	/* canceled flag */
	int canceled;

	/* current network request */
	struct getdns_network_req *current_req;

	/* first request in list */
	struct getdns_network_req *first_req;

	/* context that owns the request */
	struct getdns_context *context;

	/* request extensions */
	struct getdns_dict *extensions;

	/* callback data */
	getdns_callback_t user_callback;
	void *user_pointer;

	/* the transaction id */
	getdns_transaction_t trans_id;

    /* local timeout id */
    getdns_transaction_t local_timeout_id;

} getdns_dns_req;

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

#define GETDNS_MALLOC(obj, type)	GETDNS_XMALLOC(obj, type, 1)
#define GETDNS_REALLOC(obj, ptr, type)	GETDNS_XREALLOC(obj, ptr, type, 1);


/* utility methods */

/* network request utilities */
void network_req_free(getdns_network_req * net_req);

getdns_network_req *network_req_new(getdns_dns_req * owner,
    uint16_t request_type,
    uint16_t request_class, struct getdns_dict *extensions);

/* dns request utils */
getdns_dns_req *dns_req_new(struct getdns_context *context,
    const char *name, uint16_t request_type, struct getdns_dict *extensions);

void dns_req_free(getdns_dns_req * req);


/* extensions */
typedef void (*getdns_timeout_callback) (void* userarg);

/* context timeout data */
typedef struct getdns_timeout_data {
    getdns_transaction_t transaction_id;
    struct timeval timeout_time;
    getdns_timeout_callback callback;
    void* userarg;
    void* extension_timer;
    struct getdns_context* context;
} getdns_timeout_data_t;

typedef getdns_return_t (*getdns_eventloop_cleanup_t)(struct getdns_context* context, void* eventloop_data);
typedef getdns_return_t (*getdns_eventloop_schedule_timeout_t)(struct getdns_context* context,
    void* eventloop_data, uint16_t timeout,
    getdns_timeout_data_t* timeout_data,
    void** eventloop_timer);
typedef getdns_return_t (*getdns_eventloop_clear_timeout_t)(struct getdns_context* context,
    void* eventloop_data, void* eventloop_timer);


typedef struct getdns_eventloop_extension {
    getdns_eventloop_cleanup_t cleanup_data;
    getdns_eventloop_schedule_timeout_t schedule_timeout;
    getdns_eventloop_clear_timeout_t clear_timeout;
} getdns_eventloop_extension;


#endif

/* types-internal.h */
