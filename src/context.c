/**
 *
 * \file context.c
 * @brief getdns context management functions
 *
 * Originally taken from the getdns API description pseudo implementation.
 *
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

#include "config.h"
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unbound.h>

#include "context.h"
#include "types-internal.h"
#include "util-internal.h"

void *plain_mem_funcs_user_arg = MF_PLAIN;

/* Private functions */
static uint16_t *create_default_namespaces(struct getdns_context *context);
static struct getdns_list *create_default_root_servers();
static getdns_return_t add_ip_str(struct getdns_dict *);
static struct getdns_dict *create_ipaddr_dict_from_rdf(struct getdns_context *,
    ldns_rdf *);
static struct getdns_list *create_from_ldns_list(struct getdns_context *,
    ldns_rdf **, size_t);
static getdns_return_t set_os_defaults(struct getdns_context *);
static int transaction_id_cmp(const void *, const void *);
static int timeout_cmp(const void *, const void *);
static void set_ub_string_opt(struct getdns_context *, char *, char *);
static void set_ub_number_opt(struct getdns_context *, char *, uint16_t);
static inline void clear_resolution_type_set_flag(struct getdns_context *, uint16_t);
static void dispatch_updated(struct getdns_context *, uint16_t);
static void cancel_dns_req(getdns_dns_req *);

/* Stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))
#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

/**
 * Helper to get default lookup namespaces.
 * TODO: Determine from OS
 */
static uint16_t *
create_default_namespaces(struct getdns_context *context)
{
	uint16_t *result = GETDNS_XMALLOC(context->my_mf, uint16_t, 2);
	result[0] = GETDNS_CONTEXT_NAMESPACE_LOCALNAMES;
	result[1] = GETDNS_CONTEXT_NAMESPACE_DNS;
	return result;
}

/**
 * Helper to get the default root servers.
 * TODO: Implement
 */
static struct getdns_list *
create_default_root_servers()
{
	return NULL;
}

static getdns_return_t
add_ip_str(struct getdns_dict * ip)
{
	struct sockaddr_storage storage;
	char buff[256];
	getdns_return_t r = dict_to_sockaddr(ip, &storage);
	if (r != GETDNS_RETURN_GOOD) {
		return r;
	}
	if (storage.ss_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *) &storage;
		const char *ipStr =
		    inet_ntop(AF_INET, &(addr->sin_addr), buff, 256);
		if (!ipStr) {
			return GETDNS_RETURN_GENERIC_ERROR;
		}
		getdns_dict_util_set_string(ip, GETDNS_STR_ADDRESS_STRING,
		    ipStr);
	} else if (storage.ss_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &storage;
		const char *ipStr =
		    inet_ntop(AF_INET6, &(addr->sin6_addr), buff, 256);
		if (!ipStr) {
			return GETDNS_RETURN_GENERIC_ERROR;
		}
		getdns_dict_util_set_string(ip, GETDNS_STR_ADDRESS_STRING,
		    ipStr);
	} else {
		/* unknown */
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	return GETDNS_RETURN_GOOD;
}

static struct getdns_dict *
create_ipaddr_dict_from_rdf(struct getdns_context *context, ldns_rdf * rdf)
{
	ldns_rdf_type rt = ldns_rdf_get_type(rdf);
	size_t sz = ldns_rdf_size(rdf);
	struct getdns_dict *result = getdns_dict_create_with_context(context);
	/* set type */
	if (rt == LDNS_RDF_TYPE_A) {
		getdns_dict_util_set_string(result, GETDNS_STR_ADDRESS_TYPE,
		    GETDNS_STR_IPV4);
	} else {
		getdns_dict_util_set_string(result, GETDNS_STR_ADDRESS_TYPE,
		    GETDNS_STR_IPV6);
	}
	/* set data */
	struct getdns_bindata data_bin = { sz, ldns_rdf_data(rdf) };
	getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_DATA, &data_bin);
	add_ip_str(result);
	return result;
}

static struct getdns_list *
create_from_ldns_list(struct getdns_context *context, ldns_rdf ** ldns_list,
    size_t count)
{
	size_t i = 0;
	size_t idx = 0;
	struct getdns_list *result = getdns_list_create_with_context(context);
	for (i = 0; i < count; ++i) {
		ldns_rdf *rdf = ldns_list[i];
		switch (ldns_rdf_get_type(rdf)) {
		case LDNS_RDF_TYPE_A:
		case LDNS_RDF_TYPE_AAAA:
			{
				struct getdns_dict *ipaddr =
				    create_ipaddr_dict_from_rdf(context, rdf);
				getdns_list_add_item(result, &idx);
				getdns_list_set_dict(result, idx, ipaddr);
				getdns_dict_destroy(ipaddr);
			}
			break;

		case LDNS_RDF_TYPE_DNAME:
			{
				struct getdns_bindata item;
				char *srch = ldns_rdf2str(rdf);
				item.size = strlen(srch) + 1;
				item.data = (uint8_t *) srch;
				getdns_list_add_item(result, &idx);
				getdns_list_set_bindata(result, idx, &item);
				free(srch);
			}
			break;

		default:
			break;
		}
	}
	return result;
}

static getdns_return_t
set_os_defaults(struct getdns_context *context)
{
	ldns_resolver *lr = NULL;
	if (ldns_resolver_new_frm_file(&lr, NULL) != LDNS_STATUS_OK) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	ldns_rdf **rdf_list = ldns_resolver_nameservers(lr);
	size_t rdf_list_sz = ldns_resolver_nameserver_count(lr);
	if (rdf_list_sz > 0) {
		context->upstream_list =
		    create_from_ldns_list(context, rdf_list, rdf_list_sz);
	}
	rdf_list = ldns_resolver_searchlist(lr);
	rdf_list_sz = ldns_resolver_searchlist_count(lr);
	if (rdf_list_sz > 0) {
		context->suffix = create_from_ldns_list(context, rdf_list,
		    rdf_list_sz);
	}
    /** cleanup **/
	ldns_resolver_deep_free(lr);
	return GETDNS_RETURN_GOOD;
}

/* compare of transaction ids in DESCENDING order
   so that 0 comes last
*/
static int
transaction_id_cmp(const void *id1, const void *id2)
{
	if (id1 == NULL && id2 == NULL) {
		return 0;
	} else if (id1 == NULL && id2 != NULL) {
		return 1;
	} else if (id1 != NULL && id2 == NULL) {
		return -1;
	} else {
		getdns_transaction_t t1 =
		    *((const getdns_transaction_t *) id1);
		getdns_transaction_t t2 =
		    *((const getdns_transaction_t *) id2);
		if (t1 == t2) {
			return 0;
		} else if (t1 > t2) {
			return -1;
		} else {
			return 1;
		}
	}
}

static int timeout_cmp(const void *to1, const void *to2) {
    if (to1 == NULL && to2 == NULL) {
        return 0;
    } else if (to1 == NULL && to2 != NULL) {
        return 1;
    } else if (to1 != NULL && to2 == NULL) {
        return -1;
    } else {
        const getdns_timeout_data_t* t1 = (const getdns_timeout_data_t*) to1;
        const getdns_timeout_data_t* t2 = (const getdns_timeout_data_t*) to2;
        if (t1->timeout_time.tv_sec < t2->timeout_time.tv_sec) {
            return -1;
        } else if (t1->timeout_time.tv_sec > t2->timeout_time.tv_sec) {
            return 1;
        } else {
            /* compare usec.. */
            if (t1->timeout_time.tv_usec < t2->timeout_time.tv_usec) {
                return -1;
            } else if (t1->timeout_time.tv_usec > t2->timeout_time.tv_usec) {
                return 1;
            } else {
                return transaction_id_cmp(&t1->transaction_id, &t2->transaction_id);
            }
        }
    }
}

/*
 * getdns_context_create
 *
 * Call this to initialize the context that is used in other getdns calls.
 */
getdns_return_t
getdns_context_create_with_extended_memory_functions(
    struct getdns_context ** context,
    int set_from_os,
    void *userarg,
    void *(*malloc)(void *userarg, size_t),
    void *(*realloc)(void *userarg, void *, size_t),
    void (*free)(void *userarg, void *)
    )
{
	struct getdns_context *result = NULL;
	mf_union mf;

	if (!context || !malloc || !realloc || !free)
		return GETDNS_RETURN_INVALID_PARAMETER;

    /** default init **/
	mf.ext.malloc = malloc;
	result = userarg == MF_PLAIN
	       ? (*mf.pln.malloc)(         sizeof(struct getdns_context))
	       : (*mf.ext.malloc)(userarg, sizeof(struct getdns_context));
	if (!result) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	result->my_mf.mf_arg         = userarg;
	result->my_mf.mf.ext.malloc  = malloc;
	result->my_mf.mf.ext.realloc = realloc;
	result->my_mf.mf.ext.free    = free;

	result->update_callback = NULL;

	result->mf.mf_arg          = userarg;
	result->mf.mf.ext.malloc   = malloc;
	result->mf.mf.ext.realloc  = realloc;
	result->mf.mf.ext.free     = free;

	result->unbound_ctx = ub_ctx_create();

	result->resolution_type_set = 0;

	result->outbound_requests = ldns_rbtree_create(transaction_id_cmp);

	result->resolution_type = GETDNS_CONTEXT_RECURSING;
	result->namespaces = create_default_namespaces(result);

	result->timeout = 5000;
	result->follow_redirects = GETDNS_CONTEXT_FOLLOW_REDIRECTS;
	result->dns_root_servers = create_default_root_servers();
	result->append_name = GETDNS_CONTEXT_APPEND_NAME_ALWAYS;
	result->suffix = NULL;

	result->dnssec_trust_anchors = NULL;
	result->upstream_list = NULL;

	result->edns_extended_rcode = 0;
	result->edns_version = 0;
	result->edns_do_bit = 0;

    result->extension = NULL;
    result->extension_data = NULL;
    result->timeouts_by_time = ldns_rbtree_create(timeout_cmp);
    result->timeouts_by_id = ldns_rbtree_create(transaction_id_cmp);

	if (set_from_os) {
		if (GETDNS_RETURN_GOOD != set_os_defaults(result)) {
			getdns_context_destroy(result);
			return GETDNS_RETURN_GENERIC_ERROR;
		}
	}

	*context = result;

	/* other opts */
	getdns_context_set_dnssec_allowed_skew(result, 0);
	getdns_context_set_edns_maximum_udp_payload_size(result, 512);
	getdns_context_set_dns_transport(result,
	    GETDNS_CONTEXT_UDP_FIRST_AND_FALL_BACK_TO_TCP);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_create */

/*
 * getdns_context_create
 *
 * Call this to initialize the context that is used in other getdns calls.
 */
getdns_return_t
getdns_context_create_with_memory_functions(struct getdns_context ** context,
    int set_from_os,
    void *(*malloc)(size_t),
    void *(*realloc)(void *, size_t),
    void (*free)(void *)
    )
{
	mf_union mf;
	mf.pln.malloc = malloc;
	mf.pln.realloc = realloc;
	mf.pln.free = free;
	return getdns_context_create_with_extended_memory_functions(
	    context, set_from_os, MF_PLAIN,
	    mf.ext.malloc, mf.ext.realloc, mf.ext.free);
}				/* getdns_context_create */

/*
 * getdns_context_create
 *
 * Call this to initialize the context that is used in other getdns calls.
 */
getdns_return_t
getdns_context_create(struct getdns_context ** context, int set_from_os)
{
	return getdns_context_create_with_memory_functions(context,
			set_from_os, malloc, realloc, free);
}				/* getdns_context_create */


/*
 * getdns_context_destroy
 *
 * Call this to dispose of resources associated with a context once you
 * are done with it.
 */
void
getdns_context_destroy(struct getdns_context *context)
{
	if (context == NULL) {
		return;
	}
	if (context->namespaces)
		GETDNS_FREE(context->my_mf, context->namespaces);

	getdns_list_destroy(context->dns_root_servers);
	getdns_list_destroy(context->suffix);
	getdns_list_destroy(context->dnssec_trust_anchors);
	getdns_list_destroy(context->upstream_list);

	/* destroy the ub context */
	ub_ctx_delete(context->unbound_ctx);

	ldns_rbtree_free(context->outbound_requests);

	GETDNS_FREE(context->my_mf, context);
	return;
}				/* getdns_context_destroy */

/*
 * getdns_context_set_context_update_callback
 *
 */
getdns_return_t
getdns_context_set_context_update_callback(struct getdns_context *context,
    void (*value) (struct getdns_context *context, uint16_t changed_item)
    )
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	context->update_callback = value;
	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_context_update_callback */

/*
 * Helpers to set options on the unbound ctx
 */

static void
set_ub_string_opt(struct getdns_context *ctx, char *opt, char *value)
{
	ub_ctx_set_option(ctx->unbound_ctx, opt, value);
}

static void
set_ub_number_opt(struct getdns_context *ctx, char *opt, uint16_t value)
{
	char buffer[64];
	snprintf(buffer, 64, "%hu", value);
	set_ub_string_opt(ctx, opt, buffer);
}

/*
 * Clear the resolution type set flag if needed
 */
static inline void
clear_resolution_type_set_flag(struct getdns_context *context, uint16_t type)
{
	if (context->resolution_type_set == type) {
		context->resolution_type_set = 0;
	}
}

/*
 * getdns_context_set_context_update
 *
 */
getdns_return_t
getdns_context_set_context_update(struct getdns_context *context, uint16_t value)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	UNUSED_PARAM(value);
	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_context_update */

/**
 * Helper to dispatch the updated callback
 */
static void
dispatch_updated(struct getdns_context *context, uint16_t item)
{
	if (context->update_callback) {
		context->update_callback(context, item);
	}
}

/*
 * getdns_context_set_resolution_type
 *
 */
getdns_return_t
getdns_context_set_resolution_type(struct getdns_context *context, uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (value != GETDNS_CONTEXT_STUB && value != GETDNS_CONTEXT_RECURSING) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}

	context->resolution_type = value;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_RESOLUTION_TYPE);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_resolution_type */

/*
 * getdns_context_set_namespaces
 *
 */
getdns_return_t
getdns_context_set_namespaces(struct getdns_context *context,
    size_t namespace_count, uint16_t * namespaces)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (namespace_count == 0 || namespaces == NULL) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}

    /** clean up old namespaces **/
	GETDNS_FREE(context->my_mf, context->namespaces);

    /** duplicate **/
	context->namespaces = GETDNS_XMALLOC(context->my_mf, uint16_t,
	    namespace_count);
	memcpy(context->namespaces, namespaces,
	    namespace_count * sizeof(uint16_t));

	dispatch_updated(context, GETDNS_CONTEXT_CODE_NAMESPACES);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_namespaces */

/*
 * getdns_context_set_dns_transport
 *
 */
getdns_return_t
getdns_context_set_dns_transport(struct getdns_context *context, uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	switch (value) {
	case GETDNS_CONTEXT_UDP_FIRST_AND_FALL_BACK_TO_TCP:
		set_ub_string_opt(context, "do-udp", "yes");
		set_ub_string_opt(context, "do-tcp", "yes");
		break;
	case GETDNS_CONTEXT_UDP_ONLY:
		set_ub_string_opt(context, "do-udp", "yes");
		set_ub_string_opt(context, "do-tcp", "no");
		break;
	case GETDNS_CONTEXT_TCP_ONLY:
		set_ub_string_opt(context, "do-udp", "no");
		set_ub_string_opt(context, "do-tcp", "yes");
		break;
	default:
		/* TODO GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN */
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}

	dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_TRANSPORT);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_dns_transport */

/*
 * getdns_context_set_limit_outstanding_queries
 *
 */
getdns_return_t
getdns_context_set_limit_outstanding_queries(struct getdns_context *context,
    uint16_t limit)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	/* num-queries-per-thread */
	set_ub_number_opt(context, "num-queries-per-thread", limit);

	dispatch_updated(context,
	    GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_limit_outstanding_queries */

/*
 * getdns_context_set_timeout
 *
 */
getdns_return_t
getdns_context_set_timeout(struct getdns_context *context, uint16_t timeout)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	context->timeout = timeout;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_TIMEOUT);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_timeout */

/*
 * getdns_context_set_follow_redirects
 *
 */
getdns_return_t
getdns_context_set_follow_redirects(struct getdns_context *context, uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	context->follow_redirects = value;

	clear_resolution_type_set_flag(context, GETDNS_CONTEXT_RECURSING);
	dispatch_updated(context, GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_follow_redirects */

/*
 * getdns_context_set_dns_root_servers
 *
 */
getdns_return_t
getdns_context_set_dns_root_servers(struct getdns_context *context,
    struct getdns_list * addresses)
{
	struct getdns_list *copy = NULL;
	size_t count = 0;
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (addresses != NULL) {
		if (getdns_list_copy(addresses, &copy) != GETDNS_RETURN_GOOD) {
			return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
		}
		addresses = copy;
		getdns_list_get_length(addresses, &count);
		if (count == 0) {
			getdns_list_destroy(addresses);
			addresses = NULL;
		} else {
			size_t i = 0;
			getdns_return_t r = GETDNS_RETURN_GOOD;
			/* validate and add ip str */
			for (i = 0; i < count; ++i) {
				struct getdns_dict *dict = NULL;
				getdns_list_get_dict(addresses, i, &dict);
				r = add_ip_str(dict);
				if (r != GETDNS_RETURN_GOOD) {
					break;
				}
			}
			if (r != GETDNS_RETURN_GOOD) {
				getdns_list_destroy(addresses);
				return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
			}
		}
	}

	getdns_list_destroy(context->dns_root_servers);
	context->dns_root_servers = addresses;

	clear_resolution_type_set_flag(context, GETDNS_CONTEXT_RECURSING);

	dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_dns_root_servers */

/*
 * getdns_context_set_append_name
 *
 */
getdns_return_t
getdns_context_set_append_name(struct getdns_context *context, uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (value != GETDNS_CONTEXT_APPEND_NAME_ALWAYS &&
	    value !=
	    GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE
	    && value !=
	    GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE
	    && value != GETDNS_CONTEXT_DO_NOT_APPEND_NAMES) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}

	context->append_name = value;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_APPEND_NAME);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_append_name */

/*
 * getdns_context_set_suffix
 *
 */
getdns_return_t
getdns_context_set_suffix(struct getdns_context *context, struct getdns_list * value)
{
	struct getdns_list *copy = NULL;
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (value != NULL) {
		if (getdns_list_copy(value, &copy) != GETDNS_RETURN_GOOD) {
			return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
		}
		value = copy;
	}
	getdns_list_destroy(context->suffix);
	context->suffix = value;

	clear_resolution_type_set_flag(context, GETDNS_CONTEXT_STUB);

	dispatch_updated(context, GETDNS_CONTEXT_CODE_SUFFIX);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_suffix */

/*
 * getdns_context_set_dnssec_trust_anchors
 *
 */
getdns_return_t
getdns_context_set_dnssec_trust_anchors(struct getdns_context *context,
    struct getdns_list * value)
{
	struct getdns_list *copy = NULL;
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (value != NULL) {
		if (getdns_list_copy(value, &copy) != GETDNS_RETURN_GOOD) {
			return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
		}
		value = copy;
	}
	getdns_list_destroy(context->dnssec_trust_anchors);
	context->dnssec_trust_anchors = value;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_dnssec_trust_anchors */

/*
 * getdns_context_set_dnssec_allowed_skew
 *
 */
getdns_return_t
getdns_context_set_dnssec_allowed_skew(struct getdns_context *context,
    uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	set_ub_number_opt(context, "val-sig-skew-min", value);
	set_ub_number_opt(context, "val-sig-skew-max", value);
	dispatch_updated(context, GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_dnssec_allowed_skew */

/*
 * getdns_context_set_upstream_recursive_servers
 *
 */
getdns_return_t
getdns_context_set_upstream_recursive_servers(struct getdns_context *context,
    struct getdns_list * upstream_list)
{
	size_t count = 0;
	size_t i = 0;
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	getdns_return_t r = getdns_list_get_length(upstream_list, &count);
	if (count == 0 || r != GETDNS_RETURN_GOOD) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	struct getdns_list *copy = NULL;
	if (getdns_list_copy(upstream_list, &copy) != GETDNS_RETURN_GOOD) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	upstream_list = copy;
	/* validate and add ip str */
	for (i = 0; i < count; ++i) {
		struct getdns_dict *dict = NULL;
		getdns_list_get_dict(upstream_list, i, &dict);
		r = add_ip_str(dict);
		if (r != GETDNS_RETURN_GOOD) {
			break;
		}
	}

	if (r != GETDNS_RETURN_GOOD) {
		getdns_list_destroy(upstream_list);
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}

	getdns_list_destroy(context->upstream_list);
	context->upstream_list = upstream_list;

	clear_resolution_type_set_flag(context, GETDNS_CONTEXT_STUB);

	dispatch_updated(context,
	    GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS);

	return GETDNS_RETURN_GOOD;
}			/* getdns_context_set_upstream_recursive_servers */

/*
 * getdns_context_set_edns_maximum_udp_payload_size
 *
 */
getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(struct getdns_context *context,
    uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	/* check for < 512.  uint16_t won't let it go above max) */
	if (value < 512) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}

	/* max-udp-size */
	set_ub_number_opt(context, "max-udp-size", value);

	dispatch_updated(context,
	    GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_edns_maximum_udp_payload_size */

/*
 * getdns_context_set_edns_extended_rcode
 *
 */
getdns_return_t
getdns_context_set_edns_extended_rcode(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	context->edns_extended_rcode = value;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_edns_extended_rcode */

/*
 * getdns_context_set_edns_version
 *
 */
getdns_return_t
getdns_context_set_edns_version(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	context->edns_version = value;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_VERSION);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_edns_version */

/*
 * getdns_context_set_edns_do_bit
 *
 */
getdns_return_t
getdns_context_set_edns_do_bit(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	/* 0 or 1 */
	if (value > 1) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}

	context->edns_do_bit = value;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_DO_BIT);

	return GETDNS_RETURN_GOOD;
}				/* getdns_context_set_edns_do_bit */

/*
 * getdns_context_set_extended_memory_functions
 *
 */
getdns_return_t
getdns_context_set_extended_memory_functions(
    struct getdns_context *context,
    void *userarg,
    void *(*malloc) (void *userarg, size_t),
    void *(*realloc) (void *userarg, void *, size_t),
    void (*free) (void *userarg, void *)
    )
{
	RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (!malloc || !realloc || !free)
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;

	context->mf.mf_arg         = userarg;
	context->mf.mf.ext.malloc  = malloc;
	context->mf.mf.ext.realloc = realloc;
	context->mf.mf.ext.free    = free;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS);

	return GETDNS_RETURN_GOOD;
} /* getdns_context_set_extended_memory_functions*/


/*
 * getdns_context_set_memory_functions
 *
 */
getdns_return_t
getdns_context_set_memory_functions(struct getdns_context *context,
    void *(*malloc) (size_t),
    void *(*realloc) (void *, size_t),
    void (*free) (void *)
    )
{
	mf_union mf;
	mf.pln.malloc = malloc;
	mf.pln.realloc = realloc;
	mf.pln.free = free;
	return getdns_context_set_extended_memory_functions(
	    context, MF_PLAIN, mf.ext.malloc, mf.ext.realloc, mf.ext.free);
} /* getdns_context_set_memory_functions*/

/* cancel the request */
static void
cancel_dns_req(getdns_dns_req * req)
{
	getdns_network_req *netreq = req->first_req;
	while (netreq) {
		if (netreq->state == NET_REQ_IN_FLIGHT) {
			/* for ev based ub, this should always prevent
			 * the callback from firing */
			ub_cancel(req->context->unbound_ctx, netreq->unbound_id);
			netreq->state = NET_REQ_CANCELED;
		} else if (netreq->state == NET_REQ_NOT_SENT) {
			netreq->state = NET_REQ_CANCELED;
		}
		netreq = netreq->next;
	}
	req->canceled = 1;
}

getdns_return_t
getdns_context_cancel_request(struct getdns_context *context,
    getdns_transaction_t transaction_id, int fire_callback)
{
	getdns_dns_req *req = NULL;
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);

	/* delete the node from the tree */
	ldns_rbnode_t *node = ldns_rbtree_delete(context->outbound_requests,
	    &transaction_id);

	if (!node) {
		return GETDNS_RETURN_UNKNOWN_TRANSACTION;
	}
	req = (getdns_dns_req *) node->data;
	/* do the cancel */

	cancel_dns_req(req);

	if (fire_callback) {
		getdns_callback_t cb = NULL;
		void *user_pointer = NULL;

		cb = req->user_callback;
		user_pointer = req->user_pointer;

		/* clean up */
		GETDNS_FREE(context->my_mf, node);
		dns_req_free(req);

		/* fire callback */
		cb(context,
		    GETDNS_CALLBACK_CANCEL,
		    NULL, user_pointer, transaction_id);
	}
	return GETDNS_RETURN_GOOD;
}

/*
 * getdns_cancel_callback
 *
 */
getdns_return_t
getdns_cancel_callback(struct getdns_context *context,
    getdns_transaction_t transaction_id)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	return getdns_context_cancel_request(context, transaction_id, 1);
}				/* getdns_cancel_callback */

static void
ub_setup_stub(struct ub_ctx *ctx, struct getdns_list * upstreams, size_t count)
{
	size_t i;
	/* reset forwarding servers */
	ub_ctx_set_fwd(ctx, NULL);
	for (i = 0; i < count; ++i) {
		struct getdns_dict *dict = NULL;
		char *ip_str = NULL;
		getdns_list_get_dict(upstreams, i, &dict);
		getdns_dict_util_get_string(dict, GETDNS_STR_ADDRESS_STRING,
		    &ip_str);
		ub_ctx_set_fwd(ctx, ip_str);
	}
	/* Allow lookups of:
	 */
	/* - localhost */
	(void)ub_ctx_zone_remove(ctx, "localhost.");

	/* - reverse IPv4 loopback */
	(void)ub_ctx_zone_remove(ctx, "127.in-addr.arpa.");

	/* - reverse IPv6 loopback */
	(void)ub_ctx_zone_remove(ctx, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
	                              "0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");

	/* - reverse RFC1918 local use zones */
	(void)ub_ctx_zone_remove(ctx, "10.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "16.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "17.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "18.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "19.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "20.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "21.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "22.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "23.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "24.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "25.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "26.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "27.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "28.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "29.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "30.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "31.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "168.192.in-addr.arpa.");

	/* - reverse RFC3330 IP4 this, link-local, testnet and broadcast */
	(void)ub_ctx_zone_remove(ctx, "0.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "254.169.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "2.0.192.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "100.51.198.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "113.0.203.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "255.255.255.255.in-addr.arpa.");

	/* - reverse RFC4291 IP6 unspecified */
	(void)ub_ctx_zone_remove(ctx, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
	                              "0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");

	/* - reverse RFC4193 IPv6 Locally Assigned Local Addresses */
	(void)ub_ctx_zone_remove(ctx, "D.F.ip6.arpa.");

	/* - reverse RFC4291 IPv6 Link Local Addresses */
	(void)ub_ctx_zone_remove(ctx, "8.E.F.ip6.arpa.");
	(void)ub_ctx_zone_remove(ctx, "9.E.F.ip6.arpa.");
	(void)ub_ctx_zone_remove(ctx, "A.E.F.ip6.arpa.");
	(void)ub_ctx_zone_remove(ctx, "B.E.F.ip6.arpa.");

	/* - reverse IPv6 Example Prefix */
	(void)ub_ctx_zone_remove(ctx, "8.B.D.0.1.0.0.2.ip6.arpa.");
}

getdns_return_t
getdns_context_prepare_for_resolution(struct getdns_context *context)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
	if (context->resolution_type_set == context->resolution_type) {
		/* already set and no config changes have caused this to be
		 * bad.
		 */
		return GETDNS_RETURN_GOOD;
	}
	if (context->resolution_type == GETDNS_CONTEXT_STUB) {
		size_t upstream_len = 0;
		getdns_return_t r =
		    getdns_list_get_length(context->upstream_list,
		    &upstream_len);
		if (r != GETDNS_RETURN_GOOD || upstream_len == 0) {
			return GETDNS_RETURN_BAD_CONTEXT;
		}
		/* set upstreams */
		ub_setup_stub(context->unbound_ctx, context->upstream_list,
		    upstream_len);
		/* use /etc/hosts */
		ub_ctx_hosts(context->unbound_ctx, NULL);

	} else if (context->resolution_type == GETDNS_CONTEXT_RECURSING) {
		/* set recursive */
		/* TODO: use the root servers via root hints file */
		ub_ctx_set_fwd(context->unbound_ctx, NULL);

	} else {
		/* bogus? */
		return GETDNS_RETURN_BAD_CONTEXT;
	}
	context->resolution_type_set = context->resolution_type;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_track_outbound_request(getdns_dns_req * req)
{
	if (!req) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	struct getdns_context *context = req->context;
	ldns_rbnode_t *node = GETDNS_MALLOC(context->my_mf, ldns_rbnode_t);
	if (!node) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	node->key = &(req->trans_id);
	node->data = req;
	if (!ldns_rbtree_insert(context->outbound_requests, node)) {
		/* free the node */
		GETDNS_FREE(context->my_mf, node);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_clear_outbound_request(getdns_dns_req * req)
{
	if (!req) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	struct getdns_context *context = req->context;
	ldns_rbnode_t *node = ldns_rbtree_delete(context->outbound_requests,
	    &(req->trans_id));
	if (node) {
		GETDNS_FREE(context->my_mf, node);
	}
	return GETDNS_RETURN_GOOD;
}



char *
getdns_strdup(const struct mem_funcs *mfs, const char *s)
{
    size_t sz = strlen(s) + 1;
    char *r = GETDNS_XMALLOC(*mfs, char, sz);
    if (r)
        return memcpy(r, s, sz);
    else
        return NULL;
}

struct getdns_bindata *
getdns_bindata_copy(struct mem_funcs *mfs,
    const struct getdns_bindata *src)
{
    struct getdns_bindata *dst;

    if (!src)
        return NULL;

    dst = GETDNS_MALLOC(*mfs, struct getdns_bindata);
    if (!dst)
        return NULL;

    dst->size = src->size;
    dst->data = GETDNS_XMALLOC(*mfs, uint8_t, src->size);
    if (!dst->data) {
        GETDNS_FREE(*mfs, dst);
        return NULL;
    }
    (void) memcpy(dst->data, src->data, src->size);
    return dst;
}

void
getdns_bindata_destroy(struct mem_funcs *mfs,
    struct getdns_bindata *bindata)
{
    if (!bindata)
        return;
    GETDNS_FREE(*mfs, bindata->data);
    GETDNS_FREE(*mfs, bindata);
}

/* get the fd */
int getdns_context_fd(struct getdns_context* context) {
    RETURN_IF_NULL(context, -1);
    return ub_fd(context->unbound_ctx);
}

/* process async reqs */
getdns_return_t getdns_context_process_async(struct getdns_context* context) {
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
    if (ub_poll(context->unbound_ctx)) {
        if (ub_process(context->unbound_ctx) != 0) {
            /* need an async return code? */
            return GETDNS_RETURN_GENERIC_ERROR;
        }
    }
    if (context->extension != NULL) {
        /* no need to process timeouts since it is delegated
         * to the extension */
        return GETDNS_RETURN_GOOD;
    }
    getdns_timeout_data_t key;
    /* set to 0 so it is the last timeout if we have
     * two with the same time */
    key.transaction_id = 0;
    if (gettimeofday(&key.timeout_time, NULL) != 0) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    ldns_rbnode_t* next_timeout = ldns_rbtree_first(context->timeouts_by_time);
    while (next_timeout) {
        getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) next_timeout->data;
        if (timeout_cmp(timeout_data, &key) > 0) {
            /* no more timeouts need to be fired. */
            break;
        }
        /* get the next_timeout */
        next_timeout = ldns_rbtree_next(next_timeout);
        /* delete the node */
        /* timeout data is freed in the clear_timeout */
        ldns_rbnode_t* to_del = ldns_rbtree_delete(context->timeouts_by_time, timeout_data);
        if (to_del) {
            /* should always exist .. */
            GETDNS_FREE(context->my_mf, to_del);
        }

        /* fire the timeout */
        timeout_data->callback(timeout_data->userarg);
    }

    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_extension_detach_eventloop(struct getdns_context* context)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
    getdns_return_t r = GETDNS_RETURN_GOOD;
    if (context->extension) {
        r = context->extension->cleanup_data(context, context->extension_data);
        if (r != GETDNS_RETURN_GOOD) {
            return r;
        }
        context->extension = NULL;
        context->extension_data = NULL;
    }
    return r;
}

getdns_return_t
getdns_extension_set_eventloop(struct getdns_context* context,
    getdns_eventloop_extension* extension, void* extension_data)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
    RETURN_IF_NULL(extension, GETDNS_RETURN_INVALID_PARAMETER);
    getdns_return_t r = getdns_extension_detach_eventloop(context);
    if (r != GETDNS_RETURN_GOOD) {
        return r;
    }
    context->extension = extension;
    context->extension_data = extension_data;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_schedule_timeout(struct getdns_context* context,
    getdns_transaction_t id, uint16_t timeout, getdns_timeout_callback callback,
    void* userarg) {
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
    RETURN_IF_NULL(callback, GETDNS_RETURN_INVALID_PARAMETER);
    getdns_return_t result;
    /* create a timeout */
    getdns_timeout_data_t* timeout_data = GETDNS_MALLOC(context->my_mf, getdns_timeout_data_t);
    if (!timeout_data) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    timeout_data->context = context;
    timeout_data->transaction_id = id;
    timeout_data->callback = callback;
    timeout_data->userarg = userarg;
    timeout_data->extension_timer = NULL;

    /* insert into transaction tree */
    ldns_rbnode_t *node = GETDNS_MALLOC(context->my_mf, ldns_rbnode_t);
    if (!node) {
        GETDNS_FREE(context->my_mf, timeout_data);
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    node->key = &(timeout_data->transaction_id);
    node->data = timeout_data;
    if (!ldns_rbtree_insert(context->timeouts_by_id, node)) {
        /* free the node */
        GETDNS_FREE(context->my_mf, timeout_data);
        GETDNS_FREE(context->my_mf, node);
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    if (context->extension) {
        result = context->extension->schedule_timeout(context, context->extension_data,
            timeout, timeout_data, &(timeout_data->extension_timer));
    } else {
        result = GETDNS_RETURN_GENERIC_ERROR;
        if (gettimeofday(&timeout_data->timeout_time, NULL) == 0) {
            ldns_rbnode_t* id_node = GETDNS_MALLOC(context->my_mf, ldns_rbnode_t);
            if (id_node) {
                id_node->key = timeout_data;
                id_node->data = timeout_data;
                if (!ldns_rbtree_insert(context->timeouts_by_time, node)) {
                    GETDNS_FREE(context->my_mf, id_node);
                } else {
                    result = GETDNS_RETURN_GOOD;
                }
            }
        }
    }
    if (result != GETDNS_RETURN_GOOD) {
        GETDNS_FREE(context->my_mf, timeout_data);
        GETDNS_FREE(context->my_mf, node);
    }
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_clear_timeout(struct getdns_context* context,
    getdns_transaction_t id) {
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
    /* find the timeout_data by id */
    ldns_rbnode_t* node = ldns_rbtree_delete(context->timeouts_by_id, &id);
    if (!node) {
        return GETDNS_RETURN_UNKNOWN_TRANSACTION;
    }
    getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) node->data;
    GETDNS_FREE(context->my_mf, node);
    if (context->extension) {
        context->extension->clear_timeout(context, context->extension,
            timeout_data->extension_timer);
    } else {
        /* make sure it is removed from the timeout node */
        ldns_rbnode_t* to_del = ldns_rbtree_delete(context->timeouts_by_time, timeout_data);
        if (to_del) {
            GETDNS_FREE(context->my_mf, to_del);
        }
    }
    GETDNS_FREE(context->my_mf, timeout_data);
    return GETDNS_RETURN_GOOD;
}


/* context.c */
