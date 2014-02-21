/**
 *
 * \file context.c
 * @brief getdns context management functions
 *
 * Declarations taken from the getdns API description pseudo implementation.
 *
 */

/*
 * Copyright (c) 2013, NLNet Labs, Versign, Inc.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <unbound.h>

#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"

void *plain_mem_funcs_user_arg = MF_PLAIN;

/* Private functions */
getdns_return_t create_default_namespaces(struct getdns_context *context);
static struct getdns_list *create_default_root_servers(void);
static getdns_return_t add_ip_str(struct getdns_dict *);
static struct getdns_dict *create_ipaddr_dict_from_rdf(struct getdns_context *,
    ldns_rdf *);
static struct getdns_list *create_from_ldns_list(struct getdns_context *,
    ldns_rdf **, size_t);
static getdns_return_t set_os_defaults(struct getdns_context *);
static int transaction_id_cmp(const void *, const void *);
static int timeout_cmp(const void *, const void *);
static void dispatch_updated(struct getdns_context *, uint16_t);
static void cancel_dns_req(getdns_dns_req *);
static void cancel_outstanding_requests(struct getdns_context*, int);

/* unbound helpers */
static getdns_return_t rebuild_ub_ctx(struct getdns_context* context);
static void set_ub_string_opt(struct getdns_context *, char *, char *);
static void set_ub_number_opt(struct getdns_context *, char *, uint16_t);
static getdns_return_t set_ub_dns_transport(struct getdns_context*, getdns_transport_t);
static void set_ub_limit_outstanding_queries(struct getdns_context*,
    uint16_t);
static void set_ub_dnssec_allowed_skew(struct getdns_context*, uint32_t);
static void set_ub_edns_maximum_udp_payload_size(struct getdns_context*,
    uint16_t);


/* Stuff to make it compile pedantically */
#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

/**
 * Helper to get default lookup namespaces.
 * TODO: Determine from OS
 */
getdns_return_t
create_default_namespaces(struct getdns_context *context)
{
	context->namespaces = GETDNS_XMALLOC(context->my_mf, getdns_namespace_t, 2);
	if(context->namespaces == NULL)
		return GETDNS_RETURN_GENERIC_ERROR;

	context->namespaces[0] = GETDNS_NAMESPACE_LOCALNAMES;
	context->namespaces[1] = GETDNS_NAMESPACE_DNS;
	context->namespace_count = 2;

	return GETDNS_RETURN_GOOD;
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

#define IP_STR_BUFF_LEN 512

static getdns_return_t
add_ip_str(struct getdns_dict * ip)
{
    struct sockaddr_storage storage;
    uint32_t port = 0;
    char buff[IP_STR_BUFF_LEN];
    memset(buff, 0, IP_STR_BUFF_LEN);
    getdns_return_t r = dict_to_sockaddr(ip, &storage);
    if (r != GETDNS_RETURN_GOOD) {
        return r;
    }
    if (storage.ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *) &storage;
        const char *ipStr =
        inet_ntop(AF_INET, &(addr->sin_addr), buff, IP_STR_BUFF_LEN);
        if (!ipStr) {
            return GETDNS_RETURN_GENERIC_ERROR;
        }
        r = getdns_dict_get_int(ip, GETDNS_STR_PORT, &port);
        if (r == GETDNS_RETURN_GOOD && port > 0) {
            size_t addrLen = strlen(ipStr);
            /* append @ and port */
            buff[addrLen] = '@';
            ++addrLen;
            snprintf(buff + addrLen, IP_STR_BUFF_LEN - addrLen, "%d", port);
        }
        getdns_dict_util_set_string(ip, GETDNS_STR_ADDRESS_STRING,
            ipStr);
    } else if (storage.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &storage;
        const char *ipStr =
            inet_ntop(AF_INET6, &(addr->sin6_addr), buff, IP_STR_BUFF_LEN);
        if (!ipStr) {
            return GETDNS_RETURN_GENERIC_ERROR;
        }
        r = getdns_dict_get_int(ip, GETDNS_STR_PORT, &port);
        if (r == GETDNS_RETURN_GOOD && port > 0) {
            size_t addrLen = strlen(ipStr);
            /* append @ and port */
            buff[addrLen] = '@';
            ++addrLen;
            snprintf(buff + addrLen, IP_STR_BUFF_LEN - addrLen, "%d", port);
        }

        getdns_dict_util_set_string(ip, GETDNS_STR_ADDRESS_STRING,
            ipStr);
    } else {
        /* unknown */
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    return GETDNS_RETURN_GOOD;
}

/**
 * check a file for changes since the last check
 * and refresh the current data if changes are detected
 * @param file to check
 * @returns changes as OR'd list of GETDNS_FCHG_* values
 * @returns GETDNS_FCHG_NONE if no changes
 * @returns GETDNS_FCHG_ERRORS if problems (see fchg->errors for details)
 */
int
filechg_check(struct getdns_context *context, struct filechg *fchg)
{
    struct stat *finfo;

    if(fchg == NULL)
        return 0;

    fchg->errors  = GETDNS_FCHG_NOERROR;
    fchg->changes = GETDNS_FCHG_NOCHANGES;

    finfo = GETDNS_MALLOC(context->my_mf, struct stat);
    if(finfo == NULL)
    {
        fchg->errors = errno;
        return GETDNS_FCHG_ERRORS;
	}

    if(stat(fchg->fn, finfo) != 0)
    {
		GETDNS_FREE(context->my_mf, finfo);
        fchg->errors = errno;
        return GETDNS_FCHG_ERRORS;
    }

    /* we want to consider a file that previously returned error for stat() as a
       change */

    if(fchg->prevstat == NULL)
        fchg->changes = GETDNS_FCHG_MTIME | GETDNS_FCHG_CTIME;
    else
    {
        if(fchg->prevstat->st_mtime != finfo->st_mtime)
            fchg->changes |= GETDNS_FCHG_MTIME;
        if(fchg->prevstat->st_ctime != finfo->st_ctime)
            fchg->changes |= GETDNS_FCHG_CTIME;
    	GETDNS_FREE(context->my_mf, fchg->prevstat);
    }
    fchg->prevstat = finfo;

    return fchg->changes;
} /* filechg */

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

/*---------------------------------------- set_os_defaults
  we use ldns to read the resolv.conf file - the ldns resolver is
  destroyed once the file is read
*/
static getdns_return_t
set_os_defaults(struct getdns_context *context)
{
    ldns_resolver *lr = NULL;
    ldns_rdf      **rdf_list;
    size_t        rdf_list_sz;

    if (ldns_resolver_new_frm_file(&lr, NULL) != LDNS_STATUS_OK)
        return GETDNS_RETURN_GENERIC_ERROR;

	if(context->fchg_resolvconf == NULL)
	{
		context->fchg_resolvconf = GETDNS_MALLOC(context->my_mf, struct filechg);
		if(context->fchg_resolvconf == NULL)
			return GETDNS_RETURN_MEMORY_ERROR;
		context->fchg_resolvconf->fn       = "/etc/resolv.conf";
		context->fchg_resolvconf->prevstat = NULL;
		context->fchg_resolvconf->changes  = GETDNS_FCHG_NOCHANGES;
		context->fchg_resolvconf->errors   = GETDNS_FCHG_NOERROR;
	}
	filechg_check(context, context->fchg_resolvconf);

    rdf_list    = ldns_resolver_nameservers(lr);
    rdf_list_sz = ldns_resolver_nameserver_count(lr);
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
    ldns_resolver_deep_free(lr);

    return GETDNS_RETURN_GOOD;
} /* set_os_defaults */

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

static int
timeout_cmp(const void *to1, const void *to2)
{
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

static ldns_rbtree_t*
create_ldns_rbtree(getdns_context * context,
    int(*cmpf)(const void *, const void *)) {
    ldns_rbtree_t* result = GETDNS_MALLOC(context->mf, ldns_rbtree_t);
    if (!result) {
        return NULL;
    }
    ldns_rbtree_init(result, cmpf);
    return result;
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
    result->destroying = 0;
    result->my_mf.mf_arg         = userarg;
    result->my_mf.mf.ext.malloc  = malloc;
    result->my_mf.mf.ext.realloc = realloc;
    result->my_mf.mf.ext.free    = free;

    result->update_callback = NULL;

    result->mf.mf_arg          = userarg;
    result->mf.mf.ext.malloc   = malloc;
    result->mf.mf.ext.realloc  = realloc;
    result->mf.mf.ext.free     = free;

    result->resolution_type_set = 0;

    result->outbound_requests = create_ldns_rbtree(result, transaction_id_cmp);
    result->timeouts_by_time = create_ldns_rbtree(result, timeout_cmp);
    result->timeouts_by_id = create_ldns_rbtree(result, transaction_id_cmp);


    result->resolution_type = GETDNS_RESOLUTION_RECURSING;
    if(create_default_namespaces(result) != GETDNS_RETURN_GOOD)
		return GETDNS_RETURN_GENERIC_ERROR;

    result->timeout = 5000;
    result->follow_redirects = GETDNS_REDIRECTS_FOLLOW;
    result->dns_root_servers = create_default_root_servers();
    result->append_name = GETDNS_APPEND_NAME_ALWAYS;
    result->suffix = NULL;

    result->dnssec_trust_anchors = NULL;
    result->upstream_list = NULL;

    result->edns_extended_rcode = 0;
    result->edns_version = 0;
    result->edns_do_bit = 1;

    result->extension = NULL;
    result->extension_data = NULL;

	result->fchg_resolvconf = NULL;
	result->fchg_hosts      = NULL;
    if (set_from_os) {
        if (GETDNS_RETURN_GOOD != set_os_defaults(result)) {
            getdns_context_destroy(result);
            return GETDNS_RETURN_GENERIC_ERROR;
        }
    }
    result->dnssec_allowed_skew = 0;
    result->edns_maximum_udp_payload_size = 512;
    result->dns_transport = GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP;
    result->limit_outstanding_queries = 0;
    result->has_ta = priv_getdns_parse_ta_file(NULL, NULL);
    if (!result->outbound_requests ||
        !result->timeouts_by_id ||
        !result->timeouts_by_time) {
        getdns_context_destroy(result);
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    /* unbound context is initialized here */
    result->unbound_ctx = NULL;
    if (GETDNS_RETURN_GOOD != rebuild_ub_ctx(result)) {
        getdns_context_destroy(result);
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    *context = result;

    return GETDNS_RETURN_GOOD;
} /* getdns_context_create_with_extended_memory_functions */

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
}               /* getdns_context_create */

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
}               /* getdns_context_create */


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
    context->destroying = 1;
    cancel_outstanding_requests(context, 1);
    getdns_extension_detach_eventloop(context);

    if (context->namespaces)
        GETDNS_FREE(context->my_mf, context->namespaces);
	if(context->fchg_resolvconf)
	{
		if(context->fchg_resolvconf->prevstat)
			GETDNS_FREE(context->my_mf, context->fchg_resolvconf->prevstat);
		GETDNS_FREE(context->my_mf, context->fchg_resolvconf);
	}
	if(context->fchg_hosts)
	{
		if(context->fchg_hosts->prevstat)
			GETDNS_FREE(context->my_mf, context->fchg_hosts->prevstat);
		GETDNS_FREE(context->my_mf, context->fchg_hosts);
	}

    getdns_list_destroy(context->dns_root_servers);
    getdns_list_destroy(context->suffix);
    getdns_list_destroy(context->dnssec_trust_anchors);
    getdns_list_destroy(context->upstream_list);

    /* destroy the ub context */
    if (context->unbound_ctx)
        ub_ctx_delete(context->unbound_ctx);

    if (context->outbound_requests)
        GETDNS_FREE(context->my_mf, context->outbound_requests);
    if (context->timeouts_by_id)
        GETDNS_FREE(context->my_mf, context->timeouts_by_id);
    if (context->timeouts_by_time)
        GETDNS_FREE(context->my_mf, context->timeouts_by_time);

    GETDNS_FREE(context->my_mf, context);
    return;
}               /* getdns_context_destroy */

/*
 * getdns_context_set_context_update_callback
 *
 */
getdns_return_t
getdns_context_set_context_update_callback(struct getdns_context *context,
    void (*value) (struct getdns_context *context,
                   getdns_context_code_t changed_item))
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    context->update_callback = value;
    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_context_update_callback */

/*
 * Helpers to set options on the unbound ctx
 */

static void
set_ub_string_opt(struct getdns_context *ctx, char *opt, char *value)
{
    if (ctx->unbound_ctx)
        ub_ctx_set_option(ctx->unbound_ctx, opt, value);
}

static void
set_ub_number_opt(struct getdns_context *ctx, char *opt, uint16_t value)
{
    char buffer[64];
    snprintf(buffer, 64, "%hu", value);
    set_ub_string_opt(ctx, opt, buffer);
}

static getdns_return_t
rebuild_ub_ctx(struct getdns_context* context) {
    if (context->unbound_ctx != NULL) {
        /* cancel all requests and delete */
        cancel_outstanding_requests(context, 1);
        ub_ctx_delete(context->unbound_ctx);
        context->unbound_ctx = NULL;
    }
    /* setup */
    context->unbound_ctx = ub_ctx_create();
    if (!context->unbound_ctx) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    set_ub_dnssec_allowed_skew(context,
        context->dnssec_allowed_skew);
    set_ub_edns_maximum_udp_payload_size(context,
        context->edns_maximum_udp_payload_size);
    set_ub_dns_transport(context,
        context->dns_transport);

    /* Set default trust anchor */
    if (context->has_ta) {
        (void) ub_ctx_add_ta_file(
            context->unbound_ctx, TRUST_ANCHOR_FILE);
    }
    return GETDNS_RETURN_GOOD;
}

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
getdns_context_set_resolution_type(struct getdns_context *context,
    getdns_resolution_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (value != GETDNS_RESOLUTION_STUB && value != GETDNS_RESOLUTION_RECURSING) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    if (context->resolution_type_set != 0) {
        /* already setup */
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    context->resolution_type = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_RESOLUTION_TYPE);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_resolution_type */

/*
 * getdns_context_set_namespaces
 *
 */
getdns_return_t
getdns_context_set_namespaces(struct getdns_context *context,
    size_t namespace_count, getdns_namespace_t *namespaces)
{
	size_t i;

    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (namespace_count == 0 || namespaces == NULL) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    if (context->resolution_type_set != 0) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

	for(i=0; i<namespace_count; i++)
	{
		if( namespaces[i] != GETDNS_NAMESPACE_DNS
		 && namespaces[i] != GETDNS_NAMESPACE_LOCALNAMES
		 && namespaces[i] != GETDNS_NAMESPACE_NETBIOS
		 && namespaces[i] != GETDNS_NAMESPACE_MDNS
		 && namespaces[i] != GETDNS_NAMESPACE_NIS)
			return GETDNS_RETURN_INVALID_PARAMETER;
	}

    GETDNS_FREE(context->my_mf, context->namespaces);

    /** duplicate **/
    context->namespaces = GETDNS_XMALLOC(context->my_mf, getdns_namespace_t,
        namespace_count);
    memcpy(context->namespaces, namespaces,
        namespace_count * sizeof(getdns_namespace_t));
	context->namespace_count = namespace_count;
    dispatch_updated(context, GETDNS_CONTEXT_CODE_NAMESPACES);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_namespaces */

static getdns_return_t
set_ub_dns_transport(struct getdns_context* context,
    getdns_transport_t value) {
    switch (value) {
        case GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP:
            set_ub_string_opt(context, "do-udp", "yes");
            set_ub_string_opt(context, "do-tcp", "yes");
            break;
        case GETDNS_TRANSPORT_UDP_ONLY:
            set_ub_string_opt(context, "do-udp", "yes");
            set_ub_string_opt(context, "do-tcp", "no");
            break;
        case GETDNS_TRANSPORT_TCP_ONLY:
            set_ub_string_opt(context, "do-udp", "no");
            set_ub_string_opt(context, "do-tcp", "yes");
            break;
        default:
            /* TODO GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN */
            return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
        }
    return GETDNS_RETURN_GOOD;
}
/*
 * getdns_context_set_dns_transport
 *
 */
getdns_return_t
getdns_context_set_dns_transport(struct getdns_context *context,
    getdns_transport_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (set_ub_dns_transport(context, value) != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    if (value != context->dns_transport) {
        context->dns_transport = value;
        dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_TRANSPORT);
    }

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_dns_transport */

static void
set_ub_limit_outstanding_queries(struct getdns_context* context, uint16_t value) {
    /* num-queries-per-thread */
    set_ub_number_opt(context, "num-queries-per-thread", value);
}
/*
 * getdns_context_set_limit_outstanding_queries
 *
 */
getdns_return_t
getdns_context_set_limit_outstanding_queries(struct getdns_context *context,
    uint16_t limit)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    set_ub_limit_outstanding_queries(context, limit);
    if (limit != context->limit_outstanding_queries) {
        context->limit_outstanding_queries = limit;
        dispatch_updated(context,
            GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES);
    }

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_limit_outstanding_queries */

/*
 * getdns_context_set_timeout
 *
 */
getdns_return_t
getdns_context_set_timeout(struct getdns_context *context, uint64_t timeout)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

    if (timeout == 0) {
        return GETDNS_RETURN_INVALID_PARAMETER;
    }

    context->timeout = timeout;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_TIMEOUT);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_timeout */

/*
 * getdns_context_set_follow_redirects
 *
 */
getdns_return_t
getdns_context_set_follow_redirects(struct getdns_context *context,
    getdns_redirects_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    context->follow_redirects = value;
    if (context->resolution_type_set != 0) {
        /* already setup */
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    dispatch_updated(context, GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS);
    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_follow_redirects */

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
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (context->resolution_type_set != 0) {
        /* already setup */
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
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

    dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_dns_root_servers */

/*
 * getdns_context_set_append_name
 *
 */
getdns_return_t
getdns_context_set_append_name(struct getdns_context *context,
    getdns_append_name_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (value != GETDNS_APPEND_NAME_ALWAYS &&
        value != GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE &&
        value != GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE
        && value != GETDNS_APPEND_NAME_NEVER) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->append_name = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_APPEND_NAME);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_append_name */

/*
 * getdns_context_set_suffix
 *
 */
getdns_return_t
getdns_context_set_suffix(struct getdns_context *context, struct getdns_list * value)
{
    struct getdns_list *copy = NULL;
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (context->resolution_type_set != 0) {
        /* already setup */
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    if (value != NULL) {
        if (getdns_list_copy(value, &copy) != GETDNS_RETURN_GOOD) {
            return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
        }
        value = copy;
    }
    getdns_list_destroy(context->suffix);
    context->suffix = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_SUFFIX);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_suffix */

/*
 * getdns_context_set_dnssec_trust_anchors
 *
 */
getdns_return_t
getdns_context_set_dnssec_trust_anchors(struct getdns_context *context,
    struct getdns_list * value)
{
    struct getdns_list *copy = NULL;
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
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
}               /* getdns_context_set_dnssec_trust_anchors */

static void
set_ub_dnssec_allowed_skew(struct getdns_context* context, uint32_t value) {
    set_ub_number_opt(context, "val-sig-skew-min", value);
    set_ub_number_opt(context, "val-sig-skew-max", value);
}
/*
 * getdns_context_set_dnssec_allowed_skew
 *
 */
getdns_return_t
getdns_context_set_dnssec_allowed_skew(struct getdns_context *context,
    uint32_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    set_ub_dnssec_allowed_skew(context, value);
    if (value != context->dnssec_allowed_skew) {
        context->dnssec_allowed_skew = value;
        dispatch_updated(context, GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW);
    }

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_dnssec_allowed_skew */

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
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(upstream_list, GETDNS_RETURN_INVALID_PARAMETER);
    getdns_return_t r = getdns_list_get_length(upstream_list, &count);
    if (count == 0 || r != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    if (context->resolution_type_set != 0) {
        /* already setup */
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

    dispatch_updated(context,
        GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS);

    return GETDNS_RETURN_GOOD;
}           /* getdns_context_set_upstream_recursive_servers */


static void
set_ub_edns_maximum_udp_payload_size(struct getdns_context* context,
    uint16_t value) {
    /* max-udp-size */
    set_ub_number_opt(context, "max-udp-size", value);
}
/*
 * getdns_context_set_edns_maximum_udp_payload_size
 *
 */
getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(struct getdns_context *context,
    uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    /* check for < 512.  uint16_t won't let it go above max) */
    if (value < 512) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    set_ub_edns_maximum_udp_payload_size(context, value);
    if (value != context->edns_maximum_udp_payload_size) {
        context->edns_maximum_udp_payload_size = value;
        dispatch_updated(context,
            GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE);
    }

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_maximum_udp_payload_size */

/*
 * getdns_context_set_edns_extended_rcode
 *
 */
getdns_return_t
getdns_context_set_edns_extended_rcode(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    context->edns_extended_rcode = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_extended_rcode */

/*
 * getdns_context_set_edns_version
 *
 */
getdns_return_t
getdns_context_set_edns_version(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    context->edns_version = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_VERSION);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_version */

/*
 * getdns_context_set_edns_do_bit
 *
 */
getdns_return_t
getdns_context_set_edns_do_bit(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    /* only allow 1 */
    if (value != 1) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->edns_do_bit = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_DO_BIT);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_do_bit */

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
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
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
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

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

        /* fire callback */
        cb(context,
            GETDNS_CALLBACK_CANCEL,
            NULL, user_pointer, transaction_id);
    }
    /* clean up */
    GETDNS_FREE(context->my_mf, node);
    dns_req_free(req);
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
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    getdns_return_t r = getdns_context_cancel_request(context, transaction_id, 1);
    if (context->extension) {
        context->extension->request_count_changed(context,
            context->outbound_requests->count, context->extension_data);
    }
    return r;
} /* getdns_cancel_callback */

static getdns_return_t
ub_setup_stub(struct ub_ctx *ctx, struct getdns_list * upstreams)
{
	size_t i;
	size_t count;
	struct getdns_dict *dict;
	struct getdns_bindata *address_string;
	getdns_return_t r;

	r = getdns_list_get_length(upstreams, &count);
	if (r != GETDNS_RETURN_GOOD)
		return r;

	if (count == 0)
		return GETDNS_RETURN_BAD_CONTEXT;

	/* reset forwarding servers */
	(void) ub_ctx_set_fwd(ctx, NULL);
	for (i = 0; i < count; ++i) {
		r = getdns_list_get_dict(upstreams, i, &dict);
		if (r != GETDNS_RETURN_GOOD)
			break;

		r = getdns_dict_get_bindata(dict, GETDNS_STR_ADDRESS_STRING,
		    &address_string);
		if (r != GETDNS_RETURN_GOOD)
			break;

		(void) ub_ctx_set_fwd(ctx, (char *)address_string->data);
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

	return r;
}

static getdns_return_t
priv_getdns_ns_dns_setup(struct getdns_context *context)
{
	assert(context);

	switch (context->resolution_type) {
	case GETDNS_RESOLUTION_STUB:
		return ub_setup_stub(context->unbound_ctx,
		    context->upstream_list);

	case GETDNS_RESOLUTION_RECURSING:
		/* TODO: use the root servers via root hints file */
		(void) ub_ctx_set_fwd(context->unbound_ctx, NULL);
		return GETDNS_RETURN_GOOD;
	}
	return GETDNS_RETURN_BAD_CONTEXT;
}

getdns_return_t
getdns_context_prepare_for_resolution(struct getdns_context *context,
    int usenamespaces)
{
	int i;
	getdns_return_t r;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (context->destroying) {
        return GETDNS_RETURN_BAD_CONTEXT;
    }
	if (context->resolution_type_set == context->resolution_type)
        	/* already set and no config changes
		 * have caused this to be bad.
		 */
		return GETDNS_RETURN_GOOD;

	/* TODO: respect namespace order (unbound always uses local first if cfg
	 * the spec calls for us to treat the namespace list as ordered
	 * so we need to respect that order
	 */


	if (! usenamespaces) {
		r = priv_getdns_ns_dns_setup(context);
		if (r == GETDNS_RETURN_GOOD)
			context->resolution_type_set = context->resolution_type;
		return r;
	}

	r = GETDNS_RETURN_GOOD;
	for (i = 0; i < context->namespace_count; i++) {
		switch (context->namespaces[i]) {
		case GETDNS_NAMESPACE_LOCALNAMES:
			(void) ub_ctx_hosts(context->unbound_ctx, NULL);
			break;

		case GETDNS_NAMESPACE_DNS:
			r = priv_getdns_ns_dns_setup(context);
			break;

		default:
			r = GETDNS_RETURN_BAD_CONTEXT;
			break;
		}
		if (r != GETDNS_RETURN_GOOD)
			return r; /* try again later (resolution_type_set) */
	}
	context->resolution_type_set = context->resolution_type;
	return r;
} /* getdns_context_prepare_for_resolution */

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
    if (context->extension) {
        context->extension->request_count_changed(context,
            context->outbound_requests->count, context->extension_data);
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

uint32_t
getdns_context_get_num_pending_requests(struct getdns_context* context,
    struct timeval* next_timeout) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    uint32_t r = context->outbound_requests->count;
    if (r > 0) {
        if (!context->extension && next_timeout) {
            /* default is 1 second */
            next_timeout->tv_sec = 1;
            next_timeout->tv_usec = 0;
            struct timeval now;
            if (gettimeofday(&now, NULL) == 0) {
                /* get the first timeout */
                ldns_rbnode_t* first = ldns_rbtree_first(context->timeouts_by_time);
                if (first) {
                    getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) first->data;
                    /* subtract next_timeout from now */
                    if (timeout_data->timeout_time.tv_sec > now.tv_sec ||
                        (timeout_data->timeout_time.tv_sec == now.tv_sec &&
                         timeout_data->timeout_time.tv_usec >= now.tv_usec)) {
                        next_timeout->tv_sec = timeout_data->timeout_time.tv_sec - now.tv_sec;
                        if (timeout_data->timeout_time.tv_usec < now.tv_usec) {
                            /* we only enter this condition when timeout_data.tv_sec > now.tv_sec */
                            next_timeout->tv_usec = (timeout_data->timeout_time.tv_usec + 100000) - now.tv_usec;
                            next_timeout->tv_sec--;
                        } else {
                            next_timeout->tv_usec = timeout_data->timeout_time.tv_usec - now.tv_usec;
                        }
                    } else {
                        /* timeout passed already */
                        /* usec already 0 per setting default */
                        next_timeout->tv_sec = 0;
                    }
                }
            }
        }
    }
    return r;
}

/* process async reqs */
getdns_return_t getdns_context_process_async(struct getdns_context* context) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
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
        /* timeout data and the timeouts_by_id node are freed in the clear_timeout */
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

typedef struct timeout_accumulator {
    getdns_transaction_t* ids;
    int idx;
} timeout_accumulator;

static void
accumulate_outstanding_transactions(ldns_rbnode_t* node, void* arg) {
    timeout_accumulator* acc = (timeout_accumulator*) arg;
    acc->ids[acc->idx] = *((getdns_transaction_t*) node->key);
    acc->idx++;
}

static void
cancel_outstanding_requests(struct getdns_context* context, int fire_callback) {
    if (context->outbound_requests->count > 0) {
        timeout_accumulator acc;
        int i;
        acc.idx = 0;
        acc.ids = GETDNS_XMALLOC(context->my_mf, getdns_transaction_t, context->outbound_requests->count);
        ldns_traverse_postorder(context->outbound_requests, accumulate_outstanding_transactions, &acc);
        for (i = 0; i < acc.idx; ++i) {
            getdns_context_cancel_request(context, acc.ids[i], fire_callback);
        }
        GETDNS_FREE(context->my_mf, acc.ids);
    }
}

getdns_return_t
getdns_extension_detach_eventloop(struct getdns_context* context)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    getdns_return_t r = GETDNS_RETURN_GOOD;
    if (context->extension) {
        /* cancel all outstanding requests */
        cancel_outstanding_requests(context, 1);
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
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
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
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
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
    node->left = NULL;
    node->right = NULL;
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
            /* timeout is in millis */
            uint16_t num_secs = timeout / 1000;
            uint16_t num_usecs = (timeout % 1000) * 1000;
            timeout_data->timeout_time.tv_usec += num_usecs;
            /* overflow check */
            if (timeout_data->timeout_time.tv_usec > 1000000) {
                timeout_data->timeout_time.tv_usec -= 1000000;
                num_secs++;
            }
            timeout_data->timeout_time.tv_sec += num_secs;

            ldns_rbnode_t* id_node = GETDNS_MALLOC(context->my_mf, ldns_rbnode_t);
            if (id_node) {
                id_node->key = timeout_data;
                id_node->data = timeout_data;
                id_node->left = NULL;
                id_node->right = NULL;
                if (!ldns_rbtree_insert(context->timeouts_by_time, id_node)) {
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
    return result;
}

getdns_return_t
getdns_context_clear_timeout(struct getdns_context* context,
    getdns_transaction_t id) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    /* find the timeout_data by id */
    ldns_rbnode_t* node = ldns_rbtree_delete(context->timeouts_by_id, &id);
    if (!node) {
        return GETDNS_RETURN_UNKNOWN_TRANSACTION;
    }
    getdns_timeout_data_t* timeout_data = (getdns_timeout_data_t*) node->data;
    GETDNS_FREE(context->my_mf, node);
    if (context->extension) {
        context->extension->clear_timeout(context, context->extension_data,
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

void*
getdns_context_get_extension_data(struct getdns_context* context) {
    RETURN_IF_NULL(context, NULL);
    return context->extension_data;
}

static inline getdns_return_t
priv_dict_set_list_if_not_null(getdns_dict* dict,
    const char* name, getdns_list* list) {
    if (!list) {
        return GETDNS_RETURN_GOOD;
    }
    return getdns_dict_set_list(dict, name, list);
}

static getdns_dict*
priv_get_context_settings(getdns_context* context) {
    getdns_return_t r = GETDNS_RETURN_GOOD;
    getdns_dict* result = getdns_dict_create_with_context(context);
    if (!result) {
        return NULL;
    }
    /* int fields */
    r = getdns_dict_set_int(result, "dns_transport", context->dns_transport);
    r |= getdns_dict_set_int(result, "timeout", context->timeout);
    r |= getdns_dict_set_int(result, "limit_outstanding_queries", context->limit_outstanding_queries);
    r |= getdns_dict_set_int(result, "dnssec_allowed_skew", context->dnssec_allowed_skew);
    r |= getdns_dict_set_int(result, "follow_redirects", context->follow_redirects);
    r |= getdns_dict_set_int(result, "edns_maximum_udp_payload_size", context->edns_maximum_udp_payload_size);
    r |= getdns_dict_set_int(result, "edns_extended_rcode", context->edns_extended_rcode);
    r |= getdns_dict_set_int(result, "edns_version", context->edns_version);
    r |= getdns_dict_set_int(result, "edns_do_bit", context->edns_do_bit);
    r |= getdns_dict_set_int(result, "append_name", context->append_name);
    /* list fields */
    r |= priv_dict_set_list_if_not_null(result, "suffix", context->suffix);
    r |= priv_dict_set_list_if_not_null(result, "upstream_recursive_servers", context->upstream_list);
    if (context->namespace_count > 0) {
        /* create a namespace list */
        size_t i;
        getdns_list* namespaces = getdns_list_create_with_context(context);
        if (namespaces) {
            for (i = 0; i < context->namespace_count; ++i) {
                r |= getdns_list_set_int(namespaces, i, context->namespaces[i]);
            }
            r |= getdns_dict_set_list(result, "namespaces", namespaces);
        }
    }
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(result);
        result = NULL;
    }
    return result;
}

getdns_dict*
getdns_context_get_api_information(getdns_context* context) {
    getdns_return_t r = GETDNS_RETURN_GOOD;
    getdns_dict* result = getdns_dict_create_with_context(context);
    getdns_dict* settings;
    if (!result) {
        return NULL;
    }
    r = getdns_dict_util_set_string(result, "version_string", PACKAGE_VERSION);
    r |= getdns_dict_util_set_string(result, "implementation_string", PACKAGE_URL);
    r |= getdns_dict_set_int(result, "resolver_type", context->resolution_type);
    settings = priv_get_context_settings(context);
    r |= getdns_dict_set_dict(result, "all_context", settings);
    getdns_dict_destroy(settings);
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(result);
        result = NULL;
    }
    return result;
}

getdns_return_t
getdns_context_set_return_dnssec_status(getdns_context* context, int enabled) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (enabled != GETDNS_EXTENSION_TRUE ||
        enabled != GETDNS_EXTENSION_FALSE) {
        return GETDNS_RETURN_INVALID_PARAMETER;
    }
    context->return_dnssec_status = enabled;
    return GETDNS_RETURN_GOOD;
}

/* context.c */
