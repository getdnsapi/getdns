/**
 *
 * /brief getdns contect management functions
 * 
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
 *
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <string.h>
#include <getdns_context.h>
#include <ldns/ldns.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/**
 * Helper to get default lookup namespaces.
 * TODO: Determine from OS
 */
static uint16_t* create_default_namespaces() {
    uint16_t *result = malloc(2 * sizeof(uint16_t));
    result[0] = GETDNS_CONTEXT_NAMESPACE_LOCALNAMES;
    result[1] = GETDNS_CONTEXT_NAMESPACE_DNS;
    return result;
}

/**
 * Helper to get the default root servers.
 * TODO: Implement
 */
static struct getdns_list* create_default_root_servers() {
    return NULL;
}

static struct getdns_dict* create_ipaddr_dict_from_rdf(ldns_rdf* rdf) {
    ldns_rdf_type rt = ldns_rdf_get_type(rdf);
    size_t sz = ldns_rdf_size(rdf);
    getdns_dict *result = getdns_dict_create();
    /* set type */
    if (rt == LDNS_RDF_TYPE_A) {
        getdns_bindata type_bin = { (size_t) strlen(GETDNS_STR_IPV4), 
                                    (uint8_t*) GETDNS_STR_IPV4 };
        getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_TYPE, &type_bin);
    } else {
        getdns_bindata type_bin = { (size_t) strlen(GETDNS_STR_IPV6), 
                                    (uint8_t*) GETDNS_STR_IPV6 };
        getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_TYPE, &type_bin);
    }
    /* set data */
    getdns_bindata data_bin = { sz, ldns_rdf_data(rdf) };
    getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_DATA, &data_bin);
    return result;
}

static struct getdns_list* create_from_ldns_list(ldns_rdf** ldns_list, size_t count) {
    size_t i = 0;
    size_t idx = 0;
    struct getdns_list *result = getdns_list_create();
    for (i = 0; i < count; ++i) {
        ldns_rdf* rdf = ldns_list[i];
        switch (ldns_rdf_get_type(rdf)) {
            case LDNS_RDF_TYPE_A:
            case LDNS_RDF_TYPE_AAAA:
            {
                getdns_dict *ipaddr = create_ipaddr_dict_from_rdf(rdf);
                getdns_list_add_item(result, &idx);
                getdns_list_set_dict(result, idx, ipaddr);
                getdns_dict_destroy(ipaddr);
            }
            break;
            
            case LDNS_RDF_TYPE_DNAME:
            {
                getdns_bindata item;
                char* srch = ldns_rdf2str(rdf);
                item.size = strlen(srch);
                item.data = (uint8_t*) srch;
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

static getdns_return_t set_os_defaults(getdns_context_t context) {
    ldns_resolver *lr = NULL;
    if (ldns_resolver_new_frm_file(&lr, NULL) != LDNS_STATUS_OK) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    ldns_rdf **rdf_list= ldns_resolver_nameservers(lr);
    size_t rdf_list_sz = ldns_resolver_nameserver_count(lr);
    if (rdf_list_sz > 0) {
        context->upstream_list = create_from_ldns_list(rdf_list, rdf_list_sz);
    }
    rdf_list = ldns_resolver_searchlist(lr);
    rdf_list_sz = ldns_resolver_searchlist_count(lr);
    if (rdf_list_sz > 0) {
        context->suffix = create_from_ldns_list(rdf_list, rdf_list_sz);
    }
    /** cleanup **/
    ldns_resolver_free(lr);
    return GETDNS_RETURN_GOOD;
}

/*
 * getdns_context_create
 *
 * call this to initialize the context that is used in other getdns calls
 */
getdns_return_t
getdns_context_create(
    getdns_context_t       *context,
    bool                   set_from_os
)
{
    UNUSED_PARAM(set_from_os);
    getdns_context_t result = NULL;

    if (context == NULL) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    /** default init **/
    result = malloc(sizeof(struct getdns_context_t));
    result->resolution_type = GETDNS_CONTEXT_RECURSING;
    result->namespaces = create_default_namespaces();
    result->dns_transport = GETDNS_CONTEXT_UDP_FIRST_AND_FALL_BACK_TO_TCP;
    result->limit_outstanding_queries = 0;
    result->timeout = 5000;
    result->follow_redirects = GETDNS_CONTEXT_FOLLOW_REDIRECTS;
    result->dns_root_servers = create_default_root_servers();
    result->append_name = GETDNS_CONTEXT_APPEND_NAME_ALWAYS;
    result->suffix = NULL;
    
    result->dnssec_trust_anchors = NULL;
    result->dnssec_allow_skew = 0;
    result->upstream_list = NULL;
    result->edns_maximum_udp_payload_size = 512;
    result->edns_extended_rcode = 0;
    result->edns_version = 0;
    result->edns_do_bit = 0;

    result->update_callback = NULL;
    result->memory_allocator = malloc;
    result->memory_deallocator = free;
    result->memory_reallocator = realloc;

    if (set_from_os) {
        if (GETDNS_RETURN_GOOD != set_os_defaults(result)) {
            getdns_context_destroy(result);
            return GETDNS_RETURN_GENERIC_ERROR;
        }
    }

    *context = result;

    return GETDNS_RETURN_GOOD;
} /* getdns_context_create */

/*
 * getdns_context_destroy
 *
 * call this to dispose of resources associated with a context once you
 * are done with it
 */
void
getdns_context_destroy(
	getdns_context_t       context
)
{
    if (context == NULL) {
        return;
    }
    if (context->namespaces) {
        context->memory_deallocator(context->namespaces);
    }
    getdns_list_destroy(context->dns_root_servers);
    getdns_list_destroy(context->suffix);
    getdns_list_destroy(context->dnssec_trust_anchors);
    getdns_list_destroy(context->upstream_list);
    
    free(context);
    return;
} /* getdns_context_destroy */

/*
 * getdns_context_set_context_update_callback
 *
 */
getdns_return_t
getdns_context_set_context_update_callback(
  getdns_context_t       context,
  void                   (*value)(getdns_context_t context, uint16_t changed_item)
)
{
    context->update_callback = value;
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_context_update_callback */

/*
 * getdns_context_set_context_update
 * 
 */
getdns_return_t
getdns_context_set_context_update(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_context_update */

/**
 * Helper to dispatch the updated callback
 */
static void dispatch_updated(getdns_context_t context,
                             uint16_t item) {
    if (context->update_callback) {
        context->update_callback(context, item);
    }
}

/*
 * getdns_context_set_resolution_type
 *
 */
getdns_return_t
getdns_context_set_resolution_type(
  getdns_context_t       context,
  uint16_t               value
)
{
    if (value != GETDNS_CONTEXT_STUB && 
        value != GETDNS_CONTEXT_RECURSING) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    
    context->resolution_type = value;
    
    dispatch_updated(context, GETDNS_CONTEXT_CODE_RESOLUTION_TYPE);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_resolution_type */

/*
 * getdns_context_set_namespaces
 *
 */
getdns_return_t
getdns_context_set_namespaces(
  getdns_context_t       context,
  size_t                 namespace_count,
  uint16_t               *namespaces
)
{
    size_t namespaces_size;
    if (namespace_count == 0 || namespaces == NULL) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    
    /** clean up old namespaces **/
    context->memory_deallocator(context->namespaces);
    
    /** duplicate **/
    namespaces_size = namespace_count * sizeof(uint16_t);
    context->namespaces = context->memory_allocator(namespaces_size);
    memcpy(context->namespaces, namespaces, namespaces_size);
    
    dispatch_updated(context, GETDNS_CONTEXT_CODE_NAMESPACES);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_namespaces */

/*
 * getdns_context_set_dns_transport
 *
 */
getdns_return_t
getdns_context_set_dns_transport(
  getdns_context_t       context,
  uint16_t               value
)
{
    if (value != GETDNS_CONTEXT_UDP_FIRST_AND_FALL_BACK_TO_TCP &&
        value != GETDNS_CONTEXT_UDP_ONLY &&
        value != GETDNS_CONTEXT_TCP_ONLY &&
        value != GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    
    context->dns_transport = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_TRANSPORT);

    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_dns_transport */

/*
 * getdns_context_set_limit_outstanding_queries
 *
 */
getdns_return_t
getdns_context_set_limit_outstanding_queries(
  getdns_context_t       context,
  uint16_t               limit
)
{
    context->limit_outstanding_queries = limit;
    
    dispatch_updated(context, GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_limit_outstanding_queries */

/*
 * getdns_context_set_timeout
 *
 */
getdns_return_t
getdns_context_set_timeout(
  getdns_context_t       context,
  uint16_t               timeout
)
{
    context->timeout = timeout;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_TIMEOUT);

    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_timeout */

/*
 * getdns_context_set_follow_redirects
 *
 */
getdns_return_t
getdns_context_set_follow_redirects(
  getdns_context_t       context,
  uint16_t               value
)
{
    context->follow_redirects = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_follow_redirects */

/*
 * getdns_context_set_dns_root_servers
 *
 */
getdns_return_t
getdns_context_set_dns_root_servers(
  getdns_context_t       context,
  struct getdns_list     *addresses
)
{
    getdns_list *copy = NULL;
    if (addresses != NULL) {
        if (getdns_list_copy(addresses, &copy) != GETDNS_RETURN_GOOD) {
            return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
        }
        addresses = copy;
    }
    getdns_list_destroy(context->dns_root_servers);
    context->dns_root_servers = addresses;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS);

    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_dns_root_servers */

/*
 * getdns_context_set_append_name
 *
 */
getdns_return_t
getdns_context_set_append_name(
  getdns_context_t       context,
  uint16_t               value
)
{
    if (value != GETDNS_CONTEXT_APPEND_NAME_ALWAYS &&
        value != GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE &&
        value != GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE &&
        value != GETDNS_CONTEXT_DO_NOT_APPEND_NAMES) {
    
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->append_name = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_APPEND_NAME);

    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_append_name */

/*
 * getdns_context_set_suffix
 *
 */
getdns_return_t
getdns_context_set_suffix(
  getdns_context_t       context,
  struct getdns_list     *value
)
{
    getdns_list *copy = NULL;
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
} /* getdns_context_set_suffix */

/*
 * getdns_context_set_dnssec_trust_anchors
 *
 */
getdns_return_t
getdns_context_set_dnssec_trust_anchors(
  getdns_context_t       context,
  struct getdns_list     *value
)
{
    getdns_list *copy = NULL;
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
} /* getdns_context_set_dnssec_trust_anchors */

/*
 * getdns_context_set_dnssec_allowed_skew
 *
 */
getdns_return_t
getdns_context_set_dnssec_allowed_skew(
  getdns_context_t       context,
  uint16_t               value
)
{
    context->dnssec_allow_skew = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_dnssec_allowed_skew */

/*
 * getdns_context_set_stub_resolution
 *
 */
getdns_return_t
getdns_context_set_stub_resolution(
  getdns_context_t       context,
  struct getdns_list     *upstream_list
)
{
    if (upstream_list == NULL) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    getdns_list *copy = NULL;
    if (getdns_list_copy(upstream_list, &copy) != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    upstream_list = copy;

    getdns_context_set_resolution_type(context, GETDNS_CONTEXT_STUB);
    
    getdns_list_destroy(context->upstream_list);
    context->upstream_list = upstream_list;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_stub_resolution */

/*
 * getdns_context_set_edns_maximum_udp_payload_size
 *
 */
getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(
  getdns_context_t       context,
  uint16_t               value
)
{
    /* check for < 512.  uint16_t won't let it go above max) */
    if (value < 512) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->edns_maximum_udp_payload_size = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_maximum_udp_payload_size */

/*
 * getdns_context_set_edns_extended_rcode
 *
 */
getdns_return_t
getdns_context_set_edns_extended_rcode(
  getdns_context_t       context,
  uint8_t                value
)
{
    context->edns_extended_rcode = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_extended_rcode */

/*
 * getdns_context_set_edns_version
 *
 */
getdns_return_t
getdns_context_set_edns_version(
  getdns_context_t       context,
  uint8_t                value
)
{
    context->edns_version = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_VERSION);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_version */

/*
 * getdns_context_set_edns_do_bit
 *
 */
getdns_return_t
getdns_context_set_edns_do_bit(
  getdns_context_t       context,
  uint8_t                value
)
{
    /* 0 or 1 */
    if (value > 1) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->edns_do_bit = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_DO_BIT);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_do_bit */

/*
 * getdns_context_set_memory_allocator
 *
 */
getdns_return_t
getdns_context_set_memory_allocator(
  getdns_context_t       context,
  void                   (*value)(size_t somesize)
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
} /* getdns_context_set_memory_allocator */

/*
 * getdns_context_set_memory_deallocator
 *
 */
getdns_return_t
getdns_context_set_memory_deallocator(
  getdns_context_t       context,
  void                   (*value)(void*)
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
} /* getdns_context_set_memory_deallocator */

/*
 * getdns_context_set_memory_reallocator
 *
 */
getdns_return_t
getdns_context_set_memory_reallocator(
  getdns_context_t       context,
  void                   (*value)(void*)
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
} /* getdns_context_set_memory_reallocator */

/*
 * getdns_extension_set_libevent_base
 *
 */
getdns_return_t
getdns_extension_set_libevent_base(
    getdns_context_t       context,
    struct event_base      *this_event_base
)
{
    /* TODO: cancel anything on an existing event base */
    context->event_base = this_event_base;

    return GETDNS_RETURN_GOOD;
} /* getdns_extension_set_libevent_base */

/*
 * getdns_cancel_callback
 *
 */
getdns_return_t
getdns_cancel_callback(
	getdns_context_t           context,
	getdns_transaction_t       transaction_id
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(transaction_id);
    return GETDNS_RETURN_GOOD;
} /* getdns_cancel_callback */

/* getdns_context.c */
