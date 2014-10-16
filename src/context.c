/**
 *
 * \file context.c
 * @brief getdns context management functions
 *
 * Declarations taken from the getdns API description pseudo implementation.
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

#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unbound.h>
#include <assert.h>
#include <netdb.h>

#include "config.h"
#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"

void *plain_mem_funcs_user_arg = MF_PLAIN;

struct host_name_addr_type {
    ldns_rdf * host_name;
    ldns_rr_type addr_type;
};

/* Private functions */
getdns_return_t create_default_namespaces(struct getdns_context *context);
getdns_return_t create_local_hosts(struct getdns_context *context);
getdns_return_t destroy_local_hosts(struct getdns_context *context);
static struct getdns_list *create_default_root_servers(void);
static getdns_return_t set_os_defaults(struct getdns_context *);
static int transaction_id_cmp(const void *, const void *);
static int local_host_cmp(const void *, const void *);
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

/* ldns helpers */
static getdns_return_t set_ldns_dns_transport(struct getdns_context* context, 
    getdns_transport_t value);
static void set_ldns_edns_maximum_udp_payload_size(struct getdns_context*,
    uint16_t);
static getdns_return_t set_ldns_nameservers(struct getdns_context*, 
	getdns_upstreams *upstreams);

/* Stuff to make it compile pedantically */
#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

static void destroy_local_host(ldns_rbnode_t * node, void *arg)
{
	struct getdns_context *context = (struct getdns_context *) arg;

	struct host_name_addr_type *lh = (struct host_name_addr_type *) node->key;
	ldns_rdf_free(lh->host_name);
	ldns_rr_list_deep_free((ldns_rr_list *)node->data);
	GETDNS_FREE(context->mf, node);
}

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
 * Helper to get contents from hosts file
 */
getdns_return_t
create_local_hosts(struct getdns_context *context)
{

    ldns_rr_list * host_names = ldns_get_rr_list_hosts_frm_file(NULL);
    if (host_names == NULL)
        return GETDNS_RETURN_GENERIC_ERROR;

    /* We have a 1:1 list of name -> ip address where there is an 
       underlying many to many relationship. Need to create a lookup of
       (unique name + A/AAAA)-> list of IPV4/IPv6 ip addresses*/
    for (int i = 0 ; i<ldns_rr_list_rr_count(host_names) ; i++) {

        ldns_rr *rr = ldns_rr_list_rr(host_names, i);
        ldns_rdf *owner = ldns_rdf_clone(ldns_rr_owner(rr));

        /*Check to see if we already have an entry*/
        struct host_name_addr_type *lh_key = 
             GETDNS_MALLOC(context->my_mf, struct host_name_addr_type);
        if (lh_key == NULL)
            return GETDNS_RETURN_MEMORY_ERROR;
        lh_key->host_name = owner;
        lh_key->addr_type = ldns_rr_get_type(rr);
        ldns_rbnode_t *result_node = ldns_rbtree_search(context->local_hosts, lh_key);
        if (result_node) {
            if (!ldns_rr_list_push_rr ((ldns_rr_list *)result_node->data, ldns_rr_clone(rr)))
                return GETDNS_RETURN_GENERIC_ERROR;
        }
        else {
            ldns_rr_list *address_list = ldns_rr_list_new ();
            if (!ldns_rr_list_push_rr (address_list, ldns_rr_clone(rr)))
                return GETDNS_RETURN_GENERIC_ERROR;

            ldns_rbnode_t *node = GETDNS_MALLOC(context->my_mf, ldns_rbnode_t);
            if (!node) {
                return GETDNS_RETURN_MEMORY_ERROR;
            }
            node->key = lh_key;
            node->data = address_list;
            if (!ldns_rbtree_insert(context->local_hosts, node)) {
                GETDNS_FREE(context->my_mf, node);
                return GETDNS_RETURN_GENERIC_ERROR;
            }
        }
    }

    ldns_rr_list_deep_free(host_names);
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

/**
 * check a file for changes since the last check
 * and refresh the current data if changes are detected
 * @param context pointer to a previously created context to be used for this call
 * @param fchg file to check
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

static getdns_upstreams *
upstreams_create(getdns_context *context, size_t size)
{
	getdns_upstreams *r = (void *) GETDNS_XMALLOC(context->mf, char,
	    sizeof(getdns_upstreams) +
	    sizeof(struct getdns_upstream) * size);
	r->mf = context->mf;
	r->referenced = 1;
	r->count = 0;
	return r;
}

static getdns_upstreams *
upstreams_resize(getdns_upstreams *upstreams, size_t size)
{
	getdns_upstreams *r = (void *) GETDNS_XREALLOC(
	    upstreams->mf, upstreams, char,
	    sizeof(getdns_upstreams) +
	    sizeof(struct getdns_upstream) * size);
	return r;
}

static void
upstreams_dereference(getdns_upstreams *upstreams)
{
	if (upstreams && --upstreams->referenced == 0)
		GETDNS_FREE(upstreams->mf, upstreams);
}

static size_t
upstream_addr_len(struct getdns_upstream *upstream)
{
	return upstream->addr.ss_family == AF_INET ? 4 : 16;
}

static uint8_t*
upstream_addr(struct getdns_upstream *upstream)
{
	return upstream->addr.ss_family == AF_INET
	    ? (void *)&((struct sockaddr_in*)&upstream->addr)->sin_addr
	    : (void *)&((struct sockaddr_in6*)&upstream->addr)->sin6_addr;
}

static in_port_t
upstream_port(struct getdns_upstream *upstream)
{
	return ntohs(upstream->addr.ss_family == AF_INET
	    ? ((struct sockaddr_in *)&upstream->addr)->sin_port
	    : ((struct sockaddr_in6*)&upstream->addr)->sin6_port);
}

static uint32_t *
upstream_scope_id(struct getdns_upstream *upstream)
{
	return upstream->addr.ss_family == AF_INET ? NULL
	    : (upstream_addr(upstream)[0] == 0xFE &&
	       (upstream_addr(upstream)[1] & 0xC0) == 0x80 ?
	       &((struct sockaddr_in6*)&upstream->addr)->sin6_scope_id : NULL);
}

static void
upstream_ntop_buf(struct getdns_upstream *upstream, char *buf, size_t len)
{
	/* Also possible but prints scope_id by name (nor parsed by unbound)
	 *
	 * getnameinfo((struct sockaddr *)&upstream->addr, upstream->addr_len,
	 *     buf, len, NULL, 0, NI_NUMERICHOST)
	 */
	(void) inet_ntop(upstream->addr.ss_family, upstream_addr(upstream),
	    buf, len);
	if (upstream_scope_id(upstream))
		(void) snprintf(buf + strlen(buf), len - strlen(buf),
		    "%%%d", (int)*upstream_scope_id(upstream));
	if (upstream_port(upstream) != 53 && upstream_port(upstream) != 0)
		(void) snprintf(buf + strlen(buf), len - strlen(buf),
		    "@%d", (int)upstream_port(upstream));
}

static getdns_dict *
upstream_dict(getdns_context *context, struct getdns_upstream *upstream)
{
	getdns_dict *r = getdns_dict_create_with_context(context);
	char addrstr[1024], *b;
	getdns_bindata bindata;

	getdns_dict_util_set_string(r, "address_type",
	    upstream->addr.ss_family == AF_INET ? "IPv4" : "IPv6");

	bindata.size = upstream_addr_len(upstream);
	bindata.data = upstream_addr(upstream);
	getdns_dict_set_bindata(r, "address_data", &bindata);

	if (upstream_port(upstream) != 53)
		getdns_dict_set_int(r, "port", upstream_port(upstream));

	(void) getnameinfo((struct sockaddr *)&upstream->addr,
	    upstream->addr_len, addrstr, 1024, NULL, 0, NI_NUMERICHOST);
	if ((b = strchr(addrstr, '%')))
		getdns_dict_util_set_string(r, "scope_id", b+1);

	return r;
}

static int
net_req_query_id_cmp(const void *id1, const void *id2)
{
	return (int)((struct getdns_network_req *)id1)->query_id -
	       (int)((struct getdns_network_req *)id1)->query_id;
}

static void
upstream_init(struct getdns_upstream *upstream, struct addrinfo *ai)
{
	assert(upstream && ai);
	upstream->addr_len = ai->ai_addrlen;
	(void) memcpy(&upstream->addr, ai->ai_addr, ai->ai_addrlen);
	upstream->to_retry =  2;
	upstream->tcp_fd   = -1;
	(void) memset(&upstream->tcp_event, 0, sizeof(upstream->tcp_event));
	getdns_rbtree_init(&upstream->netreq_by_query_id,
	    net_req_query_id_cmp);
}

/*---------------------------------------- set_os_defaults
  we use ldns to read the resolv.conf file - the ldns resolver is
  destroyed once the file is read
*/
static getdns_return_t
set_os_defaults(struct getdns_context *context)
{
	FILE *in;
	char line[1024], domain[1024];
	char *parse, *token, prev_ch;
	size_t upstreams_limit = 10, length;
	struct getdns_bindata bindata;
	struct addrinfo hints;
	struct addrinfo *result;
	struct getdns_upstream *upstream;
	int s;

	if(context->fchg_resolvconf == NULL) {
		context->fchg_resolvconf =
		    GETDNS_MALLOC(context->my_mf, struct filechg);
		if(context->fchg_resolvconf == NULL)
			return GETDNS_RETURN_MEMORY_ERROR;
		context->fchg_resolvconf->fn       = "/etc/resolv.conf";
		context->fchg_resolvconf->prevstat = NULL;
		context->fchg_resolvconf->changes  = GETDNS_FCHG_NOCHANGES;
		context->fchg_resolvconf->errors   = GETDNS_FCHG_NOERROR;
	}
	filechg_check(context, context->fchg_resolvconf);

	context->suffix = getdns_list_create_with_context(context);
	context->upstreams = upstreams_create(context, upstreams_limit);

	in = fopen(context->fchg_resolvconf->fn, "r");
	if (!in)
		return GETDNS_RETURN_GOOD;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
	hints.ai_socktype  = 0;              /* Datagram socket */
	hints.ai_flags     = AI_NUMERICHOST; /* No reverse name lookups */
	hints.ai_protocol  = 0;              /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr      = NULL;
	hints.ai_next      = NULL;

	*domain = 0;
	while (fgets(line, (int)sizeof(line), in)) {
		line[sizeof(line)-1] = 0;
		/* parse = line + strspn(line, " \t"); */ /* No leading whitespace */
		parse = line;

		if (strncmp(parse, "domain", 6) == 0) {
			parse += 6;
			parse += strspn(parse, " \t");
			if (*parse == 0 || *parse == '#') continue;
			token = parse + strcspn(parse, " \t\r\n");
			*token = 0;

			(void) strcpy(domain, parse);

		} else if (strncmp(parse, "search", 6) == 0) {
			parse += 6;
			do {
				parse += strspn(parse, " \t");
				if (*parse == '#' || *parse == '\n') break;
				token = parse + strcspn(parse, " \t\r\n");
				prev_ch = *token;
				*token = 0;

				bindata.data = (uint8_t *)parse;
				bindata.size = strlen(parse) + 1;
				(void) getdns_list_get_length(
				    context->suffix, &length);
				(void) getdns_list_set_bindata(
				    context->suffix, length, &bindata);

				*token = prev_ch;
				parse = token;
			} while (*parse);

		} else if (strncmp(parse, "nameserver", 10) != 0)
			continue;

		parse += 10;
		parse += strspn(parse, " \t");
		if (*parse == 0 || *parse == '#') continue;
		token = parse + strcspn(parse, " \t\r\n");
		*token = 0;

		if ((s = getaddrinfo(parse, "53", &hints, &result)))
			continue;

		/* No lookups, so maximal 1 result */
		if (! result) continue;

		/* Grow array when needed */
		if (context->upstreams->count == upstreams_limit)
			context->upstreams = upstreams_resize(
			    context->upstreams, (upstreams_limit *= 2));

		upstream =   &context->upstreams->
		    upstreams[context->upstreams->count++];
		upstream_init(upstream, result);
		freeaddrinfo(result);
	}
	fclose(in);

	(void) getdns_list_get_length(context->suffix, &length);
	if (length == 0 && *domain != 0) {
		bindata.data = (uint8_t *)domain;
		bindata.size = strlen(domain) + 1;
		(void) getdns_list_set_bindata(context->suffix, 0, &bindata);
	}
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
local_host_cmp(const void *id1, const void *id2)
{
    if (id1 == NULL && id2 == NULL) {
        return 0;
    } else if (id1 == NULL && id2 != NULL) {
        return 1;
    } else if (id1 != NULL && id2 == NULL) {
        return -1;
    } else {
        const struct host_name_addr_type *hn1 = (const struct host_name_addr_type*) id1;
        const struct host_name_addr_type *hn2 = (const struct host_name_addr_type*) id2;
        if ((ldns_rr_type) hn1->addr_type < (ldns_rr_type) hn2->addr_type)
            return -1;
        if ((ldns_rr_type) hn1->addr_type > (ldns_rr_type) hn2->addr_type)
            return 1;
        return (ldns_rdf_compare((const ldns_rdf *) hn1->host_name,
                                 (const ldns_rdf *) hn2->host_name));
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
	getdns_return_t r;
	struct getdns_context *result = NULL;
	mf_union mf;

	if (!context || !malloc || !realloc || !free)
		return GETDNS_RETURN_INVALID_PARAMETER;

	/** default init **/
	mf.ext.malloc = malloc;
	result = userarg == MF_PLAIN
	    ? (*mf.pln.malloc)(         sizeof(struct getdns_context))
	    : (*mf.ext.malloc)(userarg, sizeof(struct getdns_context));

	if (!result)
		return GETDNS_RETURN_MEMORY_ERROR;

	result->processing = 0;
	result->destroying = 0;
	result->my_mf.mf_arg         = userarg;
	result->my_mf.mf.ext.malloc  = malloc;
	result->my_mf.mf.ext.realloc = realloc;
	result->my_mf.mf.ext.free    = free;

	result->update_callback = NULL;

	result->mf.mf_arg         = userarg;
	result->mf.mf.ext.malloc  = malloc;
	result->mf.mf.ext.realloc = realloc;
	result->mf.mf.ext.free    = free;

	result->resolution_type_set = 0;

	result->outbound_requests = create_ldns_rbtree(result, transaction_id_cmp);
	result->local_hosts = create_ldns_rbtree(result, local_host_cmp);

	if (!result->outbound_requests || !result->local_hosts) {
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto error;
	}

	result->resolution_type = GETDNS_RESOLUTION_RECURSING;
	if ((r = create_default_namespaces(result)))
		goto error;

	result->timeout = 5000;
	result->follow_redirects = GETDNS_REDIRECTS_FOLLOW;
	result->dns_root_servers = create_default_root_servers();
	result->append_name = GETDNS_APPEND_NAME_ALWAYS;
	result->suffix = NULL;

	result->dnssec_trust_anchors = NULL;
	result->upstreams = NULL;

	result->edns_extended_rcode = 0;
	result->edns_version = 0;
	result->edns_do_bit = 1;

	result->extension = &result->mini_event.loop;
	if ((r = getdns_mini_event_init(result, &result->mini_event)))
		goto error;

	result->fchg_resolvconf = NULL;
	result->fchg_hosts	  = NULL;

	if (set_from_os && (r = set_os_defaults(result)))
		goto error;

	result->dnssec_allowed_skew = 0;
	result->edns_maximum_udp_payload_size = 1232;
	result->dns_transport = GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP;
	result->limit_outstanding_queries = 0;
	result->has_ta = priv_getdns_parse_ta_file(NULL, NULL);
	result->return_dnssec_status = GETDNS_EXTENSION_FALSE;

	/* unbound context is initialized here */
	result->unbound_ctx = NULL;
	if ((r = rebuild_ub_ctx(result)))
		goto error;

	/* ldns context is initialised to NULL here and rebuilt later if needed */
	result->ldns_res = NULL;

	if ((r = create_local_hosts(result)))
		goto error;

	*context = result;
	return GETDNS_RETURN_GOOD;
error:
	getdns_context_destroy(result);
	return r;
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
    // If being destroyed during getdns callback,
    // fail via assert
    assert(context->processing == 0);
    if (context->destroying) {
        return ;
    }
    context->destroying = 1;
    cancel_outstanding_requests(context, 1);
    getdns_context_detach_eventloop(context);

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

    /* destroy the contexts */
    if (context->unbound_ctx)
        ub_ctx_delete(context->unbound_ctx);
    if (context->ldns_res)
        ldns_resolver_deep_free(context->ldns_res);

    if (context->outbound_requests)
        GETDNS_FREE(context->my_mf, context->outbound_requests);
    if (context->local_hosts) {
        ldns_traverse_postorder(context->local_hosts,
            destroy_local_host, context);
        GETDNS_FREE(context->my_mf, context->local_hosts);
    }

	upstreams_dereference(context->upstreams);

    GETDNS_FREE(context->my_mf, context);
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

static void
getdns_context_request_count_changed(getdns_context *context)
{
	DEBUG_SCHED("getdns_context_request_count_changed(%d)\n",
	    (int) context->outbound_requests->count);
	if (context->outbound_requests->count) {
		if (context->ub_event.ev) return;

		DEBUG_SCHED("gc_request_count_changed "
		    "-> ub schedule(el_ev = %p, el_ev->ev = %p)\n",
		    &context->ub_event, context->ub_event.ev);
		context->extension->vmt->schedule(
		    context->extension, ub_fd(context->unbound_ctx),
		    TIMEOUT_FOREVER, &context->ub_event);
	}
	else if (context->ub_event.ev) /* Only test if count == 0! */ {
		DEBUG_SCHED("gc_request_count_changed "
		    "-> ub clear(el_ev = %p, el_ev->ev = %p)\n",
		    &context->ub_event, context->ub_event.ev);

		context->extension->vmt->clear(
		    context->extension, &context->ub_event);
	}
}

void
priv_getdns_context_ub_read_cb(void *userarg)
{
	getdns_context *context = (getdns_context *)userarg;

	/* getdns_context_process_async, but without reinvoking an eventloop
	 * (with context->extension->vmt->run*), because we are already
	 * called from a running eventloop.
	 */
	context->processing = 1;
	if (ub_poll(context->unbound_ctx))
		(void) ub_process(context->unbound_ctx);
	context->processing = 0;

	/* No need to handle timeouts. They are handled by the extension. */

	getdns_context_request_count_changed(context);
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

	context->ub_event.userarg    = context;
	context->ub_event.read_cb    = priv_getdns_context_ub_read_cb;
	context->ub_event.write_cb   = NULL;
	context->ub_event.timeout_cb = NULL;
	context->ub_event.ev         = NULL;

	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
rebuild_ldns_res(struct getdns_context* context) {
    getdns_return_t result;
    if (context->ldns_res != NULL) {
        /* cancel all requests and delete */
        cancel_outstanding_requests(context, 1);
        ldns_resolver_deep_free(context->ldns_res);
        context->ldns_res=NULL;
    }
    /*Create LDNS resolver object. */
    context->ldns_res = ldns_resolver_new();
    if (context->ldns_res == NULL) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }

    /* TODO: ldns doesn't support this option so this will have to be taken
             account expliticly during the ldns validation
     *  set_ldns_dnssec_allowed_skew();*/

    /* This is all the settings required for stub operation in sync mode.
     * Will need additional work here when supporting async mode.*/
    set_ldns_edns_maximum_udp_payload_size(context,
        context->edns_maximum_udp_payload_size);
    result = set_ldns_dns_transport(context, context->dns_transport);
    if (result != GETDNS_RETURN_GOOD)
        return result;

    /* We need to set up the upstream recursive servers from the context */
    result = set_ldns_nameservers(context, context->upstreams);
    if (result != GETDNS_RETURN_GOOD)
        return result;

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
            set_ub_string_opt(context, "do-udp:", "yes");
            set_ub_string_opt(context, "do-tcp:", "yes");
            break;
        case GETDNS_TRANSPORT_UDP_ONLY:
            set_ub_string_opt(context, "do-udp:", "yes");
            set_ub_string_opt(context, "do-tcp:", "no");
            break;
        case GETDNS_TRANSPORT_TCP_ONLY:
            set_ub_string_opt(context, "do-udp:", "no");
            set_ub_string_opt(context, "do-tcp:", "yes");
            break;
        default:
            /* TODO GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN */
            return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
        }
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
set_ldns_dns_transport(struct getdns_context* context,
    getdns_transport_t value) {
    switch (value) {
        case GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP:
            /* ldns has fallback configured by default */
            ldns_resolver_set_usevc(context->ldns_res, 0);
            break;
        case GETDNS_TRANSPORT_UDP_ONLY:
            ldns_resolver_set_usevc(context->ldns_res, 0);
            ldns_resolver_set_fallback(context->ldns_res, false);
            break;
        case GETDNS_TRANSPORT_TCP_ONLY:
            ldns_resolver_set_usevc(context->ldns_res, 1);
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
    set_ub_number_opt(context, "num-queries-per-thread:", value);
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
    set_ub_number_opt(context, "val-sig-skew-min:", value);
    set_ub_number_opt(context, "val-sig-skew-max:", value);
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
    struct getdns_list *upstream_list)
{
	getdns_return_t r;
	size_t count = 0;
	size_t i;
	getdns_upstreams *upstreams;
	char addrstr[1024], portstr[1024], *eos;
	struct addrinfo hints;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
	RETURN_IF_NULL(upstream_list, GETDNS_RETURN_INVALID_PARAMETER);
	
	r = getdns_list_get_length(upstream_list, &count);
	if (count == 0 || r != GETDNS_RETURN_GOOD) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	if (context->resolution_type_set != 0) {
		/* already setup */
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
	hints.ai_socktype  = 0;              /* Datagram socket */
	hints.ai_flags     = AI_NUMERICHOST; /* No reverse name lookups */
	hints.ai_protocol  = 0;              /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr      = NULL;
	hints.ai_next      = NULL;

	upstreams = upstreams_create(context, count);
	for (i = 0; i < count; i++) {
		getdns_dict *dict;
		getdns_bindata *address_type;
		getdns_bindata *address_data;
		uint32_t port;
		getdns_bindata *scope_id;
		struct addrinfo *ai;
		struct getdns_upstream *upstream;

		upstream = &upstreams->upstreams[upstreams->count];
		if ((r = getdns_list_get_dict(upstream_list, i, &dict)))
			goto error;

		if ((r = getdns_dict_get_bindata(
		    dict, "address_type",&address_type)))
			goto error;
		if (address_type->size < 4)
			goto invalid_parameter;
		if (strncmp((char *)address_type->data, "IPv4", 4) == 0)
			upstream->addr.ss_family = AF_INET;
		else if (strncmp((char *)address_type->data, "IPv6", 4) == 0)
			upstream->addr.ss_family = AF_INET6;
		else	goto invalid_parameter;

		if ((r = getdns_dict_get_bindata(
		    dict, "address_data", &address_data)))
			goto error;
		if ((upstream->addr.ss_family == AF_INET &&
		     address_data->size != 4) ||
		    (upstream->addr.ss_family == AF_INET6 &&
		     address_data->size != 16))
			goto invalid_parameter;
		if (inet_ntop(upstream->addr.ss_family, address_data->data,
		    addrstr, 1024) == NULL)
			goto invalid_parameter;
		
		port = 53;
		(void) getdns_dict_get_int(dict, "port", &port);
		(void) snprintf(portstr, 1024, "%d", (int)port);
		
		if (getdns_dict_get_bindata(dict, "scope_id", &scope_id) ==
		    GETDNS_RETURN_GOOD) {
			if (strlen(addrstr) + scope_id->size > 1022)
				goto invalid_parameter;
			eos = &addrstr[strlen(addrstr)];
			*eos++ = '%';
			(void) memcpy(eos, scope_id->data, scope_id->size);
			eos[scope_id->size] = 0;
		}

		if (getaddrinfo(addrstr, portstr, &hints, &ai))
			goto invalid_parameter;

		upstream_init(upstream, ai);
		upstreams->count++;
		freeaddrinfo(ai);
	}
	upstreams_dereference(context->upstreams);
	context->upstreams = upstreams;
	dispatch_updated(context,
		GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS);

	return GETDNS_RETURN_GOOD;

invalid_parameter:
	r = GETDNS_RETURN_INVALID_PARAMETER;
error:
	upstreams_dereference(upstreams);
	return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
} /* getdns_context_set_upstream_recursive_servers */


static void
set_ub_edns_maximum_udp_payload_size(struct getdns_context* context,
    uint16_t value) {
    /* edns-buffer-size */
    set_ub_number_opt(context, "edns-buffer-size:", value);
}

static void
set_ldns_edns_maximum_udp_payload_size(struct getdns_context* context,
    uint16_t value) {
    /* max-udp-size */
    ldns_resolver_set_edns_udp_size(context->ldns_res, value);
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
		if (netreq->unbound_id != -1) {
			ub_cancel(req->context->unbound_ctx,
			    netreq->unbound_id);
			netreq->unbound_id = -1;
		} else if (netreq->event.ev) {
			req->loop->vmt->clear(req->loop, &netreq->event);
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
getdns_cancel_callback(getdns_context *context,
    getdns_transaction_t transaction_id)
{
	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	context->processing = 1;
	getdns_return_t r = getdns_context_cancel_request(context, transaction_id, 1);
	context->processing = 0;
	getdns_context_request_count_changed(context);
	return r;
} /* getdns_cancel_callback */

static getdns_return_t
ub_setup_stub(struct ub_ctx *ctx, getdns_upstreams *upstreams)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	size_t i;
	struct getdns_upstream *upstream;
	char addr[1024];

	(void) ub_ctx_set_fwd(ctx, NULL);
	for (i = 0; i < upstreams->count; i++) {
		upstream = &upstreams->upstreams[i];
		upstream_ntop_buf(upstream, addr, 1024);
		ub_ctx_set_fwd(ctx, addr);
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
set_ldns_nameservers(struct getdns_context *context,
                     getdns_upstreams *upstreams)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	size_t i;
	struct getdns_upstream *upstream;
	ldns_rdf *pop, *ns_rdf;
	uint16_t port = 53;

	if (context->ldns_res == NULL)
		return GETDNS_RETURN_BAD_CONTEXT;

	/* remove current list of nameservers from resolver */
	while((pop = ldns_resolver_pop_nameserver(context->ldns_res))) { 
		ldns_rdf_deep_free(pop); 
	}

	for (i = 0; i < upstreams->count; i++) {
		upstream = &upstreams->upstreams[i];

		/* TODO: PROBLEM! The upstream list is implemented such that there is both
		 * an IP address and a port in the bindata for each nameserver. Unbound
		 * can handle this but ldns cannot. ldns has a list of nameservers which
		 * must be A or AAAA records and it has one port setting on the resolver.
		 * TEMP SOLUTION: strip off any port and use the port of the last 
		 * nameserver in the list. Wrong, but this will support the test scripts
		 * in the short term which rely on being able to set a port for a single
		 * nameserver. */

		ns_rdf = ldns_sockaddr_storage2rdf(&upstream->addr, &port);
		if (ns_rdf == NULL)
			return GETDNS_RETURN_GENERIC_ERROR;

		ldns_resolver_push_nameserver(context->ldns_res, ns_rdf);
		ldns_rdf_deep_free(ns_rdf);
	}
	ldns_resolver_set_port(context->ldns_res, port);
	return r;
}

static getdns_return_t
priv_getdns_ns_dns_setup(struct getdns_context *context)
{
	assert(context);
	getdns_return_t r;

	switch (context->resolution_type) {
	case GETDNS_RESOLUTION_STUB: 
		/* Since we don't know if the resolution will be sync or async at this
		 * point and we only support ldns in sync mode then we must set _both_
		 * contexts up */
		/* We get away with just setting up ldns here here because sync mode
		 * always hits this method because at the moment all sync calls use DNS
		 * namespace */
		r = ub_setup_stub(context->unbound_ctx, context->upstreams);
		if (r != GETDNS_RETURN_GOOD)
			return r;
		return rebuild_ldns_res(context);

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
			/* TODO: Note to self! This must change once we have
			 * proper namespace hanlding or asynch stub mode using ldns.*/
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
	ldns_rbnode_t *node;

    	if (!req)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(node = GETDNS_MALLOC(req->context->my_mf, ldns_rbnode_t)))
		return GETDNS_RETURN_MEMORY_ERROR;

	node->key  = &(req->trans_id);
	node->data = req;
	if (! ldns_rbtree_insert(req->context->outbound_requests, node)) {
		GETDNS_FREE(req->context->my_mf, node);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	getdns_context_request_count_changed(req->context);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_clear_outbound_request(getdns_dns_req * req)
{
	ldns_rbnode_t *node;

    	if (!req)
		return GETDNS_RETURN_INVALID_PARAMETER;

	node = ldns_rbtree_delete(
	    req->context->outbound_requests, &req->trans_id);
	if (!node)
		return GETDNS_RETURN_GENERIC_ERROR;

	GETDNS_FREE(req->context->my_mf, node);
	getdns_context_request_count_changed(req->context);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_request_timed_out(struct getdns_dns_req *req)
{
    /* Don't use req after callback */
    getdns_context* context = req->context;
    getdns_transaction_t trans_id = req->trans_id;
    getdns_callback_t cb = req->user_callback;
    void *user_arg = req->user_pointer;
    getdns_dict *response = create_getdns_response(req);

    /* cancel the req - also clears it from outbound and cleans up*/
    getdns_context_cancel_request(context, trans_id, 0);
    context->processing = 1;
    cb(context, GETDNS_CALLBACK_TIMEOUT, response, user_arg, trans_id);
    context->processing = 0;
	getdns_context_request_count_changed(context);
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

/* TODO: Remove next_timeout argument from getdns_context_get_num_pending_requests
 */
void getdns_handle_timeouts(struct getdns_event_base* base, struct timeval* now,
    struct timeval* wait);
uint32_t
getdns_context_get_num_pending_requests(struct getdns_context* context,
    struct timeval* next_timeout)
{
	struct timeval dispose;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

	if (context->outbound_requests->count)
		context->extension->vmt->run_once(context->extension, 0);

	/* TODO: Remove this when next_timeout is gone */
	getdns_handle_timeouts(context->mini_event.base,
	    &context->mini_event.time_tv, next_timeout ? next_timeout : &dispose);

	return context->outbound_requests->count;
}

/* process async reqs */
getdns_return_t
getdns_context_process_async(struct getdns_context* context)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

	context->processing = 1;
	if (ub_poll(context->unbound_ctx) && ub_process(context->unbound_ctx)){
		/* need an async return code? */
		context->processing = 0;
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	context->processing = 0;
	context->extension->vmt->run_once(context->extension, 0);

	return GETDNS_RETURN_GOOD;
}

void
getdns_context_run(getdns_context *context)
{
	if (getdns_context_get_num_pending_requests(context, NULL) > 0 &&
	    !getdns_context_process_async(context))
		context->extension->vmt->run(context->extension);
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
getdns_context_detach_eventloop(struct getdns_context* context)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

	/* When called from within a callback, do not execute pending
	 * context destroys.
	 * The (other) callback handler will handle it.
	 *
	 * ( because callbacks occur in cancel_outstanding_requests,
	 *   and they may destroy the context )
	 */
	context->processing = 1;
	/* cancel all outstanding requests */
	cancel_outstanding_requests(context, 1);
	context->processing = 0;
	context->extension->vmt->cleanup(context->extension);
	context->extension = &context->mini_event.loop;
	return getdns_mini_event_init(context, &context->mini_event);
}

getdns_return_t
getdns_context_set_eventloop(struct getdns_context* context, getdns_eventloop* loop)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
	RETURN_IF_NULL(loop   , GETDNS_RETURN_INVALID_PARAMETER);

	getdns_return_t r = getdns_context_detach_eventloop(context);
	if (r != GETDNS_RETURN_GOOD)
		return r;

	context->extension = loop;
	return GETDNS_RETURN_GOOD;
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
	if (context->upstreams->count > 0) {
		size_t i;
		struct getdns_upstream *upstream;
		getdns_list *upstreams =
		    getdns_list_create_with_context(context);

		for (i = 0; i < context->upstreams->count; i++) {
			getdns_dict *d;
			upstream = &context->upstreams->upstreams[i];
			d = upstream_dict(context, upstream);
			r |= getdns_list_set_dict(upstreams, i, d);
			getdns_dict_destroy(d);
		}
		r |= getdns_dict_set_list(result, "upstream_recursive_servers",
		    upstreams);
		getdns_list_destroy(upstreams);
	}
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
    r |= getdns_dict_set_int(result, "resolution_type", context->resolution_type);
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
    if (enabled != GETDNS_EXTENSION_TRUE &&
        enabled != GETDNS_EXTENSION_FALSE) {
        return GETDNS_RETURN_INVALID_PARAMETER;
    }
    context->return_dnssec_status = enabled;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_set_use_threads(getdns_context* context, int use_threads) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (context->resolution_type_set != 0) {
        /* already setup */
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    int r = 0;
    if (use_threads)
        r = ub_ctx_async(context->unbound_ctx, 1);
    else
        r = ub_ctx_async(context->unbound_ctx, 0);
    return r == 0 ? GETDNS_RETURN_GOOD : GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
}

getdns_return_t 
getdns_context_local_namespace_resolve(getdns_dns_req* req,
                                       struct getdns_dict **response, 
                                       struct getdns_context *context)
{

    ldns_rr_list *result_list = NULL;
    struct host_name_addr_type *lh_key = 
         GETDNS_MALLOC(context->my_mf, struct host_name_addr_type);
    if (lh_key == NULL)
        return GETDNS_RETURN_MEMORY_ERROR;

    getdns_network_req *netreq = req->first_req;
    while (netreq) {
        if (netreq->request_type != GETDNS_RRTYPE_A && 
            netreq->request_type != GETDNS_RRTYPE_AAAA) {
            netreq = netreq->next;
            continue;
        }

        /*Do the lookup*/
        ldns_rdf *query_name = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, req->name);
        if (!query_name) {
            GETDNS_FREE(context->my_mf, lh_key);
            return GETDNS_RETURN_GENERIC_ERROR;
        }
        lh_key->host_name = query_name;
        lh_key->addr_type = netreq->request_type;
        ldns_rbnode_t *result_node = ldns_rbtree_search(context->local_hosts, lh_key);
        if (result_node) {
            if (result_list == NULL)
                result_list =
                          ldns_rr_list_clone((ldns_rr_list *)result_node->data);
            else {
                if (!ldns_rr_list_cat(result_list, (ldns_rr_list *)result_node->data)) {
                    GETDNS_FREE(context->my_mf, lh_key);
                    ldns_rdf_deep_free(query_name);
                    return GETDNS_RETURN_GENERIC_ERROR;
                }
            }
        }

        ldns_rdf_deep_free(query_name);
        netreq = netreq->next;
    }

    GETDNS_FREE(context->my_mf, lh_key);
    if (result_list == NULL) 
        return GETDNS_RETURN_GENERIC_ERROR;
        
    *response = create_getdns_response_from_rr_list(req, result_list);
    return response ? GETDNS_RETURN_GOOD : GETDNS_RETURN_GENERIC_ERROR;

}

struct mem_funcs *
priv_getdns_context_mf(getdns_context *context)
{
	return &context->mf;
}

/* context.c */
