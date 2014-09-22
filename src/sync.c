/**
 *
 * /brief getdns core functions for synchronous use
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

#include <string.h>
#include <unbound.h>
#include "getdns/getdns.h"
#include "config.h"
#include "context.h"
#include "general.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"
#include "ub_timed_resolve.h"

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))
#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

static getdns_return_t submit_request_sync_rec(
    getdns_dns_req* req, uint64_t *timeout)
{
    struct ub_result* ub_res = NULL;
    getdns_return_t gr = GETDNS_RETURN_GOOD;
    getdns_network_req *netreq = req->first_req;

    while (netreq) {
        int r = ub_timed_resolve(req->context->unbound_ctx,
            req->name,
            netreq->request_type,
            netreq->request_class,
            &ub_res,
	    timeout);
        gr = getdns_apply_network_result(netreq, ub_res);
        ub_resolve_free(ub_res);
        ub_res = NULL;

        if (r != GETDNS_RETURN_GOOD)
            return r;
	else if (gr != GETDNS_RETURN_GOOD)
            return gr;

        netreq = netreq->next;
    }
    return gr;
}

static getdns_return_t submit_request_sync_stub(
    getdns_dns_req* req, uint64_t *timeout)
{
    ldns_rdf *qname;
    getdns_network_req *netreq = req->first_req;
    uint16_t qflags = 0;
	struct timeval tv;

    while (netreq) {
        qname = ldns_dname_new_frm_str(req->name);
        qflags = qflags | LDNS_RD;
        /* TODO: Use timeout properly - create a ldns_timed_resolve function */
        /* timeout is in miliseconds, so map to seconds and microseconds */
        tv.tv_sec  =  *timeout / 1000;
        tv.tv_usec = (*timeout % 1000) * 1000;
        ldns_resolver_set_timeout(req->context->ldns_res, tv);
        netreq->result = ldns_resolver_query(
                req->context->ldns_res, qname, netreq->request_type,
                netreq->request_class, qflags);
        ldns_rdf_deep_free(qname);
        qname = NULL;

        if (! netreq->result) {
            /* TODO: use better errors */
            return GETDNS_RETURN_GENERIC_ERROR;
        }

        netreq = netreq->next;
    }
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t submit_request_sync(
    getdns_dns_req* req, struct getdns_context *context)
{
    if (context->resolution_type == GETDNS_RESOLUTION_STUB) {
        return submit_request_sync_stub(req, &(context->timeout));
    } else {
        return submit_request_sync_rec(req, &(context->timeout));
    }
}

getdns_return_t
getdns_general_sync(struct getdns_context *context,
    const char *name,
    uint16_t request_type,
    struct getdns_dict *extensions,
    struct getdns_dict **response)
{
	getdns_dns_req *req;
	getdns_return_t response_status;
	uint64_t timeout;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
	RETURN_IF_NULL(response, GETDNS_RETURN_INVALID_PARAMETER);
	RETURN_IF_NULL(name, GETDNS_RETURN_INVALID_PARAMETER);

	timeout = context->timeout;
	response_status = validate_dname(name);
	if (response_status != GETDNS_RETURN_GOOD)
		return response_status;

	response_status = validate_extensions(extensions);
	if (response_status != GETDNS_RETURN_GOOD)
		return response_status;

       	/* general, so without dns lookup (no namespaces) */;
	response_status = getdns_context_prepare_for_resolution(context, 0);
	if (response_status != GETDNS_RETURN_GOOD)
		return response_status;

	/* for each netreq we call ub_ctx_resolve */
	    /* request state */
	req = dns_req_new(context, name, request_type, extensions);
	if (!req)
		return GETDNS_RETURN_MEMORY_ERROR;

	response_status = submit_request_sync(req, context);
	if (response_status == GETDNS_RETURN_GOOD) {
		if (is_extension_set(req->extensions,
		    "dnssec_return_validation_chain"))
			*response = priv_getdns_get_validation_chain_sync(req, &timeout);
		else
			*response = create_getdns_response(req);

	} else if (response_status == GETDNS_RESPSTATUS_ALL_TIMEOUT) {
		*response = create_getdns_response(req);
		response_status = GETDNS_RETURN_GOOD;
	}

	dns_req_free(req);
	return response_status;
}

getdns_return_t
getdns_address_sync(struct getdns_context *context,
    const char *name,
    struct getdns_dict * extensions,
    struct getdns_dict ** response)
{
	int cleanup_extensions = 0;
	if (!extensions) {
		extensions = getdns_dict_create_with_context(context);
		cleanup_extensions = 1;
	}
	getdns_dict_set_int(extensions,
	    GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6, GETDNS_EXTENSION_TRUE);

	getdns_return_t result =
	    getdns_general_sync(context, name, GETDNS_RRTYPE_A,
	    extensions, response);
	if (cleanup_extensions) {
		getdns_dict_destroy(extensions);
	}
	return result;
}

getdns_return_t
getdns_hostname_sync(struct getdns_context *context,
    struct getdns_dict * address,
    struct getdns_dict * extensions,
    struct getdns_dict ** response)
{
	struct getdns_bindata *address_data;
	struct getdns_bindata *address_type;
	uint16_t req_type;
	char *name;
	getdns_return_t retval;

	if ((retval =
		getdns_dict_get_bindata(address, "address_data",
		    &address_data)) != GETDNS_RETURN_GOOD)
		return retval;
	if ((retval =
		getdns_dict_get_bindata(address, "address_type",
		    &address_type)) != GETDNS_RETURN_GOOD)
		return retval;
	if ((strncmp(GETDNS_STR_IPV4, (char *) address_type->data,
		    ( strlen(GETDNS_STR_IPV4) < address_type->size
		    ? strlen(GETDNS_STR_IPV4) : address_type->size )) == 0
	        && address_data->size == 4)
	    || (strncmp(GETDNS_STR_IPV6, (char *) address_type->data,
		    ( strlen(GETDNS_STR_IPV6) < address_type->size
		    ? strlen(GETDNS_STR_IPV6) : address_type->size )) == 0
		&& address_data->size == 16))
		req_type = GETDNS_RRTYPE_PTR;
	else
		return GETDNS_RETURN_INVALID_PARAMETER;
	if ((name = reverse_address(address_data)) == NULL)
		return GETDNS_RETURN_INVALID_PARAMETER;
	retval = getdns_general_sync(context, name, req_type, extensions,
	    response);
	free(name);
	return retval;
}

getdns_return_t
getdns_service_sync(struct getdns_context *context,
    const char *name,
    struct getdns_dict * extensions,
    struct getdns_dict ** response)
{

	return getdns_general_sync(context, name, GETDNS_RRTYPE_SRV,
	    extensions, response);

}

void
getdns_free_sync_request_memory(struct getdns_dict *response)
{
	getdns_dict_destroy(response);
}

/* getdns_core_sync.c */
