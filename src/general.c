/**
 *
 * \file general.c
 * @brief getdns_general and related support functions
 *
 * The getdns_general function is called by most of the other public entry
 * points to the library.  Private support functions are also included in this
 * file where they are directly logically related to the getdns_general implementation.
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

#include <stdio.h>
#include <string.h>
#include "config.h"
#include "general.h"
#ifdef HAVE_LIBUNBOUND
#include <unbound.h>
#endif
#ifdef HAVE_UNBOUND_EVENT_API
#include "ub_loop.h"
#endif
#include "gldns/wire2str.h"
#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"
#include "stub.h"
#include "dict.h"

/* cancel, cleanup and send timeout to callback */
static void
ub_resolve_timeout(void *arg)
{
	getdns_dns_req *dns_req = (getdns_dns_req *) arg;
	(void) _getdns_context_request_timed_out(dns_req);
}

void _getdns_call_user_callback(getdns_dns_req *dns_req,
    struct getdns_dict *response)
{
	struct getdns_context *context = dns_req->context;
	getdns_transaction_t trans_id = dns_req->trans_id;
	getdns_callback_t cb = dns_req->user_callback;
	void *user_arg = dns_req->user_pointer;

	/* clean up */
	_getdns_context_clear_outbound_request(dns_req);
	_getdns_dns_req_free(dns_req);

	context->processing = 1;
	cb(context,
	    (response ? GETDNS_CALLBACK_COMPLETE : GETDNS_CALLBACK_ERROR),
	    response, user_arg, trans_id);
	context->processing = 0;
}

static int
no_answer(getdns_dns_req *dns_req)
{
	getdns_network_req **netreq_p, *netreq;

	for (netreq_p = dns_req->netreqs; (netreq = *netreq_p); netreq_p++) {
		_getdns_rrset_spc answer;

		if (netreq->response_len > 0 &&
		    GLDNS_ANCOUNT(netreq->response) > 0 &&
		    _getdns_rrset_answer(&answer, netreq->response
		                                , netreq->response_len))
			return 0;
	}
	return 1;
}

void
_getdns_check_dns_req_complete(getdns_dns_req *dns_req)
{
	getdns_network_req **netreq_p, *netreq;
	int results_found = 0, r;
	
	for (netreq_p = dns_req->netreqs; (netreq = *netreq_p); netreq_p++)
		if (!_getdns_netreq_finished(netreq))
			return;
		else if (netreq->response_len > 0)
			results_found = 1;

	/* Do we have to check more suffixes on nxdomain/nodata?
	 */
	if (dns_req->suffix_appended && /* Something was appended */
	    dns_req->suffix_len > 1 &&  /* Next suffix available */
	    no_answer(dns_req)) {
		/* Remove suffix from name */
		dns_req->name_len -= dns_req->suffix_len - 1;
		dns_req->name[dns_req->name_len - 1] = 0;
		do {
			dns_req->suffix += dns_req->suffix_len;
			dns_req->suffix_len = *dns_req->suffix++;
			if (dns_req->suffix_len + dns_req->name_len - 1 < 
			    sizeof(dns_req->name)) {
				memcpy(dns_req->name + dns_req->name_len - 1,
				    dns_req->suffix, dns_req->suffix_len);
				dns_req->name_len += dns_req->suffix_len - 1;
				dns_req->suffix_appended = 1;
				break;
			}
		} while (dns_req->suffix_len > 1 && *dns_req->suffix);
		if (dns_req->append_name == GETDNS_APPEND_NAME_ALWAYS ||
		    dns_req->append_name ==
		    GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST ||
		    (dns_req->suffix_len > 1 && *dns_req->suffix)) {
			for ( netreq_p = dns_req->netreqs
			    ; (netreq = *netreq_p)
			    ; netreq_p++ ) {
				_getdns_netreq_reinit(netreq);
				if ((r = _getdns_submit_netreq(netreq))) {
					if (r == DNS_REQ_FINISHED)
						return;
					netreq->state = NET_REQ_FINISHED;
				}
			}
			_getdns_check_dns_req_complete(dns_req);
			return;
		}
	} else if (
	    ( dns_req->append_name ==
	      GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE ||
	      dns_req->append_name ==
	      GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE
	    ) &&
	    !dns_req->suffix_appended &&
	    dns_req->suffix_len > 1 &&
	    no_answer(dns_req)) {
		/* Initial suffix append */
		for (
		    ; dns_req->suffix_len > 1 && *dns_req->suffix
		    ; dns_req->suffix += dns_req->suffix_len
		    , dns_req->suffix_len = *dns_req->suffix++) {

			if (dns_req->suffix_len + dns_req->name_len - 1 < 
			    sizeof(dns_req->name)) {
				memcpy(dns_req->name + dns_req->name_len - 1,
				    dns_req->suffix, dns_req->suffix_len);
				dns_req->name_len += dns_req->suffix_len - 1;
				dns_req->suffix_appended = 1;
				break;
			}
		}
		if (dns_req->suffix_appended) {
			for ( netreq_p = dns_req->netreqs
			    ; (netreq = *netreq_p)
			    ; netreq_p++ ) {
				_getdns_netreq_reinit(netreq);
				if ((r = _getdns_submit_netreq(netreq))) {
					if (r == DNS_REQ_FINISHED)
						return;
					netreq->state = NET_REQ_FINISHED;
				}
			}
			_getdns_check_dns_req_complete(dns_req);
			return;
		}
	}
	if (dns_req->internal_cb)
		dns_req->internal_cb(dns_req);
	else if (! results_found)
		_getdns_call_user_callback(dns_req, NULL);
	else if (dns_req->dnssec_return_validation_chain
#ifdef DNSSEC_ROADBLOCK_AVOIDANCE
	    || (   dns_req->dnssec_roadblock_avoidance 
	       && !dns_req->avoid_dnssec_roadblocks)
#endif

#ifdef STUB_NATIVE_DNSSEC
	    || (dns_req->context->resolution_type == GETDNS_RESOLUTION_STUB
	        && (dns_req->dnssec_return_status ||
	            dns_req->dnssec_return_only_secure ||
	            dns_req->dnssec_return_all_statuses
	           ))
#endif
	    )
		_getdns_get_validation_chain(dns_req);
	else
		_getdns_call_user_callback(
		    dns_req, _getdns_create_getdns_response(dns_req));
}

#ifdef HAVE_LIBUNBOUND
#ifdef HAVE_UNBOUND_EVENT_API
static void
ub_resolve_event_callback(void* arg, int rcode, void *pkt, int pkt_len,
    int sec, char* why_bogus)
{
	getdns_network_req *netreq = (getdns_network_req *) arg;
	getdns_dns_req *dns_req = netreq->owner;

	netreq->state = NET_REQ_FINISHED;
	/* parse */
	if (getdns_apply_network_result(
	    netreq, rcode, pkt, pkt_len, sec, why_bogus)) {
		_getdns_call_user_callback(dns_req, NULL);
		return;
	}
	_getdns_check_dns_req_complete(dns_req);

} /* ub_resolve_event_callback */
#endif

static void
ub_resolve_callback(void* arg, int err, struct ub_result* ub_res)
{
	getdns_network_req *netreq = (getdns_network_req *) arg;
	getdns_dns_req *dns_req = netreq->owner;

	netreq->state = NET_REQ_FINISHED;
	if (err != 0) {
		_getdns_call_user_callback(dns_req, NULL);
		return;
	}
	/* parse */
	if (getdns_apply_network_result(netreq, ub_res->rcode,
	    ub_res->answer_packet, ub_res->answer_len,
	    (ub_res->secure ? 2 : ub_res->bogus ? 1 : 0), ub_res->why_bogus)) {
		ub_resolve_free(ub_res);
		_getdns_call_user_callback(dns_req, NULL);
		return;
	}
	ub_resolve_free(ub_res);

	_getdns_check_dns_req_complete(dns_req);

} /* ub_resolve_callback */
#endif


int
_getdns_submit_netreq(getdns_network_req *netreq)
{
	getdns_return_t r;
	getdns_dns_req *dns_req = netreq->owner;
	char name[1024];
	int dnsreq_freed = 0;
#ifdef HAVE_LIBUNBOUND
	int ub_resolve_r;
#endif

#ifdef STUB_NATIVE_DNSSEC
# ifdef DNSSEC_ROADBLOCK_AVOIDANCE

	if ((dns_req->context->resolution_type == GETDNS_RESOLUTION_RECURSING
	    && !dns_req->dnssec_roadblock_avoidance)
	    ||  dns_req->avoid_dnssec_roadblocks) {
# else
	if ( dns_req->context->resolution_type == GETDNS_RESOLUTION_RECURSING) {
# endif
#else
	if ( dns_req->context->resolution_type == GETDNS_RESOLUTION_RECURSING
	    || dns_req->dnssec_return_status
	    || dns_req->dnssec_return_only_secure
	    || dns_req->dnssec_return_all_statuses
	    || dns_req->dnssec_return_validation_chain) {
#endif
		/* schedule the timeout */
		if (! dns_req->timeout.timeout_cb) {
			dns_req->timeout.userarg    = dns_req;
			dns_req->timeout.read_cb    = NULL;
			dns_req->timeout.write_cb   = NULL;
			dns_req->timeout.timeout_cb = ub_resolve_timeout;
			dns_req->timeout.ev         = NULL;
			if ((r = dns_req->loop->vmt->schedule(dns_req->loop, -1,
			    dns_req->context->timeout, &dns_req->timeout)))
				return r;
		}
		(void) gldns_wire2str_dname_buf(dns_req->name,
		    dns_req->name_len, name, sizeof(name));

#ifdef HAVE_LIBUNBOUND
		dns_req->freed = &dnsreq_freed;
#ifdef HAVE_UNBOUND_EVENT_API
		if (_getdns_ub_loop_enabled(&dns_req->context->ub_loop))
			ub_resolve_r = ub_resolve_event(dns_req->context->unbound_ctx,
			    name, netreq->request_type, netreq->owner->request_class,
			    netreq, ub_resolve_event_callback, &(netreq->unbound_id)) ?
			    GETDNS_RETURN_GENERIC_ERROR : GETDNS_RETURN_GOOD;
		else
#endif
			ub_resolve_r = ub_resolve_async(dns_req->context->unbound_ctx,
			    name, netreq->request_type, netreq->owner->request_class,
			    netreq, ub_resolve_callback, &(netreq->unbound_id)) ?
			    GETDNS_RETURN_GENERIC_ERROR : GETDNS_RETURN_GOOD;
		if (dnsreq_freed)
			return DNS_REQ_FINISHED;
		dns_req->freed = NULL;
		return ub_resolve_r ? GETDNS_RETURN_GENERIC_ERROR : GETDNS_RETURN_GOOD;
#else
		return GETDNS_RETURN_NOT_IMPLEMENTED;
#endif
	}
	/* Submit with stub resolver */
	dns_req->freed = &dnsreq_freed;
	r = _getdns_submit_stub_request(netreq);
	if (dnsreq_freed)
		return DNS_REQ_FINISHED;
	dns_req->freed = NULL;
	return r;
}


/**
 * structure used by validate_extensions() to check extension formats
 */
typedef struct getdns_extension_format
{
	char *extstring;
	getdns_data_type exttype;
	int implemented;
} getdns_extension_format;

static int
extformatcmp(const void *a, const void *b)
{
	return strcmp(((getdns_extension_format *) a)->extstring,
	    ((getdns_extension_format *) b)->extstring);
}

/*---------------------------------------- validate_extensions */
static getdns_return_t
validate_extensions(struct getdns_dict * extensions)
{
	/**
	  * this is a comprehensive list of extensions and their data types
	  * used by validate_extensions()
	  * The list has to be in sorted order for bsearch lookup in function
	  * validate_extensions.
	  */
	static getdns_extension_format extformats[] = {
		{"add_opt_parameters"            , t_dict, 1},
		{"add_warning_for_bad_dns"       , t_int , 1},
		{"dnssec_return_all_statuses"    , t_int , 1},
		{"dnssec_return_full_validation_chain", t_int , 1},
		{"dnssec_return_only_secure"     , t_int , 1},
		{"dnssec_return_status"          , t_int , 1},
		{"dnssec_return_validation_chain", t_int , 1},
		{"dnssec_roadblock_avoidance"    , t_int ,
#if defined(DNSSEC_ROADBLOCK_AVOIDANCE) && defined(HAVE_LIBUNBOUND)
							   1},
#else
							   0},
#endif
		{"edns_cookies"                  , t_int ,
#ifdef EDNS_COOKIES
							   1},
#else
							   0},
#endif
		{"header"                        , t_dict, 1},
		{"return_api_information"        , t_int , 1},
		{"return_both_v4_and_v6"         , t_int , 1},
		{"return_call_reporting"         , t_int , 1},
		{"specify_class"                 , t_int , 1},
	};

	struct getdns_dict_item *item;
	getdns_extension_format *extformat;

	if (extensions)
		RBTREE_FOR(item, struct getdns_dict_item *,
		    &(extensions->root)) {

			getdns_extension_format key;
			key.extstring = (char *) item->node.key;
			extformat = bsearch(&key, extformats,
			    sizeof(extformats) /
			    sizeof(getdns_extension_format),
			    sizeof(getdns_extension_format), extformatcmp);
			if (!extformat)
				return GETDNS_RETURN_NO_SUCH_EXTENSION;

			if (!extformat->implemented)
				return GETDNS_RETURN_NOT_IMPLEMENTED;

			if (item->i.dtype != extformat->exttype)
				return GETDNS_RETURN_EXTENSION_MISFORMAT;
		}
	return GETDNS_RETURN_GOOD;
}				/* _getdns_validate_extensions */


static getdns_return_t
getdns_general_ns(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_network_req **return_netreq_p,
    getdns_callback_t callbackfn, internal_cb_t internal_cb, int usenamespaces)
{
	int r = GETDNS_RETURN_GOOD;
	getdns_network_req *netreq, **netreq_p;
	getdns_dns_req *req;
	getdns_dict *localnames_response;
	size_t i;

	if (!context || !name || (!callbackfn && !internal_cb))
		return GETDNS_RETURN_INVALID_PARAMETER;
	
	if ((r = _getdns_validate_dname(name)))
		return r;

	if (extensions && (r = validate_extensions(extensions)))
		return r;

	/* Set up the context assuming we won't use the specified namespaces.
	   This is (currently) identical to setting up a pure DNS namespace */
	if ((r = _getdns_context_prepare_for_resolution(context, 0)))
		return r;

	/* create the request */
	if (!(req = _getdns_dns_req_new(
	    context, loop, name, request_type, extensions)))
		return GETDNS_RETURN_MEMORY_ERROR;

	req->user_pointer = userarg;
	req->user_callback = callbackfn;
	req->internal_cb = internal_cb;
	req->is_sync_request = loop == &context->sync_eventloop.loop;

	if (return_netreq_p)
		*return_netreq_p = req->netreqs[0];

	_getdns_context_track_outbound_request(req);

	if (!usenamespaces)
		/* issue all network requests */
		for ( netreq_p = req->netreqs
		    ; !r && (netreq = *netreq_p)
		    ; netreq_p++) {
			if ((r = _getdns_submit_netreq(netreq))) {
				if (r == DNS_REQ_FINISHED) {
					if (return_netreq_p)
						*return_netreq_p = NULL;
					return GETDNS_RETURN_GOOD;
				}
				netreq->state = NET_REQ_FINISHED;
			}
		}

	else for (i = 0; i < context->namespace_count; i++) {
		if (context->namespaces[i] == GETDNS_NAMESPACE_LOCALNAMES) {

			if (!(r = _getdns_context_local_namespace_resolve(
			    req, &localnames_response))) {

				_getdns_call_user_callback
				    ( req, localnames_response);
				break;
			}
		} else if (context->namespaces[i] == GETDNS_NAMESPACE_DNS) {

			/* TODO: We will get a good return code here even if
			   the name is not found (NXDOMAIN). We should consider
			   if this means we go onto the next namespace instead
			   of returning */
			r = GETDNS_RETURN_GOOD;
			for ( netreq_p = req->netreqs
			    ; !r && (netreq = *netreq_p)
			    ; netreq_p++) {
				if ((r = _getdns_submit_netreq(netreq))) {
					if (r == DNS_REQ_FINISHED) {
						if (return_netreq_p)
							*return_netreq_p = NULL;
						return GETDNS_RETURN_GOOD;
					}
					netreq->state = NET_REQ_FINISHED;
				}
			}
			break;
		} else
			r = GETDNS_RETURN_BAD_CONTEXT;
	}
	if (r > 0) { /* i.e. r != GETDNS_RETURN_GOOD && r != DNS_REQ_FINISHED */
		/* clean up the request */
		_getdns_context_clear_outbound_request(req);
		_getdns_dns_req_free(req);
		return r;
	}
	return GETDNS_RETURN_GOOD;
}				/* getdns_general_ns */

getdns_return_t
_getdns_general_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_network_req **netreq_p,
    getdns_callback_t callback, internal_cb_t internal_cb)
{
	return getdns_general_ns(context, loop,
	    name, request_type, extensions,
	    userarg, netreq_p, callback, internal_cb, 0);

}				/* getdns_general_loop */

getdns_return_t
_getdns_address_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	getdns_dict *my_extensions = extensions;
	getdns_return_t r;
	uint32_t value;
	getdns_network_req *netreq = NULL;

	if (!my_extensions) {
		if (!(my_extensions=getdns_dict_create_with_context(context)))
			return GETDNS_RETURN_MEMORY_ERROR;
	} else if (
	    getdns_dict_get_int(my_extensions, "return_both_v4_and_v6", &value)
	    && (r = _getdns_dict_copy(extensions, &my_extensions)))
		return r;

	if (my_extensions != extensions && (r = getdns_dict_set_int(
	    my_extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE)))
		return r;

	r = getdns_general_ns(context, loop,
	    name, GETDNS_RRTYPE_AAAA, my_extensions,
	    userarg, &netreq, callback, NULL, 1);
	if (netreq && transaction_id)
		*transaction_id = netreq->owner->trans_id;

	if (my_extensions != extensions)
		getdns_dict_destroy(my_extensions);

	return r;
} /* getdns_address_loop */

getdns_return_t
_getdns_hostname_loop(getdns_context *context, getdns_eventloop *loop,
    getdns_dict *address, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	struct getdns_bindata *address_data;
	struct getdns_bindata *address_type;
	uint16_t req_type;
	char name[1024];
	getdns_return_t retval;
	getdns_network_req *netreq= NULL;

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

	switch (address_data->size) {
	case 4:
		(void)snprintf(name, sizeof(name),
		    "%d.%d.%d.%d.in-addr.arpa.",
		    (int)((uint8_t *)address_data->data)[3],
		    (int)((uint8_t *)address_data->data)[2],
		    (int)((uint8_t *)address_data->data)[1],
		    (int)((uint8_t *)address_data->data)[0]);
		break;
	case 16:
		(void)snprintf(name, sizeof(name),
		    "%x.%x.%x.%x.%x.%x.%x.%x."
		    "%x.%x.%x.%x.%x.%x.%x.%x."
		    "%x.%x.%x.%x.%x.%x.%x.%x."
		    "%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa.",
		    (int)(((uint8_t *)address_data->data)[15] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[15] >> 4),
		    (int)(((uint8_t *)address_data->data)[14] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[14] >> 4),
		    (int)(((uint8_t *)address_data->data)[13] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[13] >> 4),
		    (int)(((uint8_t *)address_data->data)[12] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[12] >> 4),
		    (int)(((uint8_t *)address_data->data)[11] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[11] >> 4),
		    (int)(((uint8_t *)address_data->data)[10] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[10] >> 4),
		    (int)(((uint8_t *)address_data->data)[9] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[9] >> 4),
		    (int)(((uint8_t *)address_data->data)[8] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[8] >> 4),
		    (int)(((uint8_t *)address_data->data)[7] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[7] >> 4),
		    (int)(((uint8_t *)address_data->data)[6] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[6] >> 4),
		    (int)(((uint8_t *)address_data->data)[5] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[5] >> 4),
		    (int)(((uint8_t *)address_data->data)[4] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[4] >> 4),
		    (int)(((uint8_t *)address_data->data)[3] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[3] >> 4),
		    (int)(((uint8_t *)address_data->data)[2] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[2] >> 4),
		    (int)(((uint8_t *)address_data->data)[1] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[1] >> 4),
		    (int)(((uint8_t *)address_data->data)[0] & 0x0F),
		    (int)(((uint8_t *)address_data->data)[0] >> 4));
		break;
	default:
		return GETDNS_RETURN_INVALID_PARAMETER;
	}
	retval = _getdns_general_loop(context, loop, name, req_type,
	    extensions, userarg, &netreq, callback, NULL);
	if (netreq && transaction_id)
		*transaction_id = netreq->owner->trans_id;
	return retval;
}				/* getdns_hostname_loop */

getdns_return_t
_getdns_service_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callback)
{
	getdns_return_t r;
	getdns_network_req *netreq = NULL;
	r = getdns_general_ns(context, loop, name, GETDNS_RRTYPE_SRV,
	    extensions, userarg, &netreq, callback, NULL, 1);
	if (netreq && transaction_id)
		*transaction_id = netreq->owner->trans_id;
	return r;
}				/* getdns_service_loop */

/**
 * getdns_general
 */
getdns_return_t
getdns_general(getdns_context *context,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_transaction_t * transaction_id,
    getdns_callback_t callback)
{
	getdns_return_t r;
	getdns_network_req *netreq = NULL;

	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	r = _getdns_general_loop(context, context->extension,
	    name, request_type, extensions,
	    userarg, &netreq, callback, NULL);
	if (netreq && transaction_id)
		*transaction_id = netreq->owner->trans_id;
	return r;
}				/* getdns_general */

/*
 * getdns_address
 *
 */
getdns_return_t
getdns_address(getdns_context *context,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	return _getdns_address_loop(context, context->extension,
	    name, extensions, userarg,
	    transaction_id, callback);
} /* getdns_address */

/*
 * getdns_hostname
 *
 */
getdns_return_t
getdns_hostname(getdns_context *context,
    getdns_dict *address, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	return _getdns_hostname_loop(context, context->extension,
	    address, extensions, userarg, transaction_id, callback);
}				/* getdns_hostname */

/*
 * getdns_service
 *
 */
getdns_return_t
getdns_service(getdns_context *context,
    const char *name, getdns_dict *extensions, void *userarg,
    getdns_transaction_t *transaction_id, getdns_callback_t callback)
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	return _getdns_service_loop(context, context->extension,
	    name, extensions, userarg, transaction_id, callback);
}				/* getdns_service */

/* getdns_general.c */
