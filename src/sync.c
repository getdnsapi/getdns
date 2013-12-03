/**
 *
 * /brief getdns core functions for synchronous use
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
#ifdef HAVE_EVENT2_EVENT_H
#  include <event2/event.h>
#else
#  include <event.h>
#endif
#include <getdns/getdns.h>
#include <unbound-event.h>
#include "context.h"
#include "general.h"
#include "util-internal.h"
#include <string.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

static void
sync_callback_func(getdns_context_t context,
    uint16_t callback_type,
    struct getdns_dict *response,
    void *userarg, getdns_transaction_t transaction_id)
{

	*((getdns_dict **) userarg) = response;
}

getdns_return_t
getdns_general_sync(getdns_context_t context,
    const char *name,
    uint16_t request_type,
    struct getdns_dict *extensions,
    struct getdns_dict **response)
{
	getdns_return_t response_status;

	response_status = validate_extensions(extensions);
	if (response_status == GETDNS_RETURN_GOOD) {
		response_status = getdns_general_ub(context->unbound_sync,
		    context->event_base_sync,
		    context, name, request_type,
		    extensions, (void *) response, NULL, sync_callback_func);

		event_base_dispatch(context->event_base_sync);
	}
	return response_status;
}

getdns_return_t
getdns_address_sync(getdns_context_t context,
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
getdns_hostname_sync(getdns_context_t context,
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
		    strlen(GETDNS_STR_IPV4)) == 0)
	    || (strncmp(GETDNS_STR_IPV6, (char *) address_type->data,
		    strlen(GETDNS_STR_IPV6)) == 0))
		req_type = GETDNS_RRTYPE_PTR;
	else
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
	if ((name = reverse_address((char *) address_data)) == 0)
		return GETDNS_RETURN_GENERIC_ERROR;
	return getdns_general_sync(context, name, req_type, extensions,
	    response);
}

getdns_return_t
getdns_service_sync(getdns_context_t context,
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
