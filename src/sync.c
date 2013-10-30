/**
 *
 * /brief getdns core functions for synchronous use
 *
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

#include <getdns/getdns.h>
#include <event2/event.h>
#include <unbound-event.h>
#include "context.h"
#include "general.h"
#include <string.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

static void sync_callback_func(getdns_context_t context,
                               uint16_t callback_type,
                               struct getdns_dict *response,
                               void *userarg,
                               getdns_transaction_t transaction_id) {

    *((getdns_dict **)userarg) = response;
}

getdns_return_t
getdns_general_sync(
  getdns_context_t       context,
  const char             *name,
  uint16_t               request_type,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     **response
)
{
    getdns_return_t response_status;

    response_status = getdns_general_ub(context->unbound_sync, context->event_base_sync,
                                        context, name, request_type, extensions,
                                        (void *)response, NULL, sync_callback_func);

    event_base_dispatch(context->event_base_sync);

    return response_status;
}

getdns_return_t
getdns_address_sync(
  getdns_context_t       context,
  const char             *name,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     **response
)
{
    int cleanup_extensions = 0;
    if (!extensions) {
        extensions = getdns_dict_create();
        cleanup_extensions = 1;
    }
    getdns_dict_set_int(extensions,
                        GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6,
                        GETDNS_EXTENSION_TRUE);

    getdns_return_t result =
    getdns_general_sync(context, name, GETDNS_RRTYPE_A,
                        extensions, response_length, response);
    if (cleanup_extensions) {
        getdns_dict_destroy(extensions);
    }
    return result;
}

getdns_return_t
getdns_hostname_sync(
  getdns_context_t       context,
  struct getdns_dict     *address,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     **response
)
{
    struct getdns_bindata *address_data;
    struct getdns_bindata *address_type;
    uint16_t req_type;
    char *name;
    getdns_return_t retval;


    if ((retval = getdns_dict_get_bindata(address, "address_data", &address_data)) != GETDNS_RETURN_GOOD)
        return retval;
    if ((retval = getdns_dict_get_bindata(address, "address_type", &address_type)) != GETDNS_RETURN_GOOD)
        return retval;
    if ((strncmp(GETDNS_STR_IPV4, (char *)address_type->data, strlen(GETDNS_STR_IPV4)) == 0) ||
        (strncmp(GETDNS_STR_IPV6, (char *)address_type->data, strlen(GETDNS_STR_IPV6)) == 0))
        req_type = GETDNS_RRTYPE_PTR;
    else
        return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
    if ((name = reverse_address((char *)address_data)) == 0)
        return GETDNS_RETURN_GENERIC_ERROR;
    return getdns_general_sync(context, name, req_type, extensions,
                        response_length, response);
}


getdns_return_t
getdns_service_sync(
  getdns_context_t       context,
  const char             *name,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     **response
)
{

    return getdns_general_sync(context, name, GETDNS_RRTYPE_SRV, extensions,
                               response_length, response);

}

void
getdns_free_sync_request_memory(
  struct getdns_dict     *response
)
{ UNUSED_PARAM(response); }

/* getdns_core_sync.c */
