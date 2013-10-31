/**
 *
 * /brief getdns core functions
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

#include <getdns/getdns.h>
#include "context.h"
#include "general.h"
#include "util-internal.h"
#include <string.h>


/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/*
 * getdns_hostname
 *
 */
getdns_return_t
getdns_hostname(
  getdns_context_t           context,
  struct getdns_dict         *address,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
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
    if ((name = reverse_address((char *)address_data->data)) == 0)
        return GETDNS_RETURN_GENERIC_ERROR;
    return getdns_general(context, name, req_type, extensions,
                          userarg, transaction_id, callback);

    return GETDNS_RETURN_GOOD;
} /* getdns_hostname */

/* getdns_hostname.c */
