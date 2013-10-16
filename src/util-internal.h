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

/*
#include "types-internal.h"
*/

#include <ldns/ldns.h>
#include "context.h"


/* convert an ip address dict to a sock storage */
getdns_return_t dict_to_sockaddr(getdns_dict* ns, struct sockaddr_storage* output);
getdns_return_t sockaddr_to_dict(struct sockaddr_storage* sockaddr, getdns_dict** output);

/* create a dns packet for the given request type and extensions */
ldns_pkt *create_new_pkt(getdns_context_t context,
                         const char* name,
                         uint16_t request_type,
                         struct getdns_dict* extensions);

getdns_dict *create_getdns_response(ldns_pkt* pkt);

/* dict util */
/* set a string as bindata */
getdns_return_t getdns_dict_util_set_string(getdns_dict* dict, char* name,
                                            const char* value);

/* get a string from a dict.  result is valid as long as dict is valid */
getdns_return_t getdns_dict_util_get_string(getdns_dict* dict, char* name,
                                            char** result);
