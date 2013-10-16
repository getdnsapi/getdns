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

struct getdns_dns_req;

/* convert an ip address dict to a sock storage */
getdns_return_t dict_to_sockaddr(getdns_dict* ns, struct sockaddr_storage* output);
getdns_return_t sockaddr_to_dict(struct sockaddr_storage* sockaddr, getdns_dict** output);

getdns_dict *create_getdns_response(struct getdns_dns_req* completed_request);

/* dict util */
/* set a string as bindata */
getdns_return_t getdns_dict_util_set_string(getdns_dict* dict, char* name,
                                            const char* value);

/* get a string from a dict.  result is valid as long as dict is valid */
getdns_return_t getdns_dict_util_get_string(getdns_dict* dict, char* name,
                                            char** result);
