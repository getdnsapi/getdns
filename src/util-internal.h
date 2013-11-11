/**
 *
 * /brief getdns contect management functions
 *
 * This is the meat of the API
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

/*
#include "types-internal.h"
*/

#include <ldns/ldns.h>
#include "context.h"

struct getdns_dns_req;

/* convert an ip address dict to a sock storage */
getdns_return_t dict_to_sockaddr(getdns_dict * ns,
    struct sockaddr_storage *output);
getdns_return_t sockaddr_to_dict(getdns_context_t context,
    struct sockaddr_storage *sockaddr, getdns_dict ** output);

getdns_dict *create_getdns_response(struct getdns_dns_req *completed_request);

/* dict util */
/* set a string as bindata */
getdns_return_t getdns_dict_util_set_string(getdns_dict * dict, char *name,
    const char *value);

/* get a string from a dict.  result is valid as long as dict is valid */
getdns_return_t getdns_dict_util_get_string(getdns_dict * dict, char *name,
    char **result);
char *reverse_address(char *addr_str);

/**
 * detect unrecognized extension strings or invalid extension formats
 * TODO: this could be optimized by searching a sorted list
 * @param extensions dictionary of valid extension strings and values
 * @return GETDNS_RETURN_GOOD if each extension string is valid and the format matches the API specification
 * @return GETDNS_RETURN_NO_SUCH_EXTENSION A name in the extensions dict is not a valid extension.
 * @return GETDNS_RETURN_EXTENSION_MISFORMAT One or more of the extensions has a bad format.
 */
getdns_return_t validate_extensions(getdns_dict * extensions);

/* util-internal.h */
