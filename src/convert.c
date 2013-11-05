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
#include <getdns/getdns_error.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <util-internal.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

char *
getdns_convert_dns_name_to_fqdn(char *name_from_dns_response)
{
	UNUSED_PARAM(name_from_dns_response);
	return NULL;
}

char *
getdns_convert_fqdn_to_dns_name(char *fqdn_as_string)
{
	UNUSED_PARAM(fqdn_as_string);
	return NULL;
}

char *
getdns_convert_ulabel_to_alabel(char *ulabel)
{
	UNUSED_PARAM(ulabel);
	return NULL;
}

char *
getdns_convert_alabel_to_ulabel(char *alabel)
{
	UNUSED_PARAM(alabel);
	return NULL;
}

char *
getdns_display_ip_address(struct getdns_bindata
    *bindata_of_ipv4_or_ipv6_address)
{
	char buff[256];
	if (!bindata_of_ipv4_or_ipv6_address ||
	    bindata_of_ipv4_or_ipv6_address->size == 0 ||
	    !bindata_of_ipv4_or_ipv6_address->data) {
		return NULL;
	}
	if (bindata_of_ipv4_or_ipv6_address->size == 4) {
		const char *ipStr = inet_ntop(AF_INET,
		    bindata_of_ipv4_or_ipv6_address->data,
		    buff,
		    256);
		if (ipStr) {
			return strdup(ipStr);
		}
	} else if (bindata_of_ipv4_or_ipv6_address->size == 16) {
		const char *ipStr = inet_ntop(AF_INET6,
		    bindata_of_ipv4_or_ipv6_address->data,
		    buff,
		    256);
		if (ipStr) {
			return strdup(ipStr);
		}
	}
	return NULL;
}

getdns_return_t
getdns_strerror(getdns_return_t err, char *buf, size_t buflen)
{
	getdns_return_t retval = GETDNS_RETURN_GOOD;

	const char *err_str = getdns_get_errorstr_by_id(err);
	if (!err_str) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}

	snprintf(buf, buflen, "%s", err_str);

	return retval;
}				/* getdns_strerror */

/* getdns_core_only.c */
