/**
 *
 * \file convert.c
 * @brief getdns label conversion functions
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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <locale.h>
#include <stringprep.h>
#include <idna.h>
#include "getdns/getdns.h"
#include "util-internal.h"
#include "getdns_error.h"
#include "gldns/wire2str.h"
#include "gldns/str2wire.h"

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

getdns_return_t
getdns_convert_dns_name_to_fqdn(
    const getdns_bindata *dns_name_wire_fmt, char **fqdn_as_string)
{
	char *r;

	if (!dns_name_wire_fmt || !fqdn_as_string)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(r = gldns_wire2str_dname(
	    dns_name_wire_fmt->data, dns_name_wire_fmt->size)))
		return GETDNS_RETURN_GENERIC_ERROR;

	*fqdn_as_string = r;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_convert_fqdn_to_dns_name(
    const char *fqdn_as_string, getdns_bindata **dns_name_wire_fmt)
{
	getdns_bindata *r;
	uint8_t *dname;
	size_t len;

	if (!fqdn_as_string || !dns_name_wire_fmt)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(r = malloc(sizeof(getdns_bindata))))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!(dname = gldns_str2wire_dname(fqdn_as_string, &len))) {
		free(r);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	r->size = len;
	r->data = dname;
	*dns_name_wire_fmt = r;
	return GETDNS_RETURN_GOOD;
}

/*---------------------------------------- getdns_convert_alabel_to_ulabel */
/**
 * Convert UTF-8 string into an ACE-encoded domain
 * It is the application programmer's responsibility to free()
 * the returned buffer after use
 *
 * @param ulabel the UTF-8-encoded domain name to convert
 * @return pointer to ACE-encoded string
 * @return NULL if conversion fails
 */

char *
getdns_convert_ulabel_to_alabel(const char *ulabel)
{
    int ret;
    char *buf;
    char *prepped;
    char *prepped2;

    if (ulabel == NULL)
	return 0;
    prepped2 = malloc(BUFSIZ);
    if(!prepped2)
	    return 0;
    setlocale(LC_ALL, "");
    if ((prepped = stringprep_locale_to_utf8(ulabel)) == 0) {
	/* convert to utf8 fails, which it can, but continue anyway */
	if(strlen(ulabel)+1 > BUFSIZ) {
	    free(prepped2);
	    return 0;
	}
	memcpy(prepped2, ulabel, strlen(ulabel)+1);
    } else {
	if(strlen(prepped)+1 > BUFSIZ) {
	    free(prepped);
	    free(prepped2);
	    return 0;
	}
	memcpy(prepped2, prepped, strlen(prepped)+1);
	free(prepped);
    }
    if ((ret = stringprep(prepped2, BUFSIZ, 0, stringprep_nameprep)) != STRINGPREP_OK) {
	free(prepped2);
	return 0;
    }
    if ((ret = idna_to_ascii_8z(prepped2, &buf, 0)) != IDNA_SUCCESS)  {
	free(prepped2);
	return 0;
    }
    free(prepped2);
    return buf;
}

/*---------------------------------------- getdns_convert_alabel_to_ulabel */
/**
 * Convert ACE-encoded domain name into a UTF-8 string.
 * It is the application programmer's responsibility to free()
 * the returned buffer after use
 *
 * @param alabel the ACE-encoded domain name to convert
 * @return pointer to UTF-8 string
 * @return NULL if conversion fails
 */

char *
getdns_convert_alabel_to_ulabel(const char *alabel)
{
    int  ret;              /* just in case we might want to use it someday */
    char *buf;

    if (alabel == NULL)
        return 0;
    if ((ret = idna_to_unicode_8z8z(alabel, &buf, 0)) != IDNA_SUCCESS)  {
        return NULL;
    }
    return buf;
}


char *
getdns_display_ip_address(const struct getdns_bindata
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

/* convert.c */
