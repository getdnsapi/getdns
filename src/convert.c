/**
 *
 * \file convert.c
 * @brief getdns label conversion functions
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

#include <getdns/getdns.h>
#include <getdns/getdns_error.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <util-internal.h>
#include <locale.h>
#include <stringprep.h>
#include <idna.h>
#include <ldns/ldns.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

static size_t sizeof_dname(uint8_t *dname)
{
	uint8_t *ptr;

	assert(dname);
	ptr = dname;
	while (*ptr && (*ptr & 0xC0) == 0)
		ptr += *ptr + 1;
	if ((*ptr & 0xC0) == 0xC0)
		ptr++;
	return (ptr - dname) + 1;
}

char *
getdns_convert_dns_name_to_fqdn(const char *name_from_dns_response)
{
	char *str;
	ldns_rdf *rdf = ldns_rdf_new(LDNS_RDF_TYPE_DNAME,
	    sizeof_dname((uint8_t *)name_from_dns_response),
	    (void *)name_from_dns_response); /* unconst is safe here */
	if (!rdf) return NULL;
	str = ldns_rdf2str(rdf);
	ldns_rdf_free(rdf);
	return str;
}

char *
getdns_convert_fqdn_to_dns_name(const char *fqdn_as_string)
{
	ldns_rdf *rdf;
	char *data;
	if (ldns_str2rdf_dname(&rdf, fqdn_as_string) != LDNS_STATUS_OK)
		return NULL;
	data = (char *)ldns_rdf_data(rdf);
	ldns_rdf_free(rdf);
	return data;
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

    if (ulabel == NULL)
        return 0;
    setlocale(LC_ALL, "");
    if ((prepped = stringprep_locale_to_utf8(ulabel)) == 0)
        return 0;
    if ((ret = stringprep(prepped, BUFSIZ, 0, stringprep_nameprep)) != STRINGPREP_OK)
        return 0;
    if ((ret = idna_to_ascii_8z(prepped, &buf, 0)) != IDNA_SUCCESS)  {
        return 0;
    }
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
