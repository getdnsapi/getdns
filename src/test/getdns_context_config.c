/*
 * Copyright (c) 2013, NLNet Labs, Verisign, Inc.
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

#include "getdns_context_config.h"
#include "getdns/getdns_extra.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

static int _streq(const getdns_bindata *name, const char *str)
{
	if (strlen(str) != name->size)
		return 0;
	else	return strncmp((const char *)name->data, str, name->size) == 0;
}

static getdns_return_t _get_list_or_read_file(const getdns_dict *config_dict,
    const char *setting, getdns_list **r_list, int *destroy_list)
{
	getdns_bindata *fn_bd;
	char fn[FILENAME_MAX];
	FILE *fh;
	getdns_return_t r;

	assert(r_list);
	assert(destroy_list);

	*destroy_list = 0;
	if (!(r = getdns_dict_get_list(config_dict, setting, r_list)))
		return GETDNS_RETURN_GOOD;

	else if ((r = getdns_dict_get_bindata(config_dict, setting, &fn_bd)))
		return r;

	else if (fn_bd->size >= FILENAME_MAX)
		return GETDNS_RETURN_INVALID_PARAMETER;

	(void)memcpy(fn, fn_bd->data, fn_bd->size);
	fn[fn_bd->size] = 0;

	if (!(fh = fopen(fn, "r")))
		return GETDNS_RETURN_GENERIC_ERROR;

	if (!(r = getdns_fp2rr_list(fh, r_list, NULL, 3600)))
		*destroy_list = 1;

	fclose(fh);
	return r;
}

#define CONTEXT_SETTING_INT(X) \
	} else 	if (_streq(setting, #X)) { \
		if (!(r = getdns_dict_get_int(config_dict, #X , &n))) \
			r = getdns_context_set_ ## X (context, n);

#define CONTEXT_SETTING_LIST(X) \
	} else 	if (_streq(setting, #X)) { \
		if (!(r = getdns_dict_get_list(config_dict, #X , &list))) \
			r = getdns_context_set_ ## X (context, list);

#define CONTEXT_SETTING_LIST_OR_ZONEFILE(X) \
	} else if (_streq(setting, #X)) { \
		if (!(r = _get_list_or_read_file( \
		    config_dict, #X , &list, &destroy_list))) \
			r = getdns_context_set_ ## X(context, list); \
		if (destroy_list) getdns_list_destroy(list);

#define CONTEXT_SETTING_ARRAY(X, T) \
	} else 	if (_streq(setting, #X )) { \
		if (!(r = getdns_dict_get_list(config_dict, #X , &list)) && \
		    !(r =  getdns_list_get_length(list, &count))) { \
			for (i=0; i<count && i<(sizeof(X)/sizeof(*X)); i++) { \
				if ((r = getdns_list_get_int(list, i, &n))) \
					break; \
				X[i] = (getdns_ ## T ## _t)n; \
			} \
			r = getdns_context_set_ ##X (context, count, X); \
		}

#define EXTENSION_SETTING_INT(X) \
	} else if (_streq(setting, #X )) { \
		if (!(r = getdns_dict_get_int(config_dict, #X , &n))) \
			r = getdns_dict_set_int(extensions, #X , n);

#define EXTENSION_SETTING_DICT(X) \
	} else if (_streq(setting, #X )) { \
		if (!(r = getdns_dict_get_dict(config_dict, #X , &dict))) \
			r = getdns_dict_set_dict(extensions, #X , dict);

static getdns_return_t
_getdns_context_config_setting_(
    getdns_context *context, getdns_dict *extensions,
    const getdns_dict *config_dict, const getdns_bindata *setting)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_dict *dict;
	getdns_list *list;
	getdns_namespace_t namespaces[100];
	getdns_transport_list_t dns_transport_list[100];
	size_t count, i;
	uint32_t n;
	int destroy_list = 0;

	if (_streq(setting, "all_context")) {
		if (!(r = getdns_dict_get_dict(config_dict, "all_context", &dict)))
			r = _getdns_context_config_(context, extensions, dict);

	CONTEXT_SETTING_INT(resolution_type)
	CONTEXT_SETTING_ARRAY(namespaces, namespace)
	CONTEXT_SETTING_INT(dns_transport)
	CONTEXT_SETTING_ARRAY(dns_transport_list, transport_list)
	CONTEXT_SETTING_INT(idle_timeout)
	CONTEXT_SETTING_INT(limit_outstanding_queries)
	CONTEXT_SETTING_INT(timeout)
	CONTEXT_SETTING_INT(follow_redirects)
	CONTEXT_SETTING_LIST_OR_ZONEFILE(dns_root_servers)
	CONTEXT_SETTING_INT(append_name)
	CONTEXT_SETTING_LIST(suffix)
	CONTEXT_SETTING_LIST_OR_ZONEFILE(dnssec_trust_anchors)
	CONTEXT_SETTING_INT(dnssec_allowed_skew)
	CONTEXT_SETTING_LIST(upstream_recursive_servers)
	CONTEXT_SETTING_INT(edns_maximum_udp_payload_size)
	CONTEXT_SETTING_INT(edns_extended_rcode)
	CONTEXT_SETTING_INT(edns_version)
	CONTEXT_SETTING_INT(edns_do_bit)

	/***************************************/
	/****                               ****/
	/****  Unofficial context settings  ****/
	/****                               ****/
	/***************************************/

	CONTEXT_SETTING_INT(edns_client_subnet_private)
	CONTEXT_SETTING_INT(tls_authentication)
	CONTEXT_SETTING_INT(tls_query_padding_blocksize)

	/**************************************/
	/****                              ****/
	/****  Default extensions setting  ****/
	/****                              ****/
	/**************************************/
	EXTENSION_SETTING_DICT(add_opt_parameters)
	EXTENSION_SETTING_INT(add_warning_for_bad_dns)
	EXTENSION_SETTING_INT(dnssec_return_all_statuses)
	EXTENSION_SETTING_INT(dnssec_return_full_validation_chain)
	EXTENSION_SETTING_INT(dnssec_return_only_secure)
	EXTENSION_SETTING_INT(dnssec_return_status)
	EXTENSION_SETTING_INT(dnssec_return_validation_chain)
#if defined(DNSSEC_ROADBLOCK_AVOIDANCE) && defined(HAVE_LIBUNBOUND)
	EXTENSION_SETTING_INT(dnssec_roadblock_avoidance)
#endif
#ifdef EDNS_COOKIES
	EXTENSION_SETTING_INT(edns_cookies)
#endif
	EXTENSION_SETTING_DICT(header)
	EXTENSION_SETTING_INT(return_api_information)
	EXTENSION_SETTING_INT(return_both_v4_and_v6)
	EXTENSION_SETTING_INT(return_call_reporting)
	EXTENSION_SETTING_INT(specify_class)

	/************************************/
	/****                            ****/
	/****  Ignored context settings  ****/
	/****                            ****/
	/************************************/
	} else if (!_streq(setting, "implementation_string") &&
	    !_streq(setting, "version_string")) {
		r = GETDNS_RETURN_NOT_IMPLEMENTED;
	}
	return r;
}

getdns_return_t
_getdns_context_config_(getdns_context *context,
    getdns_dict *extensions, const getdns_dict *config_dict)
{
	getdns_list *settings;
	getdns_return_t r;
	getdns_bindata *setting;
	size_t i;

	if ((r = getdns_dict_get_names(config_dict, &settings)))
		return r;

	for (i = 0; !(r = getdns_list_get_bindata(settings,i,&setting)); i++) {
		if ((r = _getdns_context_config_setting_(
		    context, extensions, config_dict, setting)))
			break;
	}
	if (r == GETDNS_RETURN_NO_SUCH_LIST_ITEM)
		r = GETDNS_RETURN_GOOD;

	getdns_list_destroy(settings);
	return r;
}

