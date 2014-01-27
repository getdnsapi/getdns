/**
 * \file
 * \brief Public interfaces to getdns, include in your application to use getdns API.
 *
 * This source was taken from the original pseudo-implementation by
 * Paul Hoffman.
 */

/*
 * Copyright (c) 2013, NLNet Labs, Versign, Inc.
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

#ifndef GETDNS_H
#define GETDNS_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GETDNS_COMPILATION_COMMENT The API implementation should fill in something here, such as a compilation version string and date, and change it each time the API is compiled.

/**
 * \defgroup returnvalues return values
 * @{
 */
#define GETDNS_RETURN_GOOD 0
#define GETDNS_RETURN_GOOD_TEXT "Good"
#define GETDNS_RETURN_GENERIC_ERROR 1
#define GETDNS_RETURN_GENERIC_ERROR_TEXT "Generic error"
#define GETDNS_RETURN_BAD_DOMAIN_NAME 300
#define GETDNS_RETURN_BAD_DOMAIN_NAME_TEXT "Badly-formed domain name in first argument"
#define GETDNS_RETURN_BAD_CONTEXT 301
#define GETDNS_RETURN_BAD_CONTEXT_TEXT "Bad value for a context type"
#define GETDNS_RETURN_CONTEXT_UPDATE_FAIL 302
#define GETDNS_RETURN_CONTEXT_UPDATE_FAIL_TEXT "Did not update the context"
#define GETDNS_RETURN_UNKNOWN_TRANSACTION 303
#define GETDNS_RETURN_UNKNOWN_TRANSACTION_TEXT "An attempt was made to cancel a callback with a transaction_id that is not recognized"
#define GETDNS_RETURN_NO_SUCH_LIST_ITEM 304
#define GETDNS_RETURN_NO_SUCH_LIST_ITEM_TEXT "A helper function for lists had an index argument that was too high."
#define GETDNS_RETURN_NO_SUCH_DICT_NAME 305
#define GETDNS_RETURN_NO_SUCH_DICT_NAME_TEXT "A helper function for dicts had a name argument that for a name that is not in the dict."
#define GETDNS_RETURN_WRONG_TYPE_REQUESTED 306
#define GETDNS_RETURN_WRONG_TYPE_REQUESTED_TEXT "A helper function was supposed to return a certain type for an item, but the wrong type was given."
#define GETDNS_RETURN_NO_SUCH_EXTENSION 307
#define GETDNS_RETURN_NO_SUCH_EXTENSION_TEXT "A name in the extensions dict is not a valid extension."
#define GETDNS_RETURN_EXTENSION_MISFORMAT 308
#define GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT "One or more of the extensions have a bad format."
#define GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED 309
#define GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED_TEXT "A query was made with a context that is using stub resolution and a DNSSEC extension specified."
#define GETDNS_RETURN_MEMORY_ERROR 310
#define GETDNS_RETURN_MEMORY_ERROR_TEXT "Unable to allocate the memory required."
#define GETDNS_RETURN_INVALID_PARAMETER  311
#define GETDNS_RETURN_INVALID_PARAMETER_TEXT "A required parameter had an invalid value."
/** @}
 */

/**
 * \defgroup dnssecvalues DNSSEC values
 * @{
 */
#define GETDNS_DNSSEC_SECURE 400
#define GETDNS_DNSSEC_SECURE_TEXT "The record was determined to be secure in DNSSEC"
#define GETDNS_DNSSEC_BOGUS 401
#define GETDNS_DNSSEC_BOGUS_TEXT "The record was determined to be bogus in DNSSEC"
#define GETDNS_DNSSEC_INDETERMINATE 402
#define GETDNS_DNSSEC_INDETERMINATE_TEXT "The record was not determined to be any state in DNSSEC"
#define GETDNS_DNSSEC_INSECURE 403
#define GETDNS_DNSSEC_INSECURE_TEXT "The record was determined to be insecure in DNSSEC"
#define GETDNS_DNSSEC_NOT_PERFORMED 404
#define GETDNS_DNSSEC_NOT_PERFORMED_TEXT "DNSSEC validation was not performed (only used for debugging)"

/**
 * \defgroup contextvars Context variables
 * @{
 */
#define GETDNS_CONTEXT_NAMESPACE_DNS 500
#define GETDNS_CONTEXT_NAMESPACE_DNS_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_CONTEXT_NAMESPACE_LOCALNAMES 501
#define GETDNS_CONTEXT_NAMESPACE_LOCALNAMES_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_CONTEXT_NAMESPACE_NETBIOS 502
#define GETDNS_CONTEXT_NAMESPACE_NETBIOS_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_CONTEXT_NAMESPACE_MDNS 503
#define GETDNS_CONTEXT_NAMESPACE_MDNS_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_CONTEXT_NAMESPACE_NIS 504
#define GETDNS_CONTEXT_NAMESPACE_NIS_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_CONTEXT_STUB 505
#define GETDNS_CONTEXT_STUB_TEXT "See getdns_context_set_resolution_type()"
#define GETDNS_CONTEXT_RECURSING 506
#define GETDNS_CONTEXT_RECURSING_TEXT "See getdns_context_set_resolution_type()"
#define GETDNS_CONTEXT_FOLLOW_REDIRECTS 507
#define GETDNS_CONTEXT_FOLLOW_REDIRECTS_TEXT "See getdns_context_set_follow_redirects()"
#define GETDNS_CONTEXT_DO_NOT_FOLLOW_REDIRECTS 508
#define GETDNS_CONTEXT_DO_NOT_FOLLOW_REDIRECTS_TEXT "See getdns_context_set_follow_redirects()"
#define GETDNS_CONTEXT_UDP_FIRST_AND_FALL_BACK_TO_TCP 509
#define GETDNS_CONTEXT_UDP_FIRST_AND_FALL_BACK_TO_TCP_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_CONTEXT_UDP_ONLY 510
#define GETDNS_CONTEXT_UDP_ONLY_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_CONTEXT_TCP_ONLY 511
#define GETDNS_CONTEXT_TCP_ONLY_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN 512
#define GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_CONTEXT_APPEND_NAME_ALWAYS 513
#define GETDNS_CONTEXT_APPEND_NAME_ALWAYS_TEXT "See getdns_context_set_append_name()"
#define GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE 514
#define GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE_TEXT "See getdns_context_set_append_name()"
#define GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE 515
#define GETDNS_CONTEXT_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE_TEXT "See getdns_context_set_append_name()"
#define GETDNS_CONTEXT_DO_NOT_APPEND_NAMES 516
#define GETDNS_CONTEXT_DO_NOT_APPEND_NAMES_TEXT "See getdns_context_set_append_name()"
/** @}
 */

/**
 * \defgroup contextcodes Context codes for getdns_context_set_context_update_callback()
 * @{
 */
#define GETDNS_CONTEXT_CODE_NAMESPACES 600
#define GETDNS_CONTEXT_CODE_NAMESPACES_TEXT "Change related to getdns_context_set_namespaces"
#define GETDNS_CONTEXT_CODE_RESOLUTION_TYPE 601
#define GETDNS_CONTEXT_CODE_RESOLUTION_TYPE_TEXT "Change related to getdns_context_set_resolution_type"
#define GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS 602
#define GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS_TEXT "Change related to getdns_context_set_follow_redirects"
#define GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS 603
#define GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS_TEXT "Change related to getdns_context_set_upstream_recursive_servers"
#define GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS 604
#define GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS_TEXT "Change related to getdns_context_set_dns_root_servers"
#define GETDNS_CONTEXT_CODE_DNS_TRANSPORT 605
#define GETDNS_CONTEXT_CODE_DNS_TRANSPORT_TEXT "Change related to getdns_context_set_dns_transport"
#define GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES 606
#define GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES_TEXT "Change related to getdns_context_set_limit_outstanding_queries"
#define GETDNS_CONTEXT_CODE_APPEND_NAME 607
#define GETDNS_CONTEXT_CODE_APPEND_NAME_TEXT "Change related to getdns_context_set_append_name"
#define GETDNS_CONTEXT_CODE_SUFFIX 608
#define GETDNS_CONTEXT_CODE_SUFFIX_TEXT "Change related to getdns_context_set_suffix"
#define GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS 609
#define GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS_TEXT "Change related to getdns_context_set_dnssec_trust_anchors"
#define GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE 610
#define GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE_TEXT "Change related to getdns_context_set_edns_maximum_udp_payload_size"
#define GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE 611
#define GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE_TEXT "Change related to getdns_context_set_edns_extended_rcode"
#define GETDNS_CONTEXT_CODE_EDNS_VERSION 612
#define GETDNS_CONTEXT_CODE_EDNS_VERSION_TEXT "Change related to getdns_context_set_edns_version"
#define GETDNS_CONTEXT_CODE_EDNS_DO_BIT 613
#define GETDNS_CONTEXT_CODE_EDNS_DO_BIT_TEXT "Change related to getdns_context_set_edns_do_bit"
#define GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW 614
#define GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW_TEXT "Change related to getdns_context_set_dnssec_allowed_skew"
#define GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS 615
#define GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS_TEXT "Change related to getdns_context_set_memory_functions"
#define GETDNS_CONTEXT_CODE_TIMEOUT 616
#define GETDNS_CONTEXT_CODE_TIMEOUT_TEXT "Change related to getdns_context_set_timeout"
/** @}
 */

/**
 * \defgroup callbacktypes Callback Type Variables
 * @{
 */
#define GETDNS_CALLBACK_COMPLETE 700
#define GETDNS_CALLBACK_COMPLETE_TEXT "The response has the requested data in it"
#define GETDNS_CALLBACK_CANCEL 701
#define GETDNS_CALLBACK_CANCEL_TEXT "The calling program cancelled the callback; response is NULL"
#define GETDNS_CALLBACK_TIMEOUT 702
#define GETDNS_CALLBACK_TIMEOUT_TEXT "The requested action timed out; response is NULL"
#define GETDNS_CALLBACK_ERROR 703
#define GETDNS_CALLBACK_ERROR_TEXT "The requested action had an error; response is NULL"
/** @}
 */

/**
 * \defgroup nametype Types of name services
 * @{
 */
#define GETDNS_NAMETYPE_DNS 800
#define GETDNS_NAMETYPE_DNS_TEXT "Normal DNS (RFC 1035)"
#define GETDNS_NAMETYPE_WINS 801
#define GETDNS_NAMETYPE_WINS_TEXT "The WINS name service (some reference needed)"
/** @}
 */

/**
 * \defgroup respstatus Status Codes for Responses
 * @{
 */
#define GETDNS_RESPSTATUS_GOOD 900
#define GETDNS_RESPSTATUS_GOOD_TEXT "At least one response was returned"
#define GETDNS_RESPSTATUS_NO_NAME 901
#define GETDNS_RESPSTATUS_NO_NAME_TEXT "Queries for the name yielded all negative responses"
#define GETDNS_RESPSTATUS_ALL_TIMEOUT 902
#define GETDNS_RESPSTATUS_ALL_TIMEOUT_TEXT "All queries for the name timed out"
#define GETDNS_RESPSTATUS_NO_SECURE_ANSWERS 903
#define GETDNS_RESPSTATUS_NO_SECURE_ANSWERS_TEXT "The context setting for getting only secure responses was specified, and at least one DNS response was received, but no DNS response was determined to be secure through DNSSEC."
/** @}
 */

/**
 * \defgroup extvals Values Associated With Extensions
 * @{
 */
#define GETDNS_EXTENSION_TRUE  1000
#define GETDNS_EXTENSION_TRUE_TEXT "Turn on the extension"
#define GETDNS_EXTENSION_FALSE 1001
#define GETDNS_EXTENSION_FALSE_TEXT "Do not turn on the extension"
/** @}
 */

/**
 * \defgroup dnserrors Values Associated With DNS Errors Found By The API
 * @{
 */
#define GETDNS_BAD_DNS_CNAME_IN_TARGET 1100
#define GETDNS_BAD_DNS_CNAME_IN_TARGET_TEXT "A DNS query type that does not allow a target to be a CNAME pointed to a CNAME"
#define GETDNS_BAD_DNS_ALL_NUMERIC_LABEL 1101
#define GETDNS_BAD_DNS_ALL_NUMERIC_LABEL_TEXT "One or more labels in a returned domain name is all-numeric; this is not legal for a hostname"
#define GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE 1102
#define GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE_TEXT "A DNS query for a type other than CNAME returned a CNAME response"
/** @}
 */

/**
 * \defgroup rrtypes RR Types
 * @{
 */
#define GETDNS_RRTYPE_A         1
#define GETDNS_RRTYPE_NS        2
#define GETDNS_RRTYPE_MD        3
#define GETDNS_RRTYPE_MF        4
#define GETDNS_RRTYPE_CNAME     5
#define GETDNS_RRTYPE_SOA       6
#define GETDNS_RRTYPE_MB        7
#define GETDNS_RRTYPE_MG        8
#define GETDNS_RRTYPE_MR        9
#define GETDNS_RRTYPE_NULL      10
#define GETDNS_RRTYPE_WKS       11
#define GETDNS_RRTYPE_PTR       12
#define GETDNS_RRTYPE_HINFO     13
#define GETDNS_RRTYPE_MINFO     14
#define GETDNS_RRTYPE_MX        15
#define GETDNS_RRTYPE_TXT       16
#define GETDNS_RRTYPE_RP        17
#define GETDNS_RRTYPE_AFSDB     18
#define GETDNS_RRTYPE_X25       19
#define GETDNS_RRTYPE_ISDN      20
#define GETDNS_RRTYPE_RT        21
#define GETDNS_RRTYPE_NSAP      22
#define GETDNS_RRTYPE_SIG       24
#define GETDNS_RRTYPE_KEY       25
#define GETDNS_RRTYPE_PX        26
#define GETDNS_RRTYPE_GPOS      27
#define GETDNS_RRTYPE_AAAA      28
#define GETDNS_RRTYPE_LOC       29
#define GETDNS_RRTYPE_NXT       30
#define GETDNS_RRTYPE_EID       31
#define GETDNS_RRTYPE_NIMLOC    32
#define GETDNS_RRTYPE_SRV       33
#define GETDNS_RRTYPE_ATMA      34
#define GETDNS_RRTYPE_NAPTR     35
#define GETDNS_RRTYPE_KX        36
#define GETDNS_RRTYPE_CERT      37
#define GETDNS_RRTYPE_A6        38
#define GETDNS_RRTYPE_DNAME     39
#define GETDNS_RRTYPE_SINK      40
#define GETDNS_RRTYPE_OPT       41
#define GETDNS_RRTYPE_APL       42
#define GETDNS_RRTYPE_DS        43
#define GETDNS_RRTYPE_SSHFP     44
#define GETDNS_RRTYPE_IPSECKEY  45
#define GETDNS_RRTYPE_RRSIG     46
#define GETDNS_RRTYPE_NSEC      47
#define GETDNS_RRTYPE_DNSKEY    48
#define GETDNS_RRTYPE_DHCID     49
#define GETDNS_RRTYPE_NSEC3     50
#define GETDNS_RRTYPE_NSEC3PARAM 51
#define GETDNS_RRTYPE_TLSA      52
#define GETDNS_RRTYPE_HIP       55
#define GETDNS_RRTYPE_NINFO     56
#define GETDNS_RRTYPE_RKEY      57
#define GETDNS_RRTYPE_TALINK    58
#define GETDNS_RRTYPE_CDS       59
#define GETDNS_RRTYPE_SPF       99
#define GETDNS_RRTYPE_UINFO     100
#define GETDNS_RRTYPE_UID       101
#define GETDNS_RRTYPE_GID       102
#define GETDNS_RRTYPE_UNSPEC    103
#define GETDNS_RRTYPE_NID       104
#define GETDNS_RRTYPE_L32       105
#define GETDNS_RRTYPE_L64       106
#define GETDNS_RRTYPE_LP        107
#define GETDNS_RRTYPE_EUI48     108
#define GETDNS_RRTYPE_EUI64     109
#define GETDNS_RRTYPE_TKEY      249
#define GETDNS_RRTYPE_TSIG      250
#define GETDNS_RRTYPE_IXFR      251
#define GETDNS_RRTYPE_AXFR      252
#define GETDNS_RRTYPE_MAILB     253
#define GETDNS_RRTYPE_MAILA     254
#define GETDNS_RRTYPE_URI       256
#define GETDNS_RRTYPE_CAA       257
#define GETDNS_RRTYPE_TA        32768
#define GETDNS_RRTYPE_DLV       32769
/** @}
 */

struct getdns_context;
typedef uint16_t getdns_return_t;
typedef uint64_t getdns_transaction_t;
/**
 * used to check data types within complex types (dict, list)
 */
typedef enum getdns_data_type
{
	t_dict, t_list, t_int, t_bindata
} getdns_data_type;
struct getdns_bindata
{
	size_t size;
	uint8_t *data;
};

/**
 * getdns dictionary data type
 * Use helper functions getdns_dict_* to manipulate and iterate dictionaries
 */
struct getdns_dict;

/**
 * getdns list data type
 * Use helper functions getdns_list_* to manipulate and iterate lists
 * Indexes are 0 based.
 */
struct getdns_list;

/**
 * translate an error code to a string value, not in the original api description
 * but seems like a nice thing to have
 * @param err return code from GETDNS_RETURN_* defines
 * @param buf buffer to which to copy the error string
 * @param buflen length of buf
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t getdns_strerror(getdns_return_t err, char *buf, size_t buflen);

/**
 * get the length of the specified list (returned in *answer)
 * @param this_list list of any of the supported data types
 * @param answer number of valid items in the list
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if list is not valid or params are NULL
 */
getdns_return_t getdns_list_get_length(const struct getdns_list *this_list,
    size_t * answer);
/**
 * get the enumerated data type of the indexed list item
 * @param this_list the list from which to fetch the data type
 * @param index the item in the list from which to fetch the data type
 * @param *answer assigned the value of the data type on success
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if the index is out of range or the list is NULL
 */
getdns_return_t getdns_list_get_data_type(const struct getdns_list *this_list,
    size_t index, getdns_data_type * answer);
/**
 * retrieve the dictionary value of the specified list item, the caller must not free
 * storage associated with the return value.  When the list is destroyed this
 * dict data is also free()'d - keep this in mind when using this function.
 * @param this_list the list from which to fetch the value
 * @param index the item in the list from which to fetch the value
 * @param **answer assigned a pointer to the dict value of the indexed element
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if the index is out of range or the list is NULL
 * @return GETDNS_RETURN_WRONG_TYPE_REQUESTED if the data type does not match the contents of the indexed item
 */
getdns_return_t getdns_list_get_dict(const struct getdns_list *this_list, size_t index,
    struct getdns_dict **answer);

/**
 * retrieve the list value of the specified list item, the caller must not free
 * storage associated with the return value.  When the list is destroyed any
 * list data is also free()'d - keep this in mind when using this function.
 * @param this_list the list from which to fetch the value
 * @param index the item in the list from which to fetch the value
 * @param **answer assigned a pointer to the list value of the indexed element
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if the index is out of range or the list is NULL
 * @return GETDNS_RETURN_WRONG_TYPE_REQUESTED if the data type does not match the contents of the indexed item
 */
getdns_return_t getdns_list_get_list(const struct getdns_list *this_list, size_t index,
    struct getdns_list **answer);
/**
 * retrieve the binary data value of the specified list item, the caller must not
 * free storage associated with the return value.  When the list is destroyed any
 * bindata data is also free()'d - keep this in mind when using this function.
 * @param this_list the list from which to fetch the value
 * @param index the item in the list from which to fetch the value
 * @param **answer assigned a pointer to the list value of the indexed element
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if the index is out of range or the list is NULL
 * @return GETDNS_RETURN_WRONG_TYPE_REQUESTED if the data type does not match the contents of the indexed item
 */
getdns_return_t getdns_list_get_bindata(const struct getdns_list *this_list, size_t index,
    struct getdns_bindata **answer);
/**
 * retrieve the integer value of the specified list item
 * @param this_list the list from which to fetch the item
 * @param index the index of the element in the list to fetch from
 * @param *answer assigned the integer value of the indexed element
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if the index is out of range or the list is NULL
 * @return GETDNS_RETURN_WRONG_TYPE_REQUESTED if the data type does not match the contents of the indexed item
 */
getdns_return_t getdns_list_get_int(const struct getdns_list *this_list, size_t index,
    uint32_t * answer);

/**
 * fetch a list of names from the dictionary, this list must be freed by the caller
 * via a call to getdns_list_destroy
 * @param this_dict dictionary from which to produce the list of names
 * @param **answer a pointer to the new list will be assigned to *answer
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_DICT_NAME if dict is invalid or empty
 */
getdns_return_t getdns_dict_get_names(const struct getdns_dict *this_dict,
    struct getdns_list **answer);
/**
 * fetch the data type for the data associated with the specified name
 * @param this_dict dictionary from which to fetch the data type
 * @param name a name/key value to look up in the dictionary
 * @param *answer data type will be stored at this address
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_DICT_NAME if dict is invalid or name does not exist
 */
getdns_return_t getdns_dict_get_data_type(const struct getdns_dict *this_dict,
    const char *name, getdns_data_type * answer);
/**
 * fetch the dictionary associated with the specified name, the dictionary should
 * not be free()'d by the caller, it will be freed when the parent dictionary is
 * free()'d
 * @param this_dict dictionary from which to fetch the dictionary
 * @param name a name/key value to look up in the dictionary
 * @param **answer a copy of the dictionary will be stored at this address
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_DICT_NAME if dict is invalid or name does not exist
 */
getdns_return_t getdns_dict_get_dict(const struct getdns_dict *this_dict,
    const char *name, struct getdns_dict **answer);
/**
 * fetch the list associated with the specified name
 * the list should not be free()'d by the caller, when the dictionary is destroyed
 * the list will also be destroyed
 * @param this_dict dictionary from which to fetch the list
 * @param name a name/key value to look up in the dictionary
 * @param **answer a copy of the list will be stored at this address
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_DICT_NAME if dict is invalid or name does not exist
 */
getdns_return_t getdns_dict_get_list(const struct getdns_dict *this_dict,
    const char *name, struct getdns_list **answer);
/**
 * fetch the bindata associated with the specified name, the bindata should not be
 * free()'d by the caller
 * @param this_dict dictionary from which to fetch the bindata
 * @param name a name/key value to look up in the dictionary
 * @param **answer a copy of the bindata will be stored at this address
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_DICT_NAME if dict is invalid or name does not exist
 */
getdns_return_t getdns_dict_get_bindata(const struct getdns_dict *this_dict,
    const char *name, struct getdns_bindata **answer);
/**
 * fetch the integer value associated with the specified name
 * @param this_dict dictionary from which to fetch the integer
 * @param name a name/key value to look up in the dictionary
 * @param *answer the integer will be stored at this address
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_DICT_NAME if dict is invalid or name does not exist
 */
getdns_return_t getdns_dict_get_int(const struct getdns_dict *this_dict,
    const char *name, uint32_t * answer);

/**
 * create a new list with no items
 * @return pointer to an allocated list, NULL if insufficient memory
 */
struct getdns_list *getdns_list_create();
struct getdns_list *getdns_list_create_with_context(struct getdns_context *context);
struct getdns_list *getdns_list_create_with_memory_functions(
    void *(*malloc) (size_t),
    void *(*realloc) (void *, size_t),
    void (*free) (void *)
);
struct getdns_list *getdns_list_create_with_extended_memory_functions(
    void *userarg,
    void *(*malloc) (void *userarg, size_t),
    void *(*realloc) (void *userarg, void *, size_t),
    void (*free) (void *userarg, void *)
);

/**
 * free memory allocated to the list (also frees all children of the list)
 * note that lists and bindata retrieved from the list via the getdns_list_get_*
 * helper functions will be destroyed as well - if you fetched them previously
 * you MUST copy those instances BEFORE you destroy the list else
 * unpleasant things will happen at run-time
 */
void getdns_list_destroy(struct getdns_list *this_list);

/**
 * assign the child_dict to an item in a parent list, the parent list copies
 * the child dict and will free the copy when the list is destroyed
 * @param this_list list containing the item to which child_list is to be assigned
 * @param index index of the item within list to which child_list is to be assigned
 * @param *child_list list to assign to the item
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if index is out of range, or list is NULL
 */
getdns_return_t getdns_list_set_dict(struct getdns_list *this_list, size_t index,
    struct getdns_dict *child_dict);

/**
 * assign the child_list to an item in a parent list, the parent list copies
 * the child list and will free the copy when the list is destroyed
 * @param this_list list containing the item to which child_list is to be assigned
 * @param index index of the item within list to which child_list is to be assigned
 * @param *child_list list to assign to the item
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if index is out of range, or list is NULL
 */
getdns_return_t getdns_list_set_list(struct getdns_list *this_list, size_t index,
    struct getdns_list *child_list);
/**
 * assign the child_bindata to an item in a parent list, the parent list copies
 * the child data and will free the copy when the list is destroyed
 * @param this_list list contiaining the item to which child_list is to be assigned
 * @param index index of the item within list to which child_list is to be assigned
 * @param *child_bindata data to assign to the item
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if index is out of range, or list is NULL
 */
getdns_return_t getdns_list_set_bindata(struct getdns_list *this_list, size_t index,
    struct getdns_bindata *child_bindata);
/**
 * set the integer value of the indexed item (zero based index)
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if index is out of range, or list is NULL
 */
getdns_return_t getdns_list_set_int(struct getdns_list *this_list, size_t index,
    uint32_t child_uint32);

/**
 * create a new dictionary with no items
 * @return pointer to an allocated dictionary, NULL if insufficient memory
 */
struct getdns_dict *getdns_dict_create();
struct getdns_dict *getdns_dict_create_with_context(struct getdns_context *context);
struct getdns_dict *getdns_dict_create_with_memory_functions(
    void *(*malloc) (size_t),
    void *(*realloc) (void *, size_t),
    void (*free) (void *)
);
struct getdns_dict *getdns_dict_create_with_extended_memory_functions(
    void *userarg,
    void *(*malloc) (void *userarg, size_t),
    void *(*realloc) (void *userarg, void *, size_t),
    void (*free) (void *userarg, void *)
);

/**
 * destroy a dictionary and all items within that dictionary
 * be aware that if you have fetched any data from the dictionary it will
 * no longer be available (you are likely to experience bad things if you try)
 */
void getdns_dict_destroy(struct getdns_dict *this_dict);

getdns_return_t getdns_dict_set_dict(struct getdns_dict *this_dict, char *name,
    struct getdns_dict *child_dict);
/**
 * create a new entry in the dictionary, or replace the value of an existing entry
 * this routine makes a copy of the child_list
 * @param this_dict dictionary in which to add or change the value
 * @param name key that identifies which item in the dictionary to add/change
 * @param child_list value to assign to the node identified by name
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t getdns_dict_set_list(struct getdns_dict *this_dict, char *name,
    struct getdns_list *child_list);
/**
 * create a new entry in the dictionary, or replace the value of an existing entry
 * this routine makes a copy of the child_bindata
 * @param this_dict dictionary in which to add or change the value
 * @param name key that identifies which item in the dictionary to add/change
 * @param child_bindata value to assign to the node identified by name
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t getdns_dict_set_bindata(struct getdns_dict *this_dict, char *name,
    struct getdns_bindata *child_bindata);
/**
 * create a new entry in the dictionary, or replace the value of an existing entry
 * @param this_dict dictionary in which to add or change the value
 * @param name key that identifies which item in the dictionary to add/change
 * @param child_uint32 value to assign to the node identified by name
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t getdns_dict_set_int(struct getdns_dict *this_dict, char *name,
    uint32_t child_uint32);

/**
 * remove the value associated with the specified name
 * @param this_dict dictionary from which to fetch the integer
 * @param name a name/key value to look up in the dictionary
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_NO_SUCH_DICT_NAME if dict is invalid or name does not exist
 */
getdns_return_t getdns_dict_remove_name(struct getdns_dict *this_dict, char *name);

/* Callback arguments */
typedef void (*getdns_callback_t) (struct getdns_context *context,
    uint16_t callback_type,
    struct getdns_dict * response,
    void *userarg, getdns_transaction_t transaction_id);

/* Function definitions */

getdns_return_t
getdns_general(struct getdns_context *context,
    const char *name,
    uint16_t request_type,
    struct getdns_dict *extensions,
    void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callbackfn);
getdns_return_t
getdns_address(struct getdns_context *context,
    const char *name,
    struct getdns_dict *extensions,
    void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callbackfn);
getdns_return_t
getdns_hostname(struct getdns_context *context,
    struct getdns_dict *address,
    struct getdns_dict *extensions,
    void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callbackfn);
getdns_return_t
getdns_service(struct getdns_context *context,
    const char *name,
    struct getdns_dict *extensions,
    void *userarg,
    getdns_transaction_t * transaction_id, getdns_callback_t callbackfn);

getdns_return_t
getdns_context_create(struct getdns_context ** context, int set_from_os);

getdns_return_t
getdns_context_create_with_memory_functions(
    struct getdns_context ** context,
    int set_from_os,
    void *(*malloc) (size_t),
    void *(*realloc) (void *, size_t),
    void (*free) (void *)
);

getdns_return_t
getdns_context_create_with_extended_memory_functions(
    struct getdns_context **context,
    int set_from_os,
    void *userarg,
    void *(*malloc) (void *userarg, size_t),
    void *(*realloc) (void *userarg, void *, size_t),
    void (*free) (void *userarg, void *)
);

void getdns_context_destroy(struct getdns_context *context);

getdns_return_t
getdns_cancel_callback(struct getdns_context *context,
    getdns_transaction_t transaction_id);

/**
 * \defgroup syncfuns Synchronous API functions that do not use callbacks
 * These functions do not use callbacks, when the application calls one of these
 * functions the library retrieves all of the data before returning.  Return
 * values are exactly the same as if you had used a callback with the
 * asynchronous functions.
 * @{
 */

/**
 * retrieve general DNS data
 * @param context pointer to a previously created context to be used for this call
 * @param name the ASCII based domain name to lookup
 * @param request_type RR type for the query, e.g. GETDNS_RR_TYPE_NS
 * @param extensions dict data structures, NULL to use no extensions
 * @param response response
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t
getdns_general_sync(struct getdns_context *context,
    const char *name,
    uint16_t request_type,
    struct getdns_dict *extensions,
    struct getdns_dict **response);

/**
 * retrieve address assigned to a DNS name
 * @param context pointer to a previously created context to be used for this call
 * @param name the ASCII based domain name to lookup
 * @param extensions dict data structures, NULL to use no extensions
 * @param response response
 * @return GETDNS_RETURN_GOOD on success

 */
getdns_return_t
getdns_address_sync(struct getdns_context *context,
    const char *name,
    struct getdns_dict *extensions,
    struct getdns_dict **response);

/**
 * retrieve hostname assigned to an IP address
 * @param context pointer to a previously created context to be used for this call
 * @param address the address to look up
 * @param extensions dict data structures, NULL to use no extensions
 * @param response response
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t
getdns_hostname_sync(struct getdns_context *context,
    struct getdns_dict *address,
    struct getdns_dict *extensions,
    struct getdns_dict **response);

/**
 * retrieve a service assigned to a DNS name
 * @param context pointer to a previously created context to be used for this call
 * @param name the ASCII based domain name to lookup
 * @param extensions dict data structures, NULL to use no extensions
 * @param response response
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t
getdns_service_sync(struct getdns_context *context,
    const char *name,
    struct getdns_dict *extensions,
    struct getdns_dict **response);

/** @}
 */

char *getdns_convert_dns_name_to_fqdn(const char *name_from_dns_response);

char *getdns_convert_fqdn_to_dns_name(const char *fqdn_as_string);

char *getdns_convert_ulabel_to_alabel(const char *ulabel);

char *getdns_convert_alabel_to_ulabel(const char *alabel);

getdns_return_t
getdns_validate_dnssec(struct getdns_bindata *record_to_validate,
    struct getdns_list *bundle_of_support_records,
    struct getdns_list *trust_anchor_rdatas);

/**
 * creates a string that describes the dictionary in a human readable form
 * one line per item in the dictionary
 * TODO: maybe this should be json or something machine readable too
 * @param this_dict dictionary to pretty print
 * @return character array (caller must free this) containing pretty string
 */
char *getdns_pretty_print_dict(const struct getdns_dict *some_dict);

char *getdns_display_ip_address(const struct getdns_bindata
    *bindata_of_ipv4_or_ipv6_address);

getdns_return_t
getdns_context_set_context_update_callback(
  struct getdns_context *      context,
  void                   (*value)(struct getdns_context *context, uint16_t changed_item)
);

getdns_return_t
getdns_context_set_resolution_type(struct getdns_context *context, uint16_t value);

getdns_return_t
getdns_context_set_namespaces(struct getdns_context *context,
    size_t namespace_count, uint16_t * namespaces);

getdns_return_t
getdns_context_set_dns_transport(struct getdns_context *context, uint16_t value);

getdns_return_t
getdns_context_set_limit_outstanding_queries(struct getdns_context *context,
    uint16_t limit);

getdns_return_t
getdns_context_set_timeout(struct getdns_context *context, uint16_t timeout);

getdns_return_t
getdns_context_set_follow_redirects(struct getdns_context *context, uint16_t value);

getdns_return_t
getdns_context_set_dns_root_servers(struct getdns_context *context,
    struct getdns_list *addresses);

getdns_return_t
getdns_context_set_append_name(struct getdns_context *context, uint16_t value);

getdns_return_t
getdns_context_set_suffix(struct getdns_context *context, struct getdns_list *value);

getdns_return_t
getdns_context_set_dnssec_trust_anchors(struct getdns_context *context,
    struct getdns_list *value);

getdns_return_t
getdns_context_set_dnssec_allowed_skew(struct getdns_context *context,
    uint16_t value);

getdns_return_t
getdns_context_set_upstream_recursive_servers(struct getdns_context *context,
    struct getdns_list *upstream_list);

getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(struct getdns_context *context,
    uint16_t value);

getdns_return_t
getdns_context_set_edns_extended_rcode(struct getdns_context *context,
    uint8_t value);

getdns_return_t
getdns_context_set_edns_version(struct getdns_context *context, uint8_t value);

getdns_return_t
getdns_context_set_edns_do_bit(struct getdns_context *context, uint8_t value);

getdns_return_t
getdns_context_set_memory_functions(struct getdns_context *context,
    void *(*malloc) (size_t),
    void *(*realloc) (void *, size_t),
    void (*free) (void *)
    );

getdns_return_t
getdns_context_set_extended_memory_functions(struct getdns_context *context,
    void *userarg,
    void *(*malloc) (void *userarg, size_t sz),
    void *(*realloc) (void *userarg, void *ptr, size_t sz),
    void (*free) (void *userarg, void *ptr)
    );

/* Extension */
getdns_return_t
getdns_extension_detach_eventloop(struct getdns_context* context);

/* get the fd */
int getdns_context_fd(struct getdns_context* context);
/* process async reqs */
getdns_return_t getdns_context_process_async(struct getdns_context* context);

#ifdef __cplusplus
}
#endif
#endif /* GETDNS_H */
