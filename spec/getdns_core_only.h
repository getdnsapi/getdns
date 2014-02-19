/* Created at 2014-02-19-15-06-22*/
#ifndef GETDNS_H
#define GETDNS_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GETDNS_COMPILATION_COMMENT The API implementation should fill in something here, such as a compilation version string and date, and change it each time the API is compiled.

/* Return values */
typedef enum getdns_return_t {
	GETDNS_RETURN_GOOD = 0,
	GETDNS_RETURN_GENERIC_ERROR = 1,
	GETDNS_RETURN_BAD_DOMAIN_NAME = 300,
	GETDNS_RETURN_BAD_CONTEXT = 301,
	GETDNS_RETURN_CONTEXT_UPDATE_FAIL = 302,
	GETDNS_RETURN_UNKNOWN_TRANSACTION = 303,
	GETDNS_RETURN_NO_SUCH_LIST_ITEM = 304,
	GETDNS_RETURN_NO_SUCH_DICT_NAME = 305,
	GETDNS_RETURN_WRONG_TYPE_REQUESTED = 306,
	GETDNS_RETURN_NO_SUCH_EXTENSION = 307,
	GETDNS_RETURN_EXTENSION_MISFORMAT = 308,
	GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED = 309,
	GETDNS_RETURN_MEMORY_ERROR = 310,
	GETDNS_RETURN_INVALID_PARAMETER = 311
} getdns_return_t;

#define GETDNS_RETURN_GOOD_TEXT "Good"
#define GETDNS_RETURN_GENERIC_ERROR_TEXT "Generic error"
#define GETDNS_RETURN_BAD_DOMAIN_NAME_TEXT "Badly-formed domain name in first argument"
#define GETDNS_RETURN_BAD_CONTEXT_TEXT "The context has internal deficiencies"
#define GETDNS_RETURN_CONTEXT_UPDATE_FAIL_TEXT "Did not update the context"
#define GETDNS_RETURN_UNKNOWN_TRANSACTION_TEXT "An attempt was made to cancel a callback with a transaction_id that is not recognized"
#define GETDNS_RETURN_NO_SUCH_LIST_ITEM_TEXT "A helper function for lists had an index argument that was too high."
#define GETDNS_RETURN_NO_SUCH_DICT_NAME_TEXT "A helper function for dicts had a name argument that for a name that is not in the dict."
#define GETDNS_RETURN_WRONG_TYPE_REQUESTED_TEXT "A helper function was supposed to return a certain type for an item, but the wrong type was given."
#define GETDNS_RETURN_NO_SUCH_EXTENSION_TEXT "A name in the extensions dict is not a valid extension."
#define GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT "One or more of the extensions have a bad format."
#define GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED_TEXT "A query was made with a context that is using stub resolution and a DNSSEC extension specified."
#define GETDNS_RETURN_MEMORY_ERROR_TEXT "Unable to allocate the memory required."
#define GETDNS_RETURN_INVALID_PARAMETER_TEXT "A required parameter had an invalid value."

/* DNSSEC values */
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

/* Namespace types */
typedef enum getdns_namespace_t {
	GETDNS_NAMESPACE_DNS = 500,
	GETDNS_NAMESPACE_LOCALNAMES = 501,
	GETDNS_NAMESPACE_NETBIOS = 502,
	GETDNS_NAMESPACE_MDNS = 503,
	GETDNS_NAMESPACE_NIS = 504
} getdns_namespace_t;

#define GETDNS_NAMESPACE_DNS_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_NAMESPACE_LOCALNAMES_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_NAMESPACE_NETBIOS_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_NAMESPACE_MDNS_TEXT "See getdns_context_set_namespaces()"
#define GETDNS_NAMESPACE_NIS_TEXT "See getdns_context_set_namespaces()"

/* Resolution types */
typedef enum getdns_resolution_t {
	GETDNS_RESOLUTION_STUB = 520,
	GETDNS_RESOLUTION_RECURSING = 521
} getdns_resolution_t;

#define GETDNS_RESOLUTION_STUB_TEXT "See getdns_context_set_resolution_type()"
#define GETDNS_RESOLUTION_RECURSING_TEXT "See getdns_context_set_resolution_type()"

/* Redirect policies */
typedef enum getdns_redirects_t {
	GETDNS_REDIRECTS_FOLLOW = 530,
	GETDNS_REDIRECTS_DO_NOT_FOLLOW = 531
} getdns_redirects_t;

#define GETDNS_REDIRECTS_FOLLOW_TEXT "See getdns_context_set_follow_redirects()"
#define GETDNS_REDIRECTS_DO_NOT_FOLLOW_TEXT "See getdns_context_set_follow_redirects()"

/* Transport arrangements */
typedef enum getdns_transport_t {
	GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP = 540,
	GETDNS_TRANSPORT_UDP_ONLY = 541,
	GETDNS_TRANSPORT_TCP_ONLY = 542,
	GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN = 543
} getdns_transport_t;

#define GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_TRANSPORT_UDP_ONLY_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_TRANSPORT_TCP_ONLY_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN_TEXT "See getdns_context_set_dns_transport()"

/* Suffix appending methods */
typedef enum getdns_append_name_t {
	GETDNS_APPEND_NAME_ALWAYS = 550,
	GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE = 551,
	GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE = 552,
	GETDNS_APPEND_NAME_NEVER = 553
} getdns_append_name_t;

#define GETDNS_APPEND_NAME_ALWAYS_TEXT "See getdns_context_set_append_name()"
#define GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE_TEXT "See getdns_context_set_append_name()"
#define GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE_TEXT "See getdns_context_set_append_name()"
#define GETDNS_APPEND_NAME_NEVER_TEXT "See getdns_context_set_append_name()"

/* Context codes */
typedef enum getdns_context_code_t {
	GETDNS_CONTEXT_CODE_NAMESPACES = 600,
	GETDNS_CONTEXT_CODE_RESOLUTION_TYPE = 601,
	GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS = 602,
	GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS = 603,
	GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS = 604,
	GETDNS_CONTEXT_CODE_DNS_TRANSPORT = 605,
	GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES = 606,
	GETDNS_CONTEXT_CODE_APPEND_NAME = 607,
	GETDNS_CONTEXT_CODE_SUFFIX = 608,
	GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS = 609,
	GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE = 610,
	GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE = 611,
	GETDNS_CONTEXT_CODE_EDNS_VERSION = 612,
	GETDNS_CONTEXT_CODE_EDNS_DO_BIT = 613,
	GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW = 614,
	GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS = 615,
	GETDNS_CONTEXT_CODE_TIMEOUT = 616
} getdns_context_code_t;

#define GETDNS_CONTEXT_CODE_NAMESPACES_TEXT "Change related to getdns_context_set_namespaces"
#define GETDNS_CONTEXT_CODE_RESOLUTION_TYPE_TEXT "Change related to getdns_context_set_resolution_type"
#define GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS_TEXT "Change related to getdns_context_set_follow_redirects"
#define GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS_TEXT "Change related to getdns_context_set_upstream_recursive_servers"
#define GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS_TEXT "Change related to getdns_context_set_dns_root_servers"
#define GETDNS_CONTEXT_CODE_DNS_TRANSPORT_TEXT "Change related to getdns_context_set_dns_transport"
#define GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES_TEXT "Change related to getdns_context_set_limit_outstanding_queries"
#define GETDNS_CONTEXT_CODE_APPEND_NAME_TEXT "Change related to getdns_context_set_append_name"
#define GETDNS_CONTEXT_CODE_SUFFIX_TEXT "Change related to getdns_context_set_suffix"
#define GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS_TEXT "Change related to getdns_context_set_dnssec_trust_anchors"
#define GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE_TEXT "Change related to getdns_context_set_edns_maximum_udp_payload_size"
#define GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE_TEXT "Change related to getdns_context_set_edns_extended_rcode"
#define GETDNS_CONTEXT_CODE_EDNS_VERSION_TEXT "Change related to getdns_context_set_edns_version"
#define GETDNS_CONTEXT_CODE_EDNS_DO_BIT_TEXT "Change related to getdns_context_set_edns_do_bit"
#define GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW_TEXT "Change related to getdns_context_set_dnssec_allowed_skew"
#define GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS_TEXT "Change related to getdns_context_set_memory_functions"
#define GETDNS_CONTEXT_CODE_TIMEOUT_TEXT "Change related to getdns_context_set_timeout"

/* Callback Type Variables */
typedef enum getdns_callback_type_t {
	GETDNS_CALLBACK_COMPLETE = 700,
	GETDNS_CALLBACK_CANCEL = 701,
	GETDNS_CALLBACK_TIMEOUT = 702,
	GETDNS_CALLBACK_ERROR = 703
} getdns_callback_type_t;

#define GETDNS_CALLBACK_COMPLETE_TEXT "The response has the requested data in it"
#define GETDNS_CALLBACK_CANCEL_TEXT "The calling program cancelled the callback; response is NULL"
#define GETDNS_CALLBACK_TIMEOUT_TEXT "The requested action timed out; response is NULL"
#define GETDNS_CALLBACK_ERROR_TEXT "The requested action had an error; response is NULL"

/* Type Of Name Services */
#define GETDNS_NAMETYPE_DNS 800
#define GETDNS_NAMETYPE_DNS_TEXT "Normal DNS (RFC 1035)"
#define GETDNS_NAMETYPE_WINS 801
#define GETDNS_NAMETYPE_WINS_TEXT "The WINS name service (some reference needed)"

/* Status Codes for Responses */
#define GETDNS_RESPSTATUS_GOOD 900
#define GETDNS_RESPSTATUS_GOOD_TEXT "At least one response was returned"
#define GETDNS_RESPSTATUS_NO_NAME 901
#define GETDNS_RESPSTATUS_NO_NAME_TEXT "Queries for the name yielded all negative responses"
#define GETDNS_RESPSTATUS_ALL_TIMEOUT 902
#define GETDNS_RESPSTATUS_ALL_TIMEOUT_TEXT "All queries for the name timed out"
#define GETDNS_RESPSTATUS_NO_SECURE_ANSWERS 903
#define GETDNS_RESPSTATUS_NO_SECURE_ANSWERS_TEXT "The context setting for getting only secure responses was specified, and at least one DNS response was received, but no DNS response was determined to be secure through DNSSEC."

/* Values Associated With Extensions */
#define GETDNS_EXTENSION_TRUE 1000
#define GETDNS_EXTENSION_TRUE_TEXT "Turn on the extension"
#define GETDNS_EXTENSION_FALSE 1001
#define GETDNS_EXTENSION_FALSE_TEXT "Do not turn on the extension"

/* Values Associated With DNS Errors Found By The API */
#define GETDNS_BAD_DNS_CNAME_IN_TARGET 1100
#define GETDNS_BAD_DNS_CNAME_IN_TARGET_TEXT "A DNS query type that does not allow a target to be a CNAME pointed to a CNAME"
#define GETDNS_BAD_DNS_ALL_NUMERIC_LABEL 1101
#define GETDNS_BAD_DNS_ALL_NUMERIC_LABEL_TEXT "One or more labels in a returned domain name is all-numeric; this is not legal for a hostname"
#define GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE 1102
#define GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE_TEXT "A DNS query for a type other than CNAME returned a CNAME response"


/* Defines for RRtypes (from 2014-02) */
#define GETDNS_RRTYPE_A 1
#define GETDNS_RRTYPE_NS 2
#define GETDNS_RRTYPE_MD 3
#define GETDNS_RRTYPE_MF 4
#define GETDNS_RRTYPE_CNAME 5
#define GETDNS_RRTYPE_SOA 6
#define GETDNS_RRTYPE_MB 7
#define GETDNS_RRTYPE_MG 8
#define GETDNS_RRTYPE_MR 9
#define GETDNS_RRTYPE_NULL 10
#define GETDNS_RRTYPE_WKS 11
#define GETDNS_RRTYPE_PTR 12
#define GETDNS_RRTYPE_HINFO 13
#define GETDNS_RRTYPE_MINFO 14
#define GETDNS_RRTYPE_MX 15
#define GETDNS_RRTYPE_TXT 16
#define GETDNS_RRTYPE_RP 17
#define GETDNS_RRTYPE_AFSDB 18
#define GETDNS_RRTYPE_X25 19
#define GETDNS_RRTYPE_ISDN 20
#define GETDNS_RRTYPE_RT 21
#define GETDNS_RRTYPE_NSAP 22
#define GETDNS_RRTYPE_SIG 24
#define GETDNS_RRTYPE_KEY 25
#define GETDNS_RRTYPE_PX 26
#define GETDNS_RRTYPE_GPOS 27
#define GETDNS_RRTYPE_AAAA 28
#define GETDNS_RRTYPE_LOC 29
#define GETDNS_RRTYPE_NXT 30
#define GETDNS_RRTYPE_EID 31
#define GETDNS_RRTYPE_NIMLOC 32
#define GETDNS_RRTYPE_SRV 33
#define GETDNS_RRTYPE_ATMA 34
#define GETDNS_RRTYPE_NAPTR 35
#define GETDNS_RRTYPE_KX 36
#define GETDNS_RRTYPE_CERT 37
#define GETDNS_RRTYPE_A6 38
#define GETDNS_RRTYPE_DNAME 39
#define GETDNS_RRTYPE_SINK 40
#define GETDNS_RRTYPE_OPT 41
#define GETDNS_RRTYPE_APL 42
#define GETDNS_RRTYPE_DS 43
#define GETDNS_RRTYPE_SSHFP 44
#define GETDNS_RRTYPE_IPSECKEY 45
#define GETDNS_RRTYPE_RRSIG 46
#define GETDNS_RRTYPE_NSEC 47
#define GETDNS_RRTYPE_DNSKEY 48
#define GETDNS_RRTYPE_DHCID 49
#define GETDNS_RRTYPE_NSEC3 50
#define GETDNS_RRTYPE_NSEC3PARAM 51
#define GETDNS_RRTYPE_TLSA 52
#define GETDNS_RRTYPE_HIP 55
#define GETDNS_RRTYPE_NINFO 56
#define GETDNS_RRTYPE_RKEY 57
#define GETDNS_RRTYPE_TALINK 58
#define GETDNS_RRTYPE_CDS 59
#define GETDNS_RRTYPE_SPF 99
#define GETDNS_RRTYPE_UINFO 100
#define GETDNS_RRTYPE_UID 101
#define GETDNS_RRTYPE_GID 102
#define GETDNS_RRTYPE_UNSPEC 103
#define GETDNS_RRTYPE_NID 104
#define GETDNS_RRTYPE_L32 105
#define GETDNS_RRTYPE_L64 106
#define GETDNS_RRTYPE_LP 107
#define GETDNS_RRTYPE_EUI48 108
#define GETDNS_RRTYPE_EUI64 109
#define GETDNS_RRTYPE_TKEY 249
#define GETDNS_RRTYPE_TSIG 250
#define GETDNS_RRTYPE_IXFR 251
#define GETDNS_RRTYPE_AXFR 252
#define GETDNS_RRTYPE_MAILB 253
#define GETDNS_RRTYPE_MAILA 254
#define GETDNS_RRTYPE_ANY 255
#define GETDNS_RRTYPE_URI 256
#define GETDNS_RRTYPE_CAA 257
#define GETDNS_RRTYPE_TA 32768
#define GETDNS_RRTYPE_DLV 32769

/* Defines for RRclasses (from 2014-02) */
#define GETDNS_RRCLASS_IN     1
#define GETDNS_RRCLASS_CH     3
#define GETDNS_RRCLASS_HS     4
#define GETDNS_RRCLASS_NONE 254
#define GETDNS_RRCLASS_ANY  255

/* Defines for Opcodes (from 2014-02) */
#define GETDNS_OPCODE_QUERY  0
#define GETDNS_OPCODE_IQUERY 1
#define GETDNS_OPCODE_STATUS 2
#define GETDNS_OPCODE_NOTIFY 4
#define GETDNS_OPCODE_UPDATE 5

/* Defines for Rcodes (from 2014-02) */
#define GETDNS_RCODE_NOERROR   0
#define GETDNS_RCODE_FORMERR   1
#define GETDNS_RCODE_SERVFAIL  2
#define GETDNS_RCODE_NXDOMAIN  3
#define GETDNS_RCODE_NOTIMP    4
#define GETDNS_RCODE_REFUSED   5
#define GETDNS_RCODE_YXDOMAIN  6
#define GETDNS_RCODE_YXRRSET   7
#define GETDNS_RCODE_NXRRSET   8
#define GETDNS_RCODE_NOTAUTH   9
#define GETDNS_RCODE_NOTZONE  10
#define GETDNS_RCODE_BADVERS  16
#define GETDNS_RCODE_BADSIG   16
#define GETDNS_RCODE_BADKEY   17
#define GETDNS_RCODE_BADTIME  18
#define GETDNS_RCODE_BADMODE  19
#define GETDNS_RCODE_BADNAME  20
#define GETDNS_RCODE_BADALG   21
#define GETDNS_RCODE_BADTRUNC 22

/* Various typedefs  */
typedef struct getdns_context getdns_context;
typedef uint64_t   getdns_transaction_t;
typedef enum getdns_data_type {
    t_dict, t_list, t_int, t_bindata
} getdns_data_type;
typedef struct getdns_bindata {
    size_t size;
    uint8_t *data;
} getdns_bindata;
typedef struct getdns_dict getdns_dict;
typedef struct getdns_list getdns_list;

/* Helper functions for data structures */

/* Lists: get the length, get the data_type of the value at a given
   position, and get the data at a given position */
getdns_return_t getdns_list_get_length(const getdns_list *this_list, size_t *answer);
getdns_return_t getdns_list_get_data_type(const getdns_list *this_list, size_t index, getdns_data_type *answer);
getdns_return_t getdns_list_get_dict(const getdns_list *this_list, size_t index, getdns_dict **answer);
getdns_return_t getdns_list_get_list(const getdns_list *this_list, size_t index, getdns_list **answer);
getdns_return_t getdns_list_get_bindata(const getdns_list *this_list, size_t index, getdns_bindata **answer);
getdns_return_t getdns_list_get_int(const getdns_list *this_list, size_t index, uint32_t *answer);

/* Dicts: get the list of names, get the data_type of the
   value at a given name, and get the data at a given name */
getdns_return_t getdns_dict_get_names(const getdns_dict *this_dict, getdns_list **answer);
getdns_return_t getdns_dict_get_data_type(const getdns_dict *this_dict, const char *name, getdns_data_type *answer);
getdns_return_t getdns_dict_get_dict(const getdns_dict *this_dict, const char *name, getdns_dict **answer);
getdns_return_t getdns_dict_get_list(const getdns_dict *this_dict, const char *name, getdns_list **answer);
getdns_return_t getdns_dict_get_bindata(const getdns_dict *this_dict, const char *name, getdns_bindata **answer);
getdns_return_t getdns_dict_get_int(const getdns_dict *this_dict, const char *name, uint32_t *answer);


/* Lists: create, destroy, and set the data at a given position */
getdns_list * getdns_list_create();
getdns_list * getdns_list_create_with_context(
  getdns_context *context
);
getdns_list * getdns_list_create_with_memory_functions(
  void *(*malloc)(size_t),
  void *(*realloc)(void *, size_t),
  void (*free)(void *)
);
getdns_list * getdns_list_create_with_extended_memory_functions(
  void *userarg,
  void *(*malloc)(void *userarg, size_t),
  void *(*realloc)(void *userarg, void *, size_t),
  void (*free)(void *userarg, void *)
);
void getdns_list_destroy(getdns_list *this_list);
getdns_return_t getdns_list_set_dict(getdns_list *this_list, size_t index, const getdns_dict *child_dict);
getdns_return_t getdns_list_set_list(getdns_list *this_list, size_t index, const getdns_list *child_list);
getdns_return_t getdns_list_set_bindata(getdns_list *this_list, size_t index, const getdns_bindata *child_bindata);
getdns_return_t getdns_list_set_int(getdns_list *this_list, size_t index, uint32_t child_uint32);

/* Dicts: create, destroy, and set the data at a given name */
getdns_dict * getdns_dict_create();
getdns_dict * getdns_dict_create_with_context(
  getdns_context *context
);
getdns_dict * getdns_dict_create_with_memory_functions(
  void *(*malloc)(size_t),
  void *(*realloc)(void *, size_t),
  void (*free)(void *)
);
getdns_dict * getdns_dict_create_with_extended_memory_functions(
  void *userarg,
  void *(*malloc)(void *userarg, size_t),
  void *(*realloc)(void *userarg, void *, size_t),
  void (*free)(void *userarg, void *)
);
void getdns_dict_destroy(getdns_dict *this_dict);
getdns_return_t getdns_dict_set_dict(getdns_dict *this_dict, const char *name, const getdns_dict *child_dict);
getdns_return_t getdns_dict_set_list(getdns_dict *this_dict, const char *name, const getdns_list *child_list);
getdns_return_t getdns_dict_set_bindata(getdns_dict *this_dict, const char *name, const getdns_bindata *child_bindata);
getdns_return_t getdns_dict_set_int(getdns_dict *this_dict, const char *name, uint32_t child_uint32);
getdns_return_t getdns_dict_remove_name(getdns_dict *this_dict, const char *name);

/* Callback arguments */
typedef void (*getdns_callback_t)(
                                  getdns_context         *context,
                                  getdns_callback_type_t callback_type,
                                  getdns_dict            *response,
                                  void                   *userarg,
                                  getdns_transaction_t   transaction_id);

/* Function definitions */

getdns_return_t
getdns_general(
  getdns_context        *context,
  const char            *name,
  uint16_t              request_type,
  getdns_dict           *extensions,
  void                  *userarg,
  getdns_transaction_t  *transaction_id,
  getdns_callback_t     callbackfn
);
getdns_return_t
getdns_address(
  getdns_context        *context,
  const char            *name,
  getdns_dict           *extensions,
  void                  *userarg,
  getdns_transaction_t  *transaction_id,
  getdns_callback_t     callbackfn
);
getdns_return_t
getdns_hostname(
  getdns_context        *context,
  getdns_dict           *address,
  getdns_dict           *extensions,
  void                  *userarg,
  getdns_transaction_t  *transaction_id,
  getdns_callback_t     callbackfn
);
getdns_return_t
getdns_service(
  getdns_context        *context,
  const char            *name,
  getdns_dict           *extensions,
  void                  *userarg,
  getdns_transaction_t  *transaction_id,
  getdns_callback_t     callbackfn
);

getdns_return_t
getdns_context_create(
  getdns_context  **context,
  int             set_from_os
);

getdns_return_t
getdns_context_create_with_memory_functions(
  getdns_context  **context,
  int             set_from_os,
  void            *(*malloc)(size_t),
  void            *(*realloc)(void *, size_t),
  void            (*free)(void *)
);
getdns_return_t
getdns_context_create_with_extended_memory_functions(
  getdns_context  **context,
  int             set_from_os,
  void            *userarg,
  void            *(*malloc)(void *userarg, size_t),
  void            *(*realloc)(void *userarg, void *, size_t),
  void            (*free)(void *userarg, void *)
);

void
getdns_context_destroy(
  getdns_context   *context
);

getdns_return_t
getdns_cancel_callback(
  getdns_context        *context,
  getdns_transaction_t  transaction_id
);

getdns_return_t
getdns_general_sync(
  getdns_context  *context,
  const char      *name,
  uint16_t        request_type,
  getdns_dict     *extensions,
  getdns_dict     **response
);

getdns_return_t
getdns_address_sync(
  getdns_context  *context,
  const char      *name,
  getdns_dict     *extensions,
  getdns_dict     **response
);

getdns_return_t
getdns_hostname_sync(
  getdns_context  *context,
  getdns_dict     *address,
  getdns_dict     *extensions,
  getdns_dict     **response
);

getdns_return_t
getdns_service_sync(
  getdns_context  *context,
  const char      *name,
  getdns_dict     *extensions,
  getdns_dict     **response
);

getdns_return_t
getdns_convert_dns_name_to_fqdn(
  const getdns_bindata *dns_name_wire_fmt,
  char **fqdn_as_string
);

getdns_return_t
getdns_convert_fqdn_to_dns_name(
  const char *fqdn_as_string,
  getdns_bindata **dns_name_wire_fmt
);

char *
getdns_convert_ulabel_to_alabel(
  const char  *ulabel
);

char *
getdns_convert_alabel_to_ulabel(
  const char  *alabel
);

getdns_return_t
getdns_validate_dnssec(
  getdns_list     *record_to_validate,
  getdns_list     *bundle_of_support_records,
  getdns_list     *trust_anchor_records
);

char *
getdns_pretty_print_dict(
  const getdns_dict  *some_dict
);

char *
getdns_display_ip_address(
  const getdns_bindata  *bindata_of_ipv4_or_ipv6_address
);

getdns_return_t
getdns_context_set_context_update_callback(
  getdns_context  *context,
  void            (*value)(getdns_context *context, getdns_context_code_t changed_item)
);

getdns_return_t
getdns_context_set_resolution_type(
  getdns_context       *context,
  getdns_resolution_t  value
);

getdns_return_t
getdns_context_set_namespaces(
  getdns_context      *context,
  size_t              namespace_count,
  getdns_namespace_t  *namespaces
);

getdns_return_t
getdns_context_set_dns_transport(
  getdns_context      *context,
  getdns_transport_t  value
);

getdns_return_t
getdns_context_set_limit_outstanding_queries(
  getdns_context  *context,
  uint16_t        limit
);

getdns_return_t
getdns_context_set_timeout(
  getdns_context  *context,
  uint64_t        timeout
);

getdns_return_t
getdns_context_set_follow_redirects(
  getdns_context      *context,
  getdns_redirects_t  value
);

getdns_return_t
getdns_context_set_dns_root_servers(
  getdns_context  *context,
  getdns_list     *addresses
);

getdns_return_t
getdns_context_set_append_name(
  getdns_context        *context,
  getdns_append_name_t  value
);

getdns_return_t
getdns_context_set_suffix(
  getdns_context  *context,
  getdns_list     *value
);

getdns_return_t
getdns_context_set_dnssec_trust_anchors(
  getdns_context  *context,
  getdns_list     *value
);

getdns_return_t
getdns_context_set_dnssec_allowed_skew(
  getdns_context  *context,
  uint32_t        value
);

getdns_return_t
getdns_context_set_upstream_recursive_servers(
  getdns_context  *context,
  getdns_list     *upstream_list
);

getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(
  getdns_context  *context,
  uint16_t        value
);

getdns_return_t
getdns_context_set_edns_extended_rcode(
  getdns_context  *context,
  uint8_t         value
);

getdns_return_t
getdns_context_set_edns_version(
  getdns_context  *context,
  uint8_t         value
);

getdns_return_t
getdns_context_set_edns_do_bit(
  getdns_context  *context,
  uint8_t         value
);

getdns_return_t
getdns_context_set_memory_functions(
  getdns_context *context,
  void           *(*malloc) (size_t),
  void           *(*realloc) (void *, size_t),
  void           (*free) (void *)
);

getdns_return_t
getdns_context_set_extended_memory_functions(
  getdns_context *context,
  void           *userarg,
  void           *(*malloc)(void *userarg, size_t sz),
  void           *(*realloc)(void *userarg, void *ptr, size_t sz),
  void           (*free)(void *userarg, void *ptr)
);

#ifdef __cplusplus
}
#endif
#endif /* GETDNS_H */
