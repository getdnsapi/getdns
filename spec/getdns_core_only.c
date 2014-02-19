#include <getdns_libevent.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

int main(){ return(0); }

/* Function definitions */

getdns_return_t
getdns_general(
  getdns_context      *context,
  const char                 *name,
  uint16_t                   request_type,
  getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(request_type); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_address(
  getdns_context      *context,
  const char                 *name,
  getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_hostname(
  getdns_context      *context,
  getdns_dict         *address,
  getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(address); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_service(
  getdns_context      *context,
  const char                 *name,
  getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_create(
    getdns_context   **context,
    int                     set_from_os
)
{ UNUSED_PARAM(context); UNUSED_PARAM(set_from_os); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_create_with_memory_functions(
  getdns_context  **context,
  int                    set_from_os,
  void                   *(*malloc)(size_t),
  void                   *(*realloc)(void *, size_t),
  void                   (*free)(void *)
)
{ UNUSED_PARAM(context); UNUSED_PARAM(set_from_os);
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_create_with_extended_memory_functions(
  getdns_context  **context,
  int                    set_from_os,
  void                   *userarg,
  void                   *(*malloc)(void *userarg, size_t),
  void                   *(*realloc)(void *userarg, void *, size_t),
  void                   (*free)(void *userarg, void *)
)
{ UNUSED_PARAM(context); UNUSED_PARAM(set_from_os); UNUSED_PARAM(userarg);
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return GETDNS_RETURN_GOOD; }

void
getdns_context_destroy(
	getdns_context  *context
)
{ UNUSED_PARAM(context); }

getdns_return_t
getdns_cancel_callback(
	getdns_context      *context,
	getdns_transaction_t       transaction_id
)
{ UNUSED_PARAM(context); UNUSED_PARAM(transaction_id); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_general_sync(
  getdns_context  *context,
  const char             *name,
  uint16_t               request_type,
  getdns_dict     *extensions,
  getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(request_type); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_address_sync(
  getdns_context  *context,
  const char             *name,
  getdns_dict     *extensions,
  getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_hostname_sync(
  getdns_context  *context,
  getdns_dict     *address,
  getdns_dict     *extensions,
  getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(address); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_service_sync(
  getdns_context  *context,
  const char             *name,
  getdns_dict     *extensions,
  getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

void
getdns_free_sync_request_memory(
  getdns_dict     *response
)
{ UNUSED_PARAM(response); }

getdns_return_t getdns_list_get_length(const getdns_list *this_list, size_t *answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_data_type(const getdns_list *this_list, size_t index, getdns_data_type *answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_dict(const getdns_list *this_list, size_t index, getdns_dict **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_list(const getdns_list *this_list, size_t index, getdns_list **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_bindata(const getdns_list *this_list, size_t index, getdns_bindata **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_int(const getdns_list *this_list, size_t index, uint32_t *answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_names(const getdns_dict *this_dict, getdns_list **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_data_type(const getdns_dict *this_dict, const char *name, getdns_data_type *answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_dict(const getdns_dict *this_dict, const char *name, getdns_dict **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_list(const getdns_dict *this_dict, const char *name, getdns_list **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_bindata(const getdns_dict *this_dict, const char *name, getdns_bindata **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_int(const getdns_dict *this_dict, const char *name, uint32_t *answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_list * getdns_list_create()
{ return NULL; }

getdns_list * getdns_list_create_with_context(
  getdns_context *context
)
{ UNUSED_PARAM(context); return NULL; }

getdns_list * getdns_list_create_with_memory_functions(
  void *(*malloc)(size_t),
  void *(*realloc)(void *, size_t),
  void (*free)(void *)
)
{ UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

getdns_list * getdns_list_create_with_extended_memory_functions(
  void *userarg,
  void *(*malloc)(void *userarg, size_t),
  void *(*realloc)(void *userarg, void *, size_t),
  void (*free)(void *userarg, void *)
)
{ UNUSED_PARAM(userarg);
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

void getdns_list_destroy(getdns_list *this_list)
{ UNUSED_PARAM(this_list); }

getdns_return_t getdns_list_set_dict(getdns_list *this_list, size_t index, const getdns_dict *child_dict)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_dict); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_list(getdns_list *this_list, size_t index, const getdns_list *child_list)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_list); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_bindata(getdns_list *this_list, size_t index, const getdns_bindata *child_bindata)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_bindata); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_int(getdns_list *this_list, size_t index, uint32_t child_uint32)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_uint32); return GETDNS_RETURN_GOOD; }

getdns_dict * getdns_dict_create()
{ return NULL; }

getdns_dict * getdns_dict_create_with_context(
  getdns_context *context
)
{ UNUSED_PARAM(context); return NULL; }

getdns_dict * getdns_dict_create_with_memory_functions(
  void *(*malloc)(size_t),
  void *(*realloc)(void *, size_t),
  void (*free)(void *)
)
{ UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

getdns_dict * getdns_dict_create_with_extended_memory_functions(
  void *userarg,
  void *(*malloc)(void *userarg, size_t),
  void *(*realloc)(void *userarg, void *, size_t),
  void (*free)(void *userarg, void *)
)
{ UNUSED_PARAM(userarg);
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

void getdns_dict_destroy(getdns_dict *this_dict)
{ UNUSED_PARAM(this_dict); }

getdns_return_t getdns_dict_set_dict(getdns_dict *this_dict, const char *name, const getdns_dict *child_dict)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_dict); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_list(getdns_dict *this_dict, const char *name, const getdns_list *child_list)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_list); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_bindata(getdns_dict *this_dict, const char *name, const getdns_bindata *child_bindata)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_bindata); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_int(getdns_dict *this_dict, const char *name, uint32_t child_uint32)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_uint32); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_remove_name(getdns_dict *this_dict, const char *name)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_convert_dns_name_to_fqdn(
  const getdns_bindata *dns_name_wire_fmt,
  char **fqdn_as_string
)
{ UNUSED_PARAM(dns_name_wire_fmt); UNUSED_PARAM(fqdn_as_string); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_convert_fqdn_to_dns_name(
  const char *fqdn_as_string,
  getdns_bindata **dns_name_wire_fmt
)
{ UNUSED_PARAM(fqdn_as_string); UNUSED_PARAM(dns_name_wire_fmt);  return GETDNS_RETURN_GOOD; }

char *
getdns_convert_ulabel_to_alabel(
	const char  *ulabel
)
{ UNUSED_PARAM(ulabel); return NULL; }

char *
getdns_convert_alabel_to_ulabel(
	const char  *alabel
)
{ UNUSED_PARAM(alabel); return NULL; }

getdns_return_t
getdns_validate_dnssec(
  getdns_list     *record_to_validate,
  getdns_list     *bundle_of_support_records,
  getdns_list     *trust_anchor_rdatas
)
{ UNUSED_PARAM(record_to_validate); UNUSED_PARAM(bundle_of_support_records); UNUSED_PARAM(trust_anchor_rdatas);
return GETDNS_RETURN_GOOD; }


char *
getdns_pretty_print_dict(
	const getdns_dict     *some_dict
)
{ UNUSED_PARAM(some_dict); return NULL; }

char *
getdns_display_ip_address(
  const getdns_bindata    *bindata_of_ipv4_or_ipv6_address
)
{ UNUSED_PARAM(bindata_of_ipv4_or_ipv6_address); return NULL; }

getdns_return_t
getdns_context_set_context_update_callback(
  getdns_context  *context,
  void                   (*value)(getdns_context *context, getdns_context_code_t changed_item)
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_resolution_type(
  getdns_context  *context,
  getdns_resolution_t    value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_namespaces(
  getdns_context  *context,
  size_t                 namespace_count,
  getdns_namespace_t      *namespaces
)
{ UNUSED_PARAM(context); UNUSED_PARAM(namespace_count); UNUSED_PARAM(namespaces);
return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dns_transport(
  getdns_context  *context,
  getdns_transport_t     value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_limit_outstanding_queries(
  getdns_context  *context,
  uint16_t               limit
)
{ UNUSED_PARAM(context); UNUSED_PARAM(limit); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_timeout(
  getdns_context  *context,
  uint64_t           timeout
)
{ UNUSED_PARAM(context); UNUSED_PARAM(timeout); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_follow_redirects(
  getdns_context  *context,
  getdns_redirects_t     value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dns_root_servers(
  getdns_context  *context,
  getdns_list     *addresses
)
{ UNUSED_PARAM(context); UNUSED_PARAM(addresses); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_append_name(
  getdns_context  *context,
  getdns_append_name_t   value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_suffix(
  getdns_context  *context,
  getdns_list     *value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dnssec_trust_anchors(
  getdns_context  *context,
  getdns_list     *value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dnssec_allowed_skew(
  getdns_context  *context,
  unsigned int           value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_upstream_recursive_servers(
  getdns_context  *context,
  getdns_list     *upstream_list
)
{ UNUSED_PARAM(context); UNUSED_PARAM(upstream_list); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(
  getdns_context  *context,
  uint16_t               value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_extended_rcode(
  getdns_context  *context,
  uint8_t                value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_version(
  getdns_context  *context,
  uint8_t                value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_do_bit(
  getdns_context  *context,
  uint8_t                value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_memory_functions(
  getdns_context *context,
  void                  *(*malloc) (size_t),
  void                  *(*realloc) (void *, size_t),
  void                  (*free) (void *)
)
{ UNUSED_PARAM(context); 
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_extended_memory_functions(
  getdns_context *context,
  void                  *userarg,
  void                  *(*malloc)(void *userarg, size_t sz),
  void                  *(*realloc)(void *userarg, void *ptr, size_t sz),
  void                  (*free)(void *userarg, void *ptr)
)
{ UNUSED_PARAM(context); UNUSED_PARAM(userarg);
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return GETDNS_RETURN_GOOD; }


getdns_return_t
getdns_extension_set_libevent_base(
    getdns_context  *context,
    struct event_base      *this_event_base
)
{ UNUSED_PARAM(context); UNUSED_PARAM(this_event_base); return GETDNS_RETURN_GOOD; }

